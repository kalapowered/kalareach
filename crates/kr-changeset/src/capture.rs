//! `changeset.capture`: reading a working tree into an immutable version.
//!
//! Everything here goes through the project service. The repository is opened with
//! [`kr_project::OpenedRepository`], every Git invocation runs under
//! [`kr_project::ProjectService::profile`] inside the execution boundary, and every file is read
//! through [`kr_project::OpenedRepository::work_tree`], which is an open directory descriptor
//! rather than a path. A capture writes nothing into the user's repository.
//!
//! # The base is the commit, and the index is not it
//!
//! A version is against a **revision**, so what the captured tree is compared with is the commit
//! `HEAD` names and never the index. `git diff --raw` against that revision reports, for every
//! path whose working tree differs from it, the mode and the object **the commit** holds. A path
//! the diff does not name has a working tree equal to the commit's own content, whatever the index
//! happens to hold for it. So a staged change is an uncommitted change like any other, a staged
//! addition is a path the base never held, and a staged deletion is a path the base does hold.
//!
//! # What a capture reads, and in which order
//!
//! 1. `HEAD`, which is the base revision, read inside each attempt and read again at the end.
//! 2. `git ls-files --stage -z`, the index, for the object an apply's preflight compares against.
//! 3. `git diff --raw -z <revision>`, which says how the working tree differs from the base and
//!    what the base holds for each of those paths.
//! 4. `git status --porcelain=v2 -z`, which adds the untracked and ignored paths.
//! 5. The grant and the policy decide, path by path, **before anything is opened**. A path a
//!    secret rule covers, a path under `.git`, and a path the grant leaves out are never opened.
//! 6. The content: from the working tree through the authorised handle, or from an immutable Git
//!    object with `git cat-file blob`.
//! 7. Steps 1, 2, 3 and 4 again. Anything that changed underneath is retried within
//!    [`kr_protocol::changeset::MAX_CAPTURE_RETRIES`] and then rejected with `SOURCE_CHANGED`.
//!
//! # The three consistency classes, and the mechanism each rests on
//!
//! * [`SourceConsistency::AtomicSnapshot`] is a capture of the base commit's **own tree**, read by
//!   walking immutable tree objects from `<revision>^{tree}` and reading each blob with
//!   `cat-file`. The commit is immutable and so is every object under it, so the whole tree is one
//!   instant by construction rather than by timing. Nothing of the working tree is read at all. A
//!   caller asks for it with `required_consistency`, and a policy that would include any
//!   uncommitted work is refused rather than served a weaker class under the name it asked for.
//! * [`SourceConsistency::QuiescedCapture`] needs three things together: the caller declared the
//!   working tree quiesced, this host found **no live session and no live automation run holding
//!   the workspace** before and after the read, and every per-file and selection check passed. The
//!   declaration alone never decides it. What the class does not exclude is an editor outside
//!   KalaReach, and the record says so.
//! * [`SourceConsistency::PerFileCapture`] otherwise. Files read one at a time from a live tree,
//!   with each file's identity, length and modification instant compared across its own read and
//!   the whole selection compared across the capture. The captured tree is still immutable and
//!   exactly identified; what it is not is one instant of the working tree.
//!
//! No filesystem this service runs on offers an unprivileged atomic snapshot of a directory tree,
//! so there is no fourth mechanism and no capture is described as one.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::Read as _;

use kr_project::{OpenedRepository, RestrictedProfile};
use kr_protocol::changeset::{
    CapturedPath, ContentOrigin, Exclusion, ExclusionReason, FileGrant, MAX_CAPTURE_BYTES,
    MAX_CAPTURE_RETRIES, MAX_PATH_RETRIES, PathClass, SourceConsistency,
};
use kr_protocol::project::{
    ChangeKind, ContentClass, InclusionChoice, InclusionClass, InclusionPolicy,
};
use kr_protocol::scalars::{Nullable, U64};
use kr_transfer::{ObjectPolicy, RelativeName};

use crate::error::{ChangeSetError, Result};
use crate::grant::{self, GrantDecision};
use crate::objects::ObjectStore;
use crate::version::Manifest;

/// How many Git objects one capture reads.
///
/// Reading content from a Git object costs one invocation each, and the boundary makes each one a
/// process of its own. A capture that would need more than this says so with the figure rather
/// than running for an hour: the caller narrows its grant, or accepts the working tree as the
/// source and the per-file class that goes with it.
pub const MAX_OBJECT_READS: usize = 4_096;

/// How many paths one capture walks into from a wholly ignored or untracked directory.
///
/// Git reports a directory nothing in which is tracked as **one** record with a trailing
/// separator, so a capture that took that record literally would hold a path that is a directory
/// and would miss every file under it. The walk expands it, and a tree deeper or wider than this
/// is refused with the figure rather than captured short.
pub const MAX_WALK_ENTRIES: usize = 200_000;

/// How deep one walk goes, into a reported directory or into the base commit's own tree.
pub const MAX_WALK_DEPTH: usize = 64;

/// Largest single file one capture reads, in bytes.
///
/// The total bound is charged as the capture goes rather than at the end, and this is the bound on
/// one file, so a file larger than a host should hold in memory is refused before it is read
/// rather than after.
pub const MAX_CAPTURE_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// The Git file modes a captured tree can hold.
///
/// `100644` and `100755` are file content. `120000` is a symbolic link, whose object holds the
/// target rather than content, and `160000` is a submodule. Writing either out as a regular file
/// would make a materialisation a different tree, so both are named and left out.
const REGULAR_MODES: &[&str] = &["100644", "100755"];

/// What the capture is asked to read.
#[derive(Clone, Copy, Debug)]
pub struct CaptureRequest<'a> {
    /// One decision per class of the working tree.
    pub policy: &'a InclusionPolicy,
    /// What the caller's grant selects and excludes.
    pub grant: &'a FileGrant,
    /// True when the caller has quiesced the working tree.
    pub quiescence_declared: bool,
    /// The class the caller requires, when it requires one.
    pub required_consistency: Option<SourceConsistency>,
}

/// What one capture established.
#[derive(Clone, Debug)]
pub struct Captured {
    /// The whole captured tree.
    pub manifest: Manifest,
    /// The revision it is against.
    pub base_revision: String,
    /// The reference that revision was named by, when it was named by one.
    pub base_reference: Option<String>,
    /// How consistent the source was.
    pub consistency: SourceConsistency,
    /// What decided that class, in this host's own words.
    pub consistency_detail: String,
    /// Every distinct content digest the tree names.
    pub objects: Vec<kr_protocol::scalars::Digest256>,
}

/// One entry of the index listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    /// The mode Git records for it, such as `100644` or `100755`.
    pub mode: String,
    /// The object the index holds for it.
    pub object_id: String,
    /// Its merge stage: zero for an ordinary entry, higher for an unresolved one.
    pub stage: u32,
}

/// One path whose working tree differs from the base revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseDifference {
    /// The mode the base revision holds, or nothing when the base does not hold the path.
    pub base_mode: Option<String>,
    /// The object the base revision holds, or nothing when the base does not hold the path.
    pub base_object_id: Option<String>,
    /// Git's own one-letter status: `A`, `D`, `M`, `T`, `U`.
    pub status: char,
}

/// Whether anything KalaReach knows of still holds the workspace.
///
/// The one mechanism behind [`SourceConsistency::QuiescedCapture`] that is not a declaration: the
/// project service records every session and automation run bound to a workspace, and a capture
/// that finds none of them live before and after the read has established that nothing this host
/// knows about was writing. What it does not establish is that an editor outside KalaReach was
/// not, and the record says so.
pub type QuiescenceProbe<'a> = &'a dyn Fn() -> Result<bool>;

/// Reads a working tree into a captured tree.
///
/// # Errors
///
/// Returns [`ChangeSetError::SourceChanged`] when the source kept changing past the bound,
/// [`ChangeSetError::InvalidArgument`] when the repository has no commit yet or the required
/// consistency class cannot be reached, and whatever the project service returns for a Git
/// invocation or a refused repository.
pub fn capture(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    store: &ObjectStore,
    request: &CaptureRequest<'_>,
    quiet: QuiescenceProbe<'_>,
) -> Result<Captured> {
    if request.required_consistency == Some(SourceConsistency::AtomicSnapshot) {
        return snapshot(profile, repository, store, request);
    }
    let mut last_change = String::new();
    for attempt in 0..=MAX_CAPTURE_RETRIES {
        let before = Reading::take(profile, repository, request.grant)?;
        let quiet_before = quiet()?;
        let planned = plan(&before, request);
        let read = read_content(profile, repository, store, &planned, request);
        let manifest = match read {
            Ok(manifest) => manifest,
            Err(ChangeSetError::SourceChanged { detail }) if attempt < MAX_CAPTURE_RETRIES => {
                last_change = detail.as_str().to_owned();
                continue;
            }
            Err(error) => return Err(error),
        };
        // Everything the selection was decided from is read again. A file this host did not touch
        // changing is exactly what a per-file capture cannot exclude, and what it must not
        // describe as one instant.
        let after = Reading::take(profile, repository, request.grant)?;
        if after != before {
            last_change = format!(
                "the working tree changed while this host was reading it: {}",
                before.difference(&after)
            );
            if attempt < MAX_CAPTURE_RETRIES {
                continue;
            }
            return Err(changed(&last_change));
        }
        let quiet_after = quiet()?;
        let (consistency, consistency_detail) = classify(request, quiet_before && quiet_after);
        if let Some(required) = request.required_consistency
            && !consistency.satisfies(required)
        {
            return Err(ChangeSetError::InvalidArgument(
                format!(
                    "this capture's source is a {} and the request requires a {}: \
                     {consistency_detail}",
                    consistency.as_str(),
                    required.as_str()
                )
                .into(),
            ));
        }
        let objects = distinct_objects(&manifest);
        return Ok(Captured {
            manifest,
            base_revision: before.revision,
            base_reference: before.reference,
            consistency,
            consistency_detail,
            objects,
        });
    }
    Err(changed(&last_change))
}

fn changed(detail: &str) -> ChangeSetError {
    ChangeSetError::SourceChanged {
        detail: format!(
            "{detail}, and this host tried {} times",
            MAX_CAPTURE_RETRIES + 1
        )
        .into(),
    }
}

/// Returns every distinct content digest a manifest names.
fn distinct_objects(manifest: &Manifest) -> Vec<kr_protocol::scalars::Digest256> {
    let mut digests: Vec<_> = manifest
        .paths
        .iter()
        .map(|entry| entry.content_digest)
        .collect();
    digests.sort_unstable();
    digests.dedup();
    digests
}

/// Everything one attempt decides its selection from, read together and compared afterwards.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Reading {
    revision: String,
    reference: Option<String>,
    index: BTreeMap<String, IndexEntry>,
    differences: BTreeMap<String, BaseDifference>,
    status: Vec<kr_project::workspace::StatusEntry>,
}

impl Reading {
    fn take(
        profile: &RestrictedProfile,
        repository: &OpenedRepository,
        grant: &FileGrant,
    ) -> Result<Self> {
        let (revision, reference) = repository.head(profile)?;
        let Some(revision) = revision else {
            return Err(ChangeSetError::InvalidArgument(
                "this repository has no commit yet, so there is no base revision a version could \
                 be captured against; commit once and capture again"
                    .into(),
            ));
        };
        let index = read_index(profile, repository)?;
        let differences = read_differences(profile, repository, &revision)?;
        let status = read_status(profile, repository, grant)?;
        Ok(Self {
            revision,
            reference,
            index,
            differences,
            status,
        })
    }

    /// Returns what changed between two readings, in this host's own words.
    fn difference(&self, other: &Self) -> String {
        if self.revision != other.revision {
            return "a commit landed while this host was reading the working tree".to_owned();
        }
        if self.index != other.index {
            return "the index changed while this host was reading the working tree".to_owned();
        }
        if self.differences != other.differences {
            return "what the working tree holds that the base revision does not changed"
                .to_owned();
        }
        "the untracked and ignored paths changed".to_owned()
    }

    /// Returns what the base revision holds for one path, when it holds it.
    ///
    /// A path the diff names carries the base's own mode and object. A path it does not name has a
    /// working tree equal to the base's content, so the base does hold it; the index's object is
    /// the base's only when nothing is staged for it, which the status says.
    fn base_of(&self, path: &str) -> Option<(String, String)> {
        if let Some(difference) = self.differences.get(path) {
            return match (&difference.base_mode, &difference.base_object_id) {
                (Some(mode), Some(object_id)) => Some((mode.clone(), object_id.clone())),
                _ => None,
            };
        }
        if self.staged(path) {
            // The working tree matches the base and the index does not, so the index's object is
            // not the base's and this host has not read the base's.
            return None;
        }
        self.index
            .get(path)
            .map(|entry| (entry.mode.clone(), entry.object_id.clone()))
    }

    /// Returns true when the status reports something staged for one path.
    fn staged(&self, path: &str) -> bool {
        self.status
            .iter()
            .any(|entry| entry.path == path && entry.class == InclusionClass::DirtyFile)
    }
}

/// Reads `git ls-files --stage -z`, which is what the index holds for every tracked path.
///
/// # Errors
///
/// Returns [`ChangeSetError::InvalidArgument`] when the index holds a path this host cannot read
/// as text, and whatever the project service returns for the invocation.
pub fn read_index(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
) -> Result<BTreeMap<String, IndexEntry>> {
    let arguments: [&OsStr; 3] = [
        OsStr::new("ls-files"),
        OsStr::new("--stage"),
        OsStr::new("-z"),
    ];
    let output = profile.run(&repository.read(&arguments))?;
    output.require_success()?;
    output.require_complete()?;
    let text = exactly(&output.stdout, "this repository's index")?;
    let mut entries = BTreeMap::new();
    for record in text.split('\0') {
        // `<mode> <object> <stage>\t<path>`
        let Some((fields, path)) = record.split_once('\t') else {
            continue;
        };
        if path.is_empty() {
            continue;
        }
        let parts: Vec<&str> = fields.splitn(3, ' ').collect();
        if parts.len() < 3 {
            continue;
        }
        let stage = parts[2].trim().parse::<u32>().unwrap_or(0);
        let entry = IndexEntry {
            mode: parts[0].to_owned(),
            object_id: parts[1].to_owned(),
            stage,
        };
        // An unmerged path has several stages. The first one wins the map and the stage is kept,
        // so the plan can see that the path is unmerged rather than ordinary.
        entries.entry(path.to_owned()).or_insert(entry);
    }
    Ok(entries)
}

/// Reads how the working tree differs from one revision, and what that revision holds.
///
/// This is what makes the base the **commit** rather than the index: Git reports the source mode
/// and the source object from the revision itself, so a staged change never passes for the base's
/// own content.
///
/// # Errors
///
/// Returns [`ChangeSetError::InvalidArgument`] when the repository names a path this host cannot
/// read as text, and whatever the project service returns for the invocation.
pub fn read_differences(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    revision: &str,
) -> Result<BTreeMap<String, BaseDifference>> {
    check_object_id(revision)?;
    let arguments: [&OsStr; 6] = [
        OsStr::new("diff"),
        OsStr::new("--raw"),
        OsStr::new("-z"),
        OsStr::new("--no-renames"),
        OsStr::new("--ignore-submodules=all"),
        OsStr::new(revision),
    ];
    let output = profile.run(&repository.read(&arguments))?;
    output.require_success()?;
    output.require_complete()?;
    let text = exactly(
        &output.stdout,
        "this repository's own report of its changes",
    )?;
    // `:<srcmode> <dstmode> <srcsha> <dstsha> <status>\0<path>\0`
    let mut fields = text.split('\0');
    let mut entries = BTreeMap::new();
    while let Some(meta) = fields.next() {
        let Some(meta) = meta.strip_prefix(':') else {
            continue;
        };
        let Some(path) = fields.next() else {
            break;
        };
        if path.is_empty() {
            continue;
        }
        let parts: Vec<&str> = meta.split(' ').collect();
        if parts.len() < 5 {
            return Err(ChangeSetError::InvalidArgument(
                "this repository reported a change record this format does not define".into(),
            ));
        }
        let status = parts[4].chars().next().unwrap_or('?');
        let absent = |value: &str| value.bytes().all(|byte| byte == b'0');
        entries.insert(
            path.to_owned(),
            BaseDifference {
                base_mode: (!absent(parts[0])).then(|| parts[0].to_owned()),
                base_object_id: (!absent(parts[2])).then(|| parts[2].to_owned()),
                status,
            },
        );
    }
    Ok(entries)
}

/// Reads `git status --porcelain=v2 -z`, with the same arguments the project service uses.
///
/// A record whose path ends in a separator is a whole directory Git reported as one entry, and
/// this expands it into the files it holds, through the working tree's own handle. The grant
/// decides a directory **before** the walk descends into it, so nothing under an excluded prefix
/// is even listed.
///
/// # Errors
///
/// Returns whatever the project service returns for the invocation, and
/// [`ChangeSetError::QuotaExceeded`] when the walk would exceed [`MAX_WALK_ENTRIES`].
pub fn read_status(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    grant: &FileGrant,
) -> Result<Vec<kr_project::workspace::StatusEntry>> {
    // `--ignore-submodules=all` is not an optimisation. Checking a submodule's dirtiness runs Git
    // *inside* the submodule, under a configuration the project service's audit never read.
    let arguments: [&OsStr; 7] = [
        OsStr::new("status"),
        OsStr::new("--porcelain=v2"),
        OsStr::new("-z"),
        OsStr::new("--untracked-files=all"),
        OsStr::new("--ignored=matching"),
        OsStr::new("--no-renames"),
        OsStr::new("--ignore-submodules=all"),
    ];
    let output = profile.run(&repository.read(&arguments))?;
    output.require_success()?;
    output.require_complete()?;
    let reported = exactly(&output.stdout, "this repository's own status")?;
    let entries = kr_project::workspace::parse_status(reported)?;
    let mut expanded = Vec::with_capacity(entries.len());
    let mut budget = MAX_WALK_ENTRIES;
    for entry in entries {
        if let Some(prefix) = entry.path.strip_suffix('/') {
            walk(
                repository.work_tree(),
                prefix,
                entry.class,
                grant,
                &mut expanded,
                &mut budget,
                0,
            )?;
        } else {
            expanded.push(entry);
        }
    }
    expanded.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(expanded)
}

/// Decodes what Git reported, refusing text this host cannot carry exactly.
///
/// A lossy decoding puts a replacement character where a byte was, and this host would then be
/// asking the filesystem about a different name: two different paths can become one, and a path
/// can go missing without anything saying so. A repository whose names this host cannot read is
/// refused rather than approximated.
fn exactly<'a>(bytes: &'a [u8], what: &str) -> Result<&'a str> {
    std::str::from_utf8(bytes).map_err(|_| {
        ChangeSetError::InvalidArgument(
            format!(
                "{what} names a path this host cannot read as text, so it cannot say what that \
                 path holds"
            )
            .into(),
        )
    })
}

/// Expands one directory entry into the files it holds.
///
/// The walk goes through the authorised directory handle, so nothing outside the working tree is
/// reached and a link is neither followed nor counted as content. Three things stop it: a
/// directory the grant excludes, a directory a secret rule covers, and a directory named `.git`,
/// which holds a repository's own administrative data including its remotes and any credential a
/// configuration file carries.
#[allow(clippy::too_many_arguments)]
fn walk(
    tree: &kr_transfer::AuthorisedDirectory,
    prefix: &str,
    class: InclusionClass,
    grant: &FileGrant,
    out: &mut Vec<kr_project::workspace::StatusEntry>,
    budget: &mut usize,
    depth: usize,
) -> Result<()> {
    if depth >= MAX_WALK_DEPTH {
        return Err(ChangeSetError::QuotaExceeded {
            detail: format!(
                "a directory this capture would read is more than {MAX_WALK_DEPTH} levels deep, \
                 and this host does not capture a tree it cannot walk to the bottom of"
            )
            .into(),
        });
    }
    // The decision is made before anything beneath the prefix is listed, which is what "the grant
    // applies before capture" means for a directory. The one entry is kept so the content read
    // records the exclusion with its reason rather than the path going missing.
    if grant::decide(grant, prefix) != GrantDecision::Permitted {
        out.push(kr_project::workspace::StatusEntry {
            path: prefix.to_owned(),
            class,
            change: ChangeKind::Present,
        });
        return Ok(());
    }
    let Ok(name) = RelativeName::parse(prefix) else {
        // A name this host cannot carry beneath the working tree's handle is kept as the one entry
        // the status reported, so the content read names it as unsupported rather than this walk
        // dropping it.
        out.push(kr_project::workspace::StatusEntry {
            path: prefix.to_owned(),
            class,
            change: ChangeKind::Present,
        });
        return Ok(());
    };
    let Ok(directory) = tree.subdirectory(&name) else {
        // Not a directory after all, or not reachable. It is still one entry the status reported,
        // and the content read decides what it is.
        out.push(kr_project::workspace::StatusEntry {
            path: prefix.to_owned(),
            class,
            change: ChangeKind::Present,
        });
        return Ok(());
    };
    let entries = directory
        .handle()
        .entries()
        .map_err(ChangeSetError::storage)?;
    for entry in entries {
        let entry = entry.map_err(ChangeSetError::storage)?;
        let file_name = entry.file_name().into_string().map_err(|_| {
            ChangeSetError::InvalidArgument(
                "this working tree holds a name this host cannot read as text, so it cannot say \
                 what that path holds"
                    .into(),
            )
        })?;
        let child = format!("{prefix}/{file_name}");
        let kind = entry.file_type().map_err(ChangeSetError::storage)?;
        if kind.is_dir() {
            walk(tree, &child, class, grant, out, budget, depth + 1)?;
            continue;
        }
        if *budget == 0 {
            return Err(ChangeSetError::QuotaExceeded {
                detail: format!(
                    "this capture would walk into more than {MAX_WALK_ENTRIES} paths that Git \
                     reported as whole directories; narrow the grant or the policy"
                )
                .into(),
            });
        }
        *budget -= 1;
        // A link, a socket or a device is not file content. It is kept as an entry so the content
        // read names it as unsupported rather than leaving it out with no record.
        out.push(kr_project::workspace::StatusEntry {
            path: child,
            class,
            change: ChangeKind::Present,
        });
    }
    Ok(())
}

/// What the capture decided to do about one path, before anything is opened.
#[derive(Clone, Debug)]
enum Plan {
    /// Read it from the working tree.
    WorkingTree {
        class: PathClass,
        change: ChangeKind,
        base_object_id: Option<String>,
        index_mode: Option<String>,
    },
    /// Read it from this immutable Git object.
    GitObject {
        class: PathClass,
        object_id: String,
        mode: String,
    },
    /// Leave it out, for this reason.
    Exclude {
        reason: ExclusionReason,
        detail: String,
    },
}

/// Decides what to do about every path, from the index, the base difference and the status alone.
///
/// Nothing is opened here. That is the point: the grant and the secret rules decide before the
/// capture reads anything, so a secret is never read, let alone stored.
fn plan(reading: &Reading, request: &CaptureRequest<'_>) -> BTreeMap<String, Plan> {
    let mut planned: BTreeMap<String, Plan> = BTreeMap::new();
    let status: BTreeMap<&str, &kr_project::workspace::StatusEntry> = reading
        .status
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();

    // Every path the base revision holds, and every tracked path the working tree holds.
    let mut tracked: Vec<&String> = reading.index.keys().collect();
    let from_base: Vec<&String> = reading.differences.keys().collect();
    tracked.extend(from_base);
    tracked.sort_unstable();
    tracked.dedup();

    for path in tracked {
        if let Some(refusal) = refused(request.grant, path) {
            planned.insert(path.clone(), refusal);
            continue;
        }
        let index = reading.index.get(path);
        if index.is_some_and(|entry| entry.mode == "160000")
            || reading
                .differences
                .get(path)
                .is_some_and(|difference| difference.base_mode.as_deref() == Some("160000"))
        {
            planned.insert(path.clone(), unsupported_submodule());
            continue;
        }
        if index.is_some_and(|entry| entry.stage != 0) {
            planned.insert(path.clone(), unresolved_merge());
            continue;
        }
        let Some(difference) = reading.differences.get(path) else {
            // The working tree holds what the base holds. Its content can come from either side;
            // an ordinary capture reads the file, which is one open rather than one process.
            let base = reading.base_of(path);
            planned.insert(
                path.clone(),
                Plan::WorkingTree {
                    class: PathClass::Tracked,
                    change: ChangeKind::Present,
                    base_object_id: base.as_ref().map(|(_, object_id)| object_id.clone()),
                    index_mode: index.map(|entry| entry.mode.clone()),
                },
            );
            continue;
        };
        planned.insert(
            path.clone(),
            plan_difference(
                reading,
                path,
                difference,
                index,
                status.get(path.as_str()),
                request,
            ),
        );
    }

    // Everything the status reports that neither the index nor the base holds: untracked and
    // ignored paths.
    for entry in &reading.status {
        if planned.contains_key(&entry.path) {
            continue;
        }
        if let Some(refusal) = refused(request.grant, &entry.path) {
            planned.insert(entry.path.clone(), refusal);
            continue;
        }
        let class = match entry.class {
            InclusionClass::UntrackedFile => PathClass::UntrackedFile,
            InclusionClass::GeneratedArtefact => PathClass::GeneratedArtefact,
            InclusionClass::Submodule => PathClass::Submodule,
            _ => PathClass::DirtyFile,
        };
        if class == PathClass::Submodule {
            planned.insert(entry.path.clone(), unsupported_submodule());
            continue;
        }
        let choice = match class {
            PathClass::UntrackedFile => request.policy.untracked_files,
            PathClass::GeneratedArtefact => request.policy.generated_artefacts,
            _ => InclusionChoice::Exclude,
        };
        if choice == InclusionChoice::Exclude {
            planned.insert(
                entry.path.clone(),
                Plan::Exclude {
                    reason: ExclusionReason::Policy,
                    detail: format!(
                        "the policy excludes {}, and the base revision does not hold this path",
                        class.as_str()
                    ),
                },
            );
            continue;
        }
        planned.insert(
            entry.path.clone(),
            Plan::WorkingTree {
                class,
                change: entry.change,
                base_object_id: None,
                index_mode: None,
            },
        );
    }
    planned
}

/// Decides what to do about one path whose working tree differs from the base revision.
fn plan_difference(
    reading: &Reading,
    path: &str,
    difference: &BaseDifference,
    index: Option<&IndexEntry>,
    status: Option<&&kr_project::workspace::StatusEntry>,
    request: &CaptureRequest<'_>,
) -> Plan {
    if difference.status == 'U' || status.is_some_and(|entry| entry.change == ChangeKind::Unmerged)
    {
        return unresolved_merge();
    }
    let base = reading.base_of(path);
    if request.policy.dirty_files == InclusionChoice::Exclude {
        // Excluding a dirty tracked file means the captured tree holds the **base's** version, not
        // that the path is absent. A path the base does not hold at all is simply absent, which is
        // what a staged or unstaged addition is.
        return match base {
            Some((mode, object_id)) => {
                if REGULAR_MODES.contains(&mode.as_str()) {
                    Plan::GitObject {
                        class: PathClass::Tracked,
                        object_id,
                        mode,
                    }
                } else {
                    unsupported_mode(&mode)
                }
            }
            None => Plan::Exclude {
                reason: ExclusionReason::Policy,
                detail: "the policy excludes uncommitted changes, and the base revision does not \
                         hold this path"
                    .to_owned(),
            },
        };
    }
    if difference.status == 'D' {
        return Plan::Exclude {
            reason: ExclusionReason::Deleted,
            detail: "the working tree has deleted this path and the capture carries the deletion"
                .to_owned(),
        };
    }
    Plan::WorkingTree {
        class: PathClass::DirtyFile,
        change: status.map_or(ChangeKind::Present, |entry| entry.change),
        base_object_id: base.map(|(_, object_id)| object_id),
        index_mode: index.map(|entry| entry.mode.clone()),
    }
}

fn unsupported_submodule() -> Plan {
    Plan::Exclude {
        reason: ExclusionReason::Unsupported,
        detail: "a submodule's own working tree is not captured, because this host never reads \
                 inside one"
            .to_owned(),
    }
}

fn unresolved_merge() -> Plan {
    Plan::Exclude {
        reason: ExclusionReason::Unsupported,
        detail: "this path has an unresolved merge, so there is no single content a version could \
                 hold for it"
            .to_owned(),
    }
}

fn unsupported_mode(mode: &str) -> Plan {
    Plan::Exclude {
        reason: ExclusionReason::Unsupported,
        detail: format!(
            "this path is recorded with mode {}, which is not file content: writing its object \
             out as a regular file would make a materialisation a different tree",
            kr_project::git::redact(mode)
        ),
    }
}

/// Returns the refusal a grant or a secret rule makes, when it makes one.
fn refused(granted: &FileGrant, path: &str) -> Option<Plan> {
    match grant::decide(granted, path) {
        GrantDecision::Permitted => None,
        GrantDecision::Refused(ExclusionReason::SecretRule) => Some(Plan::Exclude {
            reason: ExclusionReason::SecretRule,
            detail: "a secret rule covers this path, so this host did not open it".to_owned(),
        }),
        GrantDecision::Refused(ExclusionReason::Unsupported) => Some(Plan::Exclude {
            reason: ExclusionReason::Unsupported,
            detail: "this path is a repository's own administrative data rather than its content"
                .to_owned(),
        }),
        GrantDecision::Refused(reason) => Some(Plan::Exclude {
            reason,
            detail: "the file grant does not select this path".to_owned(),
        }),
    }
}

/// How much of the capture's budget is left.
struct Budget {
    bytes: u64,
    objects: usize,
}

impl Budget {
    fn charge(&mut self, bytes: u64) -> Result<()> {
        self.bytes =
            self.bytes
                .checked_sub(bytes)
                .ok_or_else(|| {
                    ChangeSetError::QuotaExceeded {
                detail: format!(
                    "this capture would hold more than {MAX_CAPTURE_BYTES} bytes, which is more \
                     than one capture holds"
                )
                .into(),
            }
                })?;
        Ok(())
    }
}

/// Reads the content of every planned path and builds the manifest.
fn read_content(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    store: &ObjectStore,
    planned: &BTreeMap<String, Plan>,
    request: &CaptureRequest<'_>,
) -> Result<Manifest> {
    let object_reads = planned
        .values()
        .filter(|plan| matches!(plan, Plan::GitObject { .. }))
        .count();
    if object_reads > MAX_OBJECT_READS {
        return Err(ChangeSetError::QuotaExceeded {
            detail: format!(
                "this capture would read {object_reads} paths from Git objects and one capture \
                 reads at most {MAX_OBJECT_READS}; narrow the grant, or capture the working tree \
                 as the source"
            )
            .into(),
        });
    }
    let mut budget = Budget {
        bytes: MAX_CAPTURE_BYTES,
        objects: MAX_OBJECT_READS,
    };
    let mut manifest = Manifest {
        paths: Vec::new(),
        exclusions: Vec::new(),
    };
    for (path, plan) in planned {
        match plan {
            Plan::Exclude { reason, detail } => manifest.exclusions.push(Exclusion {
                path: path.clone(),
                reason: *reason,
                detail: detail.clone(),
            }),
            Plan::GitObject {
                class,
                object_id,
                mode,
            } => {
                if !REGULAR_MODES.contains(&mode.as_str()) {
                    manifest
                        .exclusions
                        .push(exclusion(path, &unsupported_mode(mode)));
                    continue;
                }
                budget.objects = budget.objects.saturating_sub(1);
                let bytes = read_object(profile, repository, object_id)?;
                let content = classify_content(&bytes);
                if leave_out_binary(request, *class, content) {
                    manifest.exclusions.push(binary_exclusion(path));
                    continue;
                }
                budget.charge(bytes.len() as u64)?;
                let digest = store.put(&bytes)?;
                manifest.paths.push(CapturedPath {
                    path: path.clone(),
                    content_digest: digest,
                    byte_len: U64::new(bytes.len() as u64),
                    executable: mode == "100755",
                    content,
                    origin: ContentOrigin::GitObject,
                    class: *class,
                    change: ChangeKind::Present,
                    base_object_id: Nullable(Some(object_id.clone())),
                });
            }
            Plan::WorkingTree {
                class,
                change,
                base_object_id,
                index_mode,
            } => match read_working_tree(repository, path)? {
                WorkingRead::Gone => manifest.exclusions.push(Exclusion {
                    path: path.clone(),
                    reason: ExclusionReason::Deleted,
                    detail: "the working tree no longer holds this path".to_owned(),
                }),
                WorkingRead::Unsupported(detail) => manifest.exclusions.push(Exclusion {
                    path: path.clone(),
                    reason: ExclusionReason::Unsupported,
                    detail,
                }),
                WorkingRead::Unreadable(detail) => manifest.exclusions.push(Exclusion {
                    path: path.clone(),
                    reason: ExclusionReason::Unreadable,
                    detail,
                }),
                WorkingRead::Content { bytes, executable } => {
                    let content = classify_content(&bytes);
                    if leave_out_binary(request, *class, content) {
                        manifest.exclusions.push(binary_exclusion(path));
                        continue;
                    }
                    budget.charge(bytes.len() as u64)?;
                    let digest = store.put(&bytes)?;
                    manifest.paths.push(CapturedPath {
                        path: path.clone(),
                        content_digest: digest,
                        byte_len: U64::new(bytes.len() as u64),
                        // The bit the file actually has. A platform with none answers from the
                        // mode Git records, which is the only thing there is to answer from.
                        executable: executable
                            .unwrap_or_else(|| index_mode.as_deref() == Some("100755")),
                        content,
                        origin: ContentOrigin::WorkingTree,
                        class: *class,
                        change: *change,
                        base_object_id: Nullable(base_object_id.clone()),
                    });
                }
            },
        }
    }
    manifest.canonicalise();
    Ok(manifest)
}

/// Turns one exclusion plan into the record a version carries.
fn exclusion(path: &str, plan: &Plan) -> Exclusion {
    let Plan::Exclude { reason, detail } = plan else {
        unreachable!("only an exclusion plan becomes an exclusion");
    };
    Exclusion {
        path: path.to_owned(),
        reason: *reason,
        detail: detail.clone(),
    }
}

fn binary_exclusion(path: &str) -> Exclusion {
    Exclusion {
        path: path.to_owned(),
        reason: ExclusionReason::Policy,
        detail: "the policy excludes binary content".to_owned(),
    }
}

/// Returns true when the policy excludes this path for holding binary content.
///
/// A binary exclusion cuts across the other classes: a dirty file may be binary, and a policy that
/// includes dirty files and excludes binaries leaves that one out. An ordinary tracked file is not
/// subject to it, because leaving it out would make the captured tree short of the base rather
/// than short of a change.
fn leave_out_binary(request: &CaptureRequest<'_>, class: PathClass, content: ContentClass) -> bool {
    class.is_change()
        && content == ContentClass::Binary
        && request.policy.binary_files == InclusionChoice::Exclude
}

/// What reading one working-tree path came to.
pub enum WorkingRead {
    /// The content, and the executable bit where the platform has one.
    Content {
        /// The bytes, exactly as the file holds them.
        bytes: Vec<u8>,
        /// Whether the file is executable, or nothing on a platform with no such bit.
        executable: Option<bool>,
    },
    /// The path is not there.
    Gone,
    /// It is not file content: a link, a device, a socket, or a name this host cannot carry.
    Unsupported(String),
    /// This host could not read it.
    Unreadable(String),
}

/// Reads one path from the working tree through the authorised handle.
///
/// The file's identity, length and modification instant are read before and after its content. A
/// file that changed while this host was reading it is re-read up to [`MAX_PATH_RETRIES`] times
/// and then rejected, because a captured tree that held half of one version and half of another
/// would be a tree that never existed.
///
/// # Errors
///
/// Returns [`ChangeSetError::SourceChanged`] when the file kept changing past the bound, and
/// [`ChangeSetError::QuotaExceeded`] when it is larger than [`MAX_CAPTURE_FILE_BYTES`].
pub fn read_working_tree(repository: &OpenedRepository, path: &str) -> Result<WorkingRead> {
    let Ok(name) = RelativeName::parse(path) else {
        return Ok(WorkingRead::Unsupported(
            "this host cannot name this path beneath the working tree's own handle, so it cannot \
             read it and does not guess at it"
                .to_owned(),
        ));
    };
    let tree = repository.work_tree();
    for attempt in 0..=MAX_PATH_RETRIES {
        let mut file = match tree.open_read(&name, ObjectPolicy::ReadableFile) {
            Ok(file) => file,
            Err(kr_transfer::Escape::NotFound { .. }) => return Ok(WorkingRead::Gone),
            Err(
                error @ (kr_transfer::Escape::Link { .. } | kr_transfer::Escape::WrongKind { .. }),
            ) => {
                return Ok(WorkingRead::Unsupported(error.to_string()));
            }
            Err(error) => return Ok(WorkingRead::Unreadable(error.to_string())),
        };
        let before_identity = file.identity();
        let before_len = file.byte_len();
        if before_len > MAX_CAPTURE_FILE_BYTES {
            return Err(ChangeSetError::QuotaExceeded {
                detail: format!(
                    "one file of this working tree is {before_len} bytes and this host reads at \
                     most {MAX_CAPTURE_FILE_BYTES} into a captured tree"
                )
                .into(),
            });
        }
        let before_written = modified_at(&file);
        let executable = is_executable(&file);
        let mut bytes = Vec::with_capacity(usize::try_from(before_len).unwrap_or(0));
        // Bounded by one more byte than the bound, so a file that grows while it is being read is
        // refused rather than read without end.
        let mut bounded = file.handle_mut().take(MAX_CAPTURE_FILE_BYTES + 1);
        if let Err(error) = bounded.read_to_end(&mut bytes) {
            return Ok(WorkingRead::Unreadable(error.to_string()));
        }
        if bytes.len() as u64 > MAX_CAPTURE_FILE_BYTES {
            return Err(ChangeSetError::QuotaExceeded {
                detail: format!(
                    "one file of this working tree grew past {MAX_CAPTURE_FILE_BYTES} bytes while \
                     this host was reading it"
                )
                .into(),
            });
        }
        // The same open handle is asked again, so what is compared is the object this host read
        // rather than whatever the name now resolves to. The modification instant is compared
        // beside the length, because an overwrite in place of the same number of bytes changes
        // neither the identity nor the length and is exactly the change a reader would miss.
        let after_len = match file.revalidate() {
            Ok(length) => length,
            Err(error) => return Ok(WorkingRead::Unreadable(error.to_string())),
        };
        if file.identity() == before_identity
            && after_len == before_len
            && after_len == bytes.len() as u64
            && modified_at(&file) == before_written
        {
            return Ok(WorkingRead::Content { bytes, executable });
        }
        if attempt == MAX_PATH_RETRIES {
            return Err(ChangeSetError::SourceChanged {
                detail: format!(
                    "a path changed while this host was reading it, {} times in a row",
                    MAX_PATH_RETRIES + 1
                )
                .into(),
            });
        }
    }
    unreachable!("the loop returns on its last attempt")
}

/// Returns when a file was last written, as far as the platform will say.
fn modified_at(file: &kr_transfer::AuthorisedFile) -> Option<cap_std::time::SystemTime> {
    file.handle()
        .metadata()
        .ok()
        .and_then(|metadata| metadata.modified().ok())
}

/// Returns whether a file the working tree holds is executable.
#[cfg(unix)]
fn is_executable(file: &kr_transfer::AuthorisedFile) -> Option<bool> {
    use cap_std::fs::PermissionsExt as _;
    file.handle()
        .metadata()
        .ok()
        .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
}

/// Returns nothing: this platform has no executable bit on a file.
///
/// The mode Git records is what decides there, and the caller uses it.
#[cfg(not(unix))]
fn is_executable(_file: &kr_transfer::AuthorisedFile) -> Option<bool> {
    None
}

/// Refuses an identifier that is not one.
///
/// It reaches an argument vector, so it is checked rather than trusted: a name that is not
/// hexadecimal is not an object identifier, and a leading `-` is an option.
fn check_object_id(object_id: &str) -> Result<()> {
    if object_id.is_empty() || !object_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ChangeSetError::InvalidArgument(
            "this repository reported something that is not an object identifier".into(),
        ));
    }
    Ok(())
}

/// Reads one immutable Git object's content.
///
/// # Errors
///
/// Returns [`ChangeSetError::InvalidArgument`] when the identifier is not one, and whatever the
/// project service returns for a failed invocation.
pub fn read_object(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    object_id: &str,
) -> Result<Vec<u8>> {
    check_object_id(object_id)?;
    let arguments: [&OsStr; 3] = [
        OsStr::new("cat-file"),
        OsStr::new("blob"),
        OsStr::new(object_id),
    ];
    let output = profile.run(&repository.read(&arguments))?;
    output.require_success()?;
    output.require_complete()?;
    if output.stdout.len() as u64 > MAX_CAPTURE_FILE_BYTES {
        return Err(ChangeSetError::QuotaExceeded {
            detail: format!(
                "one object of this repository is larger than the {MAX_CAPTURE_FILE_BYTES} bytes \
                 this host reads into a captured tree"
            )
            .into(),
        });
    }
    Ok(output.stdout.clone())
}

/// One entry of one Git tree object.
#[derive(Clone, Debug)]
struct TreeEntry {
    mode: String,
    kind: String,
    object_id: String,
    name: String,
}

/// Reads one immutable Git tree object.
fn read_tree(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    object_id: &str,
) -> Result<Vec<TreeEntry>> {
    check_object_id(object_id)?;
    let arguments: [&OsStr; 3] = [
        OsStr::new("cat-file"),
        OsStr::new("-p"),
        OsStr::new(object_id),
    ];
    let output = profile.run(&repository.read(&arguments))?;
    output.require_success()?;
    output.require_complete()?;
    let text = exactly(&output.stdout, "one of this repository's own trees")?;
    let mut entries = Vec::new();
    for line in text.lines() {
        // `<mode> <type> <object>\t<name>`
        let Some((fields, name)) = line.split_once('\t') else {
            continue;
        };
        let parts: Vec<&str> = fields.split(' ').collect();
        if parts.len() < 3 || name.is_empty() {
            continue;
        }
        entries.push(TreeEntry {
            mode: parts[0].to_owned(),
            kind: parts[1].to_owned(),
            object_id: parts[2].to_owned(),
            name: name.to_owned(),
        });
    }
    Ok(entries)
}

/// Captures the base commit's own tree, from immutable objects and nothing else.
///
/// This is what [`SourceConsistency::AtomicSnapshot`] rests on. The commit names one tree, that
/// tree names its children, and every one of them is immutable, so the whole listing is one
/// instant by construction. Nothing of the working tree or the index is read.
fn snapshot(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    store: &ObjectStore,
    request: &CaptureRequest<'_>,
) -> Result<Captured> {
    // A policy that would include uncommitted work cannot be served from a commit, and serving it
    // a weaker class under the name it asked for is exactly what section 14 forbids.
    for (choice, what) in [
        (request.policy.dirty_files, "uncommitted changes"),
        (request.policy.untracked_files, "untracked files"),
        (request.policy.generated_artefacts, "ignored files"),
    ] {
        if choice == InclusionChoice::Include {
            return Err(ChangeSetError::InvalidArgument(
                format!(
                    "an atomic snapshot is a capture of the base commit's own tree, and {what} \
                     are in no Git object of it; ask for a per-file capture, or exclude them"
                )
                .into(),
            ));
        }
    }
    let (revision, reference) = repository.head(profile)?;
    let Some(revision) = revision else {
        return Err(ChangeSetError::InvalidArgument(
            "this repository has no commit yet, so there is no base revision a version could be \
             captured against; commit once and capture again"
                .into(),
        ));
    };
    let root = format!("{revision}^{{tree}}");
    let arguments: [&OsStr; 3] = [
        OsStr::new("rev-parse"),
        OsStr::new("--verify"),
        OsStr::new(&root),
    ];
    let reported = profile.run_checked(&repository.read(&arguments))?;
    let tree_id = reported.trim().to_owned();
    check_object_id(&tree_id)?;
    let mut manifest = Manifest {
        paths: Vec::new(),
        exclusions: Vec::new(),
    };
    let mut budget = Budget {
        bytes: MAX_CAPTURE_BYTES,
        objects: MAX_OBJECT_READS,
    };
    descend(
        profile,
        repository,
        store,
        &tree_id,
        "",
        request,
        &mut manifest,
        &mut budget,
        0,
    )?;
    manifest.canonicalise();
    // The commit is immutable, and this confirms that what was walked is the commit the version
    // names: a reference that moved under the capture would otherwise leave a version whose base
    // is one commit and whose tree is another's.
    let (again, _) = repository.head(profile)?;
    if again.as_deref() != Some(revision.as_str()) {
        return Err(changed(
            "a commit landed while this host was reading the base revision's own tree",
        ));
    }
    let objects = distinct_objects(&manifest);
    Ok(Captured {
        manifest,
        base_revision: revision,
        base_reference: reference,
        consistency: SourceConsistency::AtomicSnapshot,
        consistency_detail:
            "every captured path came from the base commit's own tree: the commit names one \
             immutable tree object, each tree names its children, and every blob under them is \
             immutable, so the whole listing is one instant by construction. Nothing of the \
             working tree or the index was read"
                .to_owned(),
        objects,
    })
}

/// Walks one immutable tree object and everything beneath it.
#[allow(clippy::too_many_arguments)]
fn descend(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    store: &ObjectStore,
    tree_id: &str,
    prefix: &str,
    request: &CaptureRequest<'_>,
    manifest: &mut Manifest,
    budget: &mut Budget,
    depth: usize,
) -> Result<()> {
    if depth >= MAX_WALK_DEPTH {
        return Err(ChangeSetError::QuotaExceeded {
            detail: format!(
                "the base revision's own tree is more than {MAX_WALK_DEPTH} levels deep, and this \
                 host does not capture a tree it cannot walk to the bottom of"
            )
            .into(),
        });
    }
    for entry in read_tree(profile, repository, tree_id)? {
        let path = if prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{prefix}/{}", entry.name)
        };
        if let Some(plan) = refused(request.grant, &path) {
            manifest.exclusions.push(exclusion(&path, &plan));
            continue;
        }
        if entry.kind == "tree" {
            descend(
                profile,
                repository,
                store,
                &entry.object_id,
                &path,
                request,
                manifest,
                budget,
                depth + 1,
            )?;
            continue;
        }
        if !REGULAR_MODES.contains(&entry.mode.as_str()) {
            manifest
                .exclusions
                .push(exclusion(&path, &unsupported_mode(&entry.mode)));
            continue;
        }
        if budget.objects == 0 {
            return Err(ChangeSetError::QuotaExceeded {
                detail: format!(
                    "the base revision's own tree holds more than {MAX_OBJECT_READS} paths, and \
                     one capture reads at most that many Git objects; narrow the grant"
                )
                .into(),
            });
        }
        budget.objects -= 1;
        let bytes = read_object(profile, repository, &entry.object_id)?;
        let content = classify_content(&bytes);
        if content == ContentClass::Binary
            && request.policy.binary_files == InclusionChoice::Exclude
        {
            manifest.exclusions.push(binary_exclusion(&path));
            continue;
        }
        budget.charge(bytes.len() as u64)?;
        let digest = store.put(&bytes)?;
        manifest.paths.push(CapturedPath {
            path,
            content_digest: digest,
            byte_len: U64::new(bytes.len() as u64),
            executable: entry.mode == "100755",
            content,
            origin: ContentOrigin::GitObject,
            class: PathClass::Tracked,
            change: ChangeKind::Present,
            base_object_id: Nullable(Some(entry.object_id)),
        });
    }
    Ok(())
}

/// Returns what one path's content is, by Git's own test.
///
/// A null byte in the first eight thousand bytes of the content as it is stored. A
/// `.gitattributes` declaration is not consulted, because what the repository declares must not
/// decide what this host reads.
#[must_use]
pub fn classify_content(bytes: &[u8]) -> ContentClass {
    let window = &bytes[..bytes.len().min(kr_project::workspace::BINARY_SCAN_BYTES)];
    if window.contains(&0) {
        ContentClass::Binary
    } else {
        ContentClass::Text
    }
}

/// Decides the consistency class from what the capture actually did.
///
/// A capture that read the live working tree is a per-file capture unless a real mechanism made it
/// something stronger, and the only stronger mechanism here is the one behind [`QuiescenceProbe`]:
/// the caller stopped its own work **and** this host found nothing it knows of holding the
/// workspace, before and after the read.
fn classify(request: &CaptureRequest<'_>, quiet: bool) -> (SourceConsistency, String) {
    if request.quiescence_declared && quiet {
        return (
            SourceConsistency::QuiescedCapture,
            "the caller declared the working tree quiesced, no session and no automation run this \
             host knows of held the workspace before or after the read, and every file was the \
             same object of the same length written at the same instant after its read as before \
             it, with the base revision, the index and the status unchanged at the end. What this \
             does not exclude is an editor outside KalaReach, which nothing this host can read \
             would show"
                .to_owned(),
        );
    }
    let mut detail = "files were read one at a time from a live working tree; each one was the \
                      same object of the same length written at the same instant after its read \
                      as before it, and the base revision, the index and the status were \
                      unchanged at the end, which is detection rather than one instant"
        .to_owned();
    if request.quiescence_declared && !quiet {
        detail.push_str(
            ". The caller declared the working tree quiesced and this host found a session or an \
             automation run holding the workspace, so the declaration alone did not decide the \
             class",
        );
    }
    (SourceConsistency::PerFileCapture, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        path: &str,
        class: InclusionClass,
        change: ChangeKind,
    ) -> kr_project::workspace::StatusEntry {
        kr_project::workspace::StatusEntry {
            path: path.to_owned(),
            class,
            change,
        }
    }

    fn index(items: &[(&str, &str, &str, u32)]) -> BTreeMap<String, IndexEntry> {
        items
            .iter()
            .map(|(path, mode, object_id, stage)| {
                (
                    (*path).to_owned(),
                    IndexEntry {
                        mode: (*mode).to_owned(),
                        object_id: (*object_id).to_owned(),
                        stage: *stage,
                    },
                )
            })
            .collect()
    }

    fn differences(
        items: &[(&str, Option<&str>, Option<&str>, char)],
    ) -> BTreeMap<String, BaseDifference> {
        items
            .iter()
            .map(|(path, mode, object_id, status)| {
                (
                    (*path).to_owned(),
                    BaseDifference {
                        base_mode: mode.map(std::string::ToString::to_string),
                        base_object_id: object_id.map(std::string::ToString::to_string),
                        status: *status,
                    },
                )
            })
            .collect()
    }

    fn reading(
        index: BTreeMap<String, IndexEntry>,
        differences: BTreeMap<String, BaseDifference>,
        status: Vec<kr_project::workspace::StatusEntry>,
    ) -> Reading {
        Reading {
            revision: "abcdef".to_owned(),
            reference: Some("refs/heads/main".to_owned()),
            index,
            differences,
            status,
        }
    }

    fn request<'a>(policy: &'a InclusionPolicy, granted: &'a FileGrant) -> CaptureRequest<'a> {
        CaptureRequest {
            policy,
            grant: granted,
            quiescence_declared: false,
            required_consistency: None,
        }
    }

    #[test]
    fn a_secret_is_left_out_before_anything_is_opened() {
        // The plan is built from the index, the base difference and the status alone. A secret's
        // entry is an exclusion there, so nothing downstream ever names it as something to read.
        let policy = InclusionPolicy {
            dirty_files: InclusionChoice::Include,
            untracked_files: InclusionChoice::Include,
            submodules: InclusionChoice::Include,
            binary_files: InclusionChoice::Include,
            generated_artefacts: InclusionChoice::Include,
        };
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                index(&[
                    ("src/main.rs", "100644", "aaaa", 0),
                    (".env", "100644", "bbbb", 0),
                ]),
                differences(&[(".env", Some("100644"), Some("bbbb"), 'M')]),
                vec![entry(
                    ".env",
                    InclusionClass::DirtyFile,
                    ChangeKind::Present,
                )],
            ),
            &request(&policy, &granted),
        );
        assert!(matches!(
            planned[".env"],
            Plan::Exclude {
                reason: ExclusionReason::SecretRule,
                ..
            }
        ));
        assert!(matches!(planned["src/main.rs"], Plan::WorkingTree { .. }));
    }

    #[test]
    fn excluding_uncommitted_changes_holds_the_base_commit_rather_than_the_index() {
        // The whole of the base-is-the-commit rule: what an exclusion falls back to is the object
        // the **revision** holds, which `git diff --raw` reports, and never the index's.
        let policy = InclusionPolicy::base_only();
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                // The index holds `staged`, which is neither the commit's content nor the working
                // tree's.
                index(&[("README.md", "100644", "staged", 0)]),
                differences(&[("README.md", Some("100644"), Some("committed"), 'M')]),
                vec![entry(
                    "README.md",
                    InclusionClass::DirtyFile,
                    ChangeKind::Present,
                )],
            ),
            &request(&policy, &granted),
        );
        match &planned["README.md"] {
            Plan::GitObject {
                class, object_id, ..
            } => {
                assert_eq!(*class, PathClass::Tracked);
                assert_eq!(
                    object_id, "committed",
                    "the base is the commit, not the index"
                );
            }
            other => panic!("the base's own object is what is read: {other:?}"),
        }
    }

    #[test]
    fn a_staged_addition_is_absent_when_uncommitted_changes_are_excluded() {
        // The base never held it, so excluding uncommitted changes leaves nothing to fall back to.
        let policy = InclusionPolicy::base_only();
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                index(&[("added.txt", "100644", "staged", 0)]),
                differences(&[("added.txt", None, None, 'A')]),
                vec![entry(
                    "added.txt",
                    InclusionClass::DirtyFile,
                    ChangeKind::Present,
                )],
            ),
            &request(&policy, &granted),
        );
        assert!(matches!(
            planned["added.txt"],
            Plan::Exclude {
                reason: ExclusionReason::Policy,
                ..
            }
        ));
    }

    #[test]
    fn a_staged_deletion_keeps_the_base_version_when_uncommitted_changes_are_excluded() {
        // The path is gone from the index and from the working tree, and the base holds it, so an
        // exclusion of the deletion means the captured tree holds what the commit has.
        let policy = InclusionPolicy::base_only();
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                index(&[]),
                differences(&[("gone.txt", Some("100644"), Some("committed"), 'D')]),
                vec![entry(
                    "gone.txt",
                    InclusionClass::DirtyFile,
                    ChangeKind::Deleted,
                )],
            ),
            &request(&policy, &granted),
        );
        match &planned["gone.txt"] {
            Plan::GitObject { object_id, .. } => assert_eq!(object_id, "committed"),
            other => panic!("the base's own object is what is read: {other:?}"),
        }
    }

    #[test]
    fn an_excluded_untracked_path_is_absent_because_the_base_never_held_it() {
        let policy = InclusionPolicy::base_only();
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                index(&[]),
                differences(&[]),
                vec![entry(
                    "notes.txt",
                    InclusionClass::UntrackedFile,
                    ChangeKind::Present,
                )],
            ),
            &request(&policy, &granted),
        );
        assert!(matches!(
            planned["notes.txt"],
            Plan::Exclude {
                reason: ExclusionReason::Policy,
                ..
            }
        ));
    }

    #[test]
    fn a_deletion_the_policy_includes_is_carried_by_absence_and_named() {
        let policy = InclusionPolicy {
            dirty_files: InclusionChoice::Include,
            ..InclusionPolicy::base_only()
        };
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                index(&[]),
                differences(&[("gone.txt", Some("100644"), Some("committed"), 'D')]),
                vec![entry(
                    "gone.txt",
                    InclusionClass::DirtyFile,
                    ChangeKind::Deleted,
                )],
            ),
            &request(&policy, &granted),
        );
        assert!(matches!(
            planned["gone.txt"],
            Plan::Exclude {
                reason: ExclusionReason::Deleted,
                ..
            }
        ));
    }

    #[test]
    fn an_unresolved_merge_is_never_captured_as_one_content() {
        let policy = InclusionPolicy {
            dirty_files: InclusionChoice::Include,
            ..InclusionPolicy::base_only()
        };
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                index(&[("merged.txt", "100644", "abcdef", 2)]),
                differences(&[("merged.txt", Some("100644"), Some("committed"), 'U')]),
                vec![entry(
                    "merged.txt",
                    InclusionClass::DirtyFile,
                    ChangeKind::Unmerged,
                )],
            ),
            &request(&policy, &granted),
        );
        assert!(matches!(
            planned["merged.txt"],
            Plan::Exclude {
                reason: ExclusionReason::Unsupported,
                ..
            }
        ));
    }

    #[test]
    fn a_submodule_is_never_entered_whatever_the_policy_says() {
        let policy = InclusionPolicy {
            submodules: InclusionChoice::Include,
            ..InclusionPolicy::base_only()
        };
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                index(&[("vendor/lib", "160000", "abcdef", 0)]),
                differences(&[]),
                Vec::new(),
            ),
            &request(&policy, &granted),
        );
        assert!(matches!(
            planned["vendor/lib"],
            Plan::Exclude {
                reason: ExclusionReason::Unsupported,
                ..
            }
        ));
    }

    #[test]
    fn a_mode_that_is_not_file_content_is_named_rather_than_written_out_as_a_file() {
        // A symbolic link's object holds its target. Writing that out as a regular file would make
        // a materialisation a different tree, so it is left out and said.
        let policy = InclusionPolicy::base_only();
        let granted = FileGrant::default();
        let planned = plan(
            &reading(
                index(&[("link", "120000", "target", 0)]),
                differences(&[("link", Some("120000"), Some("committed"), 'M')]),
                vec![entry(
                    "link",
                    InclusionClass::DirtyFile,
                    ChangeKind::Present,
                )],
            ),
            &request(&policy, &granted),
        );
        match &planned["link"] {
            Plan::Exclude { reason, detail } => {
                assert_eq!(*reason, ExclusionReason::Unsupported);
                assert!(
                    detail.contains("not file content"),
                    "the exclusion says why: {detail}"
                );
            }
            other => panic!("a link is not captured as a file: {other:?}"),
        }
    }

    #[test]
    fn a_path_whose_only_change_is_staged_has_no_base_object_this_host_read() {
        // The working tree matches the commit and the index does not, so the index's object is not
        // the base's and this host does not claim it is.
        let staged = reading(
            index(&[("README.md", "100644", "staged", 0)]),
            differences(&[]),
            vec![entry(
                "README.md",
                InclusionClass::DirtyFile,
                ChangeKind::Present,
            )],
        );
        assert_eq!(staged.base_of("README.md"), None);
        // With nothing staged, the index's object is the base's.
        let clean = reading(
            index(&[("README.md", "100644", "committed", 0)]),
            differences(&[]),
            Vec::new(),
        );
        assert_eq!(
            clean.base_of("README.md"),
            Some(("100644".to_owned(), "committed".to_owned()))
        );
    }

    #[test]
    fn a_quiescence_declaration_alone_never_decides_the_class() {
        let policy = InclusionPolicy::base_only();
        let granted = FileGrant::default();
        let declared = CaptureRequest {
            quiescence_declared: true,
            ..request(&policy, &granted)
        };
        let (class, detail) = classify(&declared, false);
        assert_eq!(class, SourceConsistency::PerFileCapture);
        assert!(
            detail.contains("the declaration alone did not decide the class"),
            "the detail says why: {detail}"
        );
        let (class, detail) = classify(&declared, true);
        assert_eq!(class, SourceConsistency::QuiescedCapture);
        assert!(
            detail.contains("no session and no automation run"),
            "the detail names the mechanism: {detail}"
        );
        assert!(
            detail.contains("an editor outside KalaReach"),
            "and the limit: {detail}"
        );
        // Without the declaration, quiet or not, it is a per-file capture.
        let (class, _) = classify(&request(&policy, &granted), true);
        assert_eq!(class, SourceConsistency::PerFileCapture);
    }

    #[test]
    fn content_is_binary_by_the_same_test_git_uses() {
        assert_eq!(classify_content(b"ordinary text\n"), ContentClass::Text);
        assert_eq!(classify_content(b"before\0after"), ContentClass::Binary);
        assert_eq!(classify_content(b""), ContentClass::Text);
        // A null byte past the scan window is past it, exactly as Git's own test has it.
        let mut far = vec![b'a'; kr_project::workspace::BINARY_SCAN_BYTES];
        far.push(0);
        assert_eq!(classify_content(&far), ContentClass::Text);
    }

    #[test]
    fn an_identifier_that_is_not_one_is_refused_before_it_reaches_an_argument_vector() {
        for value in ["--upload-pack=sh", "-c", "", "refs/heads/main", "zzzz"] {
            assert!(
                check_object_id(value).is_err(),
                "{value} is not an object identifier"
            );
        }
        assert!(check_object_id("abcdef0123456789").is_ok());
    }

    #[test]
    fn a_capture_larger_than_the_bound_is_refused_as_it_goes() {
        let mut budget = Budget {
            bytes: 10,
            objects: 4,
        };
        budget.charge(6).expect("the first file fits");
        let failure = budget
            .charge(6)
            .expect_err("the second takes it past the bound");
        assert!(
            failure.to_string().contains("more than"),
            "the refusal names the bound: {failure}"
        );
    }
}
