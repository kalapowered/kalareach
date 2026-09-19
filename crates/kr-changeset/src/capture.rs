//! `changeset.capture`: reading a working tree into an immutable version.
//!
//! Everything here goes through the project service. The repository is opened with
//! [`kr_project::OpenedRepository`], every Git invocation runs under
//! [`kr_project::ProjectService::profile`] inside the execution boundary, and every file is read
//! through [`kr_project::OpenedRepository::work_tree`], which is an open directory descriptor
//! rather than a path. A capture writes nothing into the user's repository.
//!
//! # What a capture reads, and in which order
//!
//! 1. `HEAD`, which is the base revision the version is against.
//! 2. `git ls-files --stage -z`, the index listing. **One invocation**, so the object identifiers
//!    it reports name one instant, and a Git object never changes once it exists.
//! 3. `git status --porcelain=v2 -z`, which says what the working tree holds that the base does
//!    not.
//! 4. The grant and the policy decide, path by path, **before anything is opened**. A path a
//!    secret rule covers is never opened at all.
//! 5. The content: from the working tree through the authorised handle, or from the immutable Git
//!    object with `git cat-file blob`.
//! 6. The index and the status again. A selection that changed underneath is retried within
//!    [`kr_protocol::changeset::MAX_CAPTURE_RETRIES`] and then rejected with `SOURCE_CHANGED`.
//!
//! # The three consistency classes, and which mechanism each rests on
//!
//! * [`SourceConsistency::AtomicSnapshot`] when **every** captured path's content came from a Git
//!   object named by that one index listing. That is a real point-in-time snapshot: one instant,
//!   immutable objects. A caller asks for it with `required_consistency`, and a working tree
//!   holding an uncommitted change the policy includes cannot reach it, because that change is in
//!   no Git object. Such a request is refused rather than served a weaker class under the name it
//!   asked for.
//! * [`SourceConsistency::QuiescedCapture`] when the caller declared the tree quiesced **and**
//!   this host observed no change: every file's identity and length unchanged across its own read,
//!   and the index and status identical afterwards. The declaration is the caller's and the
//!   verification is this host's, and the class asserts both.
//! * [`SourceConsistency::PerFileCapture`] otherwise. Files read one at a time from a live tree.
//!   The captured tree is still immutable and exactly identified; what it is not is one instant of
//!   the working tree, and this host does not say it is.
//!
//! No filesystem this service runs on offers an unprivileged atomic snapshot of a directory tree,
//! so there is no fourth mechanism and no capture is described as one.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::Read as _;

use kr_project::{OpenedRepository, RestrictedProfile};
use kr_protocol::changeset::{
    CapturedPath, ContentOrigin, Exclusion, ExclusionReason, FileGrant, MAX_CAPTURE_RETRIES,
    MAX_PATH_RETRIES, PathClass, SourceConsistency,
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
) -> Result<Captured> {
    let (revision, reference) = repository.head(profile)?;
    let Some(base_revision) = revision else {
        return Err(ChangeSetError::InvalidArgument(
            "this repository has no commit yet, so there is no base revision a version could be \
             captured against; commit once and capture again"
                .into(),
        ));
    };
    let mut last_change = String::new();
    for attempt in 0..=MAX_CAPTURE_RETRIES {
        let index = read_index(profile, repository)?;
        let status = read_status(profile, repository)?;
        let submodules = kr_project::workspace::submodule_paths(profile, repository)?;
        let plan = plan(&index, &status, &submodules, request);
        let read = read_content(profile, repository, store, &plan, request);
        let manifest = match read {
            Ok(manifest) => manifest,
            Err(ChangeSetError::SourceChanged { detail }) if attempt < MAX_CAPTURE_RETRIES => {
                last_change = detail.as_str().to_owned();
                continue;
            }
            Err(error) => return Err(error),
        };
        // The selection is read again. A file this host did not touch changing is exactly what a
        // per-file capture cannot exclude, and what it must not describe as one instant.
        let index_after = read_index(profile, repository)?;
        let status_after = read_status(profile, repository)?;
        if index_after != index || status_after != status {
            last_change =
                "the index or the working tree's status changed while this host was reading it"
                    .to_owned();
            if attempt < MAX_CAPTURE_RETRIES {
                continue;
            }
            return Err(ChangeSetError::SourceChanged {
                detail: format!(
                    "{last_change}, and this host tried {} times",
                    MAX_CAPTURE_RETRIES + 1
                )
                .into(),
            });
        }
        let (consistency, consistency_detail) = classify(&manifest, request);
        if let Some(required) = request.required_consistency
            && !consistency.satisfies(required)
        {
            return Err(ChangeSetError::InvalidArgument(
                format!(
                    "this capture's source is a {} and the request requires a {}: {consistency_detail}",
                    consistency.as_str(),
                    required.as_str()
                )
                .into(),
            ));
        }
        let objects = distinct_objects(&manifest);
        return Ok(Captured {
            manifest,
            base_revision,
            base_reference: reference,
            consistency,
            consistency_detail,
            objects,
        });
    }
    Err(ChangeSetError::SourceChanged {
        detail: format!(
            "{last_change}, and this host tried {} times",
            MAX_CAPTURE_RETRIES + 1
        )
        .into(),
    })
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

/// Reads `git ls-files --stage -z`, which is what the index holds for every tracked path.
///
/// One invocation, so every object identifier it reports names one instant. A path this host
/// cannot read as text is refused rather than approximated, for the reason the project service
/// refuses one: a name with a replacement character in it is a different name.
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
    let text = std::str::from_utf8(&output.stdout).map_err(|_| {
        ChangeSetError::InvalidArgument(
        "this repository's index holds a path this host cannot read as text, so it cannot say what \
         that path holds"
            .into(),
    )
    })?;
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

/// How many paths one capture walks into from a wholly ignored or untracked directory.
///
/// Git reports a directory nothing in it is tracked as **one** record with a trailing separator,
/// so a capture that took that record literally would hold a path that is a directory and would
/// miss every file under it. The walk expands it, and a tree deeper or wider than this is refused
/// with the figure rather than captured short.
pub const MAX_WALK_ENTRIES: usize = 200_000;

/// How deep one walk goes into such a directory.
pub const MAX_WALK_DEPTH: usize = 64;

/// Reads `git status --porcelain=v2 -z`, with the same arguments the project service uses.
///
/// A record whose path ends in a separator is a whole directory Git reported as one entry, and
/// this expands it into the files it holds, through the working tree's own handle.
///
/// # Errors
///
/// Returns whatever the project service returns for the invocation, and
/// [`ChangeSetError::QuotaExceeded`] when the walk would exceed [`MAX_WALK_ENTRIES`].
pub fn read_status(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
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
    let reported = profile.run_checked(&repository.read(&arguments))?;
    let entries = kr_project::workspace::parse_status(&reported)?;
    let mut expanded = Vec::with_capacity(entries.len());
    let mut budget = MAX_WALK_ENTRIES;
    for entry in entries {
        if let Some(prefix) = entry.path.strip_suffix('/') {
            walk(
                repository.work_tree(),
                prefix,
                entry.class,
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

/// Expands one directory entry into the files it holds.
///
/// The walk goes through the authorised directory handle, so nothing outside the working tree is
/// reached and a link is neither followed nor counted as content. A name this host could not read
/// is kept as the directory entry it came from rather than dropped, so nothing goes missing
/// silently.
fn walk(
    tree: &kr_transfer::AuthorisedDirectory,
    prefix: &str,
    class: InclusionClass,
    out: &mut Vec<kr_project::workspace::StatusEntry>,
    budget: &mut usize,
    depth: usize,
) -> Result<()> {
    if depth >= MAX_WALK_DEPTH {
        return Err(ChangeSetError::QuotaExceeded {
            detail: format!(
                "a directory this capture would read is more than {MAX_WALK_DEPTH} levels deep,                  and this host does not capture a tree it cannot walk to the bottom of"
            )
            .into(),
        });
    }
    let Ok(name) = RelativeName::parse(prefix) else {
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
                "this working tree holds a name this host cannot read as text, so it cannot say                  what that path holds"
                    .into(),
            )
        })?;
        let child = format!("{prefix}/{file_name}");
        let kind = entry.file_type().map_err(ChangeSetError::storage)?;
        if kind.is_dir() {
            walk(tree, &child, class, out, budget, depth + 1)?;
            continue;
        }
        if *budget == 0 {
            return Err(ChangeSetError::QuotaExceeded {
                detail: format!(
                    "this capture would walk into more than {MAX_WALK_ENTRIES} paths that Git                      reported as whole directories; narrow the grant or the policy"
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
        executable_in_index: bool,
    },
    /// Read it from this immutable Git object.
    GitObject {
        class: PathClass,
        object_id: String,
        executable: bool,
    },
    /// Leave it out, for this reason.
    Exclude {
        reason: ExclusionReason,
        detail: String,
    },
}

/// Decides what to do about every path, from the index and the status alone.
///
/// Nothing is opened here. That is the point: the grant and the secret rules decide before the
/// capture reads anything, so a secret is never read, let alone stored.
fn plan(
    index: &BTreeMap<String, IndexEntry>,
    status: &[kr_project::workspace::StatusEntry],
    submodules: &[String],
    request: &CaptureRequest<'_>,
) -> BTreeMap<String, Plan> {
    let mut planned: BTreeMap<String, Plan> = BTreeMap::new();
    let changed: BTreeMap<&str, &kr_project::workspace::StatusEntry> = status
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let wants_objects = request.required_consistency == Some(SourceConsistency::AtomicSnapshot);

    // Every tracked path, from the index listing.
    for (path, entry) in index {
        if let Some(refusal) = refused(request.grant, path) {
            planned.insert(path.clone(), refusal);
            continue;
        }
        if submodules.iter().any(|name| name == path) || entry.mode == "160000" {
            planned.insert(
                path.clone(),
                Plan::Exclude {
                    reason: ExclusionReason::Unsupported,
                    detail:
                        "a submodule's own working tree is not captured, because this host never \
                         reads inside one"
                            .to_owned(),
                },
            );
            continue;
        }
        let executable = entry.mode.ends_with("755");
        let Some(change) = changed.get(path.as_str()) else {
            // A tracked file with no uncommitted change. Its content is the base's own, so it can
            // come from either side; the Git object is what an atomic snapshot needs and the
            // working tree is one open rather than one process.
            planned.insert(
                path.clone(),
                if wants_objects {
                    Plan::GitObject {
                        class: PathClass::Tracked,
                        object_id: entry.object_id.clone(),
                        executable,
                    }
                } else {
                    Plan::WorkingTree {
                        class: PathClass::Tracked,
                        change: ChangeKind::Present,
                        base_object_id: Some(entry.object_id.clone()),
                        executable_in_index: executable,
                    }
                },
            );
            continue;
        };
        planned.insert(
            path.clone(),
            plan_tracked_change(change, entry, executable, request),
        );
    }

    // Everything the status reports that the index does not hold: untracked and ignored paths.
    for entry in status {
        if index.contains_key(&entry.path) || planned.contains_key(&entry.path) {
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
            planned.insert(
                entry.path.clone(),
                Plan::Exclude {
                    reason: ExclusionReason::Unsupported,
                    detail:
                        "a submodule's own working tree is not captured, because this host never \
                         reads inside one"
                            .to_owned(),
                },
            );
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
                executable_in_index: false,
            },
        );
    }
    planned
}

/// Decides what to do about one tracked path the working tree has changed.
fn plan_tracked_change(
    change: &kr_project::workspace::StatusEntry,
    entry: &IndexEntry,
    executable: bool,
    request: &CaptureRequest<'_>,
) -> Plan {
    let base = Plan::GitObject {
        class: PathClass::Tracked,
        object_id: entry.object_id.clone(),
        executable,
    };
    if entry.stage != 0 || change.change == ChangeKind::Unmerged {
        // An unresolved merge is not a version of anything. The index holds several stages and
        // the working tree holds a file with conflict markers in it; neither is the change the
        // user means. It is left out and named.
        return Plan::Exclude {
            reason: ExclusionReason::Unsupported,
            detail: "this path has an unresolved merge, so there is no single content a version \
                     could hold for it"
                .to_owned(),
        };
    }
    if request.policy.dirty_files == InclusionChoice::Exclude {
        // Excluding a dirty tracked file means the captured tree holds the **base's** version, not
        // that the path is absent. That is the project service's rule for a workspace and it is
        // the same rule here.
        return base;
    }
    if change.change == ChangeKind::Deleted {
        return Plan::Exclude {
            reason: ExclusionReason::Deleted,
            detail: "the working tree has deleted this path and the capture carries the deletion"
                .to_owned(),
        };
    }
    Plan::WorkingTree {
        class: PathClass::DirtyFile,
        change: change.change,
        base_object_id: Some(entry.object_id.clone()),
        executable_in_index: executable,
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
        GrantDecision::Refused(reason) => Some(Plan::Exclude {
            reason,
            detail: "the file grant does not select this path".to_owned(),
        }),
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
                executable,
            } => {
                let bytes = read_object(profile, repository, object_id)?;
                let content = classify_content(&bytes);
                if leave_out_binary(request, *class, content) {
                    manifest.exclusions.push(Exclusion {
                        path: path.clone(),
                        reason: ExclusionReason::Policy,
                        detail: "the policy excludes binary content".to_owned(),
                    });
                    continue;
                }
                let digest = store.put(&bytes)?;
                manifest.paths.push(CapturedPath {
                    path: path.clone(),
                    content_digest: digest,
                    byte_len: U64::new(bytes.len() as u64),
                    executable: *executable,
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
                executable_in_index,
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
                        manifest.exclusions.push(Exclusion {
                            path: path.clone(),
                            reason: ExclusionReason::Policy,
                            detail: "the policy excludes binary content".to_owned(),
                        });
                        continue;
                    }
                    let digest = store.put(&bytes)?;
                    manifest.paths.push(CapturedPath {
                        path: path.clone(),
                        content_digest: digest,
                        byte_len: U64::new(bytes.len() as u64),
                        executable: executable || *executable_in_index,
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
    manifest.check_size(kr_protocol::changeset::MAX_CAPTURE_BYTES)?;
    Ok(manifest)
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
    /// The content, and whether the file is executable.
    Content {
        /// The bytes, exactly as the file holds them.
        bytes: Vec<u8>,
        /// True when the file is executable.
        executable: bool,
    },
    /// The path is not there.
    Gone,
    /// It is not file content: a link, a device, a socket.
    Unsupported(String),
    /// This host could not read it.
    Unreadable(String),
}

/// Reads one path from the working tree through the authorised handle.
///
/// The file's identity and length are read before and after its content. A file that changed while
/// this host was reading it is re-read up to [`MAX_PATH_RETRIES`] times and then rejected, because
/// a captured tree that held half of one version and half of another would be a tree that never
/// existed.
///
/// # Errors
///
/// Returns [`ChangeSetError::SourceChanged`] when the file kept changing past the bound.
pub fn read_working_tree(repository: &OpenedRepository, path: &str) -> Result<WorkingRead> {
    let Ok(name) = RelativeName::parse(path) else {
        return Ok(WorkingRead::Unsupported(
            "this host cannot name this path beneath the working tree's own handle".to_owned(),
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
        let before_written = modified_at(&file);
        let executable = is_executable(&file);
        let mut bytes = Vec::with_capacity(usize::try_from(before_len).unwrap_or(0));
        if let Err(error) = file.handle_mut().read_to_end(&mut bytes) {
            return Ok(WorkingRead::Unreadable(error.to_string()));
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
///
/// A platform that does not report one answers the same way every time, which makes this check a
/// no-op there rather than a refusal: it is one of the three things compared, not the only one.
fn modified_at(file: &kr_transfer::AuthorisedFile) -> Option<cap_std::time::SystemTime> {
    file.handle()
        .metadata()
        .ok()
        .and_then(|metadata| metadata.modified().ok())
}

/// Returns true when a file the working tree holds is executable.
#[cfg(unix)]
fn is_executable(file: &kr_transfer::AuthorisedFile) -> bool {
    use cap_std::fs::PermissionsExt as _;
    file.handle()
        .metadata()
        .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
}

/// Returns false: this platform has no executable bit on a file.
///
/// The index's own mode is what decides there, which the caller adds.
#[cfg(not(unix))]
fn is_executable(_file: &kr_transfer::AuthorisedFile) -> bool {
    false
}

/// Reads one immutable Git object's content.
pub fn read_object(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    object_id: &str,
) -> Result<Vec<u8>> {
    // The identifier came from Git's own index listing, and it is checked here anyway: an argument
    // this host passes has to be something it can vouch for, and a name that is not hexadecimal is
    // not an object identifier.
    if object_id.is_empty() || !object_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ChangeSetError::InvalidArgument(
            "this repository's index reported something that is not an object identifier".into(),
        ));
    }
    let arguments: [&OsStr; 3] = [
        OsStr::new("cat-file"),
        OsStr::new("blob"),
        OsStr::new(object_id),
    ];
    let output = profile.run(&repository.read(&arguments))?;
    output.require_success()?;
    output.require_complete()?;
    Ok(output.stdout.clone())
}

/// Returns what one path's content is, by Git's own test.
///
/// A null byte in the first eight thousand bytes of the content as it is stored. A
/// `.gitattributes` declaration is not consulted, because what the repository declares must not
/// decide what this host reads.
pub fn classify_content(bytes: &[u8]) -> ContentClass {
    let window = &bytes[..bytes.len().min(kr_project::workspace::BINARY_SCAN_BYTES)];
    if window.contains(&0) {
        ContentClass::Binary
    } else {
        ContentClass::Text
    }
}

/// Decides the consistency class from what the capture actually did.
fn classify(manifest: &Manifest, request: &CaptureRequest<'_>) -> (SourceConsistency, String) {
    if manifest.wholly_from_git_objects() {
        return (
            SourceConsistency::AtomicSnapshot,
            "every captured path's content came from an immutable Git object named by one index \
             listing, which is one instant"
                .to_owned(),
        );
    }
    if request.quiescence_declared {
        return (
            SourceConsistency::QuiescedCapture,
            "the caller declared the working tree quiesced, and every file this host read was the \
             same object of the same length after the read as before it, with the index and the \
             status unchanged at the end"
                .to_owned(),
        );
    }
    (
        SourceConsistency::PerFileCapture,
        "files were read one at a time from a live working tree; each one was the same object of \
         the same length after its read as before it, and the index and the status were unchanged \
         at the end, which is detection rather than one instant"
            .to_owned(),
    )
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
        // The plan is built from the index and the status alone. A secret's entry is an exclusion
        // there, so nothing downstream ever names it as something to read.
        let policy = InclusionPolicy {
            dirty_files: InclusionChoice::Include,
            untracked_files: InclusionChoice::Include,
            submodules: InclusionChoice::Include,
            binary_files: InclusionChoice::Include,
            generated_artefacts: InclusionChoice::Include,
        };
        let granted = FileGrant::default();
        let planned = plan(
            &index(&[
                ("src/main.rs", "100644", "aaaa", 0),
                (".env", "100644", "bbbb", 0),
            ]),
            &[entry(
                ".env",
                InclusionClass::DirtyFile,
                ChangeKind::Present,
            )],
            &[],
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
    fn excluding_dirty_files_holds_the_base_version_rather_than_dropping_the_path() {
        // The project service's rule for a workspace, applied here: an exclusion of a dirty
        // tracked file means the captured tree holds the base's version, not that the path is
        // absent.
        let policy = InclusionPolicy::base_only();
        let granted = FileGrant::default();
        let planned = plan(
            &index(&[("README.md", "100644", "abcdef", 0)]),
            &[entry(
                "README.md",
                InclusionClass::DirtyFile,
                ChangeKind::Present,
            )],
            &[],
            &request(&policy, &granted),
        );
        match &planned["README.md"] {
            Plan::GitObject {
                class, object_id, ..
            } => {
                assert_eq!(*class, PathClass::Tracked);
                assert_eq!(object_id, "abcdef");
            }
            other => panic!("the base's own object is what is read: {other:?}"),
        }
    }

    #[test]
    fn an_excluded_untracked_path_is_absent_because_the_base_never_held_it() {
        let policy = InclusionPolicy::base_only();
        let granted = FileGrant::default();
        let planned = plan(
            &index(&[]),
            &[entry(
                "notes.txt",
                InclusionClass::UntrackedFile,
                ChangeKind::Present,
            )],
            &[],
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
            &index(&[("gone.txt", "100644", "abcdef", 0)]),
            &[entry(
                "gone.txt",
                InclusionClass::DirtyFile,
                ChangeKind::Deleted,
            )],
            &[],
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
            &index(&[("merged.txt", "100644", "abcdef", 2)]),
            &[entry(
                "merged.txt",
                InclusionClass::DirtyFile,
                ChangeKind::Unmerged,
            )],
            &[],
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
            &index(&[("vendor/lib", "160000", "abcdef", 0)]),
            &[],
            &["vendor/lib".to_owned()],
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
    fn asking_for_an_atomic_snapshot_reads_every_tracked_path_from_its_object() {
        let policy = InclusionPolicy::base_only();
        let granted = FileGrant::default();
        let asked = CaptureRequest {
            required_consistency: Some(SourceConsistency::AtomicSnapshot),
            ..request(&policy, &granted)
        };
        let planned = plan(
            &index(&[("README.md", "100644", "abcdef", 0)]),
            &[],
            &[],
            &asked,
        );
        assert!(matches!(planned["README.md"], Plan::GitObject { .. }));
        // Without the requirement the same path is one open rather than one process.
        let planned = plan(
            &index(&[("README.md", "100644", "abcdef", 0)]),
            &[],
            &[],
            &request(&policy, &granted),
        );
        assert!(matches!(planned["README.md"], Plan::WorkingTree { .. }));
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
    fn an_index_that_reports_something_that_is_not_an_object_identifier_is_refused() {
        // The identifier reaches an argument vector, so it is checked rather than trusted.
        assert!(matches!(
            Plan::GitObject {
                class: PathClass::Tracked,
                object_id: "--upload-pack=sh".to_owned(),
                executable: false,
            },
            Plan::GitObject { .. }
        ));
        // The refusal itself is in `read_object`, which needs a repository; what this asserts is
        // the rule it applies.
        assert!(!"--upload-pack=sh".bytes().all(|b| b.is_ascii_hexdigit()));
        assert!("abcdef0123456789".bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
