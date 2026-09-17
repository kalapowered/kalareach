//! Workspaces: the explicit choice, the inclusion preview, and what a creation copies.
//!
//! Section 14 paragraph 3 makes a workspace a decision rather than a default. There are two kinds
//! and no fallback: `shared_existing` uses the user's own working tree where it is, and `isolated`
//! materialises a separate one from a named base with an explicit inclusion policy. The create
//! interface previews what will be included, and this module is what the preview is.
//!
//! Three rules run through everything here.
//!
//! * **Nothing is cleaned, stashed or discarded to start a reviewer.** An exclusion means the new
//!   workspace holds the base's version of that file rather than the user's; it never means the
//!   original is touched. The restricted
//!   profile enforces the same rule from underneath: `git clean`, `git stash`, `git reset`,
//!   `git restore` and every `--force` are not things this service can run at all.
//! * **A shared workspace keeps the user's state in place.** So its policy includes every class,
//!   and a caller that asks for a shared workspace with an exclusion is refused rather than quietly
//!   given a different thing.
//! * **A worktree is not a sandbox.** It separates working files and shares repository metadata
//!   under the same account, and the preview says so among its limitations rather than leaving the
//!   user to find out.

use std::ffi::OsStr;
use std::io::{Read as _, Write as _};

use kr_protocol::ids::{ChangeSetId, ProjectRepositoryId};
use kr_protocol::project::{
    ChangeKind, ContentClass, InclusionChoice, InclusionClass, InclusionPolicy, InclusionPreview,
    IsolationMechanism, MAX_BINARY_SCAN_ENTRIES, MAX_PREVIEW_ENTRIES, PreviewCount, PreviewEntry,
    WorkspaceKind,
};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};
use kr_transfer::{AuthorisedDirectory, ObjectPolicy, RelativeName};

use crate::error::{ProjectError, Result};
use crate::git::RestrictedProfile;
use crate::identity::OpenedRepository;

/// How many bytes Git reads before deciding a file is text, and so how many this host reads.
///
/// Git's own test is a NUL byte in the first eight thousand bytes, and the preview applies the
/// same one so that what it calls binary is what Git calls binary. A `.gitattributes` declaration
/// is not consulted, because the preview reads content as it is stored.
pub const BINARY_SCAN_BYTES: usize = 8_000;

/// Largest total this host copies into an isolated workspace, in bytes.
///
/// An inclusion is a copy, and a working tree can hold more than a host should move without being
/// asked. Above this the creation is refused with the figure rather than filling a disk.
pub const MAX_WORKSPACE_COPY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// One entry of the working tree, as the status read classified it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusEntry {
    /// The path, relative to the repository's top level.
    pub path: String,
    /// Which class it belongs to.
    pub class: InclusionClass,
    /// What change the working tree holds for it.
    ///
    /// A copy is not the only way to carry an inclusion. A deletion is carried by removing the
    /// path from the new workspace, which is why the status's own operation is kept rather than
    /// reduced to a class.
    pub change: ChangeKind,
}

/// One entry of the working tree, with the decision the policy made about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurveyEntry {
    /// The path, relative to the repository's top level.
    pub path: String,
    /// Which class it belongs to.
    pub class: InclusionClass,
    /// What change the working tree holds for it.
    pub change: ChangeKind,
    /// What its content is, as far as this host read it.
    pub content: ContentClass,
    /// Its size, when the host could read one.
    pub byte_len: Option<u64>,
    /// Whether the policy in force carries it into the new workspace.
    pub included: bool,
}

/// What a read of the working tree established: the preview, and every entry behind it.
///
/// The preview's list of paths is bounded, because it travels in one control frame. The survey's
/// is not, because the creation copies from it.
#[derive(Clone, Debug)]
pub struct Survey {
    /// What a reviewer would see, as a client shows it.
    pub preview: InclusionPreview,
    /// Every entry, with its inclusion decision.
    pub entries: Vec<SurveyEntry>,
    /// The paths the policy includes that are not file content: a symbolic link, a socket, a
    /// device.
    ///
    /// Named rather than dropped. A creation reports each of them as unapplied, so a workspace
    /// that does not hold something the policy asked for says which paths those are. A path whose
    /// class the policy excludes is not here: the workspace was never going to hold it.
    pub unsupported: Vec<String>,
}

/// Parses `git status --porcelain=v2 -z`.
///
/// The records are NUL-separated, and the first character of each says what it is: `1` and `2` are
/// tracked entries with an uncommitted change, `u` is an unmerged one, `?` is untracked and `!` is
/// ignored. A tracked entry whose submodule field starts with `S` is a submodule rather than a
/// file. The path runs to the end of the record, so a space in it is part of it.
///
/// # Errors
///
/// Returns [`ProjectError::GitFailed`] when a record is not one this format defines.
pub fn parse_status(text: &str) -> Result<Vec<StatusEntry>> {
    let mut entries = Vec::new();
    let mut skip_next = false;
    for record in text.split('\0') {
        if record.is_empty() {
            continue;
        }
        if skip_next {
            skip_next = false;
            continue;
        }
        let (marker, rest) = record.split_at(1);
        let rest = rest.strip_prefix(' ').unwrap_or(rest);
        match marker {
            // A header line, which this read does not ask for but tolerates.
            "#" => {}
            "?" => entries.push(StatusEntry {
                path: rest.to_owned(),
                class: InclusionClass::UntrackedFile,
                change: ChangeKind::Present,
            }),
            "!" => entries.push(StatusEntry {
                path: rest.to_owned(),
                class: InclusionClass::GeneratedArtefact,
                change: ChangeKind::Present,
            }),
            // The field counts are the format's: eight fields for an ordinary entry, nine for a
            // renamed one and ten for an unmerged one, with the path last in each.
            "1" | "2" | "u" => {
                let fields = match marker {
                    "1" => 8,
                    "2" => 9,
                    _ => 10,
                };
                let parts: Vec<&str> = rest.splitn(fields, ' ').collect();
                if parts.len() < fields {
                    return Err(malformed(record));
                }
                let states = parts[0];
                let submodule = parts[1];
                let path = parts[fields - 1];
                if path.is_empty() {
                    return Err(malformed(record));
                }
                // The two state characters are the index's and the working tree's. A `D` in
                // either position is a path the working tree no longer holds: `.D` is deleted and
                // not staged, `D.` is deleted and staged, and either way there is nothing there to
                // copy. Carrying that inclusion means removing the path from the new workspace.
                let mut states = states.chars();
                let index = states.next().unwrap_or('.');
                let worktree = states.next().unwrap_or('.');
                entries.push(StatusEntry {
                    class: if submodule.starts_with('S') {
                        InclusionClass::Submodule
                    } else {
                        InclusionClass::DirtyFile
                    },
                    change: match (marker, index, worktree) {
                        ("u", _, _) => ChangeKind::Unmerged,
                        (_, 'D', '.') | (_, _, 'D') => ChangeKind::Deleted,
                        _ => ChangeKind::Present,
                    },
                    path: path.to_owned(),
                });
                // A renamed entry is followed by its original path as a record of its own, which
                // is not a status record. `survey` asks for `--no-renames`, so this is the
                // parser's completeness rather than a path it meets.
                if marker == "2" {
                    skip_next = true;
                }
            }
            _ => return Err(malformed(record)),
        }
    }
    Ok(entries)
}

/// Returns the submodule paths the index holds, without entering any of them.
///
/// A submodule is a `160000` entry in the index. Reading the index is a read of the repository this
/// host has audited; entering the submodule would be a read of one it has not.
///
/// # Errors
///
/// Returns [`ProjectError::GitFailed`] when the index cannot be read.
pub fn submodule_paths(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
) -> Result<Vec<String>> {
    let arguments: [&OsStr; 3] = [
        OsStr::new("ls-files"),
        OsStr::new("--stage"),
        OsStr::new("-z"),
    ];
    let output = profile.run(&repository.read(&arguments))?;
    output.require_success()?;
    // `-z` means Git writes the paths as bytes rather than quoting them, so a path this host
    // cannot read as text is one it cannot name. Decoding it lossily would put a replacement
    // character where a byte was, and the host would then be asking the filesystem about a
    // different name: a populated submodule would look absent, and a removal would delete work
    // nobody inspected. So the listing is refused rather than approximated.
    let reported = std::str::from_utf8(&output.stdout).map_err(|_| ProjectError::GitFailed {
        detail: "this repository's index holds a path this host cannot read as text, so it \
                 cannot say what that path holds"
            .to_owned(),
    })?;
    let mut paths = Vec::new();
    for record in reported.split('\0') {
        // `<mode> <object> <stage>\t<path>`
        let Some((fields, path)) = record.split_once('\t') else {
            continue;
        };
        if fields.starts_with("160000 ") && !path.is_empty() {
            paths.push(path.to_owned());
        }
    }
    paths.sort_unstable();
    paths.dedup();
    Ok(paths)
}

fn malformed(record: &str) -> ProjectError {
    ProjectError::GitFailed {
        detail: format!(
            "a status record is not one this format defines: {}",
            record.chars().take(64).collect::<String>()
        ),
    }
}

/// What a preview is taken for.
#[derive(Clone, Copy, Debug)]
pub struct PreviewRequest<'a> {
    /// The repository the preview names.
    pub project_repository_id: ProjectRepositoryId,
    /// The kind of workspace it is taken for.
    pub kind: WorkspaceKind,
    /// The policy it is taken under.
    pub policy: InclusionPolicy,
    /// The revision an isolated workspace would start from.
    pub base_revision: &'a str,
    /// The reference that revision was named by, when it was named by one.
    pub base_reference: Option<&'a str>,
    /// The change-set version an isolated workspace would materialise.
    pub base_change_set_id: Option<ChangeSetId>,
    /// When it was taken.
    pub at_ms: TimestampMs,
}

/// Reads the working tree and builds the preview a creation is decided from.
///
/// This is a read: it creates nothing and changes nothing, which is what lets the create interface
/// show it before the user commits to a workspace.
///
/// # Errors
///
/// Returns [`ProjectError::GitFailed`] when the status cannot be read or a record cannot be
/// parsed.
pub fn survey(
    profile: &RestrictedProfile,
    repository: &OpenedRepository,
    request: &PreviewRequest<'_>,
) -> Result<Survey> {
    // `--ignore-submodules=all` is not an optimisation. Checking a submodule's dirtiness runs Git
    // *inside* the submodule, and a submodule's configuration lives in the parent's modules
    // directory, which the parent's own configuration listing does not read: a filter defined
    // there is one the audit cannot see and cannot blank. So this host never enters a submodule,
    // and counts them from the index instead.
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
    let submodules = submodule_paths(profile, repository)?;
    // A wholly ignored directory is reported as one entry with a trailing separator, because that
    // is how the ignore rule matched. Expanded here so the counts are exact and an inclusion
    // copies the files rather than nothing.
    let mut budget = MAX_BINARY_SCAN_ENTRIES;
    let mut truncated = 0_u64;
    let mut unsupported: Vec<(String, InclusionClass)> = Vec::new();
    let mut status: Vec<StatusEntry> = submodules
        .into_iter()
        .map(|path| StatusEntry {
            path,
            class: InclusionClass::Submodule,
            change: ChangeKind::Present,
        })
        .collect();
    for entry in parse_status(&reported)? {
        match entry.path.strip_suffix('/') {
            None => status.push(entry),
            Some(prefix) => expand(
                repository.work_tree(),
                prefix,
                entry.class,
                &mut Walk {
                    out: &mut status,
                    budget: &mut budget,
                    truncated: &mut truncated,
                    unsupported: &mut unsupported,
                },
                0,
            ),
        }
    }
    let mut counts: Vec<PreviewCount> = InclusionClass::EVERY
        .iter()
        .map(|class| PreviewCount {
            class: *class,
            total: U64::new(0),
            included: U64::new(0),
            byte_len: U64::new(0),
        })
        .collect();
    let mut entries: Vec<SurveyEntry> = Vec::with_capacity(status.len());
    let mut scanned = 0_usize;
    let mut unknown = 0_u64;
    let shared = matches!(request.kind, WorkspaceKind::SharedExisting);
    for entry in status {
        let measured = measure(
            repository.work_tree(),
            &entry.path,
            entry.change,
            &mut scanned,
        );
        if matches!(measured.content, ContentClass::Unknown) {
            unknown += 1;
        }
        // A shared workspace keeps the user's state where it is, so a reviewer of one sees
        // everything that is there whatever the policy says. Otherwise the origin class decides
        // first and the content decides second: a path this host could not read counts as binary
        // for an exclusion, because excluding what might be binary is the direction that honours
        // the request.
        let excluded_by_content = !matches!(request.policy.binary_files, InclusionChoice::Include)
            && matches!(
                measured.content,
                ContentClass::Binary | ContentClass::Unknown
            );
        let included = shared
            || (matches!(request.policy.choice(entry.class), InclusionChoice::Include)
                && !excluded_by_content);
        bump(&mut counts, entry.class, measured.byte_len, included);
        if matches!(measured.content, ContentClass::Binary) {
            bump(
                &mut counts,
                InclusionClass::BinaryFile,
                measured.byte_len,
                included,
            );
        }
        entries.push(SurveyEntry {
            path: entry.path,
            class: entry.class,
            change: entry.change,
            content: measured.content,
            byte_len: measured.byte_len,
            included,
        });
    }
    // The sample is grouped the way the classes are listed, so a client can show it in sections
    // without sorting it again.
    let mut ordered: Vec<&SurveyEntry> = entries.iter().collect();
    ordered.sort_by(|left, right| {
        left.class
            .cmp(&right.class)
            .then_with(|| left.path.cmp(&right.path))
    });
    let sample: Vec<PreviewEntry> = ordered
        .iter()
        .take(MAX_PREVIEW_ENTRIES)
        .map(|entry| PreviewEntry {
            path: entry.path.clone(),
            class: entry.class,
            change: entry.change,
            content: entry.content,
            byte_len: Nullable(entry.byte_len.map(U64::new)),
            included: entry.included,
        })
        .collect();
    let omitted = u64::try_from(entries.len().saturating_sub(sample.len())).unwrap_or(u64::MAX);
    // The configuration and the objects an invocation ran against have to still be the ones the
    // audit and the identity check were taken from, or what it read was read under something else.
    repository.confirm(profile)?;
    let mut limitations = limitations_for(request.kind);
    limitations.extend(repository.audit().limitations());
    limitations.push(
        "a submodule is its own repository with its own configuration, and this host does not look \
         inside one: a submodule is counted and named, and what it holds is neither measured nor \
         copied"
            .to_owned(),
    );
    if unknown > 0 {
        limitations.push(format!(
            "{unknown} paths were not read, because the preview reads at most \
             {MAX_BINARY_SCAN_ENTRIES} of them or because this host could not open them. Each is \
             counted in its own class, is not counted among the binary files, and is left out by \
             an exclusion of binary files rather than treated as text"
        ));
    }
    if truncated > 0 {
        limitations.push(format!(
            "{truncated} directories inside an ignored directory were not walked to the end: they \
             hold more than the {MAX_BINARY_SCAN_ENTRIES} paths this preview walks, are nested \
             deeper than {MAX_DIRECTORY_DEPTH} levels, or hold an entry this host could not read. \
             What is beyond that is neither counted nor copied"
        ));
    }
    if !unsupported.is_empty() {
        limitations.push(format!(
            "{} paths inside an ignored directory are a symbolic link, a socket or a device \
             rather than file content; this host carries file content, so each the policy \
             includes is reported as unapplied rather than copied",
            unsupported.len()
        ));
    }
    if omitted > 0 {
        limitations.push(format!(
            "{omitted} paths are counted but not listed, because a preview lists at most \
             {MAX_PREVIEW_ENTRIES} of them in one reply"
        ));
    }
    Ok(Survey {
        preview: InclusionPreview {
            project_repository_id: request.project_repository_id,
            kind: request.kind,
            policy: request.policy,
            base_revision: request.base_revision.to_owned(),
            base_reference: Nullable(request.base_reference.map(str::to_owned)),
            base_change_set_id: Nullable(request.base_change_set_id),
            counts,
            entries: sample,
            omitted_entries: U64::new(omitted),
            unknown_content: U64::new(unknown),
            // The binary count covers the paths this host read, so a path it did not read makes
            // that count a lower bound as surely as an unwalked directory does.
            counts_complete: truncated == 0 && unknown == 0 && unsupported.is_empty(),
            limitations,
            taken_at_ms: request.at_ms,
        },
        entries,
        // Only what the policy asked for. A path the workspace was never going to hold is not a
        // path it failed to hold, and `unapplied` is the paths the policy included.
        unsupported: unsupported
            .into_iter()
            .filter(|(_, class)| {
                // The same decision the entries get: the origin class first, and then the
                // content. A link, a socket or a device is content this host could not classify,
                // and an exclusion of binary files excludes what might be binary, so it excludes
                // these too. Otherwise an excluded path would be reported as one the workspace
                // failed to hold.
                shared
                    || (matches!(request.policy.choice(*class), InclusionChoice::Include)
                        && matches!(request.policy.binary_files, InclusionChoice::Include))
            })
            .map(|(path, _)| path)
            .collect(),
    })
}

/// What one directory walk is filling in.
struct Walk<'a> {
    /// The entries the walk found.
    out: &'a mut Vec<StatusEntry>,
    /// How many more paths it may read.
    budget: &'a mut usize,
    /// How many directories it could not walk to the end of.
    truncated: &'a mut u64,
    /// The paths it found that are not file content, each with the class it was found under.
    unsupported: &'a mut Vec<(String, InclusionClass)>,
}

/// How deep this preview walks into an ignored directory.
///
/// A build directory is a handful of levels. The bound is here because the walk is recursive and a
/// tree can be as deep as the filesystem allows.
pub const MAX_DIRECTORY_DEPTH: usize = 64;

/// Expands one directory entry into the files it holds.
///
/// The walk goes through the authorised directory handle, so nothing outside the working tree is
/// reached and a symbolic link is neither followed nor counted as content. What it cannot walk is
/// reported rather than silently left out: the caller adds a limitation naming how much.
fn expand(
    tree: &AuthorisedDirectory,
    prefix: &str,
    class: InclusionClass,
    walk: &mut Walk<'_>,
    depth: usize,
) {
    if depth >= MAX_DIRECTORY_DEPTH || *walk.budget == 0 {
        *walk.truncated += 1;
        return;
    }
    let Ok(name) = RelativeName::parse(prefix) else {
        return;
    };
    let Ok(directory) = tree.subdirectory(&name) else {
        // Not a directory after all, or not reachable. It is still one entry the status reported.
        walk.out.push(StatusEntry {
            path: prefix.to_owned(),
            class,
            change: ChangeKind::Present,
        });
        return;
    };
    let Ok(entries) = directory.handle().entries() else {
        *walk.truncated += 1;
        return;
    };
    for entry in entries {
        let Ok(entry) = entry else {
            // A directory entry this host could not read is one it did not count.
            *walk.truncated += 1;
            continue;
        };
        let Ok(file_name) = entry.file_name().into_string() else {
            *walk.truncated += 1;
            continue;
        };
        let child = format!("{prefix}/{file_name}");
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => {
                expand(tree, &child, class, walk, depth + 1);
            }
            Ok(kind) if kind.is_file() => {
                if *walk.budget == 0 {
                    *walk.truncated += 1;
                    return;
                }
                *walk.budget -= 1;
                walk.out.push(StatusEntry {
                    path: child,
                    class,
                    change: ChangeKind::Present,
                });
            }
            // A link, a socket or a device is not file content, and this host carries file
            // content. Each is named so a creation can report it as unapplied rather than leave
            // the caller to notice it is missing, and each costs one of the walk's paths so the
            // list cannot outgrow the bound the preview advertises.
            _ => {
                if *walk.budget == 0 {
                    *walk.truncated += 1;
                    return;
                }
                *walk.budget -= 1;
                walk.unsupported.push((child, class));
            }
        }
    }
}

/// What reading one entry established.
#[derive(Clone, Copy, Debug)]
struct Measured {
    byte_len: Option<u64>,
    content: ContentClass,
}

impl Default for Measured {
    fn default() -> Self {
        Self {
            byte_len: None,
            // A path this host did not read is not a text path. Everything that decides from this
            // treats an unknown as it treats a binary.
            content: ContentClass::Unknown,
        }
    }
}

/// Reads one entry's size, and whether Git's own test calls it binary.
///
/// The read goes through the authorised directory handle, so a link or a path that leaves the tree
/// is refused rather than followed. A path the host cannot read is reported with no size and as
/// text, because a preview that refused to be taken would be less useful than one that says what
/// it could not measure.
fn measure(
    tree: &AuthorisedDirectory,
    path: &str,
    change: ChangeKind,
    scanned: &mut usize,
) -> Measured {
    if matches!(change, ChangeKind::Deleted) {
        // There is nothing there to read, and nothing this host would copy. A deletion is carried
        // by removing the path from the new workspace.
        return Measured {
            byte_len: None,
            content: ContentClass::Text,
        };
    }
    let Ok(name) = RelativeName::parse(path) else {
        return Measured::default();
    };
    let Ok(mut file) = tree.open_read(&name, ObjectPolicy::ReadableFile) else {
        return Measured::default();
    };
    let byte_len = file.byte_len();
    if *scanned >= MAX_BINARY_SCAN_ENTRIES {
        return Measured {
            byte_len: Some(byte_len),
            content: ContentClass::Unknown,
        };
    }
    *scanned += 1;
    let wanted = BINARY_SCAN_BYTES.min(usize::try_from(byte_len).unwrap_or(usize::MAX));
    let mut head = vec![0_u8; wanted];
    let mut read = 0_usize;
    let handle = file.handle_mut();
    loop {
        if read >= head.len() {
            break;
        }
        match handle.read(&mut head[read..]) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                // A read that failed part way says nothing about the rest of the file. Reporting
                // the prefix as text would be reporting a classification this host does not have.
                return Measured {
                    byte_len: Some(byte_len),
                    content: ContentClass::Unknown,
                };
            }
        }
    }
    Measured {
        byte_len: Some(byte_len),
        content: if head[..read].contains(&0) {
            ContentClass::Binary
        } else {
            ContentClass::Text
        },
    }
}

fn bump(counts: &mut [PreviewCount], class: InclusionClass, byte_len: Option<u64>, included: bool) {
    if let Some(count) = counts.iter_mut().find(|count| count.class == class) {
        count.total = U64::new(count.total.get().saturating_add(1));
        if included {
            count.included = U64::new(count.included.get().saturating_add(1));
        }
        if let Some(byte_len) = byte_len {
            count.byte_len = U64::new(count.byte_len.get().saturating_add(byte_len));
        }
    }
}

/// What the host says a workspace of this kind cannot promise.
#[must_use]
pub fn limitations_for(kind: WorkspaceKind) -> Vec<String> {
    match kind {
        WorkspaceKind::SharedExisting => vec![
            "this workspace is the repository's own working tree, so every session bound to it \
             sees the others' edits and an apply to it is best-effort conflict detection rather \
             than compare-and-swap"
                .to_owned(),
            "the working tree can change between this preview and anything decided from it, \
             because it is the tree you are working in"
                .to_owned(),
        ],
        WorkspaceKind::Isolated => vec![
            "a Git worktree separates working files and shares the repository's objects, \
             references and configuration under the same account, so it is not a security sandbox; \
             an independent clone is the stronger choice where that matters"
                .to_owned(),
            "the working tree can change between this preview and the copy the creation makes, so \
             what is copied is what was there when it was copied"
                .to_owned(),
            "nothing in the source tree is cleaned, stashed or discarded: an exclusion means this \
             workspace holds the base's version of the file rather than the user's, and the \
             original stays where it is"
                .to_owned(),
        ],
    }
}

/// Refuses a creation request whose kind and policy do not agree.
///
/// # Errors
///
/// Returns [`ProjectError::InvalidArgument`] naming which part disagrees.
pub fn check_choice(
    kind: WorkspaceKind,
    isolation: Option<IsolationMechanism>,
    policy: InclusionPolicy,
    has_destination: bool,
) -> Result<()> {
    match kind {
        WorkspaceKind::SharedExisting => {
            if isolation.is_some() {
                return Err(ProjectError::InvalidArgument(
                    "a shared workspace is the repository's own working tree, so it names no \
                     isolation mechanism"
                        .to_owned(),
                ));
            }
            if has_destination {
                return Err(ProjectError::InvalidArgument(
                    "a shared workspace is the repository's own working tree, so it names no \
                     destination"
                        .to_owned(),
                ));
            }
            if InclusionClass::EVERY
                .iter()
                .any(|class| matches!(policy.choice(*class), InclusionChoice::Exclude))
            {
                return Err(ProjectError::InvalidArgument(
                    "a shared workspace keeps the user's dirty and untracked state in place, so \
                     every class is included; an exclusion needs an isolated workspace"
                        .to_owned(),
                ));
            }
            Ok(())
        }
        WorkspaceKind::Isolated => {
            if isolation.is_none() {
                return Err(ProjectError::InvalidArgument(
                    "an isolated workspace names how it is separated: a Git worktree, which is not \
                     a security sandbox, or an independent clone"
                        .to_owned(),
                ));
            }
            if !has_destination {
                return Err(ProjectError::InvalidArgument(
                    "an isolated workspace names where its working tree goes".to_owned(),
                ));
            }
            Ok(())
        }
    }
}

/// What a copy moved and what it could not.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CopyReport {
    /// The paths that were copied.
    pub copied: Vec<String>,
    /// The paths that were removed, because the user's working tree does not hold them.
    pub removed: Vec<String>,
    /// The paths the policy included that this host could not carry, each named rather than
    /// hidden.
    ///
    /// A symbolic link, a device, a submodule's own working tree, and a path whose destination
    /// this host could not replace. The caller reports these; it does not treat them as copied.
    pub skipped: Vec<String>,
    /// The temporary files a failed copy left behind, because removing them failed too.
    ///
    /// A copy writes beside its destination and renames over it, so a failure ordinarily leaves
    /// nothing. Where even the cleanup failed, the name goes here and the caller records it: a
    /// file nobody accounts for in the user's new workspace is worse than a named one.
    pub leftover: Vec<String>,
    /// How many bytes were copied.
    pub byte_len: u64,
}

/// What became of one path a copy was asked to carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathOutcome {
    /// The workspace now holds the user's version of it.
    Carried,
    /// The workspace no longer holds it, because the user's tree does not.
    Removed,
    /// The workspace holds whatever the base had, because this host could not carry the user's.
    Unapplied,
    /// A copy in progress that this host could not take away again, named so it is accounted for.
    Leftover,
}

/// Returns the word one outcome is recorded under.
#[must_use]
pub const fn outcome_text(outcome: PathOutcome) -> &'static str {
    match outcome {
        PathOutcome::Carried => "carried",
        PathOutcome::Removed => "removed",
        PathOutcome::Unapplied => "unapplied",
        PathOutcome::Leftover => "leftover",
    }
}

/// Copies the entries a policy includes from one working tree into another.
///
/// Every read and every write goes through an authorised directory handle, and every directory the
/// copy needs is created one component at a time against the handle above it. The source is only
/// read: this is the whole of what "never clean, stash or discard" means in code.
///
/// # Errors
///
/// Returns [`ProjectError::QuotaExceeded`] when the total passes [`MAX_WORKSPACE_COPY_BYTES`], or
/// [`ProjectError::Destination`] when a path cannot be written.
pub fn copy_included(
    source: &AuthorisedDirectory,
    destination: &AuthorisedDirectory,
    entries: &[SurveyEntry],
    progress: &mut dyn FnMut(&str, PathOutcome) -> Result<()>,
) -> Result<CopyReport> {
    let mut report = CopyReport::default();
    for entry in entries {
        if !entry.included {
            continue;
        }
        // A submodule is its own repository with its own configuration, and copying its working
        // tree would be copying a repository this host has not opened and cannot audit. Including
        // one is recorded as unapplied rather than half done.
        if matches!(entry.class, InclusionClass::Submodule) {
            report.skipped.push(entry.path.clone());
            progress(&entry.path, PathOutcome::Unapplied)?;
            continue;
        }
        let Ok(name) = RelativeName::parse(&entry.path) else {
            report.skipped.push(entry.path.clone());
            progress(&entry.path, PathOutcome::Unapplied)?;
            continue;
        };
        // A deletion is carried by removing the path from the new workspace. The checkout put the
        // base's content there, and what the user has is its absence.
        if matches!(entry.change, ChangeKind::Deleted) {
            if remove_one(destination, &name) {
                report.removed.push(entry.path.clone());
                progress(&entry.path, PathOutcome::Removed)?;
            } else {
                report.skipped.push(entry.path.clone());
                progress(&entry.path, PathOutcome::Unapplied)?;
            }
            continue;
        }
        // Each path's outcome is reported as it settles, not at the end. A daemon that dies part
        // way through an inclusion leaves a record of which paths it had applied, which is what a
        // reader of an unfinished workspace needs and what recovery reports.
        let left = report.leftover.len();
        let carried = copy_one(source, destination, &name, &mut report)?;
        // A copy in progress this host could not take away again is journalled like any other
        // path, so nothing it wrote is left unaccounted for.
        for stray in &report.leftover[left..] {
            progress(stray, PathOutcome::Leftover)?;
        }
        if carried {
            report.copied.push(entry.path.clone());
            progress(&entry.path, PathOutcome::Carried)?;
        } else {
            report.skipped.push(entry.path.clone());
            progress(&entry.path, PathOutcome::Unapplied)?;
        }
    }
    Ok(report)
}

/// Removes one path from the new workspace, carrying a deletion the user has.
fn remove_one(destination: &AuthorisedDirectory, name: &RelativeName) -> bool {
    let components = name.components();
    let Some((leaf, parents)) = components.split_last() else {
        return false;
    };
    let mut here: Option<AuthorisedDirectory> = None;
    for component in parents {
        let Ok(component) = RelativeName::parse(component) else {
            return false;
        };
        let above = here.as_ref().unwrap_or(destination);
        match above.subdirectory(&component) {
            Ok(next) => here = Some(next),
            // The directory is not there, so neither is the path: the deletion is already carried.
            Err(_) => return true,
        }
    }
    let target = here.as_ref().unwrap_or(destination);
    let Ok(leaf) = RelativeName::parse(leaf) else {
        return false;
    };
    target.remove(&leaf).is_ok() && target.sync().is_ok()
}

fn copy_one(
    source: &AuthorisedDirectory,
    destination: &AuthorisedDirectory,
    name: &RelativeName,
    report: &mut CopyReport,
) -> Result<bool> {
    let Ok(file) = source.open_read(name, ObjectPolicy::ReadableFile) else {
        return Ok(false);
    };
    // The source's permission bits are read before anything is written, because a copy that
    // cannot carry them is a copy of a different file: an executable script that arrives without
    // its executable bit does not run. A path whose mode this host could not read is reported as
    // unapplied and the destination keeps what the base put there.
    let Ok(mode) = source_mode(&file) else {
        return Ok(false);
    };
    let byte_len = file.byte_len();
    let total = &mut report.byte_len;
    *total = total.saturating_add(byte_len);
    if *total > MAX_WORKSPACE_COPY_BYTES {
        return Err(ProjectError::QuotaExceeded {
            detail: format!(
                "this inclusion would copy more than {MAX_WORKSPACE_COPY_BYTES} bytes into the \
                 new workspace; narrow the policy or start from the base alone"
            ),
        });
    }
    let components = name.components();
    let (leaf, parents) = components
        .split_last()
        .ok_or_else(|| ProjectError::Destination {
            detail: format!("{name} names nothing to copy"),
        })?;
    // Each level is created against the handle of the level above it, so a creation never depends
    // on a prefix resolved after it was checked.
    let mut here: Option<AuthorisedDirectory> = None;
    for component in parents {
        let component = RelativeName::parse(component)?;
        let above = here.as_ref().unwrap_or(destination);
        // A directory this host could not make is one path it cannot carry, not a reason to stop
        // the inclusion: the checkout may hold a *file* at a name the user's tree has a directory
        // at. The path is reported and the destination keeps what the base put there.
        let Ok(next) = above.create_subdirectory(&component) else {
            return Ok(false);
        };
        here = Some(next);
    }
    let target = here.as_ref().unwrap_or(destination);
    let leaf = RelativeName::parse(leaf)?;
    let mut handle = file.into_handle();
    // The checkout may already have put the base's content at this name, and writing over it would
    // leave the base's tail behind whenever the user's file is shorter. So the copy is written to
    // a name of this host's own, flushed, and then renamed over the destination: a rename replaces
    // a file in one step, so the destination is either the base's file or the user's and never
    // half of each. A failure anywhere before the rename leaves the destination as it was.
    // The temporary's name follows from the destination's own path rather than from chance, so
    // the journal's row for that path accounts for the temporary as well: a replacement daemon
    // that finds a path recorded as `planned` can name the one temporary a copy of it could have
    // left. A random name would be an object nothing could account for.
    let temporary = RelativeName::parse(&temporary_name(name))?;
    // Created exclusively, and nothing is ever removed to make room for it. A name derived from a
    // path is a name a repository can also hold a file under, and this host cannot tell a file the
    // user tracked from a copy an earlier daemon left: they are the same object at the same name.
    // So an occupied name means this path is not carried, and the creation says so.
    let mut written = match target.create_new(&temporary) {
        Ok(created) => created,
        Err(_) => return Ok(false),
    };
    let temporary_path = if parents.is_empty() {
        temporary.to_string()
    } else {
        format!("{}/{temporary}", parents.join("/"))
    };
    let mut buffer = vec![0_u8; 256 * 1024];
    let outcome = (|| -> Result<()> {
        loop {
            let read = match handle.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(ProjectError::Destination {
                        detail: format!("{leaf} could not be read: {error}"),
                    });
                }
            };
            written
                .handle_mut()
                .write_all(&buffer[..read])
                .map_err(|error| ProjectError::Destination {
                    detail: format!("{leaf} could not be written: {error}"),
                })?;
        }
        // An executable script that arrives without its executable bit is not the file the user
        // has, so the source's mode is carried across where the platform has one. It goes on
        // before the flush, so what reaches the disk is the file's content *and* its mode.
        apply_mode(&written, mode)?;
        // The bytes are durable before the name changes, so a power loss cannot leave the
        // destination naming a file whose content never reached the disk.
        written
            .handle_mut()
            .sync_all()
            .map_err(|error| ProjectError::Destination {
                detail: format!("{leaf} could not be flushed: {error}"),
            })?;
        Ok(())
    })();
    drop(written);
    // Whatever went wrong, the destination keeps what it had. What is reported is whether this
    // host managed to take its own temporary file away again.
    if let Err(error) = outcome {
        if target.remove(&temporary).is_err() {
            report.leftover.push(temporary_path);
        }
        // A quota is the one failure that stops the whole inclusion; anything about this one path
        // is reported as a path that was not applied.
        if matches!(error, ProjectError::QuotaExceeded { .. }) {
            return Err(error);
        }
        return Ok(false);
    }
    if target.rename_into(&temporary, target, &leaf).is_err() {
        // Something this host could not replace is at the name: a directory where the source has a
        // file. The destination keeps whatever it had and the path is named rather than written
        // over.
        if target.remove(&temporary).is_err() {
            report.leftover.push(temporary_path);
        }
        return Ok(false);
    }
    target.sync()?;
    Ok(true)
}

/// Returns the source file's permission bits, where the platform has them.
///
/// # Errors
///
/// Returns [`ProjectError::Destination`] when the source's own metadata cannot be read, because a
/// copy that cannot carry the mode is a copy of a different file.
#[cfg(unix)]
fn source_mode(file: &kr_transfer::AuthorisedFile) -> Result<Option<u32>> {
    use cap_std::fs::MetadataExt as _;

    let metadata = file
        .handle()
        .metadata()
        .map_err(|error| ProjectError::Destination {
            detail: format!("a file's own permissions could not be read: {error}"),
        })?;
    Ok(Some(metadata.mode()))
}

/// Returns the source file's permission bits, where the platform has them.
///
/// # Errors
///
/// Never on a platform without permission bits.
#[cfg(not(unix))]
fn source_mode(_file: &kr_transfer::AuthorisedFile) -> Result<Option<u32>> {
    Ok(None)
}

/// Puts the source's permission bits on the copy, where the platform has them.
///
/// # Errors
///
/// Returns [`ProjectError::Destination`] when the bits cannot be set.
#[cfg(unix)]
fn apply_mode(file: &kr_transfer::AuthorisedFile, mode: Option<u32>) -> Result<()> {
    use cap_std::fs::PermissionsExt as _;

    if let Some(mode) = mode {
        file.handle()
            .set_permissions(cap_std::fs::Permissions::from_mode(mode))
            .map_err(|error| ProjectError::Destination {
                detail: format!("a copy's permissions could not be set: {error}"),
            })?;
    }
    Ok(())
}

/// Puts the source's permission bits on the copy, where the platform has them.
///
/// # Errors
///
/// Never on a platform without permission bits.
#[cfg(not(unix))]
fn apply_mode(_file: &kr_transfer::AuthorisedFile, _mode: Option<u32>) -> Result<()> {
    Ok(())
}

/// Returns the name a copy of one path is written under before it replaces it.
///
/// Derived from the path rather than drawn at random, so the name is recoverable: the journal
/// records the destination path before the copy begins, and this function is how a person or a
/// later task turns that path back into the one temporary name a copy of it could have left
/// behind. The digest covers the whole relative path, which makes a collision between two paths
/// in one directory as unlikely as a 128-bit digest prefix allows.
///
/// What the name does **not** establish is ownership. A repository can hold a tracked file at this
/// name, and nothing distinguishes it from a copy an earlier daemon left, so a copy never removes
/// what is at this name: an occupied name means the path is reported rather than carried.
#[must_use]
pub fn temporary_name(name: &RelativeName) -> String {
    let digest = kr_cbor::sha256(name.to_string().as_bytes());
    let mut text = String::with_capacity(41);
    text.push_str(".kr-copy-");
    for byte in &digest[..16] {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_class_the_status_reports_is_recognised() {
        // One record of each shape porcelain v2 produces, NUL-separated the way `-z` writes them.
        let status = concat!(
            "1 .M N... 100644 100644 100644 aaaa bbbb src/changed.rs\0",
            "1 M. N... 100644 100644 100644 aaaa bbbb src/staged.rs\0",
            "1 .M S.M. 160000 160000 160000 cccc dddd vendor/library\0",
            "1 .D N... 100644 100644 000000 aaaa bbbb src/gone.rs\0",
            "u UU N... 100644 100644 100644 100644 eeee ffff 0000 src/conflicted.rs\0",
            "? new-file.txt\0",
            "! target/debug/binary\0",
        );
        let entries = parse_status(status).expect("every record is one this format defines");
        assert_eq!(
            entries,
            vec![
                StatusEntry {
                    path: "src/changed.rs".to_owned(),
                    class: InclusionClass::DirtyFile,
                    change: ChangeKind::Present,
                },
                StatusEntry {
                    path: "src/staged.rs".to_owned(),
                    class: InclusionClass::DirtyFile,
                    change: ChangeKind::Present,
                },
                StatusEntry {
                    path: "vendor/library".to_owned(),
                    class: InclusionClass::Submodule,
                    change: ChangeKind::Present,
                },
                StatusEntry {
                    path: "src/gone.rs".to_owned(),
                    class: InclusionClass::DirtyFile,
                    change: ChangeKind::Deleted,
                },
                StatusEntry {
                    path: "src/conflicted.rs".to_owned(),
                    class: InclusionClass::DirtyFile,
                    change: ChangeKind::Unmerged,
                },
                StatusEntry {
                    path: "new-file.txt".to_owned(),
                    class: InclusionClass::UntrackedFile,
                    change: ChangeKind::Present,
                },
                StatusEntry {
                    path: "target/debug/binary".to_owned(),
                    class: InclusionClass::GeneratedArtefact,
                    change: ChangeKind::Present,
                },
            ]
        );
    }

    #[test]
    fn a_renamed_entry_carries_one_more_field_and_its_path_is_still_read() {
        let entries =
            parse_status("2 R. N... 100644 100644 100644 aaaa bbbb R100 src/new name.rs\0")
                .expect("it parses");
        assert_eq!(entries[0].path, "src/new name.rs");
        assert_eq!(entries[0].class, InclusionClass::DirtyFile);
    }

    #[test]
    fn a_path_with_a_space_keeps_it() {
        // Porcelain v2 with `-z` writes the path unquoted to the end of the record, so a space in
        // it is part of the path rather than a field separator.
        let entries = parse_status("1 .M N... 100644 100644 100644 aaaa bbbb src/two words.rs\0")
            .expect("it parses");
        assert_eq!(entries[0].path, "src/two words.rs");
        let entries = parse_status("? a file with spaces.txt\0").expect("it parses");
        assert_eq!(entries[0].path, "a file with spaces.txt");
    }

    #[test]
    fn a_record_this_format_does_not_define_is_reported_rather_than_guessed_at() {
        let refusal = parse_status("z something\0").expect_err("an unknown marker is refused");
        assert!(refusal.to_string().contains("not one this format defines"));
        let refusal = parse_status("1 .M N...\0").expect_err("a short record is refused");
        assert!(refusal.to_string().contains("not one this format defines"));
    }

    #[test]
    fn a_shared_workspace_takes_no_exclusion_and_an_isolated_one_names_its_mechanism() {
        // Section 14 keeps the user's dirty and untracked state in place for a shared workspace,
        // so asking for an exclusion there is asking for a different thing.
        let refusal = check_choice(
            WorkspaceKind::SharedExisting,
            None,
            InclusionPolicy::base_only(),
            false,
        )
        .expect_err("an exclusion needs an isolated workspace");
        assert!(refusal.to_string().contains("keeps the user's dirty"));
        let every = InclusionPolicy {
            dirty_files: InclusionChoice::Include,
            untracked_files: InclusionChoice::Include,
            submodules: InclusionChoice::Include,
            binary_files: InclusionChoice::Include,
            generated_artefacts: InclusionChoice::Include,
        };
        check_choice(WorkspaceKind::SharedExisting, None, every, false)
            .expect("a shared workspace that includes everything is what a shared one is");
        let refusal = check_choice(WorkspaceKind::SharedExisting, None, every, true)
            .expect_err("a shared workspace names no destination");
        assert!(refusal.to_string().contains("names no destination"));
        let refusal = check_choice(
            WorkspaceKind::SharedExisting,
            Some(IsolationMechanism::GitWorktree),
            every,
            false,
        )
        .expect_err("a shared workspace names no isolation");
        assert!(refusal.to_string().contains("names no isolation"));
        // An isolated workspace makes both choices explicit.
        let refusal = check_choice(
            WorkspaceKind::Isolated,
            None,
            InclusionPolicy::base_only(),
            true,
        )
        .expect_err("an isolated workspace names how it is separated");
        assert!(refusal.to_string().contains("not a security sandbox"));
        let refusal = check_choice(
            WorkspaceKind::Isolated,
            Some(IsolationMechanism::IndependentClone),
            InclusionPolicy::base_only(),
            false,
        )
        .expect_err("an isolated workspace names where its tree goes");
        assert!(refusal.to_string().contains("where its working tree goes"));
        check_choice(
            WorkspaceKind::Isolated,
            Some(IsolationMechanism::GitWorktree),
            InclusionPolicy::base_only(),
            true,
        )
        .expect("both choices made is a workspace this host creates");
    }

    #[test]
    fn a_worktree_is_never_described_as_a_sandbox() {
        let isolated = limitations_for(WorkspaceKind::Isolated);
        assert!(
            isolated
                .iter()
                .any(|line| line.contains("not a security sandbox")),
            "the limitation is stated: {isolated:?}"
        );
        assert!(
            isolated
                .iter()
                .any(|line| line.contains("cleaned, stashed or discarded")),
            "so is what an exclusion does not do: {isolated:?}"
        );
        let shared = limitations_for(WorkspaceKind::SharedExisting);
        assert!(
            shared
                .iter()
                .any(|line| line.contains("best-effort conflict detection")),
            "a shared workspace's apply contract is stated: {shared:?}"
        );
    }
}
