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
//!   workspace starts without that file; it never means the original is touched. The restricted
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
    InclusionChoice, InclusionClass, InclusionPolicy, InclusionPreview, IsolationMechanism,
    MAX_BINARY_SCAN_ENTRIES, MAX_PREVIEW_ENTRIES, PreviewCount, PreviewEntry, WorkspaceKind,
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
}

/// One entry of the working tree, with the decision the policy made about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurveyEntry {
    /// The path, relative to the repository's top level.
    pub path: String,
    /// Which class it belongs to.
    pub class: InclusionClass,
    /// Whether Git's own test calls its content binary.
    pub binary: bool,
    /// Its size, when the host could read one.
    pub byte_len: Option<u64>,
    /// Whether the policy in force copies it into the new workspace.
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
    for record in text.split('\0') {
        if record.is_empty() {
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
            }),
            "!" => entries.push(StatusEntry {
                path: rest.to_owned(),
                class: InclusionClass::GeneratedArtefact,
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
                let submodule = parts[1];
                let path = parts[fields - 1];
                if path.is_empty() {
                    return Err(malformed(record));
                }
                entries.push(StatusEntry {
                    class: if submodule.starts_with('S') {
                        InclusionClass::Submodule
                    } else {
                        InclusionClass::DirtyFile
                    },
                    path: path.to_owned(),
                });
            }
            _ => return Err(malformed(record)),
        }
    }
    Ok(entries)
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
    let arguments: [&OsStr; 6] = [
        OsStr::new("status"),
        OsStr::new("--porcelain=v2"),
        OsStr::new("-z"),
        OsStr::new("--untracked-files=all"),
        OsStr::new("--ignored=matching"),
        OsStr::new("--no-renames"),
    ];
    let reported = profile.run_checked(&repository.read(&arguments))?;
    // A wholly ignored directory is reported as one entry with a trailing separator, because that
    // is how the ignore rule matched. Expanded here so the counts are exact and an inclusion
    // copies the files rather than nothing.
    let mut budget = MAX_BINARY_SCAN_ENTRIES;
    let mut truncated = 0_u64;
    let mut status: Vec<StatusEntry> = Vec::new();
    for entry in parse_status(&reported)? {
        match entry.path.strip_suffix('/') {
            None => status.push(entry),
            Some(prefix) => expand(
                repository.work_tree(),
                prefix,
                entry.class,
                &mut status,
                &mut budget,
                &mut truncated,
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
    let mut unscanned = 0_u64;
    let shared = matches!(request.kind, WorkspaceKind::SharedExisting);
    for entry in status {
        let measured = measure(repository.work_tree(), &entry.path, &mut scanned);
        if measured.binary_unscanned {
            unscanned += 1;
        }
        // A shared workspace keeps the user's state where it is, so a reviewer of one sees
        // everything that is there whatever the policy says.
        let included = shared
            || (matches!(request.policy.choice(entry.class), InclusionChoice::Include)
                && (!measured.binary
                    || matches!(request.policy.binary_files, InclusionChoice::Include)));
        bump(&mut counts, entry.class, measured.byte_len, included);
        if measured.binary {
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
            binary: measured.binary,
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
            binary: entry.binary,
            byte_len: Nullable(entry.byte_len.map(U64::new)),
            included: entry.included,
        })
        .collect();
    let omitted = u64::try_from(entries.len().saturating_sub(sample.len())).unwrap_or(u64::MAX);
    let mut limitations = limitations_for(request.kind);
    limitations.extend(repository.audit().limitations());
    if unscanned > 0 {
        limitations.push(format!(
            "{unscanned} paths beyond the first {MAX_BINARY_SCAN_ENTRIES} were not read, so they \
             are counted in their own class and not among the binary files"
        ));
    }
    if truncated > 0 {
        limitations.push(format!(
            "{truncated} ignored directories hold more than the {MAX_BINARY_SCAN_ENTRIES} paths \
             this preview walks, or are nested deeper than {MAX_DIRECTORY_DEPTH} levels, so what \
             they hold beyond that is neither counted nor copied"
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
            limitations,
            taken_at_ms: request.at_ms,
        },
        entries,
    })
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
    out: &mut Vec<StatusEntry>,
    budget: &mut usize,
    truncated: &mut u64,
    depth: usize,
) {
    if depth >= MAX_DIRECTORY_DEPTH || *budget == 0 {
        *truncated += 1;
        return;
    }
    let Ok(name) = RelativeName::parse(prefix) else {
        return;
    };
    let Ok(directory) = tree.subdirectory(&name) else {
        // Not a directory after all, or not reachable. It is still one entry the status reported.
        out.push(StatusEntry {
            path: prefix.to_owned(),
            class,
        });
        return;
    };
    let Ok(entries) = directory.handle().entries() else {
        *truncated += 1;
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_name) = entry.file_name().into_string() else {
            continue;
        };
        let child = format!("{prefix}/{file_name}");
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => {
                expand(tree, &child, class, out, budget, truncated, depth + 1);
            }
            Ok(kind) if kind.is_file() => {
                if *budget == 0 {
                    *truncated += 1;
                    return;
                }
                *budget -= 1;
                out.push(StatusEntry { path: child, class });
            }
            // A link, a socket or a device is not content this host copies.
            _ => {}
        }
    }
}

/// What reading one entry established.
#[derive(Clone, Copy, Debug, Default)]
struct Measured {
    byte_len: Option<u64>,
    binary: bool,
    binary_unscanned: bool,
}

/// Reads one entry's size, and whether Git's own test calls it binary.
///
/// The read goes through the authorised directory handle, so a link or a path that leaves the tree
/// is refused rather than followed. A path the host cannot read is reported with no size and as
/// text, because a preview that refused to be taken would be less useful than one that says what
/// it could not measure.
fn measure(tree: &AuthorisedDirectory, path: &str, scanned: &mut usize) -> Measured {
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
            binary: false,
            binary_unscanned: true,
        };
    }
    *scanned += 1;
    let wanted = BINARY_SCAN_BYTES.min(usize::try_from(byte_len).unwrap_or(usize::MAX));
    let mut head = vec![0_u8; wanted];
    let mut read = 0_usize;
    let handle = file.handle_mut();
    while read < head.len() {
        match handle.read(&mut head[read..]) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    Measured {
        byte_len: Some(byte_len),
        binary: head[..read].contains(&0),
        binary_unscanned: false,
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
             workspace starts without the file, and the original stays where it is"
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
    /// The paths that could not be read or written, each named rather than hidden.
    pub skipped: Vec<String>,
    /// How many bytes were copied.
    pub byte_len: u64,
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
) -> Result<CopyReport> {
    let mut report = CopyReport::default();
    for entry in entries {
        // A submodule is its own repository with its own configuration, and copying its working
        // tree would be copying a repository this host has not opened. Including one records the
        // decision and the materialisation is the submodule task's.
        if !entry.included || matches!(entry.class, InclusionClass::Submodule) {
            continue;
        }
        let Ok(name) = RelativeName::parse(&entry.path) else {
            report.skipped.push(entry.path.clone());
            continue;
        };
        if copy_one(source, destination, &name, &mut report.byte_len)? {
            report.copied.push(entry.path.clone());
        } else {
            report.skipped.push(entry.path.clone());
        }
    }
    Ok(report)
}

fn copy_one(
    source: &AuthorisedDirectory,
    destination: &AuthorisedDirectory,
    name: &RelativeName,
    total: &mut u64,
) -> Result<bool> {
    let Ok(file) = source.open_read(name, ObjectPolicy::ReadableFile) else {
        return Ok(false);
    };
    let byte_len = file.byte_len();
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
        here = Some(above.create_subdirectory(&component)?);
    }
    let target = here.as_ref().unwrap_or(destination);
    let leaf = RelativeName::parse(leaf)?;
    let mut handle = file.into_handle();
    // The checkout may already have put the base's content at this name, and the user's own
    // content is what an inclusion means, so an existing name is written rather than refused.
    let mut written = match target.create_new(&leaf) {
        Ok(created) => created,
        Err(_) => target.open_write(&leaf)?,
    };
    let mut buffer = vec![0_u8; 256 * 1024];
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
    target.sync()?;
    Ok(true)
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
                    class: InclusionClass::DirtyFile
                },
                StatusEntry {
                    path: "src/staged.rs".to_owned(),
                    class: InclusionClass::DirtyFile
                },
                StatusEntry {
                    path: "vendor/library".to_owned(),
                    class: InclusionClass::Submodule
                },
                StatusEntry {
                    path: "src/conflicted.rs".to_owned(),
                    class: InclusionClass::DirtyFile
                },
                StatusEntry {
                    path: "new-file.txt".to_owned(),
                    class: InclusionClass::UntrackedFile
                },
                StatusEntry {
                    path: "target/debug/binary".to_owned(),
                    class: InclusionClass::GeneratedArtefact
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
