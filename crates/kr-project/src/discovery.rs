//! Finding a repository through a location's handle, before Git is asked anything about it.
//!
//! Git's own discovery opens a repository's common directory and its per-worktree directory for
//! itself, so a check made after it is too late. When a repository is reached through a location
//! the owner authorised, this host finds those directories itself, each from its own base and
//! each by a descent from the location's held handle, and refuses the repository to the location
//! when any of them would lead anywhere else. Every step is one of
//! [`AuthorisedDirectory`]'s: no link is followed, no component leaves the directory above it,
//! and nothing on another mount is entered.
//!
//! | # | Value | Base it is relative to | Rule |
//! | --- | --- | --- | --- |
//! | 1 | `.git` as a directory | the working tree | that is the Git directory |
//! | 1 | `gitdir: <path>` in a `.git` file | the working tree, which holds the file | a relative name beneath it |
//! | 2 | `commondir` in the Git directory | the Git directory | a relative name beneath it; absent means the Git directory is the common one |
//! | 3 | the object directory | the common directory | `objects` beneath it |
//! | 4 | each line of `objects/info/alternates` | the object directory that holds the file | a relative name beneath it, and then the same rule from that alternate's own object directory |
//!
//! And what each other path-bearing file decides:
//!
//! * A worktree backlink (`worktrees/` in the common directory) refuses the repository, whatever
//!   its form: a relative backlink would pass a name check, and a linked worktree is not
//!   something a location reaches.
//! * A submodule (`.gitmodules` in the working tree or `modules/` in the common directory) refuses
//!   it too: a submodule's own `.git` names a directory of its own.
//! * `info/exclude` and `info/attributes` in the common directory, and `info/sparse-checkout` in the
//!   per-worktree directory, hold patterns rather than paths; each has to be a file beneath its
//!   own base, not a link.
//! * Anything else under `objects/info/` has to be reached without a link, and an
//!   `http-alternates` file, which names objects over a network, refuses the repository.
//! * `core.worktree` is read with the rest of the configuration, after this, and refuses the
//!   repository there: overriding it would change where Git looks without proving where it looked.
//!
//! A repository refused here is refused to the location, before any read: the operation is refused
//! rather than narrowed. A repository the owner reaches without a location is found by Git as it
//! always was.

use std::collections::BTreeSet;
use std::io::Read as _;

use kr_transfer::authority::ObjectKind;
use kr_transfer::{AuthorisedDirectory, Escape, ObjectIdentity, ObjectPolicy, RelativeName};

use crate::error::{ProjectError, Result};

/// How many object directories one repository may reach through alternates, its own included.
pub const MAX_OBJECT_DIRECTORIES: usize = 16;

/// How long a chain of alternates may be.
pub const MAX_ALTERNATE_DEPTH: usize = 4;

/// The longest metadata file this host reads while it discovers a repository.
const MAX_METADATA_BYTES: u64 = 64 * 1024;

/// A repository found through a location, as handles.
#[derive(Debug)]
pub struct Discovered {
    /// The working tree.
    pub work_tree: AuthorisedDirectory,
    /// This working tree's own Git directory.
    pub git_dir: AuthorisedDirectory,
    /// The directory every worktree of the repository shares.
    pub common_dir: AuthorisedDirectory,
    /// The object directory and every alternate it reaches, the object directory first.
    pub objects: Vec<AuthorisedDirectory>,
}

/// Finds the repository whose working tree `work_tree` is, through that handle alone.
///
/// `shown` names the working tree in a refusal, for a person to read.
///
/// # Errors
///
/// Returns [`ProjectError::PermissionDenied`] naming the value when the repository reaches
/// anything the location does not, or [`ProjectError::Destination`] when it is not a repository.
pub fn discover(work_tree: AuthorisedDirectory, shown: &str) -> Result<Discovered> {
    let git_dir = match kind_of(&work_tree, ".git", shown)? {
        Some(ObjectKind::Directory) => work_tree.subdirectory(&name(".git")?)?,
        Some(ObjectKind::File) => {
            let text = read_small(&work_tree, ".git", shown)?;
            let Some(value) = text.trim_end_matches(['\n', '\r']).strip_prefix("gitdir: ") else {
                return Err(refused(
                    shown,
                    ".git",
                    "is a file that names no Git directory",
                ));
            };
            work_tree.subdirectory(&beneath(shown, ".git", value)?)?
        }
        Some(_) => return Err(refused(shown, ".git", "is neither a directory nor a file")),
        None => {
            return Err(ProjectError::Destination {
                detail: format!(
                    "{} holds no .git, so it is not a Git working tree",
                    crate::git::redact(shown)
                )
                .into(),
            });
        }
    };
    let common_dir = match kind_of(&git_dir, "commondir", shown)? {
        None => git_dir.try_clone()?,
        Some(ObjectKind::File) => {
            let text = read_small(&git_dir, "commondir", shown)?;
            git_dir.subdirectory(&beneath(
                shown,
                "commondir",
                text.trim_end_matches(['\n', '\r']),
            )?)?
        }
        Some(_) => return Err(refused(shown, "commondir", "is not a file")),
    };
    if kind_of(&common_dir, "worktrees", shown)?.is_some() {
        return Err(refused(
            shown,
            "worktrees",
            "is there, so the repository carries a worktree backlink, and a linked worktree is \
             not something a location reaches",
        ));
    }
    if kind_of(&work_tree, ".gitmodules", shown)?.is_some()
        || kind_of(&common_dir, "modules", shown)?.is_some()
    {
        return Err(refused(
            shown,
            ".gitmodules",
            "says the repository has submodules, and a submodule's own .git names a directory \
             of its own",
        ));
    }
    require_pattern_file(&common_dir, "info/exclude", shown)?;
    require_pattern_file(&common_dir, "info/attributes", shown)?;
    require_pattern_file(&git_dir, "info/sparse-checkout", shown)?;
    let objects = common_dir.subdirectory(&name("objects")?)?;
    let mut found = Vec::new();
    let mut visited = BTreeSet::new();
    follow_objects(objects, 0, &mut found, &mut visited, shown)?;
    Ok(Discovered {
        work_tree,
        git_dir,
        common_dir,
        objects: found,
    })
}

/// Takes in one object directory and every alternate it reaches, each from the directory that
/// names it.
fn follow_objects(
    objects: AuthorisedDirectory,
    depth: usize,
    found: &mut Vec<AuthorisedDirectory>,
    visited: &mut BTreeSet<ObjectIdentity>,
    shown: &str,
) -> Result<()> {
    if !visited.insert(objects.identity()) {
        return Err(refused(
            shown,
            "objects/info/alternates",
            "reaches an object directory it already reached, so the alternates loop",
        ));
    }
    if found.len() >= MAX_OBJECT_DIRECTORIES {
        return Err(refused(
            shown,
            "objects/info/alternates",
            &format!("reach more than {MAX_OBJECT_DIRECTORIES} object directories"),
        ));
    }
    let mut alternates = Vec::new();
    if matches!(
        kind_of(&objects, "info", shown)?,
        Some(ObjectKind::Directory)
    ) {
        let info = objects.subdirectory(&name("info")?)?;
        for entry in entries_of(&info, shown)? {
            match kind_of(&info, &entry, shown)? {
                None => {}
                Some(ObjectKind::Link) => {
                    return Err(refused(
                        shown,
                        &format!("objects/info/{entry}"),
                        "is a link",
                    ));
                }
                Some(_) if entry == "http-alternates" => {
                    return Err(refused(
                        shown,
                        "objects/info/http-alternates",
                        "names objects over a network",
                    ));
                }
                Some(ObjectKind::File) if entry == "alternates" => {
                    let text = read_small(&info, "alternates", shown)?;
                    for line in text.lines() {
                        let line = line.trim_end_matches('\r');
                        // Git skips an empty line and one that starts with `#`.
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        alternates.push(beneath(shown, "objects/info/alternates", line)?);
                    }
                }
                Some(_) => {}
            }
        }
    }
    let base = objects.try_clone()?;
    found.push(objects);
    for alternate in alternates {
        if depth + 1 > MAX_ALTERNATE_DEPTH {
            return Err(refused(
                shown,
                "objects/info/alternates",
                &format!("chain more than {MAX_ALTERNATE_DEPTH} object directories deep"),
            ));
        }
        let reached = base.subdirectory(&alternate)?;
        follow_objects(reached, depth + 1, found, visited, shown)?;
    }
    Ok(())
}

/// Requires one pattern file, when it is there, to be a file beneath its own base.
fn require_pattern_file(base: &AuthorisedDirectory, relative: &str, shown: &str) -> Result<()> {
    match base.probe(&name(relative)?) {
        Ok(ObjectKind::File) => Ok(()),
        Ok(_) => Err(refused(shown, relative, "is not a file")),
        Err(Escape::NotFound { .. }) => Ok(()),
        Err(Escape::Link { .. }) => Err(refused(shown, relative, "reaches through a link")),
        Err(other) => Err(other.into()),
    }
}

/// Says what one single-component name in `base` is, without following it, or none when nothing
/// is there.
fn kind_of(base: &AuthorisedDirectory, entry: &str, shown: &str) -> Result<Option<ObjectKind>> {
    match base.probe(&name(entry)?) {
        Ok(kind) => Ok(Some(kind)),
        Err(Escape::NotFound { .. }) => Ok(None),
        Err(Escape::Link { .. }) => Err(refused(shown, entry, "reaches through a link")),
        Err(other) => Err(other.into()),
    }
}

/// Lists the names one directory holds, through its handle.
fn entries_of(directory: &AuthorisedDirectory, shown: &str) -> Result<Vec<String>> {
    let listing = directory
        .handle()
        .entries()
        .map_err(|error| unreadable(shown, &error))?;
    let mut names = Vec::new();
    for entry in listing {
        let entry = entry.map_err(|error| unreadable(shown, &error))?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    Ok(names)
}

/// Reads one small metadata file through the handle of the directory that holds it.
fn read_small(base: &AuthorisedDirectory, entry: &str, shown: &str) -> Result<String> {
    let mut opened = base.open_read(&name(entry)?, ObjectPolicy::ReadableFile)?;
    if opened.byte_len() > MAX_METADATA_BYTES {
        return Err(refused(
            shown,
            entry,
            &format!("is longer than {MAX_METADATA_BYTES} bytes"),
        ));
    }
    let mut text = String::new();
    opened
        .handle_mut()
        .take(MAX_METADATA_BYTES)
        .read_to_string(&mut text)
        .map_err(|error| unreadable(shown, &error))?;
    Ok(text)
}

/// Parses a value one metadata file names as a name beneath the directory it is relative to.
///
/// An absolute path, a parent segment and any other form a relative name refuses are refused
/// here, naming the value: nothing is reinterpreted against another base to make it fit.
fn beneath(shown: &str, file: &str, value: &str) -> Result<RelativeName> {
    RelativeName::parse(value).map_err(|escape| {
        refused(
            shown,
            file,
            &format!(
                "names {}, which is not beneath the directory it is relative to ({escape})",
                crate::git::redact(value)
            ),
        )
    })
}

fn name(text: &str) -> Result<RelativeName> {
    Ok(RelativeName::parse(text)?)
}

fn refused(shown: &str, file: &str, what: &str) -> ProjectError {
    ProjectError::PermissionDenied {
        detail: format!(
            "the repository at {} is not reached through a location: its {file} {what}",
            crate::git::redact(shown)
        )
        .into(),
    }
}

fn unreadable(shown: &str, error: &std::io::Error) -> ProjectError {
    ProjectError::Destination {
        detail: format!(
            "the repository at {} could not be read: {error}",
            crate::git::redact(shown)
        )
        .into(),
    }
}
