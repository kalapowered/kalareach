//! A file an emulator reads its profile from, written and taken out without ever leaving the
//! emulator a half-written file or taking out a file the person made.
//!
//! The file is built whole beside the *parent* of the directory the emulator watches, so nothing
//! the emulator can see is created but the finished file, and published with a hard link that fails
//! if the name is taken. Removal moves the file aside, into the same parent, and reads it there:
//! only a file that still holds what was written is deleted, and a changed one is put back.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use super::record::sha256_hex;

/// What is at a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Presence {
    /// Nothing.
    Missing,
    /// A regular file with this SHA-256.
    File(String),
    /// Something else: a directory, a link, a file that cannot be read.
    Other,
}

/// What is at `path`.
pub(super) fn presence(path: &Path) -> Presence {
    match path.symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Presence::Missing,
        Err(_) => Presence::Other,
        Ok(data) if data.is_file() => {
            std::fs::read(path).map_or(Presence::Other, |bytes| Presence::File(sha256_hex(&bytes)))
        }
        Ok(_) => Presence::Other,
    }
}

/// The directories that do not exist yet on the way to `directory`, outermost first: what making
/// `directory` would create.
pub(super) fn missing_directories(directory: &Path) -> Vec<PathBuf> {
    let mut missing: Vec<PathBuf> = directory
        .ancestors()
        .take_while(|ancestor| ancestor.symlink_metadata().is_err())
        .map(Path::to_path_buf)
        .collect();
    missing.reverse();
    missing
}

/// A name for a temporary file beside the parent of a watched directory.
fn temporary_name(purpose: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    format!(".kalareach-{purpose}-{}-{nanos}", std::process::id())
}

/// What a publish came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Published {
    /// The file is in place.
    Written,
    /// The file at the destination was not what the caller found there, and is left as it is.
    Changed,
}

/// Writes `text` to `destination`, building it first in `staging` and creating the directories in
/// `made`, outermost first.
///
/// With `replace` `None` the destination must not exist: the file is linked into place and the
/// link fails if the name is taken. With it `Some(digest)` the file at the destination is moved
/// aside and read there, and replaced only if it has that digest, which is the one the caller found
/// when it planned the write: a save of the person's in between is not overwritten but put back.
/// On failure nothing this call created is left.
///
/// # Errors
///
/// Returns the failure that stopped the write.
pub(super) fn publish(
    destination: &Path,
    staging: &Path,
    text: &str,
    made: &[PathBuf],
    replace: Option<&str>,
) -> std::io::Result<Published> {
    let mut created: Vec<&Path> = Vec::new();
    let undo = |created: &[&Path]| {
        for directory in created.iter().rev() {
            let _ = std::fs::remove_dir(directory);
        }
    };
    for directory in made {
        match std::fs::create_dir(directory) {
            Ok(()) => created.push(directory),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                undo(&created);
                return Err(error);
            }
        }
    }
    let temporary = staging.join(temporary_name("profile"));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(text.as_bytes())?;
            file.sync_all()
        });
    let published = written.and_then(|()| put_in_place(&temporary, destination, staging, replace));
    // The temporary name goes in every case: after a link the file is the destination's.
    let _ = std::fs::remove_file(&temporary);
    match published {
        Ok(Published::Written) => Ok(Published::Written),
        Ok(Published::Changed) => {
            undo(&created);
            Ok(Published::Changed)
        }
        Err(error) => {
            undo(&created);
            Err(error)
        }
    }
}

/// Links the finished file into place, after moving a file that is there aside and checking it is
/// the one `replace` names.
fn put_in_place(
    temporary: &Path,
    destination: &Path,
    staging: &Path,
    replace: Option<&str>,
) -> std::io::Result<Published> {
    let Some(expected) = replace else {
        return std::fs::hard_link(temporary, destination).map(|()| Published::Written);
    };
    let aside = staging.join(temporary_name("replacing"));
    match std::fs::rename(destination, &aside) {
        Ok(()) => {}
        // Gone since it was read: written as new.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return std::fs::hard_link(temporary, destination).map(|()| Published::Written);
        }
        Err(error) => return Err(error),
    }
    let held = std::fs::read(&aside).map(|bytes| sha256_hex(&bytes));
    if held.as_deref().is_ok_and(|held| held == expected) {
        return match std::fs::hard_link(temporary, destination) {
            Ok(()) => {
                let _ = std::fs::remove_file(&aside);
                Ok(Published::Written)
            }
            Err(error) => {
                // The name was taken in between: the file moved aside goes back if the name is
                // free, and is otherwise left where it is.
                if std::fs::hard_link(&aside, destination).is_ok() {
                    let _ = std::fs::remove_file(&aside);
                }
                Err(error)
            }
        };
    }
    // Not what was read when the write was planned: the person's file goes back as it was.
    match std::fs::hard_link(&aside, destination) {
        Ok(()) => {
            let _ = std::fs::remove_file(&aside);
            Ok(Published::Changed)
        }
        Err(error) => Err(std::io::Error::new(
            error.kind(),
            format!(
                "the file at the profile's place was changed and is left at {}: {error}",
                aside.display()
            ),
        )),
    }
}

/// What taking a file out came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Removal {
    /// The file was not there.
    Gone,
    /// The file held what was written and is deleted, with the directories that were made and are
    /// now empty.
    Removed,
    /// The file is not what was written. It is where it was when `restored`; otherwise the name
    /// was taken meanwhile and the file is at `left_at`.
    Changed { restored: bool, left_at: PathBuf },
}

/// Takes `destination` out if it still holds what has the digest `sha256`.
///
/// The file is moved aside into `staging` and read there, so what is deleted is the file that was
/// read; a file that is not what was written is linked back, and the link fails if the name was
/// taken in between. `made` are the directories the install made, outermost first; each is removed
/// only when it is empty.
///
/// # Errors
///
/// Returns the failure that stopped the removal.
pub(super) fn remove_if_unchanged(
    destination: &Path,
    staging: &Path,
    sha256: &str,
    made: &[PathBuf],
) -> std::io::Result<Removal> {
    match presence(destination) {
        Presence::Missing => return Ok(Removal::Gone),
        Presence::Other => {
            return Ok(Removal::Changed {
                restored: true,
                left_at: destination.to_path_buf(),
            });
        }
        Presence::File(_) => {}
    }
    let aside = staging.join(temporary_name("removing"));
    match std::fs::rename(destination, &aside) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Removal::Gone),
        Err(error) => return Err(error),
    }
    let held = std::fs::read(&aside).map(|bytes| sha256_hex(&bytes));
    if held.as_deref().is_ok_and(|held| held == sha256) {
        std::fs::remove_file(&aside)?;
        for directory in made.iter().rev() {
            if std::fs::remove_dir(directory).is_err() {
                break;
            }
        }
        return Ok(Removal::Removed);
    }
    match std::fs::hard_link(&aside, destination) {
        Ok(()) => {
            std::fs::remove_file(&aside)?;
            Ok(Removal::Changed {
                restored: true,
                left_at: destination.to_path_buf(),
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(Removal::Changed {
            restored: false,
            left_at: aside,
        }),
        Err(error) => Err(error),
    }
}
