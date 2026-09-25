//! Changing files in a directory another program reads, and keeping what protects them.
//!
//! Two installers write into an application's own directory: the contact skill's
//! ([`crate::agent_tools`]) and the native bridge recipes the catalogue applies. What both need
//! lives here, once: a replacement that cannot leave a document truncated and keeps its mode, the
//! refusal to replace a document whose access-control list the replacement would not carry, the
//! refusal on the platform where this host cannot read those lists, the durable directory entries,
//! and the digests a change is recorded by.

use std::path::{Path, PathBuf};

use kr_flush::{NameKind, flush_directory};
use kr_protocol::scalars::Digest256;

use crate::error::{ControllerError, Result};

/// Creates a directory and makes the entry that names it durable.
pub(crate) fn create_directory_durably(path: &Path) -> Result<bool> {
    let mut created = false;
    for directory in missing_ancestors(path) {
        match std::fs::create_dir(&directory) {
            Ok(()) => created = true,
            // Something else made it between the look and the call. It is not this host's to
            // claim, and claiming it would let a later removal delete somebody else's directory.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(storage(error)),
        }
        // The parent's own entry for it, not the new directory's contents: what has to survive is
        // the name, because everything written inside it is reached through that name.
        if let Some(parent) = directory.parent() {
            sync_directory(parent, NameKind::Directory)?;
        }
    }
    Ok(created)
}

/// Refuses a change to another program's files on a platform where this host cannot check that a
/// replacement keeps who may read the file it replaces.
///
/// Every file an installer here rewrites, its own record included, is replaced by a new file
/// renamed over it, and the new file carries whatever access-control list its directory gives it.
/// Before one takes an existing file's place this host compares the two, and it reads those lists
/// on macOS and Linux only (see [`guard_access_controls`] and [`write_atomically`]). Windows gives
/// every file a list, so there every replacement would be refused, the first of them part way
/// through, once the installation's record had been written. Rather than begin a change it would
/// have to abandon, this host makes none on Windows. `change` says what is refused and `instead`
/// what to do about it, in the caller's own words.
pub(crate) fn supported_platform(change: &str, instead: &str) -> Result<()> {
    // A compile-time value rather than a conditional body, so both answers are checked on every
    // platform this crate builds for.
    if cfg!(windows) {
        return Err(ControllerError::PermissionDenied {
            detail: format!(
                "this host does not {change} on Windows, because it does not read access-control \
                 lists there and so cannot tell whether replacing a file would change who can read \
                 it; {instead}"
            ),
        });
    }
    Ok(())
}

/// Refuses to replace a document whose protection this host cannot carry across.
///
/// A replacement by rename gives the new file its own access control. The mode bits are carried
/// across; an access-control list is not, and reapplying one needs the platform's own calls. An
/// agent's configuration can hold a credential, and somebody who restricted it beyond the mode bits
/// meant it, so a document carrying one is refused before anything is written rather than quietly
/// weakened. `instead` says what to do about a refusal, in the caller's own words.
pub(crate) fn guard_access_controls(path: &Path, instead: &str) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if extended_access_controls(path)? {
        return Err(ControllerError::PermissionDenied {
            detail: format!(
                "{} is protected by an access-control list, and changing it here would not carry \
                 that across; {instead}",
                display(path)
            ),
        });
    }
    // Changing it means writing a new file beside it and renaming that over it. A directory that
    // grants access to whatever is created in it would give that grant to the replacement, and the
    // document being replaced does not have it. The write itself checks the copy it made; this
    // check is here so the refusal comes before anything is installed rather than half way through.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if inheritable_access_controls(parent)? {
        return Err(ControllerError::PermissionDenied {
            detail: format!(
                "{} grants access to the files created in it, which {} does not have, and changing \
                 that document here would replace it with one that does; {instead}",
                display(parent),
                display(path)
            ),
        });
    }
    Ok(())
}

/// Returns true when the file carries access controls its mode bits do not describe.
///
/// # Errors
///
/// Returns [`ControllerError::Storage`] when the file's access controls cannot be read, because a
/// protection this host cannot read is one it cannot promise to keep.
#[cfg(target_os = "macos")]
pub(crate) fn extended_access_controls(path: &Path) -> Result<bool> {
    // A file with no list of its own has an empty one here: this platform keeps no mode bits in it,
    // so anything in it is an extra grant or an extra restriction somebody added.
    exacl::getfacl(path, None)
        .map(|entries| !entries.is_empty())
        .map_err(storage)
}

#[cfg(target_os = "linux")]
pub(crate) fn extended_access_controls(path: &Path) -> Result<bool> {
    // This platform keeps a POSIX access-control list in one extended attribute, and a file without
    // that attribute is described by its mode bits alone.
    let mut probe = [0_u8; 1];
    interpret_probe(rustix::fs::getxattr(
        path,
        "system.posix_acl_access",
        &mut probe[..],
    ))
}

/// Turns the answer to an access-control probe into what it says about the file.
#[cfg(target_os = "linux")]
fn interpret_probe(answer: std::result::Result<usize, rustix::io::Errno>) -> Result<bool> {
    match answer {
        // There is a list. One byte of it is as much as this needs to know, so a list longer than
        // the byte offered for it answers the question as well as a shorter one would.
        Ok(_) | Err(rustix::io::Errno::RANGE) => Ok(true),
        Err(rustix::io::Errno::NODATA) => Ok(false),
        // Anything else is a failure to look, including a filesystem that does not answer this
        // question: a refusal to answer is not an answer of "none". An NFSv4 share keeps its list
        // somewhere else entirely and refuses this one, and a file protected there must not be
        // replaced on the strength of a probe that never saw its protection.
        Err(error) => Err(storage(std::io::Error::from(error))),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn extended_access_controls(path: &Path) -> Result<bool> {
    // Nothing here can read this platform's access controls, so nothing here can promise to keep
    // them. An existing document is refused rather than replaced.
    let _ = path;
    Ok(true)
}

/// Returns true when files created in this directory are given access controls by it.
///
/// # Errors
///
/// Returns [`ControllerError::Storage`] when the directory's access controls cannot be read.
#[cfg(target_os = "macos")]
fn inheritable_access_controls(directory: &Path) -> Result<bool> {
    exacl::getfacl(directory, None)
        .map(|entries| {
            entries
                .iter()
                .any(|entry| entry.flags.contains(exacl::Flag::FILE_INHERIT))
        })
        .map_err(storage)
}

#[cfg(target_os = "linux")]
fn inheritable_access_controls(directory: &Path) -> Result<bool> {
    // What a directory gives the files made in it is its default list, in an attribute of its own.
    let mut probe = [0_u8; 1];
    interpret_probe(rustix::fs::getxattr(
        directory,
        "system.posix_acl_default",
        &mut probe[..],
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn inheritable_access_controls(directory: &Path) -> Result<bool> {
    let _ = directory;
    Ok(true)
}

/// Makes a directory's own entries durable.
///
/// A rename or an unlink is not on disk until the directory holding it is. `kind` is the name that
/// changed in it, a file's or a directory's, which is the right the flush's handle asks for on
/// Windows: a directory this host removed is flushed for a directory's name, the right it was
/// created under.
pub(crate) fn sync_directory(path: &Path, kind: NameKind) -> Result<()> {
    flush_directory(path, kind).map_err(storage)
}

/// Returns the directories that have to be created for this path to exist, outermost first.
pub(crate) fn missing_ancestors(path: &Path) -> Vec<PathBuf> {
    let mut missing = Vec::new();
    let mut current = Some(path);
    while let Some(directory) = current {
        if directory.is_dir() {
            break;
        }
        missing.push(directory.to_path_buf());
        current = directory.parent();
    }
    missing.reverse();
    missing
}

pub(crate) fn read_digest(path: &Path) -> Result<Option<Digest256>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(digest_of(&bytes))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(storage(error)),
    }
}

pub(crate) fn digest_of(bytes: &[u8]) -> Digest256 {
    Digest256::from_bytes(kr_cbor::sha256(bytes))
}

/// The permissions a file another program only reads is created with: a skill's documentation, a
/// bridge's registration.
pub(crate) const READABLE: u32 = 0o644;

/// The permissions a configuration document or a host record is created with.
///
/// An application's configuration can hold a credential, so one this host creates is the owner's
/// alone.
pub(crate) const PRIVATE: u32 = 0o600;

/// Writes a file so a failure part way through cannot truncate what was there.
///
/// The replacement carries the permissions of what it replaces: a document somebody kept private
/// must not become world-readable because this host rewrote it under its own umask. A file that
/// did not exist is created with `default_mode`.
pub(crate) fn write_atomically(path: &Path, bytes: &[u8], default_mode: u32) -> Result<()> {
    use std::io::Write as _;

    let parent = path.parent().unwrap_or(Path::new("."));
    // A distinct name per write. A fixed one is a collision between two callers writing the same
    // file, and each would see the other's half-written bytes.
    let temporary = parent.join(format!(
        ".{}.{}.kalareach",
        file_name(path),
        hex(&kr_cbor::sha256(kr_ipc::new_uuid().as_bytes())[..6])
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        // The permissions are set before the content exists. Writing first and narrowing after
        // would leave a readable copy of a private document for as long as the write takes, and
        // for good after a crash.
        let mode = std::fs::metadata(path)
            .ok()
            .map_or(default_mode, |existing| {
                existing.permissions().mode() & 0o777
            });
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = default_mode;
    let mut file = options.open(&temporary).map_err(storage)?;
    // The copy that is about to take an existing file's place, before anything is written into it.
    // A directory can give what is created in it access its own files do not have, and the rename
    // below would hand that to the document being replaced.
    if path.exists() && extended_access_controls(&temporary)? {
        drop(file);
        let _ = std::fs::remove_file(&temporary);
        return Err(ControllerError::PermissionDenied {
            detail: format!(
                "a new file in {} is given an access-control list by the directory itself, so \
                 replacing {} here would change who can read it",
                display(parent),
                display(path)
            ),
        });
    }
    file.write_all(bytes).map_err(storage)?;
    // The bytes reach the disk before the rename that publishes them, and the directory entry
    // reaches it before this call returns, so a record written before an effect is on disk before
    // the effect begins.
    file.sync_all().map_err(storage)?;
    drop(file);
    std::fs::rename(&temporary, path).map_err(storage)?;
    // The rename is not on disk until the directory holding it is. A failure here is reported
    // rather than swallowed: a record that claims durability it does not have is worse than one
    // that says it could not be written.
    sync_directory(parent, NameKind::File)
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_owned())
}

pub(crate) fn display(path: &Path) -> String {
    path.display().to_string()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
        text
    })
}

pub(crate) fn storage(error: std::io::Error) -> ControllerError {
    ControllerError::Storage {
        operation: "change an agent's configuration",
        detail: error.to_string(),
    }
}

/// Returns this user's home directory.
pub(crate) fn home_directory() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Linux probe's answers, including the one that is not an answer.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_probe_that_cannot_answer_is_not_read_as_no_list() {
        assert!(interpret_probe(Ok(1)).expect("a list"));
        assert!(interpret_probe(Err(rustix::io::Errno::RANGE)).expect("a longer list"));
        assert!(!interpret_probe(Err(rustix::io::Errno::NODATA)).expect("no list"));
        // An NFSv4 share keeps its list somewhere this probe cannot see and refuses the question.
        // A refusal to answer is not an answer of "none".
        assert!(interpret_probe(Err(rustix::io::Errno::NOTSUP)).is_err());
    }

    /// The refusal names what is refused and what to do instead, and only where it applies.
    #[test]
    fn the_platform_guard_refuses_on_windows_alone() {
        let answer = supported_platform("change this", "do that instead");
        if cfg!(windows) {
            let refused = answer.expect_err("refuses");
            assert!(
                matches!(refused, ControllerError::PermissionDenied { ref detail }
                    if detail.contains("does not change this on Windows")
                        && detail.contains("does not read access-control lists")
                        && detail.ends_with("do that instead")),
                "{refused:?}"
            );
        } else {
            answer.expect("changes are made here");
        }
    }
}
