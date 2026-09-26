//! Changing files in a directory another program reads, and keeping what protects them.
//!
//! Two installers write into an application's own directory: the contact skill's
//! ([`crate::agent_tools`]) and the native bridge recipes the catalogue applies. What both need
//! lives here, once: a replacement that cannot leave a document truncated and keeps who can read
//! it, the refusal to replace a document whose access controls the replacement would not carry,
//! the durable directory entries, and the digests a change is recorded by.

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
    let extended = extended_access_controls(path).map_err(|error| match error {
        // A control this host does not evaluate is refused as one it cannot carry is, with the
        // same advice.
        ControllerError::PermissionDenied { detail } => ControllerError::PermissionDenied {
            detail: format!("{detail}; {instead}"),
        },
        other => other,
    })?;
    if extended {
        return Err(ControllerError::PermissionDenied {
            detail: format!("{} {NOT_CARRIED}; {instead}", display(path)),
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

/// Returns true when the file has access controls a new file written beside it would not be
/// given: an owner other than the one this process gives the files it creates, a list protected
/// from its directory, absent or empty, or an entry set on the file itself where its list records
/// which entries it inherited.
///
/// A replacement is a new file renamed over the old one, and Windows gives a new file its owner
/// from this process and its lists from its directory. A list written the older way does not
/// record which entries it inherited, so an entry set on such a file is not seen here; the write
/// compares the copy it made with the file before either replaces the other, and refuses there.
///
/// # Errors
///
/// Returns [`ControllerError::Storage`] when the file's access cannot be read, and
/// [`ControllerError::PermissionDenied`] when it carries a control this host does not evaluate:
/// encryption, or an entry of a kind this host does not read.
#[cfg(windows)]
pub(crate) fn extended_access_controls(path: &Path) -> Result<bool> {
    let access =
        kr_ipc::paths::FileAccess::of(path).map_err(|refusal| refused_read(path, refusal))?;
    let owned = access
        .is_owned_as_new_files_are()
        .map_err(|refusal| refused_read(path, refusal))?;
    Ok(!owned || !access.records_nothing_set_here())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
pub(crate) fn extended_access_controls(path: &Path) -> Result<bool> {
    // Nothing here can read this platform's access controls, so nothing here can promise to keep
    // them. An existing document is refused rather than replaced.
    let _ = path;
    Ok(true)
}

/// Answers a refusal of the Windows access reader: a read that failed is a storage failure, and a
/// control the reader does not evaluate is a refusal to change the file.
#[cfg(windows)]
fn refused_read(path: &Path, refusal: kr_ipc::paths::AccessListRefusal) -> ControllerError {
    match refusal {
        kr_ipc::paths::AccessListRefusal::Unreadable(detail) => storage(std::io::Error::other(
            format!("{}: {detail}", display(path)),
        )),
        kr_ipc::paths::AccessListRefusal::Policy(detail) => ControllerError::PermissionDenied {
            detail: format!(
                "{}: {detail}, so this host cannot tell whether replacing it would change who can \
                 read it",
                display(path)
            ),
        },
    }
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

/// On Windows a document whose descriptor records nothing set on it carries what its directory
/// gives its files, which a replacement made there is given too, so the directory is not read
/// here. Where the directory's list changed since the document inherited from it, or the document
/// was moved in from another directory, the write compares the copy it made with the document and
/// refuses there.
#[cfg(windows)]
fn inheritable_access_controls(directory: &Path) -> Result<bool> {
    let _ = directory;
    Ok(false)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn inheritable_access_controls(directory: &Path) -> Result<bool> {
    let _ = directory;
    Ok(true)
}

/// Why a document is refused when its access controls are ones a replacement would not carry.
#[cfg(not(windows))]
const NOT_CARRIED: &str =
    "is protected by an access-control list, and changing it here would not carry that across";

/// Why a document is refused when its access controls are ones a replacement would not carry.
#[cfg(windows)]
const NOT_CARRIED: &str = "has an owner or an access-control list that a new file in its directory \
     would not be given, and changing it here would change who can read it";

/// What a copy that would change who can read the document it replaces is given.
#[cfg(not(windows))]
const COPY_DIFFERS: &str = "is given an access-control list by the directory itself";

/// What a copy that would change who can read the document it replaces is given.
#[cfg(windows)]
const COPY_DIFFERS: &str =
    "is given another owner or access-control list than the file it would replace";

/// Returns true when the copy about to take `document`'s place would change who can read it.
///
/// On macOS and Linux the copy was created with the document's mode bits, so what it can differ in
/// is an access-control list its directory gave it.
#[cfg(not(windows))]
fn copy_changes_access(_copy: &std::fs::File, temporary: &Path, _document: &Path) -> Result<bool> {
    extended_access_controls(temporary)
}

/// Returns true when the copy about to take `document`'s place would change who can read it.
///
/// On Windows the copy's owner and lists, read through the handle that created it, are compared
/// with the document's, read again now, whole.
#[cfg(windows)]
fn copy_changes_access(copy: &std::fs::File, temporary: &Path, document: &Path) -> Result<bool> {
    let copy = kr_ipc::paths::FileAccess::read(copy)
        .map_err(|refusal| refused_read(temporary, refusal))?;
    let document = kr_ipc::paths::FileAccess::of(document)
        .map_err(|refusal| refused_read(document, refusal))?;
    Ok(copy != document)
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
    // On Windows the copy's own handle reads its access back, which needs it to read as well.
    #[cfg(windows)]
    options.read(true);
    let mut file = options.open(&temporary).map_err(storage)?;
    // The copy that is about to take an existing file's place, before anything is written into it.
    // A directory can give what is created in it access its own files do not have, and the rename
    // below would hand that to the document being replaced. A check that cannot be made refuses as
    // one that fails does, and neither leaves the copy behind.
    let changes = if path.exists() {
        copy_changes_access(&file, &temporary, path)
    } else {
        Ok(false)
    };
    if !matches!(changes, Ok(false)) {
        drop(file);
        let _ = std::fs::remove_file(&temporary);
        changes?;
        return Err(ControllerError::PermissionDenied {
            detail: format!(
                "a new file in {} {COPY_DIFFERS}, so replacing {} here would change who can read \
                 it",
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

    /// A document is replaced whole and nothing is left beside it, on every platform: a copy made
    /// in the document's own directory keeps who can read it, so the check at the replacement
    /// lets it take the document's place.
    #[test]
    fn a_document_is_replaced_whole_and_nothing_is_left_beside_it() {
        let directory = tempfile::tempdir().expect("a directory");
        let document = directory.path().join("settings.json");
        write_atomically(&document, b"first", PRIVATE).expect("creates it");
        write_atomically(&document, b"second", PRIVATE).expect("replaces it");
        assert_eq!(std::fs::read(&document).expect("reads it"), b"second");
        let names: Vec<_> = std::fs::read_dir(directory.path())
            .expect("lists the directory")
            .map(|entry| entry.expect("an entry").file_name())
            .collect();
        assert_eq!(names, ["settings.json"], "no copy is left beside it");
    }

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

    /// A read of a file's access that failed is a storage failure, and a control the reader does
    /// not evaluate is a refusal to change the file.
    #[cfg(windows)]
    #[test]
    fn a_refused_read_of_a_files_access_is_answered_by_its_kind() {
        use kr_ipc::paths::AccessListRefusal;

        let path = Path::new("C:\\somewhere\\config.toml");
        assert!(matches!(
            refused_read(
                path,
                AccessListRefusal::Unreadable("it could not be read".to_owned())
            ),
            ControllerError::Storage { .. }
        ));
        assert!(matches!(
            refused_read(
                path,
                AccessListRefusal::Policy("it is encrypted".to_owned())
            ),
            ControllerError::PermissionDenied { .. }
        ));
    }
}
