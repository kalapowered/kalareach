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
/// weakened. So is one whose owner or group is not the one the replacement would get: on macOS and
/// Linux a document of root's, or of another group, in a directory this user may write would
/// become this user's. `instead` says what to do about a refusal, in the caller's own words.
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
    // The replacement belongs to this process's user and to the group the directory gives it, and
    // the rename hands both to the document. The write compares the copy it made; this is the same
    // comparison, made before anything is installed.
    #[cfg(unix)]
    if let Some(refusal) = owners_refusal(
        path,
        Owners::of(&std::fs::metadata(path).map_err(storage)?),
        Owners::of_new_file_in(parent)?,
    ) {
        return Err(ControllerError::PermissionDenied {
            detail: format!("{refusal}; {instead}"),
        });
    }
    Ok(())
}

/// Who a file belongs to.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Owners {
    user: u32,
    group: u32,
}

#[cfg(unix)]
impl Owners {
    fn of(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            user: metadata.uid(),
            group: metadata.gid(),
        }
    }

    /// Who a file this process creates in `directory` belongs to.
    ///
    /// The user this process acts as, and a group by the platform's rule: on Linux the group this
    /// process acts as, unless the directory passes its own on (its set-group-identifier bit), and
    /// elsewhere, macOS among them, the directory's.
    fn of_new_file_in(directory: &Path) -> Result<Self> {
        use std::os::unix::fs::MetadataExt as _;

        let directory = std::fs::metadata(directory).map_err(storage)?;
        let passes_its_group_on = directory.mode() & 0o2000 != 0;
        let group = if cfg!(target_os = "linux") && !passes_its_group_on {
            rustix::process::getegid().as_raw()
        } else {
            directory.gid()
        };
        Ok(Self {
            user: rustix::process::geteuid().as_raw(),
            group,
        })
    }
}

/// Why replacing `path`, which `document` owns, with a file `replacement` owns would change who can
/// read or change it, or nothing when it would not.
#[cfg(unix)]
fn owners_refusal(path: &Path, document: Owners, replacement: Owners) -> Option<String> {
    (document != replacement).then(|| {
        format!(
            "{} belongs to user {} and group {}, and a replacement written here would belong to \
             user {} and group {}, so replacing it would change who can read or change it",
            display(path),
            document.user,
            document.group,
            replacement.user,
            replacement.group
        )
    })
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

/// Why the copy about to take `document`'s place would change who can read it, or nothing when it
/// would not.
///
/// On macOS and Linux the copy was created with the document's mode bits, so what it can differ in
/// is an access-control list its directory gave it, and who it belongs to: this process's user, and
/// the group the directory gave it.
#[cfg(not(windows))]
fn copy_refusal(copy: &std::fs::File, temporary: &Path, document: &Path) -> Result<Option<String>> {
    let parent = document.parent().unwrap_or_else(|| Path::new("."));
    if extended_access_controls(temporary)? {
        return Ok(Some(format!(
            "a new file in {} is given an access-control list by the directory itself, so \
             replacing {} here would change who can read it",
            display(parent),
            display(document)
        )));
    }
    #[cfg(unix)]
    let refusal = owners_refusal(
        document,
        Owners::of(&std::fs::metadata(document).map_err(storage)?),
        Owners::of(&copy.metadata().map_err(storage)?),
    );
    #[cfg(not(unix))]
    let refusal = {
        let _ = copy;
        None
    };
    Ok(refusal)
}

/// Why the copy about to take `document`'s place would change who can read it, or nothing when it
/// would not.
///
/// On Windows the copy's owner and lists, read through the handle that created it, are compared
/// with the document's, read again now, whole.
#[cfg(windows)]
fn copy_refusal(copy: &std::fs::File, temporary: &Path, document: &Path) -> Result<Option<String>> {
    let parent = document.parent().unwrap_or_else(|| Path::new("."));
    let copy = kr_ipc::paths::FileAccess::read(copy)
        .map_err(|refusal| refused_read(temporary, refusal))?;
    let read = kr_ipc::paths::FileAccess::of(document)
        .map_err(|refusal| refused_read(document, refusal))?;
    Ok((copy != read).then(|| {
        format!(
            "a new file in {} is given another owner or access-control list than the file it \
             would replace, so replacing {} here would change who can read it",
            display(parent),
            display(document)
        )
    }))
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
    // A directory can give what is created in it access, an owner or a group its own files do not
    // have, and the rename below would hand that to the document being replaced. A check that
    // cannot be made refuses as one that fails does, and neither leaves the copy behind.
    let refused = match path.exists().then(|| copy_refusal(&file, &temporary, path)) {
        None | Some(Ok(None)) => None,
        Some(Ok(Some(detail))) => Some(ControllerError::PermissionDenied { detail }),
        Some(Err(error)) => Some(error),
    };
    if let Some(refused) = refused {
        drop(file);
        let _ = std::fs::remove_file(&temporary);
        return Err(refused);
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

/// Another group this process's user belongs to than the one a file written in `directory` is
/// given, when there is one.
///
/// A new file takes its directory's group on macOS and this process's on Linux, so a test finds out
/// which by writing one.
#[cfg(all(test, unix))]
pub(crate) fn another_group(directory: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;

    let probe = directory.join(".group-probe");
    std::fs::write(&probe, b"").expect("a probe");
    let given = std::fs::metadata(&probe).expect("the probe").gid();
    std::fs::remove_file(&probe).expect("the probe goes");
    rustix::process::getgroups()
        .expect("this process's groups")
        .into_iter()
        .map(rustix::process::Gid::as_raw)
        .find(|group| *group != given)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A document is replaced whole and nothing is left beside it. Where this host reads access
    /// controls, a copy made in the document's own directory keeps who can read it, so the check
    /// at the replacement lets it take the document's place; anywhere else every replacement is
    /// refused, and the document keeps its bytes.
    #[test]
    fn a_document_is_replaced_whole_and_nothing_is_left_beside_it() {
        let directory = tempfile::tempdir().expect("a directory");
        let document = directory.path().join("settings.json");
        write_atomically(&document, b"first", PRIVATE).expect("creates it");
        let replaced = write_atomically(&document, b"second", PRIVATE);
        // A compile-time value rather than a conditional test, so both answers are checked on
        // every platform this crate builds for.
        if cfg!(any(target_os = "macos", target_os = "linux", windows)) {
            replaced.expect("replaces it");
            assert_eq!(std::fs::read(&document).expect("reads it"), b"second");
        } else {
            let refused = replaced.expect_err("refuses to replace it");
            assert!(
                matches!(refused, ControllerError::PermissionDenied { .. }),
                "{refused:?}"
            );
            assert_eq!(std::fs::read(&document).expect("reads it"), b"first");
        }
        let names: Vec<_> = std::fs::read_dir(directory.path())
            .expect("lists the directory")
            .map(|entry| entry.expect("an entry").file_name())
            .collect();
        assert_eq!(names, ["settings.json"], "no copy is left beside it");
    }

    /// KR-REQ-11.50: on macOS and Linux a document whose group is not the one a replacement written
    /// beside it would get is not replaced: the copy that would take its place is refused, and so
    /// is the document, before anything is written. The document keeps its bytes and its group.
    #[cfg(unix)]
    #[test]
    fn a_document_of_another_group_is_not_replaced() {
        use std::os::unix::fs::MetadataExt as _;

        let directory = tempfile::tempdir().expect("a directory");
        let Some(group) = another_group(directory.path()) else {
            println!(
                "this user belongs to one group only, so the group case runs as a decision here"
            );
            return;
        };
        let document = directory.path().join("settings.json");
        std::fs::write(&document, b"first").expect("writes");
        std::os::unix::fs::chown(&document, None, Some(group))
            .expect("the document is given another group of this user's");
        let group_of = |path: &Path| std::fs::metadata(path).expect("reads").gid();
        match write_atomically(&document, b"second", PRIVATE) {
            Ok(()) => panic!(
                "replaced, and its group is now {} rather than {group}",
                group_of(&document)
            ),
            Err(refused) => assert!(
                matches!(refused, ControllerError::PermissionDenied { ref detail }
                    if detail.contains(&format!("group {group}"))),
                "{refused:?}"
            ),
        }
        assert_eq!(std::fs::read(&document).expect("reads it"), b"first");
        assert_eq!(group_of(&document), group);
        let names: Vec<_> = std::fs::read_dir(directory.path())
            .expect("lists the directory")
            .map(|entry| entry.expect("an entry").file_name())
            .collect();
        assert_eq!(names, ["settings.json"], "no copy is left beside it");
        let refused = guard_access_controls(&document, "do it by hand")
            .expect_err("refused before anything is written");
        assert!(
            matches!(refused, ControllerError::PermissionDenied { ref detail }
                if detail.contains(&format!("group {group}")) && detail.ends_with("do it by hand")),
            "{refused:?}"
        );
    }

    /// KR-REQ-11.50: the decision the guard and the copy check make on macOS and Linux, with the
    /// owners given, since a test cannot make another user's file: a document of another user, or
    /// of another group, is refused, naming the document and both owners, and the person's own is
    /// not. Where this user belongs to one group only, this is the group case too.
    #[cfg(unix)]
    #[test]
    fn a_document_another_user_or_group_owns_is_refused_naming_both() {
        let path = Path::new("/home/someone/.claude.json");
        let own = Owners {
            user: 501,
            group: 20,
        };
        for (document, named) in [
            (Owners { user: 0, group: 20 }, "user 0 and group 20"),
            (
                Owners {
                    user: 501,
                    group: 80,
                },
                "user 501 and group 80",
            ),
        ] {
            let refusal = owners_refusal(path, document, own).expect("refused");
            assert!(
                refusal.contains("/home/someone/.claude.json")
                    && refusal.contains(named)
                    && refusal.contains("would belong to user 501 and group 20"),
                "{refusal}"
            );
        }
        assert_eq!(owners_refusal(path, own, own), None, "the person's own");
    }

    /// The owners a replacement is taken to get are the ones a file made in its directory gets:
    /// in a directory that passes its group on to what is made in it, and in one that does not.
    #[cfg(unix)]
    #[test]
    fn a_new_file_gets_the_owners_the_guard_expects() {
        use std::os::unix::fs::PermissionsExt as _;

        let made = |directory: &Path| {
            let probe = directory.join("probe");
            std::fs::write(&probe, b"").expect("a probe");
            let owners = Owners::of(&std::fs::metadata(&probe).expect("the probe"));
            std::fs::remove_file(&probe).expect("the probe goes");
            owners
        };
        let directory = tempfile::tempdir().expect("a directory");
        assert_eq!(
            Owners::of_new_file_in(directory.path()).expect("reads"),
            made(directory.path())
        );
        let Some(group) = another_group(directory.path()) else {
            println!("this user belongs to one group only, so no directory passes another on here");
            return;
        };
        let passing = directory.path().join("passing");
        std::fs::create_dir(&passing).expect("a directory");
        std::os::unix::fs::chown(&passing, None, Some(group))
            .expect("another group of this user's");
        std::fs::set_permissions(&passing, std::fs::Permissions::from_mode(0o2700))
            .expect("the directory passes its group on");
        assert_eq!(
            Owners::of_new_file_in(&passing).expect("reads"),
            made(&passing)
        );
        assert_eq!(made(&passing).group, group);
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
