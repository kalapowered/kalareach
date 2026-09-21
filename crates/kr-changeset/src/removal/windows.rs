//! Taking away a staged object through the handle this host verified it by.
//!
//! Windows can delete an open object rather than a name. The caller has just read the object's
//! identity from a handle and compared it with what the journal recorded; this reopens **that same
//! object** for deletion and marks it for removal. The name is never part of the call, so whatever
//! another writer does to the name between the comparison and this has no bearing on what goes:
//! the removal is conditioned on the object's identity by construction, which is the one thing a
//! name-based removal cannot promise.
//!
//! Two ways of marking an object exist. The first unlinks the name at once, even while handles are
//! still open, and answers straight away when it cannot: a directory that is not empty refuses the
//! call rather than failing silently later. The second, older way marks the object so that the
//! name goes as the last handle on it closes, and its refusals arrive at that close, where nothing
//! can read them. So a **file** takes the first way and falls back to the second, which is exactly
//! how a name is removed on this platform anyway; and a **directory** takes the first way or
//! nothing, because a silent failure would be this host reporting a removal that did not happen.
//! A volume that does not carry the first way answers [`None`] for a directory, and the caller
//! removes the name against the parent's own handle instead.
//!
//! This is the only module in the crate that leaves safe Rust on this platform: reopening a handle
//! and setting an object's disposition are calls into `kernel32`, and neither has a safe binding.

#![expect(
    unsafe_code,
    reason = "removing an open object rather than a name is two calls into kernel32, which have \
              no safe binding; they are made here and nowhere else in this crate"
)]

use std::io::{Error, Result};
use std::os::windows::io::{AsRawHandle as _, HandleOrInvalid, OwnedHandle};

use cap_std::fs::{Dir, File};
use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FileDispositionInfo, FileDispositionInfoEx, ReOpenFile, SetFileInformationByHandle,
};

/// Removes the file this handle names, whatever its name now reaches.
///
/// # Errors
///
/// Returns the reopen or the disposition failure. An object another process holds open without
/// allowing deletion refuses the reopen, which leaves the file exactly as it is and the record
/// with it.
pub(super) fn dispose_of(file: &File) -> Result<()> {
    let deletable = reopen_for_deletion(file.as_raw_handle(), 0)?;
    let handle: HANDLE = deletable.as_raw_handle();
    match unlink_now(handle) {
        Ok(()) => Ok(()),
        // A volume that does not carry the immediate form takes the older one, where the name goes
        // as the last handle on the object closes. The caller closes both before it asks for the
        // directory this file is in, so the directory is empty by then.
        Err(_) => unlink_at_close(handle),
    }
}

/// Removes the directory this handle names, where the volume can do it without deferring.
///
/// [`None`] means the volume does not carry the immediate form. The deferred form is not used on a
/// directory: it accepts the call and then fails at the close, where no caller can see it, so this
/// host would record a removal that never happened.
///
/// # Errors
///
/// Returns the reopen or the disposition failure, which includes the directory not being empty.
pub(super) fn dispose_of_directory(directory: &Dir) -> Option<Result<()>> {
    let deletable = match reopen_for_deletion(directory.as_raw_handle(), FILE_FLAG_BACKUP_SEMANTICS)
    {
        Ok(handle) => handle,
        Err(error) if unsupported(&error) => return None,
        Err(error) => return Some(Err(error)),
    };
    match unlink_now(deletable.as_raw_handle()) {
        Ok(()) => Some(Ok(())),
        Err(error) if unsupported(&error) => None,
        Err(error) => Some(Err(error)),
    }
}

/// Whether a failure means the volume has no such call, rather than a refusal of this object.
fn unsupported(error: &Error) -> bool {
    let code = error.raw_os_error();
    code == Some(ERROR_INVALID_PARAMETER.cast_signed())
        || code == Some(ERROR_NOT_SUPPORTED.cast_signed())
}

/// Unlinks the object's name at once, leaving the object alive for the handles that hold it.
fn unlink_now(handle: HANDLE) -> Result<()> {
    let now = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: the handle is owned by the caller and open for the whole call, and the buffer is the
    // structure the information class names, with its own size.
    let set = unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfoEx,
            std::ptr::from_ref(&now).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if set == 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// Marks the object so that its name goes as the last handle on it closes.
fn unlink_at_close(handle: HANDLE) -> Result<()> {
    let at_close = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: as above, for the older information class.
    let set = unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            std::ptr::from_ref(&at_close).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if set == 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// Opens the object an existing handle names a second time, with the right to delete it.
///
/// The handle a read gave the caller does not carry that right, and asking for it by name would
/// give up exactly what this module exists for. Reopening names no path at all: it is the same
/// object or it is a failure.
fn reopen_for_deletion(
    original: HANDLE,
    attributes: FILE_FLAGS_AND_ATTRIBUTES,
) -> Result<OwnedHandle> {
    // SAFETY: the original handle is open for the whole call, and the value that comes back is
    // either a handle this host owns or the invalid one, which the conversion below refuses.
    let reopened = unsafe {
        let raw = ReOpenFile(
            original,
            DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            attributes,
        );
        HandleOrInvalid::from_raw_handle(raw)
    };
    OwnedHandle::try_from(reopened).map_err(|_| Error::last_os_error())
}

#[cfg(test)]
mod tests {
    use std::os::windows::io::AsRawHandle as _;

    use cap_std::ambient_authority;
    use cap_std::fs::Dir;

    use super::{dispose_of, dispose_of_directory, reopen_for_deletion, unlink_at_close};

    /// The ordinary case: the staged file this host verified is the file that goes.
    #[test]
    fn the_object_this_host_verified_is_taken_away() {
        let place = tempfile::tempdir().expect("a directory to work in");
        let directory =
            Dir::open_ambient_dir(place.path(), ambient_authority()).expect("open the directory");
        directory
            .write("content", b"what this host staged\n")
            .expect("stage the content");
        let staged = directory
            .open("content")
            .expect("the handle this host verified");

        dispose_of(&staged).expect("the object this host verified goes");
        drop(staged);

        assert!(
            !directory.exists("content"),
            "the name this host staged through is free again"
        );
    }

    /// The window this exists to close: between the comparison and the removal the name comes to
    /// hold somebody else's object, and the removal still reaches only the object this host
    /// verified, because the name takes no part in it.
    #[test]
    fn a_replacement_at_the_name_is_never_what_goes() {
        let place = tempfile::tempdir().expect("a directory to work in");
        let directory =
            Dir::open_ambient_dir(place.path(), ambient_authority()).expect("open the directory");
        directory
            .write("content", b"what this host staged\n")
            .expect("stage the content");
        let staged = directory
            .open("content")
            .expect("the handle this host verified");

        // Somebody moves this host's object out of the way, which leaves the handle above holding
        // it, and puts one of their own at the name it had.
        directory
            .rename("content", &directory, "theirs-took-its-place")
            .expect("their editor moves it aside");
        directory
            .write("content", b"somebody else's file\n")
            .expect("their file");

        dispose_of(&staged).expect("the object this host verified goes");
        drop(staged);

        assert_eq!(
            directory
                .read("content")
                .expect("their file is still there"),
            b"somebody else's file\n",
            "the removal reached the object this host verified and nothing else"
        );
        assert!(
            !directory.exists("theirs-took-its-place"),
            "and the object it reached is the one this host staged"
        );
    }

    /// The older marking, which a volume without the immediate one falls back to: the name goes as
    /// the last handle on the object closes.
    #[test]
    fn the_deferred_marking_takes_the_name_when_the_handle_closes() {
        let place = tempfile::tempdir().expect("a directory to work in");
        let directory =
            Dir::open_ambient_dir(place.path(), ambient_authority()).expect("open the directory");
        directory
            .write("content", b"what this host staged\n")
            .expect("stage the content");
        let staged = directory
            .open("content")
            .expect("the handle this host verified");

        let deletable =
            reopen_for_deletion(staged.as_raw_handle(), 0).expect("reopen for deletion");
        unlink_at_close(deletable.as_raw_handle()).expect("mark it");
        drop(deletable);
        drop(staged);

        assert!(
            !directory.exists("content"),
            "the name is free once the last handle is closed"
        );
    }

    /// A staging directory this host holds open goes through that same handle, and one that holds
    /// something keeps it.
    #[test]
    fn a_directory_goes_through_its_own_handle_and_only_while_it_is_empty() {
        let place = tempfile::tempdir().expect("a directory to work in");
        let parent =
            Dir::open_ambient_dir(place.path(), ambient_authority()).expect("open the directory");
        parent.create_dir("staged").expect("stage a directory");
        let staged = parent.open_dir("staged").expect("the verified handle");
        staged
            .write("theirs.txt", b"somebody else's file\n")
            .expect("somebody puts a file inside");

        match dispose_of_directory(&staged) {
            // A volume that carries the call refuses a directory holding somebody's file.
            Some(refused) => {
                refused.expect_err("a directory holding something keeps it");
                staged.remove_file("theirs.txt").expect("they take it away");
                dispose_of_directory(&staged)
                    .expect("the volume carries it")
                    .expect("an empty directory of this host's own goes");
                drop(staged);
                assert!(!parent.exists("staged"), "and the name is free again");
            }
            // A volume that does not carry it leaves the removal to the name, which the caller
            // does against the parent's own handle.
            None => drop(staged),
        }
    }
}
