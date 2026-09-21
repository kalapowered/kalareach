//! Taking away a staged file through the handle this host verified it by.
//!
//! Windows can delete an open object rather than a name. The caller has just read the file's
//! identity from a handle and compared it with what the journal recorded; this reopens **that same
//! object** for deletion and marks it for removal. The name is never part of the call, so whatever
//! another writer does to the name between the comparison and this has no bearing on what goes:
//! the removal is conditioned on the object's identity by construction, which is the one thing a
//! name-based removal cannot promise.
//!
//! Two ways of marking it exist, and both are used. The first unlinks the name immediately, even
//! while handles are still open, which leaves the directory empty for the removal that follows. A
//! filesystem that does not offer it refuses the call, and then the older way marks the object so
//! that the name goes as the last handle closes, which is before this host asks for the directory.
//!
//! This is the only module in the crate that leaves safe Rust: reopening a handle and setting a
//! file's disposition are calls into `kernel32`, and neither has a safe binding.

#![expect(
    unsafe_code,
    reason = "removing an open object rather than a name is two calls into kernel32, which have \
              no safe binding; they are made here and nowhere else in this crate"
)]

use std::io::{Error, Result};
use std::os::windows::io::{AsRawHandle as _, HandleOrInvalid, OwnedHandle};

use cap_std::fs::File;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FileDispositionInfo, FileDispositionInfoEx, ReOpenFile,
    SetFileInformationByHandle,
};

/// Removes the object this handle names, whatever its name now reaches.
///
/// # Errors
///
/// Returns the reopen or the disposition failure. An object another process holds open without
/// allowing deletion refuses the reopen, which leaves the file exactly as it is and the record
/// with it.
pub(super) fn dispose_of(file: &File) -> Result<()> {
    let deletable = reopen_for_deletion(file)?;
    let handle: HANDLE = deletable.as_raw_handle();
    // Unlinks the name now rather than when the last handle closes, so the directory this file is
    // in is empty the moment this returns.
    let now = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: the handle is owned and open for the whole call, and the buffer is the structure the
    // information class names, with its own size.
    let set = unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfoEx,
            std::ptr::from_ref(&now).cast(),
            u32::try_from(size_of::<FILE_DISPOSITION_INFO_EX>()).unwrap_or(0),
        )
    };
    if set != 0 {
        return Ok(());
    }
    // A filesystem that does not carry the immediate form takes the older one, where the name goes
    // as the last handle on the object closes. The caller closes both before it asks for the
    // directory.
    let at_close = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: as above, for the older information class.
    let set = unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            std::ptr::from_ref(&at_close).cast(),
            u32::try_from(size_of::<FILE_DISPOSITION_INFO>()).unwrap_or(0),
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
fn reopen_for_deletion(file: &File) -> Result<OwnedHandle> {
    let original: HANDLE = file.as_raw_handle();
    // SAFETY: the original handle is open for the whole call, and the value that comes back is
    // either a handle this host owns or the invalid one, which the conversion below refuses.
    let reopened = unsafe {
        let raw = ReOpenFile(
            original,
            DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        );
        HandleOrInvalid::from_raw_handle(raw)
    };
    OwnedHandle::try_from(reopened).map_err(|_| Error::last_os_error())
}

#[cfg(test)]
mod tests {
    use cap_std::ambient_authority;
    use cap_std::fs::Dir;

    use super::dispose_of;

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

        // Somebody takes this host's object out of the way and puts one of their own at the name.
        directory
            .remove_file("content")
            .expect("theirs replaces it");
        directory
            .write("content", b"somebody else's file\n")
            .expect("their file");

        // The call may refuse, because the object it names is already on its way out. What it can
        // never do is reach the name, so what the refusal or the success leaves behind is theirs.
        let _ = dispose_of(&staged);
        drop(staged);

        assert_eq!(
            directory
                .read("content")
                .expect("their file is still there"),
            b"somebody else's file\n",
            "the removal reached the object this host verified and nothing else"
        );
    }
}
