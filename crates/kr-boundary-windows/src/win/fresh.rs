//! Directories and files made new, with their whole descriptor in the creating call.
//!
//! A file that another program reads by path (the policy that the system's own tool applies, the
//! program files that are copied on after they were checked) is written as a file that did not
//! exist: its name is random and in a directory that the installation made or checked, the call
//! fails when anything is at the name, and the descriptor, owner and protected list together, is
//! the one the call carries. No earlier handle to the file can exist, and no earlier owner. A list
//! is never changed by path afterwards.

#![allow(unsafe_code)]

use std::fs::File;
use std::io;
use std::io::Write as _;
use std::mem::ManuallyDrop;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{FromRawHandle as _, IntoRawHandle as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_RENAME_INFORMATION, FILE_RENAME_POSIX_SEMANTICS, FILE_RENAME_REPLACE_IF_EXISTS,
    FILE_SYNCHRONOUS_IO_NONALERT, FileRenameInformationEx, NtCreateFile, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
    RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_ALWAYS, CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::ffi;
use super::sd::{self, OwnedSd, Principals, SdKind};
use super::walk::{DirHandle, key_of};

/// A random name: the prefix, 32 lowercase hexadecimal digits and the suffix.
fn random_name(prefix: &str, suffix: &str) -> String {
    format!("{prefix}-{}{suffix}", uuid::Uuid::new_v4().simple())
}

fn descriptor_of(kind: SdKind, principals: &Principals) -> io::Result<OwnedSd> {
    sd::descriptor(kind, principals).map_err(|error| io::Error::other(error.to_string()))
}

/// Makes a directory under `under` at a random name that starts with `prefix`, with the descriptor
/// of the kind in the call that makes it. Fails when anything is at the name.
///
/// # Errors
///
/// Returns the platform's error when the call fails.
pub fn directory(
    under: &Path,
    prefix: &str,
    kind: SdKind,
    principals: &Principals,
) -> io::Result<PathBuf> {
    let path = under.join(random_name(prefix, ""));
    directory_at(&path, kind, principals)?;
    Ok(path)
}

/// Makes a directory at the path, with the descriptor of the kind in the call that makes it. Fails
/// when anything is at the path.
///
/// # Errors
///
/// Returns the platform's error when the call fails.
pub fn directory_at(path: &Path, kind: SdKind, principals: &Principals) -> io::Result<()> {
    let descriptor = descriptor_of(kind, principals)?;
    let attributes = descriptor.attributes();
    let wide = ffi::wide_path(path);
    // SAFETY: the path is NUL-terminated and the attributes point at a descriptor that lives
    // through the call.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &raw const attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Makes the directory at the path and every directory above it that is not there, each with the
/// descriptor of the kind in the call that makes it, and leaves what is there as it is. Returns
/// whether the directory itself was made.
///
/// # Errors
///
/// Returns the platform's error when a call fails.
pub fn directory_all(path: &Path, kind: SdKind, principals: &Principals) -> io::Result<bool> {
    let mut missing = Vec::new();
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        let there = ancestor.try_exists().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("a look at {} failed ({error})", ancestor.display()),
            )
        })?;
        if there {
            break;
        }
        missing.push(ancestor);
    }
    let made = !missing.is_empty();
    for ancestor in missing.into_iter().rev() {
        directory_at(ancestor, kind, principals)?;
    }
    Ok(made)
}

/// Opens a file at the path for writing, with the descriptor of the kind in the call that makes it.
/// With `only_new` the call fails when anything is at the name; without it a file that is there is
/// emptied and keeps its own descriptor, which the caller has checked.
///
/// # Errors
///
/// Returns the platform's error when the call fails.
pub fn file_at(path: &Path, kind: SdKind, only_new: bool) -> io::Result<File> {
    file_with(path, kind, &Principals::default(), only_new)
}

/// [`file_at`] with the identities the kind's descriptor needs.
///
/// # Errors
///
/// Returns the platform's error when the call fails.
pub fn file_with(
    path: &Path,
    kind: SdKind,
    principals: &Principals,
    only_new: bool,
) -> io::Result<File> {
    file_with_access(
        path,
        kind,
        principals,
        only_new,
        GENERIC_READ | GENERIC_WRITE,
    )
}

/// [`file_with`] with the access that the handle is opened with.
fn file_with_access(
    path: &Path,
    kind: SdKind,
    principals: &Principals,
    only_new: bool,
    access: u32,
) -> io::Result<File> {
    let descriptor = descriptor_of(kind, principals)?;
    let attributes = descriptor.attributes();
    let wide = ffi::wide_path(path);
    // SAFETY: the path is NUL-terminated and the attributes point at a descriptor that lives
    // through the call.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ,
            &raw const attributes,
            if only_new { CREATE_NEW } else { CREATE_ALWAYS },
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the handle is open, owned by nobody else and given to the file, which closes it.
    Ok(unsafe { File::from_raw_handle(raw.cast()) })
}

/// Makes a new file under `under` at a random name made of the prefix and the suffix, and returns
/// it open and the path it was made at.
///
/// # Errors
///
/// Returns the platform's error when the call fails.
pub fn named_file(
    under: &Path,
    prefix: &str,
    suffix: &str,
    kind: SdKind,
) -> io::Result<(File, PathBuf)> {
    let path = under.join(random_name(prefix, suffix));
    let file = file_at(&path, kind, true)?;
    Ok((file, path))
}

/// Opens a file that is the installation's own record at the path, owned by the administrators:
/// new when `only_new`, else emptied.
///
/// # Errors
///
/// Returns the platform's error when the call fails.
pub fn record_file(path: &Path, only_new: bool) -> io::Result<File> {
    file_at(path, SdKind::AdminFile, only_new)
}

/// Opens a directory by its path and holds it, for a caller that holds no handle of it yet.
///
/// # Errors
///
/// Returns the platform's error when the directory cannot be opened.
pub fn hold_directory(directory: &Path) -> io::Result<ffi::Handle> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
    // The flag lets the open of a directory succeed.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(directory)?;
    // text: hold_directory-1
    ffi::Handle::new(file.into_raw_handle().cast(), "holding a directory")
        .map_err(|error| io::Error::other(error.to_string()))
}

/// Makes a file new beneath the directory that `directory` holds: the name is made relative to that
/// handle and no path is resolved, in the one call that carries the whole descriptor of the kind
/// (owner and protected list), and the call fails when anything is at the name. Returns the handle
/// of the call that made it, opened with `access` and `share`, synchronous so that a file made of it
/// can be written, and without following a reparse point.
///
/// # Errors
///
/// Returns the platform's error when the call fails.
pub fn create_beneath(
    directory: &ffi::Handle,
    name: &[u16],
    kind: SdKind,
    access: u32,
    share: u32,
) -> io::Result<ffi::Handle> {
    let bytes = name.len() * 2;
    let length =
        u16::try_from(bytes).map_err(|_| io::Error::other("a name too long for the platform"))?;
    let descriptor = descriptor_of(kind, &Principals::default())?;
    let security = descriptor.attributes();
    let mut units = name.to_vec();
    let text = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: units.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: directory.raw(),
        ObjectName: &raw const text,
        Attributes: 0,
        SecurityDescriptor: security.lpSecurityDescriptor.cast_const().cast(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut raw: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: the name, the attributes (the descriptor behind them is owned by `descriptor`, which
    // lives to the end of this function) and the status block live through the call, the
    // directory's handle is open, and the call keeps none of them.
    let status = unsafe {
        NtCreateFile(
            &raw mut raw,
            access | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &raw const attributes,
            &raw mut status_block,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: converts a status the platform just returned; it reads nothing else.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(code.cast_signed()));
    }
    // text: create_beneath-1
    ffi::Handle::new(raw, "creating a file beneath a held directory")
        .map_err(|error| io::Error::other(error.to_string()))
}

/// What a write of a record tells the run that holds it, as it goes: `Some` of the handle of the
/// call that made a file and the path that the file has now, which the run keeps from then on, and
/// `None` where the file was marked for removal or has become the record that was proved.
pub type Hold<'a> = dyn Fn(Option<(&Arc<ffi::Handle>, &Path)>) + 'a;

/// Writes a record whole through one handle: a replacement is made new beside the record, relative
/// to `directory`, the handle that the caller holds of the directory that holds the record (no path
/// of the data tree is resolved for the create), with the right to delete it as well as to read
/// and write it, and shares read only. The replacement is the run's from the call that made it:
/// `hold` is called with its handle the moment the create returns, with nothing that can fail
/// between the two (the only steps are the move of the handle into a shared pointer and the call),
/// and again with the record's path once the rename has put it there; it is called with `None`
/// where the replacement was marked for removal or has become the proved record. The bytes are
/// written and flushed through that handle, the replacement is renamed over the record's name
/// through the same handle, with the new name given relative to `directory` (the platform reads a
/// bare name with no directory handle relative to the process's current directory, not to the
/// file's own). The record is then proved to be where it is read: the record's name is opened
/// relative to the same directory handle, for its attributes only and with full sharing, and the
/// identity of what that opens must be the identity of the object that was written. That open is
/// returned: it is the proof's own handle, a separate file object that holds the record's identity
/// and no right to anything. A name that is not there, a failed read or another object is a
/// failure.
///
/// Where the write, the flush or the rename fails, nothing has changed at the record's name, and
/// the same handle marks the replacement for removal. Where the rename has put the object at the
/// name, the object is marked for removal only if a read established that another object, or none,
/// stands at the name. Where a read failed, nothing is established, and the object stays at the
/// name: after a repair it may be the only manifest there is, and a failed read is no reason to
/// delete it. The error then says which read failed and that the object was left. Where a mark
/// failed, the run still holds the handle, so that its rollback marks the object again.
///
/// # Errors
///
/// Returns the first failure, with the failure of the mark where that failed too.
pub fn replace_whole(
    directory: &ffi::Handle,
    path: &Path,
    staging: &Path,
    bytes: &[u8],
    hold: &Hold<'_>,
) -> io::Result<ffi::Handle> {
    let name_of = |path: &Path, what: &str| -> io::Result<Vec<u16>> {
        Ok(path
            .file_name()
            .ok_or_else(|| io::Error::other(format!("the {what} has no file name")))?
            .encode_wide()
            .collect())
    };
    // Nothing is made before both names are known.
    let staging_name = name_of(staging, "replacement")?;
    let name = name_of(path, "record")?;
    let created = create_beneath(
        directory,
        &staging_name,
        SdKind::AdminFile,
        GENERIC_READ | GENERIC_WRITE | DELETE,
        FILE_SHARE_READ,
    )?;
    let handle = Arc::new(created);
    hold(Some((&handle, staging)));
    let written = (|| -> io::Result<()> {
        #[cfg(feature = "testing")]
        crate::manifest::forced::failure_at("replacement").map_err(io::Error::other)?;
        // The file borrows the handle for the write and is never dropped, which would close it.
        // SAFETY: the handle is open and owned by `handle`, which outlives this value.
        let mut file = ManuallyDrop::new(unsafe { File::from_raw_handle(handle.raw().cast()) });
        file.write_all(bytes)?;
        file.sync_all()
    })();
    // Before the rename nothing has changed at the record's name: the replacement is the only
    // object that this call made, and it goes.
    if let Err(failure) = written.and_then(|()| rename_by_handle(&handle, directory, &name)) {
        return Err(match super::root::delete(&handle) {
            Ok(()) => {
                hold(None);
                failure
            }
            Err(error) => io::Error::new(
                failure.kind(),
                format!(
                    "{failure}; the replacement {} could not be marked for removal either: {error}",
                    staging.display()
                ),
            ),
        });
    }
    hold(Some((&handle, path)));
    match prove_in_place(directory, &handle, &name, path) {
        Ok(found) => {
            hold(None);
            Ok(found)
        }
        // A read established that another object, or none, stands at the name: the object that
        // was written is not the record, and it goes.
        Err(Unproved::NotTheRecord(failure)) => {
            let marked = match super::root::delete(&handle) {
                Ok(()) => {
                    hold(None);
                    "the object that was written was marked for removal".to_owned()
                }
                Err(error) => {
                    format!("the object that was written could not be marked for removal: {error}")
                }
            };
            Err(io::Error::new(
                failure.kind(),
                format!("{failure}; {marked}"),
            ))
        }
        // A read failed, so nothing is established about what stands at the name, and the rename
        // has already replaced the earlier record: where this object is the only record, marking it
        // would leave none. It stays, unmarked, and the run holds its handle.
        Err(Unproved::Unread(failure)) => Err(io::Error::new(
            failure.kind(),
            format!(
                "{failure}; no read showed another object at the record's name, so the record that was written was not marked for removal and was left where the rename put it"
            ),
        )),
    }
}

/// What the proof after a rename could not show.
enum Unproved {
    /// A read established that another object, or none, stands at the record's name.
    NotTheRecord(io::Error),
    /// A read failed, so nothing is established about what stands at the record's name.
    Unread(io::Error),
}

/// Renames the file behind the handle to `name` in the directory that `directory` holds, over what
/// is there, through the file's own handle, with the native call (`NtSetInformationFile`, the
/// extended rename class). The structure is the page's `FILE_RENAME_INFORMATION`: `Flags` replace
/// and POSIX semantics, `RootDirectory` the directory's handle, `FileNameLength` the bytes of the
/// name, and the name behind it; the buffer is the structure's size plus the name's bytes, as the
/// page asks. The platform reads a name relative to the directory handle in `RootDirectory` and no
/// path is resolved (the Win32 call refuses every root handle, and a bare name with no root handle is
/// read relative to the process's current directory).
fn rename_by_handle(handle: &ffi::Handle, directory: &ffi::Handle, name: &[u16]) -> io::Result<()> {
    let name_bytes = name.len() * 2;
    let size = size_of::<FILE_RENAME_INFORMATION>() + name_bytes;
    let mut buffer = vec![0_u64; size.div_ceil(8)];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: the buffer is zeroed, aligned for the structure and `size` bytes long, so the fixed
    // fields are inside it and the name's bytes, copied behind `FileName`, end inside it; nothing
    // else points into it until the call below.
    unsafe {
        (*info).Anonymous.Flags = FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS;
        (*info).RootDirectory = directory.raw();
        (*info).FileNameLength = name_bytes as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            (&raw mut (*info).FileName).cast::<u16>(),
            name.len(),
        );
    }
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: the handle is open with the right to delete, the directory's handle is open, the
    // buffer holds the structure that the class takes, of the size given, and the status block lives
    // through the call.
    let status = unsafe {
        NtSetInformationFile(
            handle.raw(),
            &raw mut status_block,
            buffer.as_ptr().cast(),
            size as u32,
            FileRenameInformationEx,
        )
    };
    if status < 0 {
        // SAFETY: converts a status the platform just returned; it reads nothing else.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(code.cast_signed()));
    }
    Ok(())
}

/// Proves that the record is where it is read after the rename: the name is opened relative to the
/// same directory handle, for its attributes only, and the identity of what it opens is compared with
/// the identity of the object that was written. No path is opened. The open of the name, which is
/// that identity's own file object (opened for its attributes only, with full sharing), is returned
/// as the proof's handle of the record.
///
/// A name that is not there and another object at the name are the answers of reads: they are
/// [`Unproved::NotTheRecord`]. A read that failed (the identity of the written object, the open of
/// the name for a reason other than not found, the identity of what the name opens) shows nothing
/// of what stands at the name, and is [`Unproved::Unread`].
fn prove_in_place(
    directory: &ffi::Handle,
    written: &ffi::Handle,
    name: &[u16],
    path: &Path,
) -> Result<ffi::Handle, Unproved> {
    // The seam of the test build: one read of the proof fails, after a rename that really took
    // place.
    #[cfg(feature = "testing")]
    let forced = crate::manifest::forced::failure_at("proof");
    #[cfg(not(feature = "testing"))]
    let forced: Result<(), String> = Ok(());
    let wrote = forced
        .and_then(|()| key_of(written).map_err(|error| error.to_string()))
        .map_err(|error| {
        Unproved::Unread(io::Error::other(format!(
            "the rename of {} returned success, and a read of the identity of the record that was written failed: {error}",
            path.display()
        )))
    })?;
    let found = match DirHandle::open_beneath(directory, name, 0, true, FILE_OPEN) {
        Ok(found) => found,
        Err(failure)
            if failure.code == ERROR_FILE_NOT_FOUND || failure.code == ERROR_PATH_NOT_FOUND =>
        {
            return Err(Unproved::NotTheRecord(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "the rename of {} returned success, and the open of its name in the directory that holds it answered not found, so the record is not where it is read",
                    path.display()
                ),
            )));
        }
        Err(failure) => {
            return Err(Unproved::Unread(io::Error::other(format!(
                "the rename of {} returned success, and the open of its name in the directory that holds it failed: {failure}",
                path.display()
            ))));
        }
    };
    let read = key_of(&found).map_err(|error| {
        Unproved::Unread(io::Error::other(format!(
            "the rename of {} returned success, and a read of the identity of what its name opens failed: {error}",
            path.display()
        )))
    })?;
    if read != wrote {
        return Err(Unproved::NotTheRecord(io::Error::other(format!(
            "the rename of {} returned success, and its name in the directory that holds it opens the object {read}, not the record that was written, {wrote}",
            path.display()
        ))));
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard, PoisonError};

    use super::*;

    /// A forced failure is the process's, not a thread's: each case that writes a record takes this
    /// lock, so that a failure forced for one case is not met by another.
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

    fn one_at_a_time() -> MutexGuard<'static, ()> {
        match ONE_AT_A_TIME.lock() {
            Ok(held) => held,
            Err(poisoned) => PoisonError::into_inner(poisoned),
        }
    }

    /// The names that a directory holds.
    #[cfg(feature = "testing")]
    fn names_in(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// A read of the proof that fails after the rename has put the record at its name keeps the
    /// record: the earlier record is already replaced, and a repair's only manifest is not marked
    /// for removal because a read failed. The error names the read that failed and says that the
    /// record was left. A write after it then replaces the record as it does at any time.
    #[cfg(feature = "testing")]
    #[test]
    fn a_read_of_the_proof_that_fails_after_the_rename_keeps_the_record_and_the_error_says_so() {
        let _one = one_at_a_time();
        let dir = tempfile::tempdir().unwrap();
        let directory = hold_directory(dir.path()).unwrap();
        let record = dir.path().join("manifest.json");
        replace_whole(
            &directory,
            &record,
            &dir.path().join("manifest-one.new"),
            b"first",
            &|_| {},
        )
        .unwrap();
        crate::manifest::forced::fail_the_next("proof");
        let error = replace_whole(
            &directory,
            &record,
            &dir.path().join("manifest-two.new"),
            b"second",
            &|_| {},
        )
        .unwrap_err()
        .to_string();
        for part in [
            "a read of the identity of the record that was written failed",
            "a failure forced for a case at the step proof",
            "no read showed another object at the record's name",
            "was not marked for removal and was left where the rename put it",
        ] {
            assert!(error.contains(part), "{part}: {error}");
        }
        assert_eq!(std::fs::read_to_string(&record).unwrap(), "second");
        assert_eq!(names_in(dir.path()), ["manifest.json"]);
        replace_whole(
            &directory,
            &record,
            &dir.path().join("manifest-three.new"),
            b"third",
            &|_| {},
        )
        .unwrap();
        assert_eq!(std::fs::read_to_string(&record).unwrap(), "third");
    }

    /// A write that fails before the rename changes nothing at the record's name: the earlier
    /// record stays as it was, and the replacement is marked for removal through its own handle.
    #[cfg(feature = "testing")]
    #[test]
    fn a_write_that_fails_before_the_rename_marks_the_replacement_and_leaves_the_record() {
        let _one = one_at_a_time();
        let dir = tempfile::tempdir().unwrap();
        let directory = hold_directory(dir.path()).unwrap();
        let record = dir.path().join("manifest.json");
        replace_whole(
            &directory,
            &record,
            &dir.path().join("manifest-one.new"),
            b"first",
            &|_| {},
        )
        .unwrap();
        crate::manifest::forced::fail_the_next("replacement");
        let error = replace_whole(
            &directory,
            &record,
            &dir.path().join("manifest-two.new"),
            b"second",
            &|_| {},
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("a failure forced for a case at the step replacement"),
            "{error}"
        );
        assert_eq!(std::fs::read_to_string(&record).unwrap(), "first");
        assert_eq!(names_in(dir.path()), ["manifest.json"]);
    }

    /// A file is made new beneath a held directory, by its bare name relative to that handle, and a
    /// second call at the same name fails and leaves the first file as it was.
    #[test]
    fn a_file_is_made_beneath_a_held_directory_and_never_over_another() {
        let dir = tempfile::tempdir().unwrap();
        let directory = hold_directory(dir.path()).unwrap();
        let name: Vec<u16> = "made.bin".encode_utf16().collect();
        let first = create_beneath(
            &directory,
            &name,
            SdKind::AdminFile,
            GENERIC_READ | GENERIC_WRITE | DELETE,
            FILE_SHARE_READ,
        )
        .unwrap();
        // SAFETY: the handle is open; the file borrows it for one write and is never dropped.
        let mut file = ManuallyDrop::new(unsafe { File::from_raw_handle(first.raw().cast()) });
        file.write_all(b"first").unwrap();
        let again = create_beneath(
            &directory,
            &name,
            SdKind::AdminFile,
            GENERIC_READ | GENERIC_WRITE | DELETE,
            FILE_SHARE_READ,
        )
        .unwrap_err();
        assert_eq!(again.kind(), io::ErrorKind::AlreadyExists, "{again}");
        drop(first);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("made.bin")).unwrap(),
            "first"
        );
    }

    /// The run is told of a replacement at the call that made it, again where the rename has put
    /// it at the record's name, and last that it has become the proved record; a write that failed
    /// before the rename tells it that the replacement was marked, and a read of the proof that
    /// failed leaves the record in the run's hand.
    #[test]
    fn the_run_is_told_of_a_replacement_from_its_create_to_the_proved_record() {
        let _one = one_at_a_time();
        let dir = tempfile::tempdir().unwrap();
        let directory = hold_directory(dir.path()).unwrap();
        let record = dir.path().join("manifest.json");
        let told = Mutex::new(Vec::<Option<String>>::new());
        let hold = |made: Option<(&Arc<ffi::Handle>, &Path)>| {
            told.lock()
                .unwrap()
                .push(made.map(|(_, path)| path.display().to_string()));
        };
        let staging = dir.path().join("manifest-one.new");
        let found = replace_whole(&directory, &record, &staging, b"first", &hold).unwrap();
        // The proof's handle is the record's own object.
        let units: Vec<u16> = "manifest.json".encode_utf16().collect();
        let at_name = DirHandle::open_beneath(&directory, &units, 0, true, FILE_OPEN).unwrap();
        assert_eq!(key_of(&found).unwrap(), key_of(&at_name).unwrap());
        assert_eq!(
            *told.lock().unwrap(),
            [
                Some(staging.display().to_string()),
                Some(record.display().to_string()),
                None
            ]
        );
        #[cfg(feature = "testing")]
        {
            told.lock().unwrap().clear();
            crate::manifest::forced::fail_the_next("replacement");
            let two = dir.path().join("manifest-two.new");
            replace_whole(&directory, &record, &two, b"second", &hold).unwrap_err();
            assert_eq!(
                *told.lock().unwrap(),
                [Some(two.display().to_string()), None]
            );
            told.lock().unwrap().clear();
            crate::manifest::forced::fail_the_next("proof");
            let three = dir.path().join("manifest-three.new");
            replace_whole(&directory, &record, &three, b"third", &hold).unwrap_err();
            assert_eq!(
                *told.lock().unwrap(),
                [
                    Some(three.display().to_string()),
                    Some(record.display().to_string())
                ]
            );
        }
    }

    /// A replacement is put at the record's name in the directory that holds it, whatever the
    /// process's current directory is: a bare name that no directory handle goes with would be read
    /// relative to the current directory, where the record would then be put and not found. The name
    /// is proved by opening it relative to the same handle, and a second write replaces the first.
    #[test]
    fn a_replacement_is_put_at_the_records_name_in_its_own_directory_and_not_in_the_current_one() {
        let _one = one_at_a_time();
        let dir = tempfile::tempdir().unwrap();
        let directory = hold_directory(dir.path()).unwrap();
        let record = dir.path().join("manifest.json");
        let current = std::env::current_dir().unwrap().join("manifest.json");
        assert!(!current.try_exists().unwrap(), "{}", current.display());
        for (staging, bytes) in [
            ("manifest-one.new", "first"),
            ("manifest-two.new", "second"),
        ] {
            replace_whole(
                &directory,
                &record,
                &dir.path().join(staging),
                bytes.as_bytes(),
                &|_| {},
            )
            .unwrap();
            assert_eq!(std::fs::read_to_string(&record).unwrap(), bytes);
            assert!(!dir.path().join(staging).try_exists().unwrap(), "{staging}");
        }
        assert!(
            !current.try_exists().unwrap(),
            "the record went to {}",
            current.display()
        );
    }
}
