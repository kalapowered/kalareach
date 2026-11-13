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
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{FromRawHandle as _, IntoRawHandle as _};
use std::path::{Path, PathBuf};

use windows_sys::Wdk::Storage::FileSystem::{
    FILE_OPEN, FILE_RENAME_INFORMATION, FILE_RENAME_POSIX_SEMANTICS, FILE_RENAME_REPLACE_IF_EXISTS,
    FileRenameInformationEx, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
    RtlNtStatusToDosError,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_ALWAYS, CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
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

/// Writes a record whole through one handle: a replacement is made new beside the record, with the
/// right to delete it as well as to read and write it, and shares read only. The bytes are written
/// and flushed through that handle, the replacement is renamed over the record's name through the
/// same handle, with the new name given relative to `directory`, the handle that the caller holds
/// of the directory that holds the record (the platform reads a bare name with no directory handle
/// relative to the process's current directory, not to the file's own). No open of the directory by
/// a path takes place. The record is then proved to be where it is read: the record's name is opened
/// relative to the same directory handle, and the identity of what that opens must be the identity
/// of the object that was written. A name that is not there, a failed read or another object is a
/// failure. Where a step fails the same handle marks the replacement for removal: the object that
/// this call made is the one that goes, wherever it is by then.
///
/// # Errors
///
/// Returns the first failure, with the failure of the mark where that failed too.
pub fn replace_whole(
    directory: &ffi::Handle,
    path: &Path,
    staging: &Path,
    bytes: &[u8],
) -> io::Result<()> {
    let mut file = file_with_access(
        staging,
        SdKind::AdminFile,
        &Principals::default(),
        true,
        GENERIC_READ | GENERIC_WRITE | DELETE,
    )?;
    let written = (|| -> io::Result<()> {
        #[cfg(feature = "testing")]
        crate::manifest::forced::failure_at("replacement").map_err(io::Error::other)?;
        file.write_all(bytes)?;
        file.sync_all()
    })();
    // The handle is taken out of the file, which would close it, so that it is the one that renames
    // the replacement and, where a step failed, marks it.
    // text: replace_whole-1
    let handle = ffi::Handle::new(
        file.into_raw_handle().cast(),
        "the replacement's own handle",
    )
    .map_err(|error| io::Error::other(error.to_string()))?;
    let Err(failure) = written.and_then(|()| {
        let name: Vec<u16> = path
            .file_name()
            .ok_or_else(|| io::Error::other("the record has no file name"))?
            .encode_wide()
            .collect();
        rename_by_handle(&handle, directory, &name)?;
        prove_in_place(directory, &handle, &name, path)
    }) else {
        return Ok(());
    };
    match super::root::delete(&handle) {
        Ok(()) => Err(failure),
        Err(error) => Err(io::Error::new(
            failure.kind(),
            format!(
                "{failure}; the replacement {} could not be marked for removal either: {error}",
                staging.display()
            ),
        )),
    }
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
/// the identity of the object that was written. No path is opened.
fn prove_in_place(
    directory: &ffi::Handle,
    written: &ffi::Handle,
    name: &[u16],
    path: &Path,
) -> io::Result<()> {
    let wrote = key_of(written).map_err(|error| {
        io::Error::other(format!(
            "the rename of {} returned success, and a read of the identity of the record that was written failed: {error}",
            path.display()
        ))
    })?;
    let found = match DirHandle::open_beneath(directory, name, 0, true, FILE_OPEN) {
        Ok(found) => found,
        Err(failure)
            if failure.code == ERROR_FILE_NOT_FOUND || failure.code == ERROR_PATH_NOT_FOUND =>
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "the rename of {} returned success, and the open of its name in the directory that holds it answered not found, so the record is not where it is read",
                    path.display()
                ),
            ));
        }
        Err(failure) => {
            return Err(io::Error::other(format!(
                "the rename of {} returned success, and the open of its name in the directory that holds it failed: {failure}",
                path.display()
            )));
        }
    };
    let read = key_of(&found).map_err(|error| {
        io::Error::other(format!(
            "the rename of {} returned success, and a read of the identity of what its name opens failed: {error}",
            path.display()
        ))
    })?;
    if read != wrote {
        return Err(io::Error::other(format!(
            "the rename of {} returned success, and its name in the directory that holds it opens the object {read}, not the record that was written, {wrote}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A replacement is put at the record's name in the directory that holds it, whatever the
    /// process's current directory is: a bare name that no directory handle goes with would be read
    /// relative to the current directory, where the record would then be put and not found. The name
    /// is proved by opening it relative to the same handle, and a second write replaces the first.
    #[test]
    fn a_replacement_is_put_at_the_records_name_in_its_own_directory_and_not_in_the_current_one() {
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
