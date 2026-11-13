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

use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_ALWAYS, CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_RENAME_INFO, FILE_SHARE_READ, FileRenameInfoEx,
    SetFileInformationByHandle,
};

use super::ffi;
use super::sd::{self, OwnedSd, Principals, SdKind};

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

/// Writes a record whole through one handle: a replacement is made new beside the record, with the
/// right to delete it as well as to read and write it, and shares read only. The bytes are written
/// and flushed through that handle, the replacement is renamed over the record's name through the
/// same handle (a bare name, in the replacement's own directory, so that no open of the directory by
/// a path takes place), and where a step fails the same handle marks the replacement for removal: the
/// object that this call made is the one that goes, whatever is at its name by then.
///
/// # Errors
///
/// Returns the first failure, with the failure of the mark where that failed too.
pub fn replace_whole(path: &Path, staging: &Path, bytes: &[u8]) -> io::Result<()> {
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
    let Err(failure) = written.and_then(|()| rename_by_handle(&handle, path)) else {
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

/// Renames the file behind the handle to the name of `path` in the file's own directory, over what is
/// there, through the handle: the platform is given the bare name and no directory handle.
fn rename_by_handle(handle: &ffi::Handle, path: &Path) -> io::Result<()> {
    // The rename replaces a file that is there, and the name goes at once whatever else has it open.
    const REPLACE_IF_EXISTS: u32 = 0x1;
    const POSIX_SEMANTICS: u32 = 0x2;
    let name: Vec<u16> = path
        .file_name()
        .ok_or_else(|| io::Error::other("the record has no file name"))?
        .encode_wide()
        .collect();
    let header = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let size = header + name.len() * 2;
    let mut buffer = vec![0_u64; size.div_ceil(8)];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: the buffer is aligned for the structure and large enough for it and the name, which is
    // copied behind the header; nothing else points into it.
    unsafe {
        (*info).Anonymous.Flags = REPLACE_IF_EXISTS | POSIX_SEMANTICS;
        (*info).RootDirectory = std::ptr::null_mut();
        (*info).FileNameLength = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            (&raw mut (*info).FileName).cast::<u16>(),
            name.len(),
        );
    }
    // SAFETY: the handle is open with the right to delete, and the buffer holds the structure that the
    // class takes, of the size given.
    if unsafe {
        SetFileInformationByHandle(
            handle.raw(),
            FileRenameInfoEx,
            buffer.as_ptr().cast(),
            size as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
