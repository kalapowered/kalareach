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
use std::os::windows::io::FromRawHandle as _;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_ALWAYS, CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
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
    let descriptor = descriptor_of(kind, principals)?;
    let attributes = descriptor.attributes();
    let path = under.join(random_name(prefix, ""));
    let wide = ffi::wide_path(&path);
    // SAFETY: the path is NUL-terminated and the attributes point at a descriptor that lives
    // through the call.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &raw const attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(path)
}

/// Opens a file at the path for writing, with the descriptor of the kind in the call that makes it.
/// With `only_new` the call fails when anything is at the name; without it a file that is there is
/// emptied and keeps its own descriptor, which the caller has checked.
///
/// # Errors
///
/// Returns the platform's error when the call fails.
pub fn file_at(path: &Path, kind: SdKind, only_new: bool) -> io::Result<File> {
    let descriptor = descriptor_of(kind, &Principals::default())?;
    let attributes = descriptor.attributes();
    let wide = ffi::wide_path(path);
    // SAFETY: the path is NUL-terminated and the attributes point at a descriptor that lives
    // through the call.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
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
