//! The one question about an Apple file that has no answer in safe Rust.
//!
//! An access-control list on this platform is not an extended attribute anything may read: the
//! attribute it lives in is the kernel's own and refuses every call, and the only interface to it
//! takes a **descriptor**. A file's protection has to be asked of the file this host holds open,
//! because a name asked twice can be two different files, so this module makes that one call.

use std::os::fd::{AsRawFd, BorrowedFd};

/// An opaque list, as the platform hands it back.
type Acl = *mut core::ffi::c_void;

/// An opaque entry of one.
type AclEntry = *mut core::ffi::c_void;

/// The platform's name for "the first entry of this list".
const ACL_FIRST_ENTRY: i32 = 0;

unsafe extern "C" {
    /// Returns this descriptor's access-control list, or null when it has none.
    fn acl_get_fd(fd: i32) -> Acl;
    /// Writes one entry of a list and returns zero when there is one to write.
    fn acl_get_entry(acl: Acl, entry_id: i32, entry: *mut AclEntry) -> i32;
    /// Gives a list back.
    fn acl_free(obj: *mut core::ffi::c_void) -> i32;
    /// Allocates an empty access-control list.
    fn acl_init(count: i32) -> Acl;
    /// Sets an access-control list on a descriptor.
    fn acl_set_fd(fd: i32, acl: Acl) -> i32;
    /// Returns the buffer size needed for the external binary representation.
    fn acl_size(acl: Acl) -> isize;
    /// Converts an access-control list to an external binary representation in native byte order.
    fn acl_copy_ext_native(buf_p: *mut core::ffi::c_void, acl: Acl, size: isize) -> isize;
    /// Reconstructs an access-control list from an external binary representation in native byte order.
    fn acl_copy_int_native(buf_p: *const core::ffi::c_void) -> Acl;
}

/// Returns true when the file behind one descriptor carries an access-control list.
///
/// A file whose protection is its mode bits alone has none, and this platform says so by handing
/// back nothing and naming it: the list is *not found*. Nothing else it says means that. A call
/// that fails for any other reason leaves this host unable to say what protects the file, and the
/// answer it gives then is the one that stops a caller replacing it.
///
/// A list with no entries in it says nothing the mode bits do not, and is not one either.
pub(crate) fn carries_access_control(fd: BorrowedFd<'_>) -> bool {
    let acl = unsafe { acl_get_fd(fd.as_raw_fd()) };
    if acl.is_null() {
        let why = std::io::Error::last_os_error();
        return why.raw_os_error() != Some(libc::ENOENT);
    }
    let mut entry: AclEntry = core::ptr::null_mut();
    let held = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &raw mut entry) } == 0;
    unsafe { acl_free(acl) };
    held
}

/// Darwin ACL external representation header magic (`0x012cc16d`).
const ACL_EXT_MAGIC: u32 = 0x012c_c16d;

/// Reads the access-control list from a descriptor, returning its lossless binary representation.
///
/// Returns `Ok(None)` when the file carries no extended access-control list beyond its mode bits,
/// or when the list has no entries.
pub(crate) fn read_access_control(fd: BorrowedFd<'_>) -> std::io::Result<Option<Vec<u8>>> {
    let acl = unsafe { acl_get_fd(fd.as_raw_fd()) };
    if acl.is_null() {
        let why = std::io::Error::last_os_error();
        if why.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(why);
    }
    let mut entry: AclEntry = core::ptr::null_mut();
    let has_entries = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &raw mut entry) } == 0;
    if !has_entries {
        unsafe { acl_free(acl) };
        return Ok(None);
    }
    let size = unsafe { acl_size(acl) };
    if size <= 0 {
        let err = std::io::Error::last_os_error();
        unsafe { acl_free(acl) };
        return Err(err);
    }
    let mut buf = vec![0_u8; size as usize];
    let written = unsafe { acl_copy_ext_native(buf.as_mut_ptr().cast(), acl, size) };
    let err = if written <= 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };
    unsafe { acl_free(acl) };
    if let Some(err) = err {
        return Err(err);
    }
    buf.truncate(written as usize);
    Ok(Some(buf))
}

/// Sets or clears the access-control list on a descriptor.
///
/// Setting `None` clears any access-control list by setting an empty list. Setting `Some(raw)`
/// validates the binary header and applies the lossless representation to the descriptor.
pub(crate) fn set_access_control(fd: BorrowedFd<'_>, raw: Option<&[u8]>) -> std::io::Result<()> {
    match raw {
        None => {
            let empty = unsafe { acl_init(0) };
            if empty.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            let rc = unsafe { acl_set_fd(fd.as_raw_fd(), empty) };
            let err = if rc != 0 {
                Some(std::io::Error::last_os_error())
            } else {
                None
            };
            unsafe { acl_free(empty) };
            if let Some(err) = err {
                return Err(err);
            }
            Ok(())
        }
        Some(bytes) => {
            // Validate minimum size and Darwin ACL external native magic before passing to
            // acl_copy_int_native.
            if bytes.len() < 4
                || u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) != ACL_EXT_MAGIC
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid access-control list binary representation",
                ));
            }
            let acl = unsafe { acl_copy_int_native(bytes.as_ptr().cast()) };
            if acl.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            let rc = unsafe { acl_set_fd(fd.as_raw_fd(), acl) };
            let err = if rc != 0 {
                Some(std::io::Error::last_os_error())
            } else {
                None
            };
            unsafe { acl_free(acl) };
            if let Some(err) = err {
                return Err(err);
            }
            Ok(())
        }
    }
}
