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
    /// Translates an access-control list into a string.
    fn acl_to_text(acl: Acl, len_p: *mut isize) -> *mut core::ffi::c_char;
    /// Parses an access-control list from text.
    fn acl_from_text(buf_p: *const core::ffi::c_char) -> Acl;
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

/// Reads the access-control list from a descriptor, returning text if present with entries.
///
/// Returns `Ok(None)` when the file carries no extended access-control list beyond its mode bits,
/// or when the list has no entries.
pub(crate) fn read_access_control(fd: BorrowedFd<'_>) -> std::io::Result<Option<String>> {
    let acl = unsafe { acl_get_fd(fd.as_raw_fd()) };
    if acl.is_null() {
        let why = std::io::Error::last_os_error();
        if why.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(why);
    }
    let mut entry: AclEntry = core::ptr::null_mut();
    let held = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &raw mut entry) } == 0;
    if !held {
        unsafe { acl_free(acl) };
        return Ok(None);
    }
    let mut len: isize = 0;
    let text_ptr = unsafe { acl_to_text(acl, &raw mut len) };
    unsafe { acl_free(acl) };
    if text_ptr.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let c_str = unsafe { core::ffi::CStr::from_ptr(text_ptr) };
    let text = c_str.to_string_lossy().into_owned();
    unsafe { acl_free(text_ptr.cast::<core::ffi::c_void>()) };
    Ok(Some(text))
}

/// Sets or clears the access-control list on a descriptor.
///
/// Setting `None` clears any access-control list by setting an empty list. Setting `Some(text)`
/// parses the text format and applies it to the descriptor.
pub(crate) fn set_access_control(fd: BorrowedFd<'_>, text: Option<&str>) -> std::io::Result<()> {
    match text {
        None => {
            let empty = unsafe { acl_init(0) };
            if empty.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            let rc = unsafe { acl_set_fd(fd.as_raw_fd(), empty) };
            unsafe { acl_free(empty) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }
        Some(s) => {
            let c_str = std::ffi::CString::new(s).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "access-control list text contains a null byte",
                )
            })?;
            let acl = unsafe { acl_from_text(c_str.as_ptr()) };
            if acl.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            let rc = unsafe { acl_set_fd(fd.as_raw_fd(), acl) };
            unsafe { acl_free(acl) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }
    }
}
