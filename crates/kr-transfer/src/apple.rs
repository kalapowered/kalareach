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
}

/// Returns true when the file behind one descriptor carries an access-control list.
///
/// A file whose protection is its mode bits alone has none, and this platform answers that with a
/// null list. A list with no entries in it says nothing the mode bits do not, and is not one
/// either.
pub(crate) fn carries_access_control(fd: BorrowedFd<'_>) -> bool {
    // Safe: the descriptor is borrowed for the whole call, the list is asked for and given back
    // here and nowhere else, and the entry pointer is only ever written by the platform.
    let acl = unsafe { acl_get_fd(fd.as_raw_fd()) };
    if acl.is_null() {
        return false;
    }
    let mut entry: AclEntry = core::ptr::null_mut();
    let held = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &raw mut entry) } == 0;
    unsafe { acl_free(acl) };
    held
}
