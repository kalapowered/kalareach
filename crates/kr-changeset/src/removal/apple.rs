//! The one question about an Apple directory that has no answer in safe Rust.
//!
//! A directory's mode bits are not the whole of who may write in it on this platform: an
//! access-control list sits beside them and can name accounts the mode does not mention, and a
//! directory created inside one that carries an inheritable list carries it too. So a staging
//! directory whose mode says `0700` can still be one another account may write in, and this host
//! would be promising something it cannot show.
//!
//! The platform's list is reachable only through a **descriptor** and only through its own
//! interface, which is why this module leaves safe Rust and nothing else in this crate but the
//! Windows removal does. The question is asked of the handle this host already holds on the
//! directory, never of its name, because a name asked twice can be two different objects.

#![expect(
    unsafe_code,
    reason = "asking a descriptor for its access-control list is a call into the platform's own \
              interface, which has no safe binding; the call is made here and nowhere else"
)]

use std::os::fd::{AsRawFd as _, BorrowedFd};

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

/// Returns true when the object behind one descriptor carries an access-control list.
///
/// An object whose protection is its mode bits alone has none, and this platform says so by
/// handing back nothing and naming it: the list is *not found*. Nothing else it says means that. A
/// call that fails for any other reason leaves this host unable to say what protects the object,
/// and the answer it gives then is the one that stops a removal.
///
/// A list with no entries in it says nothing the mode bits do not, and is not one either.
pub(super) fn carries_access_control(fd: BorrowedFd<'_>) -> bool {
    // SAFETY: the descriptor is borrowed for the whole call, the list is asked for and given back
    // here and nowhere else, and the entry pointer is only ever written by the platform.
    let acl = unsafe { acl_get_fd(fd.as_raw_fd()) };
    if acl.is_null() {
        let why = std::io::Error::last_os_error();
        return why.raw_os_error() != Some(rustix::io::Errno::NOENT.raw_os_error());
    }
    // SAFETY: the list came from the call above and is given back below; the entry pointer is
    // written by the platform and never read here.
    unsafe {
        let mut entry: AclEntry = core::ptr::null_mut();
        let found = acl_get_entry(acl, ACL_FIRST_ENTRY, &raw mut entry) == 0;
        acl_free(acl);
        found
    }
}
