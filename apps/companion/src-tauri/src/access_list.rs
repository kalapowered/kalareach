//! The access list of a file this computer holds open, on macOS.
//!
//! A file's mode bits are not the whole of who may read it on this platform: an access list sits
//! beside them and can name accounts the mode does not mention, and a file that already exists
//! keeps its list when its mode is set. The recovery kit holds the seed, so a file the person chose
//! to put it in must be left with its mode bits as the only thing that says who may read it.
//!
//! The platform reaches a file's list through a **descriptor** and through its own interface,
//! which has no safe binding, so this module is where the crate leaves safe Rust for it. The list
//! is read and cleared through the descriptor that goes on to receive the kit, never through the
//! file's name: a name asked twice can be two different files, and the list that mattered would
//! then be the one on the file nothing was written into.

#![expect(
    unsafe_code,
    reason = "a file's access list is reached through a descriptor and the platform's own \
              interface, which has no safe binding; the calls are made here and nowhere else"
)]

use std::fs::File;
use std::os::fd::AsRawFd as _;

/// An opaque list, as the platform hands it back.
type Acl = *mut core::ffi::c_void;

/// An opaque entry of one.
type AclEntry = *mut core::ffi::c_void;

/// The platform's name for "the first entry of this list".
const ACL_FIRST_ENTRY: i32 = 0;

unsafe extern "C" {
    /// Returns this descriptor's access list, or null when it has none.
    fn acl_get_fd(fd: i32) -> Acl;
    /// Writes one entry of a list and returns zero when there is one to write.
    fn acl_get_entry(acl: Acl, entry_id: i32, entry: *mut AclEntry) -> i32;
    /// Allocates a list with room for this many entries.
    fn acl_init(count: i32) -> Acl;
    /// Sets the access list of a descriptor.
    fn acl_set_fd(fd: i32, acl: Acl) -> i32;
    /// Gives a list back.
    fn acl_free(obj: *mut core::ffi::c_void) -> i32;
}

/// Whether the file behind this descriptor has an access list with an entry in it.
///
/// A file whose protection is its mode bits alone has no list, and the platform says so by handing
/// back nothing and naming it: the list is *not found*. Any other failure is an error, because
/// this computer then cannot say what protects the file.
fn has_entries(file: &File) -> std::io::Result<bool> {
    // SAFETY: the descriptor belongs to `file`, which is borrowed for the whole call; the list is
    // asked for and given back here and nowhere else.
    let acl = unsafe { acl_get_fd(file.as_raw_fd()) };
    if acl.is_null() {
        let why = std::io::Error::last_os_error();
        return if why.kind() == std::io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(why)
        };
    }
    // SAFETY: the list came from the call above and is given back below; the entry pointer is
    // written by the platform and never read here.
    let found = unsafe {
        let mut entry: AclEntry = core::ptr::null_mut();
        let found = acl_get_entry(acl, ACL_FIRST_ENTRY, &raw mut entry) == 0;
        acl_free(acl);
        found
    };
    Ok(found)
}

/// Removes the access list of the file behind this descriptor, so that its mode bits are all that
/// say who may read it.
///
/// # Errors
///
/// Returns an error when the list cannot be read or removed, or when an entry is still there
/// after it was removed. The file's contents are not touched either way.
pub fn clear(file: &File) -> std::io::Result<()> {
    if !has_entries(file)? {
        return Ok(());
    }
    // SAFETY: the empty list is made, set on a descriptor `file` keeps open for the call, and given
    // back here and nowhere else.
    let set = unsafe {
        let empty = acl_init(0);
        if empty.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let rc = acl_set_fd(file.as_raw_fd(), empty);
        let why = (rc != 0).then(std::io::Error::last_os_error);
        acl_free(empty);
        why
    };
    if let Some(why) = set {
        return Err(why);
    }
    if has_entries(file)? {
        return Err(std::io::Error::other(
            "the file's access list could not be cleared",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;

    use exacl::{AclEntry, Perm};

    /// A list that lets everyone read the file.
    fn everyone_may_read(path: &std::path::Path) {
        exacl::setfacl(
            &[path],
            &[AclEntry::allow_group("everyone", Perm::READ, None)],
            None,
        )
        .expect("an access list");
    }

    /// The list is cleared on the file the descriptor is for, whatever the name now says: a name
    /// that is moved to another file between the open and the call is not followed.
    #[test]
    fn the_list_cleared_is_the_one_on_the_file_held_open() {
        let directory = tempfile::tempdir().expect("a directory");
        let chosen = directory.path().join("kit");
        std::fs::write(&chosen, "earlier").expect("a file");
        everyone_may_read(&chosen);
        let held = OpenOptions::new().write(true).open(&chosen).expect("open");

        // The name now belongs to another file, which also has a list.
        let moved = directory.path().join("moved");
        std::fs::rename(&chosen, &moved).expect("a rename");
        std::fs::write(&chosen, "another").expect("another file");
        everyone_may_read(&chosen);

        super::clear(&held).expect("cleared");

        assert!(
            exacl::getfacl(&moved, None).expect("list").is_empty(),
            "the file held open has no list"
        );
        assert!(
            !exacl::getfacl(&chosen, None).expect("list").is_empty(),
            "the file the name now has was not touched"
        );
    }

    #[test]
    fn a_file_with_no_list_is_left_as_it_is() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("kit");
        std::fs::write(&path, "earlier").expect("a file");
        let held = OpenOptions::new().write(true).open(&path).expect("open");
        super::clear(&held).expect("nothing to clear");
        assert!(exacl::getfacl(&path, None).expect("list").is_empty());
    }
}
