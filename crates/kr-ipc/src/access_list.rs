//! The access-control list of an open file or directory on macOS, read through its descriptor.
//!
//! On this platform the list is separate from the permission bits, and `chmod` leaves it as it was.
//! The calls that read a list by a path follow the name, which can lead to another object by the
//! time they run; a list read through the descriptor that is held is the list of the object that is
//! held, whatever has happened to its name since. The system's `acl_get_fd_np` is the one call that
//! does this, and it has no safe interface.
//!
//! The list is read as the system's own text for it, one entry to a line, so two lists compare equal
//! exactly when they hold the same entries, flags included, in the same order.
#![expect(
    unsafe_code,
    reason = "the system's call that reads an access list through a descriptor has no safe interface"
)]

use std::ffi::{CStr, c_char, c_int, c_void};
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd};

/// The type of list this platform keeps for a file or a directory, `ACL_TYPE_EXTENDED` in the SDK.
const ACL_TYPE_EXTENDED: c_int = 0x100;

/// The first line of the system's text for a list: its format and version.
const HEADER: &str = "!#acl 1";

unsafe extern "C" {
    /// `acl_get_fd_np`, which returns the list of the object a descriptor holds, or null with
    /// `errno` set: `ENOENT` where the object has no list.
    fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> *mut c_void;
    /// `acl_to_text`, which returns the text of a list in memory the caller frees, or null.
    fn acl_to_text(acl: *mut c_void, len: *mut isize) -> *mut c_char;
    /// `acl_free`, which releases a list or a text the system gave.
    fn acl_free(object: *mut c_void) -> c_int;
}

/// One entry of an access list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// True for an entry that allows, false for one that denies.
    pub allow: bool,
    /// The entry as the system writes it: the kind of account, its identity and name, the verb with
    /// its inheritance flags, and the permissions.
    pub text: String,
}

/// The access list of a file or a directory: no entries where it has none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccessList {
    /// The entries, in the order the system keeps them.
    pub entries: Vec<Entry>,
}

impl AccessList {
    /// True when some entry allows: one that applies to the object and one that is only passed on
    /// to what is made in it alike.
    #[must_use]
    pub fn allows(&self) -> bool {
        self.entries.iter().any(|entry| entry.allow)
    }
}

/// Reads the list of the object `descriptor` holds. An object with no list, and one on a file system
/// that keeps none, have an empty one; every other failure is an error, because a list that cannot
/// be read is one nothing can be said about.
///
/// # Errors
///
/// Returns the system's error when the descriptor is not open or the list cannot be read, and
/// `InvalidData` when the system's text for the list is not in the form this reads.
pub fn read(descriptor: BorrowedFd<'_>) -> io::Result<AccessList> {
    // SAFETY: the call takes the number of a descriptor the borrow keeps open, reads no memory of
    // this process, and returns a list that is released below, or null.
    let list = unsafe { acl_get_fd_np(descriptor.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if list.is_null() {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(code) if has_no_list(code) => Ok(AccessList::default()),
            _ => Err(error),
        };
    }
    let mut length: isize = 0;
    // SAFETY: the call takes the list returned above and writes one length through a pointer to a
    // live local of that type.
    let text = unsafe { acl_to_text(list, &raw mut length) };
    let failure = io::Error::last_os_error();
    // SAFETY: the list came from `acl_get_fd_np`, and it is released once, here.
    unsafe { acl_free(list) };
    if text.is_null() {
        return Err(failure);
    }
    // SAFETY: the text is NUL-terminated memory the system allocated, and it stays valid until it is
    // released below; it is copied before then.
    let copied = unsafe { CStr::from_ptr(text) }.to_str().map(str::to_owned);
    // SAFETY: the text came from `acl_to_text`, and it is released once, here.
    unsafe { acl_free(text.cast()) };
    parse(&copied.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?)
}

/// True when the system's error for a list says there is none: the object has none, or its file
/// system keeps none.
fn has_no_list(code: i32) -> bool {
    code == libc::ENOENT || code == libc::ENOTSUP
}

/// Reads the system's text for a list: the header, then one entry on each line as
/// `kind:identity:name:number:verb[,flags]:permissions`, the verb being `allow` or `deny`.
fn parse(text: &str) -> io::Result<AccessList> {
    let invalid =
        |what: &str| io::Error::new(io::ErrorKind::InvalidData, format!("{what}: {text:?}"));
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Err(invalid(
            "an access list that does not begin with its header",
        ));
    }
    let mut entries = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        // The permissions and the verb hold no colon; an account's name can.
        let mut fields = line.rsplitn(3, ':');
        let (Some(_permissions), Some(verb), Some(_account)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return Err(invalid("an access entry of too few fields"));
        };
        let allow = match verb.split(',').next() {
            Some("allow") => true,
            Some("deny") => false,
            _ => return Err(invalid("an access entry that neither allows nor denies")),
        };
        entries.push(Entry {
            allow,
            text: line.to_owned(),
        });
    }
    Ok(AccessList { entries })
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd as _;
    use std::path::PathBuf;

    use super::{AccessList, has_no_list, parse, read};

    /// A folder of this test's own, under the temporary folder, gone when this is dropped.
    struct Folder(PathBuf);

    impl Folder {
        fn make(name: &str) -> Self {
            let folder =
                std::env::temp_dir().join(format!("kr-access-list-{name}-{}", crate::new_uuid()));
            std::fs::create_dir_all(&folder).expect("a folder");
            Self(folder)
        }
    }

    impl Drop for Folder {
        fn drop(&mut self) {
            // A list with a deny entry can keep a folder from being removed; an empty one does not.
            let _ = exacl::setfacl(&[&self.0], &[], None);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const GUID: &str = "ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C";

    /// The text of a list is read entry by entry, with the verb told from the flags.
    #[test]
    fn the_text_of_a_list_is_read_entry_by_entry() {
        assert_eq!(parse("!#acl 1\n").expect("a list"), AccessList::default());
        let text = format!(
            "!#acl 1\ngroup:{GUID}:everyone:12:deny,file_inherit,only_inherit:read\n\
             user:{GUID}:a:b:7:allow:read,write\n"
        );
        let list = parse(&text).expect("a list");
        assert_eq!(list.entries.len(), 2);
        assert!(!list.entries[0].allow, "a deny entry with flags");
        assert!(
            list.entries[1].allow,
            "an allow entry whose name holds a colon"
        );
        assert!(list.allows());
        assert!(
            !parse(&format!("!#acl 1\ngroup:{GUID}:everyone:12:deny:read\n"))
                .expect("a list")
                .allows()
        );
    }

    /// A text that is not a list in the form this reads is an error, not an empty list.
    #[test]
    fn a_text_that_is_not_a_list_in_the_known_form_is_an_error() {
        for text in [
            "",
            "!#acl 2\n",
            "group:x:y:1:allow:read\n",
            "!#acl 1\nonly-one-field\n",
            "!#acl 1\ngroup:x:y:1:maybe:read\n",
        ] {
            let error = parse(text).expect_err(text);
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData, "{text:?}");
        }
    }

    /// An object with no list, and a file system that keeps none, have an empty list; any other
    /// answer of the system is an error.
    #[test]
    fn only_the_answers_that_say_there_is_no_list_are_an_empty_list() {
        assert!(has_no_list(libc::ENOENT));
        assert!(has_no_list(libc::ENOTSUP));
        assert!(!has_no_list(libc::EBADF));
        assert!(!has_no_list(libc::EACCES));
        assert!(!has_no_list(libc::EINVAL));
    }

    /// A folder that has no list reads as an empty one, through its descriptor.
    #[test]
    fn a_folder_with_no_list_reads_as_an_empty_list() {
        let folder = Folder::make("none");
        let held = std::fs::File::open(&folder.0).expect("the folder opens");
        assert_eq!(read(held.as_fd()).expect("reads"), AccessList::default());
    }

    /// The list that is read is the held object's: it follows the folder to where it was moved, and
    /// it is not the list of whatever now stands at the folder's old name.
    #[test]
    fn the_list_read_is_the_one_of_the_object_held_whatever_its_name_leads_to() {
        let folder = Folder::make("held");
        exacl::setfacl(
            &[&folder.0],
            &[
                exacl::AclEntry::allow_group("everyone", exacl::Perm::READ, None),
                exacl::AclEntry::deny_group(
                    "everyone",
                    exacl::Perm::DELETE,
                    Some(exacl::Flag::FILE_INHERIT | exacl::Flag::ONLY_INHERIT),
                ),
            ],
            None,
        )
        .expect("a list");
        let held = std::fs::File::open(&folder.0).expect("the folder opens");
        let before = read(held.as_fd()).expect("reads");
        assert_eq!(before.entries.len(), 2, "{before:?}");
        assert!(before.allows());

        let aside = folder
            .0
            .with_file_name(format!("aside-{}", crate::new_uuid()));
        let _aside = Folder(aside.clone());
        std::fs::rename(&folder.0, &aside).expect("moves the folder aside");
        std::fs::create_dir(&folder.0).expect("puts a folder with no list at its name");
        assert_eq!(
            read(held.as_fd()).expect("reads"),
            before,
            "the held folder's list"
        );
        let other = std::fs::File::open(&folder.0).expect("the new folder opens");
        assert_eq!(read(other.as_fd()).expect("reads"), AccessList::default());
    }

    /// A file's list is read through its descriptor as a folder's is.
    #[test]
    fn a_file_s_list_is_read_through_its_descriptor() {
        let folder = Folder::make("file");
        let file = folder.0.join("a");
        std::fs::write(&file, b"x").expect("a file");
        exacl::setfacl(
            &[&file],
            &[exacl::AclEntry::deny_group(
                "everyone",
                exacl::Perm::DELETE,
                None,
            )],
            None,
        )
        .expect("a list");
        let held = std::fs::File::open(&file).expect("the file opens");
        let list = read(held.as_fd()).expect("reads");
        assert_eq!(list.entries.len(), 1, "{list:?}");
        assert!(!list.allows());
    }

    /// A descriptor that is not open is an error, and not a list that is empty.
    #[test]
    fn a_descriptor_that_is_not_open_is_an_error() {
        use std::os::fd::BorrowedFd;
        // SAFETY: the number is far above any descriptor this process holds, so no object is
        // reached through it; the borrow is only given to a call that reads nothing through it.
        let closed = unsafe { BorrowedFd::borrow_raw(i32::MAX) };
        let error = read(closed).expect_err("nothing is held");
        assert_eq!(error.raw_os_error(), Some(libc::EBADF), "{error}");
    }
}
