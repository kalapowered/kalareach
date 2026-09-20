//! The one question about an Apple file that has no answer in safe Rust.
//!
//! An access-control list on this platform is not an extended attribute anything may read: the
//! attribute it lives in is the kernel's own and refuses every call, and the only interface to it
//! takes a **descriptor**. A file's protection has to be asked of the file this host holds open,
//! because a name asked twice can be two different files, so this module makes that one call.

use std::os::fd::{AsRawFd, BorrowedFd};

/// An opaque list, as the platform hands it back.
type Acl = *mut core::ffi::c_void;

unsafe extern "C" {
    /// Returns this descriptor's access-control list, or null when it has none.
    fn acl_get_fd(fd: i32) -> Acl;
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

/// Darwin ACL external representation header magic (`0x012cc16d`).
const ACL_EXT_MAGIC: u32 = 0x012c_c16d;

/// Header size of Darwin native external representation (44 bytes).
const ACL_HEADER_LEN: usize = 44;

/// Size of each ACE in Darwin native external representation (24 bytes).
const ACE_ENTRY_LEN: usize = 24;

/// An error indicating that an access-control list external representation is malformed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidAclError(pub &'static str);

impl core::fmt::Display for InvalidAclError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid access-control list: {}", self.0)
    }
}

impl std::error::Error for InvalidAclError {}

/// An aligned, opaque, validated Darwin access-control list in native binary representation.
///
/// Guaranteed to be 8-byte aligned and checked for exact buffer length, header magic, entry count,
/// and ACL-level flags before passing to FFI.
#[derive(Clone, PartialEq, Eq)]
pub struct AppleAcl {
    storage: Vec<u64>,
    len: usize,
    entry_count: u32,
    flags: u32,
}

impl core::fmt::Debug for AppleAcl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AppleAcl")
            .field("entry_count", &self.entry_count)
            .field("flags", &self.flags)
            .field("len", &self.len)
            .finish()
    }
}

impl AppleAcl {
    /// Validates and parses raw bytes into an aligned `AppleAcl`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidAclError` if the buffer is truncated, has an invalid magic header, has a
    /// declared entry count exceeding or not matching the buffer length, or has trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<Self, InvalidAclError> {
        if bytes.len() < ACL_HEADER_LEN {
            return Err(InvalidAclError("buffer smaller than 44-byte header"));
        }
        let magic = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != ACL_EXT_MAGIC {
            return Err(InvalidAclError("invalid access-control list magic header"));
        }
        let entry_count = u32::from_ne_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]);
        let flags = u32::from_ne_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]);
        let expected_len = (entry_count as usize)
            .checked_mul(ACE_ENTRY_LEN)
            .and_then(|entries_len| ACL_HEADER_LEN.checked_add(entries_len))
            .ok_or(InvalidAclError("entry count size overflow"))?;
        if bytes.len() != expected_len {
            return Err(InvalidAclError(
                "buffer length does not match declared entry count",
            ));
        }
        let u64_count = bytes.len().div_ceil(8);
        let mut storage = vec![0_u64; u64_count];
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                storage.as_mut_ptr().cast::<u8>(),
                bytes.len(),
            );
        }
        Ok(Self {
            storage,
            len: bytes.len(),
            entry_count,
            flags,
        })
    }

    /// Returns the raw binary representation slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        let ptr = self.storage.as_ptr().cast::<u8>();
        unsafe { core::slice::from_raw_parts(ptr, self.len) }
    }

    /// Returns the number of ACE entries in this list.
    #[must_use]
    pub const fn entry_count(&self) -> u32 {
        self.entry_count
    }

    /// Returns the ACL-level flags (e.g. `ACL_FLAG_DEFER_INHERIT`).
    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns true when this list carries ACE entries.
    #[must_use]
    pub const fn has_entries(&self) -> bool {
        self.entry_count > 0
    }

    /// Returns true when this list carries ACL-level flags.
    #[must_use]
    pub const fn has_flags(&self) -> bool {
        self.flags != 0
    }
}

/// Returns true when the file behind one descriptor carries an access-control list with entries or flags.
///
/// A list with no entries and no flags says nothing mode bits do not, and is not one either.
/// When inspecting the descriptor fails for any reason other than absence, returns true so the host
/// does not report an unprotected destination when it could not establish protection.
pub(crate) fn carries_access_control(fd: BorrowedFd<'_>) -> bool {
    carries_list(&read_access_control(fd))
}

/// Decides from one reading of a descriptor whether the file carries protection beyond its mode bits.
///
/// Absence is the only answer that says a file carries nothing. A reading that failed leaves this
/// host unable to establish what protection the file has, and answering "none" there is how a
/// replacement takes protection away from a file that had it.
fn carries_list(read: &std::io::Result<Option<AppleAcl>>) -> bool {
    !matches!(read, Ok(None))
}

/// Reads the access-control list from a descriptor, returning its lossless representation if it
/// carries entries or flags.
///
/// Returns `Ok(None)` when the file carries no extended access-control list beyond its mode bits,
/// or when the list has neither entries nor flags.
pub(crate) fn read_access_control(fd: BorrowedFd<'_>) -> std::io::Result<Option<AppleAcl>> {
    let acl = unsafe { acl_get_fd(fd.as_raw_fd()) };
    if acl.is_null() {
        let why = std::io::Error::last_os_error();
        if why.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(why);
    }
    let size = unsafe { acl_size(acl) };
    if size <= 0 {
        let err = std::io::Error::last_os_error();
        unsafe { acl_free(acl) };
        return Err(err);
    }
    let u64_count = (size as usize).div_ceil(8);
    let mut storage = vec![0_u64; u64_count];
    let written = unsafe { acl_copy_ext_native(storage.as_mut_ptr().cast(), acl, size) };
    let err = if written <= 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };
    unsafe { acl_free(acl) };
    if let Some(err) = err {
        return Err(err);
    }
    let byte_slice =
        unsafe { core::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), written as usize) };
    let parsed = AppleAcl::from_bytes(byte_slice)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.0))?;
    if !parsed.has_entries() && !parsed.has_flags() {
        return Ok(None);
    }
    Ok(Some(parsed))
}

/// Sets or clears the access-control list on a descriptor.
///
/// Setting `None` clears any access-control list by setting an empty list. Setting `Some(acl)`
/// restores the validated, aligned lossless representation to the descriptor.
pub(crate) fn set_access_control(
    fd: BorrowedFd<'_>,
    acl: Option<&AppleAcl>,
) -> std::io::Result<()> {
    match acl {
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
        Some(apple_acl) => {
            let acl_ptr = unsafe { acl_copy_int_native(apple_acl.storage.as_ptr().cast()) };
            if acl_ptr.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            let rc = unsafe { acl_set_fd(fd.as_raw_fd(), acl_ptr) };
            let err = if rc != 0 {
                Some(std::io::Error::last_os_error())
            } else {
                None
            };
            unsafe { acl_free(acl_ptr) };
            if let Some(err) = err {
                return Err(err);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The list's own flag that stops entries being inherited by what is made below.
    const KAUTH_ACL_NO_INHERIT: u32 = 1 << 17;

    /// Builds an external representation with the given entry count and list flags.
    ///
    /// Every entry is zeroed: what these cases decide is the header, which is what this host reads
    /// to tell a list from the absence of one.
    fn representation(entry_count: u32, flags: u32) -> Vec<u8> {
        let entries = entry_count as usize * ACE_ENTRY_LEN;
        let mut raw = vec![0_u8; ACL_HEADER_LEN + entries];
        raw[0..4].copy_from_slice(&ACL_EXT_MAGIC.to_ne_bytes());
        raw[36..40].copy_from_slice(&entry_count.to_ne_bytes());
        raw[40..44].copy_from_slice(&flags.to_ne_bytes());
        raw
    }

    #[test]
    fn malformed_acl_binary_representations_are_rejected() {
        // Less than 44 bytes
        assert!(AppleAcl::from_bytes(&[]).is_err());
        assert!(AppleAcl::from_bytes(&[0_u8; 43]).is_err());

        // Wrong magic
        let mut bad_magic = vec![0_u8; 44];
        assert!(AppleAcl::from_bytes(&bad_magic).is_err());

        // Valid magic with 0 entries and 0 flags (44 bytes)
        let magic_bytes = ACL_EXT_MAGIC.to_ne_bytes();
        bad_magic[0..4].copy_from_slice(&magic_bytes);
        let ok = AppleAcl::from_bytes(&bad_magic).expect("valid 44-byte empty acl");
        assert_eq!(ok.entry_count(), 0);
        assert_eq!(ok.flags(), 0);
        assert!(!ok.has_entries());
        assert!(!ok.has_flags());

        // Declares 1 entry (needs 44 + 24 = 68 bytes), but buffer is 44 bytes -> error
        let mut mismatch = bad_magic.clone();
        mismatch[36..40].copy_from_slice(&1_u32.to_ne_bytes());
        assert!(AppleAcl::from_bytes(&mismatch).is_err());

        // Declares 0 entries, but buffer has extra bytes (e.g. 48 bytes) -> error
        let mut extra = bad_magic.clone();
        extra.extend_from_slice(&[0_u8; 4]);
        assert!(AppleAcl::from_bytes(&extra).is_err());

        // Declares 1 entry with exact 68 bytes -> succeeds
        let mut valid_68 = bad_magic.clone();
        valid_68[36..40].copy_from_slice(&1_u32.to_ne_bytes());
        valid_68.extend_from_slice(&[0_u8; 24]);
        let ok_entry = AppleAcl::from_bytes(&valid_68).expect("valid 68-byte acl with 1 entry");
        assert_eq!(ok_entry.entry_count(), 1);
        assert!(ok_entry.has_entries());
    }

    /// A reading that failed is not a file without a list.
    ///
    /// The platform answers every failure it can attribute to the file with "there is none", so the
    /// failures that reach this host are the ones it cannot attribute at all: a descriptor that is
    /// no longer a file, a device that stopped answering. Each of those has to keep the destination
    /// protected, and the only reading that may report a file as unprotected is the one that
    /// succeeded and found nothing.
    #[test]
    fn only_a_reading_that_found_nothing_reports_a_file_as_unprotected() {
        assert!(
            !carries_list(&Ok(None)),
            "a file whose protection is its mode bits alone carries no list"
        );

        let flags_only = AppleAcl::from_bytes(&representation(0, KAUTH_ACL_NO_INHERIT))
            .expect("a list with a flag and no entries");
        assert!(
            carries_list(&Ok(Some(flags_only))),
            "a list with a flag of its own is protection no mode bit states"
        );

        let one_entry = AppleAcl::from_bytes(&representation(1, 0)).expect("a list with one entry");
        assert!(carries_list(&Ok(Some(one_entry))));

        for os_error in [libc::EBADF, libc::EIO, libc::ENOMEM] {
            assert!(
                carries_list(&Err(std::io::Error::from_raw_os_error(os_error))),
                "a reading that failed with {os_error} leaves the file protected"
            );
        }
        assert!(carries_list(&Err(std::io::Error::from(
            std::io::ErrorKind::InvalidData
        ))));
    }
}
