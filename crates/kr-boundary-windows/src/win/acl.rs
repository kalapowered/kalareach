//! Permissions on files and directories: writing a protected list from a text form, reading one
//! back as text, and telling whether an account other than the system's own could change a path.
//!
//! The system's own walk that propagates a list to every child (`SetNamedSecurityInfoW`) is used
//! only by [`set_protected`], for a directory that belongs to the installation and whose children
//! the installer made itself. A directory that a boundary account can reach, and one that may hold
//! what a hostile repository wrote, is changed only on a held handle, with nothing propagated:
//! [`set_protected_when_empty`].

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Wdk::Storage::FileSystem::NtSetSecurityObject;
use windows_sys::Win32::Foundation::{LocalFree, RtlNtStatusToDosError};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION,
    GetAce, GetAclInformation, GetLengthSid, GetSecurityDescriptorDacl, IsValidSid,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};

use super::ffi::{Result, Sid, error, from_wide, last, wide_path};
use super::sd::OwnedSd;
use super::walk::{AnchorRefusal, DirHandle, LIST};
use crate::remedy::Finding;

const SDDL_REVISION_1: u32 = 1;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const INHERIT_ONLY_ACE: u8 = 0x08;
const OBJECT_INHERIT_ACE: u8 = 0x01;
const CONTAINER_INHERIT_ACE: u8 = 0x02;
/// The rights to write attributes and extended attributes.
const ATTRIBUTE_WRITES: u32 = 0x0000_0100 | 0x0000_0010;

/// Replaces a path's permissions with a descriptor's list and stops it inheriting, by the system's
/// own call, which also walks the path's children. It is for the installation's own directories
/// (the data, staging and program directories, the proof's scratch directory and the test cases'
/// folders), which no boundary account can add children to; the system's walk then meets nothing
/// hostile. A directory that can hold what a boundary account wrote is not changed with it.
///
/// # Errors
///
/// Returns the platform's error when the descriptor has no list or the path cannot be changed.
pub fn set_protected(path: &Path, descriptor: &OwnedSd) -> Result<()> {
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = null_mut();
    // SAFETY: the descriptor is valid and the out-parameters are local.
    let got = unsafe {
        GetSecurityDescriptorDacl(
            descriptor.as_ptr(),
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
    };
    if got == 0 || present == 0 {
        return Err(error(0, "the descriptor has no permission list"));
    }
    let path_text = wide_path(path);
    // SAFETY: the path is NUL-terminated and the list belongs to the descriptor, which outlives the
    // call.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path_text.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null_mut(),
        )
    };
    if status != 0 {
        return Err(error(
            status,
            format!("setting the permissions of {}", path.display()),
        ));
    }
    Ok(())
}

/// What [`set_protected_when_empty`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reset {
    /// The directory was empty and now has the list.
    Applied,
    /// The directory holds something, so its list was not changed.
    NotEmpty,
    /// The path is not a directory that a walk may anchor on: a reparse point, something that is
    /// not a directory, or a volume that is not accepted. Nothing was changed.
    Refused(AnchorRefusal),
}

const WRITE_DAC: u32 = 0x0004_0000;
const READ_CONTROL: u32 = 0x0002_0000;

/// Replaces a directory's list with a descriptor's list and stops it inheriting, on the directory's
/// own handle and only when the directory has no child.
///
/// The directory is opened as itself, without following a reparse point and without delete
/// sharing, and stays held from the check that it is empty to the change. The change is made with
/// `NtSetSecurityObject` on that handle and propagates to nothing, so a child that appears is not
/// reached. It is for the broker's `run` directory, which holds invocations' private roots and
/// must not be changed under one. A directory that is not empty is left as it is and reported, so
/// the caller can leave it or refuse.
///
/// # Errors
///
/// Returns the platform's error when the descriptor has no list, the directory cannot be opened
/// or listed, or the list is refused. A path that is not an acceptable directory is the answer
/// [`Reset::Refused`], not an error.
pub fn set_protected_when_empty(path: &Path, descriptor: &OwnedSd) -> Result<Reset> {
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = null_mut();
    // SAFETY: the descriptor is valid and the out-parameters are local.
    let got = unsafe {
        GetSecurityDescriptorDacl(
            descriptor.as_ptr(),
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
    };
    if got == 0 || present == 0 {
        return Err(error(0, "the descriptor has no permission list"));
    }
    let held = match DirHandle::open_anchor_with(path, LIST | WRITE_DAC)? {
        Ok(held) => held,
        Err(refusal) => return Ok(Reset::Refused(refusal)),
    };
    if !held.children()?.is_empty() {
        return Ok(Reset::NotEmpty);
    }
    // SAFETY: the handle is open with the right to change the list and the descriptor lives
    // through the call.
    let status = unsafe {
        NtSetSecurityObject(
            held.handle().raw(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.as_ptr(),
        )
    };
    if status < 0 {
        // SAFETY: converts a status code to a Windows error number; it reads nothing else.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(error(
            code,
            format!("setting the permissions of {}", path.display()),
        ));
    }
    Ok(Reset::Applied)
}

/// Reads a path's owner and permission list as text.
///
/// # Errors
///
/// Returns the platform's error when the path cannot be read.
pub fn describe(path: &Path) -> Result<String> {
    let path_text = wide_path(path);
    let mut descriptor: *mut c_void = null_mut();
    // SAFETY: the path is NUL-terminated and the descriptor is an out-parameter freed below.
    unsafe {
        let status = GetNamedSecurityInfoW(
            path_text.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &raw mut descriptor,
        );
        if status != 0 {
            return Err(error(
                status,
                format!("reading the permissions of {}", path.display()),
            ));
        }
        let mut text: *mut u16 = null_mut();
        let converted = ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut text,
            null_mut(),
        );
        let result = if converted == 0 {
            Err(last(format!(
                "writing the permissions of {}",
                path.display()
            )))
        } else {
            let value = from_wide(text);
            LocalFree(text.cast());
            Ok(value)
        };
        LocalFree(descriptor);
        result
    }
}

/// The rights that let an account change a file or what is in a directory.
const CHANGES_CONTENT: u32 = 0x0000_0002 // write data, add file
    | 0x0000_0004 // append data, add subdirectory
    | 0x0000_0040 // delete child
    | 0x0001_0000 // delete
    | 0x0004_0000 // change permissions
    | 0x0008_0000 // take ownership
    | 0x4000_0000 // generic write
    | 0x1000_0000 // generic all
    | 0x0200_0000; // maximum allowed
/// The rights that let an account replace a path by another.
const REPLACES: u32 =
    0x0000_0040 | 0x0001_0000 | 0x0004_0000 | 0x0008_0000 | 0x4000_0000 | 0x1000_0000 | 0x0200_0000;

fn system_class(sid: &Sid) -> bool {
    const SYSTEM: &str = "S-1-5-18";
    const ADMINISTRATORS: &str = "S-1-5-32-544";
    const CREATOR_OWNER: &str = "S-1-3-0";
    const TRUSTED_INSTALLER: &str =
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    let text = sid.to_text();
    [SYSTEM, ADMINISTRATORS, CREATOR_OWNER, TRUSTED_INSTALLER].contains(&text.as_str())
}

/// Says which account other than the system's own can change a path, or `None` when none can.
///
/// The path is opened, following a link as the platform does, and the owner and the list are read
/// on that handle by [`changeable_by_others_on`], so the answer has its rules: an entry that only a
/// child inherits counts when it carries an inheritance flag, the rights to write attributes count,
/// and an entry that is malformed or of a type the check does not read is a finding. It is for
/// objects that the installation does not make and cannot hold open (the Git installation's
/// directory); a directory that the installation makes is held and checked on its handle.
///
/// # Errors
///
/// Returns the platform's error when the path cannot be opened or its permissions cannot be read.
pub fn changeable_by_others(path: &Path, replacement_only: bool) -> Result<Option<Finding>> {
    let wide = wide_path(path);
    // SAFETY: the path is NUL-terminated; the call keeps nothing of it.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    let handle = super::ffi::Handle::new(
        raw,
        &format!("opening {} to read its permissions", path.display()),
    )?;
    changeable_by_others_on(&handle, replacement_only)
}

/// As [`changeable_by_others`], for an object that is already open: the owner and the list are read
/// from the handle, so the answer is about the object the caller holds and not about whatever the
/// path names a moment later. The handle needs the right to read permissions.
///
/// `replacement_only` narrows which rights count. With it the check is for a directory above
/// something that must not be swapped, and only the rights that delete or take over the object count
/// (delete child, delete, change permissions, take ownership, generic write and all, maximum
/// allowed), since adding a sibling beside it changes nothing it holds. Without it every right that
/// changes a file or what a directory holds counts as well (write data or add a file, append data or
/// add a subdirectory). Either way the rights to write attributes and extended attributes count: a
/// handle with the first can turn an empty directory into a mount point.
///
/// An entry that only a child inherits (it has no effect on the object itself) counts like any
/// other when it carries an inheritance flag, since the child it gives a right on is made by the
/// caller's creating call or by whoever creates in the directory next. An entry whose size does not
/// hold its identifier is refused as malformed, whatever its type.
///
/// The answer is `None` only when the owner is in the system's own class (the system, the
/// administrators, the installer service and the creator-owner placeholder), the object has a
/// permission list, every entry of it was read, and no entry that allows names an account outside
/// that class for a right that counts. Anything else is a finding, of one of two kinds: a state that
/// is read and gives another account a right ([`Finding::Granted`]: an entry's right, an owner
/// outside the class, no list), and an object that the check cannot evaluate ([`Finding::Unevaluated`]:
/// an entry of any type but a plain allow or a plain deny, an entry too small for its identifier, no
/// owner). A callback entry or an object entry grants by a condition or a property that this check
/// does not evaluate, so it is refused and never skipped, and it is not said to grant a right. An
/// entry that allows is counted even where another entry denies, so the answer errs towards
/// refusing.
///
/// # Errors
///
/// Returns the platform's error when the permissions cannot be read or an entry cannot be read; the
/// caller treats that as a refusal.
pub fn changeable_by_others_on(
    handle: &super::ffi::Handle,
    replacement_only: bool,
) -> Result<Option<Finding>> {
    judged(
        handle,
        if replacement_only {
            Counts::Replacement
        } else {
            Counts::Content
        },
    )
}

/// As [`changeable_by_others_on`], for a folder above the installation's trees, up to the volume's
/// root: what counts is only what lets an account swap a folder below it for a link after the folder
/// below was read. The owner must be in the system's own class, and no entry that applies to the
/// folder itself may allow an identity outside that class to delete or rename an entry in it, to
/// delete it, to change its list or to take its ownership (generic write, generic all and maximum
/// allowed count as well). The rights to add a file or a subdirectory do not count: they are what
/// the system's own default lists give, and an added sibling changes nothing that was read. An entry
/// that is for inheritance alone applies to the folder's children and not to the folder, so it does
/// not count either: the system's default list of a volume's root has one that gives the
/// authenticated users the right to modify what they make there.
///
/// # Errors
///
/// Returns the platform's error when the permissions cannot be read or an entry cannot be read; the
/// caller treats that as a refusal.
pub fn replaceable_by_others_on(handle: &super::ffi::Handle) -> Result<Option<Finding>> {
    judged(handle, Counts::Above)
}

/// Which rights, and which entries, count in [`finding_in`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Counts {
    /// Every right that changes a file or what a directory holds.
    Content,
    /// The rights that delete or take over the object, and the entries that only a child inherits.
    Replacement,
    /// The rights that delete or take over a folder above the object, and only the entries that
    /// apply to the folder itself.
    Above,
}

fn judged(handle: &super::ffi::Handle, counts: Counts) -> Result<Option<Finding>> {
    use windows_sys::Win32::Security::Authorization::GetSecurityInfo;
    let mut descriptor: *mut c_void = null_mut();
    let mut owner: *mut c_void = null_mut();
    let mut dacl: *mut ACL = null_mut();
    // SAFETY: the handle is open and the caller holds it through the call; the outputs are local
    // out-parameters, and the descriptor they point into is freed below after everything borrowed
    // from it has been read.
    let status = unsafe {
        GetSecurityInfo(
            handle.raw(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            &raw mut dacl,
            null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 {
        return Err(error(status, "reading the permissions of an open object"));
    }
    // SAFETY: the call returned a valid descriptor with the owner and the list inside it, and
    // nothing borrowed from it outlives the call below.
    let outcome = unsafe { finding_in(owner, dacl, counts) };
    // SAFETY: the descriptor came from the platform's allocator and is freed once, after the last
    // read.
    unsafe {
        LocalFree(descriptor);
    }
    outcome
}

/// What [`changeable_by_others_on`] says of an owner and a list that the platform returned.
///
/// # Safety
///
/// `owner` and `dacl` are each null or point into a descriptor that lives through the call.
unsafe fn finding_in(
    owner: *mut c_void,
    dacl: *mut ACL,
    counts: Counts,
) -> Result<Option<Finding>> {
    const ACCESS_DENIED_ACE_TYPE: u8 = 1;
    if owner.is_null() {
        return Ok(Some(Finding::Unevaluated("it has no owner".to_owned())));
    }
    // SAFETY: the owner points at an identifier inside the descriptor.
    let owner_sid = unsafe { Sid::from_ptr(owner) };
    if !system_class(&owner_sid) {
        return Ok(Some(Finding::Granted(format!(
            "it is owned by {}",
            crate::remedy::identity_text(owner_sid.account_name().as_deref(), &owner_sid.to_text())
        ))));
    }
    if dacl.is_null() {
        return Ok(Some(Finding::Granted(
            "it has no permission list, so anyone may change it".to_owned(),
        )));
    }
    let mut information = ACL_SIZE_INFORMATION {
        AceCount: 0,
        AclBytesInUse: 0,
        AclBytesFree: 0,
    };
    // SAFETY: the list is valid and the buffer is the size the class asks for.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut information).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(last("reading the size of a permission list"));
    }
    let mask_of_interest = match counts {
        Counts::Content => ATTRIBUTE_WRITES | CHANGES_CONTENT,
        Counts::Replacement => ATTRIBUTE_WRITES | REPLACES,
        Counts::Above => REPLACES,
    };
    for index in 0..information.AceCount {
        let mut entry: *mut c_void = null_mut();
        // SAFETY: the index is below the entry count the list reported.
        if unsafe { GetAce(dacl, index, &raw mut entry) } == 0 {
            return Err(last("reading an entry of a permission list"));
        }
        let allowed = entry.cast::<ACCESS_ALLOWED_ACE>();
        // SAFETY: every entry begins with a header; the platform returned a pointer to a whole one.
        let header = unsafe { (*allowed).Header };
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE && header.AceType != ACCESS_DENIED_ACE_TYPE {
            return Ok(Some(Finding::Unevaluated(format!(
                "its permission list has an entry of type {}, which this check does not read",
                header.AceType
            ))));
        }
        // SAFETY: the entry is a header, a mask and an identifier; the size the header gives bounds
        // every read of the identifier.
        if !unsafe { entry_holds_its_identifier(allowed) } {
            return Ok(Some(Finding::Unevaluated(
                "its permission list has an entry whose identifier is not a valid one or does not fit in the entry's size"
                    .to_owned(),
            )));
        }
        if header.AceType == ACCESS_DENIED_ACE_TYPE {
            continue;
        }
        // An entry for inheritance alone gives no right on this object, but what it inherits is
        // given on the objects made in it. A folder above the object is judged on its own rights:
        // what its children inherit is read on the children.
        if header.AceFlags & INHERIT_ONLY_ACE != 0
            && (counts == Counts::Above
                || header.AceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) == 0)
        {
            continue;
        }
        // SAFETY: a plain allow entry is a header, a mask and an identifier.
        let (sid, mask) = unsafe {
            (
                Sid::from_ptr((&raw mut (*allowed).SidStart).cast()),
                (*allowed).Mask,
            )
        };
        if mask & mask_of_interest != 0 && !system_class(&sid) {
            if counts == Counts::Above {
                return Ok(Some(Finding::Granted(crate::remedy::rights_finding(
                    &crate::remedy::identity_text(sid.account_name().as_deref(), &sid.to_text()),
                    mask & mask_of_interest,
                ))));
            }
            return Ok(Some(Finding::Granted(crate::remedy::entry_rights_finding(
                &sid.to_text(),
                mask & mask_of_interest,
            ))));
        }
    }
    Ok(None)
}

/// Whether an allow or deny entry is large enough for the identifier it names, and the identifier
/// is a valid one.
///
/// # Safety
///
/// `entry` points at an entry of type allow or deny that lives through the call, whose header
/// (four bytes) is readable.
unsafe fn entry_holds_its_identifier(entry: *const ACCESS_ALLOWED_ACE) -> bool {
    let start = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    // An identifier is at least its revision, its count and its authority: eight bytes.
    const SID_HEAD: usize = 8;
    // SAFETY: the header is readable by the caller's contract.
    let size = usize::from(unsafe { (*entry).Header.AceSize });
    if size < start + SID_HEAD {
        return false;
    }
    // SAFETY: the size covers the identifier's first eight bytes, which say how long it is.
    let sid = unsafe { std::ptr::addr_of!((*entry).SidStart) }
        .cast_mut()
        .cast::<c_void>();
    // SAFETY: the identifier's head lies inside the entry.
    if unsafe { IsValidSid(sid) } == 0 {
        return false;
    }
    // SAFETY: the identifier is valid, so its length is the one it says.
    let length = unsafe { GetLengthSid(sid) } as usize;
    start + length <= size
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use super::*;
    use crate::win::sd;
    use windows_sys::Win32::Security::GetSecurityDescriptorOwner;

    /// A list the platform built from text, copied so that a case can damage an entry, with the
    /// owner of the descriptor it came from.
    struct Fixture {
        _descriptor: sd::OwnedSd,
        owner: *mut c_void,
        list: Vec<u8>,
    }

    impl Fixture {
        fn from(text: &str) -> Fixture {
            let descriptor = sd::descriptor_from_text(text).unwrap();
            let mut owner: *mut c_void = null_mut();
            let mut defaulted = 0;
            let mut present = 0;
            let mut dacl: *mut ACL = null_mut();
            // SAFETY: the descriptor is valid and the outputs are local.
            unsafe {
                assert_ne!(
                    GetSecurityDescriptorOwner(
                        descriptor.as_ptr(),
                        &raw mut owner,
                        &raw mut defaulted
                    ),
                    0
                );
                assert_ne!(
                    GetSecurityDescriptorDacl(
                        descriptor.as_ptr(),
                        &raw mut present,
                        &raw mut dacl,
                        &raw mut defaulted,
                    ),
                    0
                );
            }
            let mut information = ACL_SIZE_INFORMATION {
                AceCount: 0,
                AclBytesInUse: 0,
                AclBytesFree: 0,
            };
            // SAFETY: the list is valid and the buffer is the size the class asks for.
            unsafe {
                assert_ne!(
                    GetAclInformation(
                        dacl,
                        (&raw mut information).cast(),
                        size_of::<ACL_SIZE_INFORMATION>() as u32,
                        AclSizeInformation,
                    ),
                    0
                );
            }
            // SAFETY: the list holds `AclBytesInUse` bytes.
            let list = unsafe {
                std::slice::from_raw_parts(dacl.cast::<u8>(), information.AclBytesInUse as usize)
            }
            .to_vec();
            Fixture {
                _descriptor: descriptor,
                owner,
                list,
            }
        }

        /// Where entry `index` begins in the copy.
        fn offset(&self, index: usize) -> usize {
            let mut at = size_of::<ACL>();
            for _ in 0..index {
                at += usize::from(u16::from_le_bytes([self.list[at + 2], self.list[at + 3]]));
            }
            at
        }

        fn set_size(&mut self, index: usize, size: u16) {
            let at = self.offset(index);
            self.list[at + 2..at + 4].copy_from_slice(&size.to_le_bytes());
        }

        fn finding(&mut self, replacement_only: bool) -> Option<String> {
            self.judge(if replacement_only {
                Counts::Replacement
            } else {
                Counts::Content
            })
        }

        fn above(&mut self) -> Option<String> {
            self.judge(Counts::Above)
        }

        fn kind(&mut self, counts: Counts) -> Option<Finding> {
            // SAFETY: the owner lives in the descriptor the fixture keeps, and the list is a copy
            // of a valid one, damaged only in an entry's size or identifier.
            unsafe { finding_in(self.owner, self.list.as_mut_ptr().cast(), counts).unwrap() }
        }

        fn judge(&mut self, counts: Counts) -> Option<String> {
            self.kind(counts).map(|found| found.to_string())
        }
    }

    const BASE: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

    #[test]
    fn a_list_of_the_system_class_alone_has_no_finding() {
        assert_eq!(Fixture::from(BASE).finding(false), None);
        assert_eq!(Fixture::from(BASE).finding(true), None);
    }

    #[test]
    fn an_entry_that_only_a_child_inherits_counts_and_one_that_inherits_nowhere_does_not() {
        let mut fixture = Fixture::from(&format!("{BASE}(A;OICIIO;FA;;;BU)"));
        let finding = fixture.finding(false).expect("a child would inherit it");
        assert!(finding.contains("S-1-5-32-545"), "{finding}");
        assert!(
            matches!(fixture.kind(Counts::Content), Some(Finding::Granted(_))),
            "an entry's right is a grant"
        );
        // An entry that inherits to no child and applies to nothing is not a right.
        let at = fixture.offset(2);
        fixture.list[at + 1] = INHERIT_ONLY_ACE;
        assert_eq!(fixture.finding(false), None);
    }

    #[test]
    fn the_rights_to_write_attributes_and_extended_attributes_count() {
        for mask in ["0x100", "0x10"] {
            for replacement_only in [false, true] {
                let mut fixture = Fixture::from(&format!("{BASE}(A;;{mask};;;BU)"));
                assert!(
                    fixture.finding(replacement_only).is_some(),
                    "{mask} is a right that turns an empty folder into a link"
                );
            }
        }
        // Reading and listing do not.
        assert_eq!(
            Fixture::from(&format!("{BASE}(A;;0x1200a9;;;BU)")).finding(false),
            None
        );
    }

    #[test]
    fn an_entry_that_is_too_small_for_its_identifier_is_refused_whatever_its_type() {
        // An allow entry, a deny entry and an inherit-only entry, each cut to a size that holds the
        // mask and not the identifier; and one cut to hold the identifier's head and not all of it.
        for text in [
            format!("{BASE}(A;;0x1200a9;;;BU)"),
            format!("{BASE}(D;;FA;;;BU)"),
            format!("{BASE}(A;OICIIO;0x1200a9;;;BU)"),
        ] {
            for size in [8_u16, 12, 15, 20] {
                let mut fixture = Fixture::from(&text);
                fixture.set_size(2, size);
                let finding = fixture.finding(false).unwrap_or_default();
                assert!(
                    finding.contains("does not hold its identifier"),
                    "{text} cut to {size}: {finding:?}"
                );
                assert!(
                    matches!(fixture.kind(Counts::Content), Some(Finding::Unevaluated(_))),
                    "an entry that cannot be read is not a grant: {text} cut to {size}"
                );
            }
        }
        // An identifier whose count of parts is not one that exists.
        let mut fixture = Fixture::from(&format!("{BASE}(D;;FA;;;BU)"));
        let at = fixture.offset(2) + 8;
        fixture.list[at + 1] = 0xff;
        assert!(
            fixture
                .finding(false)
                .unwrap_or_default()
                .contains("does not hold its identifier")
        );
    }

    /// The system's default list of a volume's root, as `icacls` shows it: the administrators and
    /// the system with every right, the users with read and execute, the authenticated users with
    /// the right to add a subdirectory and, for what is made below, to modify it.
    const VOLUME_ROOT: &str = "O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICIIO;0x1301bf;;;AU)(A;;0x4;;;AU)";

    #[test]
    fn the_default_list_of_a_volumes_root_and_of_program_data_has_no_finding_above_the_trees() {
        assert_eq!(Fixture::from(VOLUME_ROOT).above(), None);
        // Program Data: the users may add a file and a subdirectory and write attributes and
        // extended attributes (0x116 is write data, append data, write extended attributes and write
        // attributes), and the creator-owner placeholder has every right on what it makes.
        let data = "O:SYD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICIIO;FA;;;CO)(A;OICI;0x1200a9;;;BU)(A;CI;0x116;;;BU)";
        assert_eq!(Fixture::from(data).above(), None);
    }

    #[test]
    fn a_right_to_delete_rename_change_the_list_or_take_the_folder_is_a_finding_above_the_trees() {
        for (rights, said) in [
            ("0x40", "delete or rename an entry in it"),
            ("0x10000", "delete it"),
            ("0x40000", "change its list"),
            ("0x80000", "take its ownership"),
        ] {
            let mut fixture = Fixture::from(&format!("{BASE}(A;CI;{rights};;;BU)"));
            let finding = fixture.above().expect(rights);
            assert!(finding.contains("S-1-5-32-545"), "{finding}");
            assert!(finding.contains(said), "{rights}: {finding}");
        }
        // The right the default list gives to add an entry stays allowed.
        for rights in ["0x2", "0x4", "0x10", "0x100", "0x116"] {
            assert_eq!(
                Fixture::from(&format!("{BASE}(A;CI;{rights};;;BU)")).above(),
                None,
                "{rights}"
            );
        }
    }

    #[test]
    fn an_entry_for_inheritance_alone_is_no_finding_above_the_trees_and_one_that_applies_is() {
        let inherit_only = format!("{BASE}(A;OICIIO;0x40;;;BU)");
        assert_eq!(Fixture::from(&inherit_only).above(), None);
        // The same entry counts for the folder that the installation holds, whose children inherit it.
        assert!(Fixture::from(&inherit_only).finding(true).is_some());
        assert!(
            Fixture::from(&format!("{BASE}(A;OICI;0x40;;;BU)"))
                .above()
                .is_some()
        );
    }

    #[test]
    fn an_owner_outside_the_system_class_and_an_entry_this_check_does_not_read_are_findings_above()
    {
        let finding = Fixture::from("O:BUD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
            .above()
            .expect("owned by the users");
        assert!(finding.contains("is owned by "), "{finding}");
        assert!(finding.contains("(S-1-5-32-545)"), "{finding}");
        let mut fixture = Fixture::from(&format!("{BASE}(D;;FA;;;BU)"));
        fixture.set_size(2, 12);
        assert!(
            fixture
                .above()
                .unwrap_or_default()
                .contains("does not hold its identifier")
        );
    }
}
