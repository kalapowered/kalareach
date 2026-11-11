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
    GetAce, GetAclInformation, GetSecurityDescriptorDacl, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION,
};

use super::ffi::{Result, Sid, error, from_wide, last, wide_path};
use super::sd::OwnedSd;
use super::walk::{AnchorRefusal, DirHandle, LIST};

const SDDL_REVISION_1: u32 = 1;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const INHERIT_ONLY_ACE: u8 = 0x08;

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
        return Err(error(1, "the descriptor has no permission list"));
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
        return Err(error(1, "the descriptor has no permission list"));
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
/// With `replacement_only` the check is for a directory above something that must not be swapped:
/// only the rights that delete or take over the path count, since adding a sibling beside it
/// changes nothing it holds. Without it, every right that changes a file or what a directory
/// holds counts. The owner must be the system's own class either way. An entry that allows is
/// counted even where another entry denies, so the answer errs towards refusing.
///
/// # Errors
///
/// Returns the platform's error when the path's permissions cannot be read.
pub fn changeable_by_others(path: &Path, replacement_only: bool) -> Result<Option<String>> {
    let path_text = wide_path(path);
    let mut descriptor: *mut c_void = null_mut();
    let mut owner: *mut c_void = null_mut();
    let mut dacl: *mut ACL = null_mut();
    // SAFETY: the path is NUL-terminated; the outputs are out-parameters, and the descriptor is
    // freed below after everything borrowed from it has been read.
    unsafe {
        let status = GetNamedSecurityInfoW(
            path_text.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            &raw mut dacl,
            null_mut(),
            &raw mut descriptor,
        );
        if status != 0 {
            return Err(error(
                status,
                format!("reading the permissions of {}", path.display()),
            ));
        }
        let mut finding = None;
        if !owner.is_null() {
            let owner_sid = Sid::from_ptr(owner);
            if !system_class(&owner_sid) {
                finding = Some(format!("it is owned by {}", owner_sid.to_text()));
            }
        }
        if finding.is_none() && dacl.is_null() {
            finding = Some("it has no permission list, so anyone may change it".to_owned());
        }
        if finding.is_none() {
            let mut information = ACL_SIZE_INFORMATION {
                AceCount: 0,
                AclBytesInUse: 0,
                AclBytesFree: 0,
            };
            GetAclInformation(
                dacl,
                (&raw mut information).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            );
            let mask_of_interest = if replacement_only {
                REPLACES
            } else {
                CHANGES_CONTENT
            };
            for index in 0..information.AceCount {
                let mut entry: *mut c_void = null_mut();
                if GetAce(dacl, index, &raw mut entry) == 0 {
                    continue;
                }
                let allowed = entry.cast::<ACCESS_ALLOWED_ACE>();
                let header = (*allowed).Header;
                if header.AceType != ACCESS_ALLOWED_ACE_TYPE
                    || header.AceFlags & INHERIT_ONLY_ACE != 0
                {
                    continue;
                }
                let sid = Sid::from_ptr((&raw mut (*allowed).SidStart).cast());
                let mask = (*allowed).Mask;
                if mask & mask_of_interest != 0 && !system_class(&sid) {
                    finding = Some(format!(
                        "{} is allowed rights 0x{:x} on it",
                        sid.to_text(),
                        mask & mask_of_interest
                    ));
                    break;
                }
            }
        }
        LocalFree(descriptor);
        Ok(finding)
    }
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
/// add a subdirectory).
///
/// The answer is `None` only when the owner is in the system's own class (the system, the
/// administrators, the installer service and the creator-owner placeholder), the object has a
/// permission list, every entry of it was read, and no entry that allows names an account outside
/// that class for a right that counts. Anything else is a finding: another account's right, an owner
/// outside the class, no list, and an entry of any type but a plain allow or a plain deny. A
/// callback entry or an object entry grants by a condition or a property that this check does not
/// evaluate, so it is refused and never skipped. An entry that allows is counted even where another
/// entry denies, so the answer errs towards refusing.
///
/// # Errors
///
/// Returns the platform's error when the permissions cannot be read or an entry cannot be read; the
/// caller treats that as a refusal.
pub fn changeable_by_others_on(
    handle: &super::ffi::Handle,
    replacement_only: bool,
) -> Result<Option<String>> {
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
    let outcome = unsafe { finding_in(owner, dacl, replacement_only) };
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
    replacement_only: bool,
) -> Result<Option<String>> {
    const ACCESS_DENIED_ACE_TYPE: u8 = 1;
    if owner.is_null() {
        return Ok(Some("it has no owner".to_owned()));
    }
    // SAFETY: the owner points at an identifier inside the descriptor.
    let owner_sid = unsafe { Sid::from_ptr(owner) };
    if !system_class(&owner_sid) {
        return Ok(Some(format!("it is owned by {}", owner_sid.to_text())));
    }
    if dacl.is_null() {
        return Ok(Some(
            "it has no permission list, so anyone may change it".to_owned(),
        ));
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
    let mask_of_interest = if replacement_only {
        REPLACES
    } else {
        CHANGES_CONTENT
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
        if header.AceType == ACCESS_DENIED_ACE_TYPE {
            continue;
        }
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE {
            return Ok(Some(format!(
                "its permission list has an entry of type {}, which this check does not read",
                header.AceType
            )));
        }
        if header.AceFlags & INHERIT_ONLY_ACE != 0 {
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
            return Ok(Some(format!(
                "{} is allowed rights 0x{:x} on it",
                sid.to_text(),
                mask & mask_of_interest
            )));
        }
    }
    Ok(None)
}
