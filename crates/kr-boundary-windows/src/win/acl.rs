//! Permissions on files and directories: writing a protected list from a text form, reading one
//! back as text, and telling whether an account other than the system's own could change a path.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::LocalFree;
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

const SDDL_REVISION_1: u32 = 1;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const INHERIT_ONLY_ACE: u8 = 0x08;

/// Replaces a path's permissions with a descriptor's list and stops it inheriting.
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
