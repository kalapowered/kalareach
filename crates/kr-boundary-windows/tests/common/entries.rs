//! Writes an entry for a raw security identifier into the permission list of a file with the
//! platform's own calls, and not through the product. The identifier of an invocation's group
//! belongs to no account, so a tool that resolves names (`icacls`) refuses it.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW,
    NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID,
    TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PSID};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_APPEND_DATA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
};

/// Adds an allow entry for the identifier in `sid_text` (the text form, `S-1-...`) with the rights
/// to write data, append data, write extended attributes and write attributes to the file's
/// permission list, and keeps the entries that are already there. Panics with the platform's
/// status when a call refuses.
pub fn grant_write_to_identifier(path: &Path, sid_text: &str) {
    let name: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let text: Vec<u16> = sid_text.encode_utf16().chain([0]).collect();
    let mut sid: PSID = null_mut();
    let mut descriptor: *mut c_void = null_mut();
    let mut grown: *mut ACL = null_mut();
    // SAFETY: both texts are NUL-terminated and outlive the calls; every pointer that a call
    // returns is released below, once, with `LocalFree`, and nothing is read after its release.
    let failure = unsafe {
        let made = ConvertStringSidToSidW(text.as_ptr(), &raw mut sid);
        if made == 0 {
            Some(format!("{sid_text} is not an identifier"))
        } else {
            let mut current: *mut ACL = null_mut();
            let read = GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &raw mut current,
                null_mut(),
                &raw mut descriptor,
            );
            if read != 0 {
                Some(format!("reading the list: status {read}"))
            } else {
                let entry = EXPLICIT_ACCESS_W {
                    grfAccessPermissions: FILE_WRITE_DATA
                        | FILE_APPEND_DATA
                        | FILE_WRITE_EA
                        | FILE_WRITE_ATTRIBUTES,
                    grfAccessMode: GRANT_ACCESS,
                    grfInheritance: NO_INHERITANCE,
                    Trustee: TRUSTEE_W {
                        pMultipleTrustee: null_mut(),
                        MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                        TrusteeForm: TRUSTEE_IS_SID,
                        TrusteeType: TRUSTEE_IS_UNKNOWN,
                        ptstrName: sid.cast(),
                    },
                };
                let built = SetEntriesInAclW(1, &raw const entry, current, &raw mut grown);
                if built != 0 {
                    Some(format!("adding the entry: status {built}"))
                } else {
                    let written = SetNamedSecurityInfoW(
                        name.as_ptr(),
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION,
                        null_mut(),
                        null_mut(),
                        grown,
                        null_mut(),
                    );
                    (written != 0).then(|| format!("writing the list: status {written}"))
                }
            }
        }
    };
    // SAFETY: each pointer is null or was returned by the platform to this function alone.
    unsafe {
        LocalFree(grown.cast());
        LocalFree(descriptor);
        LocalFree(sid);
    }
    if let Some(failure) = failure {
        panic!("{}: {failure}", path.display());
    }
}
