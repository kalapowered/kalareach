//! The two boundary accounts: making them, refusing them sign-in, hiding them from the sign-in
//! screen and removing them with everything that was set for them.
//!
//! Each account has a random password that nobody keeps: it is made once, handed to the platform
//! and dropped. Git runs as the account through a logon that needs no password, so the password
//! is never used, and no program holds it.

#![allow(unsafe_code)]

use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NONE_MAPPED};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NERR_UserNotFound, NetUserAdd, NetUserDel, UF_DONT_EXPIRE_PASSWD,
    UF_PASSWD_CANT_CHANGE, UF_SCRIPT, USER_INFO_1, USER_PRIV_USER,
};
use windows_sys::Win32::Security::Authentication::Identity::{
    LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING, LsaAddAccountRights, LsaClose,
    LsaEnumerateAccountRights, LsaFreeMemory, LsaNtStatusToWinError, LsaOpenPolicy,
    LsaRemoveAccountRights, POLICY_CREATE_ACCOUNT, POLICY_LOOKUP_NAMES,
};
use windows_sys::Win32::UI::Shell::DeleteProfileW;

use super::ffi::{Result, Sid, error, last, wide};
use super::registry;

/// The rights that refuse an account sign-in at the screen and by Remote Desktop, and the two
/// that refuse it a batch logon and a service logon, which a scheduled task or a service would
/// need to start a process for the account outside the invocation's job.
pub const DENY_RIGHTS: [&str; 4] = [
    "SeDenyInteractiveLogonRight",
    "SeDenyRemoteInteractiveLogonRight",
    "SeDenyBatchLogonRight",
    "SeDenyServiceLogonRight",
];

/// The key whose values name the accounts the sign-in screen does not list.
const SPECIAL_ACCOUNTS: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList";

fn random_password() -> String {
    format!(
        "Aa1!{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// The identifier of a local account: `Some` where the lookup found it, `None` where the lookup
/// answered that no account has that name (the platform's "no mapping" answer).
///
/// # Errors
///
/// Returns the platform's error when the lookup failed for any other reason: nothing is then
/// known about the account.
pub fn find(name: &str) -> Result<Option<Sid>> {
    match Sid::of_account(name) {
        Ok(sid) => Ok(Some(sid)),
        Err(failure) if failure.code == ERROR_NONE_MAPPED => Ok(None),
        Err(failure) => Err(failure),
    }
}

/// Makes a local account: no group, a password nobody keeps that never expires and cannot be
/// changed.
///
/// # Errors
///
/// Returns the platform's error when the account cannot be made.
pub fn create(name: &str) -> Result<Sid> {
    let mut account = wide(name);
    let mut secret = wide(&random_password());
    let mut comment = wide("KalaReach repository boundary account");
    let info = USER_INFO_1 {
        usri1_name: account.as_mut_ptr(),
        usri1_password: secret.as_mut_ptr(),
        usri1_password_age: 0,
        usri1_priv: USER_PRIV_USER,
        usri1_home_dir: null_mut(),
        usri1_comment: comment.as_mut_ptr(),
        usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE,
        usri1_script_path: null_mut(),
    };
    let mut parameter = 0_u32;
    // SAFETY: the structure and the strings it points at are this function's own for the call.
    let status = unsafe { NetUserAdd(null(), 1, (&raw const info).cast(), &raw mut parameter) };
    // Nothing keeps the password: overwrite the copy this function made.
    secret.fill(0);
    if status != NERR_Success {
        return Err(error(status, format!("making the account {name}")));
    }
    Sid::of_account(name)
}

/// Deletes a local account. An account that is not there counts as deleted.
///
/// # Errors
///
/// Returns the platform's error for any failure but a missing account.
pub fn delete(name: &str) -> Result<()> {
    let account = wide(name);
    // SAFETY: the name is NUL-terminated.
    let status = unsafe { NetUserDel(null(), account.as_ptr()) };
    if status == NERR_Success || status == NERR_UserNotFound {
        Ok(())
    } else {
        Err(error(status, format!("deleting the account {name}")))
    }
}

fn unicode(text: &mut Vec<u16>) -> LSA_UNICODE_STRING {
    // The platform wants the length in bytes without the terminator.
    let length = ((text.len() - 1) * 2) as u16;
    LSA_UNICODE_STRING {
        Length: length,
        MaximumLength: length + 2,
        Buffer: text.as_mut_ptr(),
    }
}

fn policy() -> Result<isize> {
    let attributes = LSA_OBJECT_ATTRIBUTES {
        Length: size_of::<LSA_OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: null_mut(),
        ObjectName: null_mut(),
        Attributes: 0,
        SecurityDescriptor: null_mut(),
        SecurityQualityOfService: null_mut(),
    };
    let mut handle: isize = 0;
    // SAFETY: the attributes are this function's own and the handle is an out-parameter.
    let status = unsafe {
        LsaOpenPolicy(
            null(),
            &raw const attributes,
            (POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES) as u32,
            &raw mut handle,
        )
    };
    if status != 0 {
        // SAFETY: converts a status the platform returned.
        return Err(error(
            unsafe { LsaNtStatusToWinError(status) },
            "opening the security policy",
        ));
    }
    Ok(handle)
}

/// Grants an account user rights.
///
/// # Errors
///
/// Returns the platform's error when the rights cannot be granted.
pub fn grant_rights(sid: &Sid, rights: &[&str]) -> Result<()> {
    let handle = policy()?;
    let mut texts: Vec<Vec<u16>> = rights.iter().map(|right| wide(right)).collect();
    let list: Vec<LSA_UNICODE_STRING> = texts.iter_mut().map(unicode).collect();
    // SAFETY: the handle is open, the list and the strings it points at outlive the call.
    let status = unsafe {
        let status = LsaAddAccountRights(handle, sid.as_ptr(), list.as_ptr(), list.len() as u32);
        LsaClose(handle);
        status
    };
    if status == 0 {
        Ok(())
    } else {
        // SAFETY: converts a status the platform returned.
        Err(error(
            unsafe { LsaNtStatusToWinError(status) },
            "granting user rights",
        ))
    }
}

/// Takes away every right an account holds. An account that holds none counts as done.
///
/// # Errors
///
/// Returns the platform's error when the rights cannot be taken away.
pub fn revoke_all_rights(sid: &Sid) -> Result<()> {
    let handle = policy()?;
    // SAFETY: the handle is open and every right is removed, so no list is passed.
    let status = unsafe {
        let status = LsaRemoveAccountRights(handle, sid.as_ptr(), true, null(), 0);
        LsaClose(handle);
        status
    };
    // SAFETY: converts a status the platform returned.
    let code = unsafe { LsaNtStatusToWinError(status) };
    match code {
        0 | 2 => Ok(()),
        // The account holds no rights: the platform answers that the file is not found.
        _ if code == ERROR_FILE_NOT_FOUND => Ok(()),
        other => Err(error(other, "taking away user rights")),
    }
}

/// The rights an account holds, by name.
///
/// # Errors
///
/// Returns the platform's error when the rights cannot be read.
pub fn rights_of(sid: &Sid) -> Result<Vec<String>> {
    let handle = policy()?;
    let mut list: *mut LSA_UNICODE_STRING = null_mut();
    let mut count = 0_u32;
    // SAFETY: the handle is open; the list is an out-parameter the platform allocates and this
    // function frees.
    let (status, rights) = unsafe {
        let status = LsaEnumerateAccountRights(handle, sid.as_ptr(), &raw mut list, &raw mut count);
        let mut rights = Vec::new();
        if status == 0 {
            for index in 0..count as usize {
                let entry = &*list.add(index);
                let text = std::slice::from_raw_parts(entry.Buffer, usize::from(entry.Length) / 2);
                rights.push(String::from_utf16_lossy(text));
            }
            LsaFreeMemory(list.cast());
        }
        LsaClose(handle);
        (status, rights)
    };
    // SAFETY: converts a status the platform returned.
    let code = unsafe { LsaNtStatusToWinError(status) };
    match code {
        0 => Ok(rights),
        2 => Ok(Vec::new()),
        other => Err(error(other, "reading user rights")),
    }
}

/// Keeps an account off the sign-in screen.
///
/// # Errors
///
/// Returns the platform's error when the registry cannot be written.
pub fn hide_from_sign_in(name: &str) -> Result<()> {
    registry::create(SPECIAL_ACCOUNTS)?.set_dword(name, 0)
}

/// Lets an account show on the sign-in screen again, and drops the key when nothing else is in it.
///
/// # Errors
///
/// Returns the platform's error when the registry cannot be written.
pub fn unhide_from_sign_in(name: &str) -> Result<()> {
    if let Some(key) = registry::open(SPECIAL_ACCOUNTS)? {
        key.delete_value(name)?;
    }
    Ok(())
}

/// Whether the sign-in screen is told to leave an account out.
///
/// # Errors
///
/// Returns the platform's error when the registry cannot be read.
pub fn hidden_from_sign_in(name: &str) -> Result<bool> {
    Ok(match registry::open(SPECIAL_ACCOUNTS)? {
        Some(key) => key.dword(name)?.is_some(),
        None => false,
    })
}

/// Deletes the profile folder an account's sign-in made. An account with no profile counts as done.
///
/// # Errors
///
/// Returns the platform's error for any failure but a missing profile.
pub fn delete_profile(sid: &Sid) -> Result<()> {
    let text = wide(&sid.to_text());
    // SAFETY: the identifier text is NUL-terminated; the two optional names are null.
    let removed = unsafe { DeleteProfileW(text.as_ptr(), null(), null()) };
    if removed != 0 {
        return Ok(());
    }
    let failure = last("deleting a profile");
    // The profile is missing: error 2 (file not found) or 3 (path not found).
    if failure.code == 2 || failure.code == 3 {
        Ok(())
    } else {
        Err(failure)
    }
}
