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
use windows_sys::Win32::Security::Authentication::Identity::{
    LsaQueryInformationPolicy, POLICY_ACCOUNT_DOMAIN_INFO, POLICY_VIEW_LOCAL_INFORMATION,
    PolicyAccountDomainInformation,
};
use windows_sys::Win32::UI::Shell::DeleteProfileW;

use super::ffi::{Named, Result, Sid, error, last, wide};
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
/// answered that no local account has that name (the platform's "no mapping" answer). The lookup is
/// local: it names this computer.
///
/// # Errors
///
/// Returns the platform's error when the lookup failed for any other reason: nothing is then
/// known about the account.
pub fn find(name: &str) -> Result<Option<Sid>> {
    // The name is qualified with the name of the domain of this computer's own accounts, as the
    // system gives it, so that the platform looks it up among those accounts and asks no other
    // domain. A plain name that no local account has is passed on to a domain's controller, and an
    // error of that lookup would be taken for the account's.
    let qualified = format!("{}\\{name}", account_domain()?);
    match Sid::of_account(&qualified) {
        Ok(sid) => Ok(Some(sid)),
        Err(failure) if failure.code == ERROR_NONE_MAPPED => Ok(None),
        Err(failure) => Err(failure),
    }
}

/// The account that has an identifier, found by that identifier: `Some` with its own name where
/// an account of that identifier is there, however it has been renamed since, and `None` where the
/// system answers that no account has it. The identifier is the one a manifest records.
///
/// # Errors
///
/// Returns the platform's error when the text is not an identifier or the lookup failed for any
/// other reason, and an error where the identifier belongs to something that is not a user
/// account: nothing is then known about the account.
pub fn find_by_id(recorded: &str) -> Result<Option<(Sid, String)>> {
    let sid = Sid::parse(recorded)?;
    match sid.lookup_account()? {
        None => Ok(None),
        Some(Named {
            name, user: true, ..
        }) => Ok(Some((sid, name))),
        Some(Named { .. }) => {
            // text: account_find_by_id-1
            Err(error(
                0,
                format!("the identifier {recorded} does not belong to a user account"),
            ))
        }
    }
}

/// The name that the system gives the domain of this computer's own accounts, the domain part of
/// an account's qualified name. It is the computer's name on a workstation or a member server and
/// the domain's own name on a domain controller, so it is read from the system's policy and never
/// taken to be the computer's name.
///
/// # Errors
///
/// Returns the platform's error when the policy cannot be opened or read, and an error for an empty
/// name: no name is then given.
pub fn account_domain() -> Result<String> {
    let handle = policy_with(POLICY_VIEW_LOCAL_INFORMATION as u32)?;
    let mut buffer: *mut std::ffi::c_void = null_mut();
    // SAFETY: the handle is open and the buffer is an out-parameter that this function frees.
    let status = unsafe {
        LsaQueryInformationPolicy(handle, PolicyAccountDomainInformation, &raw mut buffer)
    };
    // SAFETY: converts a status the platform returned.
    let code = unsafe { LsaNtStatusToWinError(status) };
    let domain = if code == 0 {
        // SAFETY: the platform returned the structure that the class names; the name's buffer is
        // inside the allocation and is read before it is freed.
        let text = unsafe {
            let information = &*buffer.cast::<POLICY_ACCOUNT_DOMAIN_INFO>();
            let name = &information.DomainName;
            let text = if name.Buffer.is_null() {
                &[][..]
            } else {
                std::slice::from_raw_parts(name.Buffer, usize::from(name.Length) / 2)
            };
            String::from_utf16_lossy(text)
        };
        // SAFETY: the buffer is the platform's allocation and is freed once.
        unsafe { LsaFreeMemory(buffer) };
        Some(text)
    } else {
        None
    };
    // SAFETY: the handle is open and is closed once.
    unsafe { LsaClose(handle) };
    match domain {
        Some(text) if !text.is_empty() => Ok(text),
        // text: account_domain-1
        Some(_) => Err(error(
            0,
            "the name of the domain of this computer's accounts is empty",
        )),
        // text: account_domain-2
        None => Err(error(
            code,
            "reading the name of the domain of this computer's accounts",
        )),
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
        // text: account_create-1
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
        // text: account_delete-1
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
    policy_with((POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES) as u32)
}

fn policy_with(access: u32) -> Result<isize> {
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
    let status = unsafe { LsaOpenPolicy(null(), &raw const attributes, access, &raw mut handle) };
    if status != 0 {
        // SAFETY: converts a status the platform returned.
        // text: account_policy-1
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
        // text: account_grant_rights-1
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
        // text: account_revoke_all_rights-1
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
    let text = wide(&sid.to_text()?);
    // SAFETY: the identifier text is NUL-terminated; the two optional names are null.
    let removed = unsafe { DeleteProfileW(text.as_ptr(), null(), null()) };
    if removed != 0 {
        return Ok(());
    }
    // text: account_delete_profile-1
    let failure = last("deleting a profile");
    // The profile is missing: error 2 (file not found) or 3 (path not found).
    if failure.code == 2 || failure.code == 3 {
        Ok(())
    } else {
        Err(failure)
    }
}
