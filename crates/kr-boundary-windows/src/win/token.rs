//! The logon token Git runs under.
//!
//! The token is made for a boundary account without its password, by a logon that only the
//! system's own service can ask for. It carries one group no other token has, the invocation's
//! group, and it is built so that every grant flows through that group and none through the
//! account itself:
//!
//! - the account's own identifier is marked deny-only, so an entry that names the account allows
//!   nothing, and the owner implied by an object the account made is not an owner here;
//! - the invocation's group is the token's owner and default owner, and the default permission
//!   list of every object the token creates names that group and the system.
//!
//! Three kinds of object must be told apart. An object made with no descriptor given takes the
//! token's default list, which names the group and the system. An object made with a NULL list is
//! open to every account, and one made with an empty list is open to none. Two invocations of one
//! account therefore cannot reach each other's objects when the objects are closed to everyone but
//! the account, the group and the system, whether they took the defaults or got an explicit owner
//! and a list that names the account. An object whose list names Everyone or Authenticated Users,
//! or that has a NULL list, stays open to a sibling invocation for as long as it lives. A deny rule
//! written for the account still refuses what it names, because a deny-only identifier still
//! matches a deny.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{HANDLE, LUID, LocalFree};
use windows_sys::Win32::Security::Authentication::Identity::{
    LSA_STRING, LsaDeregisterLogonProcess, LsaFreeReturnBuffer, LsaLogonUser,
    LsaLookupAuthenticationPackage, LsaNtStatusToWinError, LsaRegisterLogonProcess,
    MSV1_0_S4U_LOGON, SECURITY_LOGON_TYPE,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{
    ACL, AdjustTokenPrivileges, AllocateLocallyUniqueId, CreateRestrictedToken, DuplicateTokenEx,
    GetSecurityDescriptorDacl, GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    QUOTA_LIMITS, SE_PRIVILEGE_ENABLED, SID_AND_ATTRIBUTES, SecurityImpersonation,
    SetTokenInformation, TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS, TOKEN_DEFAULT_DACL,
    TOKEN_GROUPS, TOKEN_OWNER, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_SOURCE, TokenDefaultDacl,
    TokenOwner, TokenPrimary, TokenUser,
};
use windows_sys::Win32::System::SystemServices::{
    SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_MANDATORY, SE_GROUP_OWNER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::ffi::{Handle, Result, Sid, error, last, wide};

/// The logon package that makes a token for a local account without its password.
const PACKAGE: &[u8] = b"MICROSOFT_AUTHENTICATION_PACKAGE_V1_0";
/// The message type of the S4U logon the package takes.
const S4U_LOGON: i32 = 12;

fn lsa_string(text: &[u8]) -> LSA_STRING {
    LSA_STRING {
        Length: text.len() as u16,
        MaximumLength: text.len() as u16 + 1,
        Buffer: text.as_ptr().cast_mut(),
    }
}

/// A fresh group identifier that no other token carries: the authority 9 with four random parts.
#[must_use]
pub fn new_invocation_group() -> Sid {
    let random = uuid::Uuid::new_v4();
    let bytes = random.as_bytes();
    let part = |index: usize| {
        u32::from_le_bytes([
            bytes[index],
            bytes[index + 1],
            bytes[index + 2],
            bytes[index + 3],
        ])
    };
    Sid::parse(&format!(
        "S-1-9-{}-{}-{}-{}",
        part(0),
        part(4),
        part(8),
        part(12)
    ))
    .expect("an identifier of this form is valid")
}

/// Turns a privilege on in this process's own token.
///
/// # Errors
///
/// Returns the platform's error when the process does not hold the privilege.
pub fn enable_privilege(name: &str) -> Result<()> {
    let mut token: HANDLE = null_mut();
    // SAFETY: the current process's token is opened for adjusting; the handle is owned below.
    unsafe {
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &raw mut token,
        ) == 0
        {
            return Err(last("opening this process's token"));
        }
    }
    let token = Handle::new(token, "opening this process's token")?;
    let wide_name = wide(name);
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    // SAFETY: the name is NUL-terminated and the identifier is an out-parameter.
    unsafe {
        if LookupPrivilegeValueW(null(), wide_name.as_ptr(), &raw mut luid) == 0 {
            return Err(last(format!("looking up the privilege {name}")));
        }
    }
    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    // SAFETY: the token is open and the structure is this function's own.
    unsafe {
        if AdjustTokenPrivileges(
            token.raw(),
            0,
            &raw const privileges,
            0,
            null_mut(),
            null_mut(),
        ) == 0
            || windows_sys::Win32::Foundation::GetLastError() != 0
        {
            return Err(last(format!("enabling the privilege {name}")));
        }
    }
    Ok(())
}

/// A primary token from an S4U logon of an account, with one extra group when one is given.
fn s4u(account: &str, group: Option<&Sid>) -> Result<Handle> {
    let process_name = lsa_string(b"KalaReachBoundary");
    let package_name = lsa_string(PACKAGE);
    let origin = lsa_string(b"kr-boundary");
    let mut lsa: HANDLE = null_mut();
    let mut mode = 0_u32;
    // SAFETY: the names outlive the calls; the handle is an out-parameter closed below.
    unsafe {
        let status = LsaRegisterLogonProcess(&raw const process_name, &raw mut lsa, &raw mut mode);
        if status != 0 {
            // text: token_s4u-1
            return Err(error(
                LsaNtStatusToWinError(status),
                "registering with the logon service",
            ));
        }
    }
    let result = s4u_with(lsa, &package_name, &origin, account, group);
    // SAFETY: the handle is the one registered above, closed once.
    unsafe {
        LsaDeregisterLogonProcess(lsa);
    }
    result
}

fn s4u_with(
    lsa: HANDLE,
    package_name: &LSA_STRING,
    origin: &LSA_STRING,
    account: &str,
    group: Option<&Sid>,
) -> Result<Handle> {
    let mut package = 0_u32;
    // SAFETY: the handle is registered; the name outlives the call.
    unsafe {
        let status = LsaLookupAuthenticationPackage(lsa, package_name, &raw mut package);
        if status != 0 {
            // text: token_s4u_with-1
            return Err(error(
                LsaNtStatusToWinError(status),
                "finding the logon package",
            ));
        }
    }
    // The request is the structure followed by the two names it points at, in one allocation that
    // is aligned for the structure.
    let user: Vec<u16> = account.encode_utf16().collect();
    let domain: Vec<u16> = computer_name()?.encode_utf16().collect();
    let header = size_of::<MSV1_0_S4U_LOGON>();
    let total = header + (user.len() + domain.len()) * 2;
    let mut request = vec![0_u64; total.div_ceil(8)];
    let base = request.as_mut_ptr().cast::<u8>();
    // SAFETY: the allocation holds the structure and both names; the pointers stay inside it.
    unsafe {
        let user_at = base.add(header).cast::<u16>();
        std::ptr::copy_nonoverlapping(user.as_ptr(), user_at, user.len());
        let domain_at = user_at.add(user.len());
        std::ptr::copy_nonoverlapping(domain.as_ptr(), domain_at, domain.len());
        let structure = base.cast::<MSV1_0_S4U_LOGON>();
        (*structure).MessageType = S4U_LOGON;
        (*structure).Flags = 0;
        (*structure).UserPrincipalName.Length = (user.len() * 2) as u16;
        (*structure).UserPrincipalName.MaximumLength = (user.len() * 2) as u16;
        (*structure).UserPrincipalName.Buffer = user_at;
        (*structure).DomainName.Length = (domain.len() * 2) as u16;
        (*structure).DomainName.MaximumLength = (domain.len() * 2) as u16;
        (*structure).DomainName.Buffer = domain_at;
    }
    let groups = group.map(|sid| TOKEN_GROUPS {
        GroupCount: 1,
        Groups: [SID_AND_ATTRIBUTES {
            Sid: sid.as_ptr(),
            Attributes: (SE_GROUP_MANDATORY
                | SE_GROUP_ENABLED_BY_DEFAULT
                | SE_GROUP_ENABLED
                | SE_GROUP_OWNER) as u32,
        }],
    });
    let mut source = TOKEN_SOURCE {
        SourceName: [75, 97, 108, 97, 82, 99, 104, 0],
        SourceIdentifier: LUID {
            LowPart: 0,
            HighPart: 0,
        },
    };
    let mut profile: *mut c_void = null_mut();
    let mut profile_length = 0_u32;
    let mut logon = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    let mut token: HANDLE = null_mut();
    let mut quotas = QUOTA_LIMITS {
        PagedPoolLimit: 0,
        NonPagedPoolLimit: 0,
        MinimumWorkingSetSize: 0,
        MaximumWorkingSetSize: 0,
        PagefileLimit: 0,
        TimeLimit: 0,
    };
    let mut substatus = 0_i32;
    // SAFETY: every pointer is this function's own and outlives the call; the token is owned below.
    let status = unsafe {
        AllocateLocallyUniqueId(&raw mut source.SourceIdentifier);
        LsaLogonUser(
            lsa,
            origin,
            SECURITY_LOGON_TYPE(3),
            package,
            request.as_ptr().cast(),
            total as u32,
            groups.as_ref().map_or(null(), |groups| &raw const *groups),
            &raw const source,
            &raw mut profile,
            &raw mut profile_length,
            &raw mut logon,
            &raw mut token,
            &raw mut quotas,
            &raw mut substatus,
        )
    };
    if status != 0 {
        // SAFETY: converts a status the platform returned.
        let code = unsafe { LsaNtStatusToWinError(status) };
        // text: token_s4u_with-2
        return Err(error(
            code,
            format!("logging {account} on without its password (sub-status {substatus})"),
        ));
    }
    // SAFETY: the buffer is the platform's, returned by the call above.
    unsafe {
        if !profile.is_null() {
            LsaFreeReturnBuffer(profile);
        }
    }
    // text: token_s4u_with-3
    let impersonation = Handle::new(token, "the logon's token")?;
    let mut primary: HANDLE = null_mut();
    // SAFETY: the token is open; the duplicate is an out-parameter owned below.
    unsafe {
        if DuplicateTokenEx(
            impersonation.raw(),
            TOKEN_ALL_ACCESS,
            null(),
            SecurityImpersonation,
            TokenPrimary,
            &raw mut primary,
        ) == 0
        {
            // text: token_s4u_with-4
            return Err(last("making the logon's token a primary token"));
        }
    }
    // text: token_s4u_with-5
    Handle::new(primary, "the primary token")
}

pub(super) fn computer_name() -> Result<String> {
    use windows_sys::Win32::System::WindowsProgramming::GetComputerNameW;
    let mut buffer = [0_u16; 64];
    let mut length = buffer.len() as u32;
    // SAFETY: the buffer is the length passed.
    unsafe {
        if GetComputerNameW(buffer.as_mut_ptr(), &raw mut length) == 0 {
            // text: token_computer_name-1
            return Err(last("reading this computer's name"));
        }
    }
    Ok(String::from_utf16_lossy(&buffer[..length as usize]))
}

/// The identifier of the account a token belongs to.
///
/// # Errors
///
/// Returns the platform's error when the token cannot be read.
pub fn user_of(token: &Handle) -> Result<Sid> {
    let mut needed = 0_u32;
    // SAFETY: the first call only asks for the size.
    unsafe {
        GetTokenInformation(token.raw(), TokenUser, null_mut(), 0, &raw mut needed);
    }
    let mut buffer = vec![0_u64; (needed as usize).div_ceil(8).max(1)];
    // SAFETY: the buffer is the size the first call asked for and is aligned.
    unsafe {
        if GetTokenInformation(
            token.raw(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &raw mut needed,
        ) == 0
        {
            // text: token_user_of-1
            return Err(last("reading the token's account"));
        }
        let entry = &*buffer.as_ptr().cast::<SID_AND_ATTRIBUTES>();
        Ok(Sid::from_ptr(entry.Sid))
    }
}

/// The token Git runs under for an account and an invocation: the logon without a password, the
/// account's own identifier deny-only, and the invocation's group as owner and default owner.
///
/// # Errors
///
/// Returns the platform's error when the logon or any change to the token is refused.
pub fn boundary_token(account: &str, group: &Sid) -> Result<Handle> {
    let logon = s4u(account, Some(group))?;
    let user = user_of(&logon)?;
    let deny_only = SID_AND_ATTRIBUTES {
        Sid: user.as_ptr(),
        Attributes: 0,
    };
    let mut restricted: HANDLE = null_mut();
    // SAFETY: the token is open; the list names one identifier; the result is owned below.
    unsafe {
        if CreateRestrictedToken(
            logon.raw(),
            0,
            1,
            &raw const deny_only,
            0,
            null(),
            0,
            null(),
            &raw mut restricted,
        ) == 0
        {
            // text: token_boundary_token-1
            return Err(last("marking the account's own identifier deny-only"));
        }
    }
    // text: token_boundary_token-2
    let token = Handle::new(restricted, "the restricted token")?;
    let owner = TOKEN_OWNER {
        Owner: group.as_ptr(),
    };
    // SAFETY: the token is open and the structure names an identifier that outlives the call.
    unsafe {
        if SetTokenInformation(
            token.raw(),
            TokenOwner,
            (&raw const owner).cast(),
            size_of::<TOKEN_OWNER>() as u32,
        ) == 0
        {
            // text: token_boundary_token-3
            return Err(last("making the invocation's group the token's owner"));
        }
    }
    let list = format!("D:(A;;GA;;;{})(A;;GA;;;SY)", group.to_text()?);
    let text = wide(&list);
    let mut descriptor: *mut c_void = null_mut();
    // SAFETY: the text is NUL-terminated; the descriptor is freed below, after the token has
    // copied the list out of it.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &raw mut descriptor,
            null_mut(),
        ) == 0
        {
            // text: token_boundary_token-4
            return Err(last("reading the default permission list"));
        }
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl: *mut ACL = null_mut();
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        );
        let default = TOKEN_DEFAULT_DACL { DefaultDacl: dacl };
        let set = SetTokenInformation(
            token.raw(),
            TokenDefaultDacl,
            (&raw const default).cast(),
            size_of::<TOKEN_DEFAULT_DACL>() as u32,
        );
        LocalFree(descriptor);
        if set == 0 {
            // text: token_boundary_token-5
            return Err(last("setting the token's default permission list"));
        }
    }
    Ok(token)
}

/// A token for an account with no invocation group and the account's identifier enabled. Nothing
/// runs under it: it stands for what the account holds on its own, which is what a check of the
/// account's reach is made against.
///
/// # Errors
///
/// Returns the platform's error when the logon is refused.
pub fn baseline_token(account: &str) -> Result<Handle> {
    s4u(account, None)
}

/// The account this process runs as.
///
/// # Errors
///
/// Returns the platform's error when the token cannot be read.
pub fn current_user() -> Result<Sid> {
    let mut token: HANDLE = null_mut();
    // SAFETY: the current process's token is opened for reading and owned below.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) == 0 {
            // text: token_current_user-1
            return Err(last("opening this process's token"));
        }
    }
    // text: token_current_user-2
    user_of(&Handle::new(token, "opening this process's token")?)
}

/// Whether this process holds the Administrators group enabled: an administrator, elevated.
///
/// # Errors
///
/// Returns the platform's error when the check cannot be made.
pub fn current_is_administrator() -> Result<bool> {
    use windows_sys::Win32::Security::CheckTokenMembership;
    let administrators = Sid::parse("S-1-5-32-544")?;
    let mut member = 0;
    // SAFETY: a null token means this thread's own, and the identifier is valid.
    unsafe {
        if CheckTokenMembership(null_mut(), administrators.as_ptr(), &raw mut member) == 0 {
            // text: token_current_is_administrator-1
            return Err(last("checking whether this process is an administrator"));
        }
    }
    Ok(member != 0)
}
