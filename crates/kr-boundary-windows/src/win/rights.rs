//! What a token may do to an object, computed from the object's own descriptor and never tried on
//! the object.
//!
//! The broker is the system, so it can open objects that the person it serves cannot, and it must
//! never do for a person what the person could not do. Before it opens, reads or changes an object
//! for an invocation it asks, here, whether the person's token and its own token hold the rights the
//! action needs. The question is asked for each right alone: a union of rights that is denied does
//! not show that every member is denied. The answer comes from the platform's own access check over
//! the descriptor read from the open object (owner, group, permission list and the mandatory
//! label), so deny entries, the owner-rights rule and the generic mapping are the platform's.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::GetSecurityInfo;
use windows_sys::Win32::Security::{
    AccessCheck, AdjustTokenPrivileges, DACL_SECURITY_INFORMATION, DuplicateTokenEx,
    GENERIC_MAPPING, GROUP_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PRIVILEGE_SET, SecurityIdentification, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_DUPLICATE, TOKEN_QUERY, TokenImpersonation,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::frame::Class;
use crate::manifest::Manifest;

use super::ffi::{Handle, Result, error, last};
use super::{proof, token};

/// One right on a file or a directory. The same bit has two names on the two kinds of object (a
/// directory's `FILE_ADD_FILE` is a file's `FILE_WRITE_DATA`), and one value stands for both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Right {
    /// Read a file's data, or list a directory.
    ReadData,
    /// Write a file's data, or add a file to a directory.
    WriteData,
    /// Append to a file, or add a subdirectory to a directory.
    AppendData,
    /// Write the extended attributes.
    WriteEa,
    /// Delete a directory's children whatever their own lists say.
    DeleteChild,
    /// Write the attributes.
    WriteAttributes,
    /// Delete the object.
    Delete,
    /// Read the descriptor.
    ReadControl,
    /// Change the permission list.
    WriteDac,
    /// Change the owner.
    WriteOwner,
}

impl Right {
    /// The right's access mask.
    #[must_use]
    pub const fn mask(self) -> u32 {
        match self {
            Right::ReadData => 0x0001,
            Right::WriteData => 0x0002,
            Right::AppendData => 0x0004,
            Right::WriteEa => 0x0010,
            Right::DeleteChild => 0x0040,
            Right::WriteAttributes => 0x0100,
            Right::Delete => 0x0001_0000,
            Right::ReadControl => 0x0002_0000,
            Right::WriteDac => 0x0004_0000,
            Right::WriteOwner => 0x0008_0000,
        }
    }
}

/// The kind of an object a list of rights is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    /// A directory.
    Directory,
    /// A file.
    File,
}

/// The rights that let an account write to a directory, change it or remove it, each of which is
/// asked alone for every directory of a grant's walk.
pub const DIRECTORY_WRITE_RIGHTS: [Right; 8] = [
    Right::WriteData,
    Right::AppendData,
    Right::WriteEa,
    Right::WriteAttributes,
    Right::DeleteChild,
    Right::Delete,
    Right::WriteDac,
    Right::WriteOwner,
];

/// The rights that let an account write to a file, change it or remove it, each of which is asked
/// alone for every file of a grant's walk.
pub const FILE_WRITE_RIGHTS: [Right; 7] = [
    Right::WriteData,
    Right::AppendData,
    Right::WriteEa,
    Right::WriteAttributes,
    Right::Delete,
    Right::WriteDac,
    Right::WriteOwner,
];

/// The right that the report of a tree asks for besides the write rights: whether the account can
/// read, or list, the object.
pub const REPORT_RIGHT: Right = Right::ReadData;

/// What the person's own token must be allowed to do to an object before the broker grants it,
/// changes it or removes it: read its descriptor, change its list, delete it, and list or read it.
pub const PERSON_RIGHTS: [Right; 4] = [
    Right::ReadControl,
    Right::WriteDac,
    Right::Delete,
    Right::ReadData,
];

/// What the broker's own token, with its privileges off, must be allowed to do to an object that a
/// grant will write: read its descriptor, change its list, and list or read it.
pub const SYSTEM_RIGHTS: [Right; 3] = [Right::ReadControl, Right::WriteDac, Right::ReadData];

/// The rights that let an account write to an object of this kind, change it or remove it.
#[must_use]
pub const fn write_rights(kind: ObjectKind) -> &'static [Right] {
    match kind {
        ObjectKind::Directory => &DIRECTORY_WRITE_RIGHTS,
        ObjectKind::File => &FILE_WRITE_RIGHTS,
    }
}

/// An impersonation token at identification level: enough for an access check and for reading
/// what the token holds, and unable to act as the account on any object.
#[derive(Debug)]
pub struct ImpersonationToken(Handle);

impl ImpersonationToken {
    /// A copy of a token that has the right to be duplicated, as an impersonation token at
    /// identification level that can be queried and have its privileges changed.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the token cannot be duplicated.
    pub fn duplicate_of(source: &Handle) -> Result<ImpersonationToken> {
        let mut copy: HANDLE = null_mut();
        // SAFETY: the source is an open token with the right to be duplicated; the out-parameter is
        // local and owned below.
        let made = unsafe {
            DuplicateTokenEx(
                source.raw(),
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                null(),
                SecurityIdentification,
                TokenImpersonation,
                &raw mut copy,
            )
        };
        if made == 0 {
            // text: rights_duplicate-1
            return Err(last("copying a token for an access check"));
        }
        // text: rights_duplicate-2
        Ok(ImpersonationToken(Handle::new(
            copy,
            "copying a token for an access check",
        )?))
    }

    /// The impersonation token that a pipe's caller carries, as the handle that the pipe's server
    /// opened with the right to query it. The token is the system's own copy of the caller's
    /// effective token at identification level or above, so no copy is made of it here.
    #[must_use]
    pub fn of_caller(handle: Handle) -> ImpersonationToken {
        ImpersonationToken(handle)
    }

    /// The account the token is of.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the token cannot be read.
    pub fn user(&self) -> Result<super::ffi::Sid> {
        token::user_of(&self.0)
    }

    /// The handle, still owned by this value.
    #[must_use]
    pub fn raw(&self) -> HANDLE {
        self.0.raw()
    }

    /// The same token with every privilege disabled, so that an access check over it asks what the
    /// account's own entries allow and no privilege adds to it.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the privileges cannot be disabled.
    fn without_privileges(self) -> Result<ImpersonationToken> {
        // SAFETY: the token is open with the right to change its privileges; no list is given, so
        // the call disables every one.
        let changed =
            unsafe { AdjustTokenPrivileges(self.0.raw(), 1, null(), 0, null_mut(), null_mut()) };
        if changed == 0 {
            // text: rights_without_privileges-1
            return Err(last("turning a token's privileges off"));
        }
        Ok(self)
    }
}

/// An object's descriptor as an access check reads it: owner, group, permission list and mandatory
/// label, read from the open object.
pub struct Sd(*mut c_void);

// SAFETY: the block is the platform's own, owned by this value alone and never changed.
unsafe impl Send for Sd {}
// SAFETY: the block is read-only after it is made.
unsafe impl Sync for Sd {}

const SE_FILE_OBJECT: i32 = 1;

impl Sd {
    /// Reads the descriptor of an open file or directory. The handle needs the right to read the
    /// descriptor.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the descriptor cannot be read.
    pub fn of_handle(object: &Handle) -> Result<Sd> {
        let mut descriptor: *mut c_void = null_mut();
        // SAFETY: the handle is open; the out-parameter is local and its block is freed when the
        // value is dropped.
        let code = unsafe {
            GetSecurityInfo(
                object.raw(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | LABEL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &raw mut descriptor,
            )
        };
        if code != 0 {
            // text: rights_sd-1
            return Err(error(
                code,
                "reading an object's descriptor for an access check",
            ));
        }
        Ok(Sd(descriptor))
    }
}

impl Drop for Sd {
    fn drop(&mut self) {
        // SAFETY: the block came from the platform's allocator and is freed once.
        unsafe {
            LocalFree(self.0);
        }
    }
}

impl std::fmt::Debug for Sd {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Sd(..)")
    }
}

/// Asks the platform whether the token is granted every bit of `mask` by the descriptor, with the
/// file generic mapping.
///
/// # Errors
///
/// Returns the platform's error when the check cannot be made.
pub fn granted(token: &ImpersonationToken, descriptor: &Sd, mask: u32) -> Result<bool> {
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };
    // SAFETY: a zeroed set is a valid empty one; the check writes at most this much.
    let mut privileges: PRIVILEGE_SET = unsafe { std::mem::zeroed() };
    let mut length = size_of::<PRIVILEGE_SET>() as u32;
    let mut granted_mask = 0_u32;
    let mut status = 0_i32;
    // SAFETY: the descriptor and the token are open and live for the call; the out-parameters are
    // local.
    let checked = unsafe {
        AccessCheck(
            descriptor.0,
            token.raw(),
            mask,
            &raw const mapping,
            &raw mut privileges,
            &raw mut length,
            &raw mut granted_mask,
            &raw mut status,
        )
    };
    if checked == 0 {
        // text: rights_granted-1
        return Err(last("checking a token's access to an object"));
    }
    Ok(status != 0)
}

/// Whether the token holds one right on the descriptor. A check that cannot be made is a refusal:
/// the broker does nothing for a client whose rights it could not compute.
#[must_use]
pub fn may(token: &ImpersonationToken, descriptor: &Sd, right: Right) -> bool {
    matches!(granted(token, descriptor, right.mask()), Ok(true))
}

/// The probe token of a class: a token that stands for a sibling invocation of the class's account.
/// It is made by the same builder as the invocation's own token, with a fresh random group that no
/// object names and the account's own identifier deny-only, and it is the baseline the grant's
/// reach is computed against.
///
/// # Errors
///
/// Returns the reason when the manifest records no account for the class, no account has the
/// recorded identifier, or the logon or the copy is refused.
pub fn probe_token(manifest: &Manifest, class: Class) -> Result<ImpersonationToken> {
    // text: rights_probe_token-1
    let (account, _) = proof::account_of(manifest, class).map_err(|reason| error(0, reason))?;
    let primary = token::boundary_token(&account, &token::new_invocation_group())?;
    ImpersonationToken::duplicate_of(&primary)
}

/// The broker's own token with its privileges off, copied once for every check of the broker's own
/// rights. A token that cannot be made is never used: every question about the broker's rights is
/// then answered no.
fn system_token() -> Option<&'static ImpersonationToken> {
    static OWN: OnceLock<Option<ImpersonationToken>> = OnceLock::new();
    OWN.get_or_init(|| {
        let mut own: HANDLE = null_mut();
        // SAFETY: this process's own token is opened with the right to be duplicated; the result is
        // owned below.
        let opened = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_QUERY,
                &raw mut own,
            )
        };
        if opened == 0 {
            return None;
        }
        // text: rights_system_token-1
        let Ok(own) = Handle::new(own, "the broker's own token") else {
            return None;
        };
        #[expect(
            clippy::disallowed_methods,
            reason = "a token that cannot be made is never used, and every question about the broker's own rights is then answered no: the failure is not a statement about the machine"
        )]
        let copy = ImpersonationToken::duplicate_of(&own)
            .and_then(ImpersonationToken::without_privileges)
            .ok();
        copy
    })
    .as_ref()
}

/// Whether the broker's own token, with every privilege off, holds one right on the descriptor.
#[must_use]
pub fn system_may(descriptor: &Sd, right: Right) -> bool {
    system_token().is_some_and(|own| may(own, descriptor, right))
}
