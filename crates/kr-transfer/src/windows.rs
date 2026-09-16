//! The Windows access rules of the transfer service's own directories.
//!
//! Windows has no mode bits, so the equivalent of `0700` is the object's access-control list. Two
//! things have to happen to it. The staging directory is created with a list of this host's own,
//! protected so nothing is inherited into it from the user profile above. Every later open reads
//! the list back from the handle it just opened and refuses one that has been widened, because a
//! directory that already existed is a directory this host did not create.
//!
//! This is the only module in the crate that leaves safe Rust. The list comes from `advapi32` and
//! is applied by `kernel32`, and reading one back is four more calls into the same library.

use std::os::windows::io::{AsRawHandle as _, BorrowedHandle};
use std::path::Path;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetSecurityDescriptorControl, GetTokenInformation, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, TOKEN_INFORMATION_CLASS,
    TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER, TokenOwner, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::error::{Result, TransferError};

/// The object's owner only, with inheritance blocked and children covered.
///
/// `D:P` makes the list protected, so no inherited entry from the user profile widens it.
/// `(A;;GA;;;OW)` grants everything to OWNER RIGHTS, which resolves to whoever owns the object:
/// the process that created the directory, which is this user. `(A;OICIIO;GA;;;CO)` is
/// inherit-only and names CREATOR OWNER, the placeholder that becomes the owner's own entry on
/// each file and directory created beneath, so a payload file is owner-only without a second call
/// per file.
pub(crate) const OWNER_ONLY_DESCRIPTOR: &str = "D:P(A;;GA;;;OW)(A;OICIIO;GA;;;CO)";

/// The accounts an entry in one of these directories may name.
///
/// `S-1-5-18` is the local system and `S-1-5-32-544` the local administrators group: both already
/// hold the machine, and nothing this host does can keep them out. `S-1-3-0` is CREATOR OWNER and
/// `S-1-3-4` is OWNER RIGHTS, the two placeholders that resolve to the object's owner, which is
/// this user. The owner itself is trusted separately. Every other account is a refusal.
const TRUSTED_ACCOUNTS: &[&str] = &["S-1-5-18", "S-1-5-32-544", "S-1-3-0", "S-1-3-4"];

/// An entry that grants access.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
/// An entry that denies access, which cannot widen anything.
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
/// An entry that records an access attempt.
const SYSTEM_AUDIT_ACE_TYPE: u8 = 2;
/// An entry that raises an alarm on an access attempt.
const SYSTEM_ALARM_ACE_TYPE: u8 = 3;

/// Why an access-control list was not accepted.
#[derive(Debug)]
pub(crate) enum Refusal {
    /// The list could not be read, which is a storage failure rather than a policy one.
    Unreadable(String),
    /// The list was read and does not meet the policy.
    Policy(String),
}

/// Creates a directory whose access-control list names its owner and nothing else.
///
/// An existing directory is left alone: the caller checks the list it already carries.
///
/// # Errors
///
/// Returns [`TransferError::StagingUnavailable`] when the list cannot be built or the directory
/// cannot be created.
pub(crate) fn create_owner_only_directory(path: &Path) -> Result<()> {
    create_directory_with_list(path, OWNER_ONLY_DESCRIPTOR)
}

/// Creates a directory with one explicit access-control list, written as SDDL.
///
/// # Errors
///
/// Returns [`TransferError::StagingUnavailable`] when the list cannot be built or the directory
/// cannot be created.
pub(crate) fn create_directory_with_list(path: &Path, descriptor: &str) -> Result<()> {
    let wide_path = wide(path.as_os_str());
    let wide_descriptor = wide_str(descriptor);
    let mut built: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: both pointers are null-terminated wide buffers this function owns for the whole
    // call, `built` is a live out parameter, and the size parameter is optional.
    let parsed = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_descriptor.as_ptr(),
            SDDL_REVISION_1,
            &raw mut built,
            std::ptr::null_mut(),
        )
    };
    if parsed == 0 {
        return Err(TransferError::staging(format!(
            "the access-control list of {} could not be built: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: built,
        bInheritHandle: 0,
    };
    // SAFETY: `wide_path` is a null-terminated wide buffer this function owns, and `attributes`
    // points at a descriptor that stays live until it is freed below.
    let created = unsafe { CreateDirectoryW(wide_path.as_ptr(), &raw const attributes) };
    let failure = (created == 0).then(std::io::Error::last_os_error);
    // SAFETY: `built` was allocated by the conversion above and is freed exactly once.
    unsafe {
        LocalFree(built.cast());
    }
    match failure {
        None => Ok(()),
        // An existing staging directory is the ordinary case on every start after the first. Its
        // list is checked by the caller rather than replaced here.
        Some(error) if error.raw_os_error() == Some(ERROR_ALREADY_EXISTS.cast_signed()) => Ok(()),
        Some(error) => Err(TransferError::staging(format!(
            "the directory {} could not be created: {error}",
            path.display()
        ))),
    }
}

/// Checks the access-control list of an opened directory.
///
/// `what` names the directory in the refusal. `require_protected` additionally demands a protected
/// list, which is the check for a boundary directory: nothing above it can widen it later. A
/// directory beneath one of those inherits the owner entry from it by design, so its list is
/// checked for the accounts it names and not for protection.
///
/// # Errors
///
/// Returns [`Refusal::Unreadable`] when the list cannot be read and [`Refusal::Policy`] when it
/// names an account this host does not trust.
pub(crate) fn check_access_list(
    handle: BorrowedHandle<'_>,
    what: &str,
    require_protected: bool,
) -> std::result::Result<(), Refusal> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut list: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the handle is borrowed for the whole call and was opened for reading, which on
    // Windows carries the right to read the list. The three out parameters are live, and the two
    // this host does not ask for are null, which the function documents as "do not return this".
    let status = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            &raw mut list,
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(Refusal::Unreadable(format!(
            "the access-control list of {what} could not be read: {}",
            std::io::Error::from_raw_os_error(status.cast_signed())
        )));
    }
    let outcome = evaluate(owner, list, descriptor, what, require_protected);
    // SAFETY: the descriptor came from the call above and is freed exactly once. `owner` and
    // `list` point into it and are not used after this.
    unsafe {
        LocalFree(descriptor.cast());
    }
    outcome
}

/// Applies the policy to a list that has been read.
fn evaluate(
    owner: PSID,
    list: *mut ACL,
    descriptor: PSECURITY_DESCRIPTOR,
    what: &str,
    require_protected: bool,
) -> std::result::Result<(), Refusal> {
    if owner.is_null() {
        return Err(Refusal::Policy(format!("{what} records no owner")));
    }
    if require_protected {
        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        // SAFETY: the descriptor is the one just read, and both out parameters are live.
        let read = unsafe {
            GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision)
        };
        if read == 0 {
            return Err(Refusal::Unreadable(format!(
                "the access-control list of {what} could not be inspected: {}",
                std::io::Error::last_os_error()
            )));
        }
        if control & SE_DACL_PROTECTED == 0 {
            return Err(Refusal::Policy(format!(
                "{what} inherits its access-control list from the directory above it, which can \
                 widen it at any time"
            )));
        }
    }
    // A missing list is not an empty one: an object with no list at all grants every account full
    // access, which is the widest answer Windows has.
    if list.is_null() {
        return Err(Refusal::Policy(format!(
            "{what} carries no access-control list, which grants every account full access"
        )));
    }
    let accounts = TokenAccounts::read()?;
    let mut trusted = Vec::with_capacity(TRUSTED_ACCOUNTS.len());
    for text in TRUSTED_ACCOUNTS {
        trusted.push(OwnedSid::parse(text)?);
    }
    // Two different rules, so they are two different predicates. The owner has to be an account
    // this process could have created the directory as: its own user, or the owner new objects of
    // this process receive. The machine's own accounts are trusted to *hold* the directory, which
    // nothing can prevent, but a directory owned by one of them is not one this host created.
    let is_owner = |sid: PSID| equal(sid, accounts.user()) || equal(sid, accounts.owner());
    let permitted =
        |sid: PSID| is_owner(sid) || trusted.iter().any(|account| equal(sid, account.as_psid()));
    if !is_owner(owner) {
        return Err(Refusal::Policy(format!(
            "{what} belongs to {}, and this host runs as another account",
            describe(owner)
        )));
    }
    // SAFETY: `list` points at the list inside the descriptor read above.
    let count = unsafe { (*list).AceCount };
    for index in 0..u32::from(count) {
        let mut entry: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: `list` is live and `index` is below the entry count it reported.
        let got = unsafe { GetAce(list, index, &raw mut entry) };
        if got == 0 || entry.is_null() {
            return Err(Refusal::Unreadable(format!(
                "entry {index} of the access-control list of {what} could not be read: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: every entry in a list begins with its header.
        let header = unsafe { std::ptr::read(entry.cast::<ACE_HEADER>()) };
        match header.AceType {
            // A denial, an audit and an alarm grant nothing.
            ACCESS_DENIED_ACE_TYPE | SYSTEM_AUDIT_ACE_TYPE | SYSTEM_ALARM_ACE_TYPE => continue,
            ACCESS_ALLOWED_ACE_TYPE => {}
            // A callback or conditional entry can grant access on terms this host does not read.
            // Refusing it is the answer that cannot be wrong.
            other => {
                return Err(Refusal::Policy(format!(
                    "the access-control list of {what} carries a type-{other} entry, which this \
                     host does not evaluate"
                )));
            }
        }
        // SAFETY: the identifier of an allowed entry begins at the offset of `SidStart` within it,
        // inside the list this pointer came from.
        let sid: PSID = unsafe {
            entry
                .cast::<u8>()
                .add(std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart))
        }
        .cast();
        if !permitted(sid) {
            return Err(Refusal::Policy(format!(
                "the access-control list of {what} grants access to {}, which is neither its \
                 owner nor an account that already holds this machine",
                describe(sid)
            )));
        }
    }
    Ok(())
}

/// A security identifier this module allocated.
struct OwnedSid(PSID);

impl OwnedSid {
    /// Resolves one identifier written in the numeric form.
    fn parse(text: &str) -> std::result::Result<Self, Refusal> {
        let wide = wide_str(text);
        let mut sid: PSID = std::ptr::null_mut();
        // SAFETY: `wide` is a null-terminated wide buffer this function owns for the call, and
        // `sid` is a live out parameter.
        let parsed = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &raw mut sid) };
        if parsed == 0 || sid.is_null() {
            return Err(Refusal::Unreadable(format!(
                "the account {text} could not be resolved: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self(sid))
    }

    const fn as_psid(&self) -> PSID {
        self.0
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        // SAFETY: the pointer came from the resolution above and is freed exactly once.
        unsafe {
            LocalFree(self.0.cast());
        }
    }
}

/// The two accounts this process could have created a directory as.
struct TokenAccounts {
    /// The buffer holding this process's user identifier.
    user: Vec<u64>,
    /// The buffer holding the identifier new objects of this process are owned by.
    owner: Vec<u64>,
}

impl TokenAccounts {
    /// Reads both from this process's own token.
    fn read() -> std::result::Result<Self, Refusal> {
        let token = TokenHandle::open()?;
        Ok(Self {
            user: token.information(TokenUser, std::mem::size_of::<TOKEN_USER>())?,
            owner: token.information(TokenOwner, std::mem::size_of::<TOKEN_OWNER>())?,
        })
    }

    /// Returns this process's user, which points into the buffer this holds.
    fn user(&self) -> PSID {
        // SAFETY: the buffer holds a `TOKEN_USER` the kernel wrote, and a `Vec<u64>` is aligned
        // for the pointer inside it.
        unsafe { std::ptr::read(self.user.as_ptr().cast::<TOKEN_USER>()) }
            .User
            .Sid
    }

    /// Returns the owner new objects of this process receive.
    fn owner(&self) -> PSID {
        // SAFETY: the buffer holds a `TOKEN_OWNER` the kernel wrote, aligned as above.
        unsafe { std::ptr::read(self.owner.as_ptr().cast::<TOKEN_OWNER>()) }.Owner
    }
}

/// This process's own token, closed when it goes out of scope.
struct TokenHandle(HANDLE);

impl TokenHandle {
    /// Opens the token for reading.
    fn open() -> std::result::Result<Self, Refusal> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: the process handle is a pseudo-handle that needs no release, and `token` is a
        // live out parameter.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) };
        if opened == 0 || token.is_null() {
            return Err(Refusal::Unreadable(format!(
                "this process's own token could not be read: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self(token))
    }

    /// Reads one class of token information into an aligned buffer.
    fn information(
        &self,
        class: TOKEN_INFORMATION_CLASS,
        least: usize,
    ) -> std::result::Result<Vec<u64>, Refusal> {
        let mut needed: u32 = 0;
        // SAFETY: a null buffer with a zero length asks for the size, which is what this call is
        // for; `needed` is a live out parameter and the failure it returns is expected.
        let _ =
            unsafe { GetTokenInformation(self.0, class, std::ptr::null_mut(), 0, &raw mut needed) };
        let bytes = usize::try_from(needed).unwrap_or(0).max(least);
        let mut buffer = vec![0_u64; bytes.div_ceil(8).max(1)];
        let length = u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX);
        // SAFETY: the buffer holds `length` bytes, which is at least the size the call above
        // reported, and `needed` is a live out parameter.
        let read = unsafe {
            GetTokenInformation(
                self.0,
                class,
                buffer.as_mut_ptr().cast(),
                length,
                &raw mut needed,
            )
        };
        if read == 0 {
            return Err(Refusal::Unreadable(format!(
                "this process's own accounts could not be read: {}",
                std::io::Error::last_os_error()
            )));
        }
        if usize::try_from(needed).unwrap_or(0) < least {
            return Err(Refusal::Unreadable(format!(
                "this process's own token returned {needed} bytes where {least} were needed"
            )));
        }
        Ok(buffer)
    }
}

impl Drop for TokenHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from the open above and is closed exactly once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Compares two identifiers, treating a missing one as no match.
fn equal(left: PSID, right: PSID) -> bool {
    if left.is_null() || right.is_null() {
        return false;
    }
    // SAFETY: both pointers name live identifiers inside buffers this call does not outlive.
    unsafe { EqualSid(left, right) != 0 }
}

/// Names one identifier for a refusal.
fn describe(sid: PSID) -> String {
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` is live and `text` is a live out parameter.
    let converted = unsafe { ConvertSidToStringSidW(sid, &raw mut text) };
    if converted == 0 || text.is_null() {
        return "an account that could not be named".to_owned();
    }
    let mut length = 0_usize;
    // SAFETY: the buffer the conversion allocated is null-terminated, so the scan stops inside it.
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: the buffer holds `length` code units before its terminator.
    let described = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
    // SAFETY: the buffer came from the conversion above and is freed exactly once.
    unsafe {
        LocalFree(text.cast());
    }
    described
}

/// Encodes a path for the wide form of a Windows call.
fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt as _;

    text.encode_wide().chain(std::iter::once(0)).collect()
}

/// Encodes a string for the wide form of a Windows call.
fn wide_str(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use std::os::windows::io::AsHandle as _;

    use super::{
        Refusal, check_access_list, create_directory_with_list, create_owner_only_directory,
    };

    /// Opens a directory the way the authority does and checks its list.
    fn check(path: &std::path::Path, require_protected: bool) -> Result<(), Refusal> {
        let directory =
            cap_std::fs::Dir::open_ambient_dir(path, cap_std::ambient_authority()).unwrap();
        check_access_list(
            directory.as_handle(),
            &path.display().to_string(),
            require_protected,
        )
    }

    #[test]
    fn an_owner_only_directory_is_accepted_as_a_boundary() {
        let parent = tempfile::tempdir().unwrap();
        let path = parent.path().join("staging");
        create_owner_only_directory(&path).unwrap();

        check(&path, true).unwrap();
    }

    #[test]
    fn a_directory_that_grants_another_account_is_refused() {
        let parent = tempfile::tempdir().unwrap();
        let path = parent.path().join("staging");
        // `WD` is the Everyone group, and `GA` is full control.
        create_directory_with_list(&path, "D:P(A;;GA;;;OW)(A;;GA;;;WD)").unwrap();

        let refusal = check(&path, true).unwrap_err();

        assert!(
            matches!(refusal, Refusal::Policy(detail) if detail.contains("grants access to")),
            "a list naming Everyone is a policy refusal"
        );
    }

    #[test]
    fn a_directory_that_inherits_its_list_is_refused_as_a_boundary() {
        let parent = tempfile::tempdir().unwrap();
        let path = parent.path().join("inheriting");
        std::fs::create_dir(&path).unwrap();

        let refusal = check(&path, true).unwrap_err();

        assert!(
            matches!(refusal, Refusal::Policy(detail) if detail.contains("inherits")),
            "a directory under the user profile inherits its list and is not a boundary"
        );
        // The same directory is acceptable beneath a boundary: the entries it inherits name this
        // user, the local system and the administrators group.
        check(&path, false).unwrap();
    }
}
