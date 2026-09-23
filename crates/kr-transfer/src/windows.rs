//! The questions about a Windows file that have no answer in safe Rust.
//!
//! Every file on this platform carries a discretionary access-control list, and the list is
//! reachable only through `advapi32`, which has no safe binding. Each call here takes a **handle**
//! this host already holds: `GetSecurityInfo` and `SetSecurityInfo` with `SE_FILE_OBJECT`, never
//! the named forms. A name asked twice can be two different files, so the list is asked of the
//! object rather than of the name, and the write goes to the same handle the read came from.
//!
//! What a reading records is the owner, whether the list is protected against inheritance, and
//! each entry's kind, inheritance flags, access mask and account, with the entries the object
//! carries itself kept apart from the entries it inherits from the directory above it. Neither
//! part is ever dropped: an object with no entry of its own still reports what it inherits. That
//! division is the one Windows fact with no counterpart on the other platforms, and it decides
//! what a replacement has to write: the entries an object carries itself, because a copy created
//! in the same directory receives the inherited ones by itself.
//!
//! An entry whose terms this host does not read refuses the whole reading, wherever it sits. A
//! callback, a conditional or an object entry decides access on terms that are not its kind, its
//! flags, its mask and its account, and a reading that recorded one without them would compare
//! equal to a reading of a different list.
//!
//! A recursive removal comes here for one more thing: a file in a tree goes through its own
//! handle, reopened for deletion and marked, rather than by its name. Reopening a handle and
//! marking an object for deletion are two calls into `kernel32`.

use std::os::windows::io::{AsRawHandle as _, BorrowedHandle};

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, AddAccessAllowedAceEx, AddAccessDeniedAceEx,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetLengthSid, GetSecurityDescriptorControl,
    INHERITED_ACE, InitializeAcl, IsValidSid, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PRESENT,
    SE_DACL_PROTECTED, UNPROTECTED_DACL_SECURITY_INFORMATION,
};

/// An entry that grants access.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
/// An entry that denies access.
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

/// A security identifier, held as the bytes the platform wrote.
///
/// Stored word-aligned, because an identifier is a structure of 32-bit words and the calls that
/// read one expect it aligned for them. Compared by identity and never by its text: the text form
/// exists for a refusal a person reads, and two spellings of one account are still one account.
#[derive(Clone)]
pub struct Sid {
    storage: Vec<u32>,
    len: usize,
}

impl Sid {
    /// Copies an identifier out of a buffer this host does not own.
    fn copy_from(sid: PSID) -> Option<Self> {
        if sid.is_null() {
            return None;
        }
        // SAFETY: the pointer is not null and names memory inside a descriptor the caller holds
        // for the whole call.
        if unsafe { IsValidSid(sid) } == 0 {
            return None;
        }
        // SAFETY: the identifier was just checked valid, so it has a length.
        let len = unsafe { GetLengthSid(sid) } as usize;
        if len == 0 {
            return None;
        }
        let mut storage = vec![0_u32; len.div_ceil(4)];
        // SAFETY: the source holds `len` bytes, the destination holds at least that many, and the
        // two buffers do not overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(sid.cast::<u8>(), storage.as_mut_ptr().cast::<u8>(), len);
        }
        Some(Self { storage, len })
    }

    /// Returns a pointer to this identifier, for the length of the borrow.
    fn as_psid(&self) -> PSID {
        self.storage.as_ptr().cast::<core::ffi::c_void>().cast_mut()
    }

    /// Returns the identifier's own bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: the storage holds at least `len` bytes, written by the copy above.
        unsafe { std::slice::from_raw_parts(self.storage.as_ptr().cast::<u8>(), self.len) }
    }
}

impl PartialEq for Sid {
    fn eq(&self, other: &Self) -> bool {
        // SAFETY: both pointers name valid identifiers this call does not outlive.
        unsafe { EqualSid(self.as_psid(), other.as_psid()) != 0 }
    }
}

impl Eq for Sid {}

impl core::fmt::Debug for Sid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", describe(self.as_psid()))
    }
}

impl core::fmt::Display for Sid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", describe(self.as_psid()))
    }
}

/// One entry of a discretionary access-control list, read out of the descriptor it lived in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AclEntry {
    /// The kind of entry: allowing, denying, or something this host does not rewrite.
    kind: u8,
    /// The inheritance flags, with the bit that marks an inherited entry taken off: whether an
    /// entry is inherited is recorded by which list it is in rather than inside the entry.
    flags: u8,
    /// The rights the entry decides.
    mask: u32,
    /// The account it decides them for.
    sid: Sid,
}

impl AclEntry {
    /// Builds one entry, for a caller that constructs a list rather than reading one.
    #[must_use]
    pub fn new(kind: u8, flags: u8, mask: u32, sid: Sid) -> Self {
        Self {
            kind,
            flags: flags & !inherited_flag(),
            mask,
            sid,
        }
    }

    /// Returns the kind of entry.
    #[must_use]
    pub const fn kind(&self) -> u8 {
        self.kind
    }

    /// Returns the inheritance flags.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Returns the rights the entry decides.
    #[must_use]
    pub const fn mask(&self) -> u32 {
        self.mask
    }

    /// Returns the account the entry decides them for.
    #[must_use]
    pub const fn account(&self) -> &Sid {
        &self.sid
    }
}

/// The inheritance bit that says an entry came from the directory above.
const fn inherited_flag() -> u8 {
    // The constant is declared as the wider flag type; an entry's header holds one byte of it.
    INHERITED_ACE as u8
}

/// A discretionary access-control list as this host reads and writes it.
///
/// A reading holds everything the descriptor said: whether the list is protected against
/// inheritance, the entries the object carries itself in the order the platform holds them, and
/// the entries it inherits from the directory above it in theirs.
///
/// Two readings are equal when the protection an object carries itself is the same: the protection
/// flag, and the entries of its own compared one by one in order. A self-relative descriptor has
/// no canonical byte layout, so two lists that say the same thing can differ byte for byte; what
/// this compares is what they say, and each entry says its kind, its inheritance flags, its access
/// mask and its account. Order is part of it, because the platform stops at the first entry that
/// decides the access being asked for: a denial before an allowance is not the same list as a
/// denial after it.
///
/// The entries an object inherits are deliberately outside that comparison. They belong to the
/// directory above it, which hands the same ones to every object created there, so a copy staged
/// beside a destination receives the directory's current entries whichever ones the destination
/// happens to hold. They are read and reported so that a caller can see them; what a replacement
/// carries and verifies is the object's own.
#[derive(Clone, Debug)]
pub struct WindowsAcl {
    /// Whether the list is protected against inheritance from the directory above it.
    protected: bool,
    /// The entries the object carries itself.
    explicit: Vec<AclEntry>,
    /// The entries it inherits from the directory above it.
    inherited: Vec<AclEntry>,
}

impl WindowsAcl {
    /// Builds a list, for a caller that constructs one rather than reading one.
    #[must_use]
    pub fn new(protected: bool, explicit: Vec<AclEntry>, inherited: Vec<AclEntry>) -> Self {
        Self {
            protected,
            explicit,
            inherited,
        }
    }

    /// Returns true when the list is protected against inheritance.
    #[must_use]
    pub const fn is_protected(&self) -> bool {
        self.protected
    }

    /// Returns the entries the object carries itself.
    #[must_use]
    pub fn explicit(&self) -> &[AclEntry] {
        &self.explicit
    }

    /// Returns the entries the object inherits from the directory above it.
    #[must_use]
    pub fn inherited(&self) -> &[AclEntry] {
        &self.inherited
    }

    /// Returns true when the object carries protection of its own.
    ///
    /// A list every file has is not protection a replacement has to carry: an inherited-only list
    /// is exactly what a copy created in the same directory receives by itself. What the object
    /// carries itself is a protected list, which keeps the directory above from widening it, or at
    /// least one entry of its own.
    #[must_use]
    pub fn has_entries(&self) -> bool {
        self.protected || !self.explicit.is_empty()
    }
}

impl PartialEq for WindowsAcl {
    fn eq(&self, other: &Self) -> bool {
        self.protected == other.protected && self.explicit == other.explicit
    }
}

impl Eq for WindowsAcl {}

/// Everything one read of a handle's security says.
pub struct Security {
    /// The account the object belongs to.
    pub owner: Sid,
    /// The whole discretionary list, the object's own entries and its inherited ones alike.
    pub list: WindowsAcl,
}

/// Reads the owner and the discretionary list of an opened object.
///
/// The audit list is deliberately not asked for: reading one needs `SeSecurityPrivilege`, which
/// this service neither holds nor acquires, and a request for it would fail the whole read.
///
/// # Errors
///
/// Returns an error when the platform refuses the read, when the object reports no list at all
/// (which grants every account full access, and is not something this host can reproduce), or when
/// an entry cannot be read.
pub fn read_security(handle: BorrowedHandle<'_>) -> std::io::Result<Security> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut list: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the handle is borrowed for the whole call and was opened with the right to read the
    // list. The three out parameters are live, and the two this host does not ask for are null,
    // which the call documents as "do not return this".
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
        return Err(std::io::Error::from_raw_os_error(status.cast_signed()));
    }
    let read = interpret(owner, list, descriptor);
    // SAFETY: the descriptor came from the call above and is freed exactly once. `owner` and
    // `list` point into it and are not read after this.
    unsafe {
        LocalFree(descriptor.cast());
    }
    read
}

/// Turns one read descriptor into the reading this host keeps.
fn interpret(
    owner: PSID,
    list: *mut ACL,
    descriptor: PSECURITY_DESCRIPTOR,
) -> std::io::Result<Security> {
    let Some(owner) = Sid::copy_from(owner) else {
        return Err(std::io::Error::other(
            "the object records no owner this host can read",
        ));
    };
    let mut control: u16 = 0;
    let mut revision: u32 = 0;
    // SAFETY: the descriptor is the one just read and both out parameters are live.
    let read =
        unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) };
    if read == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // A missing list is not an empty one: an object with no list at all grants every account full
    // access, and a replacement cannot reproduce that by writing entries. The path is left alone.
    if control & SE_DACL_PRESENT == 0 || list.is_null() {
        return Err(std::io::Error::other(
            "the object carries no access-control list, which grants every account full access",
        ));
    }
    let protected = control & SE_DACL_PROTECTED != 0;
    let (explicit, inherited) = entries_of(list)?;
    Ok(Security {
        owner,
        list: WindowsAcl {
            protected,
            explicit,
            inherited,
        },
    })
}

/// Reads every entry of one list, keeping what the object carries apart from what it inherits.
fn entries_of(list: *mut ACL) -> std::io::Result<(Vec<AclEntry>, Vec<AclEntry>)> {
    // SAFETY: the pointer names the list inside the descriptor the caller holds.
    let count = unsafe { (*list).AceCount };
    let mut explicit = Vec::new();
    let mut inherited = Vec::new();
    for index in 0..u32::from(count) {
        let mut entry: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: the list is live and the index is below the entry count it reported.
        let got = unsafe { GetAce(list, index, &raw mut entry) };
        if got == 0 || entry.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: every entry begins with its header, inside the list this pointer came from.
        let header = unsafe { std::ptr::read(entry.cast::<ACE_HEADER>()) };
        let is_inherited = header.AceFlags & inherited_flag() != 0;
        // Allowing and denying are the two kinds whose whole meaning is their flags, their mask
        // and their account. A callback, a conditional or an object entry decides access on terms
        // that are not any of those, so it refuses the reading wherever it sits: a reading that
        // kept such an entry without its terms would compare equal to a reading of another list,
        // and a replacement built on that comparison would take protection away.
        if !matches!(
            header.AceType,
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE
        ) {
            return Err(std::io::Error::other(
                "the access-control list carries an entry kind this host does not read",
            ));
        }
        // SAFETY: an allowing and a denying entry share the layout of `ACCESS_ALLOWED_ACE`, whose
        // mask and identifier sit at these offsets inside the entry read above.
        let mask = unsafe { std::ptr::read(entry.cast::<ACCESS_ALLOWED_ACE>()) }.Mask;
        // SAFETY: the identifier of such an entry begins at the offset of `SidStart`.
        let start: PSID = unsafe {
            entry
                .cast::<u8>()
                .add(std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart))
        }
        .cast();
        let Some(sid) = Sid::copy_from(start) else {
            return Err(std::io::Error::other(
                "an entry of the access-control list names an account this host cannot read",
            ));
        };
        let read = AclEntry {
            kind: header.AceType,
            flags: header.AceFlags & !inherited_flag(),
            mask,
            sid,
        };
        if is_inherited {
            inherited.push(read);
        } else {
            explicit.push(read);
        }
    }
    Ok((explicit, inherited))
}

/// Reads the account an opened object belongs to.
///
/// # Errors
///
/// Returns an error when the platform refuses the read.
pub fn read_owner(handle: BorrowedHandle<'_>) -> std::io::Result<Sid> {
    Ok(read_security(handle)?.owner)
}

/// Returns true when an opened object carries protection of its own.
///
/// Asked of the handle, and decided from what the read says rather than from the platform call
/// itself, so the decision can be driven over every answer a read has.
#[must_use]
pub fn carries_access_control(handle: BorrowedHandle<'_>) -> bool {
    carries_list(&read_security(handle).map(|security| security.list))
}

/// Decides, from one reading, whether an object carries protection beyond what it inherits.
///
/// A read that failed answers true: an object this host could not ask about is one whose
/// protection it cannot say it can carry across, and the callers turn that into a refusal to
/// replace it rather than into a silent loss.
fn carries_list(read: &std::io::Result<WindowsAcl>) -> bool {
    match read {
        Ok(list) => list.has_entries(),
        Err(_) => true,
    }
}

/// Reads the whole discretionary list of an opened object, its own entries and its inherited ones.
///
/// # Errors
///
/// Returns an error when the platform refuses the read, when the object carries no list at all,
/// or when the list carries an entry kind this host does not read.
pub fn read_access_control(handle: BorrowedHandle<'_>) -> std::io::Result<WindowsAcl> {
    Ok(read_security(handle)?.list)
}

/// Puts a discretionary list on an opened object, or takes the object's own entries off it.
///
/// `None` leaves the object with exactly what the directory above it gives: an unprotected list
/// with no entry of its own. That is the Windows form of clearing a list, and it is what a copy
/// staged beside a destination that carries nothing of its own has to end up with.
///
/// Writing needs `WRITE_DAC` on the handle, which only the staged copy's own open asks for.
///
/// # Errors
///
/// Returns an error when the list carries an entry this host cannot write back, when the list
/// cannot be built, or when the platform refuses the write.
pub fn set_access_control(
    handle: BorrowedHandle<'_>,
    list: Option<&WindowsAcl>,
) -> std::io::Result<()> {
    let empty = Vec::new();
    let (protected, entries) = match list {
        // The object's own entries and its protection flag are what a replacement writes. The
        // inherited ones are the directory's, and the platform gives them to the object again.
        Some(list) => (list.protected, &list.explicit),
        None => (false, &empty),
    };
    let mut buffer = build_list(entries)?;
    let information = DACL_SECURITY_INFORMATION
        | if protected {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
    // SAFETY: the handle is borrowed for the whole call and was opened with `WRITE_DAC`. The list
    // pointer names the buffer built above, which outlives the call, and the parameters this host
    // does not set are null, which the call documents as "leave this alone".
    let status = unsafe {
        SetSecurityInfo(
            handle.as_raw_handle(),
            SE_FILE_OBJECT,
            information,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast::<ACL>(),
            std::ptr::null(),
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(status.cast_signed()))
    }
}

/// Gives an opened object to an account.
///
/// A process that holds neither the account itself nor `SeRestorePrivilege` can give a file only
/// to an account its own token names, so this fails where the platform refuses it and the caller
/// decides what a refusal means.
///
/// # Errors
///
/// Returns an error when the platform refuses the write.
pub fn set_owner(handle: BorrowedHandle<'_>, owner: &Sid) -> std::io::Result<()> {
    // SAFETY: the handle is borrowed for the whole call and was opened with `WRITE_OWNER`. The
    // identifier points at the caller's own buffer, which outlives the call.
    let status = unsafe {
        SetSecurityInfo(
            handle.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            owner.as_psid(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(status.cast_signed()))
    }
}

/// Builds one list in the layout the platform reads, in the order the entries are given.
///
/// The order is kept because the platform evaluates a list in order: a denial that came before an
/// allowance decides differently if it comes after it.
fn build_list(entries: &[AclEntry]) -> std::io::Result<Vec<u32>> {
    let header = std::mem::size_of::<ACL>();
    let fixed = std::mem::size_of::<ACCESS_ALLOWED_ACE>() - std::mem::size_of::<u32>();
    let mut bytes = header;
    for entry in entries {
        bytes = bytes.checked_add(fixed + entry.sid.len).ok_or_else(|| {
            std::io::Error::other("the access-control list is too large to build")
        })?;
    }
    let length = u32::try_from(bytes)
        .map_err(|_| std::io::Error::other("the access-control list is too large to build"))?;
    let mut buffer = vec![0_u32; bytes.div_ceil(4).max(2)];
    // SAFETY: the buffer holds at least `length` bytes and is aligned for a list.
    let started = unsafe { InitializeAcl(buffer.as_mut_ptr().cast::<ACL>(), length, ACL_REVISION) };
    if started == 0 {
        return Err(std::io::Error::last_os_error());
    }
    for entry in entries {
        let flags = u32::from(entry.flags);
        let added = match entry.kind {
            // SAFETY: the buffer holds an initialised list with room for this entry, and the
            // identifier points at the entry's own buffer for the length of the call.
            ACCESS_ALLOWED_ACE_TYPE => unsafe {
                AddAccessAllowedAceEx(
                    buffer.as_mut_ptr().cast::<ACL>(),
                    ACL_REVISION,
                    flags,
                    entry.mask,
                    entry.sid.as_psid(),
                )
            },
            // SAFETY: as above.
            ACCESS_DENIED_ACE_TYPE => unsafe {
                AddAccessDeniedAceEx(
                    buffer.as_mut_ptr().cast::<ACL>(),
                    ACL_REVISION,
                    flags,
                    entry.mask,
                    entry.sid.as_psid(),
                )
            },
            _ => {
                return Err(std::io::Error::other(
                    "the access-control list carries an entry kind this host does not write",
                ));
            }
        };
        if added == 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(buffer)
}

/// Names one identifier, for a refusal a person reads.
fn describe(sid: PSID) -> String {
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: the identifier is live and the out parameter is live.
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

/// Resolves one identifier written in the numeric form.
///
/// For a test that has to name a well-known account, and for nothing else: an account this host
/// decides about comes off a handle rather than out of a string.
///
/// # Errors
///
/// Returns an error when the text does not name an account.
pub fn account_named(text: &str) -> std::io::Result<Sid> {
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;

    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sid: PSID = std::ptr::null_mut();
    // SAFETY: the text is a null-terminated wide buffer this function owns for the call, and the
    // out parameter is live.
    let parsed = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &raw mut sid) };
    if parsed == 0 || sid.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let copied = Sid::copy_from(sid);
    // SAFETY: the identifier came from the conversion above and is freed exactly once.
    unsafe {
        LocalFree(sid.cast());
    }
    copied.ok_or_else(|| std::io::Error::other("the account named could not be read back"))
}

/// Removes the file an open handle names, whatever its name reaches by now.
///
/// The object is opened a second time with the right to delete it, from the handle rather than
/// by a name, and marked for removal. The name takes no part in either call, so a replacement put
/// at it in the meantime is never what goes. A file marked read-only goes too: what a tree holds
/// is removed whole, and Git writes its objects read-only.
///
/// Two markings exist and a file takes whichever its volume carries. The first unlinks the name at
/// once, even while handles are still open. The second, older one takes the name as the last
/// handle on the object closes, which is before the caller removes the directory the file is in.
///
/// # Errors
///
/// Returns the reopen or the marking failure. An object another process holds open without
/// allowing deletion refuses the reopen and stays exactly as it is.
pub(crate) fn dispose_of(file: &cap_std::fs::File) -> std::io::Result<()> {
    use std::os::windows::io::{HandleOrInvalid, OwnedHandle};

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
        FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileDispositionInfo,
        FileDispositionInfoEx, ReOpenFile, SetFileInformationByHandle,
    };

    // SAFETY: the original handle is open for the whole call, and what comes back is either a
    // handle this function owns or the invalid one, which the conversion below refuses.
    let reopened = unsafe {
        HandleOrInvalid::from_raw_handle(ReOpenFile(
            file.as_raw_handle(),
            DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        ))
    };
    let deletable = OwnedHandle::try_from(reopened).map_err(|_| std::io::Error::last_os_error())?;
    let handle: HANDLE = deletable.as_raw_handle();
    let now = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    // SAFETY: the handle is owned here and open for the whole call, and the buffer is the
    // structure the information class names, with its own size.
    let marked = unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfoEx,
            std::ptr::from_ref(&now).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if marked != 0 {
        return Ok(());
    }
    // A volume that does not carry the immediate marking takes the older one.
    let at_close = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: as above, for the older information class.
    let marked = unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            std::ptr::from_ref(&at_close).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if marked == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::Security::ACL;

    use super::{AclEntry, Sid, WindowsAcl, account_named, build_list, carries_list, entries_of};

    /// An account every Windows installation has, for a reading this test builds by hand.
    fn everyone() -> Sid {
        account_named("S-1-1-0").expect("the world account resolves")
    }

    /// A second account, so a changed account can be told from a changed mask.
    fn local_system() -> Sid {
        account_named("S-1-5-18").expect("the system account resolves")
    }

    /// An entry an object received from the directory above it.
    ///
    /// Which list an entry is in is what records that it was inherited, so this is an ordinary
    /// entry; it is the list it is put in that says where it came from.
    fn from_the_directory_above() -> AclEntry {
        AclEntry::new(0, 0, 0x0012_0089, everyone())
    }

    #[test]
    fn a_reading_decides_whether_an_object_carries_protection_of_its_own() {
        let one = AclEntry::new(0, 0, 0x0012_0089, everyone());
        assert!(
            !carries_list(&Ok(WindowsAcl::new(
                false,
                Vec::new(),
                vec![from_the_directory_above()]
            ))),
            "a list that is entirely the directory's doing is not protection of the object's own"
        );
        assert!(
            carries_list(&Ok(WindowsAcl::new(false, vec![one], Vec::new()))),
            "one entry of the object's own is protection it carries"
        );
        assert!(
            carries_list(&Ok(WindowsAcl::new(true, Vec::new(), Vec::new()))),
            "a protected list keeps the directory above from widening it, which is protection"
        );
        assert!(
            carries_list(&Err(std::io::Error::other("the platform refused"))),
            "an object this host could not ask about is one it cannot say it can replace"
        );
    }

    #[test]
    fn the_order_two_entries_are_held_in_is_part_of_what_a_list_says() {
        let allow = AclEntry::new(0, 0, 0x001f_01ff, everyone());
        let deny = AclEntry::new(1, 0, 0x0000_0002, everyone());
        // The platform stops at the first entry that decides the access asked for, so denying
        // before allowing refuses a write that allowing before denying permits.
        let refuses = WindowsAcl::new(false, vec![deny.clone(), allow.clone()], Vec::new());
        let permits = WindowsAcl::new(false, vec![allow, deny], Vec::new());
        assert_ne!(
            refuses, permits,
            "the same entries in another order decide differently"
        );
    }

    #[test]
    fn what_an_object_inherits_is_outside_what_it_carries_itself() {
        let allow = AclEntry::new(0, 0, 0x0012_0089, everyone());
        let here = WindowsAcl::new(false, vec![allow.clone()], vec![from_the_directory_above()]);
        let elsewhere = WindowsAcl::new(
            false,
            vec![allow],
            vec![AclEntry::new(1, 0, 0x0000_0004, local_system())],
        );
        // The directory above hands its entries to every object made in it, so a copy staged
        // beside a destination receives the directory's current ones whatever the destination
        // holds. What the two say about themselves is the same.
        assert_eq!(
            here, elsewhere,
            "two objects carrying the same entries of their own carry the same protection"
        );
        assert_eq!(
            here.inherited().len(),
            1,
            "and each still reports what it inherits"
        );
    }

    #[test]
    fn an_entry_kind_this_host_cannot_read_refuses_the_whole_reading() {
        /// An entry whose access is decided by a callback this host neither runs nor reproduces.
        const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;
        /// The flag that says an entry came from the directory above.
        const INHERITED: u8 = 0x10;

        for flags in [0_u8, INHERITED] {
            let mut buffer = build_list(&[AclEntry::new(0, 0, 0x0012_0089, everyone())])
                .expect("a list this host writes");
            // The kind and the flags are the first two bytes of the first entry, which follows the
            // list's own header. Rewriting them makes exactly the list a host can hold and this one
            // cannot read, in the second turn as an entry the directory above handed down: an entry
            // this host cannot read is refused wherever it sits, and a builder will not write the
            // inherited flag itself, because which list an entry is in is what records it.
            // SAFETY: the buffer holds an initialised list with one entry, so this writes inside
            // that entry's own header.
            unsafe {
                let header = buffer.as_mut_ptr().cast::<u8>().add(size_of::<ACL>());
                header.write(ACCESS_ALLOWED_CALLBACK_ACE_TYPE);
                header.add(1).write(flags);
            }
            // SAFETY: the same header, read back to establish which list the entry would land in.
            let written = unsafe {
                buffer
                    .as_ptr()
                    .cast::<u8>()
                    .add(size_of::<ACL>() + 1)
                    .read()
            };
            assert_eq!(
                written & INHERITED,
                flags,
                "the entry is the one this turn means to read"
            );
            let read = entries_of(buffer.as_mut_ptr().cast::<ACL>());
            assert!(
                read.is_err(),
                "an entry this host cannot read refuses the reading, inherited or not: {read:?}"
            );
        }
    }

    #[test]
    fn a_changed_entry_makes_two_lists_unequal() {
        let allow = AclEntry::new(0, 0, 0x0012_0089, everyone());
        let base = WindowsAcl::new(false, vec![allow.clone()], Vec::new());

        let wider = WindowsAcl::new(
            false,
            vec![AclEntry::new(0, 0, 0x001f_01ff, everyone())],
            Vec::new(),
        );
        assert_ne!(base, wider, "a changed access mask is a changed list");

        let elsewhere = WindowsAcl::new(
            false,
            vec![AclEntry::new(0, 0, 0x0012_0089, local_system())],
            Vec::new(),
        );
        assert_ne!(base, elsewhere, "a changed account is a changed list");

        let denied = WindowsAcl::new(
            false,
            vec![AclEntry::new(1, 0, 0x0012_0089, everyone())],
            Vec::new(),
        );
        assert_ne!(base, denied, "an allowance turned into a denial is changed");

        let inheriting = WindowsAcl::new(
            false,
            vec![AclEntry::new(0, 3, 0x0012_0089, everyone())],
            Vec::new(),
        );
        assert_ne!(base, inheriting, "a changed inheritance flag is changed");

        let dropped = WindowsAcl::new(false, Vec::new(), Vec::new());
        assert_ne!(base, dropped, "a dropped entry is a changed list");

        let added = WindowsAcl::new(
            false,
            vec![
                allow.clone(),
                AclEntry::new(0, 0, 0x0000_0004, local_system()),
            ],
            Vec::new(),
        );
        assert_ne!(base, added, "an added entry is a changed list");

        let protected = WindowsAcl::new(true, vec![allow], Vec::new());
        assert_ne!(base, protected, "a list that gained protection is changed");
    }

    #[test]
    fn an_account_is_compared_by_identity_rather_than_by_its_text() {
        assert_eq!(everyone(), everyone(), "one account is one account");
        assert_ne!(everyone(), local_system(), "two accounts are two accounts");
    }
}
