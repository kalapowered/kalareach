//! The pieces every call module shares: wide strings, owned handles, errors and identifiers.

#![allow(unsafe_code)]

use std::ffi::{OsStr, c_void};
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{
    CopySid, EqualSid, GetLengthSid, LookupAccountNameW, SID_NAME_USE,
};

/// A failed call: the platform's error number and what was being done.
#[derive(Debug)]
pub struct Error {
    /// The platform's error number, or 0 for a failure that no call returned.
    pub code: u32,
    /// What the failed call was doing.
    pub what: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(&crate::remedy::platform_error(&self.what, self.code))
    }
}

impl std::error::Error for Error {}

/// The result of a call into the platform.
pub type Result<T> = std::result::Result<T, Error>;

/// An error with an explicit number; the number 0 is for a failure that no call returned.
#[must_use]
pub fn error(code: u32, what: impl Into<String>) -> Error {
    Error {
        code,
        what: what.into(),
    }
}

/// The error of the last failed call on this thread.
#[must_use]
pub fn last(what: impl Into<String>) -> Error {
    // SAFETY: reads the calling thread's last error.
    error(unsafe { GetLastError() }, what)
}

/// A lock taken even when a thread that held it panicked. What these locks guard is a hook or a list
/// that this crate keeps for itself, and nothing in it is read from the machine, so a poisoned lock
/// holds data as good as any.
pub fn locked<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    #[expect(
        clippy::disallowed_methods,
        reason = "a lock that a panicking thread poisoned still holds its data, and nothing in it was read from the machine"
    )]
    let guard = mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard
}

/// A duration as the whole milliseconds that a wait takes, and never more than `longest`: a longer
/// duration, or one that does not fit the platform's count, waits for `longest`.
#[must_use]
pub fn milliseconds(duration: std::time::Duration, longest: u32) -> u32 {
    match u32::try_from(duration.as_millis()) {
        Ok(milliseconds) => milliseconds.min(longest),
        Err(_) => longest,
    }
}

/// Text as a NUL-terminated wide string.
#[must_use]
pub fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text).encode_wide().chain([0]).collect()
}

/// A path as a NUL-terminated wide string.
#[must_use]
pub fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}

/// Text from a NUL-terminated wide string.
///
/// # Safety
///
/// `text` must point at a NUL-terminated wide string, or be null.
#[must_use]
pub unsafe fn from_wide(text: *const u16) -> String {
    if text.is_null() {
        return String::new();
    }
    let mut length = 0;
    // SAFETY: the caller promises the string is NUL-terminated.
    unsafe {
        while *text.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(text, length))
    }
}

/// The system's own Windows directory, as the platform reports it: never read from an environment
/// variable, which a caller could have set.
///
/// # Errors
///
/// Returns the platform's error when the directory cannot be read.
pub fn system_windows_directory() -> Result<String> {
    let mut buffer = vec![0_u16; 260];
    // SAFETY: the buffer is as long as the length given.
    let length = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW(
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    } as usize;
    if length == 0 || length >= buffer.len() {
        // text: ffi_system_windows_directory-1
        return Err(last("reading the system's Windows directory"));
    }
    Ok(String::from_utf16_lossy(&buffer[..length]))
}

/// One of the system's own folders that the installation is laid in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KnownFolder {
    /// `Program Files`, where the program directory is.
    ProgramFiles,
    /// `ProgramData`, where the data directory is.
    ProgramData,
}

impl KnownFolder {
    /// The folder's name as a person reads it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            KnownFolder::ProgramFiles => "Program Files",
            KnownFolder::ProgramData => "ProgramData",
        }
    }
}

/// A known folder that the shell could not give: which one, and the platform's answer.
#[derive(Debug, thiserror::Error)]
// text: ffi-1
#[error("reading the system's {} folder: {}", .folder.name(), known_folder_answer(*.status))]
pub struct KnownFolderError {
    /// The folder.
    pub folder: KnownFolder,
    /// The platform's answer, an `HRESULT`.
    pub status: u32,
}

/// What a known folder's call answered, in words: the system's form of an error, or, for an answer
/// of success, that the call gave no path.
fn known_folder_answer(status: u32) -> String {
    // An HRESULT with its top bit set is a failure.
    if status >= 0x8000_0000 {
        system_form(status)
    } else {
        "the call reported success and gave no path".to_owned()
    }
}

/// A platform error in the system's own form: its code in hexadecimal and, where the system has a
/// message for it, the message. An `HRESULT` that wraps a Windows error is looked up by that error.
#[must_use]
// text: system_form
pub fn system_form(code: u32) -> String {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS, FormatMessageW,
    };
    let number = if code >> 16 == 0x8007 {
        code & 0xFFFF
    } else {
        code
    };
    let mut buffer = [0_u16; 512];
    // SAFETY: the buffer's length is passed; the call takes no source and no inserts.
    let length = unsafe {
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            null(),
            number,
            0,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            null(),
        )
    } as usize;
    let message = String::from_utf16_lossy(&buffer[..length.min(buffer.len())]);
    let message = message.trim();
    if message.is_empty() {
        format!("0x{code:08X}")
    } else {
        format!("0x{code:08X} ({message})")
    }
}

/// A system folder as the shell's own call gives it. It is never read from the environment: an
/// unelevated session of the same account can set its own variables, and the installation runs
/// elevated and lays programs down that the system runs.
///
/// # Errors
///
/// Returns the platform's error when the folder cannot be read.
pub fn known_folder(
    which: KnownFolder,
) -> std::result::Result<std::path::PathBuf, KnownFolderError> {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_ProgramData, FOLDERID_ProgramFiles, SHGetKnownFolderPath,
    };
    let id = match which {
        KnownFolder::ProgramFiles => &FOLDERID_ProgramFiles,
        KnownFolder::ProgramData => &FOLDERID_ProgramData,
    };
    let mut text: *mut u16 = null_mut();
    // SAFETY: the identifier is a constant, the token is the calling process's own and the answer
    // is an out-parameter that is freed below.
    let status = unsafe { SHGetKnownFolderPath(id, 0, null_mut(), &raw mut text) };
    if status < 0 || text.is_null() {
        // SAFETY: frees what the call allocated, if it did.
        unsafe { CoTaskMemFree(text.cast()) };
        return Err(KnownFolderError {
            folder: which,
            status: status as u32,
        });
    }
    // SAFETY: the answer is a NUL-terminated string that the call allocated.
    let length = unsafe { (0..).take_while(|&at| *text.add(at) != 0).count() };
    // SAFETY: as above, and `length` units are before the terminator.
    let path = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
    // SAFETY: frees what the call allocated, once.
    unsafe { CoTaskMemFree(text.cast()) };
    Ok(std::path::PathBuf::from(path))
}

/// How long Windows has been running, in milliseconds.
#[must_use]
pub fn uptime_millis() -> u64 {
    // SAFETY: takes no argument and reads the system's tick count.
    unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() }
}

/// A handle that closes when dropped.
#[derive(Debug)]
pub struct Handle(HANDLE);

// SAFETY: a kernel handle is a process-wide number, not tied to a thread.
unsafe impl Send for Handle {}
// SAFETY: the calls made through a shared handle are the kernel's own, which synchronise.
unsafe impl Sync for Handle {}

impl Handle {
    /// Takes ownership of a handle. Null and the invalid value are an error.
    ///
    /// # Errors
    ///
    /// Returns the last error when the handle is null or invalid.
    pub fn new(raw: HANDLE, what: &str) -> Result<Handle> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            Err(last(what))
        } else {
            Ok(Handle(raw))
        }
    }

    /// The raw handle, still owned by this value.
    #[must_use]
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this value and closed once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// A security identifier in storage that is aligned for the platform's structures.
#[derive(Clone, Debug)]
pub struct Sid {
    storage: Vec<u64>,
}

impl PartialEq for Sid {
    fn eq(&self, other: &Sid) -> bool {
        // SAFETY: both identifiers are valid and live.
        unsafe { EqualSid(self.as_ptr(), other.as_ptr()) != 0 }
    }
}
impl Eq for Sid {}

impl Sid {
    /// Copies an identifier the platform owns.
    ///
    /// # Safety
    ///
    /// `sid` must point at a valid identifier.
    #[must_use]
    pub unsafe fn from_ptr(sid: *mut c_void) -> Sid {
        // SAFETY: the caller promises the identifier is valid.
        let length = unsafe { GetLengthSid(sid) } as usize;
        let mut storage = vec![0_u64; length.div_ceil(8)];
        // SAFETY: the buffer holds at least `length` bytes and the identifier is that long.
        unsafe {
            CopySid(length as u32, storage.as_mut_ptr().cast(), sid);
        }
        Sid { storage }
    }

    /// Reads an identifier written as text, such as `S-1-5-18`.
    ///
    /// # Errors
    ///
    /// Returns the platform's error for text that is not an identifier.
    pub fn parse(text: &str) -> Result<Sid> {
        let wide_text = wide(text);
        let mut sid: *mut c_void = null_mut();
        // SAFETY: the text is NUL-terminated and the identifier is an out-parameter freed below.
        unsafe {
            if ConvertStringSidToSidW(wide_text.as_ptr(), &raw mut sid) == 0 {
                // text: ffi_parse-1
                return Err(last(format!("reading the identifier {text}")));
            }
            let copy = Sid::from_ptr(sid);
            LocalFree(sid);
            Ok(copy)
        }
    }

    /// Looks up the identifier of a local account by name.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the lookup fails: the error is "no mapping" where no
    /// account has the name.
    pub fn of_account(name: &str) -> Result<Sid> {
        let wide_name = wide(name);
        let mut sid_length = 0_u32;
        let mut domain_length = 0_u32;
        let mut kind: SID_NAME_USE = 0;
        // SAFETY: the first call only asks for the sizes it needs.
        unsafe {
            LookupAccountNameW(
                null(),
                wide_name.as_ptr(),
                null_mut(),
                &raw mut sid_length,
                null_mut(),
                &raw mut domain_length,
                &raw mut kind,
            );
        }
        if sid_length == 0 {
            // text: ffi_of_account-1
            return Err(last(format!("looking up the account {name}")));
        }
        let mut storage = vec![0_u64; (sid_length as usize).div_ceil(8)];
        let mut domain = vec![0_u16; domain_length as usize];
        // SAFETY: both buffers are the sizes the first call asked for.
        let found = unsafe {
            LookupAccountNameW(
                null(),
                wide_name.as_ptr(),
                storage.as_mut_ptr().cast(),
                &raw mut sid_length,
                domain.as_mut_ptr(),
                &raw mut domain_length,
                &raw mut kind,
            )
        };
        if found == 0 {
            // text: ffi_of_account-2
            return Err(last(format!("looking up the account {name}")));
        }
        Ok(Sid { storage })
    }

    /// The identifier as the platform's pointer type.
    #[must_use]
    pub fn as_ptr(&self) -> *mut c_void {
        self.storage.as_ptr().cast_mut().cast()
    }

    /// The account's name as the system resolves it, with its domain (`BUILTIN\Users`), or `None`
    /// where it does not resolve.
    #[must_use]
    pub fn account_name(&self) -> Option<String> {
        use windows_sys::Win32::Security::LookupAccountSidW;
        let (mut name_length, mut domain_length) = (0_u32, 0_u32);
        let mut kind: SID_NAME_USE = 0;
        // SAFETY: the identifier is valid; with no buffers the call only reports the sizes.
        unsafe {
            LookupAccountSidW(
                null(),
                self.as_ptr(),
                null_mut(),
                &raw mut name_length,
                null_mut(),
                &raw mut domain_length,
                &raw mut kind,
            );
        }
        if name_length == 0 {
            return None;
        }
        let mut name = vec![0_u16; name_length as usize];
        let mut domain = vec![0_u16; domain_length.max(1) as usize];
        // SAFETY: both buffers are the sizes the first call asked for.
        let found = unsafe {
            LookupAccountSidW(
                null(),
                self.as_ptr(),
                name.as_mut_ptr(),
                &raw mut name_length,
                domain.as_mut_ptr(),
                &raw mut domain_length,
                &raw mut kind,
            )
        };
        if found == 0 {
            return None;
        }
        name.truncate(name_length as usize);
        domain.truncate(domain_length as usize);
        let (name, domain) = (
            String::from_utf16_lossy(&name),
            String::from_utf16_lossy(&domain),
        );
        Some(if domain.is_empty() {
            name
        } else {
            format!("{domain}\\{name}")
        })
    }

    /// The identifier as text.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the identifier cannot be converted: no text is then given,
    /// and in particular no empty one.
    pub fn to_text(&self) -> Result<String> {
        let mut text: *mut u16 = null_mut();
        // SAFETY: the identifier is valid; the text is an out-parameter freed below.
        unsafe {
            if ConvertSidToStringSidW(self.as_ptr(), &raw mut text) == 0 {
                // text: sid_to_text-1
                return Err(last("converting an identifier to text"));
            }
            let value = from_wide(text);
            LocalFree(text.cast());
            Ok(value)
        }
    }
}

/// The names of the window stations the caller's session can see, for a case that shows the
/// boundary made none of its own.
///
/// # Errors
///
/// Returns an error when the platform cannot list them.
pub fn window_station_names() -> Result<Vec<String>> {
    use std::sync::Mutex;

    use windows_sys::Win32::System::StationsAndDesktops::EnumWindowStationsW;

    static NAMES: Mutex<Vec<String>> = Mutex::new(Vec::new());
    unsafe extern "system" fn collect(name: *const u16, _: isize) -> i32 {
        // SAFETY: the platform passes a NUL-terminated name that lives through the call.
        let name = unsafe { from_wide(name) };
        locked(&NAMES).push(name);
        1
    }
    locked(&NAMES).clear();
    // SAFETY: the callback has the signature the call wants and touches only the static list.
    if unsafe { EnumWindowStationsW(Some(collect), 0) } == 0 {
        return Err(last("listing the window stations"));
    }
    Ok(locked(&NAMES).clone())
}
