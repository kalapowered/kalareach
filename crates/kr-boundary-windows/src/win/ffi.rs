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
#[derive(Debug, thiserror::Error)]
#[error("{what}: Windows error {code}")]
pub struct Error {
    /// The platform's error number.
    pub code: u32,
    /// What the failed call was doing.
    pub what: String,
}

/// The result of a call into the platform.
pub type Result<T> = std::result::Result<T, Error>;

/// An error with an explicit number.
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
    /// Returns the platform's error when there is no such account.
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
            return Err(last(format!("looking up the account {name}")));
        }
        Ok(Sid { storage })
    }

    /// The identifier as the platform's pointer type.
    #[must_use]
    pub fn as_ptr(&self) -> *mut c_void {
        self.storage.as_ptr().cast_mut().cast()
    }

    /// The identifier as text.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut text: *mut u16 = null_mut();
        // SAFETY: the identifier is valid; the text is an out-parameter freed below.
        unsafe {
            if ConvertSidToStringSidW(self.as_ptr(), &raw mut text) == 0 {
                return String::new();
            }
            let value = from_wide(text);
            LocalFree(text.cast());
            value
        }
    }
}
