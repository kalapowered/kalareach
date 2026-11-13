//! The pieces every call module shares: wide strings, owned handles, errors and identifiers.

#![allow(unsafe_code)]

use std::ffi::{OsStr, c_void};
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_INSUFFICIENT_BUFFER, ERROR_IO_INCOMPLETE,
    ERROR_IO_PENDING, ERROR_NONE_MAPPED, ERROR_PIPE_CONNECTED, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE, LocalFree, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{
    CopySid, EqualSid, GetLengthSid, LookupAccountNameW, SID_NAME_USE,
};
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{ConnectNamedPipe, PeekNamedPipe};
use windows_sys::Win32::System::Threading::WaitForMultipleObjects;

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

/// What the system names an account that has an identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Named {
    /// The name of the account's domain: this computer's account domain for a local account.
    pub domain: String,
    /// The account's own name in it.
    pub name: String,
    /// Whether the identifier is that of a user account.
    pub user: bool,
}

/// The result of a call into the platform.
pub type Result<T> = std::result::Result<T, Error>;

/// How a wait that did not fail ended: an object was signalled, or the bound ran out. A wait has a
/// third answer, that it failed, and that is the error of [`wait`] and [`wait_any`]: it says nothing
/// of any object, so no caller may take it for either of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Waited {
    /// The object at this index (0 for [`wait`]) was signalled.
    Signalled(usize),
    /// The bound ran out first.
    TimedOut,
}

/// Waits on one object for up to `milliseconds`, as [`wait_any`] does for one handle.
///
/// # Errors
///
/// Returns the platform's error, in words that start with `what`, when the wait failed, and an
/// error with no number when it answered neither signalled nor timed out (an abandoned mutex).
pub fn wait(handle: HANDLE, milliseconds: u32, what: &str) -> Result<Waited> {
    wait_any(&[handle], milliseconds, what)
}

/// Waits until any of the objects is signalled or the bound runs out. Where several are signalled
/// the lowest index is the answer, so an object that must win goes first. The only place of the
/// crate that calls the platform's wait.
///
/// # Errors
///
/// Returns the platform's error, in words that start with `what`, when the wait failed, and an
/// error with no number when it answered neither an object nor a timeout (an abandoned mutex).
pub fn wait_any(handles: &[HANDLE], milliseconds: u32, what: &str) -> Result<Waited> {
    // SAFETY: every handle is open for the length of the wait, and the count is the slice's.
    #[expect(
        clippy::disallowed_methods,
        reason = "this is the wrapper: it turns the platform's one number into signalled, timed out or failed"
    )]
    let answer =
        unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, milliseconds) };
    let index = answer.wrapping_sub(WAIT_OBJECT_0) as usize;
    if answer == WAIT_TIMEOUT {
        Ok(Waited::TimedOut)
    } else if answer == WAIT_FAILED {
        // text: ffi_wait_any-1
        Err(last(what))
    } else if index < handles.len() {
        Ok(Waited::Signalled(index))
    } else {
        // text: ffi_wait_any-2
        Err(error(0, format!("{what} gave the answer {answer:#x}")))
    }
}

/// What a read of a pipe answered, other than a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeRead {
    /// This many bytes were read.
    Data(u32),
    /// Nothing is waiting, and a writer is still there.
    Empty,
    /// Every writer has closed its handle: the pipe's end.
    Ended,
}

/// Reads what a pipe holds now, into the buffer, with no wait: the bytes waiting (up to the
/// buffer's length), nothing, or the end. The answers of the two calls it makes are told apart: a
/// broken pipe is the end, and any other failure is the error, never the end and never nothing.
/// The only place of the crate that peeks at a pipe or reads one in a loop.
///
/// # Errors
///
/// Returns the platform's error when the look or the read failed, or when a read of waiting bytes
/// gave none.
pub fn pipe_read(pipe: &Handle, buffer: &mut [u8]) -> Result<PipeRead> {
    let mut available = 0_u32;
    // SAFETY: the pipe is open and only the available-bytes out-parameter is used.
    #[expect(
        clippy::disallowed_methods,
        reason = "this is the wrapper: it turns the platform's failure into the end or the error"
    )]
    let peeked = unsafe {
        PeekNamedPipe(
            pipe.raw(),
            null_mut(),
            0,
            null_mut(),
            &raw mut available,
            null_mut(),
        )
    };
    if peeked == 0 {
        // SAFETY: reads the calling thread's last error.
        let code = unsafe { GetLastError() };
        if code == ERROR_BROKEN_PIPE {
            return Ok(PipeRead::Ended);
        }
        // text: ffi_pipe_read-1
        return Err(error(code, "looking at what a pipe holds"));
    }
    let wanted = available.min(buffer.len() as u32);
    if wanted == 0 {
        return Ok(PipeRead::Empty);
    }
    let mut read = 0_u32;
    // SAFETY: the pipe is open, `wanted` bytes are waiting and the buffer is at least that long.
    #[expect(
        clippy::disallowed_methods,
        reason = "this is the wrapper: it turns the platform's failure into the end or the error"
    )]
    let ok = unsafe {
        ReadFile(
            pipe.raw(),
            buffer.as_mut_ptr().cast(),
            wanted,
            &raw mut read,
            null_mut(),
        )
    };
    if ok == 0 {
        // SAFETY: reads the calling thread's last error.
        let code = unsafe { GetLastError() };
        if code == ERROR_BROKEN_PIPE {
            return Ok(PipeRead::Ended);
        }
        // text: ffi_pipe_read-2
        return Err(error(code, "reading a pipe"));
    }
    if read == 0 {
        // text: ffi_pipe_read-3
        return Err(error(0, "a read of a pipe that held bytes gave none"));
    }
    Ok(PipeRead::Data(read))
}

/// How the start of an overlapped read of a pipe answered, other than a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadStarted {
    /// The read is under way or done: its record says when, and its result is read there.
    Going,
    /// Every writer has closed its handle: the pipe's end.
    Ended,
}

/// Starts an overlapped read of a pipe into `buffer`, with `record` as its record. A broken pipe is
/// the end and any other failure but "pending" is the error.
///
/// # Safety
///
/// The buffer and the record must stay where they are until the read has completed or has been
/// cancelled and seen to end.
///
/// # Errors
///
/// Returns the platform's error when the read could not be started.
pub unsafe fn read_overlapped(
    pipe: HANDLE,
    buffer: &mut [u8],
    record: *mut OVERLAPPED,
) -> Result<ReadStarted> {
    // SAFETY: the caller keeps the buffer and the record in place, as the contract says.
    #[expect(
        clippy::disallowed_methods,
        reason = "this is the wrapper: it turns the platform's failure into the end, going or the error"
    )]
    let started = unsafe {
        ReadFile(
            pipe,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            null_mut(),
            record,
        )
    };
    if started != 0 {
        return Ok(ReadStarted::Going);
    }
    // SAFETY: reads the calling thread's last error.
    let code = unsafe { GetLastError() };
    match code {
        ERROR_IO_PENDING => Ok(ReadStarted::Going),
        ERROR_BROKEN_PIPE => Ok(ReadStarted::Ended),
        // text: ffi_read_overlapped-1
        other => Err(error(other, "starting a read of a pipe")),
    }
}

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

/// What the read of an overlapped operation's result gave. It has three answers, and none is
/// folded into another: a failed transfer is not a transfer that has not completed.
#[derive(Debug)]
pub enum Completion {
    /// The operation completed; this many bytes were transferred.
    Done(u32),
    /// The operation has not completed.
    Incomplete,
    /// The operation completed with a failure; the error carries the platform's number.
    Failed(Error),
}

/// Reads the result of an overlapped operation without waiting for it, as [`Completion`]. The only
/// place of the crate that reads one.
///
/// # Safety
///
/// `file` must be an open handle, and `record` the record of an operation that was started on it.
#[must_use]
pub unsafe fn overlapped_result(file: HANDLE, record: &OVERLAPPED) -> Completion {
    let mut transferred = 0_u32;
    // SAFETY: the handle is open and the record is the one of an operation on it; the call does not
    // wait.
    #[expect(
        clippy::disallowed_methods,
        reason = "this is the wrapper: it tells a failed transfer from one that is not complete"
    )]
    let ok = unsafe { GetOverlappedResult(file, record, &raw mut transferred, 0) };
    if ok != 0 {
        return Completion::Done(transferred);
    }
    // SAFETY: reads the calling thread's last error.
    let code = unsafe { GetLastError() };
    if code == ERROR_IO_INCOMPLETE {
        return Completion::Incomplete;
    }
    // text: ffi_overlapped_result-1
    Completion::Failed(error(code, "reading the result of a transfer"))
}

/// What a connect on a named pipe's server end gave. It has three answers, and none is folded into
/// another: a failure is not a client that is there.
#[derive(Debug)]
pub enum Connect {
    /// A client is connected: it was before the call, or the call completed at once.
    Connected,
    /// The connect is pending; the operation's event is set when a client connects.
    Pending,
    /// The call failed; the error carries the platform's number.
    Failed(Error),
}

/// Starts an overlapped connect on a named pipe's server end, as [`Connect`]. The only place of the
/// crate that connects one.
///
/// # Safety
///
/// `pipe` must be an open handle to the server end of a named pipe made for overlapped use, and
/// `record` must stay alive and in place until the operation has completed, or been cancelled and
/// seen to end, or is kept for the life of the process.
#[must_use]
pub unsafe fn connect_named_pipe(pipe: HANDLE, record: &mut OVERLAPPED) -> Connect {
    // SAFETY: the pipe is open; the caller keeps the record alive and in place until the operation
    // has completed, or been cancelled, or is kept for the life of the process.
    #[expect(
        clippy::disallowed_methods,
        reason = "this is the wrapper: it tells a pending connect and a client that is there from a failure"
    )]
    let connected = unsafe { ConnectNamedPipe(pipe, record) };
    if connected != 0 {
        return Connect::Connected;
    }
    // SAFETY: reads the calling thread's last error.
    let code = unsafe { GetLastError() };
    match code {
        ERROR_IO_PENDING => Connect::Pending,
        ERROR_PIPE_CONNECTED => Connect::Connected,
        // text: ffi_connect_named_pipe-1
        other => Connect::Failed(error(other, "connecting a client to the pipe")),
    }
}

/// A lock taken even when a thread that held it panicked. What these locks guard is a hook, a list of
/// lines, a set of handles or a list of names that threads of this crate put there; each holder only
/// adds to it, takes it or clears it. Taking a poisoned lock is not a read of the machine, and it
/// folds no failed read into an answer: what a thread put there stays as that thread left it.
pub fn locked<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    #[expect(
        clippy::disallowed_methods,
        reason = "taking a poisoned lock is not a read of the machine: what it guards was put there by threads of this crate, whatever they read, and the lock folds no failed read into an answer"
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

    /// The account that has this identifier, as the system resolves it: `Some` where an account has
    /// it, `None` where the system answers that no account has it (its "no mapping" answer).
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the lookup failed for any other reason: nothing is then
    /// known about the account.
    pub fn lookup_account(&self) -> Result<Option<Named>> {
        use windows_sys::Win32::Security::{LookupAccountSidW, SidTypeUser};
        let (mut name_length, mut domain_length) = (0_u32, 0_u32);
        let mut kind: SID_NAME_USE = 0;
        // SAFETY: the identifier is valid; with no buffers the call only reports the sizes.
        let sized = unsafe {
            LookupAccountSidW(
                null(),
                self.as_ptr(),
                null_mut(),
                &raw mut name_length,
                null_mut(),
                &raw mut domain_length,
                &raw mut kind,
            )
        };
        if sized == 0 {
            // SAFETY: reads the calling thread's last error.
            let code = unsafe { GetLastError() };
            if code == ERROR_NONE_MAPPED {
                return Ok(None);
            }
            if code != ERROR_INSUFFICIENT_BUFFER {
                // text: ffi_lookup_account-1
                return Err(error(code, "looking up the account that has an identifier"));
            }
        }
        let mut name = vec![0_u16; name_length.max(1) as usize];
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
            // SAFETY: reads the calling thread's last error.
            let code = unsafe { GetLastError() };
            if code == ERROR_NONE_MAPPED {
                return Ok(None);
            }
            // text: ffi_lookup_account-2
            return Err(error(code, "looking up the account that has an identifier"));
        }
        name.truncate(name_length as usize);
        domain.truncate(domain_length as usize);
        Ok(Some(Named {
            domain: String::from_utf16_lossy(&domain),
            name: String::from_utf16_lossy(&name),
            user: kind == SidTypeUser,
        }))
    }

    /// The account's name as the system resolves it, with its domain (`BUILTIN\Users`), or `None`
    /// where it does not resolve or the lookup failed: it is for showing the identifier beside a
    /// name, and nothing decides on it.
    #[must_use]
    pub fn account_name(&self) -> Option<String> {
        match self.lookup_account() {
            Ok(Some(Named { domain, name, .. })) => Some(if domain.is_empty() {
                name
            } else {
                format!("{domain}\\{name}")
            }),
            Ok(None) | Err(_) => None,
        }
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
