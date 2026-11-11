//! The broker's pipe: a local-only endpoint that only the service can create and only the people
//! it names can open, with every wait able to end the moment the service is told to stop.
//!
//! The service makes the pipe first, so a program that took the name earlier makes the service
//! refuse to start rather than serve beside it. The pipe's permission list names the system,
//! administrators and the enrolled people with the rights to read and write and without the right
//! to make another instance, so nobody but the service can stand a second pipe under the name.
//! Remote clients are refused by the pipe itself.
//!
//! All input and output is overlapped and waits on the stop event as well as on the transfer, so
//! a connection never holds the service up when it is asked to end.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io::{self, Read, Write};
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::time::Instant;

use windows_sys::Win32::Foundation::{
    ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE, LocalFree,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{
    CheckTokenMembership, GetTokenInformation, RevertToSelf, SECURITY_ATTRIBUTES,
    SID_AND_ATTRIBUTES, TOKEN_QUERY, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    ImpersonateNamedPipeClient, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentThread, INFINITE, OpenThreadToken, SetEvent, WaitForMultipleObjects,
    WaitForSingleObject,
};

use super::ffi::{Handle, Result, Sid, error, last, wide};

/// The name the broker's pipe has.
pub const NAME: &str = r"\\.\pipe\KalaReachBoundary";

/// The most pipe instances the service keeps open at once.
pub const MAX_INSTANCES: u32 = 8;

/// The rights a client has on the pipe: read, write and read the attributes. Not the right to
/// make another instance, which is the same bit as appending.
const CLIENT_RIGHTS: &str = "0x120183";

/// An event that, once set, ends every wait of every connection that holds it.
pub struct Stop(Handle);

impl Stop {
    /// A new stop event, not set.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the event cannot be made.
    pub fn new() -> Result<Arc<Stop>> {
        // SAFETY: a manual-reset event with no name and no security attributes.
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        Ok(Arc::new(Stop(Handle::new(event, "making the stop event")?)))
    }

    /// Ends every wait.
    pub fn set(&self) {
        // SAFETY: the event handle is open.
        unsafe {
            SetEvent(self.0.raw());
        }
    }

    /// Whether the event is set.
    #[must_use]
    pub fn is_set(&self) -> bool {
        // SAFETY: the event handle is open; a zero wait only reads its state.
        unsafe { WaitForSingleObject(self.0.raw(), 0) == WAIT_OBJECT_0 }
    }
}

/// Who is on the other end of a connection, taken from the pipe and never from a message.
#[derive(Debug)]
pub struct Identity {
    /// The caller's process.
    pub pid: u32,
    /// The account the caller runs as.
    pub user: Sid,
    /// Whether the caller's token holds the Administrators group enabled, which is a caller that
    /// is an administrator and elevated.
    pub administrator: bool,
}

/// One end of a connected pipe.
pub struct Connection {
    pipe: Handle,
    stop: Arc<Stop>,
    /// The time after which no transfer on this connection waits, or none.
    deadline: Option<Instant>,
}

fn wait(
    pipe: HANDLE,
    overlapped: &mut OVERLAPPED,
    event: &Handle,
    stop: &Stop,
    deadline: Option<Instant>,
) -> io::Result<u32> {
    let handles = [event.raw(), stop.0.raw()];
    let milliseconds = deadline.map_or(INFINITE, |deadline| {
        let left = deadline.saturating_duration_since(Instant::now());
        // One less than the longest wait, which means "forever".
        u32::try_from(left.as_millis()).map_or(INFINITE - 1, |left| left.min(INFINITE - 1))
    });
    // SAFETY: both handles are open for the length of the wait.
    let signalled = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, milliseconds) };
    if signalled != WAIT_OBJECT_0 {
        // SAFETY: the transfer belongs to this connection and is cancelled and waited for.
        unsafe {
            CancelIoEx(pipe, overlapped);
            let mut ignored = 0_u32;
            GetOverlappedResult(pipe, overlapped, &raw mut ignored, 1);
        }
        return Err(if signalled == WAIT_TIMEOUT {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "the other end did not answer before the deadline",
            )
        } else {
            io::Error::new(io::ErrorKind::Interrupted, "the service is stopping")
        });
    }
    let mut transferred = 0_u32;
    // SAFETY: the transfer has completed, so the result can be read without waiting.
    if unsafe { GetOverlappedResult(pipe, overlapped, &raw mut transferred, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(transferred)
}

fn overlapped_with(event: &Handle) -> OVERLAPPED {
    // SAFETY: a zeroed record is a valid start; the event is set below.
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = event.raw();
    overlapped
}

impl Read for Connection {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        // SAFETY: an event with no name; a fresh one for each transfer keeps transfers apart.
        let event = Handle::new(
            unsafe { CreateEventW(null(), 1, 0, null()) },
            "making an event",
        )
        .map_err(|error| io::Error::other(error.to_string()))?;
        let mut overlapped = overlapped_with(&event);
        let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        // SAFETY: the buffer and the record outlive the transfer, which `wait` completes or cancels.
        let started = unsafe {
            ReadFile(
                self.pipe.raw(),
                buffer.as_mut_ptr(),
                length,
                null_mut(),
                &raw mut overlapped,
            )
        };
        if started == 0 {
            let failure = io::Error::last_os_error();
            if failure.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                // A client that closed its end reads as the end of the stream.
                return if failure.raw_os_error() == Some(109) {
                    Ok(0)
                } else {
                    Err(failure)
                };
            }
        }
        match wait(
            self.pipe.raw(),
            &mut overlapped,
            &event,
            &self.stop,
            self.deadline,
        ) {
            Ok(count) => Ok(count as usize),
            Err(failure) if failure.raw_os_error() == Some(109) => Ok(0),
            Err(failure) => Err(failure),
        }
    }
}

impl Write for Connection {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        // SAFETY: an event with no name; a fresh one for each transfer keeps transfers apart.
        let event = Handle::new(
            unsafe { CreateEventW(null(), 1, 0, null()) },
            "making an event",
        )
        .map_err(|error| io::Error::other(error.to_string()))?;
        let mut overlapped = overlapped_with(&event);
        let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        // SAFETY: the buffer and the record outlive the transfer, which `wait` completes or cancels.
        let started = unsafe {
            WriteFile(
                self.pipe.raw(),
                buffer.as_ptr(),
                length,
                null_mut(),
                &raw mut overlapped,
            )
        };
        if started == 0 {
            let failure = io::Error::last_os_error();
            if failure.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                return Err(failure);
            }
        }
        wait(
            self.pipe.raw(),
            &mut overlapped,
            &event,
            &self.stop,
            self.deadline,
        )
        .map(|count| count as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Connection {
    /// Sets the time after which a read or a write on this connection stops waiting and fails with
    /// [`io::ErrorKind::TimedOut`]; none waits for as long as the other end takes. It is how a client
    /// holds one absolute deadline over a request and its answer.
    pub fn set_deadline(&mut self, deadline: Option<Instant>) {
        self.deadline = deadline;
    }

    /// The process on the other end of a connection a client made to this server, and the account
    /// and standing of its token.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the caller cannot be identified.
    pub fn identity(&self) -> Result<Identity> {
        let mut pid = 0_u32;
        // SAFETY: the pipe is a connected server end.
        if unsafe { GetNamedPipeClientProcessId(self.pipe.raw(), &raw mut pid) } == 0 {
            return Err(last("identifying the caller's process"));
        }
        // SAFETY: impersonation lasts only until the reversal below, on this thread.
        unsafe {
            if ImpersonateNamedPipeClient(self.pipe.raw()) == 0 {
                return Err(last("impersonating the caller"));
            }
        }
        let mut token: HANDLE = null_mut();
        // SAFETY: the thread's own impersonation token is opened as the service itself.
        let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) };
        let failure = if opened == 0 {
            Some(last("reading the caller's token"))
        } else {
            None
        };
        // SAFETY: reverts this thread to the service's own identity.
        unsafe {
            RevertToSelf();
        }
        if let Some(failure) = failure {
            return Err(failure);
        }
        let token = Handle::new(token, "the caller's token")?;
        let administrators = Sid::parse("S-1-5-32-544")?;
        let mut member = 0;
        // SAFETY: the token is an impersonation token and the identifier is valid.
        unsafe {
            if CheckTokenMembership(token.raw(), administrators.as_ptr(), &raw mut member) == 0 {
                return Err(last("checking the caller's standing"));
            }
        }
        let mut needed = 0_u32;
        // SAFETY: the first call only asks for the size.
        unsafe {
            GetTokenInformation(token.raw(), TokenUser, null_mut(), 0, &raw mut needed);
        }
        let mut buffer = vec![0_u64; (needed as usize).div_ceil(8).max(1)];
        // SAFETY: the buffer is the size the first call asked for and is aligned.
        let user = unsafe {
            if GetTokenInformation(
                token.raw(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &raw mut needed,
            ) == 0
            {
                return Err(last("reading the caller's account"));
            }
            Sid::from_ptr((*buffer.as_ptr().cast::<SID_AND_ATTRIBUTES>()).Sid)
        };
        Ok(Identity {
            pid,
            user,
            administrator: member != 0,
        })
    }
}

/// The pipe the service listens on.
pub struct Listener {
    descriptor: *mut c_void,
    stop: Arc<Stop>,
    next: Option<Handle>,
}

// SAFETY: the descriptor is owned by the listener and only read to make an instance.
unsafe impl Send for Listener {}

impl Drop for Listener {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated by the conversion call and is freed once.
        unsafe {
            LocalFree(self.descriptor);
        }
    }
}

impl Listener {
    /// Makes the first instance of the pipe, refusing when the name is taken.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the name is already in use or the pipe cannot be made.
    pub fn bind(people: &[Sid], stop: Arc<Stop>) -> Result<Listener> {
        let mut list = format!("D:P(A;;GA;;;SY)(A;;{CLIENT_RIGHTS};;;BA)");
        for person in people {
            list.push_str(&format!("(A;;{CLIENT_RIGHTS};;;{})", person.to_text()));
        }
        let text = wide(&list);
        let mut descriptor: *mut c_void = null_mut();
        // SAFETY: the text is NUL-terminated and the descriptor is an out-parameter kept in the
        // listener and freed when it drops.
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &raw mut descriptor,
                null_mut(),
            ) == 0
            {
                return Err(last("reading the pipe's permission list"));
            }
        }
        let mut listener = Listener {
            descriptor,
            stop,
            next: None,
        };
        listener.next = Some(listener.instance(true)?);
        Ok(listener)
    }

    fn instance(&self, first: bool) -> Result<Handle> {
        let name = wide(NAME);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor,
            bInheritHandle: 0,
        };
        let open_mode = PIPE_ACCESS_DUPLEX
            | FILE_FLAG_OVERLAPPED
            | if first {
                FILE_FLAG_FIRST_PIPE_INSTANCE
            } else {
                0
            };
        // SAFETY: the name is NUL-terminated and the attributes outlive the call.
        let pipe = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                MAX_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                &raw const attributes,
            )
        };
        Handle::new(pipe, "making the pipe")
    }

    /// Waits for a client, and returns `None` when the service is told to stop.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the wait fails.
    pub fn accept(&mut self) -> Result<Option<Connection>> {
        let pipe = match self.next.take() {
            Some(pipe) => pipe,
            None => self.instance(false)?,
        };
        // SAFETY: an event with no name.
        let event = Handle::new(
            unsafe { CreateEventW(null(), 1, 0, null()) },
            "making an event",
        )?;
        let mut overlapped = overlapped_with(&event);
        // SAFETY: the pipe is open and the record outlives the wait.
        let connected = unsafe { ConnectNamedPipe(pipe.raw(), &raw mut overlapped) };
        if connected == 0 {
            // SAFETY: reads the calling thread's last error.
            let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if code == ERROR_IO_PENDING {
                match wait(pipe.raw(), &mut overlapped, &event, &self.stop, None) {
                    Ok(_) => {}
                    Err(failure) if failure.kind() == io::ErrorKind::Interrupted => {
                        return Ok(None);
                    }
                    Err(failure) => {
                        return Err(error(
                            failure.raw_os_error().unwrap_or(0) as u32,
                            "waiting for a client",
                        ));
                    }
                }
            } else if code != ERROR_PIPE_CONNECTED {
                return Err(error(code, "waiting for a client"));
            }
        }
        Ok(Some(Connection {
            pipe,
            stop: Arc::clone(&self.stop),
            deadline: None,
        }))
    }
}

/// Connects to the broker's pipe as a client and checks that the process serving it is the one
/// the service manager reports for the service, so a program that took the name first is refused.
///
/// # Errors
///
/// Returns the platform's error when the pipe cannot be opened, or an error when the server is
/// not the expected process.
pub fn connect(expected_server: u32) -> Result<Connection> {
    let name = wide(NAME);
    // SAFETY: the name is NUL-terminated; the client asks for identification only, so the server
    // learns who is calling and cannot act as the caller.
    let pipe = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_IDENTIFICATION,
            null_mut(),
        )
    };
    let pipe = Handle::new(pipe, "opening the broker's pipe")?;
    let mut server = 0_u32;
    // SAFETY: the pipe is a connected client end.
    if unsafe { GetNamedPipeServerProcessId(pipe.raw(), &raw mut server) } == 0 {
        return Err(last("identifying the process that serves the pipe"));
    }
    if server != expected_server {
        return Err(error(
            0,
            format!(
                "the pipe is served by process {server}, not by the service (process {expected_server})"
            ),
        ));
    }
    Ok(Connection {
        pipe,
        stop: Stop::new()?,
        deadline: None,
    })
}
