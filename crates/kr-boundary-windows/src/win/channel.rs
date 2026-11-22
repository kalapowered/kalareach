//! An invocation's data pipes: the two named pipes that carry Git's standard output and standard
//! error to the client.
//!
//! The broker makes both pipes itself and gives the client only their names. Each is one instance, a
//! first instance, local-only, with an explicit descriptor that lets the person read and no other
//! account open it, boundary accounts included. The server end is the child's standard handle: it is
//! inheritable here, and the launcher's handle list is what lets only the intended child inherit it.
//! A server end made for output can only be written, so the child can neither read its standard
//! output nor write its standard input. The data does not pass through the broker.
//!
//! The server ends are plain, not overlapped: a child writes them with calls that give no overlapped
//! record, and such a call on an overlapped handle is not defined. The broker therefore waits for the
//! client on one thread for each pipe, in a blocking connect that the waiting thread ends with a
//! cancel when the time or the service's stop comes first. Each connection's client is checked against
//! the process the broker holds; a connection from any other process is disconnected and the instance
//! stays, because closing it would free the name for a program that wants it.

#![allow(unsafe_code)]

use std::os::windows::io::AsRawHandle;
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED, GetLastError, HANDLE,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_OUTBOUND,
};
use windows_sys::Win32::System::IO::CancelSynchronousIo;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent};

use crate::channel::{PipeNames, pipe_names};

use super::client::ClientIdentity;
use super::ffi::{self, Handle, Result, error, last, wide};
use super::launch::{LaunchError, OwnedPipeEnd};
use super::pipe::Stop;
use super::sd::{Principals, SdKind, descriptor};

/// How long a cancelled connect is given to end before the wait stops asking for it.
const CANCEL_GRACE: Duration = Duration::from_secs(2);

/// The two server ends of an invocation's data pipes and their names.
#[derive(Debug)]
pub struct DataPipes {
    stdout_server: Handle,
    stderr_server: Handle,
    /// The names the client opens.
    pub names: PipeNames,
    client_pid: u32,
}

/// How the wait for the client's connections ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Both pipes have the retained client connected.
    Connected,
    /// The bound ran out first.
    TimedOut,
    /// The service was told to stop first.
    Stopped,
}

/// 128 random bits from the system's generator.
fn random_bits() -> Result<[u8; 16]> {
    let mut bits = [0_u8; 16];
    // SAFETY: the buffer is local and its length is the one given; no algorithm handle is needed
    // with the system's preferred generator.
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            bits.as_mut_ptr(),
            bits.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        // text: channel_random_bits-1
        return Err(error(status as u32, "making a data pipe's name"));
    }
    Ok(bits)
}

/// Makes one data pipe's server end, with the descriptor for the client.
fn make_server(name: &str, client: &ClientIdentity) -> Result<Handle> {
    let descriptor = descriptor(
        SdKind::DataPipe,
        &Principals {
            client: Some(client.user_sid.clone()),
            ..Principals::default()
        },
    )?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 1,
    };
    let name = wide(name);
    // SAFETY: the name is NUL-terminated and the attributes and the descriptor outlive the call.
    let pipe = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            64 * 1024,
            0,
            0,
            &raw const attributes,
        )
    };
    // text: channel_make_server-1
    Handle::new(pipe, "making a data pipe")
}

/// Makes the two data pipes of an invocation for the client.
///
/// # Errors
///
/// Returns the platform's error when a name cannot be made or a pipe cannot be created; a name that
/// is already taken is refused by the platform.
pub fn make_data_pipes(client: &ClientIdentity) -> Result<DataPipes> {
    let names = pipe_names(random_bits()?);
    let stdout_server = make_server(&names.stdout, client)?;
    let stderr_server = make_server(&names.stderr, client)?;
    Ok(DataPipes {
        stdout_server,
        stderr_server,
        names,
        client_pid: client.pid,
    })
}

/// The process on the other end of a connected server end.
fn client_pid(pipe: HANDLE) -> Result<u32> {
    let mut pid = 0_u32;
    // SAFETY: the pipe is a connected server end.
    if unsafe { GetNamedPipeClientProcessId(pipe, &raw mut pid) } == 0 {
        // text: channel_client_pid-1
        return Err(last(
            "identifying the process that connected to a data pipe",
        ));
    }
    Ok(pid)
}

/// Waits for a client on a plain server end: it returns when one is connected, which is also an
/// answer when it was connected before the call.
fn connect_blocking(pipe: HANDLE) -> Result<()> {
    // SAFETY: the pipe is an open server end made without the overlapped flag, so the call blocks
    // until a client connects or the thread's call is cancelled.
    #[expect(
        clippy::disallowed_methods,
        reason = "the answer is read with the last error: a client that is already connected is told from a failure"
    )]
    let connected = unsafe { ConnectNamedPipe(pipe, null_mut()) };
    if connected != 0 {
        return Ok(());
    }
    // SAFETY: reads the calling thread's last error.
    let code = unsafe { GetLastError() };
    if code == ERROR_PIPE_CONNECTED {
        return Ok(());
    }
    // text: channel_connect-1
    Err(error(
        code,
        "waiting for a client to connect to a data pipe",
    ))
}

/// The body of the thread that waits on one pipe: it takes connections until one comes from the
/// retained client, and disconnects every other, leaving the instance.
fn connect_the_client(pipe: usize, expected: u32, cancelled: &AtomicBool) -> Result<()> {
    let pipe = pipe as HANDLE;
    loop {
        if cancelled.load(Ordering::SeqCst) {
            // text: channel_connect-2
            return Err(error(
                ERROR_OPERATION_ABORTED,
                "waiting for a client to connect to a data pipe",
            ));
        }
        connect_blocking(pipe)?;
        if client_pid(pipe)? == expected {
            return Ok(());
        }
        // SAFETY: the pipe is a connected server end; the instance stays and waits again.
        if unsafe { DisconnectNamedPipe(pipe) } == 0 {
            // text: channel_disconnect-1
            return Err(last("disconnecting a wrong client of a data pipe"));
        }
    }
}

/// One waiting thread, with the event it sets when it ends.
struct Waiter {
    thread: Option<JoinHandle<Result<()>>>,
    done: Handle,
    cancelled: Arc<AtomicBool>,
}

impl Waiter {
    fn start(pipe: &Handle, expected: u32) -> Result<Waiter> {
        // SAFETY: an event with no name, set by hand.
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        // text: channel_waiter-1
        let done = Handle::new(event, "making an event for a data pipe's wait")?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let (pipe, event, flag) = (pipe.raw() as usize, done.raw() as usize, cancelled.clone());
        let thread = std::thread::spawn(move || {
            let result = connect_the_client(pipe, expected, &flag);
            // SAFETY: the event is open until the waiter has joined this thread.
            unsafe {
                SetEvent(event as HANDLE);
            }
            result
        });
        Ok(Waiter {
            thread: Some(thread),
            done,
            cancelled,
        })
    }

    /// Ends the thread's blocking call and joins it, within [`CANCEL_GRACE`].
    fn cancel(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        self.cancelled.store(true, Ordering::SeqCst);
        let until = Instant::now() + CANCEL_GRACE;
        let handle = thread.as_raw_handle();
        while !thread.is_finished() && Instant::now() < until {
            // SAFETY: the handle is the thread's own, valid until the join below. A call that finds
            // no blocking call to cancel (the thread is between two) fails, and the loop asks again.
            unsafe {
                CancelSynchronousIo(handle as HANDLE);
            }
            // text: channel_cancel-1
            let _ = ffi::wait(
                self.done.raw(),
                10,
                "waiting for a cancelled connect to end",
            );
        }
        if thread.is_finished() {
            let _ = thread.join();
        }
    }

    /// The result of a thread that has ended.
    fn result(&mut self) -> Result<()> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        match thread.join() {
            Ok(result) => result,
            // text: channel_waiter-2
            Err(_) => Err(error(0, "waiting for a client to connect to a data pipe")),
        }
    }
}

impl DataPipes {
    /// Waits until the retained client is connected to both pipes, for at most `bound` and until
    /// `stop` is set. A connection from any other process is disconnected and the wait goes on.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when a wait or a connect fails.
    pub fn wait_connected(&self, bound: Duration, stop: &Stop) -> Result<Outcome> {
        let mut waiters = [
            Waiter::start(&self.stdout_server, self.client_pid)?,
            Waiter::start(&self.stderr_server, self.client_pid)?,
        ];
        let until = Instant::now() + bound;
        let mut pending = vec![0_usize, 1];
        let outcome = loop {
            if pending.is_empty() {
                break Ok(Outcome::Connected);
            }
            let events: Vec<HANDLE> = pending.iter().map(|at| waiters[*at].done.raw()).collect();
            let left = until.saturating_duration_since(Instant::now());
            match stop.wait_for(
                &events,
                ffi::milliseconds(left, u32::MAX - 1),
                "waiting for the client to connect to the data pipes",
            ) {
                Ok(ffi::Waited::Signalled(0)) => break Ok(Outcome::Stopped),
                Ok(ffi::Waited::Signalled(number)) => {
                    let at = pending.remove(number - 1);
                    if let Err(failure) = waiters[at].result() {
                        break Err(failure);
                    }
                }
                Ok(ffi::Waited::TimedOut) => break Ok(Outcome::TimedOut),
                Err(failure) => break Err(failure),
            }
        };
        for waiter in &mut waiters {
            waiter.cancel();
        }
        outcome
    }

    /// Gives the two server ends to the launcher as the child's standard output and standard error.
    ///
    /// # Errors
    ///
    /// Returns the launcher's refusal when an end is not inheritable.
    pub fn into_child_ends(self) -> std::result::Result<(OwnedPipeEnd, OwnedPipeEnd), LaunchError> {
        Ok((
            OwnedPipeEnd::new(self.stdout_server)?,
            OwnedPipeEnd::new(self.stderr_server)?,
        ))
    }
}
