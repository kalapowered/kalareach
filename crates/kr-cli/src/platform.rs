//! The one module in this crate that calls the operating system directly.
//!
//! Three things have no safe interface in the standard library, and no higher-level library exposes
//! them in the form this command needs:
//!
//! * **Ignoring the background-write signal.** A guard that restores a terminal acts from the
//!   background, where changing terminal state is stopped by `SIGTTOU`. Catching the signal is not
//!   enough; the call still fails. The disposition has to be `SIG_IGN`, which needs `signal(2)`.
//! * **Reading and restoring a console's exact mode.** The Windows guard carries the mode words
//!   across a process boundary, which the terminal libraries do not expose.
//! * **Waiting for a terminal and a pipe at once.** `select(2)` is the wait that works on every
//!   open of a terminal on macOS, `/dev/tty` included, and the wrapper the system-call library
//!   gives it is unsafe only because it cannot see that the descriptors stay open.
//!
//! Every such call is wrapped once, here, and each wrapper documents what makes its call sound.
//!
//! Two product modules relax the workspace's rule against unsafe code: this one, and
//! `windows::records`, which reads the console's input records on Windows. One unit-test helper,
//! `shell::tests::question_table`, relaxes it for the process that it runs in. Nothing else in the
//! library does, and each integration program under `tests/` that does gives its own reason.

#![expect(
    unsafe_code,
    reason = "signal dispositions, console modes and a wait on descriptors have no safe interface"
)]

/// Ignores the signal that stops a background process from changing the terminal.
///
/// POSIX is explicit: `tcsetattr` from a background process succeeds when `SIGTTOU` is blocked or
/// ignored, and is stopped otherwise. A handler that merely records the signal leaves the call
/// failing, which is why this sets the disposition rather than registering anything.
///
/// # Errors
///
/// Returns the platform's failure when the disposition cannot be set.
#[cfg(unix)]
pub fn ignore_background_write_signal() -> std::io::Result<()> {
    // SAFETY: `SIG_IGN` is a disposition, not a handler function, so nothing runs in a signal
    // context and there is no async-signal-safety obligation to meet. The call has no other
    // effect on this process.
    let previous = unsafe { libc::signal(libc::SIGTTOU, libc::SIG_IGN) };
    if previous == libc::SIG_ERR {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Ends this process the way `signal` would have ended it had nothing handled it: the signal's
/// default action is restored and the signal is sent to this process, so that whatever started it
/// reads a death by that signal and not an exit status.
///
/// Only a process that has caught `signal` and finished what it owed calls this.
#[cfg(unix)]
pub fn end_by_signal(signal: std::os::raw::c_int) -> ! {
    // SAFETY: `SIG_DFL` is a disposition, not a handler function, so nothing runs in a signal
    // context; `raise` sends the signal to this process only.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
    // The signal was blocked or ignored: the conventional status of a process it ended.
    std::process::exit(128 + signal)
}

/// Which of two descriptors a wait found ready to be read.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ready {
    /// The first descriptor can be read, is at its end or has hung up.
    pub first: bool,
    /// The second can.
    pub second: bool,
}

/// Waits until `first` or `second` can be read, which a descriptor at its end or hung up can, and
/// says which can.
///
/// It is `select` and not `poll`. macOS answers a poll of an open of `/dev/tty` at once with an
/// error and no wait, while `select` waits on it as it does on any terminal and wakes together with
/// a pipe, which is what ends a thread that waits for a terminal without a read to cancel.
///
/// # Errors
///
/// Returns the system's failure, an interruption by a signal among them.
#[cfg(unix)]
pub fn wait_until_readable(
    first: std::os::fd::BorrowedFd<'_>,
    second: std::os::fd::BorrowedFd<'_>,
) -> std::io::Result<Ready> {
    use std::os::fd::AsRawFd as _;

    use rustix::event::{FdSetElement, FdSetIter, fd_set_insert, fd_set_num_elements, select};

    let (first_fd, second_fd) = (first.as_raw_fd(), second.as_raw_fd());
    let bound = first_fd.max(second_fd) + 1;
    let mut waiting = vec![FdSetElement::default(); fd_set_num_elements(2, bound)];
    fd_set_insert(&mut waiting, first_fd);
    fd_set_insert(&mut waiting, second_fd);
    // SAFETY: both descriptors are open for the whole call, because the borrows that name them last
    // as long as it does and the set holds no others, and the set has the number of elements
    // `fd_set_num_elements` gives for descriptors below `bound`, which is what `select` is told.
    unsafe { select(bound, Some(&mut waiting), None, None, None) }.map_err(std::io::Error::from)?;
    let ready: Vec<std::os::fd::RawFd> = FdSetIter::new(&waiting).collect();
    Ok(Ready {
        first: ready.contains(&first_fd),
        second: ready.contains(&second_fd),
    })
}

/// Ignores the signal that stops a background process from changing the terminal.
///
/// Windows has no job-control signal: a process that is not in the foreground can still set its
/// console's mode.
///
/// # Errors
///
/// Never fails.
#[cfg(not(unix))]
pub const fn ignore_background_write_signal() -> std::io::Result<()> {
    Ok(())
}

/// Ends the read `thread` is blocked in on the console, so that the thread goes on to see that it
/// has been asked to stop.
///
/// A read of the console's text cannot be woken by anything else the thread waits on. The call is a
/// request: the thread is not joined after it, because a console that did not honour it would hold
/// the joiner for good. It says whether the system took the request, which it does not for a thread
/// paused between two calls, and which does not say how the read ended: a read can end by itself as
/// the request arrives.
#[cfg(not(unix))]
pub fn cancel_blocked_read<T>(thread: &std::thread::JoinHandle<T>) -> bool {
    use std::os::windows::io::AsRawHandle as _;

    // SAFETY: the handle is the thread's own, kept open by the `JoinHandle` this borrows, and the
    // call only asks the system to end that thread's pending synchronous I/O.
    unsafe {
        windows_sys::Win32::System::IO::CancelSynchronousIo(thread.as_raw_handle().cast()) != 0
    }
}

/// How long a wait for a reader thread lasts, when it first asks for the read to be cancelled and
/// how often it looks again.
#[cfg(any(not(unix), test))]
#[derive(Clone, Copy, Debug)]
pub struct Schedule {
    /// The longest the wait lasts.
    pub wait: std::time::Duration,
    /// How long the wait lets the thread end by itself before it first asks for its read to be
    /// cancelled.
    pub cancel_after: std::time::Duration,
    /// How long the wait sleeps between two looks at the thread, which is how often a read that is
    /// still blocked has its cancel asked again.
    pub pause: std::time::Duration,
}

/// What a wait for a reader thread found.
#[cfg(any(not(unix), test))]
#[derive(Debug)]
pub struct Waited<T> {
    /// Whether the thread had not ended when the wait did, so that what it holds is not counted.
    pub still_running: bool,
    /// Whether the wait asked for a read to be cancelled and the system took the request. A read can
    /// end by itself as the request arrives, so it does not say that the request was needed.
    pub cancel_asked: bool,
    /// What the thread returned, once it had ended, and nothing for a thread that was still running
    /// or that panicked.
    pub result: Option<T>,
}

/// Waits for `thread`, which reads the console and has been told to stop, to end, and asks `cancel`
/// to end the read it may be blocked in, again and again, until the thread has ended or the wait
/// is over.
///
/// A read of the console's text is ended by nothing the thread waits on besides, and a cancel is a
/// request that can miss a thread between two reads, so it is repeated. The thread is joined only
/// once it has ended: a console that does not honour the request would hold a joiner for good, and
/// a thread still running when the wait is over is left, which the answer says.
#[cfg(any(not(unix), test))]
pub fn wait_for_a_blocked_reader<T>(
    thread: std::thread::JoinHandle<T>,
    schedule: Schedule,
    cancel: &dyn Fn(&std::thread::JoinHandle<T>) -> bool,
) -> Waited<T> {
    let started = std::time::Instant::now();
    let deadline = started + schedule.wait;
    let cancel_from = started + schedule.cancel_after;
    let mut cancel_asked = false;
    while !thread.is_finished() {
        let now = std::time::Instant::now();
        if now >= deadline {
            return Waited {
                still_running: true,
                cancel_asked,
                result: None,
            };
        }
        if now >= cancel_from {
            cancel_asked |= cancel(&thread);
        }
        std::thread::sleep(schedule.pause);
    }
    Waited {
        still_running: false,
        cancel_asked,
        result: thread.join().ok(),
    }
}

#[cfg(windows)]
pub use protection::ProtectionCalls;

/// Protects this process from other programs of the account: the access lists of its token, its
/// process and its threads, as [`crate::backup::protect`] says, and the settings that keep a crash
/// from making a report. The token it opened stays open for as long as the answer is kept.
///
/// # Errors
///
/// Returns the refusal when a list cannot be set or reads back other than it was set, or when a
/// debugger is attached.
#[cfg(windows)]
pub fn protect_this_process()
-> Result<crate::backup::protect::Protected<ProtectionCalls>, crate::backup::protect::Refusal> {
    crate::backup::protect::apply(ProtectionCalls { token: None })
}

#[cfg(windows)]
mod protection {
    use std::io;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, HANDLE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        GetSecurityInfo, SE_KERNEL_OBJECT, SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetLengthSid, GetTokenInformation,
        PROTECTED_DACL_SECURITY_INFORMATION, SetTokenInformation, TOKEN_ADJUST_DEFAULT,
        TOKEN_DEFAULT_DACL, TOKEN_QUERY, TOKEN_USER, TokenDefaultDacl, TokenUser,
    };
    use windows_sys::Win32::System::Diagnostics::Debug::{
        CheckRemoteDebuggerPresent, EXCEPTION_POINTERS, IsDebuggerPresent, SetErrorMode,
        SetUnhandledExceptionFilter,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentProcessId, GetProcessIdOfThread, OpenProcessToken, OpenThread,
        TerminateProcess,
    };

    use crate::backup::protect::{Calls, Entry, List, Open, Previous, acl_image, entries_of};

    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
    const SEM_FAILCRITICALERRORS: u32 = 0x0001;
    const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;
    const SEM_NOOPENFILEERRORBOX: u32 = 0x8000;

    /// The system's calls for the protection of this process.
    pub struct ProtectionCalls {
        /// The process token, opened once and held to the end of the command.
        pub(super) token: Option<OwnedHandle>,
    }

    /// A thread of this process, open.
    pub struct OpenedThread(OwnedHandle);

    fn checked(ok: i32) -> io::Result<()> {
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn status(code: u32) -> io::Result<()> {
        if code == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(
                i32::try_from(code).unwrap_or(i32::MAX),
            ))
        }
    }

    /// The bytes copied into words, so that a structure with pointers in it can be read from them.
    fn aligned(bytes: &[u8]) -> Vec<u64> {
        bytes
            .chunks(8)
            .map(|chunk| {
                let mut word = [0_u8; 8];
                word[..chunk.len()].copy_from_slice(chunk);
                u64::from_ne_bytes(word)
            })
            .collect()
    }

    /// The entries of the list that `acl` points to, and none for no list.
    ///
    /// # Safety
    ///
    /// `acl` is null or points to a whole access list that stays valid for the call.
    unsafe fn entries_at(acl: *const ACL) -> io::Result<List> {
        if acl.is_null() {
            return Ok(Vec::new());
        }
        // SAFETY: the caller says the list is whole, and its header says how large it is.
        let image =
            unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), usize::from((*acl).AclSize)) };
        entries_of(image).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "an access list that is not a list",
            )
        })
    }

    /// Reads the information of `class` that the token holds, in words that suit a pointer.
    fn token_information(token: HANDLE, class: i32) -> io::Result<Vec<u64>> {
        let mut length = 0_u32;
        // SAFETY: the call is asked only how much room it needs; the handle is open.
        unsafe { GetTokenInformation(token, class, null_mut(), 0, &raw mut length) };
        let mut buffer = vec![0_u64; usize::try_from(length).unwrap_or(0).div_ceil(8).max(1)];
        // SAFETY: the buffer has at least the room that the system asked for.
        checked(unsafe {
            GetTokenInformation(
                token,
                class,
                buffer.as_mut_ptr().cast(),
                length,
                &raw mut length,
            )
        })?;
        Ok(buffer)
    }

    fn set_security(handle: HANDLE, list: &[Entry]) -> io::Result<()> {
        let image = aligned(&acl_image(list));
        // SAFETY: the handle is open with the right to change the list, and the list is a whole
        // image that stays alive for the call.
        status(unsafe {
            SetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                image.as_ptr().cast(),
                null(),
            )
        })
    }

    fn get_security(handle: HANDLE) -> io::Result<List> {
        let mut acl: *mut ACL = null_mut();
        let mut descriptor = null_mut();
        // SAFETY: the handle is open with the right to read the list, and the pointers are slots.
        status(unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &raw mut acl,
                null_mut(),
                &raw mut descriptor,
            )
        })?;
        // SAFETY: the list lives in the descriptor that the system allocated, which is let go of
        // only after the entries are copied out.
        let list = unsafe { entries_at(acl) };
        // SAFETY: the descriptor was allocated by the call above for the caller to free.
        unsafe { LocalFree(descriptor) };
        list
    }

    fn own_token(held: &Option<OwnedHandle>) -> io::Result<HANDLE> {
        held.as_ref()
            .map(|token| token.as_raw_handle().cast())
            .ok_or_else(|| io::Error::other("the token was not opened"))
    }

    /// Ends the process at once on an unhandled exception that reaches the filter, so that no
    /// report is made of it.
    unsafe extern "system" fn end_at_once(_exception: *const EXCEPTION_POINTERS) -> i32 {
        // SAFETY: the pseudo-handle of this process always names it.
        unsafe { TerminateProcess(GetCurrentProcess(), 1) };
        0
    }

    impl Calls for ProtectionCalls {
        type Thread = OpenedThread;

        fn account(&mut self) -> io::Result<Vec<u8>> {
            let mut token: HANDLE = null_mut();
            // SAFETY: the pseudo-handle of this process needs no close and the pointer is a slot.
            checked(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) })?;
            // SAFETY: the handle was just opened and nothing else owns it.
            let token = unsafe { OwnedHandle::from_raw_handle(token.cast()) };
            let buffer = token_information(token.as_raw_handle().cast(), TokenUser)?;
            // SAFETY: the buffer holds a `TOKEN_USER`, whose identifier lies in the same buffer.
            let identifier = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
            // SAFETY: the identifier is whole, and the call only reads it.
            let length = unsafe { GetLengthSid(identifier) } as usize;
            // SAFETY: as above, for as many bytes as the identifier says it has.
            Ok(unsafe { std::slice::from_raw_parts(identifier.cast::<u8>(), length) }.to_vec())
        }

        fn suppress_crash_reports(&mut self) -> Previous {
            // SAFETY: the calls take flags and a filter that lives as long as the process.
            let error_mode = unsafe {
                SetErrorMode(
                    SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX,
                )
            };
            // SAFETY: as above.
            let before = unsafe { SetUnhandledExceptionFilter(Some(end_at_once)) };
            Previous {
                error_mode,
                filter: before.map_or(0, |filter| filter as usize),
            }
        }

        fn open_token(&mut self) -> io::Result<()> {
            let mut token: HANDLE = null_mut();
            // SAFETY: the pseudo-handle needs no close and the pointer is a slot. The handle is not
            // inheritable, and is kept in `self` until the command ends.
            checked(unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | READ_CONTROL | WRITE_DAC,
                    &raw mut token,
                )
            })?;
            // SAFETY: the handle was just opened and nothing else owns it.
            self.token = Some(unsafe { OwnedHandle::from_raw_handle(token.cast()) });
            Ok(())
        }

        fn set_default_list(&mut self, list: &[Entry]) -> io::Result<()> {
            let token = own_token(&self.token)?;
            let image = aligned(&acl_image(list));
            let information = TOKEN_DEFAULT_DACL {
                DefaultDacl: image.as_ptr().cast_mut().cast(),
            };
            // SAFETY: the token is open for the change and the structure points into a whole list
            // that stays alive for the call.
            checked(unsafe {
                SetTokenInformation(
                    token,
                    TokenDefaultDacl,
                    (&raw const information).cast(),
                    u32::try_from(std::mem::size_of::<TOKEN_DEFAULT_DACL>()).unwrap_or(0),
                )
            })
        }

        fn default_list(&mut self) -> io::Result<List> {
            let buffer = token_information(own_token(&self.token)?, TokenDefaultDacl)?;
            // SAFETY: the buffer holds a `TOKEN_DEFAULT_DACL` whose list lies in the same buffer.
            unsafe { entries_at((*buffer.as_ptr().cast::<TOKEN_DEFAULT_DACL>()).DefaultDacl) }
        }

        fn set_token_list(&mut self, list: &[Entry]) -> io::Result<()> {
            set_security(own_token(&self.token)?, list)
        }

        fn token_list(&mut self) -> io::Result<List> {
            get_security(own_token(&self.token)?)
        }

        fn set_process_list(&mut self, list: &[Entry]) -> io::Result<()> {
            // SAFETY: the pseudo-handle of this process always has the rights the call needs.
            set_security(unsafe { GetCurrentProcess() }, list)
        }

        fn process_list(&mut self) -> io::Result<List> {
            // SAFETY: as above.
            get_security(unsafe { GetCurrentProcess() })
        }

        fn thread_ids(&mut self) -> io::Result<Vec<u32>> {
            // SAFETY: the call takes integers and returns a handle or an invalid value.
            let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
            if snapshot.is_null() || snapshot as isize == -1 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the snapshot is open and nothing else owns it.
            let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot.cast()) };
            // SAFETY: the structure is plain data that the calls fill.
            let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
            entry.dwSize = u32::try_from(std::mem::size_of::<THREADENTRY32>()).unwrap_or(0);
            // SAFETY: the call takes no arguments.
            let own = unsafe { GetCurrentProcessId() };
            let mut ids = Vec::new();
            // SAFETY: the snapshot is open and the pointer is a live structure.
            let mut more =
                unsafe { Thread32First(snapshot.as_raw_handle().cast(), &raw mut entry) } != 0;
            while more {
                if entry.th32OwnerProcessID == own {
                    ids.push(entry.th32ThreadID);
                }
                // SAFETY: as above.
                more =
                    unsafe { Thread32Next(snapshot.as_raw_handle().cast(), &raw mut entry) } != 0;
            }
            Ok(ids)
        }

        fn open_thread(&mut self, id: u32, to_write: bool) -> io::Result<Open<OpenedThread>> {
            let rights = READ_CONTROL
                | THREAD_QUERY_LIMITED_INFORMATION
                | if to_write { WRITE_DAC } else { 0 };
            // SAFETY: the call takes integers and returns a handle or null.
            let handle = unsafe { OpenThread(rights, 0, id) };
            if handle.is_null() {
                let error = io::Error::last_os_error();
                return match u32::try_from(error.raw_os_error().unwrap_or(0)) {
                    Ok(ERROR_ACCESS_DENIED) => Ok(Open::Denied),
                    Ok(ERROR_INVALID_PARAMETER) => Ok(Open::Gone),
                    _ => Err(error),
                };
            }
            // SAFETY: the handle was just opened and nothing else owns it.
            Ok(Open::Opened(OpenedThread(unsafe {
                OwnedHandle::from_raw_handle(handle.cast())
            })))
        }

        fn thread_is_ours(&mut self, thread: &OpenedThread) -> io::Result<bool> {
            // SAFETY: the handle is open with the query right the call needs.
            let owner = unsafe { GetProcessIdOfThread(thread.0.as_raw_handle().cast()) };
            if owner == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the call takes no arguments.
            Ok(owner == unsafe { GetCurrentProcessId() })
        }

        fn set_thread_list(&mut self, thread: &OpenedThread, list: &[Entry]) -> io::Result<()> {
            set_security(thread.0.as_raw_handle().cast(), list)
        }

        fn thread_list(&mut self, thread: &OpenedThread) -> io::Result<List> {
            get_security(thread.0.as_raw_handle().cast())
        }

        fn debugger_present(&mut self) -> bool {
            // SAFETY: the call takes no arguments.
            if unsafe { IsDebuggerPresent() } != 0 {
                return true;
            }
            let mut attached = 0_i32;
            // SAFETY: the pseudo-handle names this process and the pointer is a slot.
            let asked =
                unsafe { CheckRemoteDebuggerPresent(GetCurrentProcess(), &raw mut attached) };
            asked != 0 && attached != 0
        }
    }
}

#[cfg(not(unix))]
pub use console::{ControllingTerminal, SavedModes};

#[cfg(not(unix))]
mod console {
    use std::fs::File;

    use kr_client::shown::Shown;

    use crate::error::{CliError, Result};
    use crate::terminal::{KeyboardState, Probe, RESET_SEQUENCES, ScreenModes, TerminalSize};

    /// A handle on this process's console.
    ///
    /// Windows has no controlling terminal and no `termios`. What it has is a console whose input
    /// and output modes are read and set through the console API, and that pair of mode words is
    /// the state a guard restores.
    pub struct ControllingTerminal {
        input: File,
        output: File,
        /// The console's input mode when the attachment began, which the console is given back
        /// with the mouse: whether it had quick edit on, and whether it reported its private flags.
        attached_input: std::sync::atomic::AtomicU32,
    }

    impl ControllingTerminal {
        /// Opens this process's console.
        ///
        /// # Errors
        ///
        /// Returns [`CliError::NotATerminal`] when this process has no console.
        pub fn open() -> Result<Self> {
            let input = File::options()
                .read(true)
                .write(true)
                .open("CONIN$")
                .map_err(|_| CliError::NotATerminal)?;
            let output = File::options()
                .read(true)
                .write(true)
                .open("CONOUT$")
                .map_err(|_| CliError::NotATerminal)?;
            Ok(Self {
                input,
                output,
                attached_input: std::sync::atomic::AtomicU32::new(0),
            })
        }

        /// Returns the console's input handle, which is the one bytes are read from. Nothing is
        /// written to it: a console takes written bytes on its output handle.
        #[must_use]
        pub const fn handle(&self) -> &File {
            &self.input
        }

        /// Returns the console's output handle.
        #[must_use]
        pub const fn output(&self) -> &File {
            &self.output
        }

        /// Reads the console's current modes.
        ///
        /// # Errors
        ///
        /// Returns an error when the console will not answer.
        pub fn modes(&self) -> Result<SavedModes> {
            Ok(SavedModes {
                input: console_mode(&self.input)?,
                output: console_mode(&self.output)?,
            })
        }

        /// Reads the console's size.
        ///
        /// # Errors
        ///
        /// Returns an error when the console will not answer.
        pub fn size(&self) -> Result<TerminalSize> {
            let info = self.buffer_info("read the console's size: the console did not answer")?;
            let columns = info.srWindow.Right.saturating_sub(info.srWindow.Left) + 1;
            let rows = info.srWindow.Bottom.saturating_sub(info.srWindow.Top) + 1;
            Ok(TerminalSize {
                columns: u16::try_from(columns).unwrap_or(80),
                rows: u16::try_from(rows).unwrap_or(24),
            })
        }

        /// What the console says of its screen buffer and its window, or `failure` when it says
        /// nothing.
        fn buffer_info(
            &self,
            failure: &'static str,
        ) -> Result<windows_sys::Win32::System::Console::CONSOLE_SCREEN_BUFFER_INFO> {
            use std::os::windows::io::AsRawHandle as _;

            let mut info = windows_sys::Win32::System::Console::CONSOLE_SCREEN_BUFFER_INFO {
                dwSize: windows_sys::Win32::System::Console::COORD { X: 0, Y: 0 },
                dwCursorPosition: windows_sys::Win32::System::Console::COORD { X: 0, Y: 0 },
                wAttributes: 0,
                srWindow: windows_sys::Win32::System::Console::SMALL_RECT {
                    Left: 0,
                    Top: 0,
                    Right: 0,
                    Bottom: 0,
                },
                dwMaximumWindowSize: windows_sys::Win32::System::Console::COORD { X: 0, Y: 0 },
            };
            if unsafe_free_get_console_screen_buffer_info(
                self.output.as_raw_handle(),
                &raw mut info,
            ) {
                Ok(info)
            } else {
                Err(CliError::Terminal(Shown::said(failure)))
            }
        }

        /// The part of the console's screen buffer its window shows.
        ///
        /// A mouse record's position is counted in the screen buffer, and what an application is
        /// told is counted in the window.
        ///
        /// # Errors
        ///
        /// Returns an error when the console will not answer.
        pub fn window(&self) -> Result<crate::mouse::Window> {
            let info =
                self.buffer_info("read where the console's window is: the console did not answer")?;
            let extent = |from: i16, to: i16| {
                u16::try_from(i32::from(to) - i32::from(from) + 1).unwrap_or(0)
            };
            Ok(crate::mouse::Window {
                left: info.srWindow.Left,
                top: info.srWindow.Top,
                columns: extent(info.srWindow.Left, info.srWindow.Right),
                rows: extent(info.srWindow.Top, info.srWindow.Bottom),
            })
        }

        /// Gives the mouse to the session's application while it asks to be told of it, and back to
        /// the console, which selects text with it, when it stops asking.
        ///
        /// The mode is changed from the one the console has now, so a console that has been asked
        /// to spell its keys itself goes on spelling them, and quick edit comes back only if the
        /// console had it when the attachment began. A console that reported none of its private
        /// flags then is given none: only the mouse flag is set, and cleared again.
        ///
        /// # Errors
        ///
        /// Returns an error when the console's input mode cannot be read or set.
        pub fn report_mouse(&self, asked: bool) -> Result<()> {
            use std::sync::atomic::Ordering::SeqCst;

            let current = console_mode(&self.input)?;
            set_console_mode(
                &self.input,
                crate::mouse::mouse_input_mode(current, self.attached_input.load(SeqCst), asked),
            )
        }

        /// Throws away what has been typed and not yet read.
        ///
        /// # Errors
        ///
        /// Returns an error when the console will not do it.
        pub fn discard_input(&self) -> Result<()> {
            use std::os::windows::io::AsRawHandle as _;

            if unsafe_free_flush_console_input(self.input.as_raw_handle()) {
                Ok(())
            } else {
                Err(CliError::Terminal(Shown::said(
                    "discard the console's queued input: the console refused",
                )))
            }
        }

        /// Whether all three standard handles of this process are consoles. A pseudo-terminal of
        /// the MSYS or Cygwin kind passes the standard library's terminal check and is not one, and
        /// `CONOUT$` could name a console other than the one the command's output goes to.
        #[must_use]
        pub fn standard_handles_are_a_console() -> bool {
            use windows_sys::Win32::System::Console::{
                GetConsoleMode, GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
            };

            [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE]
                .into_iter()
                .all(|which| {
                    let mut mode = 0_u32;
                    // SAFETY: the call takes a constant and returns a handle or an invalid value,
                    // and the mode call is given that handle and a live `u32`.
                    unsafe { GetConsoleMode(GetStdHandle(which), &raw mut mode) != 0 }
                })
        }

        /// Puts the console into the modes a line dialogue needs, and returns what it replaced:
        /// line input, echo and processed input, so that a console another program left raw reads
        /// lines and takes Ctrl-C; processed output on and the output's own return at a line feed
        /// back, so that a line feed does not leave the next line where the last one ended.
        ///
        /// # Errors
        ///
        /// Returns an error when the modes cannot be read or set. A console whose output mode
        /// cannot be set is given its input mode back first, so a failure leaves it as it was.
        pub fn enter_dialogue_modes(&self) -> Result<SavedModes> {
            use windows_sys::Win32::System::Console::{
                DISABLE_NEWLINE_AUTO_RETURN, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
                ENABLE_PROCESSED_INPUT, ENABLE_PROCESSED_OUTPUT,
            };

            let saved = self.modes()?;
            set_console_mode(
                &self.input,
                saved.input | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT,
            )?;
            let output = (saved.output | ENABLE_PROCESSED_OUTPUT) & !DISABLE_NEWLINE_AUTO_RETURN;
            if let Err(error) = set_console_mode(&self.output, output) {
                let _ = set_console_mode(&self.input, saved.input);
                return Err(error);
            }
            Ok(saved)
        }

        /// Puts back both mode words and nothing else: no sequence is written, because a console
        /// without virtual-terminal output would show one as text. Both are attempted, and the first
        /// failure is the answer.
        ///
        /// # Errors
        ///
        /// Returns an error when either mode cannot be set.
        pub fn put_modes_back(&self, saved: &SavedModes) -> Result<()> {
            let input = set_console_mode(&self.input, saved.input);
            let output = set_console_mode(&self.output, saved.output);
            input.and(output)
        }

        /// Puts the console into the mode a command that reads bytes needs, and returns what it
        /// replaced.
        ///
        /// Keys come back as the console's own virtual-terminal sequences.
        ///
        /// # Errors
        ///
        /// Returns an error when the modes cannot be read or set. A console whose output mode
        /// cannot be set is given its input mode back first, so a failure leaves it as it was.
        pub fn enter_raw_mode(&self) -> Result<SavedModes> {
            use windows_sys::Win32::System::Console::{
                ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
                ENABLE_VIRTUAL_TERMINAL_INPUT,
            };

            self.enter_mode(|saved| {
                (saved & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT))
                    | ENABLE_VIRTUAL_TERMINAL_INPUT
            })
        }

        /// What makes this console spell its keys itself: its virtual-terminal input, which turns
        /// the keys into the sequences a terminal sends. It is asked for on the mode the console
        /// has then, and put back with the rest when the attachment ends.
        ///
        /// # Errors
        ///
        /// Returns an error when the console's input handle cannot be duplicated.
        pub fn input_switch(&self) -> Result<crate::attach::InputSwitch> {
            use windows_sys::Win32::System::Console::ENABLE_VIRTUAL_TERMINAL_INPUT;

            let input = self
                .input
                .try_clone()
                .map_err(|error| CliError::Terminal(Shown::io(&error)))?;
            Ok(crate::attach::InputSwitch::new(move || {
                let mode = console_mode(&input)?;
                set_console_mode(&input, mode | ENABLE_VIRTUAL_TERMINAL_INPUT)
            }))
        }

        /// Puts the console into the mode an attachment needs, and returns what it replaced.
        ///
        /// Keys come back as the records the console reports them as, with no translation into
        /// sequences: the session spells them as its terminal asked for.
        ///
        /// # Errors
        ///
        /// As [`Self::enter_raw_mode`].
        pub fn enter_record_mode(&self) -> Result<SavedModes> {
            self.enter_mode(crate::mouse::record_input_mode)
        }

        /// Sets the input mode `input` makes of the one the console has and the output mode a
        /// forwarded terminal needs.
        fn enter_mode(&self, input: impl FnOnce(u32) -> u32) -> Result<SavedModes> {
            use windows_sys::Win32::System::Console::{
                DISABLE_NEWLINE_AUTO_RETURN, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
            };

            let saved = self.modes()?;
            self.attached_input
                .store(saved.input, std::sync::atomic::Ordering::SeqCst);
            let raw_output =
                saved.output | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
            set_console_mode(&self.input, input(saved.input))?;
            if let Err(error) = set_console_mode(&self.output, raw_output) {
                let _ = set_console_mode(&self.input, saved.input);
                return Err(error);
            }
            Ok(saved)
        }

        /// Restores saved modes and undoes the modes an application may have left enabled.
        ///
        /// `keyboard` is what this console had negotiated before the attachment began, written
        /// back as the state it is, and `screen` is the mouse, cursor and paste state it reported.
        /// A console answers for neither, so both are usually empty here and the reset block is the
        /// whole restoration.
        ///
        /// When the attachment has set the output mode, the sequences are written while it still
        /// holds, with virtual-terminal processing on, and only then is the console's own output
        /// mode put back: a console that had no such processing would print them as text. Before
        /// the attachment sets it, the console's own mode holds throughout.
        ///
        /// # Errors
        ///
        /// Returns an error when the modes cannot be set.
        pub fn restore(
            &self,
            saved: &SavedModes,
            keyboard: Option<&KeyboardState>,
            screen: &ScreenModes,
        ) -> Result<()> {
            use std::io::Write as _;

            set_console_mode(&self.input, saved.input)?;
            let mut handle = &self.output;
            let _ = handle.write_all(RESET_SEQUENCES);
            let _ = handle.write_all(&screen.restore_sequences());
            if let Some(keyboard) = keyboard {
                let _ = handle.write_all(&keyboard.cleanup_sequences());
            }
            let _ = handle.flush();
            set_console_mode(&self.output, saved.output)
        }

        /// Runs the bounded capability handshake.
        ///
        /// The console host answers neither keyboard query: the Kitty protocol and
        /// `modifyOtherKeys` are terminal protocols, and the console mode has no equivalent to
        /// read. An attachment here therefore has nothing to put back, and the clearing in
        /// [`RESET_SEQUENCES`] is the whole restoration.
        ///
        /// # Errors
        ///
        /// Returns [`crate::CliError::TerminalProbeFailed`] on a stream a previous probe
        /// contaminated, which is the same refusal the other platform gives: a console that was
        /// never asked anything is still a console whose input may hold a late reply.
        pub fn probe(
            &self,
            context: kr_term::probe::InputContext,
            _profile: Option<&str>,
        ) -> Result<Probe> {
            Probe::unasked(context)
        }

        /// The same answer for a caller with its own questions: this console is asked none of them.
        ///
        /// # Errors
        ///
        /// Returns [`CliError::TerminalProbeFailed`] when a probe has already gone out here.
        pub fn probe_asking(
            &self,
            context: kr_term::probe::InputContext,
            _asked: &[kr_term::probe::ProbeItem],
        ) -> Result<Probe> {
            Probe::unasked(context)
        }

        /// What this console declares itself to be.
        ///
        /// The terminfo name its environment gives it, when there is one: a person who sets `TERM`
        /// has said what their terminal is, and that name is declared with what it claims, although
        /// this command reads the keys as console key records whatever `TERM` says. A console sets
        /// none, and an attachment that declares nothing is refused the input lease, so a console
        /// then names itself. The declaration is made only here, where this command has read the
        /// console's input and output modes and will put them back, and the console's own name
        /// claims no more than the keys this command reads can produce: console key records, which
        /// the session spells in the ordinary encoding.
        #[must_use]
        pub fn profile(&self) -> Option<String> {
            let term = std::env::var("TERM").ok();
            Some(kr_term::win32::console_declaration(term.as_deref()).to_owned())
        }

        /// A name for this console that no other console shares while it exists.
        ///
        /// The console host has no device path and no session identifier of the kind a terminal
        /// has, so there is nothing here to name one by. A probe is never sent to it, so nothing
        /// needs the name.
        #[must_use]
        pub const fn identity(&self) -> Option<String> {
            None
        }
    }

    /// A console's complete state: the input mode and the output mode.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SavedModes {
        /// The console input mode.
        pub input: u32,
        /// The console output mode.
        pub output: u32,
    }

    impl SavedModes {
        /// Returns the state as it already is.
        ///
        /// The console reports its modes as two words, so reading them and saving them are the
        /// same step; the Unix side has to extract its state from a larger structure, which is why
        /// both platforms answer the same call.
        #[must_use]
        pub const fn from_state(modes: &Self) -> Self {
            *modes
        }

        /// Renders the state as one argument.
        #[must_use]
        pub fn encode(&self) -> String {
            format!("{:x}:{:x}", self.input, self.output)
        }

        /// Parses the state back.
        ///
        /// # Errors
        ///
        /// Returns an error when the text is not two hexadecimal words.
        pub fn decode(text: &str) -> Result<Self> {
            let mut parts = text.split(':');
            let mut next = || -> Result<u32> {
                let part = parts.next().ok_or_else(|| {
                    CliError::Terminal(Shown::said("the saved console state is incomplete"))
                })?;
                u32::from_str_radix(part, 16).map_err(|_| {
                    CliError::Terminal(Shown::said("the saved console state is not hexadecimal"))
                })
            };
            let modes = Self {
                input: next()?,
                output: next()?,
            };
            if parts.next().is_some() {
                return Err(CliError::Terminal(Shown::said(
                    "the saved console state has more fields than expected",
                )));
            }
            Ok(modes)
        }
    }

    fn console_mode(handle: &File) -> Result<u32> {
        use std::os::windows::io::AsRawHandle as _;

        let mut mode = 0_u32;
        if unsafe_free_get_console_mode(handle.as_raw_handle(), &raw mut mode) {
            Ok(mode)
        } else {
            Err(CliError::Terminal(Shown::said(
                "read the console's mode: the console did not answer",
            )))
        }
    }

    fn set_console_mode(handle: &File, mode: u32) -> Result<()> {
        use std::os::windows::io::AsRawHandle as _;

        if unsafe_free_set_console_mode(handle.as_raw_handle(), mode) {
            Ok(())
        } else {
            Err(CliError::Terminal(Shown::said(
                "set the console's mode: the console refused",
            )))
        }
    }

    // The three console calls this module needs, each wrapped once. The wrappers exist so the
    // pointer handling is in one place rather than at every call site.
    fn unsafe_free_get_console_mode(handle: std::os::windows::raw::HANDLE, mode: *mut u32) -> bool {
        // SAFETY: `handle` comes from an open console file and `mode` points at a live `u32`.
        unsafe { windows_sys::Win32::System::Console::GetConsoleMode(handle.cast(), mode) != 0 }
    }

    fn unsafe_free_set_console_mode(handle: std::os::windows::raw::HANDLE, mode: u32) -> bool {
        // SAFETY: `handle` comes from an open console file.
        unsafe { windows_sys::Win32::System::Console::SetConsoleMode(handle.cast(), mode) != 0 }
    }

    fn unsafe_free_flush_console_input(handle: std::os::windows::raw::HANDLE) -> bool {
        // SAFETY: `handle` comes from an open console file.
        unsafe { windows_sys::Win32::System::Console::FlushConsoleInputBuffer(handle.cast()) != 0 }
    }

    fn unsafe_free_get_console_screen_buffer_info(
        handle: std::os::windows::raw::HANDLE,
        info: *mut windows_sys::Win32::System::Console::CONSOLE_SCREEN_BUFFER_INFO,
    ) -> bool {
        // SAFETY: `handle` comes from an open console file and `info` points at a live structure.
        unsafe {
            windows_sys::Win32::System::Console::GetConsoleScreenBufferInfo(handle.cast(), info)
                != 0
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    use super::{Schedule, wait_for_a_blocked_reader};

    fn schedule(wait: u64, cancel_after: u64) -> Schedule {
        Schedule {
            wait: Duration::from_millis(wait),
            cancel_after: Duration::from_millis(cancel_after),
            pause: Duration::from_millis(5),
        }
    }

    /// A thread that ends by itself before the cancel is first asked is joined and has no cancel
    /// asked.
    #[test]
    fn a_thread_that_ends_by_itself_is_joined_and_no_cancel_is_asked() {
        let asked = AtomicUsize::new(0);
        let thread = std::thread::spawn(|| 7);
        let waited = wait_for_a_blocked_reader(thread, schedule(2_000, 1_000), &|_| {
            asked.fetch_add(1, Ordering::SeqCst);
            true
        });
        assert!(!waited.still_running);
        assert!(!waited.cancel_asked);
        assert_eq!(waited.result, Some(7));
        assert_eq!(asked.load(Ordering::SeqCst), 0);
    }

    /// A thread blocked in a read has the cancel asked again and again, and ends once one is taken.
    #[test]
    fn a_blocked_thread_has_its_cancel_asked_until_it_ends() {
        let released = Arc::new(AtomicBool::new(false));
        let asked = AtomicUsize::new(0);
        let blocked = Arc::clone(&released);
        let thread = std::thread::spawn(move || {
            while !blocked.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
            "read ended"
        });
        let waited = wait_for_a_blocked_reader(thread, schedule(5_000, 0), &|_| {
            // The third request is the one the read honours: the first two miss it.
            if asked.fetch_add(1, Ordering::SeqCst) == 2 {
                released.store(true, Ordering::SeqCst);
            }
            true
        });
        assert!(!waited.still_running);
        assert!(waited.cancel_asked);
        assert_eq!(waited.result, Some("read ended"));
        assert!(asked.load(Ordering::SeqCst) >= 3);
    }

    /// The cancel is not asked before the thread has had its time to end by itself.
    #[test]
    fn the_first_cancel_waits_for_its_time() {
        let (ended, wait) = mpsc::channel::<()>();
        let asked = AtomicUsize::new(0);
        let thread = std::thread::spawn(move || {
            let _ = wait.recv_timeout(Duration::from_millis(150));
        });
        let waited = wait_for_a_blocked_reader(thread, schedule(2_000, 1_000), &|_| {
            asked.fetch_add(1, Ordering::SeqCst);
            true
        });
        drop(ended);
        assert!(!waited.still_running);
        assert_eq!(
            asked.load(Ordering::SeqCst),
            0,
            "no cancel in the first second"
        );
    }

    /// A thread that does not end within the wait is left, and the wait says so, without joining it.
    #[test]
    fn a_thread_that_never_ends_is_left_when_the_wait_is_over() {
        let release = Arc::new(AtomicBool::new(false));
        let held = Arc::clone(&release);
        let thread = std::thread::spawn(move || {
            while !held.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        let started = std::time::Instant::now();
        let waited = wait_for_a_blocked_reader(thread, schedule(100, 0), &|_| false);
        release.store(true, Ordering::SeqCst);
        assert!(waited.still_running);
        assert!(!waited.cancel_asked, "the system took no request");
        assert!(waited.result.is_none());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
