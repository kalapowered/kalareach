//! The Windows pseudo-console this host owns, the two pipes it talks through, and the shell it
//! starts inside it.
//!
//! This exists for one reason: **a write into the terminal has to answer rather than wait.** The
//! boundary a lease change shares with the writer holds the fence, one write and the accounting for
//! what that write sent, and a write that waited inside it would hold a takeover, a detach and a
//! closure behind an application that had stopped reading. The pseudo-console backend this host
//! would otherwise use creates its pipes with `CreatePipe`, whose writes wait, and a pipe cannot be
//! changed into another mode after it exists. So the pipes are created here: the end this host
//! writes into is put into the mode where a write takes what there is room for and says so, and the
//! end it reads from is overlapped, so the reader waits on its own read rather than asking again on
//! a timer.
//!
//! Everything else follows from owning the pipes: a console has to be created around them, and a
//! shell has to be started inside that console.
//!
//! **None of this has been run.** It is compiled for `x86_64-pc-windows-gnu` in the acceptance, and
//! the runtime proof on Windows belongs to T-024 and T-059, on a machine that has one.

#![cfg(windows)]

use std::io::{Read, Write};
use std::os::windows::io::OwnedHandle;
use std::sync::{Arc, Mutex};

use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, SlavePty};

/// How much each pipe buffers before a write has to wait for the other end.
///
/// The input side never waits - its writes answer - so this is the room one piece of input can
/// find, and what the terminal's output can get ahead by before the read loop is asked again.
const PIPE_BYTES: u32 = 64 * 1024;

/// One read at a time, which is what the read loop asks for.
const READ_BYTES: usize = 64 * 1024;

/// The pseudo-console, with the two ends of the two pipes this host keeps.
pub struct Console {
    console: Arc<handle::PseudoConsole>,
    /// The end this host writes input into. It answers rather than waits.
    input: Mutex<Option<OwnedHandle>>,
    /// The end this host reads output from. It is overlapped.
    output: Arc<OwnedHandle>,
    /// The event a started read is signalled on. The reader reads through it and the waiter waits
    /// on it, which is how one can wait for what the other started.
    event: OwnedHandle,
    size: Mutex<PtySize>,
}

impl std::fmt::Debug for Console {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Console").finish_non_exhaustive()
    }
}

/// Creates a pseudo-console and the pipes this host talks to it through.
///
/// # Errors
///
/// Returns the operating system's failure when a pipe or the console cannot be created.
pub fn open(size: PtySize) -> std::io::Result<(Console, Slave)> {
    let pipes = handle::pipes()?;
    let console = Arc::new(handle::PseudoConsole::new(
        size,
        &pipes.console_input,
        &pipes.console_output,
    )?);
    // The console has copies of its own now. Holding these would keep the terminal alive after the
    // shell exits, so the read loop would never see the end of the output.
    drop(pipes.console_input);
    drop(pipes.console_output);
    let slave = Slave {
        console: Arc::clone(&console),
    };
    Ok((
        Console {
            console,
            input: Mutex::new(Some(pipes.input)),
            output: Arc::new(pipes.output),
            event: handle::event()?,
            size: Mutex::new(size),
        },
        slave,
    ))
}

impl Console {
    /// Returns a view of the event a started read is signalled on.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure when the handle cannot be duplicated.
    pub fn output_event(&self) -> std::io::Result<OwnedHandle> {
        self.event.try_clone()
    }
}

impl MasterPty for Console {
    fn resize(&self, size: PtySize) -> Result<(), anyhow::Error> {
        self.console.resize(size)?;
        *self.size.lock().expect("the recorded size is not poisoned") = size;
        Ok(())
    }

    fn get_size(&self) -> Result<PtySize, anyhow::Error> {
        Ok(*self.size.lock().expect("the recorded size is not poisoned"))
    }

    fn try_clone_reader(&self) -> Result<Box<dyn Read + Send>, anyhow::Error> {
        Ok(Box::new(Reader::over(
            Arc::clone(&self.output),
            self.event.try_clone()?,
        )))
    }

    fn take_writer(&self) -> Result<Box<dyn Write + Send>, anyhow::Error> {
        let handle = self
            .input
            .lock()
            .expect("the terminal's input is not poisoned")
            .take()
            .ok_or_else(|| anyhow::anyhow!("the terminal's writer has already been taken"))?;
        Ok(Box::new(Writer { handle }))
    }
}

/// What starts the root shell inside the pseudo-console.
pub struct Slave {
    console: Arc<handle::PseudoConsole>,
}

impl SlavePty for Slave {
    fn spawn_command(
        &self,
        command: CommandBuilder,
    ) -> Result<Box<dyn Child + Send + Sync>, anyhow::Error> {
        Ok(Box::new(handle::spawn(&self.console, &command)?))
    }
}

/// The end this host writes input into, in the mode where a write answers rather than waits.
struct Writer {
    handle: OwnedHandle,
}

impl Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        handle::write(&self.handle, bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // Nothing is held here: what a write returned is what the terminal took.
        Ok(())
    }
}

/// The end this host reads the terminal's output from, one overlapped read at a time.
///
/// A read that cannot be answered now says so and leaves the read it started with the operating
/// system; the waiter beside it waits on that read's own event, and the next call collects it.
pub struct Reader {
    pending: handle::Pending,
    ready: std::ops::Range<usize>,
}

impl Reader {
    fn over(handle: Arc<OwnedHandle>, event: OwnedHandle) -> Self {
        Self {
            pending: handle::Pending::over(handle, event, READ_BYTES),
            ready: 0..0,
        }
    }
}

impl Read for Reader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.ready.is_empty() {
            self.ready = 0..self.pending.read()?;
        }
        let taken = self.ready.len().min(out.len());
        out[..taken].copy_from_slice(self.pending.taken(self.ready.start, taken));
        self.ready.start += taken;
        Ok(taken)
    }
}

/// Waits until the terminal has output to read.
///
/// It waits on the read the reader started, which is the only thing that says when there is
/// something: a pipe has no readiness of its own to ask about.
#[derive(Debug)]
pub struct OutputWaiter {
    event: OwnedHandle,
}

impl OutputWaiter {
    /// Builds a waiter over the event a started read is signalled on.
    #[must_use]
    pub const fn over(event: OwnedHandle) -> Self {
        Self { event }
    }

    /// Waits until the terminal has output, or until `timeout` passes.
    #[must_use]
    pub fn wait(&self, timeout: std::time::Duration) -> crate::pty::Room {
        match handle::wait(&self.event, timeout) {
            Ok(true) => crate::pty::Room::Ready,
            Ok(false) => crate::pty::Room::NotYet,
            Err(_) => crate::pty::Room::Gone,
        }
    }
}

/// The calls that have no safe form, and the handles they own.
///
/// This crate denies unsafe code and relaxes the rule here and in [`crate::pty::descriptor`] alone.
/// Creating a console and its pipes, driving them without waiting, and starting a process inside
/// the console are all calls with out-parameters and handle ownership that only the caller can
/// promise.
mod handle {
    #![expect(
        unsafe_code,
        reason = "creating and driving a pseudo-console are calls with no safe form"
    )]

    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use std::sync::Arc;

    use portable_pty::{CommandBuilder, ExitStatus, PtySize};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_BROKEN_PIPE, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING,
        ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
        PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND, ReadFile, WriteFile,
    };
    use windows_sys::Win32::System::Console::{
        COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole,
    };
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
        SetNamedPipeHandleState,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_UNICODE_ENVIRONMENT, CreateEventW, CreateProcessW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
        STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
    };

    /// The attribute that puts a new process inside a pseudo-console.
    const PSEUDOCONSOLE_ATTRIBUTE: usize = 0x0002_0016;

    /// The mode the input end is put into: bytes, and a write that answers rather than waits.
    static NOWAIT_MODE: u32 = PIPE_READMODE_BYTE | PIPE_NOWAIT;

    /// The pseudo-console itself.
    pub(super) struct PseudoConsole(HPCON);

    // SAFETY: the console is a handle the operating system owns and serialises for itself. Nothing
    // in this process reaches inside it; every use here is one call with that handle.
    unsafe impl Send for PseudoConsole {}
    // SAFETY: as above.
    unsafe impl Sync for PseudoConsole {}

    impl PseudoConsole {
        /// Creates a console that reads one pipe and writes the other.
        pub(super) fn new(
            size: PtySize,
            input: &OwnedHandle,
            output: &OwnedHandle,
        ) -> std::io::Result<Self> {
            let mut console: HPCON = 0;
            // SAFETY: both handles are open for the call, which takes copies of its own; the
            // out-parameter is a local this thread owns.
            let created = unsafe {
                CreatePseudoConsole(
                    coordinates(size),
                    input.as_raw_handle().cast(),
                    output.as_raw_handle().cast(),
                    0,
                    &raw mut console,
                )
            };
            if created == 0 {
                Ok(Self(console))
            } else {
                Err(std::io::Error::from_raw_os_error(created))
            }
        }

        /// Tells the console its new size.
        pub(super) fn resize(&self, size: PtySize) -> std::io::Result<()> {
            // SAFETY: the console is this object's own and open for the call.
            let resized = unsafe { ResizePseudoConsole(self.0, coordinates(size)) };
            if resized == 0 {
                Ok(())
            } else {
                Err(std::io::Error::from_raw_os_error(resized))
            }
        }
    }

    impl Drop for PseudoConsole {
        fn drop(&mut self) {
            // SAFETY: the console is this object's own, nothing else holds it, and this is its last
            // use.
            unsafe { ClosePseudoConsole(self.0) };
        }
    }

    /// Returns a size the way the console wants it.
    fn coordinates(size: PtySize) -> COORD {
        COORD {
            X: i16::try_from(size.cols).unwrap_or(i16::MAX),
            Y: i16::try_from(size.rows).unwrap_or(i16::MAX),
        }
    }

    /// The four ends of the two pipes a pseudo-console needs.
    pub(super) struct Pipes {
        /// The end this host writes into, which answers rather than waits.
        pub(super) input: OwnedHandle,
        /// The end the console reads its input from.
        pub(super) console_input: OwnedHandle,
        /// The end this host reads from, which is overlapped.
        pub(super) output: OwnedHandle,
        /// The end the console writes its output to.
        pub(super) console_output: OwnedHandle,
    }

    /// Creates both pipes, each end in the mode whoever keeps it needs.
    pub(super) fn pipes() -> std::io::Result<Pipes> {
        let (output, console_output) = pipe(Direction::FromConsole)?;
        let (input, console_input) = pipe(Direction::ToConsole)?;
        // The end this host writes into is what the input boundary depends on: a write that takes
        // what there is room for and says so, rather than one that waits for the application.
        //
        // SAFETY: the handle is this process's own and open for the call; the mode is a local this
        // thread owns, and the two nulls are the documented "leave the rest alone".
        let changed = unsafe {
            SetNamedPipeHandleState(
                input.as_raw_handle().cast(),
                &raw const NOWAIT_MODE,
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if changed == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Pipes {
            input,
            console_input,
            output,
            console_output,
        })
    }

    /// Which way one pipe carries.
    #[derive(Clone, Copy)]
    enum Direction {
        /// The console writes, this host reads.
        FromConsole,
        /// This host writes, the console reads.
        ToConsole,
    }

    /// Creates one pipe and returns this host's end and the console's.
    ///
    /// A named pipe rather than an anonymous one, because only a named pipe can be created
    /// overlapped or put into the mode where a write answers. The name is unique to this process
    /// and this pipe, the instance is the only one that name will ever have, and the console's end
    /// is opened immediately: nothing else can reach a name whose one instance is already taken.
    fn pipe(direction: Direction) -> std::io::Result<(OwnedHandle, OwnedHandle)> {
        let name: Vec<u16> = std::ffi::OsString::from(format!(
            "\\\\.\\pipe\\kr-{}-{}",
            std::process::id(),
            kr_ipc::new_uuid()
        ))
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
        let (access, flags) = match direction {
            Direction::FromConsole => (PIPE_ACCESS_INBOUND, FILE_FLAG_OVERLAPPED),
            Direction::ToConsole => (PIPE_ACCESS_OUTBOUND, 0),
        };
        // SAFETY: the name is a null-terminated wide string that outlives the call and every other
        // argument is a value. The call returns a handle this process owns, or the invalid value.
        let ours = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                access | flags | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                super::PIPE_BYTES,
                super::PIPE_BYTES,
                0,
                std::ptr::null(),
            )
        };
        if ours == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the call reported a handle this process owns and nothing else holds.
        let ours = unsafe { OwnedHandle::from_raw_handle(ours.cast()) };
        let theirs = match direction {
            Direction::FromConsole => GENERIC_WRITE,
            Direction::ToConsole => GENERIC_READ,
        };
        // SAFETY: as above; the name still outlives the call.
        let console = unsafe {
            CreateFileW(
                name.as_ptr(),
                theirs,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if console == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: as above.
        let console = unsafe { OwnedHandle::from_raw_handle(console.cast()) };
        Ok((ours, console))
    }

    /// Writes what the pipe has room for, and says so when that is nothing.
    pub(super) fn write(handle: &OwnedHandle, bytes: &[u8]) -> std::io::Result<usize> {
        let mut written = 0_u32;
        // SAFETY: the handle is open for the call, the slice outlives it, and the count is a local
        // this thread owns. The call writes the count there and reports whether it succeeded.
        let wrote = unsafe {
            WriteFile(
                handle.as_raw_handle().cast(),
                bytes.as_ptr(),
                u32::try_from(bytes.len()).unwrap_or(u32::MAX),
                &raw mut written,
                std::ptr::null_mut(),
            )
        };
        if wrote == 0 {
            // Every failure here is a failure. A pipe in this mode that has no room does not fail:
            // it takes what it can and says how much, which is the short write below. "No data" is
            // this pipe closing, and reading that as no room would leave the writer asking a pipe
            // that has gone, for ever.
            return Err(std::io::Error::last_os_error());
        }
        if written == 0 && !bytes.is_empty() {
            // Nothing fitted. That is the answer the boundary wants: the terminal is there, and it
            // will take more when the application has read what it has.
            return Err(std::io::ErrorKind::WouldBlock.into());
        }
        Ok(written as usize)
    }

    /// A read of the terminal's output: the pipe, the block it is started through, and the memory
    /// it is read into.
    ///
    /// The three are one object because the operating system owns all three for as long as a read
    /// is outstanding. A read still with it when this is dropped is taken back through the **pipe**
    /// - cancelling names the handle the read was started on, not the event it signals - and then
    /// waited for, because cancelling asks and does not wait. Only then can the block and the
    /// buffer be freed.
    pub(super) struct Pending {
        pipe: Arc<OwnedHandle>,
        overlapped: Box<OVERLAPPED>,
        /// Held for as long as the block that names it.
        _event: OwnedHandle,
        buffer: Vec<u8>,
        outstanding: bool,
    }

    // SAFETY: the pipe, the block, the event and the buffer belong to one reader, which owns all of
    // them and is the only thing that starts or collects a read through them. Nothing is shared
    // between threads except by moving the whole reader, which is what `Send` is.
    unsafe impl Send for Pending {}

    impl Pending {
        /// Builds the read: this pipe, signalling this event, into a buffer of this size.
        pub(super) fn over(pipe: Arc<OwnedHandle>, event: OwnedHandle, bytes: usize) -> Self {
            // SAFETY: `OVERLAPPED` is a structure of integers and one handle, and all zeroes is the
            // state the operating system documents for starting a read.
            let mut overlapped: Box<OVERLAPPED> = Box::new(unsafe { std::mem::zeroed() });
            overlapped.hEvent = event.as_raw_handle().cast();
            Self {
                pipe,
                overlapped,
                _event: event,
                buffer: vec![0; bytes],
                outstanding: false,
            }
        }

        /// Returns part of what the last read produced.
        pub(super) fn taken(&self, from: usize, len: usize) -> &[u8] {
            &self.buffer[from..from + len]
        }

        /// Collects the read that was started, or starts one and says there is nothing yet.
        pub(super) fn read(&mut self) -> std::io::Result<usize> {
            if self.outstanding {
                return self.collect(0);
            }
            let mut read = 0_u32;
            // SAFETY: the pipe is open for the call; the buffer and the block outlive the read,
            // because this object owns both and takes the read back before either can be freed.
            let started = unsafe {
                ReadFile(
                    self.pipe.as_raw_handle().cast(),
                    self.buffer.as_mut_ptr(),
                    u32::try_from(self.buffer.len()).unwrap_or(u32::MAX),
                    &raw mut read,
                    std::ptr::from_mut::<OVERLAPPED>(self.overlapped.as_mut()),
                )
            };
            if started == 0 {
                let failure = std::io::Error::last_os_error();
                return match failure
                    .raw_os_error()
                    .and_then(|code| u32::try_from(code).ok())
                {
                    Some(ERROR_IO_PENDING) => {
                        self.outstanding = true;
                        Err(std::io::ErrorKind::WouldBlock.into())
                    }
                    Some(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED) => Ok(0),
                    _ => Err(failure),
                };
            }
            Ok(read as usize)
        }

        /// Asks what the outstanding read has done, waiting for it or not.
        fn collect(&mut self, wait: i32) -> std::io::Result<usize> {
            let mut read = 0_u32;
            // SAFETY: the pipe and the block are the ones the read was started with, and the count
            // is a local this thread owns.
            let finished = unsafe {
                GetOverlappedResult(
                    self.pipe.as_raw_handle().cast(),
                    std::ptr::from_mut::<OVERLAPPED>(self.overlapped.as_mut()),
                    &raw mut read,
                    wait,
                )
            };
            if finished == 0 {
                let failure = std::io::Error::last_os_error();
                return match failure
                    .raw_os_error()
                    .and_then(|code| u32::try_from(code).ok())
                {
                    Some(ERROR_IO_INCOMPLETE) => Err(std::io::ErrorKind::WouldBlock.into()),
                    Some(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED) => {
                        self.outstanding = false;
                        Ok(0)
                    }
                    _ => {
                        self.outstanding = false;
                        Err(failure)
                    }
                };
            }
            self.outstanding = false;
            Ok(read as usize)
        }
    }

    impl Drop for Pending {
        fn drop(&mut self) {
            if !self.outstanding {
                return;
            }
            // The block and the buffer are about to be freed, and the operating system is still
            // writing into them. Cancelling asks; waiting is what makes it true.
            //
            // SAFETY: the pipe is the handle the read was started on and the block is that read's
            // own, both still alive here. A read that has already finished makes this fail rather
            // than act.
            let _ = unsafe {
                CancelIoEx(
                    self.pipe.as_raw_handle().cast(),
                    std::ptr::from_mut::<OVERLAPPED>(self.overlapped.as_mut()),
                )
            };
            let _ = self.collect(1);
        }
    }

    /// Creates the event a read is signalled on.
    ///
    /// Manual reset, because the reader and the waiter both look at it and neither may clear it for
    /// the other; the operating system resets it as each read starts.
    pub(super) fn event() -> std::io::Result<OwnedHandle> {
        // SAFETY: every argument is a value; the call returns a handle this process owns, or null.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the call reported a handle this process owns and nothing else holds.
        Ok(unsafe { OwnedHandle::from_raw_handle(event.cast()) })
    }

    /// Waits until a started read has finished, or until the timeout passes.
    ///
    /// `true` when the read has finished, `false` when it has not yet.
    pub(super) fn wait(event: &OwnedHandle, timeout: std::time::Duration) -> std::io::Result<bool> {
        let milliseconds = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: the handle is an event this process owns and is open for the call.
        let waited = unsafe { WaitForSingleObject(event.as_raw_handle().cast(), milliseconds) };
        match waited {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(std::io::Error::last_os_error()),
        }
    }

    /// The shell this host started inside the console.
    #[derive(Debug)]
    pub(super) struct Spawned {
        process: Arc<OwnedHandle>,
        identifier: u32,
    }

    /// What can end that shell from a thread that is not waiting on it.
    #[derive(Debug)]
    struct Killer(Arc<OwnedHandle>);

    /// Starts a process inside the console.
    ///
    /// The console reaches the child through a process attribute rather than through inherited
    /// standard handles, which is what keeps this host's own handles out of it: nothing is
    /// inherited.
    pub(super) fn spawn(
        console: &PseudoConsole,
        command: &CommandBuilder,
    ) -> std::io::Result<Spawned> {
        let mut line = command_line(command);
        let environment = environment(command);
        let directory: Option<Vec<u16>> = command.get_cwd().map(|cwd| {
            std::path::Path::new(cwd)
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect()
        });

        let mut bytes = 0_usize;
        // The first call asks how much room the list needs and always reports failure; the second
        // builds it.
        //
        // SAFETY: the count is a local this thread owns, and a null list is what asks for the size.
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &raw mut bytes) };
        let mut list = vec![0_u8; bytes];
        let attributes: LPPROC_THREAD_ATTRIBUTE_LIST = list.as_mut_ptr().cast();
        // SAFETY: the buffer is the size the call above asked for and outlives every use below.
        let built = unsafe { InitializeProcThreadAttributeList(attributes, 1, 0, &raw mut bytes) };
        if built == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the list is initialised, the console outlives the process call below, and the
        // size is that handle's own.
        let updated = unsafe {
            UpdateProcThreadAttribute(
                attributes,
                0,
                PSEUDOCONSOLE_ATTRIBUTE,
                console.0 as *const std::ffi::c_void,
                std::mem::size_of::<HPCON>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if updated == 0 {
            let failure = std::io::Error::last_os_error();
            // SAFETY: the list was initialised above and nothing else holds it.
            unsafe { DeleteProcThreadAttributeList(attributes) };
            return Err(failure);
        }

        // SAFETY: `STARTUPINFOEXW` is a structure of integers, pointers and handles, and all zeroes
        // is the documented starting state.
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = u32::try_from(std::mem::size_of::<STARTUPINFOEXW>()).unwrap_or(0);
        startup.lpAttributeList = attributes;
        // SAFETY: as above.
        let mut started: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: every pointer is to a local that outlives the call. The command line is mutable
        // because the call is documented to be allowed to write into it. Nothing is inherited: the
        // console reaches the child through the attribute list.
        let spawned = unsafe {
            CreateProcessW(
                std::ptr::null(),
                line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                directory
                    .as_ref()
                    .map_or(std::ptr::null(), |directory| directory.as_ptr()),
                std::ptr::from_mut(&mut startup).cast(),
                &raw mut started,
            )
        };
        // SAFETY: the list was initialised above, the process no longer needs it, and nothing else
        // holds it.
        unsafe { DeleteProcThreadAttributeList(attributes) };
        if spawned == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the call reported both handles. The thread's is not needed here, and closing it
        // does not end the thread.
        unsafe { CloseHandle(started.hThread) };
        // SAFETY: the process handle is this process's own and nothing else holds it.
        let process = unsafe { OwnedHandle::from_raw_handle(started.hProcess.cast()) };
        Ok(Spawned {
            process: Arc::new(process),
            identifier: started.dwProcessId,
        })
    }

    /// Builds the command line, quoted the way the operating system takes one apart again.
    ///
    /// The rule itself is [`crate::pty::command_line`], which is a rule about a string with nothing
    /// of this platform in it, so it is tested on a machine that cannot run Windows.
    fn command_line(command: &CommandBuilder) -> Vec<u16> {
        std::ffi::OsString::from(crate::pty::command_line(command.get_argv()))
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Builds the environment block: every name and value, and an empty one to end it.
    fn environment(command: &CommandBuilder) -> Vec<u16> {
        let mut block = Vec::new();
        for (name, value) in command.iter_full_env_as_str() {
            block.extend(
                std::ffi::OsString::from(format!("{name}={value}"))
                    .encode_wide()
                    .chain(std::iter::once(0)),
            );
        }
        block.push(0);
        block
    }

    impl portable_pty::ChildKiller for Spawned {
        fn kill(&mut self) -> std::io::Result<()> {
            end(&self.process)
        }

        fn clone_killer(&self) -> Box<dyn portable_pty::ChildKiller + Send + Sync> {
            Box::new(Killer(Arc::clone(&self.process)))
        }
    }

    impl portable_pty::ChildKiller for Killer {
        fn kill(&mut self) -> std::io::Result<()> {
            end(&self.0)
        }

        fn clone_killer(&self) -> Box<dyn portable_pty::ChildKiller + Send + Sync> {
            Box::new(Self(Arc::clone(&self.0)))
        }
    }

    impl portable_pty::Child for Spawned {
        fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
            // Asked rather than waited on, and asked of the process itself: a code read without
            // this cannot tell a process that is still running from one that ended with the code
            // that means "still running".
            //
            // SAFETY: the handle is this object's own and open for the call.
            let waited = unsafe { WaitForSingleObject(self.process.as_raw_handle().cast(), 0) };
            match waited {
                WAIT_TIMEOUT => Ok(None),
                WAIT_OBJECT_0 => status(&self.process).map(Some),
                _ => Err(std::io::Error::last_os_error()),
            }
        }

        fn wait(&mut self) -> std::io::Result<ExitStatus> {
            // SAFETY: as above.
            let waited =
                unsafe { WaitForSingleObject(self.process.as_raw_handle().cast(), INFINITE) };
            if waited == WAIT_OBJECT_0 {
                status(&self.process)
            } else {
                Err(std::io::Error::last_os_error())
            }
        }

        fn process_id(&self) -> Option<u32> {
            Some(self.identifier)
        }

        fn as_raw_handle(&self) -> Option<std::os::windows::io::RawHandle> {
            Some(self.process.as_raw_handle())
        }
    }

    /// Reads the code a process that has ended left.
    fn status(process: &OwnedHandle) -> std::io::Result<ExitStatus> {
        let mut code = 0_u32;
        // SAFETY: the handle is open for the call and the code is a local this thread owns.
        let read = unsafe { GetExitCodeProcess(process.as_raw_handle().cast(), &raw mut code) };
        if read == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(ExitStatus::with_exit_code(code))
    }

    /// Ends a process.
    fn end(process: &OwnedHandle) -> std::io::Result<()> {
        // SAFETY: the handle is open for the call.
        let ended = unsafe { TerminateProcess(process.as_raw_handle().cast(), 1) };
        if ended == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
