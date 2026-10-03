//! Starting an agent on Windows: in its jobs before it runs, with only the handles it is given.
//!
//! Section 7 has every process the worker starts for a session join the session's job before it
//! runs, and an agent also joins a job of its own, so the broker can say which processes are the
//! agent's. The create performs both assignments itself, through the job-list attribute, and the
//! process is created suspended and asked whether each job holds it before its first instruction.
//!
//! What the agent is given is exactly three handles, named by the handle-list attribute: its
//! standard input and output, which are pipes this host keeps the other ends of, and a null device
//! for its standard error. Nothing else this worker holds that could be inherited reaches it, and
//! the ends of the pipes are made inheritable only for the call that creates the process, under
//! one lock that every start this worker makes takes, so that a process started by another part of
//! the worker at the same moment does not hold a stream end either: the reader of a backend's
//! output would never see the end of the file while a stranger held the other end.
//!
//! Only a program can be started. A script, a batch file or anything an interpreter runs is
//! refused by name, because the process that would run is the interpreter, whose identity is not
//! the program's. The command line is built from the program and its arguments by the one quoting
//! rule this host writes every command line with; no caller's text is ever parsed by a shell.

use std::ffi::OsString;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

/// The lock every start of a process takes while this worker's streams are inheritable.
static INHERITING: Mutex<()> = Mutex::new(());

/// Takes the lock a start holds for as long as a handle of this worker's can be inherited.
///
/// A launch makes the ends of the streams it gives the agent inheritable only for the call that
/// creates it, and a process any other part of this worker creates meanwhile would inherit them
/// too. The standard library's own lock is private to its calls, so every start this worker makes
/// takes this one, and only for the call that creates the process: never while it runs.
pub fn inheriting() -> MutexGuard<'static, ()> {
    INHERITING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The longest command line `CreateProcessW` takes, in UTF-16 units, its terminator included.
const MAX_COMMAND_LINE: usize = 32_767;

/// Refuses a program that is not one the operating system starts itself.
///
/// Only `.exe` and `.com` are programs. A batch file is run by `cmd.exe`, a script by its
/// interpreter, and a program a runtime runs by that runtime: the process that starts is the
/// interpreter or the runtime, and its identity is not the program's.
///
/// # Errors
///
/// Returns the reason by name.
pub fn refuse_program(program: &Path) -> Result<(), String> {
    let extension = program
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .map(str::to_ascii_lowercase);
    match extension.as_deref() {
        Some("exe" | "com") => Ok(()),
        Some("cmd" | "bat") => Err(format!(
            "{} is a batch file, which cmd.exe runs, and the process that would start is cmd.exe, \
             not the program",
            program.display()
        )),
        Some("ps1") => Err(format!(
            "{} is a PowerShell script, which an interpreter runs, and the process that would \
             start is the interpreter, not the program",
            program.display()
        )),
        Some("js" | "mjs" | "cjs" | "vbs" | "wsf" | "py") => Err(format!(
            "{} is a script, which a runtime runs, and the process that would start is the \
             runtime, not the program",
            program.display()
        )),
        Some(other) => Err(format!(
            "{} is a .{other} file, and only a .exe or a .com program is started here",
            program.display()
        )),
        None => Err(format!(
            "{} has no extension, and only a .exe or a .com program is started here",
            program.display()
        )),
    }
}

/// Builds the command line a program is started with: the program's path and each argument,
/// quoted so that the program's own parser reads every one of them back whole.
///
/// # Errors
///
/// Returns why the line cannot be made: it is longer than the operating system takes.
pub fn command_line(program: &Path, arguments: &[String]) -> Result<Vec<u16>, String> {
    let mut argv = vec![program.as_os_str().to_owned()];
    argv.extend(arguments.iter().map(OsString::from));
    let line = crate::pty::command_line(&argv);
    let units: Vec<u16> = line.encode_utf16().chain(std::iter::once(0)).collect();
    if units.len() > MAX_COMMAND_LINE {
        return Err(format!(
            "the command line is {} characters, and the most the operating system takes is {}",
            units.len() - 1,
            MAX_COMMAND_LINE - 1
        ));
    }
    Ok(units)
}

/// One environment variable: its name and its value, as UTF-16.
pub type Variable = (Vec<u16>, Vec<u16>);

/// Builds an environment block: the variables of `base` with those of `additions` set over them
/// and sorted by name, which is how the operating system wants them, ending with an empty one.
///
/// Names are compared without regard to case, as the operating system compares them, so an
/// addition replaces the variable it names however that was spelled. The first of the additions
/// that names a variable wins.
#[must_use]
pub fn environment_block(base: Vec<Variable>, additions: Vec<Variable>) -> Vec<u16> {
    fn key(name: &[u16]) -> String {
        String::from_utf16_lossy(name).to_uppercase()
    }
    let mut variables: std::collections::BTreeMap<String, Variable> =
        std::collections::BTreeMap::new();
    for variable in base {
        variables.insert(key(&variable.0), variable);
    }
    let mut added = std::collections::BTreeSet::new();
    for variable in additions {
        let name = key(&variable.0);
        if added.insert(name.clone()) {
            variables.insert(name, variable);
        }
    }
    let mut block = Vec::new();
    for (name, value) in variables.into_values() {
        block.extend(name);
        block.push(u16::from(b'='));
        block.extend(value);
        block.push(0);
    }
    block.push(0);
    block
}

/// Returns the handles a process is to inherit, each once, in the order given.
///
/// A standard output and a standard error that are one handle are listed once: the list refuses a
/// repeated entry as invalid.
#[must_use]
pub fn distinct(handles: &[usize]) -> Vec<usize> {
    let mut listed = Vec::new();
    for handle in handles {
        if !listed.contains(handle) {
            listed.push(*handle);
        }
    }
    listed
}

#[cfg(windows)]
pub use platform::{Child, Spec, StdinPipe, start};

/// The calls with no safe form, and the handles they own.
#[cfg(windows)]
mod platform {
    #![expect(
        unsafe_code,
        reason = "creating a process with an attribute list and driving its pipes are calls with \
                  no safe form"
    )]

    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use std::os::windows::process::ExitStatusExt as _;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, PoisonError, RwLock};

    use windows_sys::Win32::Foundation::{
        ERROR_OPERATION_ABORTED, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    use windows_sys::Win32::System::IO::CancelIoEx;
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
        DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION,
        ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
        UpdateProcThreadAttribute, WaitForSingleObject,
    };

    use super::{Variable, command_line, distinct, environment_block, inheriting, refuse_program};
    use crate::windows::job::{AgentJob, SessionJob};

    /// How much a pipe holds before a write waits.
    const PIPE_BYTES: u32 = 64 * 1024;

    /// How long a process that was created and never resumed is given to end.
    const END_WAIT_MS: u32 = 10_000;

    /// How long a blocked write is cancelled for before the writer is given up on.
    const CLOSE_PATIENCE: std::time::Duration = std::time::Duration::from_secs(10);

    /// What to start, and what to start it in.
    #[derive(Debug)]
    pub struct Spec<'a> {
        /// The program: an absolute path to an `.exe` or a `.com`.
        pub program: &'a Path,
        /// The arguments after the program's own name, as the launch recorded them.
        pub arguments: &'a [String],
        /// The directory it starts in.
        pub directory: &'a Path,
        /// Variables set beside this process's own environment, in addition to it.
        pub environment: &'a [(&'a str, &'a std::ffi::OsStr)],
        /// The session's job, which ends everything in it when it closes. Absent only for a launch
        /// whose profile has been explicitly selected not to be held by one.
        pub session: Option<&'a SessionJob>,
        /// The agent's own job, which lists what the agent started.
        pub agent: &'a AgentJob,
        /// Whether the agent's standard input is a pipe this host writes, and a null device if not.
        pub pipe_input: bool,
        /// Whether the agent's standard output is a pipe this host reads, and a null device if not.
        pub pipe_output: bool,
    }

    /// A process this host started, and the ends of its pipes this host keeps.
    #[derive(Debug)]
    pub struct Child {
        process: OwnedHandle,
        id: u32,
        /// The agent's standard input, where it is a pipe.
        pub stdin: Option<StdinPipe>,
        /// The agent's standard output, where it is a pipe.
        pub stdout: Option<std::fs::File>,
    }

    impl Child {
        /// Returns the process's identifier.
        #[must_use]
        pub const fn id(&self) -> u32 {
            self.id
        }

        /// Returns the handle the process is held by, for as long as this value lives.
        #[must_use]
        pub fn as_raw_handle(&self) -> std::os::windows::io::RawHandle {
            self.process.as_raw_handle()
        }

        /// Ends the process, which a process that has ended already is not a failure of.
        ///
        /// # Errors
        ///
        /// Returns the operating system's failure when a running process cannot be ended.
        pub fn kill(&mut self) -> std::io::Result<()> {
            // SAFETY: the handle is this value's own and open for the call.
            let ended = unsafe { TerminateProcess(self.process.as_raw_handle().cast(), 1) };
            if ended != 0 {
                return Ok(());
            }
            let failure = std::io::Error::last_os_error();
            // A process that has ended already refuses to be ended again, which is the outcome
            // that was wanted.
            match self.try_wait() {
                Ok(Some(_)) => Ok(()),
                _ => Err(failure),
            }
        }

        /// Waits for the process to end.
        ///
        /// # Errors
        ///
        /// Returns the operating system's failure.
        pub fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
            // SAFETY: the handle is this value's own and open for the call.
            let waited =
                unsafe { WaitForSingleObject(self.process.as_raw_handle().cast(), INFINITE) };
            if waited == WAIT_OBJECT_0 {
                self.status()
            } else {
                Err(std::io::Error::last_os_error())
            }
        }

        /// Says whether the process has ended, and how, without waiting.
        ///
        /// # Errors
        ///
        /// Returns the operating system's failure.
        pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
            // SAFETY: as for the wait.
            let waited = unsafe { WaitForSingleObject(self.process.as_raw_handle().cast(), 0) };
            match waited {
                WAIT_TIMEOUT => Ok(None),
                WAIT_OBJECT_0 => self.status().map(Some),
                _ => Err(std::io::Error::last_os_error()),
            }
        }

        fn status(&self) -> std::io::Result<std::process::ExitStatus> {
            let mut code = 0_u32;
            // SAFETY: the handle is open for the call and the code is a local this thread owns.
            let read =
                unsafe { GetExitCodeProcess(self.process.as_raw_handle().cast(), &raw mut code) };
            if read == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(std::process::ExitStatus::from_raw(code))
        }
    }

    /// The write end of an agent's standard input, which what stops the agent can close and a
    /// blocked write cannot hold open.
    ///
    /// A write holds a shared lock for as long as it runs. Closing cancels any write that is
    /// blocked, which ends it with an error, and then takes the lock to close the handle, so no
    /// write is ever on a handle another thread is closing. Two closes are made one after the
    /// other: the cancel of one is never made on a handle the other has closed, whose value the
    /// system may hand to something else.
    #[derive(Clone)]
    pub struct StdinPipe {
        shared: Arc<Shared>,
    }

    struct Shared {
        /// The handle's value, kept for the cancel, which does not take the lock a blocked write
        /// holds. It is used only while `closing` is held, which nothing but a close can end the
        /// handle's life under, so the handle is open.
        raw: AtomicUsize,
        handle: RwLock<Option<OwnedHandle>>,
        /// Held for the whole of a close.
        closing: Mutex<()>,
    }

    impl std::fmt::Debug for StdinPipe {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("StdinPipe")
                .field("open", &(self.shared.raw.load(Ordering::SeqCst) != 0))
                .finish()
        }
    }

    impl StdinPipe {
        fn new(handle: OwnedHandle) -> Self {
            Self {
                shared: Arc::new(Shared {
                    raw: AtomicUsize::new(handle.as_raw_handle() as usize),
                    handle: RwLock::new(Some(handle)),
                    closing: Mutex::new(()),
                }),
            }
        }

        /// Cancels any write that is blocked and closes the pipe, so the agent reads the end of its
        /// input.
        ///
        /// Cancelling is repeated until the lock a write holds is free, because a write that had
        /// not yet begun when one cancel was made is not cancelled by it.
        ///
        /// # Errors
        ///
        /// Returns why a write that was cancelled did not end in time. The pipe is then still
        /// open, and whatever ends the agent ends that write with it.
        pub fn close(&self) -> Result<(), String> {
            let _closing = self
                .shared
                .closing
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let deadline = std::time::Instant::now() + CLOSE_PATIENCE;
            loop {
                if let Ok(mut handle) = self.shared.handle.try_write() {
                    // Dropped here, which closes it.
                    handle.take();
                    self.shared.raw.store(0, Ordering::SeqCst);
                    return Ok(());
                }
                let raw = self.shared.raw.load(Ordering::SeqCst);
                if raw != 0 {
                    // SAFETY: the handle is not closed, because only a close closes it and this
                    // is the one running; a null overlapped cancels every request on the handle.
                    // A handle with nothing pending answers with a failure that is the outcome
                    // wanted.
                    unsafe { CancelIoEx(raw as HANDLE, std::ptr::null()) };
                }
                if std::time::Instant::now() >= deadline {
                    return Err(
                        "a write to the agent's input did not end when it was cancelled".to_owned(),
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }

        /// Returns whether the pipe has been closed.
        #[must_use]
        pub fn is_closed(&self) -> bool {
            self.shared
                .handle
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .is_none()
        }
    }

    impl std::io::Write for StdinPipe {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let guard = self
                .shared
                .handle
                .read()
                .unwrap_or_else(PoisonError::into_inner);
            let Some(handle) = guard.as_ref() else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "the agent's input has been closed",
                ));
            };
            let wanted = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
            let mut written = 0_u32;
            // SAFETY: the handle is open for the call because the lock is held, the buffer is the
            // caller's and at least as long as the length told, and the count is a local.
            let wrote = unsafe {
                WriteFile(
                    handle.as_raw_handle().cast(),
                    bytes.as_ptr(),
                    wanted,
                    &raw mut written,
                    std::ptr::null_mut(),
                )
            };
            if wrote == 0 {
                let failure = std::io::Error::last_os_error();
                return Err(
                    if failure
                        .raw_os_error()
                        .and_then(|code| u32::try_from(code).ok())
                        == Some(ERROR_OPERATION_ABORTED)
                    {
                        std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "the write was cancelled because the agent is being stopped",
                        )
                    } else {
                        failure
                    },
                );
            }
            Ok(usize::try_from(written).unwrap_or(0))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// An anonymous pipe: the end the agent reads, then the end this host writes, or the reverse.
    /// Neither is inheritable until a start makes one so.
    fn pipe() -> std::io::Result<(OwnedHandle, OwnedHandle)> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 0,
        };
        let mut read: HANDLE = std::ptr::null_mut();
        let mut write: HANDLE = std::ptr::null_mut();
        // SAFETY: both out-parameters are locals this thread owns, and the attributes outlive the
        // call.
        let made = unsafe {
            CreatePipe(
                &raw mut read,
                &raw mut write,
                &raw const attributes,
                PIPE_BYTES,
            )
        };
        if made == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the call reported two handles this process owns and nothing else holds.
        Ok(unsafe {
            (
                OwnedHandle::from_raw_handle(read.cast()),
                OwnedHandle::from_raw_handle(write.cast()),
            )
        })
    }

    /// The null device, opened for reading or for writing, and not inheritable.
    fn null_device(for_reading: bool) -> std::io::Result<OwnedHandle> {
        std::fs::OpenOptions::new()
            .read(for_reading)
            .write(!for_reading)
            .open("NUL")
            .map(OwnedHandle::from)
    }

    /// Makes a handle inheritable or not.
    fn set_inheritable(handle: &OwnedHandle, inheritable: bool) -> std::io::Result<()> {
        // SAFETY: the handle is open for the call; the mask and flags are values.
        let set = unsafe {
            SetHandleInformation(
                handle.as_raw_handle().cast(),
                HANDLE_FLAG_INHERIT,
                if inheritable { HANDLE_FLAG_INHERIT } else { 0 },
            )
        };
        if set == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn variable(name: &std::ffi::OsStr, value: &std::ffi::OsStr) -> Variable {
        (name.encode_wide().collect(), value.encode_wide().collect())
    }

    /// Ends a process that was created and never resumed, and says why, and if it cannot be ended,
    /// that too: a suspended process nothing can reach is worse than a launch that failed.
    fn end_unstarted(process: &OwnedHandle, because: &str) -> std::io::Error {
        // SAFETY: the handle is open for the call.
        let ended = unsafe { TerminateProcess(process.as_raw_handle().cast(), 1) };
        if ended == 0 {
            return std::io::Error::other(format!(
                "a process was created and never started, because {because}, and then could not \
                 be ended either: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: as above.
        unsafe { WaitForSingleObject(process.as_raw_handle().cast(), END_WAIT_MS) };
        std::io::Error::other(format!(
            "a process was created and never started, because {because}"
        ))
    }

    /// Starts a program in the jobs the spec names, with the three handles the spec describes.
    ///
    /// # Errors
    ///
    /// Returns why nothing was started: the program is not an executable, the command line is too
    /// long, a stream cannot be made, the create failed, or a job does not hold the process once it
    /// exists, in which case the process is ended and never runs.
    pub fn start(spec: &Spec<'_>) -> std::io::Result<Child> {
        refuse_program(spec.program).map_err(std::io::Error::other)?;
        let mut line = command_line(spec.program, spec.arguments).map_err(std::io::Error::other)?;
        let base: Vec<Variable> = std::env::vars_os()
            .map(|(name, value)| variable(&name, &value))
            .collect();
        let additions: Vec<Variable> = spec
            .environment
            .iter()
            .map(|(name, value)| variable(std::ffi::OsStr::new(name), value))
            .collect();
        let environment = environment_block(base, additions);
        let program = wide(spec.program);
        let directory = wide(spec.directory);

        // The ends the agent is given, and the ends this host keeps.
        let (input, kept_input) = if spec.pipe_input {
            let (read, write) = pipe()?;
            (read, Some(write))
        } else {
            (null_device(true)?, None)
        };
        let (output, kept_output) = if spec.pipe_output {
            let (read, write) = pipe()?;
            (write, Some(read))
        } else {
            (null_device(false)?, None)
        };
        let errors = null_device(false)?;
        let given = [&input, &output, &errors];

        let mut jobs: Vec<HANDLE> = Vec::new();
        if let Some(session) = spec.session {
            jobs.push(session.handle());
        }
        jobs.push(spec.agent.handle());
        let handles: Vec<HANDLE> = distinct(
            &given
                .iter()
                .map(|handle| handle.as_raw_handle() as usize)
                .collect::<Vec<_>>(),
        )
        .into_iter()
        .map(|value| value as HANDLE)
        .collect();

        // The attribute list keeps the pointers it is given, so both arrays are locals that outlive
        // the creation. It is built in memory the size of a pointer apart.
        let mut bytes = 0_usize;
        // SAFETY: the count is a local this thread owns, and a null list is what asks for the size;
        // the call reports failure for it, which is the answer.
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &raw mut bytes) };
        let mut list = vec![0_usize; bytes.div_ceil(std::mem::size_of::<usize>())];
        let attributes: LPPROC_THREAD_ATTRIBUTE_LIST = list.as_mut_ptr().cast();
        // SAFETY: the buffer is at least the size the call above asked for and outlives every use.
        if unsafe { InitializeProcThreadAttributeList(attributes, 2, 0, &raw mut bytes) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let update = |attribute: u32, values: &[HANDLE]| -> std::io::Result<()> {
            // SAFETY: the list is initialised, the array outlives the creation, and the size is
            // that array's own.
            let updated = unsafe {
                UpdateProcThreadAttribute(
                    attributes,
                    0,
                    attribute as usize,
                    values.as_ptr().cast(),
                    std::mem::size_of_val(values),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                )
            };
            if updated == 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        };
        let listed = update(PROC_THREAD_ATTRIBUTE_JOB_LIST, &jobs)
            .and_then(|()| update(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &handles));
        if let Err(failure) = listed {
            // SAFETY: the list was initialised above and nothing else holds it.
            unsafe { DeleteProcThreadAttributeList(attributes) };
            return Err(failure);
        }

        // SAFETY: all zeroes is the documented starting state of a structure of integers, pointers
        // and handles.
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = u32::try_from(std::mem::size_of::<STARTUPINFOEXW>()).unwrap_or(0);
        startup.lpAttributeList = attributes;
        startup.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = input.as_raw_handle().cast();
        startup.StartupInfo.hStdOutput = output.as_raw_handle().cast();
        startup.StartupInfo.hStdError = errors.as_raw_handle().cast();
        // SAFETY: all zeroes is a structure of integers that the call fills in.
        let mut started: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        let created = {
            // Held for the call that creates the process and not a moment longer: while the ends
            // are inheritable, no other start this worker makes may run.
            let _inheriting = inheriting();
            let made_inheritable = given.iter().try_for_each(|end| set_inheritable(end, true));
            let outcome = made_inheritable.and_then(|()| {
                // SAFETY: every pointer is to a local that outlives the call. The command line is
                // mutable because the call may write into it. The handles inherited are the ones
                // the list names and no others.
                let spawned = unsafe {
                    CreateProcessW(
                        program.as_ptr(),
                        line.as_mut_ptr(),
                        std::ptr::null(),
                        std::ptr::null(),
                        1,
                        EXTENDED_STARTUPINFO_PRESENT
                            | CREATE_UNICODE_ENVIRONMENT
                            | CREATE_SUSPENDED
                            | CREATE_NO_WINDOW,
                        environment.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                        directory.as_ptr(),
                        std::ptr::from_mut(&mut startup).cast(),
                        &raw mut started,
                    )
                };
                if spawned == 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
            // Private again whatever happened: a handle left inheritable would reach every start
            // that follows.
            let cleared = given
                .iter()
                .map(|end| set_inheritable(end, false))
                .collect::<Result<Vec<()>, _>>();
            (outcome, cleared)
        };
        // SAFETY: the list was initialised above, the creation no longer needs it, and nothing else
        // holds it.
        unsafe { DeleteProcThreadAttributeList(attributes) };
        let (outcome, cleared) = created;
        outcome?;
        // SAFETY: the call reported both handles, and each is this process's own with nothing else
        // holding it.
        let process = unsafe { OwnedHandle::from_raw_handle(started.hProcess.cast()) };
        // SAFETY: as above.
        let thread = unsafe { OwnedHandle::from_raw_handle(started.hThread.cast()) };
        if let Err(failure) = cleared {
            return Err(end_unstarted(
                &process,
                &format!("a stream end could not be made private again: {failure}"),
            ));
        }
        // The ends this host gave away are closed here, so that what the agent holds is the only
        // other holder: the output's reader sees the end of the file when the agent's last
        // process lets go.
        drop(input);
        drop(output);
        drop(errors);

        // Suspended, so nothing has run yet, and already inside both jobs because the create put it
        // there. The kernel is asked whether each really holds it rather than the creation being
        // taken at its word.
        if let Some(session) = spec.session {
            match session.holds(&process) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(end_unstarted(
                        &process,
                        "the session's job does not hold it",
                    ));
                }
                Err(failure) => {
                    return Err(end_unstarted(
                        &process,
                        &format!("the session's job would not say whether it holds it: {failure}"),
                    ));
                }
            }
        }
        match spec.agent.holds_process(&process) {
            Ok(true) => {}
            Ok(false) => return Err(end_unstarted(&process, "its job does not hold it")),
            Err(failure) => {
                return Err(end_unstarted(
                    &process,
                    &format!("its job would not say whether it holds it: {failure}"),
                ));
            }
        }
        // SAFETY: the thread is the one the call above created, suspended, and this handle is the
        // only one for it.
        if unsafe { ResumeThread(thread.as_raw_handle().cast()) } == u32::MAX {
            let failure = std::io::Error::last_os_error();
            return Err(end_unstarted(
                &process,
                &format!("its thread would not resume: {failure}"),
            ));
        }
        drop(thread);
        Ok(Child {
            process,
            id: started.dwProcessId,
            stdin: kept_input.map(StdinPipe::new),
            stdout: kept_output.map(std::fs::File::from),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn variable(name: &str, value: &str) -> Variable {
        (wide(name), wide(value))
    }

    #[test]
    fn only_an_exe_or_a_com_is_a_program() {
        for accepted in [
            "C:\\bin\\agent.exe",
            "C:\\bin\\AGENT.EXE",
            "C:\\bin\\old.com",
        ] {
            assert_eq!(refuse_program(Path::new(accepted)), Ok(()), "{accepted}");
        }
        for (refused, named) in [
            ("C:\\npm\\codex.cmd", "batch file"),
            ("C:\\npm\\codex.BAT", "batch file"),
            ("C:\\npm\\codex.ps1", "PowerShell script"),
            ("C:\\npm\\codex.js", "runtime"),
            ("C:\\npm\\codex.mjs", "runtime"),
            ("C:\\bin\\agent.dll", ".dll file"),
            ("C:\\bin\\agent", "no extension"),
        ] {
            let why = refuse_program(Path::new(refused)).expect_err(refused);
            assert!(why.contains(named), "{refused}: {why}");
            assert!(why.contains(refused), "{why}");
        }
    }

    #[test]
    fn a_command_line_quotes_the_program_and_each_argument_whole() {
        let line = command_line(
            Path::new("C:\\Program Files\\Agent\\agent.exe"),
            &[
                "plain".to_owned(),
                "a b".to_owned(),
                "c\"d".to_owned(),
                String::new(),
                "x&y".to_owned(),
                "%PATH%".to_owned(),
            ],
        )
        .expect("a line");
        let text = String::from_utf16(&line[..line.len() - 1]).expect("text");
        assert_eq!(
            text,
            "\"C:\\Program Files\\Agent\\agent.exe\" plain \"a b\" \"c\\\"d\" \"\" x&y %PATH%"
        );
        assert_eq!(line.last(), Some(&0), "ended with a terminator");
    }

    #[test]
    fn a_command_line_longer_than_the_operating_system_takes_is_refused_by_length() {
        let long = "x".repeat(40_000);
        let why = command_line(Path::new("C:\\a.exe"), &[long]).expect_err("too long");
        assert!(why.contains("characters"), "{why}");
        let fits = "x".repeat(32_000);
        assert!(command_line(Path::new("C:\\a.exe"), &[fits]).is_ok());
    }

    #[test]
    fn an_environment_block_is_sorted_by_name_and_additions_replace_without_regard_to_case() {
        let block = environment_block(
            vec![
                variable("Path", "C:\\Windows"),
                variable("ZED", "z"),
                variable("alpha", "a"),
            ],
            vec![
                variable("PATH", "C:\\bin"),
                variable("KR_REGISTRATION", "r"),
            ],
        );
        let text = String::from_utf16(&block).expect("text");
        let entries: Vec<&str> = text.split('\0').collect();
        assert_eq!(
            entries,
            [
                "alpha=a",
                "KR_REGISTRATION=r",
                "PATH=C:\\bin",
                "ZED=z",
                "",
                ""
            ],
            "sorted without regard to case, and the addition replaced the variable it names"
        );
        assert_eq!(block.last(), Some(&0));
    }

    #[test]
    fn the_first_addition_to_name_a_variable_wins() {
        let block = environment_block(
            Vec::new(),
            vec![variable("A", "first"), variable("a", "second")],
        );
        let text = String::from_utf16(&block).expect("text");
        assert!(text.starts_with("A=first\0"), "{text:?}");
        assert!(!text.contains("second"), "{text:?}");
    }

    #[test]
    fn handles_are_listed_once_in_the_order_given() {
        assert_eq!(distinct(&[4, 8, 8]), vec![4, 8]);
        assert_eq!(distinct(&[4, 8, 12]), vec![4, 8, 12]);
        assert_eq!(distinct(&[4, 4, 4]), vec![4]);
        assert!(distinct(&[]).is_empty());
    }
}
