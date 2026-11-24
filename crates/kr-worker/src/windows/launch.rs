//! Starting an agent on Windows: in its jobs before it runs, with only the handles it is given.
//!
//! Section 7 has every process the worker starts for a session join the session's job before it
//! runs, and an agent also joins a job of its own, so the broker can say which processes are the
//! agent's. The create performs both assignments itself, through the job-list attribute, and the
//! process is created suspended and asked whether each job holds it before its first instruction.
//!
//! What the agent is given is exactly three handles, named by the handle-list attribute: its
//! standard input, output and error, each a null device, a blocking pipe this host keeps the other
//! end of, or an overlapped one the runtime reads and writes. Nothing else this worker holds that
//! could be inherited reaches it, and the ends of the pipes are made inheritable only for the call
//! that creates the process, under one lock that every start this worker makes takes, so that a
//! process started by another part of the worker at the same moment does not hold a stream end
//! either: the reader of a backend's output would never see the end of the file while a stranger
//! held the other end.
//!
//! An overlapped stream is a named pipe made private at its creation, because a name can be opened
//! by any process that knows it: the name has random bits in it, the access list names this account
//! alone, there is one instance, and this worker's own client takes that instance before the agent
//! exists. What opens the pipe in the interval is refused by name and the start goes no further.
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

/// A complete environment: every variable a process is started with, and no other.
///
/// Starting a process adds nothing to it and reads no variable of this worker's own, so the
/// process sees exactly these variables. A caller that wants this worker's variables builds them in
/// with [`Environment::of_this_process_with`]; one that presents a set gives that set.
///
/// Names are compared as the operating system compares them, without regard to case, so a set holds
/// one variable for each name however it is spelled, and the variables are kept in the order the
/// system wants them in a block.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Environment {
    /// The variables, by the upper-cased text of their names.
    variables: std::collections::BTreeMap<String, Variable>,
}

/// The key a name is compared and sorted by: its text, upper-cased.
fn name_key(name: &[u16]) -> String {
    String::from_utf16_lossy(name).to_uppercase()
}

/// Refuses a variable the operating system could not read back as it was given, by its name.
///
/// A name holds no `=` but a first one, which cmd.exe's per-drive folders (`=C:`) begin with, and
/// has something after it; a NUL ends the text the system reads, in a name and in a value alike.
/// The refusal names the variable and never says its value.
fn refuse_variable((name, value): &Variable) -> Result<(), String> {
    let shown = String::from_utf16_lossy(name);
    if name.is_empty() {
        return Err("an environment variable has an empty name".to_owned());
    }
    if name.contains(&0) {
        return Err(format!(
            "the environment variable {shown:?} has a NUL in its name"
        ));
    }
    let equals = u16::from(b'=');
    let plain = name.strip_prefix(&[equals]).unwrap_or(name);
    if plain.is_empty() {
        return Err(format!(
            "the environment variable {shown:?} has no name after its first ="
        ));
    }
    if plain.contains(&equals) {
        return Err(format!(
            "the environment variable {shown:?} has a = in its name, which only its first \
             character may be"
        ));
    }
    if value.contains(&0) {
        return Err(format!(
            "the environment variable {shown:?} has a NUL in its value"
        ));
    }
    Ok(())
}

impl Environment {
    /// Builds the environment `variables` are, refusing a set that cannot be one: a name that is
    /// empty, holds a NUL or a `=` other than its first character, a NUL in a value, or one
    /// variable named twice however the spellings differ in case.
    ///
    /// # Errors
    ///
    /// Returns the refusal, which names the variable and never its value.
    pub fn from_variables(variables: Vec<Variable>) -> Result<Self, String> {
        let mut set = Self::default();
        for variable in variables {
            refuse_variable(&variable)?;
            let name = String::from_utf16_lossy(&variable.0);
            if let Some(first) = set.variables.insert(name_key(&variable.0), variable) {
                return Err(format!(
                    "the environment names one variable twice, as {:?} and as {name:?}",
                    String::from_utf16_lossy(&first.0),
                ));
            }
        }
        Ok(set)
    }

    /// Builds the environment of `base` with `additions` set over it: an addition replaces the
    /// variable it names however that was spelled, and the first of the additions to name a
    /// variable wins.
    ///
    /// # Errors
    ///
    /// Returns the refusal of the first variable, in `base` or in `additions`, that cannot be one.
    pub fn merged(base: Vec<Variable>, additions: Vec<Variable>) -> Result<Self, String> {
        let mut set = Self::default();
        for variable in base {
            refuse_variable(&variable)?;
            set.variables.insert(name_key(&variable.0), variable);
        }
        let mut added = std::collections::BTreeSet::new();
        for variable in additions {
            refuse_variable(&variable)?;
            let key = name_key(&variable.0);
            if added.insert(key.clone()) {
                set.variables.insert(key, variable);
            }
        }
        Ok(set)
    }

    /// This environment less the variables `names` name, compared without regard to case.
    #[must_use]
    pub fn without(&self, names: &[&str]) -> Self {
        let mut set = self.clone();
        for name in names {
            let units: Vec<u16> = name.encode_utf16().collect();
            set.variables.remove(&name_key(&units));
        }
        set
    }

    /// How many variables it holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.variables.len()
    }

    /// Whether it holds no variable.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.variables.is_empty()
    }

    /// The value of the variable `name` names, compared without regard to case.
    #[must_use]
    pub fn value_of(&self, name: &str) -> Option<&[u16]> {
        let units: Vec<u16> = name.encode_utf16().collect();
        self.variables
            .get(&name_key(&units))
            .map(|(_, value)| value.as_slice())
    }

    /// The block `CreateProcessW` takes: each variable as `name=value` ending in a NUL, sorted by
    /// name, and one NUL more to end the block.
    ///
    /// An empty environment has no entry for that last NUL to follow, and the system reads a block
    /// that holds none as two NULs, so it is written as two.
    #[must_use]
    pub fn block(&self) -> Vec<u16> {
        let mut block = Vec::new();
        for (name, value) in self.variables.values() {
            block.extend(name);
            block.push(u16::from(b'='));
            block.extend(value);
            block.push(0);
        }
        if block.is_empty() {
            block.push(0);
        }
        block.push(0);
        block
    }
}

impl std::fmt::Debug for Environment {
    /// How many variables it holds and no more: what a person keeps in their environment is shown
    /// to nothing.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Environment({} variables)", self.variables.len())
    }
}

/// Which way the bytes of one of an agent's streams go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// The agent reads and this worker writes: its standard input.
    ToAgent,
    /// The agent writes and this worker reads: its standard output and its standard error.
    FromAgent,
}

/// The name of the pipe made for one stream of a server this worker starts: the worker's own
/// process identifier and 128 random bits, which no other process can guess.
#[must_use]
pub fn pipe_name(worker: u32, random: [u8; 16]) -> String {
    use std::fmt::Write as _;

    let mut name = format!(r"\\.\pipe\kr-server-{worker}-");
    for byte in random {
        let _ = write!(name, "{byte:02x}");
    }
    name
}

/// The security descriptor a private pipe is created with: an access list that no parent's list
/// can add to (protected) and that holds one entry, full control for the account `sid` names.
#[must_use]
pub fn private_descriptor(sid: &str) -> String {
    format!("D:P(A;;GA;;;{sid})")
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
pub(crate) use platform::end_process;
#[cfg(all(windows, feature = "testing"))]
pub use platform::seams;
#[cfg(windows)]
pub use platform::{Child, Spec, StdinPipe, Stdio, available, start, start_within};

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

    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::{
        DuplicateHandle, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_OPERATION_ABORTED,
        ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE, HANDLE, HANDLE_FLAG_INHERIT,
        INVALID_HANDLE_VALUE, LocalFree, STILL_ACTIVE, SetHandleInformation, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetTokenInformation,
        PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
    };
    use windows_sys::Win32::System::IO::CancelIoEx;
    use windows_sys::Win32::System::Pipes::{
        CreatePipe, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, PeekNamedPipe,
    };
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
        DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
        GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList,
        LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
        UpdateProcThreadAttribute, WaitForSingleObject,
    };

    use super::{
        Direction, Environment, Variable, command_line, distinct, inheriting, pipe_name,
        private_descriptor, refuse_program,
    };
    use crate::windows::job::{AgentJob, SessionJob};

    /// How much a pipe holds before a write waits.
    const PIPE_BYTES: u32 = 64 * 1024;

    /// How long a process that was asked to end is given to end, or to show that it is ending.
    const END_WAIT_MS: u32 = 10_000;

    /// How long the handle of a process is waited on before its exit status is read again. A
    /// status sets no signal, so a process that is ending is seen by one or the other.
    const STATUS_SLICE_MS: u32 = 10;

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
        /// The whole environment the process starts with. Nothing of this worker's own is added to
        /// it: a caller that wants this worker's variables builds them in.
        pub environment: &'a Environment,
        /// The session's job, which ends everything in it when it closes. Absent only for a launch
        /// whose profile has been explicitly selected not to be held by one.
        pub session: Option<&'a SessionJob>,
        /// The agent's own job, which lists what the agent started.
        pub agent: &'a AgentJob,
        /// What the agent's standard input is.
        pub stdin: Stdio,
        /// What the agent's standard output is.
        pub stdout: Stdio,
        /// What the agent's standard error is.
        pub stderr: Stdio,
    }

    /// What one of an agent's streams is, and what this host keeps of it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Stdio {
        /// The null device: nothing to read and nowhere to write, and this host keeps nothing.
        Null,
        /// An anonymous pipe whose other end this host reads or writes with blocking calls.
        Blocking,
        /// A private named pipe whose other end this host reads or writes through the runtime. A
        /// start that makes one has to run where a tokio runtime is entered.
        Overlapped,
    }

    /// A process this host started, and the ends of its pipes this host keeps.
    #[derive(Debug)]
    pub struct Child {
        process: OwnedHandle,
        id: u32,
        /// The agent's standard input, where it is a blocking pipe.
        pub stdin: Option<StdinPipe>,
        /// The agent's standard output, where it is a blocking pipe.
        pub stdout: Option<std::fs::File>,
        /// The agent's standard error, where it is a blocking pipe.
        pub stderr: Option<std::fs::File>,
        /// The agent's standard input, where it is an overlapped pipe.
        pub overlapped_stdin: Option<NamedPipeServer>,
        /// The agent's standard output, where it is an overlapped pipe.
        pub overlapped_stdout: Option<NamedPipeServer>,
        /// The agent's standard error, where it is an overlapped pipe.
        pub overlapped_stderr: Option<NamedPipeServer>,
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

        /// Ends the process, which a process that has ended already, or is ending, is not a
        /// failure of.
        ///
        /// # Errors
        ///
        /// Returns the operating system's failure when a running process cannot be ended.
        pub fn kill(&mut self) -> std::io::Result<()> {
            end_process(&self.process)
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

        /// Waits up to `timeout` for the process to end, and says how it ended, or nothing if it is
        /// still running when the time is up.
        ///
        /// # Errors
        ///
        /// Returns the operating system's failure.
        pub fn wait_for(
            &mut self,
            timeout: std::time::Duration,
        ) -> std::io::Result<Option<std::process::ExitStatus>> {
            let millis = u32::try_from(timeout.as_millis())
                .unwrap_or(u32::MAX)
                .min(INFINITE - 1);
            // SAFETY: the handle is this value's own and open for the call.
            let waited =
                unsafe { WaitForSingleObject(self.process.as_raw_handle().cast(), millis) };
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

    /// How many bytes the blocking pipe `pipe` holds to be read now, which a read takes without
    /// waiting; none means nothing yet, and nothing means its other end has closed and the end of
    /// the file is the next read.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure.
    pub fn available(pipe: &std::fs::File) -> std::io::Result<Option<u32>> {
        let mut count = 0_u32;
        // SAFETY: the handle is open for the call; the count is a local this thread owns, and the
        // call is asked for nothing else.
        let peeked = unsafe {
            PeekNamedPipe(
                pipe.as_raw_handle().cast(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &raw mut count,
                std::ptr::null_mut(),
            )
        };
        if peeked != 0 {
            return Ok(Some(count));
        }
        let failure = std::io::Error::last_os_error();
        if failure.raw_os_error().map(i32::cast_unsigned) == Some(ERROR_BROKEN_PIPE) {
            Ok(None)
        } else {
            Err(failure)
        }
    }

    /// Ends the process `process` is a handle to, which a process that has ended already, or is
    /// ending, is not a failure of.
    ///
    /// A process that has ended already refuses to be ended again, and so does one that is ending,
    /// whether it was ended or ended itself: it is not signalled until its last thread has gone,
    /// but it has its exit status from the moment it begins to end. Between the two, while another
    /// thread is taking the process's end in hand and has not yet recorded its status, the process
    /// refuses and shows neither: that refusal is waited out until one of the two appears. Either
    /// is the outcome that was wanted. A process that is running has no status and is not
    /// signalled, and its refusal is a failure once the wait has run out. A process that [`start`]
    /// created, one that was created and never resumed, and the shell in the console are ended
    /// here, so the rule is one rule for them.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure when a running process cannot be ended.
    pub(crate) fn end_process(process: &OwnedHandle) -> std::io::Result<()> {
        end_process_within(
            process,
            std::time::Duration::from_millis(u64::from(END_WAIT_MS)),
        )
    }

    /// Ends the process as [`end_process`] does, waiting no longer than `patience` for a process
    /// that refuses and shows no sign of ending.
    fn end_process_within(
        process: &OwnedHandle,
        patience: std::time::Duration,
    ) -> std::io::Result<()> {
        // SAFETY: the handle is the caller's own and open for the call.
        let ended = unsafe { TerminateProcess(process.as_raw_handle().cast(), 1) };
        if ended != 0 {
            return Ok(());
        }
        let failure = std::io::Error::last_os_error();
        if ends_within(process, patience) {
            Ok(())
        } else {
            Err(failure)
        }
    }

    /// Says whether the process has ended or is ending, or does within `patience`.
    ///
    /// The wait is on the process's handle, so an end is seen the moment the process is signalled,
    /// and the exit status is read again after each slice, because a status is no object to wait
    /// on.
    fn ends_within(process: &OwnedHandle, patience: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + patience;
        loop {
            if has_exit_status(process) {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            // SAFETY: the handle is the caller's own and open for the call.
            unsafe { WaitForSingleObject(process.as_raw_handle().cast(), STATUS_SLICE_MS) };
        }
    }

    /// Says whether the process has ended or is ending.
    ///
    /// While a process runs the system reports a status of its own, which a process may also end
    /// with, so a process that is signalled is ended whatever it reports.
    fn has_exit_status(process: &OwnedHandle) -> bool {
        // SAFETY: the handle is the caller's own and open for the call.
        let signalled =
            unsafe { WaitForSingleObject(process.as_raw_handle().cast(), 0) } == WAIT_OBJECT_0;
        let mut code = 0_u32;
        // SAFETY: as above, and the code is a local this thread owns.
        let read = unsafe { GetExitCodeProcess(process.as_raw_handle().cast(), &raw mut code) };
        signalled || (read != 0 && code.cast_signed() != STILL_ACTIVE)
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

    /// What this host keeps of a stream: nothing, an end it calls blocking, or one the runtime drives.
    enum Kept {
        Nothing,
        Blocking(OwnedHandle),
        Overlapped(NamedPipeServer),
    }

    impl Kept {
        /// The kept end as a file and as an overlapped end: one of them at most.
        fn files(self) -> (Option<std::fs::File>, Option<NamedPipeServer>) {
            match self {
                Self::Nothing => (None, None),
                Self::Blocking(handle) => (Some(std::fs::File::from(handle)), None),
                Self::Overlapped(server) => (None, Some(server)),
            }
        }
    }

    /// The end a stream gives the agent, and what this host keeps of it.
    fn stream(kind: Stdio, direction: Direction) -> std::io::Result<(OwnedHandle, Kept)> {
        match kind {
            Stdio::Null => Ok((null_device(direction == Direction::ToAgent)?, Kept::Nothing)),
            Stdio::Blocking => {
                let (read, write) = pipe()?;
                Ok(match direction {
                    Direction::ToAgent => (read, Kept::Blocking(write)),
                    Direction::FromAgent => (write, Kept::Blocking(read)),
                })
            }
            Stdio::Overlapped => {
                let (worker, agent) = overlapped_pipe(direction)?;
                Ok((agent, Kept::Overlapped(worker)))
            }
        }
    }

    /// Memory the system allocated, freed when this is dropped.
    struct Local(*mut std::ffi::c_void);

    impl Drop for Local {
        fn drop(&mut self) {
            // SAFETY: the pointer is the system's own allocation, which nothing else frees.
            unsafe { LocalFree(self.0) };
        }
    }

    /// The account this process runs as, read from its token.
    struct OwnSid {
        /// The buffer holding the token's user, aligned for it.
        buffer: Vec<u64>,
    }

    impl OwnSid {
        fn read() -> std::io::Result<Self> {
            let mut token: HANDLE = std::ptr::null_mut();
            // SAFETY: the pseudo-handle names this process, and the token is a local this thread
            // owns.
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: the call reported a token this process owns and nothing else holds.
            let token = unsafe { OwnedHandle::from_raw_handle(token.cast()) };
            let mut needed = 0_u32;
            // SAFETY: a null buffer of no size asks for the size, which the call reports as a
            // failure; the count is a local this thread owns.
            unsafe {
                GetTokenInformation(
                    token.as_raw_handle().cast(),
                    TokenUser,
                    std::ptr::null_mut(),
                    0,
                    &raw mut needed,
                );
            }
            let mut buffer = vec![0_u64; usize::try_from(needed).unwrap_or(0).div_ceil(8).max(1)];
            // SAFETY: the buffer is at least the size the call above asked for.
            let read = unsafe {
                GetTokenInformation(
                    token.as_raw_handle().cast(),
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX),
                    &raw mut needed,
                )
            };
            if read == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self { buffer })
        }

        fn sid(&self) -> PSID {
            // SAFETY: the buffer holds a `TOKEN_USER` the kernel wrote, aligned for it.
            unsafe { (*self.buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid }
        }

        /// The identifier as the text a security descriptor is written with.
        fn text(&self) -> std::io::Result<String> {
            let mut text: *mut u16 = std::ptr::null_mut();
            // SAFETY: the identifier is valid for the call and the pointer is a local this thread
            // owns.
            if unsafe { ConvertSidToStringSidW(self.sid(), &raw mut text) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let allocated = Local(text.cast());
            let mut length = 0;
            // SAFETY: the call wrote a NUL-terminated string, which the allocation holds.
            while unsafe { *text.add(length) } != 0 {
                length += 1;
            }
            // SAFETY: the string is `length` units long and lives as long as the allocation.
            let units = unsafe { std::slice::from_raw_parts(text, length) };
            let converted = String::from_utf16_lossy(units);
            drop(allocated);
            Ok(converted)
        }
    }

    /// The pair of ends of one private overlapped pipe: the end this host keeps, and the end the
    /// agent is given. Each is made in the order below, and any failure closes everything made so
    /// far and refuses the start by name, before an agent exists.
    ///
    /// 1. A name no other pipe has: this process's identifier and 128 random bits.
    /// 2. A security descriptor given at creation: one entry, full control for this account,
    ///    protected, and no inheritance of the handle.
    /// 3. This host's end, with one instance only that must be the first of its name, so that a name
    ///    that exists already refuses the create, and no remote client.
    /// 4. The agent's end, opened at once as a synchronous client: it takes the one instance, so a
    ///    client that connected in the interval leaves the pipe busy here.
    /// 5. This host's end completes its connect, and both ends are checked: the other process at
    ///    each end is this one, and this host's end holds one entry in its access list.
    fn overlapped_pipe(direction: Direction) -> std::io::Result<(NamedPipeServer, OwnedHandle)> {
        let mut random = [0_u8; 16];
        kr_crypto::random_bytes(&mut random)
            .map_err(|failure| std::io::Error::other(format!("no random name: {failure}")))?;
        let name = pipe_name(std::process::id(), random);
        #[cfg(feature = "testing")]
        let name = seams::fixed_name().unwrap_or(name);

        let account = OwnSid::read()?;
        let descriptor_text: Vec<u16> = private_descriptor(&account.text()?)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: the text is NUL-terminated, and the out-parameters are locals this thread owns.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor_text.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if converted == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let descriptor = Local(descriptor);
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };

        let toward_agent = direction == Direction::ToAgent;
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(true)
            .max_instances(1)
            .reject_remote_clients(true)
            .access_inbound(!toward_agent)
            .access_outbound(toward_agent)
            .in_buffer_size(PIPE_BYTES)
            .out_buffer_size(PIPE_BYTES);
        // SAFETY: the attributes and the descriptor they point to outlive the call, which copies
        // them.
        let server = unsafe {
            options.create_with_security_attributes_raw(
                &name,
                (&raw mut attributes).cast::<std::ffi::c_void>(),
            )
        }
        .map_err(
            |failure| match failure.raw_os_error().map(i32::cast_unsigned) {
                Some(ERROR_ACCESS_DENIED | ERROR_PIPE_BUSY) => {
                    std::io::Error::other("the server's pipe name was already taken")
                }
                _ => failure,
            },
        )?;
        drop(descriptor);

        #[cfg(feature = "testing")]
        seams::run_after_server_create(&name);

        let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: the name is NUL-terminated; the share mode, security attributes and template are
        // none; and the create does not follow a link, because a pipe has none.
        let opened = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                if toward_agent {
                    GENERIC_READ
                } else {
                    GENERIC_WRITE
                },
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        };
        if opened == INVALID_HANDLE_VALUE {
            let failure = std::io::Error::last_os_error();
            return Err(
                if failure.raw_os_error().map(i32::cast_unsigned) == Some(ERROR_PIPE_BUSY) {
                    std::io::Error::other("another process connected to the server's pipe")
                } else {
                    failure
                },
            );
        }
        // SAFETY: the call reported a handle this process owns and nothing else holds.
        let agent = unsafe { OwnedHandle::from_raw_handle(opened.cast()) };

        // The agent's end has connected, so the connect completes at once, with the answer that
        // says so. One that does not is a connect to something that is not ours.
        {
            let mut connect = std::pin::pin!(server.connect());
            let mut context = std::task::Context::from_waker(std::task::Waker::noop());
            match std::future::Future::poll(connect.as_mut(), &mut context) {
                std::task::Poll::Ready(Ok(())) => {}
                std::task::Poll::Ready(Err(failure)) => return Err(failure),
                std::task::Poll::Pending => {
                    return Err(std::io::Error::other(
                        "the server's pipe did not complete its connect",
                    ));
                }
            }
        }
        let worker = std::process::id();
        let mut other = 0_u32;
        // SAFETY: the handle is open for the call and the identifier is a local this thread owns.
        let asked =
            unsafe { GetNamedPipeClientProcessId(server.as_raw_handle().cast(), &raw mut other) };
        if asked == 0 || other != worker {
            return Err(std::io::Error::other(
                "another process connected to the server's pipe",
            ));
        }
        // SAFETY: as above.
        let asked =
            unsafe { GetNamedPipeServerProcessId(agent.as_raw_handle().cast(), &raw mut other) };
        if asked == 0 || other != worker {
            return Err(std::io::Error::other(
                "another process holds the server's end of the pipe",
            ));
        }
        require_one_entry(server.as_raw_handle().cast(), account.sid())?;
        Ok((server, agent))
    }

    /// Reads the access list of the object `handle` names and refuses it unless it has one entry,
    /// which allows `account` and no one else.
    fn require_one_entry(handle: HANDLE, account: PSID) -> std::io::Result<()> {
        let mut list: *mut ACL = std::ptr::null_mut();
        let mut descriptor: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: the handle is open for the call and the out-parameters are locals this thread
        // owns; the descriptor is freed with the guard below.
        let read = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut list,
                std::ptr::null_mut(),
                &raw mut descriptor,
            )
        };
        if read != 0 {
            return Err(std::io::Error::from_raw_os_error(read.cast_signed()));
        }
        let _descriptor = Local(descriptor);
        let refusal = |why: &str| {
            std::io::Error::other(format!(
                "the server's pipe has an unexpected access list: {why}"
            ))
        };
        if list.is_null() {
            return Err(refusal("it has none"));
        }
        // SAFETY: the call reported a list inside the descriptor, which the guard keeps alive.
        let count = unsafe { (*list).AceCount };
        if count != 1 {
            return Err(refusal(&format!("it has {count} entries")));
        }
        let mut entry: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: the list is valid, the index is in range, and the pointer is a local.
        if unsafe { GetAce(list, 0, &raw mut entry) } == 0 || entry.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let entry = entry.cast::<ACCESS_ALLOWED_ACE>();
        // SAFETY: the entry lies inside the list; the identifier starts at its last field.
        let (kind, sid) = unsafe {
            (
                (*entry).Header.AceType,
                (&raw mut (*entry).SidStart).cast::<std::ffi::c_void>(),
            )
        };
        if u32::from(kind) != ACCESS_ALLOWED_ACE_TYPE {
            return Err(refusal("its one entry does not allow access"));
        }
        // SAFETY: both identifiers are valid for the call.
        if unsafe { EqualSid(sid, account) } == 0 {
            return Err(refusal("its one entry is not for this account"));
        }
        Ok(())
    }

    /// The seams the cases of the private pipes stand in. They are process-wide, so a case that uses
    /// one runs alone; neither exists in a shipped build.
    #[cfg(feature = "testing")]
    pub mod seams {
        use std::sync::{Arc, Mutex, PoisonError};

        /// What runs at the seam, given the pipe's name.
        pub type Hook = Box<dyn Fn(&str) + Send + Sync>;

        type Shared = Arc<dyn Fn(&str) + Send + Sync>;

        static NAME: Mutex<Option<String>> = Mutex::new(None);
        static FAILING_START: Mutex<Vec<std::path::PathBuf>> = Mutex::new(Vec::new());
        static AFTER_SERVER_CREATE: Mutex<Option<Shared>> = Mutex::new(None);

        /// Makes every pipe the next starts make have this name, or not.
        pub fn fix_name(name: Option<String>) {
            *NAME.lock().unwrap_or_else(PoisonError::into_inner) = name;
        }

        /// Sets what runs, given the pipe's name, after this host's end exists and before the
        /// agent's end is opened, or clears it.
        pub fn after_server_create(hook: Option<Hook>) {
            *AFTER_SERVER_CREATE
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = hook.map(Arc::from);
        }

        /// Makes a start in `directory` fail after its process was created, and be unable to end
        /// it, or stops doing so. Each directory is set on its own, so the cases that use it need
        /// not run alone.
        pub fn fail_start_in(directory: &std::path::Path, fails: bool) {
            let mut failing = FAILING_START.lock().unwrap_or_else(PoisonError::into_inner);
            failing.retain(|here| here != directory);
            if fails {
                failing.push(directory.to_path_buf());
            }
        }

        pub(super) fn fails_in(directory: &std::path::Path) -> bool {
            FAILING_START
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .any(|here| here == directory)
        }

        pub(super) fn fixed_name() -> Option<String> {
            NAME.lock().unwrap_or_else(PoisonError::into_inner).clone()
        }

        pub(super) fn run_after_server_create(name: &str) {
            let hook = AFTER_SERVER_CREATE
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if let Some(hook) = hook {
                hook(name);
            }
        }
    }

    /// Ends a process that was created and never resumed, as [`end_unstarted`] does, through a
    /// handle that can be waited on and asked its status but cannot end the process, so that the
    /// process neither ends nor shows that it is ending.
    #[cfg(feature = "testing")]
    fn failed_start(process: &OwnedHandle, patience: std::time::Duration) -> std::io::Error {
        let mut watcher: HANDLE = std::ptr::null_mut();
        // SAFETY: both handles are this process's own, the source is open for the call, and the
        // new handle is stored in a local this thread owns.
        let duplicated = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                process.as_raw_handle().cast(),
                GetCurrentProcess(),
                &raw mut watcher,
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                0,
            )
        };
        if duplicated == 0 {
            return std::io::Error::last_os_error();
        }
        // SAFETY: the call stored a new handle that nothing else holds.
        let watcher = unsafe { OwnedHandle::from_raw_handle(watcher.cast()) };
        end_unstarted(&watcher, "a case made the start fail", patience)
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

    impl Environment {
        /// Builds the environment `pairs` are, as [`Environment::from_variables`] does.
        ///
        /// # Errors
        ///
        /// Returns the refusal of a set that cannot be an environment, by the name of the variable.
        pub fn from_pairs(
            pairs: &[(std::ffi::OsString, std::ffi::OsString)],
        ) -> Result<Self, String> {
            Self::from_variables(
                pairs
                    .iter()
                    .map(|(name, value)| variable(name, value))
                    .collect(),
            )
        }

        /// Builds this process's own environment with `additions` set over it: an addition replaces
        /// the variable it names however that was spelled, and the first of them to name a variable
        /// wins.
        ///
        /// # Errors
        ///
        /// Returns the refusal of a variable that cannot be one, by its name.
        pub fn of_this_process_with(
            additions: &[(&str, &std::ffi::OsStr)],
        ) -> Result<Self, String> {
            Self::merged(
                std::env::vars_os()
                    .map(|(name, value)| variable(&name, &value))
                    .collect(),
                additions
                    .iter()
                    .map(|(name, value)| variable(std::ffi::OsStr::new(name), value))
                    .collect(),
            )
        }
    }

    /// Ends a process that was created and never resumed, and says why, and if it cannot be ended,
    /// that too: a suspended process nothing can reach is worse than a launch that failed. It waits
    /// no longer than `patience` in all.
    fn end_unstarted(
        process: &OwnedHandle,
        because: &str,
        patience: std::time::Duration,
    ) -> std::io::Error {
        let until = std::time::Instant::now() + patience;
        if let Err(failure) = end_process_within(process, patience) {
            return std::io::Error::other(format!(
                "a process was created and never started, because {because}, and then could not \
                 be ended either: {failure}"
            ));
        }
        let left = until.saturating_duration_since(std::time::Instant::now());
        // SAFETY: as above.
        unsafe {
            WaitForSingleObject(
                process.as_raw_handle().cast(),
                u32::try_from(left.as_millis()).unwrap_or(u32::MAX),
            );
        }
        std::io::Error::other(format!(
            "a process was created and never started, because {because}"
        ))
    }

    /// Starts a program in the jobs the spec names, with the three handles the spec describes.
    ///
    /// # Errors
    ///
    /// Returns why nothing was started: the program is not an executable, the command line is too
    /// long, a stream cannot be made (an overlapped one is refused by name when another process
    /// holds its name or connects to it first, and where no runtime is entered), the create failed,
    /// or a job does not hold the process once it exists, in which case the process is ended and
    /// never runs.
    ///
    /// A process that was created and could not be started is waited for at most ten seconds in all:
    /// the wait for its end and the wait for the signal that it ended share that time.
    pub fn start(spec: &Spec<'_>) -> std::io::Result<Child> {
        start_within(
            spec,
            std::time::Duration::from_millis(u64::from(END_WAIT_MS)),
        )
    }

    /// Starts a program as [`start`] does, and waits no longer than `patience` in all, for both of
    /// its waits, for a process that was created and could not be started to end.
    ///
    /// # Errors
    ///
    /// Returns what [`start`] does.
    pub fn start_within(spec: &Spec<'_>, patience: std::time::Duration) -> std::io::Result<Child> {
        refuse_program(spec.program).map_err(std::io::Error::other)?;
        let mut line = command_line(spec.program, spec.arguments).map_err(std::io::Error::other)?;
        let environment = spec.environment.block();
        let program = wide(spec.program);
        let directory = wide(spec.directory);

        // An overlapped end belongs to a runtime, which is looked for before anything is made.
        if [spec.stdin, spec.stdout, spec.stderr].contains(&Stdio::Overlapped)
            && tokio::runtime::Handle::try_current().is_err()
        {
            return Err(std::io::Error::other(
                "an overlapped stream belongs to a runtime, and none is entered on this thread",
            ));
        }

        // The ends the agent is given, and the ends this host keeps.
        let (input, kept_input) = stream(spec.stdin, Direction::ToAgent)?;
        let (output, kept_output) = stream(spec.stdout, Direction::FromAgent)?;
        let (errors, kept_errors) = stream(spec.stderr, Direction::FromAgent)?;
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
                patience,
            ));
        }
        // The ends this host gave away are closed here, so that what the agent holds is the only
        // other holder: the output's reader sees the end of the file when the agent's last
        // process lets go.
        drop(input);
        drop(output);
        drop(errors);

        #[cfg(feature = "testing")]
        if seams::fails_in(spec.directory) {
            return Err(failed_start(&process, patience));
        }

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
                        patience,
                    ));
                }
                Err(failure) => {
                    return Err(end_unstarted(
                        &process,
                        &format!("the session's job would not say whether it holds it: {failure}"),
                        patience,
                    ));
                }
            }
        }
        match spec.agent.holds_process(&process) {
            Ok(true) => {}
            Ok(false) => {
                return Err(end_unstarted(
                    &process,
                    "its job does not hold it",
                    patience,
                ));
            }
            Err(failure) => {
                return Err(end_unstarted(
                    &process,
                    &format!("its job would not say whether it holds it: {failure}"),
                    patience,
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
                patience,
            ));
        }
        drop(thread);
        let (stdin, overlapped_stdin) = match kept_input {
            Kept::Blocking(handle) => (Some(StdinPipe::new(handle)), None),
            other => (None, other.files().1),
        };
        let (stdout, overlapped_stdout) = kept_output.files();
        let (stderr, overlapped_stderr) = kept_errors.files();
        Ok(Child {
            process,
            id: started.dwProcessId,
            stdin,
            stdout,
            stderr,
            overlapped_stdin,
            overlapped_stdout,
            overlapped_stderr,
        })
    }

    /// The moment in which a process refuses to be ended and shows no sign of ending, which is
    /// the moment another thread takes its end in hand and has not yet recorded its status, cannot
    /// be held for a test. The refusal here comes from a handle that has no right to end the
    /// process, and the system answers it as it answers that moment: access is denied, and the
    /// process is neither signalled nor carries a status.
    #[cfg(test)]
    mod tests {
        use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
        use std::time::Duration;

        use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
        use windows_sys::Win32::System::Diagnostics::Debug::{
            CloseThreadWaitChainSession, GetThreadWaitChain, OpenThreadWaitChainSession,
            WAITCHAIN_NODE_INFO, WCT_MAX_NODE_COUNT, WCT_OUT_OF_PROC_COM_FLAG,
            WCT_OUT_OF_PROC_CS_FLAG, WCT_OUT_OF_PROC_FLAG, WctProcessWaitType,
        };
        use windows_sys::Win32::System::Threading::{
            GetThreadId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        };

        use super::{TerminateProcess, end_process, end_process_within, has_exit_status};

        /// A process that waits far longer than any test takes, and a handle on it that can be
        /// waited on and asked its status but cannot end it.
        fn waiting_process_and_a_handle_that_cannot_end_it() -> (std::process::Child, OwnedHandle) {
            let child = std::process::Command::new("ping.exe")
                .args(["-n", "600", "127.0.0.1"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("a process that waits starts");
            // SAFETY: the call takes a process identifier and nothing this function owns.
            let opened = unsafe {
                OpenProcess(
                    PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                    0,
                    child.id(),
                )
            };
            assert!(!opened.is_null(), "the process is opened to be watched");
            // SAFETY: the handle is a new one this function owns, closed once.
            let watcher = unsafe { OwnedHandle::from_raw_handle(opened.cast()) };
            // The premise: the refusal arrives, and the process shows neither sign.
            // SAFETY: the handle is open for the call.
            let ended = unsafe { TerminateProcess(watcher.as_raw_handle().cast(), 1) };
            assert_eq!(ended, 0, "this handle cannot end the process");
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                i32::try_from(ERROR_ACCESS_DENIED).ok(),
                "and the system's answer is a refusal"
            );
            assert!(
                !has_exit_status(&watcher),
                "the process has neither ended nor begun to"
            );
            (child, watcher)
        }

        /// Says whether the thread `thread` is waiting for a process to end.
        fn waits_for_a_process(session: *const std::ffi::c_void, thread: u32) -> bool {
            let mut nodes = [WAITCHAIN_NODE_INFO::default(); WCT_MAX_NODE_COUNT as usize];
            let mut count = WCT_MAX_NODE_COUNT;
            let mut cycle = 0;
            // SAFETY: the session is open, and the array holds as many nodes as the count says.
            let read = unsafe {
                GetThreadWaitChain(
                    session,
                    0,
                    WCT_OUT_OF_PROC_FLAG | WCT_OUT_OF_PROC_COM_FLAG | WCT_OUT_OF_PROC_CS_FLAG,
                    thread,
                    &raw mut count,
                    nodes.as_mut_ptr(),
                    &raw mut cycle,
                )
            };
            // A thread that is not waiting, or has gone, has no chain to read.
            read != 0
                && nodes[..count as usize]
                    .iter()
                    .any(|node| node.ObjectType == WctProcessWaitType)
        }

        /// A refused end of a process that shows no sign yet is waited out: the process that
        /// ends then is ended, where a refusal taken for a failure at once would report an end
        /// that was about to happen as one that could not.
        #[test]
        fn a_refused_end_of_a_process_that_shows_no_sign_waits_for_the_process_to_end() {
            let (mut child, watcher) = waiting_process_and_a_handle_that_cannot_end_it();
            let ending = std::thread::spawn(move || end_process(&watcher));
            let thread = {
                // SAFETY: the handle is the thread's own, open for as long as it is not joined.
                unsafe { GetThreadId(ending.as_raw_handle().cast()) }
            };
            // SAFETY: both arguments are the documented "synchronous, no callback".
            let session = unsafe { OpenThreadWaitChainSession(0, None) };
            assert!(!session.is_null(), "a session to read the thread's wait");
            // Until the call has returned or is waiting for the process: the process must not
            // end before the call has refused and found no sign, or there is nothing to wait for.
            while !ending.is_finished() && !waits_for_a_process(session, thread) {
                std::thread::yield_now();
            }
            // SAFETY: the session is open and closed once.
            unsafe { CloseThreadWaitChainSession(session) };
            child.kill().expect("the process is ended by its owner");
            let outcome = ending.join().expect("the call returns");
            child.wait().expect("the process is collected");
            outcome.expect("a refused end of a process that then ends is not a failure");
        }

        /// A refusal of a process that is running and shows no sign is a failure, once the wait
        /// for a sign has run out.
        #[test]
        fn a_refused_end_of_a_process_that_goes_on_running_is_a_failure() {
            let (mut child, watcher) = waiting_process_and_a_handle_that_cannot_end_it();
            let outcome = end_process_within(&watcher, Duration::ZERO);
            let _ = child.kill();
            let _ = child.wait();
            let failure = outcome.expect_err("a process that is running is not ended");
            assert_eq!(
                failure.raw_os_error(),
                i32::try_from(ERROR_ACCESS_DENIED).ok(),
                "and the failure is the system's refusal"
            );
        }
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

    fn text(block: &[u16]) -> String {
        String::from_utf16(block).expect("text")
    }

    #[test]
    fn an_environment_block_is_sorted_by_name_and_additions_replace_without_regard_to_case() {
        let environment = Environment::merged(
            vec![
                variable("Path", "C:\\Windows"),
                variable("ZED", "z"),
                variable("alpha", "a"),
            ],
            vec![
                variable("PATH", "C:\\bin"),
                variable("KR_REGISTRATION", "r"),
            ],
        )
        .expect("an environment");
        let block = environment.block();
        let text = text(&block);
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
        let environment = Environment::merged(
            Vec::new(),
            vec![variable("A", "first"), variable("a", "second")],
        )
        .expect("an environment");
        let text = text(&environment.block());
        assert!(text.starts_with("A=first\0"), "{text:?}");
        assert!(!text.contains("second"), "{text:?}");
    }

    #[test]
    fn an_empty_environment_block_ends_with_the_two_terminators_the_create_reads() {
        assert_eq!(
            Environment::default().block(),
            [0, 0],
            "an empty set is two terminators, not one"
        );
        let one = Environment::from_variables(vec![variable("A", "b")]).expect("an environment");
        assert_eq!(
            text(&one.block()),
            "A=b\0\0",
            "a set that holds one ends with one more"
        );
    }

    #[test]
    fn a_given_value_wins_over_a_workers_own_of_the_same_name_in_any_case() {
        for spelling in ["PATH", "path", "pAtH"] {
            let environment = Environment::merged(
                vec![variable("Path", "worker"), variable("OTHER", "kept")],
                vec![variable(spelling, "given")],
            )
            .expect("an environment");
            assert_eq!(environment.len(), 2, "{spelling}");
            let value = environment.value_of("PATH").expect("the variable");
            assert_eq!(String::from_utf16_lossy(value), "given", "{spelling}");
            assert_eq!(
                text(&environment.block()),
                format!("OTHER=kept\0{spelling}=given\0\0"),
                "the name is spelled as the addition spelled it"
            );
        }
    }

    #[test]
    fn a_withheld_name_in_four_case_variants_is_absent() {
        for held in ["KR_GATEWAY", "kr_gateway", "Kr_Gateway", "kR_gAtEwAy"] {
            let environment =
                Environment::from_variables(vec![variable(held, "x"), variable("KEPT", "y")])
                    .expect("an environment");
            for withheld in ["KR_GATEWAY", "kr_gateway", "Kr_Gateway", "kR_gAtEwAy"] {
                let without = environment.without(&[withheld]);
                assert_eq!(without.len(), 1, "{held} withheld as {withheld}");
                assert!(
                    without.value_of("KR_GATEWAY").is_none(),
                    "{held} as {withheld}"
                );
                assert_eq!(text(&without.block()), "KEPT=y\0\0");
            }
        }
    }

    #[test]
    fn a_name_may_begin_with_one_equals_and_holds_no_other() {
        let environment = Environment::from_variables(vec![
            variable("=C:", "C:\\work"),
            variable("=D:", "D:\\"),
            variable("PATH", "p"),
        ])
        .expect("cmd.exe's per-drive folders are variables");
        let block = environment.block();
        let text = text(&block);
        assert!(
            text.starts_with("=C:=C:\\work\0=D:=D:\\\0PATH=p\0"),
            "presented unchanged and first, as the system sorts them: {text:?}"
        );
        for refused in ["A=B", "==", "=", "=A=B", ""] {
            let why = Environment::from_variables(vec![variable(refused, "v")]).expect_err(refused);
            assert!(why.contains("environment"), "{refused:?}: {why}");
        }
    }

    #[test]
    fn a_nul_is_refused_in_a_value_as_it_is_in_a_name() {
        let in_name = Environment::from_variables(vec![(wide("A\0B"), wide("v"))])
            .expect_err("a NUL in a name");
        assert!(in_name.contains("NUL in its name"), "{in_name}");
        let in_value = Environment::from_variables(vec![(wide("A"), wide("secret\0more"))])
            .expect_err("a NUL in a value");
        assert!(in_value.contains("NUL in its value"), "{in_value}");
        assert!(
            in_value.contains("\"A\""),
            "it names the variable: {in_value}"
        );
        assert!(
            !in_value.contains("secret") && !in_value.contains("more"),
            "it never says the value: {in_value}"
        );
        let merged = Environment::merged(Vec::new(), vec![(wide("A"), wide("x\0"))])
            .expect_err("a NUL in an addition's value");
        assert!(merged.contains("NUL in its value"), "{merged}");
    }

    #[test]
    fn a_set_that_names_one_variable_twice_by_case_is_refused_by_name() {
        let why = Environment::from_variables(vec![variable("Path", "1"), variable("PATH", "2")])
            .expect_err("two spellings of one name");
        assert!(why.contains("Path") && why.contains("PATH"), "{why}");
        assert!(
            !why.contains('1') && !why.contains('2'),
            "never the values: {why}"
        );
    }

    #[test]
    fn an_environment_shows_how_many_variables_it_holds_and_no_more() {
        let environment = Environment::from_variables(vec![variable("TOKEN", "hunter2")])
            .expect("an environment");
        let shown = format!("{environment:?}");
        assert_eq!(shown, "Environment(1 variables)");
    }

    #[test]
    fn a_pipe_name_holds_the_workers_identifier_and_all_the_random_bits() {
        let name = pipe_name(4242, [0xab; 16]);
        assert_eq!(
            name,
            format!(r"\\.\pipe\kr-server-4242-{}", "ab".repeat(16))
        );
        assert_ne!(pipe_name(4242, [0xcd; 16]), name);
        let mut last = [0xab; 16];
        last[15] = 0xac;
        assert_ne!(pipe_name(4242, last), name, "the last bit counts");
        assert_ne!(pipe_name(4243, [0xab; 16]), name, "so does the worker's");
    }

    #[test]
    fn a_private_descriptor_is_protected_and_has_one_entry_for_the_account() {
        let text = private_descriptor("S-1-5-21-1-2-3-1001");
        assert_eq!(text, "D:P(A;;GA;;;S-1-5-21-1-2-3-1001)");
        assert!(
            text.starts_with("D:P("),
            "protected: no parent's list is added"
        );
        assert_eq!(text.matches('(').count(), 1, "one entry");
    }

    #[test]
    fn handles_are_listed_once_in_the_order_given() {
        assert_eq!(distinct(&[4, 8, 8]), vec![4, 8]);
        assert_eq!(distinct(&[4, 8, 12]), vec![4, 8, 12]);
        assert_eq!(distinct(&[4, 4, 4]), vec![4]);
        assert!(distinct(&[]).is_empty());
    }
}
