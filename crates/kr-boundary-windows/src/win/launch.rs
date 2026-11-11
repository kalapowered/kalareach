//! Starting a program: the one place in the broker that creates a process.
//!
//! Every child the broker has, an operation's Git, a reader of its settings or of the repository,
//! and the proof's programs, is made by [`launch`], with the one `CreateProcessAsUserW` call of the
//! crate's broker. No other call creates a process, and nothing in the broker starts a program
//! through the standard library. A child is made like this:
//!
//! - **suspended**, so that nothing of it has run when [`launch`] returns, and it runs only when a
//!   caller passes [`resume`](SuspendedChild::resume) the proof that its process row is durable;
//! - **inside its job**, by the creation attribute: it is never assigned afterwards, and a launch
//!   that cannot apply the attribute fails with nothing started;
//! - with **exactly three inherited handles**, its standard handles, named in an explicit list. An
//!   unused one is a `NUL` handle the broker opened. Any other inheritable handle in the broker, in
//!   this thread or another, is not inherited;
//! - with a **descriptor on its process and on its thread** that names the invocation's group and
//!   the system alone, and handles back that no child can inherit;
//! - with **no console** and **no desktop**, and with an environment of exactly the block it is
//!   given.
//!
//! The flags that would make a child escape these are never used: a new console, a pseudoconsole,
//! no window, breakaway from the job, and the default error mode.

#![allow(unsafe_code)]

use std::mem::ManuallyDrop;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    FILETIME, GENERIC_READ, GENERIC_WRITE, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT,
    SetHandleInformation, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, SECURITY_ATTRIBUTES, SecurityImpersonation, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DUPLICATE, TOKEN_QUERY, TokenPrimary,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, ReadFile,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::SystemServices::MAXIMUM_ALLOWED;
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, DETACHED_PROCESS,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetExitCodeProcess, GetProcessTimes, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

use crate::env::EnvBlock;

use super::ffi::{self, Handle, Sid, last, wide, wide_path};
use super::job::{Job, Limits};
use super::sd::{OwnedSd, Principals, SdKind, descriptor};

/// How a program that was started ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// It ended with this exit code.
    Ran(u32),
    /// It was still running when the bound ran out, and was ended.
    TimedOut,
}

/// The error number the platform gives a program that application control refused.
pub const REFUSED_BY_POLICY: u32 = 1260;

/// Why a program was not started, or why a started child was ended.
#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    /// The platform refused to create the process, with this error number. The application-control
    /// policy's refusal is [`REFUSED_BY_POLICY`]. Nothing was started.
    #[error("the program could not be started: Windows error {0}")]
    NotStarted(u32),
    /// The job could not be applied at creation. Nothing was started.
    #[error("the job could not be applied at creation, and nothing was started: {0}")]
    Job(ffi::Error),
    /// A standard handle was not usable. Nothing was started.
    #[error("a standard handle is not usable: {0}")]
    Handle(&'static str),
    /// The process was made but is not in the job. It was ended.
    #[error("the new process was not in its job and was ended")]
    NotInJob,
    /// Another call failed.
    #[error(transparent)]
    Platform(#[from] ffi::Error),
}

/// The token a child runs under.
#[derive(Clone, Copy, Debug)]
pub enum TokenSpec<'a> {
    /// A boundary account's logon token for an invocation.
    Boundary(&'a Handle),
    /// The broker's own token: a copy of its primary token, for the proof's own programs.
    Own,
}

/// A program the caller has vetted: an absolute path to a program of the qualified Git set or to a
/// system program. The launcher starts nothing it is given any other way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPath(PathBuf);

impl VerifiedPath {
    /// Takes a program's path that the caller has vetted.
    ///
    /// # Errors
    ///
    /// Returns an error for a path that is not absolute: a relative one would be searched for.
    pub fn new(path: impl Into<PathBuf>) -> Result<VerifiedPath, LaunchError> {
        let path = path.into();
        if path.is_absolute() {
            Ok(VerifiedPath(path))
        } else {
            Err(LaunchError::Handle("the program's path is not absolute"))
        }
    }

    /// The path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

/// The write end or the read end of a pipe that a child inherits as one of its standard handles.
#[derive(Debug)]
pub struct OwnedPipeEnd(Handle);

impl OwnedPipeEnd {
    /// Takes a pipe end that was made inheritable.
    ///
    /// # Errors
    ///
    /// Returns an error when the handle is not inheritable: the child could not use it.
    pub fn new(handle: Handle) -> Result<OwnedPipeEnd, LaunchError> {
        if is_inheritable(&handle)? {
            Ok(OwnedPipeEnd(handle))
        } else {
            Err(LaunchError::Handle("the pipe end is not inheritable"))
        }
    }
}

/// One of a child's three standard handles.
#[derive(Debug)]
pub enum Std {
    /// The null device, opened by the launcher: for reading in the input's place and for writing in
    /// an output's.
    Nul,
    /// A pipe end the broker made.
    Pipe(OwnedPipeEnd),
}

/// Proof that a child's process row is durable, which a resume requires.
///
/// The journal makes this value when its append of a process row has returned. Until the journal
/// exists, the only other maker is for the proof's own programs, which belong to no invocation and
/// which no recovery has to find.
#[derive(Debug)]
pub struct DurableProcessRow(());

impl DurableProcessRow {
    /// The row of a child that belongs to no invocation: a program of the proof.
    pub(crate) fn for_proof_child() -> DurableProcessRow {
        DurableProcessRow(())
    }

    /// A row for the cases that start a child and have no journal to write.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn for_cases() -> DurableProcessRow {
        DurableProcessRow(())
    }
}

/// What to start, and how.
pub struct ChildSpec<'a> {
    /// The token the child runs under.
    pub token: TokenSpec<'a>,
    /// The job the child is made in.
    pub job: &'a Job,
    /// The program.
    pub program: VerifiedPath,
    /// The command line, quoted by [`quote_command_line`](crate::quote::quote_command_line).
    pub command_line: String,
    /// The child's working directory.
    pub cwd: &'a Path,
    /// The child's environment.
    pub env: &'a EnvBlock,
    /// The child's standard input.
    pub stdin: Std,
    /// The child's standard output.
    pub stdout: Std,
    /// The child's standard error.
    pub stderr: Std,
    /// The descriptor of the child's process.
    pub process_descriptor: &'a OwnedSd,
    /// The descriptor of the child's primary thread.
    pub thread_descriptor: &'a OwnedSd,
}

/// A child that exists, is in its job and has run nothing.
///
/// A suspended child that is dropped is ended and waited for: it is never left.
#[derive(Debug)]
pub struct SuspendedChild {
    /// The child's process, a handle that no child can inherit.
    pub process: Handle,
    /// The child's primary thread, a handle that no child can inherit.
    pub thread: Handle,
    /// The process identifier.
    pub pid: u32,
    /// When the process was created, as the platform's 64-bit time. With the identifier it names
    /// the process for good: identifiers are reused.
    pub creation_time: u64,
    /// Whether the launcher asked the platform, before returning, whether the process is in the
    /// job and was told it is. A child that is not in the job is never returned.
    pub in_job_checked: bool,
}

/// A child that has been resumed.
#[derive(Debug)]
pub struct Child {
    /// The child's process, a handle that no child can inherit.
    pub process: Handle,
    /// The process identifier.
    pub pid: u32,
    /// When the process was created.
    pub creation_time: u64,
}

/// How long a dropped suspended child is waited for.
const END_WAIT_MS: u32 = 10_000;

impl Drop for SuspendedChild {
    fn drop(&mut self) {
        // SAFETY: the process handle is open and the process is this value's own child.
        unsafe {
            TerminateProcess(self.process.raw(), 1);
            WaitForSingleObject(self.process.raw(), END_WAIT_MS);
        }
    }
}

impl SuspendedChild {
    /// Lets the child run, once its process row is durable.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the thread cannot be resumed, or when it was not suspended
    /// exactly once; the child is ended.
    pub fn resume(self, durable: DurableProcessRow) -> Result<Child, LaunchError> {
        let _: DurableProcessRow = durable;
        // SAFETY: the thread handle is open.
        let previous = unsafe { ResumeThread(self.thread.raw()) };
        if previous != 1 {
            // Dropping `self` ends the child.
            return Err(if previous == u32::MAX {
                LaunchError::Platform(last("resuming the child"))
            } else {
                LaunchError::Handle("the child was not suspended exactly once")
            });
        }
        let this = ManuallyDrop::new(self);
        // SAFETY: `this` is never used or dropped again, so each handle is moved out once and the
        // platform sees the child resumed, not ended.
        let (process, thread) =
            unsafe { (std::ptr::read(&this.process), std::ptr::read(&this.thread)) };
        drop(thread);
        Ok(Child {
            process,
            pid: this.pid,
            creation_time: this.creation_time,
        })
    }
}

impl Child {
    /// Waits for the child to end, up to a bound.
    ///
    /// Returns the exit code, or `None` when the bound ran out first.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the wait or the exit code fails.
    pub fn wait(&self, bound: Duration) -> Result<Option<u32>, ffi::Error> {
        let milliseconds = u32::try_from(bound.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: the process handle is open.
        let waited = unsafe { WaitForSingleObject(self.process.raw(), milliseconds) };
        if waited != WAIT_OBJECT_0 {
            return Ok(None);
        }
        let mut code = 0_u32;
        // SAFETY: the process has ended and the handle is open.
        if unsafe { GetExitCodeProcess(self.process.raw(), &raw mut code) } == 0 {
            return Err(last("reading the exit code"));
        }
        Ok(Some(code))
    }

    /// Ends the child by force.
    pub fn terminate(&self) {
        // SAFETY: the process handle is open.
        unsafe {
            TerminateProcess(self.process.raw(), 1);
        }
    }
}

fn is_inheritable(handle: &Handle) -> Result<bool, ffi::Error> {
    let mut flags = 0_u32;
    // SAFETY: the handle is open.
    if unsafe { GetHandleInformation(handle.raw(), &raw mut flags) } == 0 {
        return Err(last("reading a handle's flags"));
    }
    Ok(flags & HANDLE_FLAG_INHERIT != 0)
}

fn inheritable_null_device(access: u32) -> Result<Handle, ffi::Error> {
    let name = wide("NUL");
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: the name is NUL-terminated and the attributes are this function's own for the call.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &raw const attributes,
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    Handle::new(handle, "opening the null device")
}

fn standard(std: Std, access: u32) -> Result<Handle, ffi::Error> {
    match std {
        Std::Nul => inheritable_null_device(access),
        Std::Pipe(end) => Ok(end.0),
    }
}

/// An anonymous pipe: the end the broker reads, which no child can inherit, and the end a child
/// writes, which it inherits.
///
/// # Errors
///
/// Returns the platform's error when the pipe cannot be made.
pub fn pipe() -> Result<(Handle, OwnedPipeEnd), ffi::Error> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let mut read: HANDLE = null_mut();
    let mut write: HANDLE = null_mut();
    // SAFETY: the out-parameters and the attributes are this function's own for the call.
    if unsafe { CreatePipe(&raw mut read, &raw mut write, &raw const attributes, 0) } == 0 {
        return Err(last("making a pipe"));
    }
    let read = Handle::new(read, "the pipe's read end")?;
    let write = Handle::new(write, "the pipe's write end")?;
    // SAFETY: the read end is open; the broker alone keeps it.
    if unsafe { SetHandleInformation(read.raw(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(last("keeping the pipe's read end from children"));
    }
    Ok((read, OwnedPipeEnd(write)))
}

/// A copy of the broker's own primary token, which can start a process.
fn own_token() -> Result<Handle, ffi::Error> {
    let mut process_token: HANDLE = null_mut();
    // SAFETY: the current process pseudo-handle is always valid; the out-parameter is local.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
            &raw mut process_token,
        )
    };
    if opened == 0 {
        return Err(last("opening the broker's own token"));
    }
    let process_token = Handle::new(process_token, "the broker's own token")?;
    let mut copy: HANDLE = null_mut();
    // SAFETY: the token is open and the out-parameter is local.
    let duplicated = unsafe {
        DuplicateTokenEx(
            process_token.raw(),
            MAXIMUM_ALLOWED,
            null(),
            SecurityImpersonation,
            TokenPrimary,
            &raw mut copy,
        )
    };
    if duplicated == 0 {
        return Err(last("copying the broker's own token"));
    }
    Handle::new(copy, "the copy of the broker's own token")
}

/// The attribute list of a launch, freed when dropped.
struct Attributes {
    storage: Vec<usize>,
}

impl Attributes {
    fn list(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}

impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: the list was initialised by `attributes` and is deleted once.
        unsafe {
            DeleteProcThreadAttributeList(self.list());
        }
    }
}

/// Builds the list that holds the handle list and the job list.
fn attributes(handles: &[HANDLE; 3], job: &HANDLE) -> Result<Attributes, LaunchError> {
    let mut size = 0_usize;
    // SAFETY: the first call only asks for the size it needs, and is expected to fail.
    unsafe {
        InitializeProcThreadAttributeList(null_mut(), 2, 0, &raw mut size);
    }
    if size == 0 {
        return Err(LaunchError::Platform(last("sizing the attribute list")));
    }
    let mut list = Attributes {
        storage: vec![0_usize; size.div_ceil(size_of::<usize>())],
    };
    // SAFETY: the buffer is the size the first call asked for and is aligned for the list.
    if unsafe { InitializeProcThreadAttributeList(list.list(), 2, 0, &raw mut size) } == 0 {
        return Err(LaunchError::Platform(last("making the attribute list")));
    }
    // SAFETY: the list is initialised; the values outlive the call that uses the list because the
    // caller holds them.
    let handle_list = unsafe {
        UpdateProcThreadAttribute(
            list.list(),
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles.as_ptr().cast(),
            size_of::<[HANDLE; 3]>(),
            null_mut(),
            null(),
        )
    };
    if handle_list == 0 {
        return Err(LaunchError::Platform(last("listing the inherited handles")));
    }
    // SAFETY: as above.
    let job_list = unsafe {
        UpdateProcThreadAttribute(
            list.list(),
            0,
            PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
            std::ptr::from_ref(job).cast(),
            size_of::<HANDLE>(),
            null_mut(),
            null(),
        )
    };
    if job_list == 0 {
        return Err(LaunchError::Job(last("naming the job at creation")));
    }
    Ok(list)
}

fn time_of(process: &Handle) -> Result<u64, ffi::Error> {
    let mut created = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exited = created;
    let mut kernel = created;
    let mut user = created;
    // SAFETY: the process handle is open and the out-parameters are local.
    let read = unsafe {
        GetProcessTimes(
            process.raw(),
            &raw mut created,
            &raw mut exited,
            &raw mut kernel,
            &raw mut user,
        )
    };
    if read == 0 {
        return Err(last("reading the process's creation time"));
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

/// Starts a child, suspended, in its job, with exactly its three standard handles.
///
/// # Errors
///
/// Returns [`LaunchError::NotStarted`] with the platform's error number when the process cannot be
/// created, which is how application control's refusal shows. Any other error leaves nothing
/// started, or a child that was ended.
pub fn launch(spec: ChildSpec<'_>) -> Result<SuspendedChild, LaunchError> {
    let input = standard(spec.stdin, GENERIC_READ)?;
    let output = standard(spec.stdout, GENERIC_WRITE)?;
    let errors = standard(spec.stderr, GENERIC_WRITE)?;
    let token_copy;
    let token = match spec.token {
        TokenSpec::Boundary(handle) => handle.raw(),
        TokenSpec::Own => {
            token_copy = own_token()?;
            token_copy.raw()
        }
    };
    let handles = [input.raw(), output.raw(), errors.raw()];
    let job = spec.job.raw();
    let mut list = attributes(&handles, &job)?;
    let program = wide_path(spec.program.path());
    let mut command = wide(&spec.command_line);
    let cwd = wide_path(spec.cwd);
    let mut process_attributes = spec.process_descriptor.attributes();
    let mut thread_attributes = spec.thread_descriptor.attributes();
    // SAFETY: a zeroed record is the documented starting point.
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = handles[0];
    startup.StartupInfo.hStdOutput = handles[1];
    startup.StartupInfo.hStdError = handles[2];
    startup.lpAttributeList = list.list();
    // SAFETY: a zeroed record is what the platform fills in.
    let mut created: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the token is open, every string is NUL-terminated and outlives the call, the
    // environment block ends with its double terminator, and the attribute list, the handles it
    // names and the descriptors are held until the call returns. The flags are fixed: suspended,
    // an extended startup record, a wide environment and no console. The desktop is left unset.
    let started = unsafe {
        CreateProcessAsUserW(
            token,
            program.as_ptr(),
            command.as_mut_ptr(),
            &raw mut process_attributes,
            &raw mut thread_attributes,
            1,
            CREATE_SUSPENDED
                | EXTENDED_STARTUPINFO_PRESENT
                | CREATE_UNICODE_ENVIRONMENT
                | DETACHED_PROCESS,
            spec.env.units().as_ptr().cast(),
            cwd.as_ptr(),
            &raw const startup.StartupInfo,
            &raw mut created,
        )
    };
    if started == 0 {
        // SAFETY: reads the calling thread's last error.
        return Err(LaunchError::NotStarted(unsafe {
            windows_sys::Win32::Foundation::GetLastError()
        }));
    }
    let process = Handle::new(created.hProcess, "the started process")?;
    let thread = match Handle::new(created.hThread, "the started process's thread") {
        Ok(thread) => thread,
        Err(error) => {
            // SAFETY: the process handle is open and the process is this function's own child.
            unsafe {
                TerminateProcess(process.raw(), 1);
            }
            return Err(error.into());
        }
    };
    drop((input, output, errors));
    let mut child = SuspendedChild {
        process,
        thread,
        pid: created.dwProcessId,
        creation_time: 0,
        in_job_checked: false,
    };
    // From here a failure drops `child`, which ends it.
    child.creation_time = time_of(&child.process)?;
    match spec.job.contains(&child.process) {
        Ok(true) => child.in_job_checked = true,
        Ok(false) => return Err(LaunchError::NotInJob),
        Err(error) => return Err(LaunchError::Platform(error)),
    }
    Ok(child)
}

/// What to run for [`run_captured`].
pub struct Run<'a> {
    /// The token the program runs under.
    pub token: TokenSpec<'a>,
    /// The group the token carries, named on the program's process and thread; none for a program
    /// of the broker's own token.
    pub group: Option<&'a Sid>,
    /// The program.
    pub program: VerifiedPath,
    /// Its command line.
    pub command_line: String,
    /// Its working directory.
    pub cwd: &'a Path,
    /// Its environment.
    pub env: &'a EnvBlock,
}

/// What a captured run wrote and how it ended.
#[derive(Debug)]
pub struct Captured {
    /// How the program ended.
    pub outcome: Outcome,
    /// What it wrote to its standard output.
    pub stdout: Vec<u8>,
    /// What it wrote to its standard error.
    pub stderr: Vec<u8>,
}

/// The most a captured run keeps of each stream; the rest is read and dropped.
const CAPTURE_LIMIT: usize = 8 << 20;

fn read_all(pipe: &Handle) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut chunk = vec![0_u8; 64 * 1024];
    loop {
        let mut read = 0_u32;
        // SAFETY: the pipe is open and the buffer is the length given.
        let ok = unsafe {
            ReadFile(
                pipe.raw(),
                chunk.as_mut_ptr().cast(),
                chunk.len() as u32,
                &raw mut read,
                null_mut(),
            )
        };
        if ok == 0 || read == 0 {
            return kept;
        }
        let room = CAPTURE_LIMIT.saturating_sub(kept.len());
        kept.extend_from_slice(&chunk[..(read as usize).min(room)]);
    }
}

/// Runs a program of the proof to its end, up to a bound, and keeps what it wrote.
///
/// The program has a job of its own, which is ended before the function returns, so nothing it
/// started outlives the call. Its process and thread name the token's group and the system, or the
/// system alone for the broker's own token. Its process row is not journalled, because it belongs to no invocation.
///
/// # Errors
///
/// Returns [`LaunchError::NotStarted`] when the platform refuses to start the program, and the
/// other errors of [`launch`] and of the pipes.
pub fn run_captured(run: Run<'_>, bound: Duration) -> Result<Captured, LaunchError> {
    let mut job = Job::new(Limits::INVOCATION)?;
    let (out_read, out_write) = pipe()?;
    let (err_read, err_write) = pipe()?;
    let descriptor = descriptor(
        SdKind::ProcessThread,
        &Principals {
            group: run.group.cloned(),
            ..Principals::default()
        },
    )?;
    let suspended = launch(ChildSpec {
        token: run.token,
        job: &job,
        program: run.program,
        command_line: run.command_line,
        cwd: run.cwd,
        env: run.env,
        stdin: Std::Nul,
        stdout: Std::Pipe(out_write),
        stderr: Std::Pipe(err_write),
        process_descriptor: &descriptor,
        thread_descriptor: &descriptor,
    })?;
    let (result, out, err) = std::thread::scope(|scope| {
        let out = scope.spawn(|| read_all(&out_read));
        let err = scope.spawn(|| read_all(&err_read));
        let result = match suspended.resume(DurableProcessRow::for_proof_child()) {
            Ok(child) => {
                let waited = child.wait(bound);
                // Anything the program started ends with the job, which also lets the pipes
                // reach their end. A program still running at the bound is ended the same way.
                job.end(&[&child], Duration::from_secs(10));
                match waited {
                    Ok(Some(code)) => Ok(Outcome::Ran(code)),
                    Ok(None) => Ok(Outcome::TimedOut),
                    Err(error) => Err(LaunchError::Platform(error)),
                }
            }
            Err(error) => {
                job.end(&[], Duration::from_secs(10));
                Err(error)
            }
        };
        (result, out.join(), err.join())
    });
    Ok(Captured {
        outcome: result?,
        stdout: out.unwrap_or_default(),
        stderr: err.unwrap_or_default(),
    })
}
