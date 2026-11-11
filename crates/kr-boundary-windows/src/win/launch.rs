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
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_BROKEN_PIPE, FILETIME, GENERIC_READ, GENERIC_WRITE, GetHandleInformation, HANDLE,
    HANDLE_FLAG_INHERIT, SetHandleInformation, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, SECURITY_ATTRIBUTES, SecurityImpersonation, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DUPLICATE, TOKEN_QUERY, TokenPrimary,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, ReadFile,
};
use windows_sys::Win32::System::Pipes::{CreatePipe, PeekNamedPipe};
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

use super::ffi::{self, Handle, last, wide, wide_path};
use super::job::{Job, Reports, State};
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
    /// The deadline had passed before the program was started. Nothing was started.
    #[error("the deadline passed before the program was started")]
    DeadlinePassed,
    /// The process was made but is not in the job. It was ended.
    #[error("the new process was not in its job and was ended")]
    NotInJob,
    /// The permit to resume was made for another child, or for another invocation. The child was
    /// ended.
    #[error("the permit to resume is for another child, and the child was ended")]
    PermitForAnotherChild,
    /// A child or a job could not be shown to have ended. Nothing may be released or removed on
    /// the strength of this end.
    #[error("the end is not proved: {0}")]
    EndUncertain(String),
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
    /// The handle's value, which a child that inherits it sees unchanged.
    #[must_use]
    pub fn raw(&self) -> HANDLE {
        self.0.raw()
    }

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

/// The 128-bit identifier of an invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvocationId(pub [u8; 16]);

/// Leave to resume one child, bound to the invocation it belongs to and to that child alone, by
/// its process identifier and its creation time. A permit for another invocation or another child
/// is refused: each of the three is compared.
///
/// The journal makes the permit of an invocation's child when its append of the child's process
/// row has returned, so that a child cannot run before its row is durable. A program of the proof
/// belongs to no invocation and no recovery has to find it: the proof module alone makes the
/// permits of those.
#[derive(Debug)]
pub struct ResumePermit {
    invocation: Option<InvocationId>,
    pid: u32,
    creation_time: u64,
}

impl ResumePermit {
    fn bound_to(invocation: Option<InvocationId>, child: &SuspendedChild) -> ResumePermit {
        ResumePermit {
            invocation,
            pid: child.pid,
            creation_time: child.creation_time,
        }
    }

    /// The permit of an invocation's child, for the journal to make once the child's process row
    /// is durable.
    pub(crate) fn for_invocation(invocation: InvocationId, child: &SuspendedChild) -> ResumePermit {
        ResumePermit::bound_to(Some(invocation), child)
    }

    /// The permit of a program of the proof, which belongs to no invocation.
    pub(super) fn for_proof(child: &SuspendedChild) -> ResumePermit {
        ResumePermit::bound_to(None, child)
    }

    /// A permit for the cases that start a child and have no journal to write.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn for_cases(invocation: InvocationId, child: &SuspendedChild) -> ResumePermit {
        ResumePermit::for_invocation(invocation, child)
    }

    /// A permit with each of the three facts given, for the cases that show each one is compared.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn with_identity(
        invocation: Option<InvocationId>,
        pid: u32,
        creation_time: u64,
    ) -> ResumePermit {
        ResumePermit {
            invocation,
            pid,
            creation_time,
        }
    }

    /// The invocation the permit belongs to, or none for a program of the proof.
    #[must_use]
    pub fn invocation(&self) -> Option<InvocationId> {
        self.invocation
    }
}

/// What to start, and how.
pub struct ChildSpec<'a> {
    /// The invocation the child belongs to, or none for a program of the proof. Only a permit for
    /// this invocation resumes the child.
    pub invocation: Option<InvocationId>,
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
    /// The caller's absolute deadline. A child that is ended on an error path, before it ran, is
    /// waited for no longer than this (with a floor of 100 ms); none waits for five seconds.
    pub deadline: Option<Instant>,
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
    /// Whether the child was made suspended.
    suspended: bool,
    /// The invocation the child belongs to, or none for a program of the proof.
    invocation: Option<InvocationId>,
    /// Where the job's owner is told that this child could not be shown to have ended.
    reports: Reports,
    /// The caller's deadline, which the wait for this child's end keeps to when it is dropped.
    deadline: Option<Instant>,
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

/// Hooks for the cases.
#[cfg(feature = "testing")]
pub mod testing {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::win::ffi::Handle;

    static SKIP_NEXT_TERMINATION: AtomicBool = AtomicBool::new(false);
    static FAIL_NEXT_LAUNCH_AFTER_CREATION: AtomicBool = AtomicBool::new(false);
    static HOLD_NEXT_PIPE_WRITER: AtomicBool = AtomicBool::new(false);
    static FAIL_NEXT_EXIT_CODE_READ: AtomicBool = AtomicBool::new(false);
    static HELD_WRITERS: Mutex<Vec<Handle>> = Mutex::new(Vec::new());

    /// Makes the next dropped suspended child skip its call to end the process, as if the platform
    /// had refused it: the child stays, and its drop must report that it was not seen to end.
    pub fn skip_next_termination() {
        SKIP_NEXT_TERMINATION.store(true, Ordering::SeqCst);
    }

    pub(super) fn take_skip() -> bool {
        SKIP_NEXT_TERMINATION.swap(false, Ordering::SeqCst)
    }

    /// Makes the next launch fail after its process was made, as if a call that comes after the
    /// creation had failed: the child is dropped, which ends it and waits for it.
    pub fn fail_next_launch_after_creation() {
        FAIL_NEXT_LAUNCH_AFTER_CREATION.store(true, Ordering::SeqCst);
    }

    pub(super) fn take_fail_after_creation() -> bool {
        FAIL_NEXT_LAUNCH_AFTER_CREATION.swap(false, Ordering::SeqCst)
    }

    /// Makes the next capture pipe keep a writer outside the launcher: a copy of its write end is
    /// held until [`release_held_pipe_writers`], as a process that is not in the job would hold it.
    /// The pipe then does not reach its end when the job's processes have gone.
    pub fn hold_next_pipe_writer() {
        HOLD_NEXT_PIPE_WRITER.store(true, Ordering::SeqCst);
    }

    pub(super) fn take_hold() -> bool {
        HOLD_NEXT_PIPE_WRITER.swap(false, Ordering::SeqCst)
    }

    pub(super) fn keep(writer: Handle) {
        HELD_WRITERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(writer);
    }

    /// Lets go of every writer that [`hold_next_pipe_writer`] kept.
    pub fn release_held_pipe_writers() {
        HELD_WRITERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    /// Makes the next read of a child's exit code fail, after the child has ended.
    pub fn fail_next_exit_code_read() {
        FAIL_NEXT_EXIT_CODE_READ.store(true, Ordering::SeqCst);
    }

    pub(super) fn take_fail_exit_code() -> bool {
        FAIL_NEXT_EXIT_CODE_READ.swap(false, Ordering::SeqCst)
    }
}

/// How long a dropped suspended child is waited for when its caller gave no deadline.
const END_WAIT_MS: u32 = 5_000;
/// The least a child that was ended is waited for, whatever the deadline: the call that ends a
/// process returns before the process is signalled as ended. The one floor beyond a deadline.
const END_FLOOR_MS: u32 = 100;

/// Ends a child that never ran and waits for it: up to [`END_WAIT_MS`], or up to the caller's
/// deadline when it gave one (never less than [`END_FLOOR_MS`]). A child that is not seen to end is
/// reported to the job's owner, whatever the call to end it said: no release or removal may rest on
/// this child's end. The drop of a suspended child and the launch's own error path both end a
/// child this way.
fn end_unresumed(process: &Handle, pid: u32, reports: &Reports, deadline: Option<Instant>) {
    #[cfg(feature = "testing")]
    let skipped = testing::take_skip();
    #[cfg(not(feature = "testing"))]
    let skipped = false;
    // SAFETY: the process handle is open and the process is the caller's own child.
    let terminated = !skipped && unsafe { TerminateProcess(process.raw(), 1) } != 0;
    let terminate_error = (!terminated).then(|| last("ending a suspended child"));
    let wait_ms = deadline.map_or(END_WAIT_MS, |deadline| {
        u32::try_from(
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
        )
        .unwrap_or(END_WAIT_MS)
        .clamp(END_FLOOR_MS, END_WAIT_MS)
    });
    // SAFETY: as above.
    let waited = unsafe { WaitForSingleObject(process.raw(), wait_ms) };
    if waited != WAIT_OBJECT_0 {
        let call = terminate_error.map_or_else(
            || "the call succeeded".to_owned(),
            |error| error.to_string(),
        );
        reports.add(format!(
            "the suspended child (process {pid}) was not seen to end within {wait_ms} ms ({call})"
        ));
    }
}

impl Drop for SuspendedChild {
    fn drop(&mut self) {
        end_unresumed(&self.process, self.pid, &self.reports, self.deadline);
    }
}

impl SuspendedChild {
    /// The invocation the child belongs to, or none for a program of the proof.
    #[must_use]
    pub fn invocation(&self) -> Option<InvocationId> {
        self.invocation
    }

    /// Lets the child run, with the permit that was made for this child.
    ///
    /// # Errors
    ///
    /// Returns an error, and ends the child, when the permit is for another child, when the thread
    /// cannot be resumed, or when it was not suspended exactly once.
    pub fn resume(self, permit: ResumePermit) -> Result<Child, LaunchError> {
        if permit.invocation != self.invocation
            || permit.pid != self.pid
            || permit.creation_time != self.creation_time
        {
            // Dropping `self` ends the child.
            return Err(LaunchError::PermitForAnotherChild);
        }
        // SAFETY: the thread handle is open.
        let previous = if self.suspended {
            unsafe { ResumeThread(self.thread.raw()) }
        } else {
            1
        };
        if previous != 1 {
            // Dropping `self` ends the child.
            return Err(if previous == u32::MAX {
                LaunchError::Platform(last("resuming the child"))
            } else {
                LaunchError::Handle("the child was not suspended exactly once")
            });
        }
        let this = ManuallyDrop::new(self);
        // SAFETY: `this` is never used or dropped again, so each handle and the reference to the
        // job's reports are moved out once and the platform sees the child resumed, not ended.
        let (process, thread, reports) = unsafe {
            (
                std::ptr::read(&this.process),
                std::ptr::read(&this.thread),
                std::ptr::read(&this.reports),
            )
        };
        drop(thread);
        drop(reports);
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
        #[cfg(feature = "testing")]
        if testing::take_fail_exit_code() {
            return Err(ffi::error(
                0,
                "reading the exit code failed, as a case asked",
            ));
        }
        // SAFETY: the process has ended and the handle is open.
        if unsafe { GetExitCodeProcess(self.process.raw(), &raw mut code) } == 0 {
            return Err(last("reading the exit code"));
        }
        Ok(Some(code))
    }

    /// Ends the child by force.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the call fails: the child's end is then not proved until
    /// it is observed.
    pub fn terminate(&self) -> Result<(), ffi::Error> {
        // SAFETY: the process handle is open.
        if unsafe { TerminateProcess(self.process.raw(), 1) } == 0 {
            return Err(last("ending a child"));
        }
        Ok(())
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
/// writes, which it inherits. Its descriptor is explicit: only the system may open the pipe
/// object, and the child holds its end as an inherited handle.
///
/// # Errors
///
/// Returns the platform's error when the pipe cannot be made.
pub fn pipe() -> Result<(Handle, OwnedPipeEnd), ffi::Error> {
    let descriptor = descriptor(SdKind::CapturePipe, &Principals::default())?;
    let mut attributes = descriptor.attributes();
    attributes.bInheritHandle = 1;
    let mut read: HANDLE = null_mut();
    let mut write: HANDLE = null_mut();
    // SAFETY: the out-parameters and the attributes are this function's own for the call.
    if unsafe { CreatePipe(&raw mut read, &raw mut write, &raw const attributes, 0) } == 0 {
        return Err(last("making a pipe"));
    }
    let read = Handle::new(read, "the pipe's read end")?;
    let write = Handle::new(write, "the pipe's write end")?;
    #[cfg(feature = "testing")]
    if testing::take_hold() {
        let mut copy: HANDLE = null_mut();
        // SAFETY: both handles are open; the copy is owned by the value made below and no child
        // can inherit it.
        unsafe {
            windows_sys::Win32::Foundation::DuplicateHandle(
                GetCurrentProcess(),
                write.raw(),
                GetCurrentProcess(),
                &raw mut copy,
                0,
                0,
                windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS,
            );
        }
        testing::keep(Handle::new(copy, "a held copy of the pipe's write end")?);
    }
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
    let count = 2;
    let mut size = 0_usize;
    // SAFETY: the first call only asks for the size it needs, and is expected to fail.
    unsafe {
        InitializeProcThreadAttributeList(null_mut(), count, 0, &raw mut size);
    }
    if size == 0 {
        return Err(LaunchError::Platform(last("sizing the attribute list")));
    }
    let mut list = Attributes {
        storage: vec![0_usize; size.div_ceil(size_of::<usize>())],
    };
    // SAFETY: the buffer is the size the first call asked for and is aligned for the list.
    if unsafe { InitializeProcThreadAttributeList(list.list(), count, 0, &raw mut size) } == 0 {
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
    } != 0;
    if !handle_list {
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
    } != 0;
    if !job_list {
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
    // A job that has been ended is closed to new children: the platform would still take one.
    if spec.job.state() == State::Ended {
        return Err(LaunchError::Job(ffi::error(
            0,
            "the job has ended and takes no new process",
        )));
    }
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
    let flags = CREATE_SUSPENDED
        | EXTENDED_STARTUPINFO_PRESENT
        | CREATE_UNICODE_ENVIRONMENT
        | DETACHED_PROCESS;
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
            flags,
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
            // The child is ended and waited for as a dropped one is, and reported when it is not
            // seen to end: the caller reads the job's reports on its way out.
            end_unresumed(
                &process,
                created.dwProcessId,
                &spec.job.reports(),
                spec.deadline,
            );
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
        suspended: true,
        invocation: spec.invocation,
        reports: spec.job.reports(),
        deadline: spec.deadline,
    };
    // From here a failure drops `child`, which ends it.
    child.creation_time = time_of(&child.process)?;
    #[cfg(feature = "testing")]
    if testing::take_fail_after_creation() {
        return Err(LaunchError::Platform(ffi::error(
            0,
            "a failure after the process was made, asked for by a case",
        )));
    }
    match spec.job.contains(&child.process) {
        Ok(true) => child.in_job_checked = true,
        Ok(false) => return Err(LaunchError::NotInJob),
        Err(error) => return Err(LaunchError::Platform(error)),
    }
    Ok(child)
}

/// The most [`read_pipe`] keeps; the rest is read and dropped.
const CAPTURE_LIMIT: usize = 8 << 20;

/// How often [`read_pipe`] looks again at a pipe that holds nothing yet.
const PIPE_POLL: Duration = Duration::from_millis(10);

/// What [`read_pipe`] read.
#[derive(Debug)]
pub struct Piped {
    /// What the pipe held, up to a limit.
    pub bytes: Vec<u8>,
    /// Whether the pipe reached its end: every writer had closed its handle. When it did not, a
    /// process that is not shown to have ended still holds the child's output.
    pub ended: bool,
}

/// Reads a pipe to its end or to a deadline, whichever comes first, keeping up to a limit of what
/// it holds. The end comes when every writer has closed its handle, which for a child's output
/// means the child and everything it started has ended. The reader looks at what the pipe holds
/// before it reads, so no call waits on a writer that never closes, and it looks at the clock on
/// every pass, so a writer that keeps the pipe supplied does not keep the reader past the deadline.
#[must_use]
pub fn read_pipe(pipe: &Handle, deadline: Instant) -> Piped {
    let mut kept = Vec::new();
    let mut chunk = vec![0_u8; 64 * 1024];
    loop {
        if Instant::now() >= deadline {
            return Piped {
                bytes: kept,
                ended: false,
            };
        }
        let mut available = 0_u32;
        // SAFETY: the pipe is open and only the available-bytes out-parameter is used.
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
            // A pipe with no writer left answers with a broken pipe: that is its end. Any other
            // failure leaves the end unproved.
            // SAFETY: reads the calling thread's last error.
            let ended =
                unsafe { windows_sys::Win32::Foundation::GetLastError() } == ERROR_BROKEN_PIPE;
            return Piped { bytes: kept, ended };
        }
        if available == 0 {
            std::thread::sleep(PIPE_POLL.min(deadline.saturating_duration_since(Instant::now())));
            continue;
        }
        let mut read = 0_u32;
        let wanted = available.min(chunk.len() as u32);
        // SAFETY: the pipe is open, `wanted` bytes are waiting and the buffer is at least that long.
        let ok = unsafe {
            ReadFile(
                pipe.raw(),
                chunk.as_mut_ptr().cast(),
                wanted,
                &raw mut read,
                null_mut(),
            )
        };
        if ok == 0 || read == 0 {
            // SAFETY: reads the calling thread's last error.
            let ended = ok == 0
                && unsafe { windows_sys::Win32::Foundation::GetLastError() } == ERROR_BROKEN_PIPE;
            return Piped { bytes: kept, ended };
        }
        let room = CAPTURE_LIMIT.saturating_sub(kept.len());
        kept.extend_from_slice(&chunk[..(read as usize).min(room)]);
    }
}
