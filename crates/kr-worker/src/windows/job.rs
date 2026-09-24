//! The job object a session's processes are held by.
//!
//! Section 7: *the worker holds the sole owning handle for a per-session Job Object with
//! kill-on-close. Owned child processes join it before execution. Default breakaway is disabled.*
//! Each of those three is a decision this module makes and a test can check.
//!
//! **Sole owning handle.** The job is created without a name, so nothing else on the machine can
//! open it by asking for it; the only handle is this one. Kill-on-close then means what it says: a
//! worker that crashes, is killed, or exits without closing its session still takes the processes
//! down with it, because the last handle to the job goes with the process that held it.
//!
//! **Joined before execution.** A process that ran before it was assigned could have started
//! children of its own that are outside the job for ever. So the operating system puts the shell
//! into the job as part of creating it, through the create's own job-list attribute: there is no
//! window in which it is running and unheld, and none in which it exists and is unheld either, so
//! a worker that dies between the create and the first instruction still takes it down. The shell
//! is created suspended on top of that, and the kernel is asked whether it really holds it before
//! anything runs.
//!
//! **Breakaway disabled.** Neither `JOB_OBJECT_LIMIT_BREAKAWAY_OK` nor
//! `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK` is set, so a child that asks to be created outside the
//! job is refused rather than granted. This is not the same question as nesting: a vendor sandbox
//! that creates a job of its own nests inside this one, which Windows 8 and later support, and
//! that child job's limits apply on top of these rather than instead of them. [S48]
//!
//! **What is deliberately outside it.** A GUI resource that has to outlive the session is created
//! through the desktop broker, which starts it outside this job and records it as an external
//! resource. Existing browsers, simulators and their shared services are never in the job and are
//! never ended by closing it.
//!
//! **What this worker is not in.** The worker process itself is never assigned to the job it owns.
//! Kill-on-close would then make the worker's own exit its own killer, and section 7 is explicit
//! that a Windows worker does not belong to a kill-on-close job that something else owns either.
//!
//! **An agent's job.** An agent the session's broker launches runs in a job of its own, for a
//! different reason: so that the broker can say which processes are that agent's. The parent a
//! Windows process names is kept after that parent exits, so a chain of parents read back from the
//! kernel proves nothing here; a job does. The agent joins its job before it runs and breakaway is
//! disabled, so the job holds the agent and every process the agent starts, and nothing else. It
//! is not kill-on-close: it is a record of who belongs to the agent, not a second owner of the
//! agent's lifetime, which stays what it is without one.

#![expect(
    unsafe_code,
    reason = "creating a job object and moving a process into it have no safe form"
)]

use std::collections::BTreeMap;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::os::windows::process::CommandExt as _;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use kr_protocol::identity::ProcessStartIdentity;
use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    JOBOBJECT_BASIC_PROCESS_ID_LIST, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation, QueryInformationJobObject,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
};

/// How many process identifiers one query asks the job for before it asks again with more room.
const FIRST_QUERY_CAPACITY: usize = 64;

/// The most a query will ever ask for, so a job with a runaway number of processes cannot make
/// this allocate without bound.
const MAX_QUERY_CAPACITY: usize = 16 * 1024;

/// A job object this worker owns, holding one session's processes.
#[derive(Debug)]
pub struct SessionJob {
    job: Job,
}

impl SessionJob {
    /// Creates the session's job: unnamed, kill-on-close, breakaway disabled.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure when the job cannot be created or its limits cannot
    /// be set. A caller that cannot have a job has a named launch failure to report or a
    /// reduced-ownership profile to select explicitly; it never carries on as though it had one.
    pub fn create() -> std::io::Result<Self> {
        let job = Job::create(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)?;
        // Read back from the operating system before this job is anybody's boundary. A job whose
        // limits are not what section 7 requires is a named launch failure here rather than a
        // session that carries on owning less than it says it does.
        if !job.kills_on_close()? {
            return Err(std::io::Error::other(
                "the session's job object does not end what it holds when it is closed",
            ));
        }
        if job.breakaway_permitted()? {
            return Err(std::io::Error::other(
                "the session's job object would let a child break away from it",
            ));
        }
        Ok(Self { job })
    }

    /// Returns the handle a process creation names this job by.
    ///
    /// The creation's job-list attribute takes the job's own handle, which is how the operating
    /// system performs the assignment itself rather than leaving it to a second call.
    pub(super) fn handle(&self) -> HANDLE {
        self.job.raw()
    }

    /// Returns whether a process is inside this job.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure when it will not say.
    pub fn holds(&self, process: &OwnedHandle) -> std::io::Result<bool> {
        self.job.holds(process.as_raw_handle().cast())
    }

    /// Returns whether this job still permits a child to break away from it.
    ///
    /// Read back from the operating system rather than from what was asked for, because what the
    /// ownership record claims has to be what the kernel is enforcing.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure when the limits cannot be read.
    pub fn breakaway_permitted(&self) -> std::io::Result<bool> {
        self.job.breakaway_permitted()
    }

    /// Returns whether closing the last handle to this job ends the processes it holds.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure when the limits cannot be read.
    pub fn kills_on_close(&self) -> std::io::Result<bool> {
        self.job.kills_on_close()
    }

    /// Returns the identifiers of every process the job currently holds.
    ///
    /// This is the process tree. A descendant that changed its session, detached, or was started
    /// by something the shell started is in it just the same, which is what makes this a boundary
    /// rather than a guess. An identifier alone is not an identity: the caller asks the operating
    /// system to describe each one before it records it.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure when the job will not say. A partial answer is never
    /// returned as a whole one: a job holding more processes than the query had room for is asked
    /// again with more.
    pub fn process_ids(&self) -> std::io::Result<Vec<u32>> {
        self.job.process_ids()
    }

    /// Ends every process the job holds, at once.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure when the job will not be terminated.
    pub fn terminate(&self, code: u32) -> std::io::Result<()> {
        self.job.terminate(code)
    }
}

/// A job object this worker owns, holding one agent its broker launched and every process that
/// agent starts.
#[derive(Debug)]
pub struct AgentJob {
    job: Job,
}

impl AgentJob {
    /// Creates an agent's job: unnamed, breakaway disabled, and not kill-on-close.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure when the job cannot be created or its limits cannot
    /// be set, and a failure of its own when the kernel reports that a child could break away.
    pub fn create() -> std::io::Result<Self> {
        let job = Job::create(0)?;
        // A job a child could leave would hold some of the agent's processes and not others, and a
        // process it did not hold would be taken for one that is not the agent's.
        if job.breakaway_permitted()? {
            return Err(std::io::Error::other(
                "the agent's job object would let a child break away from it",
            ));
        }
        Ok(Self { job })
    }

    /// Starts `command` inside this job, joined before it runs.
    ///
    /// The process is created suspended, put into the job, and resumed only once the kernel says
    /// the job holds it, so no instruction of it runs outside the job and nothing it starts is
    /// outside it either. The command's creation flags are this call's. A failure at any step ends
    /// the process rather than leaving one this worker cannot account for, and a failure to end it
    /// is reported rather than swallowed.
    ///
    /// # Errors
    ///
    /// Returns the failure to start the process, to put it into this job, to confirm that the job
    /// holds it, or to resume it.
    pub fn start(
        &self,
        command: &mut std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        command.creation_flags(CREATE_SUSPENDED);
        let mut child = command.spawn()?;
        // SAFETY: both handles are open for the call: the job's is this object's own, and the
        // process's belongs to `child`, which outlives the call.
        let assigned =
            unsafe { AssignProcessToJobObject(self.job.raw(), child.as_raw_handle().cast()) };
        if assigned == 0 {
            let failure = std::io::Error::last_os_error();
            return Err(end_unstarted(
                &mut child,
                &format!("it could not be put into its job: {failure}"),
            ));
        }
        // Suspended, so nothing has run yet. The kernel is asked whether the job really holds it
        // rather than the assignment being taken at its word: a process this host believed was
        // the agent's and was not would be placed by a job that does not describe it.
        match self.job.holds(child.as_raw_handle().cast()) {
            Ok(true) => {}
            Ok(false) => return Err(end_unstarted(&mut child, "its job does not hold it")),
            Err(failure) => {
                return Err(end_unstarted(
                    &mut child,
                    &format!("its job would not say whether it holds it: {failure}"),
                ));
            }
        }
        if let Err(failure) = resume(child.id()) {
            return Err(end_unstarted(
                &mut child,
                &format!("it could not be resumed: {failure}"),
            ));
        }
        Ok(child)
    }

    /// Returns whether this job holds `child`.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure when it will not say.
    pub fn holds(&self, child: &std::process::Child) -> std::io::Result<bool> {
        self.job.holds(child.as_raw_handle().cast())
    }

    /// Returns whether this job still permits a child to break away from it.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure when the limits cannot be read.
    pub fn breakaway_permitted(&self) -> std::io::Result<bool> {
        self.job.breakaway_permitted()
    }

    /// Returns whether closing the last handle to this job ends the processes it holds.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure when the limits cannot be read.
    pub fn kills_on_close(&self) -> std::io::Result<bool> {
        self.job.kills_on_close()
    }

    /// Returns the identifiers of every process the job currently holds: the agent while it runs,
    /// and every process it started that is still running.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure when the job will not say. A partial answer is never
    /// returned as a whole one.
    pub fn process_ids(&self) -> std::io::Result<Vec<u32>> {
        self.job.process_ids()
    }

    /// Ends every process the job holds, at once.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure when the job will not be terminated.
    pub fn terminate(&self, code: u32) -> std::io::Result<()> {
        self.job.terminate(code)
    }
}

/// Ends a process that was created suspended and never resumed, and says why.
///
/// When the process cannot be ended either, the error carries both causes: the one that stopped
/// the start, and the one that stopped the cleanup, because the second says what is still there.
fn end_unstarted(child: &mut std::process::Child, because: &str) -> std::io::Error {
    match child.kill().and_then(|()| child.wait().map(drop)) {
        Ok(()) => std::io::Error::other(format!(
            "a process was created and never started, because {because}"
        )),
        Err(failure) => std::io::Error::other(format!(
            "a process was created and never started, because {because}, and then could not be \
             ended either: {failure}"
        )),
    }
}

/// An unnamed job object this worker holds the only handle to, and what it can be asked.
#[derive(Debug)]
struct Job {
    handle: OwnedHandle,
}

impl Job {
    /// Creates an unnamed job with these limit flags and no others.
    fn create(limit_flags: u32) -> std::io::Result<Self> {
        // SAFETY: both arguments are the documented "no security attributes, no name". The call
        // returns a handle this process owns, or null.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the call reported a handle this process owns and nothing else holds.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
        let job = Self { handle };
        job.apply_limits(limit_flags)?;
        Ok(job)
    }

    /// Sets these limit flags and nothing else.
    fn apply_limits(&self, limit_flags: u32) -> std::io::Result<()> {
        // SAFETY: the structure is integers and pointers throughout, and all zeroes is the state
        // that means "no limit set", which is exactly what every field but the one below should be.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = limit_flags;
        // SAFETY: the handle is this object's own and open for the call; the structure is a local
        // this thread owns and its declared size is its own.
        let set = unsafe {
            SetInformationJobObject(
                self.raw(),
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .unwrap_or(0),
            )
        };
        if set == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Returns whether a process is inside this job.
    fn holds(&self, process: HANDLE) -> std::io::Result<bool> {
        let mut inside = 0_i32;
        // SAFETY: both handles are open for the call and the answer is a local this thread owns.
        let asked = unsafe { IsProcessInJob(process, self.raw(), &raw mut inside) };
        if asked == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(inside != 0)
    }

    /// Returns whether this job still permits a child to break away from it, as the kernel reads
    /// its limits back rather than as they were asked for.
    fn breakaway_permitted(&self) -> std::io::Result<bool> {
        let flags = self.limit_flags()?;
        Ok(flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) != 0)
    }

    /// Returns whether closing the last handle to this job ends the processes it holds.
    fn kills_on_close(&self) -> std::io::Result<bool> {
        Ok(self.limit_flags()? & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0)
    }

    fn limit_flags(&self) -> std::io::Result<u32> {
        // SAFETY: as in `apply_limits`; the call fills the structure rather than reading it.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        let mut written = 0_u32;
        // SAFETY: the handle is this object's own and open for the call; the structure and the
        // count are locals this thread owns, and the declared size is the structure's own.
        let read = unsafe {
            QueryInformationJobObject(
                self.raw(),
                JobObjectExtendedLimitInformation,
                std::ptr::from_mut(&mut limits).cast(),
                u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .unwrap_or(0),
                &raw mut written,
            )
        };
        if read == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(limits.BasicLimitInformation.LimitFlags)
    }

    /// Returns the identifiers of every process the job currently holds, asking again with more
    /// room while the answer is partial.
    fn process_ids(&self) -> std::io::Result<Vec<u32>> {
        let mut capacity = FIRST_QUERY_CAPACITY;
        loop {
            match self.query_process_ids(capacity)? {
                Query::Complete(ids) => return Ok(ids),
                Query::Truncated { holds } if capacity < MAX_QUERY_CAPACITY => {
                    // Ask for what it said it holds, and a little more, because processes start
                    // between one query and the next.
                    capacity = holds.saturating_add(holds / 2).max(capacity * 2);
                    capacity = capacity.min(MAX_QUERY_CAPACITY);
                }
                Query::Truncated { holds } => {
                    return Err(std::io::Error::other(format!(
                        "the job holds {holds} processes, more than one query may ask for"
                    )));
                }
            }
        }
    }

    /// Asks once, with room for `capacity` identifiers.
    fn query_process_ids(&self, capacity: usize) -> std::io::Result<Query> {
        // One header followed by `capacity` identifiers. The declared structure carries the first
        // identifier itself, so the buffer is the header plus the rest.
        let header = std::mem::size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>();
        let extra = capacity.saturating_sub(1) * std::mem::size_of::<usize>();
        let mut buffer = vec![0_u8; header + extra];
        let mut written = 0_u32;
        // SAFETY: the handle is this object's own and open for the call. The buffer is a local
        // this thread owns, its declared length is its own, and the count is another local.
        let read = unsafe {
            QueryInformationJobObject(
                self.raw(),
                JobObjectBasicProcessIdList,
                buffer.as_mut_ptr().cast(),
                u32::try_from(buffer.len()).unwrap_or(u32::MAX),
                &raw mut written,
            )
        };
        // A buffer too small is reported as a failure *and* fills in what fitted, so that one
        // failure is read as "ask again with more room" and every other one is a failure.
        let failure = (read == 0).then(std::io::Error::last_os_error);
        if let Some(failure) = &failure
            && !failure
                .raw_os_error()
                .and_then(|code| u32::try_from(code).ok())
                .is_some_and(|code| code == ERROR_MORE_DATA || code == ERROR_INSUFFICIENT_BUFFER)
        {
            return Err(std::io::Error::other(format!(
                "the job would not say which processes it holds: {failure}"
            )));
        }
        // SAFETY: the call filled the buffer this thread owns with a structure of this shape, and
        // the read is inside the allocation because the buffer is at least one header long.
        let list = unsafe {
            std::ptr::read_unaligned(buffer.as_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>())
        };
        let holds = usize::try_from(list.NumberOfAssignedProcesses).unwrap_or(0);
        let returned = usize::try_from(list.NumberOfProcessIdsInList).unwrap_or(0);
        if returned > capacity {
            // The operating system reported more than it had room for, which is not an answer.
            return Ok(Query::Truncated { holds });
        }
        let mut ids = Vec::with_capacity(returned);
        for index in 0..returned {
            let offset = std::mem::offset_of!(JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList)
                + index * std::mem::size_of::<usize>();
            if offset + std::mem::size_of::<usize>() > buffer.len() {
                break;
            }
            // SAFETY: the offset and the size are inside the buffer this thread owns, which the
            // check above establishes, and an identifier is a plain integer.
            let value =
                unsafe { std::ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<usize>()) };
            if let Ok(pid) = u32::try_from(value) {
                ids.push(pid);
            }
        }
        if holds > returned || ids.len() != returned || failure.is_some() {
            // Either the job holds more than it reported, or the buffer did not carry every entry
            // the header counted. Both are a partial answer, and a partial answer is never
            // returned as a whole one.
            return Ok(Query::Truncated {
                holds: holds.max(returned),
            });
        }
        Ok(Query::Complete(ids))
    }

    /// Ends every process the job holds, at once.
    fn terminate(&self, code: u32) -> std::io::Result<()> {
        // SAFETY: the handle is this object's own and open for the call.
        let ended = unsafe { TerminateJobObject(self.raw(), code) };
        if ended == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn raw(&self) -> HANDLE {
        self.handle.as_raw_handle().cast()
    }
}

/// The job each live session's root shell is held by, found by that shell's identifier.
///
/// The ownership boundary is established from the root shell's identity, after the launch and
/// away from the terminal that performed it, so the two need somewhere to meet. This is that
/// place. The reference is weak on purpose: the job is kill-on-close, so a strong one left here
/// would keep a closed session's processes alive for the rest of the worker's life.
static JOBS: OnceLock<Mutex<BTreeMap<u32, Weak<SessionJob>>>> = OnceLock::new();

fn registry() -> &'static Mutex<BTreeMap<u32, Weak<SessionJob>>> {
    JOBS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Records that `root` is held by `job`, and forgets every session whose job has gone.
pub fn record(root: u32, job: &Arc<SessionJob>) {
    let mut jobs = registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    jobs.retain(|_, held| held.strong_count() > 0);
    jobs.insert(root, Arc::downgrade(job));
}

/// Returns the job holding the session whose root shell is `root`, while that session is live.
#[must_use]
pub fn holding(root: u32) -> Option<Arc<SessionJob>> {
    let jobs = registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    jobs.get(&root).and_then(Weak::upgrade)
}

/// The job each agent this worker launched was started in, found by that agent's start identity.
///
/// The agent is started where the broker's launch is, and placed where a caller is verified, so the
/// two need somewhere to meet, as a session's root shell and its boundary do. The reference is
/// strong and kept until the broker lets it go with [`release_agent`], when the last instance that
/// names the agent ends: an agent's job is not kill-on-close, so keeping it keeps no process alive,
/// and the broker asks about an agent only for as long as one of its instances lasts. It costs one
/// handle for each agent with a live instance.
static AGENTS: OnceLock<Mutex<Vec<KeptAgent>>> = OnceLock::new();

/// One launched agent and the job it was started in.
type KeptAgent = (ProcessStartIdentity, Arc<AgentJob>);

fn agents() -> &'static Mutex<Vec<KeptAgent>> {
    AGENTS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Records that `agent` was started in `job`.
pub fn keep_agent(agent: ProcessStartIdentity, job: Arc<AgentJob>) {
    let mut kept = agents()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    kept.retain(|(recorded, _)| *recorded != agent);
    kept.push((agent, job));
}

/// Forgets the job `agent` was started in.
///
/// Nothing is placed under the agent afterwards: a process it started is found in no job this
/// worker keeps. Closing the handle ends nothing, because an agent's job is not kill-on-close, and
/// forgetting an agent that was never kept changes nothing.
pub fn release_agent(agent: &ProcessStartIdentity) {
    let mut kept = agents()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    kept.retain(|(recorded, _)| recorded != agent);
}

/// Returns the job `agent` was started in, or None when this worker did not start it in one.
#[must_use]
pub fn agent_job(agent: &ProcessStartIdentity) -> Option<Arc<AgentJob>> {
    let kept = agents()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    kept.iter()
        .find(|(recorded, _)| recorded == agent)
        .map(|(_, job)| Arc::clone(job))
}

/// Resumes a process that was created suspended.
///
/// The standard library's process creation keeps the handle of the thread it created to itself, so
/// the thread is found in the system's list of threads. A process created suspended has that one
/// thread. Every thread of the process is resumed, and resuming a thread that is running already
/// changes nothing.
fn resume(pid: u32) -> std::io::Result<()> {
    // SAFETY: the flag is the documented "every thread in the system" and the identifier is
    // ignored for it. The call returns a handle this process owns, or the invalid value.
    let raw = unsafe { toolhelp::CreateToolhelp32Snapshot(toolhelp::TH32CS_SNAPTHREAD, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the call reported a handle this process owns and nothing else holds.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
    let mut entry = toolhelp::ThreadEntry::sized();
    let mut resumed = 0_usize;
    // SAFETY: the snapshot is open for the call and the entry is a local of the declared size.
    let mut listed =
        unsafe { toolhelp::Thread32First(snapshot.as_raw_handle().cast(), &raw mut entry) };
    while listed != 0 {
        if entry.owner_process_id == pid {
            // SAFETY: the access right and the identifier are plain values; the call returns a
            // handle this process owns, or null.
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.thread_id) };
            if thread.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: the call reported a handle this process owns and nothing else holds.
            let thread = unsafe { OwnedHandle::from_raw_handle(thread.cast()) };
            // SAFETY: the handle is open for the call with the right to resume.
            if unsafe { ResumeThread(thread.as_raw_handle().cast()) } == u32::MAX {
                return Err(std::io::Error::last_os_error());
            }
            resumed += 1;
        }
        // SAFETY: as for the first entry.
        listed = unsafe { toolhelp::Thread32Next(snapshot.as_raw_handle().cast(), &raw mut entry) };
    }
    let ended = std::io::Error::last_os_error();
    if ended
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
        != Some(ERROR_NO_MORE_FILES)
    {
        return Err(ended);
    }
    if resumed == 0 {
        return Err(std::io::Error::other(format!(
            "the system lists no thread of process {pid}"
        )));
    }
    Ok(())
}

/// The system's thread list, which `windows-sys` declares only behind a feature this crate does not
/// enable: the three documented `kernel32` functions and the one structure they fill.
mod toolhelp {
    use windows_sys::Win32::Foundation::HANDLE;

    /// Asks for every thread in the system.
    pub(super) const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;

    /// One thread as the list describes it: `THREADENTRY32`. The fields this worker never reads
    /// are there because the system writes them.
    #[repr(C)]
    #[derive(Default)]
    pub(super) struct ThreadEntry {
        /// The structure's own size, set before the first call.
        pub(super) size: u32,
        _usage: u32,
        /// The thread's identifier.
        pub(super) thread_id: u32,
        /// The identifier of the process the thread belongs to.
        pub(super) owner_process_id: u32,
        _base_priority: i32,
        _delta_priority: i32,
        _flags: u32,
    }

    impl ThreadEntry {
        /// An empty entry that says its own size, which the list requires before the first call.
        pub(super) fn sized() -> Self {
            Self {
                size: u32::try_from(std::mem::size_of::<Self>()).unwrap_or(0),
                ..Self::default()
            }
        }
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub(super) fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> HANDLE;
        pub(super) fn Thread32First(snapshot: HANDLE, entry: *mut ThreadEntry) -> i32;
        pub(super) fn Thread32Next(snapshot: HANDLE, entry: *mut ThreadEntry) -> i32;
    }
}

/// What one query of the job's process list produced.
enum Query {
    /// Every identifier the job holds.
    Complete(Vec<u32>),
    /// The job holds more than the query had room for.
    Truncated {
        /// How many it says it holds.
        holds: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_job_kills_on_close_and_refuses_breakaway() {
        // What the kernel says the limits are, rather than what was asked for. The behaviour those
        // limits name is checked by `closing_the_last_handle_ends_what_the_job_holds` in
        // `crates/kr-worker/tests/windows.rs`, which needs a process to hold.
        let job = SessionJob::create().expect("a job");
        assert!(
            job.kills_on_close().expect("the limits"),
            "closing the last handle ends what the job holds"
        );
        assert!(
            !job.breakaway_permitted().expect("the limits"),
            "a child cannot leave the job by asking"
        );
    }

    #[test]
    fn an_empty_job_holds_nothing() {
        let job = SessionJob::create().expect("a job");
        assert!(job.process_ids().expect("the process list").is_empty());
    }

    /// A process that starts one of its own and waits, far longer than any test takes: `cmd.exe`
    /// running `ping`, both on every Windows machine. The test ends both.
    fn an_agent_with_a_child() -> std::process::Command {
        let mut command = std::process::Command::new("cmd.exe");
        command
            .args(["/d", "/c", "ping -n 600 127.0.0.1 > NUL"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        command
    }

    /// A process a test started, ended when the test ends, however it ends: with everything in its
    /// job while the test still holds that job, and on its own otherwise.
    struct Started<'a> {
        job: Option<&'a AgentJob>,
        agent: std::process::Child,
    }

    impl Drop for Started<'_> {
        fn drop(&mut self) {
            if let Some(job) = self.job {
                let _ = job.terminate(1);
            } else {
                let _ = self.agent.kill();
            }
            let _ = self.agent.wait();
        }
    }

    /// Waits until `job` holds at least `count` processes, and returns them.
    fn held_by_at_least(job: &AgentJob, count: usize) -> Vec<u32> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let held = job.process_ids().expect("the job's process list");
            if held.len() >= count {
                return held;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the job still holds only {held:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    #[test]
    fn an_agent_job_refuses_breakaway_and_ends_nothing_when_it_closes() {
        let job = AgentJob::create().expect("a job");
        assert!(
            !job.breakaway_permitted().expect("the limits"),
            "a child cannot leave the job by asking"
        );
        assert!(
            !job.kills_on_close().expect("the limits"),
            "the job records the agent's processes and does not own them"
        );
    }

    #[test]
    fn an_agent_and_every_process_it_starts_are_held_by_its_job() {
        let job = AgentJob::create().expect("a job");
        let started = Started {
            agent: job
                .start(&mut an_agent_with_a_child())
                .expect("the agent starts"),
            job: Some(&job),
        };
        assert!(
            job.holds(&started.agent).expect("the job says"),
            "the agent is in it"
        );
        // The agent's own child joins it without being put there, and this process never does.
        let held = held_by_at_least(&job, 2);
        assert!(held.contains(&started.agent.id()), "the job holds {held:?}");
        assert!(
            !held.contains(&std::process::id()),
            "the worker is never in an agent's job: {held:?}"
        );
    }

    #[test]
    fn closing_an_agent_job_leaves_the_agent_running() {
        let job = AgentJob::create().expect("a job");
        let mut started = Started {
            agent: job
                .start(
                    std::process::Command::new("ping.exe")
                        .args(["-n", "600", "127.0.0.1"])
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null()),
                )
                .expect("the agent starts"),
            job: None,
        };
        drop(job);
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            started
                .agent
                .try_wait()
                .expect("the agent's status")
                .is_none(),
            "closing the job ended the agent"
        );
    }

    #[test]
    fn an_agent_job_is_found_by_the_agent_it_was_started_for() {
        let agent = ProcessStartIdentity::new(
            0xF000_0003,
            kr_protocol::identity::ProcessStartSource::WindowsProcessCreationTime,
            17,
        );
        assert!(agent_job(&agent).is_none(), "nothing was started for it");
        let job = Arc::new(AgentJob::create().expect("a job"));
        keep_agent(agent.clone(), Arc::clone(&job));
        assert!(agent_job(&agent).is_some_and(|found| Arc::ptr_eq(&found, &job)));
        let mut again = agent;
        again.start_value = kr_protocol::scalars::U64::new(18);
        assert!(
            agent_job(&again).is_none(),
            "the same identifier started again is another process"
        );
    }

    #[test]
    fn a_released_agent_is_placed_through_no_job_and_the_others_are_kept() {
        let source = kr_protocol::identity::ProcessStartSource::WindowsProcessCreationTime;
        let released = ProcessStartIdentity::new(0xF000_0004, source, 17);
        let kept = ProcessStartIdentity::new(0xF000_0005, source, 17);
        let released_job = Arc::new(AgentJob::create().expect("a job"));
        let kept_job = Arc::new(AgentJob::create().expect("a job"));
        keep_agent(released.clone(), Arc::clone(&released_job));
        keep_agent(kept.clone(), Arc::clone(&kept_job));

        release_agent(&released);
        assert!(
            agent_job(&released).is_none(),
            "a released agent is placed through no job"
        );
        assert_eq!(
            Arc::strong_count(&released_job),
            1,
            "and nothing but this test holds its job any more"
        );
        assert!(
            agent_job(&kept).is_some_and(|found| Arc::ptr_eq(&found, &kept_job)),
            "another agent's job is kept"
        );
        release_agent(&released);
        assert!(
            agent_job(&kept).is_some(),
            "releasing an agent twice changes nothing else"
        );
        release_agent(&kept);
        assert!(agent_job(&kept).is_none());
    }

    #[test]
    fn a_recorded_job_is_found_by_its_root_and_forgotten_when_it_closes() {
        let root = 0xF000_0001;
        let job = Arc::new(SessionJob::create().expect("a job"));
        record(root, &job);
        assert!(holding(root).is_some(), "the boundary finds the job");
        drop(job);
        assert!(
            holding(root).is_none(),
            "a closed session's job is not kept alive by the record of it"
        );
    }
}
