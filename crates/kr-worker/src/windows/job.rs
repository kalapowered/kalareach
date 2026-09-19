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
//! children of its own that are outside the job for ever. So the shell is created suspended, put
//! into the job, and only then resumed. There is no window in which it is running and unheld.
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

#![expect(
    unsafe_code,
    reason = "creating a job object and moving a process into it have no safe form"
)]

use std::collections::BTreeMap;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    JOBOBJECT_BASIC_PROCESS_ID_LIST, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation, QueryInformationJobObject,
    SetInformationJobObject, TerminateJobObject,
};

/// How many process identifiers one query asks the job for before it asks again with more room.
const FIRST_QUERY_CAPACITY: usize = 64;

/// The most a query will ever ask for, so a job with a runaway number of processes cannot make
/// this allocate without bound.
const MAX_QUERY_CAPACITY: usize = 16 * 1024;

/// A job object this worker owns, holding one session's processes.
#[derive(Debug)]
pub struct SessionJob {
    handle: OwnedHandle,
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
        // SAFETY: both arguments are the documented "no security attributes, no name". The call
        // returns a handle this process owns, or null.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the call reported a handle this process owns and nothing else holds.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
        let job = Self { handle };
        job.apply_limits()?;
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
        Ok(job)
    }

    /// Sets kill-on-close and leaves both breakaway permissions off.
    fn apply_limits(&self) -> std::io::Result<()> {
        // SAFETY: the structure is integers and pointers throughout, and all zeroes is the state
        // that means "no limit set", which is exactly what every field but the one below should be.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
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

    /// Puts a process into the job.
    ///
    /// The caller creates the process suspended and calls this before resuming it, so that nothing
    /// the process starts can be outside the job.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure when the process cannot be assigned.
    pub fn hold(&self, process: &OwnedHandle) -> std::io::Result<()> {
        // SAFETY: both handles are open for the call and neither is retained by it.
        let assigned =
            unsafe { AssignProcessToJobObject(self.raw(), process.as_raw_handle().cast()) };
        if assigned == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Returns whether a process is inside this job.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure when it will not say.
    pub fn holds(&self, process: &OwnedHandle) -> std::io::Result<bool> {
        let mut inside = 0_i32;
        // SAFETY: both handles are open for the call and the answer is a local this thread owns.
        let asked =
            unsafe { IsProcessInJob(process.as_raw_handle().cast(), self.raw(), &raw mut inside) };
        if asked == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(inside != 0)
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
        let flags = self.limit_flags()?;
        Ok(flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) != 0)
    }

    /// Returns whether closing the last handle to this job ends the processes it holds.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure when the limits cannot be read.
    pub fn kills_on_close(&self) -> std::io::Result<bool> {
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
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure when the job will not be terminated.
    pub fn terminate(&self, code: u32) -> std::io::Result<()> {
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
