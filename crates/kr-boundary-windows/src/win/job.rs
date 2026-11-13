//! The job every child of an invocation is made in.
//!
//! The job is unnamed, so nothing opens it by name, and only the broker holds a handle to it. It
//! kills every process in it when its last handle closes, ends a process that dies of an
//! unhandled exception, and caps the number of processes and the memory the job may use. A
//! completion port is attached to it, but the port's messages are only a reason to look again: what
//! decides that a job has ended is the job's own count of active processes and the retained
//! process objects, read after the wake-up.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_ASSOCIATE_COMPLETION_PORT,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_BASIC_PROCESS_ID_LIST,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectAssociateCompletionPortInformation,
    JobObjectBasicAccountingInformation, JobObjectBasicProcessIdList,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject,
};

use super::ffi::{self, Handle, Result, Waited, error, last};
use super::launch::Child;

/// What the job holds a process tree to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The most processes the job may hold at once.
    pub active_processes: u32,
    /// The most memory the whole job may commit, in bytes.
    pub memory_bytes: usize,
}

impl Limits {
    /// The caps of an invocation's job: sixteen processes and one gibibyte.
    pub const INVOCATION: Limits = Limits {
        active_processes: 16,
        memory_bytes: 1 << 30,
    };
}

/// The limit flags every job carries: kill on close, die on an unhandled exception, an
/// active-process cap and a job memory cap.
pub const LIMIT_FLAGS: u32 = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
    | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
    | JOB_OBJECT_LIMIT_JOB_MEMORY;

/// What the platform reports a job's limits to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadBack {
    /// The limit flags in force.
    pub flags: u32,
    /// The cap on active processes.
    pub active_processes: u32,
    /// The cap on the job's memory, in bytes.
    pub memory_bytes: usize,
}

/// Where a job is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// No end has been asked of it.
    Fresh,
    /// [`Job::end`] has run: every process was ended.
    Ended,
}

/// How an end went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ended {
    /// Every retained process object is signalled: each process has exited.
    pub all_exited: bool,
    /// The job's own count of active processes was read at the last look and is zero.
    pub active_zero: bool,
    /// The job's own count of active processes could be read at the last look. Where it could not,
    /// `active_zero` is false and says nothing about the count.
    pub count_read: bool,
}

impl Ended {
    /// Whether the end is proved: every retained process has exited and the job counts no active
    /// process. Anything else is an uncertain end, and nothing is released or removed on the
    /// strength of it. What a child or the end itself reported on the way is in
    /// [`Job::unproved_reasons`].
    #[must_use]
    pub fn proved(self) -> bool {
        self.all_exited && self.active_zero
    }

    /// What the last look at the job's count showed, in words for a person.
    #[must_use]
    // text: count_words
    pub fn count_words(self) -> &'static str {
        match (self.count_read, self.active_zero) {
            (false, _) => "the job's count of processes could not be read",
            (true, true) => "the job counts no process",
            (true, false) => "the job counts a process",
        }
    }
}

/// Where the children of a job tell its owner that one of them could not be shown to have ended.
///
/// A child that is dropped cannot return an error, so it writes here, and the owner reads it when
/// it ends the job: a report is never lost and never ignored.
#[derive(Clone, Debug, Default)]
pub struct Reports(Arc<Mutex<Vec<String>>>);

impl Reports {
    /// Adds a report.
    pub(super) fn add(&self, text: String) {
        crate::win::ffi::locked(&self.0).push(text);
    }

    fn all(&self) -> Vec<String> {
        crate::win::ffi::locked(&self.0).clone()
    }
}

/// A job object with a completion port.
#[derive(Debug)]
pub struct Job {
    handle: Handle,
    port: Handle,
    state: State,
    reports: Reports,
}

impl Job {
    /// Makes an unnamed job with the limits, reads the limits back from the platform and refuses a
    /// job whose limits are not the ones asked for.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the job, its limits or its port cannot be made, or an
    /// error when the limits read back differ from the limits set.
    pub fn new(limits: Limits) -> Result<Job> {
        // SAFETY: no attributes and no name: the job is unnamed and its handle is not inheritable.
        let raw = unsafe { CreateJobObjectW(null(), null()) };
        // text: job_new-1
        let handle = Handle::new(raw, "making the job")?;
        // SAFETY: a zeroed record is the documented starting point.
        let mut extended: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        extended.BasicLimitInformation.LimitFlags = LIMIT_FLAGS;
        extended.BasicLimitInformation.ActiveProcessLimit = limits.active_processes;
        extended.JobMemoryLimit = limits.memory_bytes;
        // SAFETY: the handle is open and the record is the size the class takes.
        let set = unsafe {
            SetInformationJobObject(
                handle.raw(),
                JobObjectExtendedLimitInformation,
                (&raw const extended).cast::<c_void>(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if set == 0 {
            // text: job_new-2
            return Err(last("setting the job's limits"));
        }
        // SAFETY: a completion port made with no file is the documented way to make a new one.
        let port_raw = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, null_mut(), 0, 1) };
        // text: job_new-3
        let port = Handle::new(port_raw, "making the job's completion port")?;
        let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: null_mut(),
            CompletionPort: port.raw(),
        };
        // SAFETY: the job and the port are open and the record is the size the class takes.
        let associated = unsafe {
            SetInformationJobObject(
                handle.raw(),
                JobObjectAssociateCompletionPortInformation,
                (&raw const association).cast::<c_void>(),
                size_of::<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>() as u32,
            )
        };
        if associated == 0 {
            // text: job_new-4
            return Err(last("attaching the completion port to the job"));
        }
        let job = Job {
            handle,
            port,
            state: State::Fresh,
            reports: Reports::default(),
        };
        let read = job.read_back()?;
        if read.flags != LIMIT_FLAGS
            || read.active_processes != limits.active_processes
            || read.memory_bytes != limits.memory_bytes
        {
            // text: job_new-5
            return Err(error(
                0,
                format!("the job's limits read back as {read:?}, not as set ({limits:?})"),
            ));
        }
        Ok(job)
    }

    /// Where the job's children report an end that was not proved.
    pub(super) fn reports(&self) -> Reports {
        self.reports.clone()
    }

    /// What the job's children and its own end reported as not shown to have ended. An owner that
    /// closes a job without ending it reads this before it treats the children as gone.
    #[must_use]
    pub fn unproved_reasons(&self) -> Vec<String> {
        self.reports.all()
    }

    /// The raw handle, still owned by the job.
    pub(super) fn raw(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.handle.raw()
    }

    /// Where the job is in its life.
    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    /// The limits the platform reports for the job.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the job cannot be queried.
    pub fn read_back(&self) -> Result<ReadBack> {
        // SAFETY: a zeroed record is what the platform fills in.
        let mut extended: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: the handle is open and the record is the size the class takes.
        let queried = unsafe {
            QueryInformationJobObject(
                self.handle.raw(),
                JobObjectExtendedLimitInformation,
                (&raw mut extended).cast::<c_void>(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                null_mut(),
            )
        };
        if queried == 0 {
            // text: job_read_back-1
            return Err(last("reading the job's limits"));
        }
        Ok(ReadBack {
            flags: extended.BasicLimitInformation.LimitFlags,
            active_processes: extended.BasicLimitInformation.ActiveProcessLimit,
            memory_bytes: extended.JobMemoryLimit,
        })
    }

    /// The job's own count of active processes.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the job cannot be queried. A caller that cannot tell must
    /// not take the count for zero.
    pub fn active_processes(&self) -> Result<u32> {
        // SAFETY: a zeroed record is what the platform fills in.
        let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: the handle is open and the record is the size the class takes.
        let queried = unsafe {
            QueryInformationJobObject(
                self.handle.raw(),
                JobObjectBasicAccountingInformation,
                (&raw mut accounting).cast::<c_void>(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                null_mut(),
            )
        };
        if queried == 0 {
            return Err(last("reading the job's active process count"));
        }
        Ok(accounting.ActiveProcesses)
    }

    /// The identifiers of the processes in the job now.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the job cannot be queried or holds more processes than
    /// its cap allows the list to name.
    pub fn process_ids(&self) -> Result<Vec<u32>> {
        const CAPACITY: usize = 256;
        // The record is two 32-bit counts, which fill one word, then an array of identifiers.
        let mut storage = vec![0_usize; 1 + CAPACITY];
        // SAFETY: the buffer is aligned for the record and large enough for `CAPACITY` entries.
        let queried = unsafe {
            QueryInformationJobObject(
                self.handle.raw(),
                JobObjectBasicProcessIdList,
                storage.as_mut_ptr().cast::<c_void>(),
                (storage.len() * size_of::<usize>()) as u32,
                null_mut(),
            )
        };
        if queried == 0 {
            return Err(last("listing the job's processes"));
        }
        // SAFETY: the buffer holds a record the platform filled in.
        let list = unsafe { &*storage.as_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() };
        let listed = list.NumberOfProcessIdsInList as usize;
        if listed < list.NumberOfAssignedProcesses as usize {
            return Err(error(
                0,
                "the job holds more processes than the list can name",
            ));
        }
        Ok(storage[1..1 + listed].iter().map(|id| *id as u32).collect())
    }

    /// A handle to the same job that may only query it, for the cases that show a launch whose job
    /// the platform will not take a process into.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the handles cannot be copied.
    #[cfg(feature = "testing")]
    pub fn query_only_copy(&self) -> Result<Job> {
        use windows_sys::Win32::Foundation::{DuplicateHandle, HANDLE};
        use windows_sys::Win32::System::SystemServices::JOB_OBJECT_QUERY;
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        let copy = |source: &Handle, access: u32| -> Result<Handle> {
            let mut target: HANDLE = null_mut();
            // SAFETY: both handles are open and the copy is owned by the value made below.
            let duplicated = unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    source.raw(),
                    GetCurrentProcess(),
                    &raw mut target,
                    access,
                    0,
                    0,
                )
            };
            if duplicated == 0 {
                return Err(last("copying a job handle"));
            }
            Handle::new(target, "the copy of the job handle")
        };
        Ok(Job {
            handle: copy(&self.handle, JOB_OBJECT_QUERY)?,
            port: copy(&self.port, 0x0010_0000)?,
            state: self.state,
            reports: self.reports.clone(),
        })
    }

    /// Whether a process is in this job.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the question cannot be asked.
    pub fn contains(&self, process: &Handle) -> Result<bool> {
        let mut inside = 0;
        // SAFETY: both handles are open.
        let asked = unsafe { IsProcessInJob(process.raw(), self.handle.raw(), &raw mut inside) };
        if asked == 0 {
            // text: job_contains-1
            return Err(last("asking whether a process is in the job"));
        }
        Ok(inside != 0)
    }

    /// Ends every process in the job and waits, up to the caller's absolute deadline, until each
    /// has gone. The deadline is not rebuilt from a duration after the call that ends the job, so
    /// that call's own time is part of the wait and not an addition to it.
    ///
    /// The completion port wakes the wait; the answer is the job's own active count and the
    /// retained process objects, read after each wake-up. A message that never comes changes
    /// nothing but how soon the next read happens.
    ///
    /// A job that is not seen empty at the bound is reported with the reason, beside what its
    /// children reported, and its end is not proved. A refused call to end the job does not by
    /// itself keep the end from being proved: the observation decides, and the refusal is in the
    /// report when the observation fails.
    pub fn end(&mut self, retained: &[&Child], deadline: Instant) -> Ended {
        self.state = State::Ended;
        // SAFETY: the handle is open.
        let terminated = unsafe { TerminateJobObject(self.handle.raw(), 1) } != 0;
        // text: job_end-1
        let terminate_error = (!terminated).then(|| last("ending the job"));
        // A process that is not seen to have ended is one that has not, or one whose wait failed: the
        // first failure of any turn of the loop is kept for the report, and a later turn that reads
        // the process does not drop it.
        let mut wait_failed = None;
        loop {
            let all_exited = retained.iter().all(|child| {
                // text: job_end-2
                match ffi::wait(
                    child.process.raw(),
                    0,
                    "waiting for a retained process to be seen ended",
                ) {
                    Ok(Waited::Signalled(_)) => true,
                    Ok(Waited::TimedOut) => false,
                    Err(failure) => {
                        wait_failed.get_or_insert(failure);
                        false
                    }
                }
            });
            let counted = self.active_processes();
            let (active_zero, count_read) = match &counted {
                Ok(count) => (*count == 0, true),
                Err(_) => (false, false),
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            if (all_exited && active_zero) || remaining.is_zero() {
                if !(all_exited && active_zero) {
                    let call = terminate_error.map_or_else(
                        || "the call to end the job succeeded".to_owned(),
                        |error| error.to_string(),
                    );
                    let count = match &counted {
                        Ok(count) => format!("{count}"),
                        Err(error) => format!("not read ({error})"),
                    };
                    let waited =
                        wait_failed.map_or_else(String::new, |failure| format!("; {failure}"));
                    self.reports.add(format!(
                        "the job was not seen empty within the bound (exited {all_exited}, \
                         active count {count}; {call}{waited})"
                    ));
                }
                return Ended {
                    all_exited,
                    active_zero,
                    count_read,
                };
            }
            self.wait_for_message(remaining.min(Duration::from_millis(100)));
        }
    }

    fn wait_for_message(&self, up_to: Duration) {
        let mut bytes = 0_u32;
        let mut key = 0_usize;
        let mut overlapped = null_mut();
        // SAFETY: the port is open and the out-parameters are this function's own.
        #[expect(
            clippy::disallowed_methods,
            reason = "its answer is only a wake-up: whether a message came or the time ran out, the next read of the job's count and of the retained processes decides"
        )]
        let _woken = unsafe {
            GetQueuedCompletionStatus(
                self.port.raw(),
                &raw mut bytes,
                &raw mut key,
                &raw mut overlapped,
                super::ffi::milliseconds(up_to, u32::MAX),
            )
        };
    }
}
