//! The job a command the server starts runs in, on Windows.
//!
//! On Unix the server's command leads a process group of its own, and ending the group ends what
//! the command started. A Windows process has no such group, so the pinned release's server puts
//! each command it starts in a job object of its own and ends the job. The job has the limits the
//! release gives it: it ends its processes when its last handle closes, and a process in it may
//! start one that leaves it (`CREATE_BREAKAWAY_FROM_JOB`), where every job above it allows that.
//!
//! The command is created suspended and joins its job before it runs, so nothing it starts is
//! outside the job. Where the job cannot be made, or the command cannot join it (a job that holds
//! the server and does not let a nested job be made, on a system that does not nest jobs), the
//! command runs outside a job of its own, as it does in the pinned release, and only the command
//! itself is ended.

#![expect(
    unsafe_code,
    reason = "creating a job object, moving a process into it and resuming it have no safe form"
)]

use std::io;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle, RawHandle};

use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};

/// The flag that makes a process start suspended: it does not run until it is resumed.
pub const CREATE_SUSPENDED: u32 = windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

/// The exit code the processes of an ended job have.
const ENDED: u32 = 1;

#[link(name = "ntdll")]
unsafe extern "system" {
    /// Resumes every thread of a process that was created suspended.
    fn NtResumeProcess(process: HANDLE) -> NTSTATUS;
}

/// A job object. Its last handle closing ends every process in it.
#[derive(Debug)]
pub struct Job(OwnedHandle);

impl Job {
    /// Makes a job that ends its processes when it is closed and lets a process in it start one
    /// outside it.
    ///
    /// # Errors
    ///
    /// Returns the system's failure.
    pub fn create() -> io::Result<Self> {
        // SAFETY: no security attributes and no name are given, so the call reads nothing of ours.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the call returned a handle that nothing else owns.
        let job = Self(unsafe { OwnedHandle::from_raw_handle(handle) });
        // SAFETY: the structure is integers and pointers throughout, and all zeroes is the state
        // that means "no limit set", which is what every field but the flags should be.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK;
        // SAFETY: the handle is this job's own and open for the call; the structure is a local and
        // its declared size is its own.
        let set = unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .unwrap_or(0),
            )
        };
        if set == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    fn raw(&self) -> HANDLE {
        self.0.as_raw_handle()
    }

    /// Moves a process into the job.
    ///
    /// # Errors
    ///
    /// Returns the system's failure: a process that is already in a job that does not nest one
    /// cannot move.
    pub fn assign(&self, process: RawHandle) -> io::Result<()> {
        // SAFETY: both handles are open for the call.
        if unsafe { AssignProcessToJobObject(self.raw(), process) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Ends every process in the job.
    pub fn terminate(&self) {
        // SAFETY: the handle is this job's own and open for the call.
        let _ = unsafe { TerminateJobObject(self.raw(), ENDED) };
    }
}

/// Lets a process that was created suspended run.
///
/// # Errors
///
/// Returns the system's status where it is not a success.
pub fn resume(process: RawHandle) -> io::Result<()> {
    // SAFETY: the handle is open for the call.
    let status = unsafe { NtResumeProcess(process) };
    if status < 0 {
        return Err(io::Error::other(format!(
            "the process could not be resumed: status {status:#x}"
        )));
    }
    Ok(())
}
