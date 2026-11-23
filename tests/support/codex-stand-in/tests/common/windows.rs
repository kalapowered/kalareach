//! What the cases need of Windows processes: a command's processes in place of a process group,
//! and a job that holds a server from outside, as the broker's job holds the one it starts.

#![expect(
    unsafe_code,
    reason = "listing the system's processes, making a job and moving a process into it have no safe form"
)]

use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, NTSTATUS};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

#[link(name = "ntdll")]
unsafe extern "system" {
    /// Resumes every thread of a process that was created suspended.
    fn NtResumeProcess(process: HANDLE) -> NTSTATUS;
}

/// The system's processes, each with the process that started it.
fn processes() -> Vec<(u32, u32)> {
    // SAFETY: the call reads no memory of ours.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Vec::new();
    }
    // SAFETY: the snapshot is a handle that nothing else owns.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
    // SAFETY: all zeroes is a valid state of the structure, whose size is then told as the call
    // requires.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = u32::try_from(std::mem::size_of::<PROCESSENTRY32W>()).unwrap_or(0);
    let mut found = Vec::new();
    // SAFETY: the snapshot is open for the calls and the entry is a local of the size told.
    let mut more = unsafe { Process32FirstW(snapshot.as_raw_handle(), &raw mut entry) } != 0;
    while more {
        found.push((entry.th32ProcessID, entry.th32ParentProcessID));
        // SAFETY: as above.
        more = unsafe { Process32NextW(snapshot.as_raw_handle(), &raw mut entry) } != 0;
    }
    found
}

/// A process and every process below it, as the system lists them now: the processes a command
/// started that are still running.
pub fn tree(root: u32) -> Vec<u32> {
    let all = processes();
    let mut members = Vec::new();
    if all.iter().any(|(process, _)| *process == root) {
        members.push(root);
    }
    let mut at = 0;
    while at < members.len() {
        let parent = members[at];
        for (process, started_by) in &all {
            if *started_by == parent && *process != parent && !members.contains(process) {
                members.push(*process);
            }
        }
        at += 1;
    }
    members
}

/// Whether the system lists a process under this number.
pub fn running(process: u32) -> bool {
    processes().iter().any(|(listed, _)| *listed == process)
}

/// Ends the processes of the command a test names, and what they started, when the test stops
/// before the server has ended them.
pub struct EndsGroup(pub Option<String>);

impl Drop for EndsGroup {
    fn drop(&mut self) {
        if let Some(process) = self.0.take() {
            let _ = std::process::Command::new("taskkill")
                .args(["/T", "/F", "/PID", &process])
                .output();
        }
    }
}

/// A job, made outside the stand-in, that holds a server as the broker's job holds the server it
/// starts: it ends what it holds when it closes, and lets nothing in it break away.
pub struct OuterJob(OwnedHandle);

/// Starts `command` suspended, moves it into a new job, and lets it run.
///
/// # Errors
///
/// Returns the system's failure.
pub fn start_in_a_job(
    command: &mut tokio::process::Command,
) -> std::io::Result<(tokio::process::Child, OuterJob)> {
    // SAFETY: no security attributes and no name are given, so the call reads nothing of ours.
    let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the call returned a handle that nothing else owns.
    let job = OuterJob(unsafe { OwnedHandle::from_raw_handle(handle) });
    // SAFETY: all zeroes is "no limit set", which every field but the flags should be.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: the handle is open for the call and the structure is a local of the size told.
    let set = unsafe {
        SetInformationJobObject(
            job.0.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            std::ptr::from_ref(&limits).cast(),
            u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap_or(0),
        )
    };
    if set == 0 {
        return Err(std::io::Error::last_os_error());
    }
    command.creation_flags(CREATE_SUSPENDED);
    let mut child = command.spawn()?;
    let process = child
        .raw_handle()
        .ok_or_else(|| std::io::Error::other("the child has no handle"))?;
    // SAFETY: both handles are open for the call.
    if unsafe { AssignProcessToJobObject(job.0.as_raw_handle(), process) } == 0 {
        let error = std::io::Error::last_os_error();
        let _ = child.start_kill();
        return Err(error);
    }
    // SAFETY: the handle is open for the call.
    let status = unsafe { NtResumeProcess(process) };
    if status < 0 {
        let _ = child.start_kill();
        return Err(std::io::Error::other(format!(
            "the child could not be resumed: status {status:#x}"
        )));
    }
    Ok((child, job))
}

impl OuterJob {
    /// Whether the process under this number is in the job, as one that a job inside it holds is.
    ///
    /// # Errors
    ///
    /// Returns the system's failure, among them that the process has ended.
    pub fn holds(&self, process: u32) -> std::io::Result<bool> {
        // SAFETY: the call reads no memory of ours.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the call returned a handle that nothing else owns.
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        let mut inside = 0_i32;
        // SAFETY: both handles are open for the call and the answer is a local.
        if unsafe {
            IsProcessInJob(
                handle.as_raw_handle(),
                self.0.as_raw_handle(),
                &raw mut inside,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(inside != 0)
    }
}
