//! The detector scan of an invocation's end: every process on the machine, looked at once.
//!
//! The scan lists every process (creation times come with the list, no open is needed for them) and
//! opens each by a limited query. It **reports** a process that carries the invocation's group and
//! is outside the job, which is a containment failure, and every process that appeared after the
//! invocation began and refuses the limited query.
//!
//! **It proves no absence.** A process can remove the service from its own descriptor (it owns it),
//! and the service holds no debug privilege and gets none. What the scan says is this: a group member
//! found outside the job proves a containment failure; an inaccessible or unclassifiable process
//! gives no absence proof; no report means only that the scan found no inspectable matching process.
//! What proves the end is the logon session (`session`).

#![allow(unsafe_code)]

use std::ptr::null_mut;

use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
use windows_sys::Win32::Foundation::{FILETIME, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY, TokenGroups,
};
use windows_sys::Win32::System::JobObjects::IsProcessInJob;
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::ffi::{Handle, Result, Sid, error, last};
use super::job::Job;

/// The information class that lists every process.
const SYSTEM_PROCESS_INFORMATION: i32 = 5;
/// `STATUS_INFO_LENGTH_MISMATCH`: the buffer was too small.
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
/// The offsets, in a list entry, of the fields the scan reads. The list is read as bytes: the entry
/// is the platform's `SYSTEM_PROCESS_INFORMATION` on a 64-bit system.
const NEXT_ENTRY: usize = 0;
const CREATE_TIME: usize = 32;
const PROCESS_ID: usize = 80;
const ENTRY_MIN: usize = 96;
const _: () = assert!(
    size_of::<usize>() == 8,
    "the list's layout is the 64-bit one"
);

/// What the scan needs to know of the invocation.
pub struct Facts<'a> {
    /// The invocation's group: a process whose token carries it belongs to the invocation.
    pub group: &'a Sid,
    /// The invocation's job, or none for a recovery, whose job closed with the broker that made
    /// it: a process that carries the group is then outside it.
    pub job: Option<&'a Job>,
    /// The platform's time, as a 64-bit count, at which the invocation began: a process created
    /// before it cannot be one of the invocation's.
    pub since: u64,
}

/// What the scan found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// How many processes the list held.
    pub listed: usize,
    /// How many of them the scan could look at.
    pub inspected: usize,
    /// How many processes older than the invocation could not be looked at or classified. They
    /// cannot be the invocation's, so they are no report.
    pub older_unlooked: usize,
    /// A containment failure for each process that carries the group outside the job, and a line
    /// for each process that appeared after the invocation began and refused the limited query. An
    /// empty list proves no absence.
    pub reports: Vec<String>,
}

struct Entry {
    pid: u32,
    created: u64,
}

fn list() -> Result<Vec<Entry>> {
    let mut buffer = vec![0_u64; 1 << 16];
    loop {
        let mut needed = 0_u32;
        // SAFETY: the buffer is the length given, aligned for the record.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_PROCESS_INFORMATION,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * 8) as u32,
                &raw mut needed,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH {
            let more = (needed as usize / 8 + 4096).max(buffer.len() * 2);
            buffer.resize(more, 0);
            continue;
        }
        if status != 0 {
            // text: scan_list-1
            return Err(error(status as u32, "listing the processes of the machine"));
        }
        break;
    }
    // SAFETY: the buffer holds `len * 8` initialised bytes.
    let bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), buffer.len() * 8) };
    let mut found = Vec::new();
    let mut at = 0_usize;
    loop {
        if at + ENTRY_MIN > bytes.len() {
            break;
        }
        let word = |offset: usize| -> u64 {
            let mut eight = [0_u8; 8];
            eight.copy_from_slice(&bytes[at + offset..at + offset + 8]);
            u64::from_le_bytes(eight)
        };
        let next = u32::from_le_bytes([
            bytes[at + NEXT_ENTRY],
            bytes[at + NEXT_ENTRY + 1],
            bytes[at + NEXT_ENTRY + 2],
            bytes[at + NEXT_ENTRY + 3],
        ]) as usize;
        found.push(Entry {
            pid: word(PROCESS_ID) as u32,
            created: word(CREATE_TIME),
        });
        if next == 0 {
            break;
        }
        at += next;
    }
    Ok(found)
}

fn created_of(process: &Handle) -> Result<u64> {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: the process is open for a limited query and the out-parameters are local.
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
        // text: scan_created_of-1
        return Err(last("reading a process's creation time"));
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

/// Whether the process's token carries the group.
fn carries(process: &Handle, group: &Sid) -> Result<bool> {
    let mut token: HANDLE = null_mut();
    // SAFETY: the process is open for a limited query; the token is owned below.
    if unsafe { OpenProcessToken(process.raw(), TOKEN_QUERY, &raw mut token) } == 0 {
        // text: scan_carries-1
        return Err(last("opening a process's token"));
    }
    // text: scan_carries-2
    let token = Handle::new(token, "opening a process's token")?;
    let mut needed = 0_u32;
    // SAFETY: the first call only asks for the size.
    unsafe {
        GetTokenInformation(token.raw(), TokenGroups, null_mut(), 0, &raw mut needed);
    }
    let mut buffer = vec![0_u64; (needed as usize).div_ceil(8).max(1)];
    // SAFETY: the buffer is the size the first call asked for and is aligned.
    if unsafe {
        GetTokenInformation(
            token.raw(),
            TokenGroups,
            buffer.as_mut_ptr().cast(),
            needed,
            &raw mut needed,
        )
    } == 0
    {
        // text: scan_carries-3
        return Err(last("reading a process's groups"));
    }
    // SAFETY: the call filled the buffer with a TOKEN_GROUPS record and its entries.
    let groups = unsafe { &*buffer.as_ptr().cast::<TOKEN_GROUPS>() };
    // SAFETY: the record holds `GroupCount` entries from its first.
    let entries: &[SID_AND_ATTRIBUTES] =
        unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) };
    // SAFETY: each entry's identifier points into the buffer, valid until it is dropped.
    Ok(entries
        .iter()
        .any(|entry| unsafe { Sid::from_ptr(entry.Sid) } == *group))
}

fn look(pid: u32) -> Result<Handle> {
    // SAFETY: opens a process by number for a limited query; the result is checked.
    let opened = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    // text: scan_look-1
    Handle::new(opened, "looking at a process")
}

/// Whether the process that a journal names, by number and creation time, is alive.
///
/// # Errors
///
/// Returns the platform's error when the process exists and cannot be looked at, or its creation
/// time cannot be read: the answer is then not known.
pub fn is_alive(pid: u32, created: u64) -> Result<bool> {
    /// The error that says no process has this number.
    const ERROR_INVALID_PARAMETER: u32 = 87;
    match look(pid) {
        Ok(process) => Ok(created_of(&process)? == created),
        Err(failure) if failure.code == ERROR_INVALID_PARAMETER => Ok(false),
        Err(failure) => Err(failure),
    }
}

/// Looks at every process of the machine and reports what it is told to report.
///
/// # Errors
///
/// Returns the platform's error when the list of processes cannot be read. A process that cannot be
/// looked at is not an error of the scan: it is a line of the report where it appeared after the
/// invocation began.
pub fn scan(facts: &Facts<'_>) -> Result<Report> {
    let mut report = Report::default();
    for entry in list()? {
        report.listed += 1;
        if entry.pid == 0 || entry.pid == 4 {
            continue;
        }
        let newer = entry.created >= facts.since;
        let process = match look(entry.pid) {
            Ok(process) => process,
            Err(failure) => {
                if newer {
                    report.reports.push(format!(
                        "process {} (created {}) appeared after the invocation began and cannot be looked at ({failure})",
                        entry.pid, entry.created
                    ));
                } else {
                    report.older_unlooked += 1;
                }
                continue;
            }
        };
        // A number that now names another process than the list's has nothing to say of this one.
        match created_of(&process) {
            Ok(created) if created == entry.created => {}
            Ok(_) => continue,
            Err(failure) => {
                if newer {
                    report.reports.push(format!(
                        "process {} (created {}) appeared after the invocation began and its creation time cannot be read ({failure})",
                        entry.pid, entry.created
                    ));
                } else {
                    report.older_unlooked += 1;
                }
                continue;
            }
        }
        report.inspected += 1;
        if let Some(job) = facts.job {
            let mut inside = 0;
            // SAFETY: the process is open and the job is open for the length of the call.
            let asked = unsafe { IsProcessInJob(process.raw(), job.raw(), &raw mut inside) };
            if asked == 0 || inside != 0 {
                continue;
            }
        }
        match carries(&process, facts.group) {
            Ok(true) => report.reports.push(format!(
                "process {} (created {}) carries the invocation's group and is outside its job",
                entry.pid, entry.created
            )),
            Ok(false) => {}
            Err(failure) if newer => report.reports.push(format!(
                "process {} (created {}) appeared after the invocation began and its token cannot be read ({failure})",
                entry.pid, entry.created
            )),
            Err(failure) => {
                report.older_unlooked += 1;
                drop(failure);
            }
        }
    }
    Ok(report)
}
