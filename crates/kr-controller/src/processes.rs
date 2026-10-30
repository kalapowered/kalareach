//! The processes a session's worker had recorded, each read against the operating system, for
//! `session.processes`.
//!
//! A worker keeps a record of the processes it owns in its journal. This daemon reads that record
//! and asks the operating system, through `kr-ipc`'s process interfaces, what each recorded process
//! is now. Nothing here runs a tool or reads terminal text.
//!
//! The record is read while the worker runs, which is an exception to this daemon's rule that it
//! does not read another process's journal behind its back. It is safe here because the open is
//! read-only on a database in write-ahead mode, the record is one row the worker replaces whole,
//! and the read migrates nothing and takes no lock the worker waits on for more than a moment.
//! The archive's `bring_forward` is not called, and a journal at another schema version is refused
//! rather than brought forward.
//!
//! What the answer says it is: what the worker had recorded at its last write, each identity
//! checked at the moment of the call. See [`kr_protocol::session_processes`] for what it cannot
//! know.

use kr_ipc::identity::{ProcessReading, boot_identity, read_process};
use kr_protocol::error::ErrorCode;
use kr_protocol::identity::{BootIdentity, ProcessStartIdentity};
use kr_protocol::ids::SessionId;
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::session_processes::{
    MAX_PROCESS_BOUNDARY_BYTES, MAX_PROCESS_CGROUP_BYTES, MAX_PROCESS_LIMIT_BYTES,
    MAX_PROCESS_LIMITS, MAX_PROCESS_ROWS, ProcessBoot, ProcessListing, ProcessRole,
    ProcessStanding, SessionProcess, SessionProcessesResult,
};
use kr_worker::journal::Journal;
use kr_worker::ownership::OwnedRecord;

use crate::error::{ControllerError, Result};

/// What the platform gives, said once in the answer's limits.
#[cfg(windows)]
const PLATFORM_LIMIT: Option<&str> = Some(
    "this host reads the state of a recorded process on this platform and neither its parent nor its executable",
);
#[cfg(not(windows))]
const PLATFORM_LIMIT: Option<&str> = None;

/// Reads the processes `session_id`'s worker recorded and checks each against the operating
/// system.
///
/// This blocks: it opens a journal and asks the kernel about each row, so a caller on an
/// asynchronous runtime runs it on a blocking thread.
///
/// # Errors
///
/// Returns `RESOURCE_UNAVAILABLE` when the worker's journal is not there, and
/// `STORAGE_UNAVAILABLE` when it cannot be read (another schema version, not a database, a record
/// that does not decode).
pub fn session_processes(
    paths: &kr_ipc::paths::EnvironmentPaths,
    session_id: SessionId,
) -> Result<SessionProcessesResult> {
    let path = paths.journal_database(session_id);
    let storage = |detail: String| ControllerError::Storage {
        operation: "read a worker's record of its processes",
        detail,
    };
    // A path that cannot be examined is not a path that is not there: only absence is a refusal to
    // try again.
    if !path
        .try_exists()
        .map_err(|error| storage(error.to_string()))?
    {
        return Err(ControllerError::Refused {
            code: ErrorCode::ResourceUnavailable,
            detail: format!(
                "session {session_id} has no journal this daemon can read yet, so no record of \
                 its processes was read: it is not yet created, or its worker could not open \
                 its journal"
            ),
        });
    }
    let record = {
        let journal = Journal::open_read_only(&path).map_err(|error| storage(error.to_string()))?;
        journal
            .read_owned(session_id)
            .map_err(|error| storage(error.to_string()))?
    };
    Ok(view(session_id, record, boot_identity().ok().as_ref()))
}

/// The answer for a record, its boot compared with `now`, each row read from the system.
fn view(
    session_id: SessionId,
    record: Option<OwnedRecord>,
    now: Option<&BootIdentity>,
) -> SessionProcessesResult {
    let mut limits: Vec<String> = PLATFORM_LIMIT.map(str::to_owned).into_iter().collect();
    let Some(record) = record else {
        limits.push("the worker recorded no processes of its session".to_owned());
        return SessionProcessesResult {
            session_id,
            listing: ProcessListing::Recorded,
            boot: ProcessBoot::Unrecorded,
            boundary: String::new(),
            limits,
            cgroup: Nullable::null(),
            processes: Vec::new(),
            omitted: U64::new(0),
        };
    };
    let boot = match (&record.boot, now) {
        (Some(recorded), Some(now)) if recorded == now => ProcessBoot::Same,
        (Some(recorded), Some(now)) if crate::archive::is_an_earlier_boot(recorded, now) => {
            ProcessBoot::Earlier
        }
        (None, _) => ProcessBoot::Unrecorded,
        _ => ProcessBoot::Incomparable,
    };
    match boot {
        ProcessBoot::Same => {}
        ProcessBoot::Earlier => limits.push(
            "the record is from an earlier boot, in which no recorded process can still run"
                .to_owned(),
        ),
        ProcessBoot::Unrecorded => limits.push(
            "the record names no boot, so its start values cannot be tied to this one and no \
             process was asked about"
                .to_owned(),
        ),
        ProcessBoot::Incomparable => limits.push(
            "the record's boot and this boot cannot be compared, so no process was asked about"
                .to_owned(),
        ),
    }
    let kept = record.limits.len().min(MAX_PROCESS_LIMITS);
    limits.extend(
        record.limits[..kept]
            .iter()
            .map(|limit| cut(limit, MAX_PROCESS_LIMIT_BYTES)),
    );
    if record.limits.len() > kept {
        limits.push(format!(
            "{} more of the worker's limits are not listed",
            record.limits.len() - kept
        ));
    }

    let mut rows = rows_of(&record);
    let omitted = rows.len().saturating_sub(MAX_PROCESS_ROWS);
    rows.truncate(MAX_PROCESS_ROWS);
    let processes = rows
        .into_iter()
        .map(|(role, process)| {
            let (state, parent, name) = match boot {
                ProcessBoot::Earlier => (ProcessStanding::Ended, None, None),
                ProcessBoot::Unrecorded | ProcessBoot::Incomparable => {
                    (ProcessStanding::Unknown, None, None)
                }
                ProcessBoot::Same => match read_process(&process) {
                    ProcessReading::Running(facts) => {
                        (ProcessStanding::Running, facts.parent, facts.name)
                    }
                    ProcessReading::Ended => (ProcessStanding::Ended, None, None),
                    ProcessReading::Unknown { .. } => (ProcessStanding::Unknown, None, None),
                },
            };
            SessionProcess {
                process,
                role,
                state,
                parent: Nullable(parent),
                name: Nullable(name),
            }
        })
        .collect();
    SessionProcessesResult {
        session_id,
        listing: ProcessListing::Recorded,
        boot,
        boundary: cut(&record.boundary, MAX_PROCESS_BOUNDARY_BYTES),
        limits,
        cgroup: Nullable(
            record
                .cgroup
                .map(|cgroup| cut(&cgroup, MAX_PROCESS_CGROUP_BYTES)),
        ),
        processes,
        omitted: U64::new(omitted as u64),
    }
}

/// The record's processes with their roles: the root, then the servers, then the rest by start.
fn rows_of(record: &OwnedRecord) -> Vec<(ProcessRole, ProcessStartIdentity)> {
    let mut rows = vec![(ProcessRole::Root, record.root.clone())];
    for backend in &record.backends {
        if *backend != record.root {
            rows.push((ProcessRole::Backend, backend.clone()));
        }
    }
    let mut rest: Vec<&ProcessStartIdentity> = record
        .processes
        .iter()
        .filter(|process| **process != record.root && !record.backends.contains(process))
        .collect();
    rest.sort_by_key(|process| (process.start_value.get(), process.pid.get()));
    rest.dedup();
    rows.extend(
        rest.into_iter()
            .map(|process| (ProcessRole::Descendant, process.clone())),
    );
    rows
}

/// `text` cut at `max` bytes on a character boundary.
fn cut(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}
