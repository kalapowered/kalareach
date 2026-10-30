//! The processes a session's worker recorded, read against the operating system.
//!
//! Each case writes a real journal file with a record of its own making, as a worker does, and the
//! processes the record names are real children this test started: what is checked is the
//! operating system's answer about each, and what the daemon makes of a record it cannot trust.
//! The live session, the shell and the console are the end-to-end suite's, in `network.rs`.

#![cfg(unix)]

use std::process::{Child, Command, Stdio};

use kr_controller::processes::session_processes;
use kr_ipc::testing::TempHost;
use kr_protocol::error::ErrorCode;
use kr_protocol::identity::{
    BootIdentity, BootIdentitySource, ProcessStartIdentity, ProcessStartSource,
};
use kr_protocol::ids::SessionId;
use kr_protocol::scalars::{Bytes, Uuid};
use kr_protocol::session_processes::{
    MAX_PROCESS_BOUNDARY_BYTES, MAX_PROCESS_CGROUP_BYTES, MAX_PROCESS_LIMIT_BYTES,
    MAX_PROCESS_LIMITS, MAX_PROCESS_NAME_BYTES, MAX_PROCESS_ROWS, ProcessBoot, ProcessListing,
    ProcessRole, ProcessStanding, SessionProcess, SessionProcessesResult,
};
use kr_worker::journal::Journal;
use kr_worker::ownership::OwnedRecord;

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([0x25; 16]))
}

/// A real process this test owns, and its identity as the kernel reads it.
fn child() -> (Child, ProcessStartIdentity) {
    let child = Command::new("/bin/sh")
        .args(["-c", "exec sleep 600"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("starts a child");
    let identity = kr_ipc::identity::process_start_identity(child.id()).expect("its identity");
    (child, identity)
}

fn end(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn record(
    boot: Option<BootIdentity>,
    processes: Vec<ProcessStartIdentity>,
    backends: Vec<ProcessStartIdentity>,
) -> OwnedRecord {
    OwnedRecord {
        boot,
        root: processes.first().cloned().expect("a root"),
        processes,
        cgroup: None,
        boundary: "the terminal's process group".to_owned(),
        limits: Vec::new(),
        backends,
    }
}

/// Writes `record` into the session's journal, replacing the one there, as the worker does.
fn write(host: &TempHost, record: &OwnedRecord) {
    let path = host.environment().journal_database(session());
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the journal directory");
    let mut journal = Journal::open(&path).expect("opens");
    journal
        .record_owned(session(), record)
        .expect("records what the session owned");
}

fn this_boot() -> BootIdentity {
    kr_ipc::identity::boot_identity().expect("this boot")
}

/// A boot of the same kind and length as this one with another value: an earlier boot.
fn an_earlier_boot() -> BootIdentity {
    let now = this_boot();
    let mut value = now.value.as_slice().to_vec();
    let last = value.last_mut().expect("a value");
    *last ^= 0xff;
    BootIdentity {
        source: now.source,
        value: Bytes::new(value),
    }
}

fn read(host: &TempHost) -> SessionProcessesResult {
    session_processes(&host.environment(), session()).expect("the record is read")
}

/// Every process the operating system was read about during `work`, on this thread.
#[cfg(target_os = "linux")]
fn processes_read(
    work: impl FnOnce() -> SessionProcessesResult,
) -> (SessionProcessesResult, usize) {
    let (view, read) = kr_ipc::identity::processes_read_during(work);
    (view, read.len())
}

/// KR-REQ-25.06: a record of this boot is listed row by row as the operating system reads each
/// process: the root first, then the servers, then the rest; a running row holds its parent as an
/// identity and the base name of its executable; a process that has ended since the record was
/// written reads as ended in that stale record; and a later record that omits it lists nothing of
/// it. The control is that this case reads processes, which the cases of the earlier and the
/// unknown boots do not.
#[test]
fn a_record_of_this_boot_is_listed_as_the_system_reads_each_process() {
    let host = TempHost::create();
    let (root, root_identity) = child();
    let (server, server_identity) = child();
    let (below, below_identity) = child();
    write(
        &host,
        &record(
            Some(this_boot()),
            vec![
                root_identity.clone(),
                below_identity.clone(),
                server_identity.clone(),
            ],
            vec![server_identity.clone()],
        ),
    );

    #[cfg(target_os = "linux")]
    let (view, probes) = processes_read(|| read(&host));
    #[cfg(not(target_os = "linux"))]
    let view = read(&host);
    #[cfg(target_os = "linux")]
    assert!(probes > 0, "the control: this case asks the system");
    assert_eq!(view.session_id, session());
    assert_eq!(view.listing, ProcessListing::Recorded);
    assert_eq!(view.boot, ProcessBoot::Same);
    let rows: Vec<_> = view
        .processes
        .iter()
        .map(|row| (row.role, row.process.clone(), row.state))
        .collect();
    assert_eq!(
        rows,
        vec![
            (
                ProcessRole::Root,
                root_identity.clone(),
                ProcessStanding::Running
            ),
            (
                ProcessRole::Backend,
                server_identity.clone(),
                ProcessStanding::Running
            ),
            (
                ProcessRole::Descendant,
                below_identity.clone(),
                ProcessStanding::Running
            ),
        ]
    );
    let this_process =
        kr_ipc::identity::process_start_identity(std::process::id()).expect("this process");
    for row in &view.processes {
        assert_eq!(
            row.parent.0.as_ref(),
            Some(&this_process),
            "a child of this test, as an identity: {row:?}"
        );
        assert!(
            row.name
                .0
                .as_deref()
                .is_some_and(|name| !name.is_empty() && !name.contains('/')),
            "the base name of the executable: {row:?}"
        );
    }
    assert_eq!(view.omitted.get(), 0);

    // The process below ends. The record is as the worker last wrote it, so the row stays and
    // reads as ended, with nothing of a process that is gone.
    end(below);
    let stale = read(&host);
    let below_row = stale
        .processes
        .iter()
        .find(|row| row.process == below_identity)
        .expect("the stale record still lists it");
    assert_eq!(below_row.state, ProcessStanding::Ended);
    assert!(below_row.parent.0.is_none() && below_row.name.0.is_none());
    assert_eq!(
        stale
            .processes
            .iter()
            .filter(|row| row.state == ProcessStanding::Running)
            .count(),
        2
    );

    // The worker's next write omits it, and the view lists what the record lists.
    write(
        &host,
        &record(
            Some(this_boot()),
            vec![root_identity.clone(), server_identity.clone()],
            vec![server_identity.clone()],
        ),
    );
    assert_eq!(read(&host).processes.len(), 2);
    end(root);
    end(server);
}

/// KR-REQ-25.06: a record of an earlier boot lists every process as ended without asking the
/// system about any, and a record that names no boot or one that cannot be compared lists every
/// process as unknown, asking about none: start values mean nothing in another boot, and a process
/// that is running now is not shown as ended because its record cannot be tied to this boot. The
/// processes are real and running, so a probe would show as a running row.
#[test]
fn a_record_that_cannot_be_tied_to_this_boot_asks_about_no_process() {
    let incomparable = BootIdentity {
        source: BootIdentitySource::BootTime,
        value: Bytes::new(vec![1, 2, 3]),
    };
    let incomparable = if this_boot().source == BootIdentitySource::BootTime {
        BootIdentity {
            source: BootIdentitySource::LinuxBootId,
            ..incomparable
        }
    } else {
        incomparable
    };
    for (boot, expected, standing) in [
        (
            Some(an_earlier_boot()),
            ProcessBoot::Earlier,
            ProcessStanding::Ended,
        ),
        (None, ProcessBoot::Unrecorded, ProcessStanding::Unknown),
        (
            Some(incomparable),
            ProcessBoot::Incomparable,
            ProcessStanding::Unknown,
        ),
    ] {
        let host = TempHost::create();
        let (first, first_identity) = child();
        let (second, second_identity) = child();
        write(
            &host,
            &record(boot, vec![first_identity, second_identity], Vec::new()),
        );
        #[cfg(target_os = "linux")]
        let (view, probes) = processes_read(|| read(&host));
        #[cfg(not(target_os = "linux"))]
        let view = read(&host);
        #[cfg(target_os = "linux")]
        assert_eq!(probes, 0, "{expected:?}: no process was asked about");
        assert_eq!(view.boot, expected);
        assert_eq!(view.processes.len(), 2);
        for row in &view.processes {
            assert_eq!(row.state, standing, "{expected:?}: {row:?}");
            assert!(row.parent.0.is_none() && row.name.0.is_none(), "{row:?}");
        }
        end(first);
        end(second);
    }
}

/// KR-REQ-25.06: a journal that is not there is a refusal to try again, a file that is not a
/// journal is a refusal to read it, and a journal that holds no record lists nothing and says so;
/// none of them is a successful empty list for a worker that had processes.
#[test]
fn a_journal_that_cannot_be_read_is_a_refusal_and_one_with_no_record_says_so() {
    let host = TempHost::create();
    let missing = session_processes(&host.environment(), session()).expect_err("no journal");
    assert_eq!(missing.code(), ErrorCode::ResourceUnavailable, "{missing}");

    let path = host.environment().journal_database(session());
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the directory");
    std::fs::write(&path, b"this is not a database, and never was one").expect("a file");
    let unreadable = session_processes(&host.environment(), session()).expect_err("not a journal");
    assert_eq!(
        unreadable.code(),
        ErrorCode::StorageUnavailable,
        "{unreadable}"
    );

    let empty = TempHost::create();
    let path = empty.environment().journal_database(session());
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the directory");
    drop(Journal::open(&path).expect("opens"));
    let view = read(&empty);
    assert!(view.processes.is_empty());
    assert!(
        view.limits
            .iter()
            .any(|limit| limit.contains("recorded no processes")),
        "{view:?}"
    );
}

/// KR-REQ-25.06: the answer is bounded however much the record holds, and the largest answer fits
/// a control frame with room for its envelope. A record of more processes than the view lists is
/// cut with the rest counted, and the text the record carries is cut on a character boundary.
#[test]
fn the_answer_is_bounded_and_the_largest_fits_a_frame() {
    let host = TempHost::create();
    let mut processes: Vec<_> = (0..u64::try_from(MAX_PROCESS_ROWS).expect("a count") + 50)
        .map(|n| ProcessStartIdentity::new(4_000_000 + n, ProcessStartSource::LinuxProcStat, n))
        .collect();
    processes.sort_by_key(|process| process.start_value.get());
    let mut big = record(Some(this_boot()), processes, Vec::new());
    // Three-byte characters, so that a cut at a byte count lands inside one: none of these limits is
    // a multiple of three.
    big.boundary = "€".repeat(MAX_PROCESS_BOUNDARY_BYTES);
    big.cgroup = Some("€".repeat(MAX_PROCESS_CGROUP_BYTES));
    big.limits = (0..MAX_PROCESS_LIMITS + 5)
        .map(|_| "€".repeat(MAX_PROCESS_LIMIT_BYTES))
        .collect();
    write(&host, &big);
    let view = read(&host);
    assert_eq!(view.processes.len(), MAX_PROCESS_ROWS);
    assert_eq!(view.omitted.get(), 50);
    assert!(view.boundary.len() <= MAX_PROCESS_BOUNDARY_BYTES);
    assert_eq!(
        view.boundary.len() % 3,
        0,
        "the cut is on a character boundary, not inside a character"
    );
    assert!(view.cgroup.0.as_ref().expect("a group").len() <= MAX_PROCESS_CGROUP_BYTES);
    assert!(
        view.limits
            .iter()
            .all(|limit| limit.len() <= MAX_PROCESS_LIMIT_BYTES)
    );
    assert!(
        view.limits
            .last()
            .is_some_and(|limit| limit.contains("5 more")),
        "the limits that were cut are counted: {:?}",
        view.limits.last()
    );

    // The largest answer there can be: every row running, with a parent and the longest name.
    let identity = |n: u64| {
        ProcessStartIdentity::new(
            u64::MAX - n,
            ProcessStartSource::WindowsProcessStartSeconds,
            u64::MAX - n,
        )
    };
    let largest = SessionProcessesResult {
        processes: (0..MAX_PROCESS_ROWS as u64)
            .map(|n| SessionProcess {
                process: identity(n),
                role: ProcessRole::Descendant,
                state: ProcessStanding::Running,
                parent: kr_protocol::scalars::Nullable::some(identity(n + 1)),
                name: kr_protocol::scalars::Nullable::some("a".repeat(MAX_PROCESS_NAME_BYTES)),
            })
            .collect(),
        ..view
    };
    let encoded = kr_cbor::to_canonical_vec(&largest).expect("encodes");
    assert!(
        encoded.len() + 4096 <= kr_protocol::limits::MAX_CONTROL_FRAME_LEN,
        "{} bytes leave room for the envelope",
        encoded.len()
    );
}

/// KR-REQ-25.06: a record that does not decode, and a journal of another schema version, are
/// refusals with their cause, and never a successful empty list for a worker that had processes.
#[test]
fn a_record_that_does_not_decode_and_a_journal_of_another_schema_are_refusals() {
    fn change(host: &TempHost, statement: &str, parameters: &[&dyn rusqlite::ToSql]) {
        let path = host.environment().journal_database(session());
        let connection = rusqlite::Connection::open(path).expect("opens the journal's file");
        connection
            .execute(statement, parameters)
            .expect("the journal is changed");
    }

    let host = TempHost::create();
    let (root, identity) = child();
    write(
        &host,
        &record(Some(this_boot()), vec![identity], Vec::new()),
    );
    read(&host);
    change(&host, "UPDATE owned_processes SET record = x'ff'", &[]);
    let undecodable = session_processes(&host.environment(), session()).expect_err("no record");
    assert_eq!(
        undecodable.code(),
        ErrorCode::StorageUnavailable,
        "{undecodable}"
    );

    change(
        &host,
        "UPDATE schema_version SET version = version + 1000",
        &[],
    );
    let other_schema = session_processes(&host.environment(), session()).expect_err("no read");
    assert_eq!(
        other_schema.code(),
        ErrorCode::StorageUnavailable,
        "{other_schema}"
    );
    end(root);
}
