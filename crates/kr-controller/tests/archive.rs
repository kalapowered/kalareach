//! Section 24's archive service: closed and crashed sessions served with no worker.
//!
//! Everything here runs against real stores on the internal disk. What a session leaves behind is
//! a journal and a spool directory, and the archive reads those; nothing here starts a worker,
//! because the contract under test is that nothing can.

use kr_controller::archive::{ArchiveService, Incompleteness};
use kr_ipc::testing::TempHost;
use kr_protocol::ids::SessionEpoch;
use kr_protocol::ids::{ActorId, SessionId};
use kr_protocol::recovery::HistoryGapCause;
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_protocol::session::{
    ClosureReason, ClosureRecord, DisplayNumber, Durability, OwnershipCoverage, SurvivingResource,
    TerminatedProcess,
};
use kr_worker::journal::{Journal, Submission};

fn session() -> SessionId {
    SessionId::new(kr_ipc::new_uuid())
}

fn closure(session_id: SessionId, reason: ClosureReason) -> ClosureRecord {
    ClosureRecord {
        session_id,
        session_epoch: SessionEpoch::V1,
        reason,
        root_exit_code: Nullable::null(),
        root_signal: Nullable::null(),
        terminated: Vec::new(),
        surviving: Vec::new(),
        ownership_coverage: OwnershipCoverage::Incomplete,
        durability: Durability::Durable,
        closed_at_ms: kr_ipc::now_ms(),
    }
}

fn summary(session_id: SessionId) -> kr_protocol::session::SessionSummary {
    kr_protocol::session::SessionSummary {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id: kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid()),
        display_number: DisplayNumber::new(1),
        state: kr_protocol::session::SessionState::Closed,
        shell_mode: kr_protocol::session::ShellMode::NativeCompat,
        shell_path: "/bin/sh".to_owned(),
        cwd: "/".to_owned(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        desktop: kr_protocol::identity::DesktopBinding::none(),
        created_at_ms: kr_ipc::now_ms(),
        dimensions: kr_protocol::session::Dimensions::new(80, 24),
        attachment_count: kr_protocol::scalars::U64::new(0),
        application_state: Nullable::null(),
        root_process: Nullable::null(),
        closure: Nullable::null(),
    }
}

/// Writes a journal where a session's journal belongs, and returns the archive over it.
fn host() -> (TempHost, ArchiveService) {
    let temp = TempHost::create();
    let paths = temp.environment();
    let archive = ArchiveService::new(paths);
    (temp, archive)
}

fn journal_for(archive: &ArchiveService, session_id: SessionId) -> Journal {
    let path = archive.paths().journal_database(session_id);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the journal directory");
    Journal::open(&path).expect("opens")
}

fn submission(byte: u8) -> Submission {
    Submission {
        actor_id: ActorId::new("test:archive").expect("an actor"),
        action_id: kr_worker::journal::action_id_from([byte; 16]),
        method: kr_protocol::method::Method::SessionClose.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        payload_digest: kr_protocol::scalars::Digest256::from_bytes([byte; 32]),
        subject_digest: kr_protocol::scalars::Digest256::from_bytes([byte; 32]),
        intent: vec![0xa0],
        accepted_deadline_ms: Some(TimestampMs::new(kr_ipc::now_ms().get() + 120_000)),
        now_ms: kr_ipc::now_ms(),
    }
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-24.07, KR-ACC-029: serving a closed session with no worker
// ---------------------------------------------------------------------------------------------

#[test]
fn a_closed_session_is_served_from_what_it_left_behind() {
    let (_temp, archive) = host();
    let session_id = session();
    {
        let mut journal = journal_for(&archive, session_id);
        journal
            .record_session(&summary(session_id))
            .expect("records the summary");
        journal
            .record_closure(&closure(session_id, ClosureReason::CloseRequested))
            .expect("records the closure");
        journal.accept(&submission(1)).expect("accepts");
    }
    let read = archive.archive(session_id).expect("reads the archive");
    assert!(read.summary.is_some(), "the summary survived");
    assert_eq!(
        read.closure.as_ref().expect("the closure survived").reason,
        ClosureReason::CloseRequested
    );
    assert_eq!(read.receipts, 1);
    assert!(read.is_complete(), "{:?}", read.incompleteness);

    // And the receipt itself, with no worker anywhere.
    let actor = ActorId::new("test:archive").expect("an actor");
    let receipt = archive
        .receipt(
            session_id,
            &actor,
            kr_worker::journal::action_id_from([1; 16]),
        )
        .expect("reads the receipt");
    assert_eq!(
        receipt.receipt.state,
        kr_protocol::receipt::ReceiptState::Accepted
    );
}

#[test]
fn a_lost_journal_produces_an_explicit_incomplete_archive_rather_than_an_empty_success() {
    // KR-REQ-24.19. "This session kept nothing" and "this host cannot say what this session kept"
    // are different answers, and the second is the one a reader is owed.
    let (_temp, archive) = host();
    let session_id = session();
    let read = archive.archive(session_id).expect("reads the archive");
    assert!(!read.is_complete());
    assert_eq!(read.incompleteness, vec![Incompleteness::JournalMissing]);
    assert!(read.summary.is_none());
    assert!(read.closure.is_none());
}

#[test]
fn a_corrupt_journal_produces_an_explicit_incomplete_archive() {
    let (_temp, archive) = host();
    let session_id = session();
    let path = archive.paths().journal_database(session_id);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the directory");
    std::fs::write(&path, b"this is not a database").expect("a file that is not a journal");
    let read = archive.archive(session_id).expect("reads the archive");
    assert!(!read.is_complete());
    assert!(
        read.incompleteness
            .iter()
            .any(|reason| matches!(reason, Incompleteness::JournalUnreadable { .. })),
        "{:?}",
        read.incompleteness
    );
}

#[test]
fn a_session_whose_journal_holds_no_closure_says_so_rather_than_inventing_one() {
    let (_temp, archive) = host();
    let session_id = session();
    {
        let mut journal = journal_for(&archive, session_id);
        journal
            .record_session(&summary(session_id))
            .expect("records the summary");
    }
    let read = archive.archive(session_id).expect("reads the archive");
    assert!(
        read.incompleteness
            .contains(&Incompleteness::ClosureMissing)
    );
    assert!(read.closure.is_none());
}

#[test]
fn an_interval_durable_writing_was_lost_is_part_of_what_the_archive_reports() {
    let (_temp, archive) = host();
    let session_id = session();
    {
        let mut journal = journal_for(&archive, session_id);
        journal
            .record_session(&summary(session_id))
            .expect("records the summary");
        journal
            .record_closure(&closure(session_id, ClosureReason::WorkerCrash))
            .expect("records the closure");
        // A fault and its recovery, which leaves an interval this host cannot account for.
        journal.cap_at_current_size().expect("caps the store");
        let mut byte = 10_u8;
        while journal.accept(&submission(byte)).is_ok() {
            byte = byte.checked_add(1).expect("the bounded store never filled");
        }
        journal.release_size_cap().expect("releases the cap");
        journal
            .recover(kr_ipc::now_ms())
            .expect("recovers")
            .expect("a fault was open");
    }
    let read = archive.archive(session_id).expect("reads the archive");
    assert!(
        read.incompleteness
            .iter()
            .any(|reason| matches!(reason, Incompleteness::DurabilityLost { .. })),
        "{:?}",
        read.incompleteness
    );
}

#[test]
fn a_history_request_against_a_session_with_no_spool_is_a_gap_rather_than_an_empty_page() {
    // KR-ACC-029: a history request never creates a worker, and it never reads as "nothing
    // happened" when what happened was that the record went.
    let (_temp, archive) = host();
    let session_id = session();
    let page = archive.history_page(session_id, 0, 4096).expect("a page");
    assert!(page.bytes.is_empty());
    let gap = page.gap.0.expect("an explicit gap");
    assert_eq!(gap.cause, Some(HistoryGapCause::ArchiveIncomplete));
}

#[test]
fn a_closed_sessions_retained_output_is_paged_from_its_spool() {
    let (_temp, archive) = host();
    let session_id = session();
    let spool = archive.paths().session_spool(session_id);
    {
        let mut history = kr_worker::history::OutputHistory::with_spool(
            8,
            &spool,
            kr_worker::history::SpoolLayout::new(8, 1 << 20),
        )
        .expect("a spool");
        history.append(b"0123456789abcdef");
    }
    let page = archive.history_page(session_id, 0, 4096).expect("a page");
    assert_eq!(page.bytes.as_slice(), b"0123456789abcdef");
    assert!(!page.gap.is_present());
    let read = archive.archive(session_id).expect("reads the archive");
    assert_eq!(read.next_cursor, 16);
    assert!(
        read.retained
            .iter()
            .any(|resource| resource.kind == "output_spool")
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-24.18: exclusive recovery ownership, after fencing and death validation
// ---------------------------------------------------------------------------------------------

#[test]
fn ownership_is_refused_while_the_worker_is_alive() {
    let (_temp, archive) = host();
    let session_id = session();
    // This process is alive, and it stands in for a worker that is.
    let alive = kr_ipc::identity::current_process_start_identity().expect("an identity");
    let refused = archive
        .take_ownership(session_id, DisplayNumber::new(1), &alive)
        .expect_err("a live worker's stores are not the archive's");
    assert!(refused.to_string().contains("still running"), "{refused}");
}

#[test]
fn ownership_fences_the_endpoint_before_it_is_taken() {
    let (_temp, archive) = host();
    let session_id = session();
    // A descriptor and an endpoint, as a worker publishes them.
    let descriptor = archive.paths().descriptor_file(session_id);
    std::fs::create_dir_all(descriptor.parent().expect("a parent")).expect("the directory");
    std::fs::write(&descriptor, b"a descriptor").expect("writes it");
    let endpoint = archive
        .paths()
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    std::fs::create_dir_all(endpoint.as_path().parent().expect("a parent")).expect("the directory");
    std::fs::write(endpoint.as_path(), b"a socket").expect("writes it");

    // A process identity the kernel never described belongs to a process that had ended.
    // An identity the kernel never described belongs to a process that had already ended when it
    // was made, which is what `ended_process_identity` records and what the archive validates.
    let ended = kr_ipc::identity::ended_process_identity(1);
    let ownership = archive
        .take_ownership(session_id, DisplayNumber::new(1), &ended)
        .expect("a dead worker's stores are the archive's");
    assert!(ownership.endpoint_fenced);
    assert!(!descriptor.exists(), "the descriptor was fenced");
    assert!(!endpoint.as_path().exists(), "the endpoint was fenced");
    assert_eq!(ownership.session_id, session_id);
}

#[test]
fn taking_ownership_creates_no_worker_and_no_store() {
    let (_temp, archive) = host();
    let session_id = session();
    // An identity the kernel never described belongs to a process that had already ended when it
    // was made, which is what `ended_process_identity` records and what the archive validates.
    let ended = kr_ipc::identity::ended_process_identity(1);
    archive
        .take_ownership(session_id, DisplayNumber::new(1), &ended)
        .expect("ownership");
    assert!(
        !archive.paths().journal_database(session_id).exists(),
        "no journal was created for a session that never had one"
    );
    assert!(
        !archive.paths().session_spool(session_id).exists(),
        "no spool was created either"
    );
    let read = archive.archive(session_id).expect("reads the archive");
    assert_eq!(read.incompleteness, vec![Incompleteness::JournalMissing]);
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-07.65, 07.66: the closure receipt and what a crash fences
// ---------------------------------------------------------------------------------------------

#[test]
fn a_crash_fences_what_the_session_recorded_and_never_claims_more() {
    // KR-REQ-07.66. Only identities the session recorded are touched, each is checked against the
    // kernel's own answer first, and what survives outside that boundary is the user's.
    let (_temp, archive) = host();
    let session_id = session();
    // An identity the kernel never described belongs to a process that had already ended when it
    // was made, which is what `ended_process_identity` records and what the archive validates.
    let ended = kr_ipc::identity::ended_process_identity(1);
    let ownership = archive
        .take_ownership(session_id, DisplayNumber::new(1), &ended)
        .expect("ownership");

    // One process this test started itself, which stands in for a job the session owned.
    let mut child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("sleep 30")
        .spawn()
        .expect("starts a child");
    let owned = kr_ipc::identity::process_start_identity(child.id()).expect("its identity");
    let mut record = closure(session_id, ClosureReason::WorkerCrash);
    record.terminated = vec![
        TerminatedProcess {
            identity: owned.clone(),
            name: Nullable::some("a job this session owned".to_owned()),
            forced: false,
        },
        TerminatedProcess {
            identity: ended.clone(),
            name: Nullable::some("the session's worker".to_owned()),
            forced: false,
        },
    ];
    record.surviving = vec![SurvivingResource {
        kind: "browser".to_owned(),
        detail: "an explicitly brokered window".to_owned(),
    }];

    let fenced = archive.fence_owned(&ownership, &record);
    assert_eq!(fenced.session_id, session_id);
    assert_eq!(fenced.stopped, vec![owned], "the live one was terminated");
    assert_eq!(fenced.already_gone, 1, "the worker had already ended");
    assert_eq!(fenced.unaccounted, 0);
    assert_eq!(fenced.surviving.len(), 1, "what survives is reported");
    assert_eq!(
        fenced.coverage,
        OwnershipCoverage::Incomplete,
        "a session with a surviving resource never claims complete coverage"
    );
    let status = child.wait().expect("the child is collected");
    assert!(
        !status.success(),
        "the child ended because it was terminated rather than on its own"
    );
}

#[test]
fn a_closure_record_lists_terminated_identities_survivors_and_the_coverage_flag() {
    // KR-REQ-07.65. The record is what a later reader is served, so it carries all three.
    let (_temp, archive) = host();
    let session_id = session();
    let mut record = closure(session_id, ClosureReason::WorkerCrash);
    record.terminated = vec![TerminatedProcess {
        identity: kr_ipc::identity::ended_process_identity(4242),
        name: Nullable::some("the root shell".to_owned()),
        forced: true,
    }];
    record.surviving = vec![SurvivingResource {
        kind: "simulator".to_owned(),
        detail: "started through the desktop broker".to_owned(),
    }];
    {
        let mut journal = journal_for(&archive, session_id);
        journal.record_closure(&record).expect("records it");
    }
    let read = archive.archive(session_id).expect("reads the archive");
    let served = read.closure.expect("the closure survived");
    assert_eq!(served.terminated.len(), 1);
    assert!(served.terminated[0].forced);
    assert_eq!(served.surviving.len(), 1);
    assert_eq!(served.ownership_coverage, OwnershipCoverage::Incomplete);
}

// ---------------------------------------------------------------------------------------------
// The transfer sweep's one question (T-027 residual 1, D-054)
// ---------------------------------------------------------------------------------------------

#[test]
fn a_session_the_archive_holds_a_record_of_keeps_what_was_submitted_to_it() {
    let (_temp, archive) = host();
    let kept = session();
    {
        let mut journal = journal_for(&archive, kept);
        journal
            .record_closure(&closure(kept, ClosureReason::CloseRequested))
            .expect("records the closure");
    }
    assert!(
        archive.retains_submissions(kept).expect("answers"),
        "a closed session keeps what was submitted to it"
    );
    assert!(
        !archive.retains_submissions(session()).expect("answers"),
        "a session this host has no record of keeps nothing"
    );
}

#[test]
fn a_session_whose_journal_cannot_be_read_keeps_what_was_submitted_to_it() {
    // Declining to delete is the answer that cannot lose a file.
    let (_temp, archive) = host();
    let session_id = session();
    let path = archive.paths().journal_database(session_id);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the directory");
    std::fs::write(&path, b"this is not a database").expect("a file that is not a journal");
    assert!(archive.retains_submissions(session_id).expect("answers"));
}
