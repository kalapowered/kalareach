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
    // This session produced no output, so it has no spool, and this host cannot tell a spool that
    // never existed from one that is gone: it says the range is missing rather than reporting an
    // archive with nothing missing. It also holds one action that was admitted and never
    // dispatched, and no recovery pass has run over this store, so the archive says that too
    // rather than serving a session whose last action has no ending.
    assert_eq!(
        read.incompleteness,
        vec![
            Incompleteness::RecoveryUnfinished { unresolved: 1 },
            Incompleteness::HistoryLost {
                from_cursor: 0,
                to_cursor: 0
            }
        ]
    );

    // And the receipt itself, with no worker anywhere. It was admitted and never dispatched, and
    // recovery has not run, so what it says is what the worker left: section 9's rules are run
    // once under recovery ownership, which the next test drives.
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
fn recovery_resolves_what_a_crashed_worker_left_unfinished() {
    // Section 9's two recovery rules are the worker's, and a worker that crashed never ran them.
    // The archive runs them once under ownership: a dispatch marker with no authoritative outcome
    // becomes `unknown` and is never dispatched again, and an accepted intent with no marker is
    // rejected, because the freshness it was admitted under cannot be revalidated.
    let (_temp, archive) = host();
    let session_id = session();
    let actor = ActorId::new("test:archive").expect("an actor");
    {
        let mut journal = journal_for(&archive, session_id);
        journal.accept(&submission(1)).expect("an accepted intent");
        journal.accept(&submission(2)).expect("a second one");
        journal
            .mark_dispatching(
                actor.clone(),
                kr_worker::journal::action_id_from([2; 16]),
                kr_ipc::now_ms(),
            )
            .expect("a dispatch marker with no outcome");
    }
    let ended = kr_ipc::identity::ended_process_identity(1);
    let ownership = archive
        .take_ownership(session_id, DisplayNumber::new(1), &ended)
        .expect("ownership");
    let recovered = archive.recover_journal(&ownership).expect("recovers");
    assert_eq!(recovered.left_unknown, 1);
    assert_eq!(recovered.rejected, 1);

    let dispatched = archive
        .receipt(
            session_id,
            &actor,
            kr_worker::journal::action_id_from([2; 16]),
        )
        .expect("reads the receipt");
    assert_eq!(
        dispatched.receipt.state,
        kr_protocol::receipt::ReceiptState::Unknown,
        "a marker with no answer is unknown rather than dispatching for ever"
    );
    let accepted = archive
        .receipt(
            session_id,
            &actor,
            kr_worker::journal::action_id_from([1; 16]),
        )
        .expect("reads the receipt");
    assert_eq!(
        accepted.receipt.state,
        kr_protocol::receipt::ReceiptState::Rejected
    );
}

#[test]
fn recovery_of_a_session_with_no_journal_creates_none() {
    let (_temp, archive) = host();
    let session_id = session();
    let ended = kr_ipc::identity::ended_process_identity(1);
    let ownership = archive
        .take_ownership(session_id, DisplayNumber::new(1), &ended)
        .expect("ownership");
    let recovered = archive.recover_journal(&ownership).expect("answers");
    assert_eq!(recovered.left_unknown, 0);
    assert_eq!(recovered.rejected, 0);
    assert!(
        !archive.paths().journal_database(session_id).exists(),
        "an empty journal is not invented for a session that had none"
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
    assert_eq!(
        read.incompleteness,
        vec![
            Incompleteness::JournalMissing,
            Incompleteness::ClosureMissing
        ]
    );
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
fn a_live_workers_endpoint_is_not_fenced_by_an_enquiry_that_is_refused() {
    // Fencing before validating would delete a working session's socket on the way to finding out
    // that it was working. Death is validated first, so a refusal leaves everything where it was.
    let (_temp, archive) = host();
    let session_id = session();
    let descriptor = archive.paths().descriptor_file(session_id);
    std::fs::create_dir_all(descriptor.parent().expect("a parent")).expect("the directory");
    std::fs::write(&descriptor, b"a descriptor").expect("writes it");
    let endpoint = archive
        .paths()
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    std::fs::create_dir_all(endpoint.as_path().parent().expect("a parent")).expect("the directory");
    std::fs::write(endpoint.as_path(), b"a socket").expect("writes it");

    let alive = kr_ipc::identity::current_process_start_identity().expect("an identity");
    archive
        .take_ownership(session_id, DisplayNumber::new(1), &alive)
        .expect_err("a live worker's stores are not the archive's");
    assert!(descriptor.exists(), "the descriptor is still published");
    assert!(
        endpoint.as_path().exists(),
        "the live worker's endpoint is still there"
    );
}

#[test]
fn ownership_fences_the_endpoint_once_death_is_validated() {
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
    assert_eq!(
        read.incompleteness,
        vec![
            Incompleteness::JournalMissing,
            Incompleteness::ClosureMissing
        ]
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-07.65, 07.66: the closure receipt and what a crash fences
// ---------------------------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_crash_stops_nothing_on_the_strength_of_an_identifier_the_kernel_may_have_reused() {
    // KR-REQ-07.66's cleanup half. A worker's descendants join the group it led, and once the
    // worker has gone the kernel is free to give its number to an unrelated process whose group
    // would answer to it. This host therefore stops nothing from a dead identifier, and says so:
    // the boundary is one it has none of, and the coverage is incomplete.
    let (_temp, archive) = host();
    let session_id = session();

    // A process this test started, which stands in for whatever a crashed session left behind.
    let mut child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("sleep 5")
        .spawn()
        .expect("starts a child");
    let owned = kr_ipc::identity::process_start_identity(child.id()).expect("its identity");

    let ended = kr_ipc::identity::ended_process_identity(1);
    let ownership = archive
        .take_ownership(session_id, DisplayNumber::new(1), &ended)
        .expect("ownership");
    let mut record = closure(session_id, ClosureReason::WorkerCrash);
    record.terminated = vec![TerminatedProcess {
        identity: ended.clone(),
        name: Nullable::some("the session's worker".to_owned()),
        forced: false,
    }];
    record.surviving = vec![SurvivingResource {
        kind: "browser".to_owned(),
        detail: "an explicitly brokered window".to_owned(),
    }];

    let fenced = archive.fence_owned(&ownership, &record);
    assert_eq!(fenced.session_id, session_id);
    assert_eq!(
        fenced.boundary,
        kr_controller::archive::CleanupBoundary::None
    );
    assert!(fenced.stopped.is_empty(), "nothing is stopped by inference");
    assert_eq!(fenced.already_gone, 1, "the worker had already ended");
    assert!(
        fenced.unaccounted > 0,
        "a boundary this host has none of is something it cannot account for"
    );
    assert_eq!(fenced.surviving.len(), 1, "what survives is reported");
    assert_eq!(fenced.coverage, OwnershipCoverage::Incomplete);

    // And the process this test started is untouched, because nothing went looking for it.
    assert!(matches!(
        kr_ipc::identity::process_state(&owned),
        kr_ipc::identity::ProcessState::Running
    ));
    let _ = child.kill();
    let _ = child.wait();
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

#[test]
fn a_recovery_that_did_not_run_is_part_of_what_the_archive_reports() {
    // Residual 19's reader half. A closure can be written for a session whose store this host
    // never reconciled - the kernel would not confirm the death, or the pass itself failed - and
    // the closure says nothing about that, because section 23 defines its durability as whether
    // the *record* was written. What a reader needs is the store's own answer, so the archive
    // reads it: an action still accepted or still dispatching is one the recovery rules never
    // settled.
    let (_temp, archive) = host();
    let session_id = session();
    let actor = ActorId::new("test:archive").expect("an actor");
    {
        let mut journal = journal_for(&archive, session_id);
        journal
            .record_session(&summary(session_id))
            .expect("records the summary");
        journal
            .record_closure(&closure(session_id, ClosureReason::WorkerCrash))
            .expect("records the closure");
        journal.accept(&submission(4)).expect("an accepted intent");
        journal
            .mark_dispatching(
                actor.clone(),
                kr_worker::journal::action_id_from([4; 16]),
                kr_ipc::now_ms(),
            )
            .expect("a dispatch marker with no outcome");
    }
    let before = archive.archive(session_id).expect("reads the archive");
    assert!(
        before
            .incompleteness
            .contains(&Incompleteness::RecoveryUnfinished { unresolved: 1 }),
        "a store nothing recovered is reported as such: {:?}",
        before.incompleteness
    );

    // Once the pass has run under ownership, it is not reported any more: the marker has an
    // ending, and the archive says what is missing rather than repeating itself.
    let ended = kr_ipc::identity::ended_process_identity(1);
    let ownership = archive
        .take_ownership(session_id, DisplayNumber::new(1), &ended)
        .expect("ownership");
    archive.recover_journal(&ownership).expect("recovers");
    let after = archive
        .archive(session_id)
        .expect("reads the archive again");
    assert!(
        !after
            .incompleteness
            .iter()
            .any(|missing| matches!(missing, Incompleteness::RecoveryUnfinished { .. })),
        "the pass ran: {:?}",
        after.incompleteness
    );
}

#[test]
fn a_session_closed_by_an_earlier_build_is_brought_forward_rather_than_refused() {
    // Section 24's forward-only migration reaches a session that has no worker left to run it. A
    // store an earlier build wrote records an earlier schema, and this build reads one current
    // schema; without this the shell, the directory, the geometry and the creation time a person
    // is shown for a closed session would be lost the moment this build shipped.
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
    }
    // The store as an earlier build left it: the version it recorded, and none of the objects the
    // steps after it added.
    let path = archive.paths().journal_database(session_id);
    {
        let connection = rusqlite::Connection::open(&path).expect("opens the store");
        connection
            .execute_batch(
                "DROP TABLE privacy;
                 DROP TABLE outbox;
                 DROP TABLE outbox_cursors;
                 DROP TABLE journal_gaps;
                 UPDATE schema_version SET version = 3;",
            )
            .expect("puts it back to the earlier shape");
    }
    assert_eq!(
        kr_worker::journal::Journal::recorded_schema_version(&path).expect("reads the version"),
        3
    );

    let read = archive.archive(session_id).expect("reads the archive");
    assert!(
        read.summary.is_some(),
        "the session an earlier build recorded is still described: {:?}",
        read.incompleteness
    );
    assert_eq!(
        read.closure.as_ref().expect("the closure survived").reason,
        ClosureReason::CloseRequested
    );
    assert_eq!(
        kr_worker::journal::Journal::recorded_schema_version(&path).expect("reads the version"),
        kr_worker::persistence::migration::CURRENT,
        "the store was brought forward once rather than read twice"
    );
}

#[test]
fn a_store_whose_worker_may_still_own_it_is_not_migrated() {
    // Review 10's finding, and the reason the migration asks its own question. A closure can be
    // recorded for a session whose death this host never confirmed, and the registry row that
    // every later read checks goes with the closure. So the migration - which is a write - asks
    // the published descriptor itself: a process the kernel has not said ended may still own this
    // store, and opening it writable would be a second writer.
    let (_temp, archive) = host();
    let session_id = session();
    {
        let mut journal = journal_for(&archive, session_id);
        journal
            .record_session(&summary(session_id))
            .expect("records the summary");
    }
    let path = archive.paths().journal_database(session_id);
    {
        let connection = rusqlite::Connection::open(&path).expect("opens the store");
        connection
            .execute_batch(
                "DROP TABLE privacy;
                 DROP TABLE outbox;
                 DROP TABLE outbox_cursors;
                 DROP TABLE journal_gaps;
                 UPDATE schema_version SET version = 3;",
            )
            .expect("puts it back to the earlier shape");
    }
    // A descriptor naming this process, which is alive. That is what a worker publishes, and it
    // outlives the worker that wrote it.
    let alive = kr_ipc::identity::current_process_start_identity().expect("an identity");
    publish_descriptor(&archive, session_id, &alive);

    archive.bring_forward(session_id);
    assert_eq!(
        kr_worker::journal::Journal::recorded_schema_version(&path).expect("reads the version"),
        3,
        "a store a live worker may own is left exactly where it is"
    );

    // Once the descriptor names a process that has ended, the same call brings it forward.
    let ended = kr_ipc::identity::ended_process_identity(1);
    publish_descriptor(&archive, session_id, &ended);
    archive.bring_forward(session_id);
    assert_eq!(
        kr_worker::journal::Journal::recorded_schema_version(&path).expect("reads the version"),
        kr_worker::persistence::migration::CURRENT
    );
}

#[test]
#[cfg(unix)]
fn a_descriptor_this_host_cannot_read_refuses_the_migration_rather_than_guessing() {
    // A migration is a write. Absence of a descriptor is the ordinary archive case - a session
    // this host fenced published none - but a descriptor that is *there* and cannot be read
    // answers nothing at all, and a write must not be made on nothing.
    use std::os::unix::fs::PermissionsExt as _;
    let (_temp, archive) = host();
    let session_id = session();
    {
        let mut journal = journal_for(&archive, session_id);
        journal
            .record_session(&summary(session_id))
            .expect("records the summary");
    }
    let path = archive.paths().journal_database(session_id);
    {
        let connection = rusqlite::Connection::open(&path).expect("opens the store");
        connection
            .execute_batch(
                "DROP TABLE privacy;
                 DROP TABLE outbox;
                 DROP TABLE outbox_cursors;
                 DROP TABLE journal_gaps;
                 UPDATE schema_version SET version = 3;",
            )
            .expect("puts it back to the earlier shape");
    }
    let ended = kr_ipc::identity::ended_process_identity(1);
    publish_descriptor(&archive, session_id, &ended);
    let descriptor = archive.paths().descriptor_file(session_id);
    let mode = std::fs::metadata(&descriptor).expect("reads").permissions();
    std::fs::set_permissions(&descriptor, std::fs::Permissions::from_mode(0o000))
        .expect("makes the descriptor unreadable");

    archive.bring_forward(session_id);
    let refused = kr_worker::journal::Journal::recorded_schema_version(&path).expect("reads it");
    std::fs::set_permissions(&descriptor, mode).expect("puts the permissions back");
    assert_eq!(
        refused, 3,
        "a descriptor this host could not read is not a death it can act on"
    );

    // Readable again, and the same call brings it forward.
    archive.bring_forward(session_id);
    assert_eq!(
        kr_worker::journal::Journal::recorded_schema_version(&path).expect("reads it"),
        kr_worker::persistence::migration::CURRENT
    );
}

/// Publishes a descriptor for a session, as a worker does when it starts.
fn publish_descriptor(
    archive: &ArchiveService,
    session_id: SessionId,
    identity: &kr_protocol::identity::ProcessStartIdentity,
) {
    let descriptor = kr_protocol::worker::WorkerDescriptor {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id: archive.paths().environment_id(),
        display_number: DisplayNumber::new(1),
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        process_start_identity: identity.clone(),
        protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
        endpoint: "/tmp/kr-archive-test.sock".to_owned(),
        worker_public_key: kr_protocol::scalars::AuthorisationKey::from_bytes([7; 32]),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        published_at_ms: kr_ipc::now_ms(),
    };
    kr_ipc::descriptor::publish(archive.paths(), &descriptor).expect("publishes the descriptor");
}
