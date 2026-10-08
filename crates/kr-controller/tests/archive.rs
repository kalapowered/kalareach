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
        environment_sources: None,
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
            true,
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
            true,
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
            true,
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
    // The control for the hole below: a spool whose segments meet reports no range as lost.
    assert!(
        !read
            .incompleteness
            .iter()
            .any(|missing| matches!(missing, Incompleteness::HistoryLost { .. })),
        "{:?}",
        read.incompleteness
    );
}

#[test]
fn a_hole_inside_a_closed_sessions_retained_output_is_part_of_what_the_archive_reports() {
    // KR-REQ-24.19. A segment that has gone from the middle of the retained range is a range this
    // host cannot account for. The archive's own account names it, beside the range before the
    // oldest cursor, and a reader paging the archive is told the range and given what follows.
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
        for byte in *b"abcd" {
            history.append(&[byte; 8]);
        }
    }
    std::fs::remove_file(spool.join(format!("{:020}.out", 8))).expect("removes a middle segment");

    let read = archive.archive(session_id).expect("reads the archive");
    assert!(
        read.incompleteness.contains(&Incompleteness::HistoryLost {
            from_cursor: 8,
            to_cursor: 16
        }),
        "the hole is part of the account: {:?}",
        read.incompleteness
    );
    assert!(!read.is_complete());
    let page = archive.history_page(session_id, 8, 4096).expect("a page");
    let gap = page.gap.0.expect("the missing range is a gap");
    assert_eq!((gap.from_cursor.get(), gap.to_cursor.get()), (8, 16));
    assert_eq!(gap.cause, Some(HistoryGapCause::ArchiveIncomplete));
    assert_eq!(page.from_cursor.get(), 16);
    assert_eq!(
        page.bytes.as_slice(),
        [[b'c'; 8], [b'd'; 8]].concat().as_slice()
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-20.20, 20.21: a closed session's retention, applied with no worker
// ---------------------------------------------------------------------------------------------

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// A closed session with two receipts and sixteen bytes of output. With `aged`, the first receipt
/// was written thirty-one days ago in an earlier boot.
fn closed_session_with_history(archive: &ArchiveService, aged: bool) -> SessionId {
    let session_id = session();
    {
        let mut journal = journal_for(archive, session_id);
        journal
            .record_session(&summary(session_id))
            .expect("records the summary");
        journal
            .record_closure(&closure(session_id, ClosureReason::CloseRequested))
            .expect("records the closure");
        journal.accept(&submission(1)).expect("a first receipt");
        journal.accept(&submission(2)).expect("a second one");
    }
    if aged {
        let connection = rusqlite::Connection::open(archive.paths().journal_database(session_id))
            .expect("opens the store");
        connection
            .execute(
                "UPDATE receipts SET created_at_ms = ?1, created_boot = 'an-earlier-boot'
                 WHERE action_id = ?2",
                rusqlite::params![
                    i64::try_from(kr_ipc::now_ms().get() - 31 * DAY_MS).expect("a time"),
                    kr_worker::journal::action_id_from([1; 16])
                        .get()
                        .as_bytes()
                        .as_slice(),
                ],
            )
            .expect("ages the first receipt");
    }
    let mut history = kr_worker::history::OutputHistory::with_spool(
        8,
        archive.paths().session_spool(session_id),
        kr_worker::history::SpoolLayout::new(8, 1 << 20),
    )
    .expect("a spool");
    history.append(b"0123456789abcdef");
    session_id
}

/// Eight days from now: output written now is past seven days, a receipt written now is not past
/// thirty, and one written thirty-one days ago is.
fn eight_days_on() -> TimestampMs {
    TimestampMs::new(kr_ipc::now_ms().get() + 8 * DAY_MS)
}

#[test]
fn a_closed_sessions_output_past_seven_days_and_receipts_past_thirty_are_collected() {
    // KR-REQ-20.21 and 20.20's seven days, for a session with no worker to apply them. The
    // archive applies both under recovery ownership, each on its own budget, and runs section 9's
    // recovery rules first so no receipt goes while its action has no ending.
    let (_temp, archive) = host();
    let session_id = closed_session_with_history(&archive, true);
    let ended = kr_ipc::identity::ended_process_identity(1);
    let ownership = archive
        .take_ownership(session_id, DisplayNumber::new(1), &ended)
        .expect("ownership");
    let collected = archive
        .collect(&ownership, eight_days_on(), true)
        .expect("collects");
    assert_eq!(collected.output_bytes, 16, "{collected:?}");
    assert_eq!(collected.receipts, 1, "{collected:?}");
    assert_eq!(collected.output_retained, Some(0));
    assert_eq!(collected.receipts_retained, Some(1));
    assert_eq!(collected.output_left_behind, None);
    assert_eq!(collected.receipts_left_behind, None);
    assert_eq!(
        collected.recovered.rejected, 2,
        "the recovery rules ran before anything went"
    );
    assert!(collected.age_permitted);

    let read = archive.archive(session_id).expect("reads the archive");
    assert_eq!(
        read.receipts, 1,
        "the receipt inside its thirty days is kept"
    );
    assert_eq!(
        read.next_cursor, 16,
        "the boundary still says where it reached"
    );
    assert_eq!(read.oldest_retained_cursor, 16, "the output went");
    assert!(
        read.incompleteness.contains(&Incompleteness::HistoryLost {
            from_cursor: 0,
            to_cursor: 16
        }),
        "{:?}",
        read.incompleteness
    );
    assert!(
        !read
            .incompleteness
            .iter()
            .any(|missing| matches!(missing, Incompleteness::RecoveryUnfinished { .. })),
        "{:?}",
        read.incompleteness
    );
}

#[test]
fn a_closed_session_inside_its_retention_keeps_everything() {
    // The control for the test above: nothing is past either period, so nothing goes.
    let (_temp, archive) = host();
    let session_id = closed_session_with_history(&archive, false);
    let ended = kr_ipc::identity::ended_process_identity(1);
    let ownership = archive
        .take_ownership(session_id, DisplayNumber::new(1), &ended)
        .expect("ownership");
    let collected = archive
        .collect(&ownership, kr_ipc::now_ms(), true)
        .expect("collects");
    assert_eq!(collected.output_bytes, 0);
    assert_eq!(collected.receipts, 0);
    assert_eq!(collected.output_retained, Some(16));
    assert_eq!(collected.receipts_retained, Some(2));
    let read = archive.archive(session_id).expect("reads the archive");
    assert_eq!(read.receipts, 2);
    assert_eq!(read.oldest_retained_cursor, 0);
    assert_eq!(read.next_cursor, 16);
}

#[test]
fn a_clock_this_host_cannot_prove_collects_nothing_by_age_from_a_closed_session() {
    // Section 9's rule for expiry-based collection holds for the archive as for the worker:
    // removing what is old on a clock this host cannot prove is how a rollback deletes what had
    // not expired.
    let (_temp, archive) = host();
    let session_id = closed_session_with_history(&archive, true);
    let ended = kr_ipc::identity::ended_process_identity(1);
    let ownership = archive
        .take_ownership(session_id, DisplayNumber::new(1), &ended)
        .expect("ownership");
    let much_later = TimestampMs::new(kr_ipc::now_ms().get() + 40 * DAY_MS);
    let collected = archive
        .collect(&ownership, much_later, false)
        .expect("collects");
    assert!(!collected.age_permitted);
    assert_eq!(collected.output_bytes, 0);
    assert_eq!(collected.receipts, 0);
    let read = archive.archive(session_id).expect("reads the archive");
    assert_eq!(read.receipts, 2);
    assert_eq!(read.oldest_retained_cursor, 0);
}

#[test]
fn a_session_a_worker_may_still_own_is_not_collected() {
    // Collection is a write, so it asks the question every write of the archive asks: a
    // descriptor naming a process the kernel has not said ended belongs to a worker that may
    // still own these stores.
    let (_temp, archive) = host();
    let session_id = closed_session_with_history(&archive, true);
    let ended = kr_ipc::identity::ended_process_identity(1);
    let ownership = archive
        .take_ownership(session_id, DisplayNumber::new(1), &ended)
        .expect("ownership");
    let alive = kr_ipc::identity::current_process_start_identity().expect("an identity");
    publish_descriptor(&archive, session_id, &alive);
    let refused = archive
        .collect(&ownership, eight_days_on(), true)
        .expect_err("a store a worker may still own is not collected");
    assert!(refused.to_string().contains("may still"), "{refused}");
    let connection = rusqlite::Connection::open(archive.paths().journal_database(session_id))
        .expect("opens the store");
    let held: i64 = connection
        .query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))
        .expect("counts");
    assert_eq!(held, 2, "nothing was taken");
}

#[test]
#[cfg(unix)]
fn a_descriptor_this_host_cannot_read_stops_the_collection() {
    // A descriptor that is there and cannot be read answers nothing about the worker it names,
    // and a collection is a write: nothing is collected on nothing.
    use std::os::unix::fs::PermissionsExt as _;
    let (_temp, archive) = host();
    let session_id = closed_session_with_history(&archive, true);
    let ended = kr_ipc::identity::ended_process_identity(1);
    let ownership = archive
        .take_ownership(session_id, DisplayNumber::new(1), &ended)
        .expect("ownership");
    publish_descriptor(&archive, session_id, &ended);
    let descriptor = archive.paths().descriptor_file(session_id);
    let mode = std::fs::metadata(&descriptor).expect("reads").permissions();
    std::fs::set_permissions(&descriptor, std::fs::Permissions::from_mode(0o000))
        .expect("makes the descriptor unreadable");
    let refused = archive.collect(&ownership, eight_days_on(), true);
    std::fs::set_permissions(&descriptor, mode).expect("puts the permissions back");
    let refused = refused.expect_err("an unreadable descriptor stops the collection");
    assert!(refused.to_string().contains("may still"), "{refused}");
}

#[test]
fn a_journal_the_collection_cannot_read_is_reported_and_the_output_is_still_collected() {
    // The two stores are collected on their own accounts, so a journal this host cannot open is
    // reported in the receipts' result and does not stop the output's.
    let (_temp, archive) = host();
    let session_id = closed_session_with_history(&archive, true);
    std::fs::write(
        archive.paths().journal_database(session_id),
        b"this is not a database",
    )
    .expect("a file that is not a journal");
    let ended = kr_ipc::identity::ended_process_identity(1);
    let ownership = archive
        .take_ownership(session_id, DisplayNumber::new(1), &ended)
        .expect("ownership");
    let collected = archive
        .collect(&ownership, eight_days_on(), true)
        .expect("collects");
    assert!(collected.receipts_left_behind.is_some(), "{collected:?}");
    assert_eq!(collected.receipts, 0);
    assert_eq!(collected.receipts_retained, None, "this host cannot say");
    assert_eq!(collected.output_bytes, 16, "{collected:?}");
    assert_eq!(collected.output_retained, Some(0));
}

#[test]
fn a_segment_the_collection_cannot_remove_is_reported_rather_than_counted_as_gone() {
    let (_temp, archive) = host();
    let session_id = closed_session_with_history(&archive, true);
    // A directory stands where the oldest segment's file was, so no platform removes it as one.
    let oldest = archive
        .paths()
        .session_spool(session_id)
        .join(format!("{:020}.out", 0));
    std::fs::remove_file(&oldest).expect("removes the oldest segment's file");
    std::fs::create_dir(&oldest).expect("puts a directory in its place");
    std::fs::write(oldest.join("in-the-way"), b"x").expect("and something in it");
    let ended = kr_ipc::identity::ended_process_identity(1);
    let ownership = archive
        .take_ownership(session_id, DisplayNumber::new(1), &ended)
        .expect("ownership");
    let collected = archive
        .collect(&ownership, eight_days_on(), true)
        .expect("collects");
    assert_eq!(collected.output_bytes, 0, "{collected:?}");
    assert!(
        collected
            .output_left_behind
            .as_deref()
            .is_some_and(|why| why.contains("could not be removed")),
        "{collected:?}"
    );
    assert!(
        collected.output_retained.is_some_and(|held| held > 0),
        "what could not be removed is still counted: {collected:?}"
    );
    assert_eq!(
        collected.receipts, 1,
        "the receipts are collected on their own account"
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

/// A process this test starts to stand in for what a crashed session left behind: it runs until it
/// is ended, and ends when asked.
fn leftover() -> Reaped {
    #[cfg(unix)]
    let mut command = {
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", "exec sleep 600"]);
        command
    };
    #[cfg(windows)]
    let mut command = {
        let root = std::env::var_os("SystemRoot").expect("the system directory");
        let mut command = std::process::Command::new(
            std::path::Path::new(&root)
                .join("System32")
                .join("PING.EXE"),
        );
        command.args(["-n", "600", "127.0.0.1"]);
        command
    };
    let child = command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("starts a process");
    let identity = kr_ipc::identity::process_start_identity(child.id()).expect("its identity");
    Reaped { child, identity }
}

/// A leftover process, ended when the test is over whatever the test did.
struct Reaped {
    child: std::process::Child,
    identity: kr_protocol::identity::ProcessStartIdentity,
}

impl Reaped {
    fn running(&self) -> bool {
        matches!(
            kr_ipc::identity::process_state(&self.identity),
            kr_ipc::identity::ProcessState::Running
        )
    }
}

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The record a worker leaves of a session whose root shell and descendants are `processes`.
fn owned_record(
    processes: Vec<kr_protocol::identity::ProcessStartIdentity>,
) -> kr_worker::ownership::OwnedRecord {
    kr_worker::ownership::OwnedRecord {
        boot: Some(kr_ipc::identity::boot_identity().expect("this boot")),
        root: processes.first().cloned().expect("a root"),
        processes,
        cgroup: None,
        boundary: "the terminal's process group".to_owned(),
        limits: Vec::new(),
    }
}

/// Takes ownership of a session whose worker is gone, as the daemon does before it fences.
fn take(
    archive: &ArchiveService,
    session_id: SessionId,
) -> kr_controller::archive::RecoveryOwnership {
    let ended = kr_ipc::identity::ended_process_identity(1);
    archive
        .take_ownership(session_id, DisplayNumber::new(1), &ended)
        .expect("ownership")
}

/// KR-REQ-07.66's cleaning half and KR-REQ-24.25's fencing half. A crashed session's recorded
/// processes are stopped by their identity and nothing else is: a recorded identifier that now
/// belongs to another process leaves that process alone, and a process the worker never recorded is
/// not looked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_stops_the_processes_the_worker_recorded_and_no_other() {
    let (_temp, archive) = host();
    let session_id = session();
    let recorded = leftover();
    // The identifier is right and the start is not: the number belongs to another process now.
    let stranger = leftover();
    let reused = kr_protocol::identity::ProcessStartIdentity::new(
        stranger.identity.pid.get(),
        stranger.identity.source,
        stranger.identity.start_value.get().wrapping_add(1_000_000),
    );
    let unrecorded = leftover();
    {
        let mut journal = journal_for(&archive, session_id);
        journal
            .record_owned(
                session_id,
                &owned_record(vec![recorded.identity.clone(), reused.clone()]),
            )
            .expect("records what the session owned");
    }
    let ownership = take(&archive, session_id);

    let fenced = archive.fence_owned(&ownership, None).await;

    assert_eq!(fenced.session_id, session_id);
    assert!(
        !recorded.running(),
        "the process the worker recorded was stopped"
    );
    assert!(
        fenced
            .ended
            .iter()
            .any(|ended| ended.identity == recorded.identity && ended.root),
        "and the closure names it, as the root shell it was recorded as: {fenced:?}"
    );
    assert!(
        fenced
            .ended
            .iter()
            .any(|ended| ended.identity == reused && !ended.forced),
        "the recorded process whose number was reused had ended, and was not forced"
    );
    assert!(
        stranger.running(),
        "the process that holds a recorded number now was not touched"
    );
    assert!(
        unrecorded.running(),
        "and a process the worker never recorded was not looked for"
    );
    assert_eq!(
        fenced.coverage,
        OwnershipCoverage::Incomplete,
        "nothing here proves a boundary, so the coverage is incomplete"
    );
}

/// A record this pass may not act on stops nothing, and the closure says why. The processes are
/// real and carry their true identities, so the only reason they are left alone is the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_from_another_boot_or_none_at_all_stops_nothing_and_says_why() {
    for what in ["another boot", "a record that names no boot", "no record"] {
        let (_temp, archive) = host();
        let session_id = session();
        let leftover = leftover();
        {
            let mut journal = journal_for(&archive, session_id);
            let mut record = owned_record(vec![leftover.identity.clone()]);
            match what {
                "another boot" => {
                    record.boot = Some(kr_protocol::identity::BootIdentity {
                        source: kr_protocol::identity::BootIdentitySource::BootTime,
                        value: kr_protocol::scalars::Bytes::new(b"not this boot".to_vec()),
                    });
                }
                "a record that names no boot" => record.boot = None,
                _ => {}
            }
            if what != "no record" {
                journal
                    .record_owned(session_id, &record)
                    .expect("records what the session owned");
            }
        }
        let ownership = take(&archive, session_id);
        let fenced = archive.fence_owned(&ownership, None).await;
        assert!(leftover.running(), "{what}: nothing was stopped");
        assert!(fenced.ended.is_empty(), "{what}: nothing is reported ended");
        assert!(
            fenced
                .surviving
                .iter()
                .any(|resource| resource.kind == "unestablished"),
            "{what}: the closure says why: {fenced:?}"
        );
        assert_eq!(fenced.coverage, OwnershipCoverage::Incomplete, "{what}");
    }
}

/// A process the platform will not let this host stop is named in the closure, by identifier and
/// start and where it ran, with incomplete coverage: it is not claimed gone.
///
/// The kernel's refusal is the only part supplied, because a test cannot make a process of its own
/// refuse a signal without an account it does not have; the process is real and keeps running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_process_the_platform_will_not_stop_is_named_and_the_coverage_stays_incomplete() {
    let (_temp, archive) = host();
    let session_id = session();
    let obstinate = leftover();
    let obedient = leftover();
    {
        let mut journal = journal_for(&archive, session_id);
        journal
            .record_owned(
                session_id,
                &owned_record(vec![obedient.identity.clone(), obstinate.identity.clone()]),
            )
            .expect("records what the session owned");
    }
    kr_controller::testing::refuse_stopping(obstinate.identity.clone());
    let ownership = take(&archive, session_id);

    let fenced = archive.fence_owned(&ownership, None).await;

    assert!(!obedient.running(), "the process that can be stopped was");
    assert!(
        obstinate.running(),
        "the one the platform refused still runs"
    );
    let named = fenced
        .surviving
        .iter()
        .find(|resource| resource.kind == "process")
        .expect("the survivor is in the closure");
    assert!(
        named
            .detail
            .contains(&format!("process {} ", obstinate.identity.pid.get()))
            && named
                .detail
                .contains(&format!("started {}", obstinate.identity.start_value.get())),
        "it is named by identifier and start: {named:?}"
    );
    assert!(
        named.detail.contains("terminal's process group"),
        "and by where it ran: {named:?}"
    );
    assert!(
        !fenced
            .ended
            .iter()
            .any(|ended| ended.identity == obstinate.identity),
        "it is not claimed gone"
    );
    assert_eq!(fenced.coverage, OwnershipCoverage::Incomplete);
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
// The transfer sweep's one question
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
    // The reader's half. A closure can be written for a session whose store this host never
    // reconciled - the kernel would not confirm the death, or the pass itself failed - and the
    // closure says nothing about that, because section 23 defines its durability as whether the
    // *record* was written. What a reader needs is the store's own answer, so the archive reads
    // it: an action still accepted or still dispatching is one the recovery rules never settled.
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
    // Why the migration asks its own question. A closure can be recorded for a session whose
    // death this host never confirmed, and the registry row that every later read checks goes
    // with the closure. So the migration - which is a write - asks the published descriptor
    // itself: a process the kernel has not said ended may still own this store, and opening it
    // writable would be a second writer.
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

// ---------------------------------------------------------------------------------------------
// KR-REQ-24.30: a journal older than the ladder, refused by name and imported explicitly
// ---------------------------------------------------------------------------------------------

/// Opens the environment's registry as a daemon does, creating it on first use.
fn registry(archive: &ArchiveService) -> kr_controller::registry::Registry {
    kr_controller::registry::Registry::open(
        archive.paths().registry_database(),
        archive.paths().environment_id(),
    )
    .expect("the registry")
}

/// Writes the journal the first build of this schema wrote, version 1 with one receipt, where the
/// session's journal belongs.
fn write_version_one_journal(archive: &ArchiveService, session_id: SessionId) {
    let path = archive.paths().journal_database(session_id);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the journal directory");
    let connection = rusqlite::Connection::open(&path).expect("creates the fixture");
    connection
        .execute_batch(
            "CREATE TABLE schema_version (version INTEGER NOT NULL);
             CREATE TABLE receipts (
                 actor_id             TEXT    NOT NULL,
                 action_id            BLOB    NOT NULL,
                 method               TEXT    NOT NULL,
                 method_version       INTEGER NOT NULL,
                 revision             INTEGER NOT NULL,
                 state                TEXT    NOT NULL,
                 reason               TEXT,
                 payload_digest       BLOB    NOT NULL,
                 accepted_deadline_ms INTEGER,
                 error_code           TEXT,
                 error_message        TEXT,
                 created_at_ms        INTEGER NOT NULL,
                 updated_at_ms        INTEGER NOT NULL,
                 PRIMARY KEY (actor_id, action_id)
             );
             CREATE INDEX receipts_created_at ON receipts (created_at_ms);
             INSERT INTO schema_version (version) VALUES (1);",
        )
        .expect("the version 1 schema");
    connection
        .execute(
            "INSERT INTO receipts (
                 actor_id, action_id, method, method_version, revision, state,
                 payload_digest, accepted_deadline_ms, created_at_ms, updated_at_ms
             ) VALUES ('test:archive', ?1, 'session.close', 1, 1, 'rejected', ?2, 10000, 1000, 1000)",
            rusqlite::params![[5_u8; 16].as_slice(), [5_u8; 32].as_slice()],
        )
        .expect("the earlier build's receipt");
}

#[test]
fn a_closed_sessions_journal_older_than_the_ladder_is_refused_by_name_rather_than_brought_forward()
{
    // KR-REQ-24.30. The archive brings a journal inside the ladder forward on its own; one older
    // than the ladder it neither migrates nor reads in part. It says so, naming the command that
    // imports it, and leaves the store where it was.
    let (_temp, archive) = host();
    let session_id = session();
    write_version_one_journal(&archive, session_id);
    let read = archive.archive(session_id).expect("reads the archive");
    assert!(
        read.incompleteness.iter().any(|missing| matches!(
            missing,
            Incompleteness::JournalUnreadable { detail } if detail.contains("kr host import-journals")
        )),
        "the refusal names the importer: {:?}",
        read.incompleteness
    );
    assert_eq!(
        Journal::recorded_schema_version(archive.paths().journal_database(session_id))
            .expect("reads the version"),
        1,
        "nothing brought it forward behind the person's back"
    );
}

#[test]
fn the_importer_brings_a_closed_sessions_version_one_journal_forward_once() {
    // The explicit import, run as `kr host import-journals` runs it: every journal older than the
    // ladder is brought to the current version once, what is left of a worker whose end is
    // confirmed is fenced first, a journal already inside the ladder is left alone, and the
    // archive then reads the imported one.
    use kr_controller::archive::ImportOutcome;
    let (_temp, archive) = host();
    drop(registry(&archive));
    let old = session();
    write_version_one_journal(&archive, old);
    let ended = kr_ipc::identity::ended_process_identity(1);
    publish_descriptor(&archive, old, &ended);
    let current = session();
    {
        let mut journal = journal_for(&archive, current);
        journal
            .record_session(&summary(current))
            .expect("records the summary");
    }

    let imported = archive.import_journals().expect("imports");
    let outcome_of = |session_id: SessionId| {
        imported
            .iter()
            .find(|done| done.session_id == session_id)
            .map(|done| done.outcome.clone())
            .expect("the session is reported")
    };
    assert_eq!(
        outcome_of(old),
        ImportOutcome::Imported {
            from: 1,
            to: kr_worker::persistence::migration::CURRENT,
            receipts: 1,
        }
    );
    assert_eq!(
        outcome_of(current),
        ImportOutcome::Untouched {
            version: kr_worker::persistence::migration::CURRENT
        }
    );
    assert!(
        !archive.paths().descriptor_file(old).exists(),
        "the ended worker's descriptor was fenced before the journal was opened"
    );
    let read = archive.archive(old).expect("reads the archive");
    assert_eq!(read.receipts, 1, "the receipt was kept");
    assert!(
        !read
            .incompleteness
            .iter()
            .any(|missing| matches!(missing, Incompleteness::JournalUnreadable { .. })),
        "{:?}",
        read.incompleteness
    );
    assert_eq!(
        archive
            .import_journals()
            .expect("imports")
            .into_iter()
            .find(|done| done.session_id == old)
            .map(|done| done.outcome),
        Some(ImportOutcome::Untouched {
            version: kr_worker::persistence::migration::CURRENT
        }),
        "a second run finds nothing to import"
    );
}

#[test]
fn a_journal_a_worker_may_still_own_is_not_imported() {
    // A worker can outlive its daemon. Each of the three things that can say a worker may still
    // be there - its published descriptor, the registry's worker row, and a closure that never
    // confirmed its end - keeps the journal from being opened, and the store stays at version 1.
    use kr_controller::archive::ImportOutcome;
    let (_temp, archive) = host();
    let alive = kr_ipc::identity::current_process_start_identity().expect("an identity");

    let described = session();
    write_version_one_journal(&archive, described);
    publish_descriptor(&archive, described, &alive);

    let unconfirmed = session();
    write_version_one_journal(&archive, unconfirmed);
    {
        let mut registry = registry(&archive);
        let mut record = closure(unconfirmed, ClosureReason::WorkerCrash);
        record.surviving = vec![SurvivingResource {
            kind: "unaccounted_worker".to_owned(),
            detail: "its end was never confirmed".to_owned(),
        }];
        registry
            .record_closure(&record)
            .expect("records the closure");
    }

    let imported = archive.import_journals().expect("imports");
    for session_id in [described, unconfirmed] {
        let outcome = imported
            .iter()
            .find(|done| done.session_id == session_id)
            .map(|done| done.outcome.clone())
            .expect("the session is reported");
        assert!(
            matches!(outcome, ImportOutcome::Refused { .. }),
            "{session_id}: {outcome:?}"
        );
        assert_eq!(
            Journal::recorded_schema_version(archive.paths().journal_database(session_id))
                .expect("reads the version"),
            1,
            "a journal a worker may still own is left alone"
        );
    }
}

/// What the import did with one session's journal.
fn outcome_of(
    imported: &[kr_controller::archive::JournalImport],
    session_id: SessionId,
) -> kr_controller::archive::ImportOutcome {
    imported
        .iter()
        .find(|done| done.session_id == session_id)
        .map(|done| done.outcome.clone())
        .expect("the session is reported")
}

/// Asserts that a journal was refused because a worker may still own it, for a reason that says
/// `why`, and that it is still at version 1.
#[track_caller]
fn refused_as_owned(
    archive: &ArchiveService,
    outcome: &kr_controller::archive::ImportOutcome,
    session_id: SessionId,
    why: &str,
) {
    use kr_controller::archive::{ImportOutcome, RefusalCause};
    match outcome {
        ImportOutcome::Refused {
            cause: RefusalCause::WorkerMayRemain,
            reason,
        } => assert!(reason.contains(why), "the refusal says {why:?}: {reason}"),
        other => panic!("{session_id} was not refused as a worker's: {other:?}"),
    }
    assert_eq!(
        Journal::recorded_schema_version(archive.paths().journal_database(session_id))
            .expect("reads the version"),
        1,
        "the journal is left as it was"
    );
}

#[test]
fn a_registry_that_lost_a_table_it_is_asked_is_not_read_as_recording_no_worker() {
    // The registry's worker rows and its closures are two of the three things that say whether a
    // worker may still hold a journal. A registry that lost either table would read as saying
    // there is no worker at all, so the import reads the registry as it is, repairs nothing in it,
    // and refuses what it cannot ask.
    for table in ["workers", "tombstones"] {
        let (_temp, archive) = host();
        drop(registry(&archive));
        rusqlite::Connection::open(archive.paths().registry_database())
            .expect("a second connection")
            .execute_batch(&format!("DROP TABLE {table};"))
            .expect("the table goes");
        let session_id = session();
        write_version_one_journal(&archive, session_id);
        let imported = archive
            .import_journals()
            .expect("the environment is walked");
        refused_as_owned(
            &archive,
            &outcome_of(&imported, session_id),
            session_id,
            table,
        );
        let recreated: i64 = rusqlite::Connection::open(archive.paths().registry_database())
            .expect("a second connection")
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .expect("reads the schema");
        assert_eq!(
            recreated, 0,
            "the import did not make a new, empty {table} table"
        );
    }
}

#[test]
fn a_registry_of_another_schema_version_is_not_read() {
    // A registry this build would have to bring forward, or could not read, is not evidence this
    // build can weigh, so nothing below the ladder is imported against it.
    let (_temp, archive) = host();
    drop(registry(&archive));
    rusqlite::Connection::open(archive.paths().registry_database())
        .expect("a second connection")
        .execute(
            "UPDATE schema_version SET version = ?1",
            [kr_controller::registry::SCHEMA_VERSION + 1],
        )
        .expect("the version moves");
    let session_id = session();
    write_version_one_journal(&archive, session_id);
    let imported = archive
        .import_journals()
        .expect("the environment is walked");
    refused_as_owned(
        &archive,
        &outcome_of(&imported, session_id),
        session_id,
        "schema version",
    );
}

#[test]
fn an_environment_without_a_registry_imports_nothing_below_the_ladder() {
    // A journal is only ever written under a daemon, and a daemon keeps a registry. One that has
    // gone took with it what would say whether a worker may still be there.
    let (_temp, archive) = host();
    let old = session();
    write_version_one_journal(&archive, old);
    let current = session();
    {
        let mut journal = journal_for(&archive, current);
        journal
            .record_session(&summary(current))
            .expect("records the summary");
    }
    let imported = archive
        .import_journals()
        .expect("the environment is walked");
    refused_as_owned(&archive, &outcome_of(&imported, old), old, "no registry");
    assert_eq!(
        outcome_of(&imported, current),
        kr_controller::archive::ImportOutcome::Untouched {
            version: kr_worker::persistence::migration::CURRENT
        },
        "a journal inside the ladder needs no registry to be left alone"
    );
    assert!(
        !archive.paths().registry_database().exists(),
        "the import made no registry"
    );
}

#[test]
fn a_live_worker_recorded_only_in_the_registry_keeps_its_journal() {
    // No descriptor and no closure: the registry's worker row alone names a process the kernel
    // says is running.
    let (_temp, archive) = host();
    let session_id = session();
    write_version_one_journal(&archive, session_id);
    registry(&archive)
        .adopt_worker(
            &kr_controller::registry::WorkerRecord {
                session_id,
                display_number: DisplayNumber::new(1),
                public_key: kr_protocol::scalars::AuthorisationKey::from_bytes([7; 32]),
                process_identity: kr_ipc::identity::current_process_start_identity()
                    .expect("an identity"),
                endpoint: "/tmp/kr-archive-test.sock".to_owned(),
                profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                state: kr_protocol::session::SessionState::Live,
                acknowledged_revision: kr_protocol::ids::AuthorityRevision::new(0),
            },
            // A headless worker is bound to no desktop.
            Some(&kr_protocol::identity::DesktopBinding::none()),
        )
        .expect("records the worker");
    let imported = archive
        .import_journals()
        .expect("the environment is walked");
    refused_as_owned(
        &archive,
        &outcome_of(&imported, session_id),
        session_id,
        "registry names its worker",
    );
}

/// Sets a directory's mode for as long as it lives, and gives it back its owner's full access.
#[cfg(unix)]
struct Mode(std::path::PathBuf);

/// The directory that holds one path a fence removes.
#[cfg(unix)]
type HeldBy = fn(&ArchiveService) -> std::path::PathBuf;

#[cfg(unix)]
impl Mode {
    fn read_only(path: std::path::PathBuf) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500))
            .expect("the directory is made read-only");
        Self(path)
    }
}

#[cfg(unix)]
impl Drop for Mode {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
    }
}

#[cfg(unix)]
#[test]
fn what_is_left_of_an_ended_worker_that_cannot_be_removed_stops_the_import() {
    // Death is confirmed, so the endpoint and then the descriptor are removed before the journal
    // is opened. A path that is already gone is fenced; one that is still there after the attempt
    // is not, and the journal is left alone rather than opened beside it. The descriptor is the
    // evidence the next import reads, so it stays until the endpoint has gone: an import run again
    // while the removal is still impossible is refused again, rather than finding nothing to
    // fence.
    use kr_controller::archive::{ImportOutcome, RefusalCause};
    let ended = kr_ipc::identity::ended_process_identity(1);
    let held_by: [(&str, HeldBy); 2] = [
        ("the descriptor", |archive| {
            archive.paths().descriptors_dir()
        }),
        ("the endpoint", |archive| {
            archive.paths().runtime_dir().to_path_buf()
        }),
    ];
    for (held, directory) in held_by {
        let (_temp, archive) = host();
        drop(registry(&archive));
        let session_id = session();
        write_version_one_journal(&archive, session_id);
        publish_descriptor(&archive, session_id, &ended);
        let endpoint = archive
            .paths()
            .worker_endpoint(DisplayNumber::new(1))
            .expect("an endpoint");
        std::fs::write(endpoint.as_path(), b"a socket").expect("the endpoint's file");
        let imported = {
            let _held = Mode::read_only(directory(&archive));
            [
                archive
                    .import_journals()
                    .expect("the environment is walked"),
                archive
                    .import_journals()
                    .expect("the environment is walked again"),
            ]
        };
        for (run, imported) in imported.iter().enumerate() {
            match outcome_of(imported, session_id) {
                ImportOutcome::Refused {
                    cause: RefusalCause::NotFenced,
                    ..
                } => {}
                other => panic!("{held} could not be removed, and import {run} went on: {other:?}"),
            }
        }
        assert!(
            archive.paths().descriptor_file(session_id).exists(),
            "the descriptor stays while what it names is still there"
        );
        assert_eq!(
            Journal::recorded_schema_version(archive.paths().journal_database(session_id))
                .expect("reads the version"),
            1,
            "the journal is left as it was"
        );
    }
}

/// A question answered by `device:phone`, with text where content is kept.
fn answered_question() -> kr_protocol::question::Question {
    use kr_protocol::ids::{ApplicationInstanceId, ConnectionId, QuestionId, QuestionRevision};
    use kr_protocol::question::{
        AnswerRecord, QuestionAnswer, QuestionKind, QuestionSource, QuestionState,
    };
    use kr_protocol::scalars::Uuid;

    kr_protocol::question::Question {
        question_id: QuestionId::new(Uuid::from_bytes([1; 16])),
        revision: QuestionRevision::new(2),
        state: QuestionState::Answered,
        session_id: SessionId::new(Uuid::from_bytes([2; 16])),
        session_epoch: SessionEpoch::V1,
        kind: QuestionKind::Confirm,
        context: "Two tests are failing.".to_owned(),
        question: "Push the branch anyway?".to_owned(),
        choices: Vec::new(),
        source: QuestionSource {
            application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([3; 16])),
            process: kr_protocol::identity::ProcessStartIdentity::new(
                7,
                kr_protocol::identity::ProcessStartSource::LinuxProcStat,
                11,
            ),
            executable: Nullable::null(),
            agent_label: Nullable::some("the release agent".to_owned()),
            connection_id: ConnectionId::new(Uuid::from_bytes([4; 16])),
            launch_channel: false,
            session_member: true,
            ancestry: true,
            agent_binding_revision: Nullable::null(),
        },
        created_at_ms: TimestampMs::new(1_000),
        expires_at_ms: TimestampMs::new(61_000),
        answer: Nullable::some(AnswerRecord {
            answer: QuestionAnswer::Decision { decided: true },
            actor_id: ActorId::new("test:archive").expect("an actor"),
            device_id: Nullable::null(),
            question_revision: QuestionRevision::new(1),
            answered_at_ms: TimestampMs::new(1_001),
        }),
        resolved_at_ms: Nullable::some(TimestampMs::new(1_001)),
    }
}

/// Settles the action `byte` of a session's journal as applied, with `result` kept for it.
fn settled_with(
    archive: &ArchiveService,
    session_id: SessionId,
    byte: u8,
    method: kr_protocol::method::Method,
    result: &kr_protocol::envelope::ParamsValue,
) {
    let mut journal = journal_for(archive, session_id);
    let mut accepted = submission(byte);
    accepted.method = method.into();
    journal.accept(&accepted).expect("an accepted intent");
    let actor = accepted.actor_id.clone();
    let action = accepted.action_id;
    journal
        .mark_dispatching(actor.clone(), action, kr_ipc::now_ms())
        .expect("a dispatch marker");
    journal
        .settle(
            actor,
            action,
            kr_protocol::receipt::ReceiptState::Applied,
            Some(&kr_cbor::encode(result.as_value())),
            None,
            kr_ipc::now_ms(),
        )
        .expect("settles");
}

/// KR-REQ-10.49 and KR-REQ-23.34: the archive shows a closed session's receipts as their reader may
/// see them. The owner at this machine reads a retained question and a close's description whole.
/// Any other reader is told the state of the action: the question's text, its choices, who asked
/// and what was answered are withheld, the description of the session goes, and a receipt's error
/// text is replaced. What is kept is not changed by either read.
#[test]
fn kr_req_10_49_a_closed_sessions_receipts_are_shown_whole_to_the_owner_and_as_state_to_anybody_else()
 {
    use kr_protocol::envelope::ParamsValue;
    use kr_protocol::method::Method;

    let (_temp, archive) = host();
    let session_id = session();
    let actor = ActorId::new("test:archive").expect("an actor");

    let resolution = kr_worker::questions::Resolution {
        question: answered_question(),
    };
    settled_with(
        &archive,
        session_id,
        1,
        Method::QuestionAnswer,
        &ParamsValue::from_typed(&resolution).expect("encodes"),
    );
    let closed = kr_protocol::session::SessionCloseResult {
        session_id,
        state: kr_protocol::session::SessionState::Closed,
        durability: Durability::Durable,
        closure: Nullable::null(),
        session: Some(summary(session_id)),
    };
    settled_with(
        &archive,
        session_id,
        2,
        Method::SessionClose,
        &ParamsValue::from_typed(&closed).expect("encodes"),
    );
    {
        let mut journal = journal_for(&archive, session_id);
        journal.accept(&submission(3)).expect("an accepted intent");
        journal
            .reject(
                actor.clone(),
                kr_worker::journal::action_id_from([3; 16]),
                kr_protocol::receipt::RejectionReason::StalePreconditions,
                Some(kr_protocol::error::ProtocolError::new(
                    kr_protocol::error::ErrorCode::PermissionDenied,
                    "the agent quoted /home/person/notes",
                )),
                kr_ipc::now_ms(),
            )
            .expect("rejects");
    }
    let read = |byte: u8, owner: bool| {
        archive
            .receipt(
                session_id,
                &actor,
                kr_worker::journal::action_id_from([byte; 16]),
                owner,
            )
            .expect("reads the receipt")
    };

    // The question.
    let owner = read(1, true);
    let shown: kr_protocol::question::QuestionResolveResult = owner
        .result
        .as_ref()
        .expect("a result")
        .to_typed()
        .expect("a resolution result");
    assert_eq!(shown.question(), Some(&answered_question()));
    let other = read(1, false);
    let withheld: kr_protocol::question::QuestionResolveResult = other
        .result
        .as_ref()
        .expect("a result")
        .to_typed()
        .expect("a resolution result");
    assert_eq!(withheld.question(), None);
    assert_eq!(
        withheld.state,
        kr_protocol::question::QuestionState::Answered
    );
    let text = serde_json::to_string(&other).expect("encodes");
    for content in [
        "Push the branch anyway?",
        "Two tests are failing.",
        "the release agent",
    ] {
        assert!(!text.contains(content), "{content:?} in {text}");
    }

    // The close's description.
    let described = |read: &kr_protocol::receipt::ActionReadResult| {
        kr_worker::history_filter::retained::member(
            read.result.as_ref().expect("a result"),
            "session",
        )
        .is_some()
    };
    assert!(described(&read(2, true)), "the owner reads the description");
    assert!(!described(&read(2, false)), "nobody else does");

    // The error text of a refused action.
    let own = read(3, true);
    assert!(!own.receipt.error_withheld);
    assert!(
        own.receipt
            .error
            .as_ref()
            .expect("an error")
            .message
            .contains("/home/person/notes")
    );
    let theirs = read(3, false);
    assert!(theirs.receipt.error_withheld);
    let error = theirs.receipt.error.as_ref().expect("an error");
    assert_eq!(error.code, kr_protocol::error::ErrorCode::PermissionDenied);
    assert!(!error.message.contains("/home/person/notes"));

    // What the journal keeps is the bytes it kept.
    let kept = Journal::open_read_only(archive.paths().journal_database(session_id))
        .expect("opens")
        .read_result(&actor, kr_worker::journal::action_id_from([1; 16]))
        .expect("reads")
        .expect("a result is kept");
    let kept: kr_worker::questions::Resolution =
        kr_cbor::from_canonical_slice(&kept, &kr_cbor::Limits::DEFAULT).expect("the stored form");
    assert_eq!(kept, resolution);
}
