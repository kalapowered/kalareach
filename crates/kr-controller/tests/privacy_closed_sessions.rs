//! Privacy mode and a session whose worker has ended.
//!
//! A live session's worker removes its own retained output and receipt content when it is told
//! privacy mode is on. A session that has closed has no worker to tell, so what it kept is the
//! archive's to remove, and the daemon serves none of it while that is owed. One real daemon on the
//! loopback network, and closed sessions planted where a worker leaves them: a journal, with
//! receipts, and a spool. `privacy.set` and the reads reach the daemon on its local socket, and
//! what each test asserts is read back from the daemon's answers and from the files.

#![cfg(unix)]

mod net_support;

use std::path::PathBuf;
use std::time::Duration;

use kr_controller::archive::ArchiveService;
use kr_ipc::client::LocalClient;
use kr_protocol::attention::{AttentionReadParams, AttentionReadResult, AttentionRule};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, ActorId, SessionEpoch, SessionId};
use kr_protocol::method::Method;
use kr_protocol::privacy::{
    PrivacyCompletion, PrivacyReport, PrivacySessionStanding, PrivacySetParams, PrivacyStatusParams,
};
use kr_protocol::receipt::{ActionReadParams, ActionReadResult, ReceiptState};
use kr_protocol::recovery::{HistoryPageParams, HistoryPageResult};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};
use kr_protocol::session::{
    ClosureReason, ClosureRecord, DisplayNumber, Durability, OwnershipCoverage,
};
use kr_worker::journal::{Journal, Submission};

use net_support::Host;

/// How long a test waits for the daemon's own pass, which fails it and never decides it.
const PATIENCE: Duration = Duration::from_secs(60);

/// The output every planted session retained.
const OUTPUT: &[u8] = b"0123456789abcdef";

/// What the settled receipt kept as its result, as a CBOR text string.
const RESULT: &[u8] = b"\x6eprivate result";

/// The actor the daemon names a caller on its own socket: this user. A receipt is read by the actor
/// that holds it, so the planted receipt is this user's.
fn actor() -> ActorId {
    kr_protocol::sharing::local_actor(u64::from(rustix::process::getuid().as_raw()))
}

/// A closed session as its worker left it: a journal that holds the summary, the closure, one
/// settled receipt with a result and two that had not settled when the worker ended (one accepted
/// and never dispatched, one dispatched with no outcome recorded), and, with `spool`, sixteen bytes
/// of retained output.
fn plant(host: &Host, spool: bool) -> SessionId {
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let archive = ArchiveService::new(host.tree().environment());
    let path = archive.paths().journal_database(session_id);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the journal directory");
    {
        let mut journal = Journal::open(&path).expect("opens the journal");
        journal
            .record_session(&summary(session_id))
            .expect("records the summary");
        journal
            .record_closure(&closure(session_id))
            .expect("records the closure");
        let submission = submission();
        journal.accept(&submission).expect("a receipt");
        journal
            .mark_dispatching(actor(), submission.action_id, kr_ipc::now_ms())
            .expect("the dispatch is marked");
        journal
            .settle(
                actor(),
                submission.action_id,
                ReceiptState::Applied,
                Some(RESULT),
                None,
                kr_ipc::now_ms(),
            )
            .expect("the receipt settles with a result");
        let never_dispatched = submission_numbered(8);
        journal.accept(&never_dispatched).expect("a receipt");
        let no_outcome = submission_numbered(9);
        journal.accept(&no_outcome).expect("a receipt");
        journal
            .mark_dispatching(actor(), no_outcome.action_id, kr_ipc::now_ms())
            .expect("the dispatch is marked");
    }
    if spool {
        let mut history = kr_worker::history::OutputHistory::with_spool(
            8,
            archive.paths().session_spool(session_id),
            kr_worker::history::SpoolLayout::new(8, 1 << 20),
        )
        .expect("a spool");
        history.append(OUTPUT);
    }
    session_id
}

/// A notice the session's program raised while no attachment held the lease, which its worker
/// kept in the journal `plant` made as a host event, and that the closure the daemon then records
/// leaves in the inbox.
fn plant_notice(host: &Host, session_id: SessionId, body: &str) {
    let path = ArchiveService::new(host.tree().environment())
        .paths()
        .journal_database(session_id);
    let mut journal = Journal::open(&path).expect("opens the journal");
    journal
        .record_host_event(
            &kr_term::sideeffect::SideEffect {
                kind: kr_term::sideeffect::SideEffectKind::Notification {
                    title: None,
                    body: body.to_owned(),
                    id: None,
                    urgency: kr_term::sideeffect::NotificationUrgency::Normal,
                    display: kr_term::sideeffect::NotificationDisplay::Always,
                },
                destination: kr_term::sideeffect::SideEffectDestination::HostEvent,
                at: 0,
            },
            kr_ipc::now_ms(),
        )
        .expect("the journal records the notice");
}

/// A closed session as a daemon records the end of a worker it could not see leave: a reservation
/// that closed and the closure the registry holds, with sixteen bytes of retained output in its
/// spool and no journal, since the worker never wrote one.
///
/// With `unconfirmed`, the closure says the daemon closed the session without confirming that its
/// worker ended, and `launched` is the process the reservation names for the launch, if any.
fn plant_recorded(
    host: &Host,
    unconfirmed: bool,
    launched: Option<&kr_protocol::identity::ProcessStartIdentity>,
) -> SessionId {
    use kr_controller::registry::{LaunchPhase, Registry};
    use kr_protocol::scalars::Digest256;
    use kr_protocol::session::SurvivingResource;

    let mut registry =
        Registry::open(host.registry_database(), host.environment_id).expect("opens the registry");
    let admission = registry
        .reserve(
            &actor(),
            kr_ipc::new_uuid(),
            Digest256::from_bytes([1; 32]),
            &[0xa0],
            TimestampMs::new(1),
        )
        .expect("a reservation");
    let session_id = admission.reservation.session_id;
    if let Some(identity) = launched {
        registry
            .record_launch(admission.reservation.reservation_id, identity)
            .expect("the launch's process");
    }
    registry
        .set_phase(admission.reservation.reservation_id, LaunchPhase::Closed)
        .expect("the session closes");
    let mut record = closure(session_id);
    if unconfirmed {
        record.surviving = vec![SurvivingResource {
            kind: kr_controller::archive::UNACCOUNTED_WORKER.to_owned(),
            detail: "this host closed the session without confirming that its worker ended"
                .to_owned(),
        }];
    }
    registry.record_closure(&record).expect("the closure");
    let mut history = kr_worker::history::OutputHistory::with_spool(
        8,
        ArchiveService::new(host.tree().environment())
            .paths()
            .session_spool(session_id),
        kr_worker::history::SpoolLayout::new(8, 1 << 20),
    )
    .expect("a spool");
    history.append(OUTPUT);
    session_id
}

fn closure(session_id: SessionId) -> ClosureRecord {
    ClosureRecord {
        session_id,
        session_epoch: SessionEpoch::V1,
        reason: ClosureReason::CloseRequested,
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
        attachment_count: U64::new(0),
        application_state: Nullable::null(),
        root_process: Nullable::null(),
        closure: Nullable::null(),
        environment_sources: None,
        root: None,
        application: None,
    }
}

fn submission() -> Submission {
    submission_numbered(7)
}

fn submission_numbered(number: u8) -> Submission {
    Submission {
        actor_id: actor(),
        action_id: kr_worker::journal::action_id_from([number; 16]),
        method: Method::SessionClose.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        payload_digest: kr_protocol::scalars::Digest256::from_bytes([number; 32]),
        subject_digest: kr_protocol::scalars::Digest256::from_bytes([number; 32]),
        intent: vec![0xa0],
        accepted_deadline_ms: Some(TimestampMs::new(kr_ipc::now_ms().get() + 120_000)),
        now_ms: kr_ipc::now_ms(),
    }
}

/// What a session's journal holds of its receipts: how many still carry the intent the caller sent,
/// and how many have not settled.
fn receipts_holding(host: &Host, session_id: SessionId) -> (i64, i64) {
    let path = ArchiveService::new(host.tree().environment())
        .paths()
        .journal_database(session_id);
    let journal = rusqlite::Connection::open(path).expect("the journal");
    let count = |query: &str| {
        journal
            .query_row(query, [], |row| row.get::<_, i64>(0))
            .expect("a count")
    };
    (
        count("SELECT COUNT(*) FROM receipts WHERE intent IS NOT NULL"),
        count("SELECT COUNT(*) FROM receipts WHERE state IN ('accepted', 'dispatching')"),
    )
}

/// The segments a session's spool holds.
fn segments(host: &Host, session_id: SessionId) -> Vec<PathBuf> {
    let directory = host.tree().environment().session_spool(session_id);
    std::fs::read_dir(directory)
        .map(|entries| {
            entries
                .filter_map(std::result::Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|extension| extension == "out"))
                .collect()
        })
        .unwrap_or_default()
}

async fn set(client: &mut LocalClient, host: &Host, enabled: bool) -> PrivacyReport {
    client
        .mutate(
            Method::PrivacySet,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &PrivacySetParams { enabled },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("privacy mode changes")
        .to_typed()
        .expect("decodes")
}

async fn status(client: &mut LocalClient) -> PrivacyReport {
    client
        .request(Method::PrivacyStatus, &PrivacyStatusParams {})
        .await
        .expect("the call reaches the daemon")
        .expect("privacy.status is served")
        .to_typed()
        .expect("decodes")
}

/// Waits until the daemon's report satisfies `holds`, and fails the test when it has not within
/// the patience.
async fn until(
    what: &str,
    client: &mut LocalClient,
    holds: impl Fn(&PrivacyReport) -> bool,
) -> PrivacyReport {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        let report = status(client).await;
        if holds(&report) {
            return report;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} did not happen in time: {report:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// What the owner's inbox shows of the session's notice: the words of its summary, and none when
/// the item is there without them. The inbox is read until the daemon has the notice, which it
/// reads from the journal once the session's closure is recorded.
async fn notice_words(client: &mut LocalClient, session_id: SessionId) -> Option<String> {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        let read: AttentionReadResult = client
            .request(
                Method::AttentionRead,
                &AttentionReadParams {
                    session_id: Nullable::null(),
                    include_acknowledged: true,
                    max_items: U64::new(50),
                    after: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the inbox reads")
            .to_typed()
            .expect("decodes");
        if let Some(notice) = read.items.iter().find(|item| {
            item.rule == AttentionRule::ApplicationNotice
                && item.session_id == Nullable::some(session_id)
        }) {
            return notice.summary.0.clone();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the notice did not reach the inbox: {:?}",
            read.items
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn page(
    client: &mut LocalClient,
    session_id: SessionId,
) -> std::result::Result<HistoryPageResult, kr_protocol::error::ProtocolError> {
    client
        .request(
            Method::HistoryPage,
            &HistoryPageParams {
                session_id,
                from_cursor: U64::new(0),
                max_bytes: U64::new(1 << 20),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .map(|value| value.to_typed().expect("decodes"))
}

async fn receipt(
    client: &mut LocalClient,
    session_id: SessionId,
) -> std::result::Result<ActionReadResult, kr_protocol::error::ProtocolError> {
    client
        .request(
            Method::ActionRead,
            &ActionReadParams {
                action_id: kr_worker::journal::action_id_from([7; 16]),
                session_id: Some(session_id),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .map(|value| value.to_typed().expect("decodes"))
}

/// KR-REQ-24.27 and KR-REQ-24.28: turning privacy mode on removes what a closed session retained,
/// and the change then reports complete. The archive takes the session's recovery ownership and
/// removes its output and its settled receipts' content; the receipt keeps its identity and state,
/// a reader of the output is told the range is gone and where the output had reached, and
/// disabling privacy mode brings nothing back. The control is the same reads before privacy mode,
/// which serve the output and the receipt's result. A session with a journal and no spool is
/// settled as well.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn turning_privacy_mode_on_removes_what_a_closed_session_retained() {
    let host = Host::start_unowned().await;
    let mut client = host.client().await;
    let with_output = plant(&host, true);
    let journal_only = plant(&host, false);

    let before = page(&mut client, with_output).await.expect("a page");
    assert_eq!(
        before.bytes.as_slice(),
        OUTPUT,
        "the control serves the output"
    );
    assert!(
        receipt(&mut client, with_output)
            .await
            .expect("a receipt")
            .result
            .0
            .is_some(),
        "and the receipt's result"
    );
    assert!(!segments(&host, with_output).is_empty());
    assert_eq!(
        receipts_holding(&host, with_output),
        (3, 2),
        "the control: every receipt carries its intent, and two have not settled"
    );

    let report = set(&mut client, &host, true).await;
    assert!(report.enabled);
    let report = until("the change taking effect", &mut client, |report| {
        matches!(report.completion, PrivacyCompletion::Complete)
    })
    .await;
    assert!(
        report.sessions.is_empty(),
        "nothing is owed once the archive has removed what the sessions retained: {:?}",
        report.sessions
    );

    assert!(
        segments(&host, with_output).is_empty(),
        "the output is gone"
    );
    for session_id in [with_output, journal_only] {
        let read = receipt(&mut client, session_id).await.expect("a receipt");
        assert_eq!(read.receipt.state, ReceiptState::Applied, "its state stays");
        assert!(read.result.0.is_none(), "and its result is gone");
        assert_eq!(
            receipts_holding(&host, session_id),
            (0, 0),
            "no worker is left to retry an action that had not settled, so recovery settles it and \
             no receipt keeps the intent the caller sent"
        );
    }
    let after = page(&mut client, with_output).await.expect("a page");
    assert!(after.bytes.as_slice().is_empty(), "no byte is served");
    assert_eq!(
        after.next_cursor.get(),
        OUTPUT.len() as u64,
        "the output is still said to have reached its end"
    );
    assert!(after.gap.0.is_some(), "and the range is said to be gone");

    let off = set(&mut client, &host, false).await;
    assert!(!off.enabled);
    let again = page(&mut client, with_output).await.expect("a page");
    assert!(
        again.bytes.as_slice().is_empty(),
        "turning privacy mode off brings nothing back"
    );
    host.stop().await;
}

/// KR-REQ-24.28: a removal the archive cannot finish is owed and reported with the reason, what the
/// session retained is not served while it is owed, the obligation survives a restart of the
/// daemon, and the change reports complete once the removal finishes. A directory stands where the
/// oldest segment's file was, so no platform removes it as one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_the_archive_cannot_finish_is_owed_and_not_served_until_it_has() {
    let host = Host::start_unowned().await;
    let mut client = host.client().await;
    let session_id = plant(&host, true);
    let oldest = host
        .tree()
        .environment()
        .session_spool(session_id)
        .join(format!("{:020}.out", 0));
    std::fs::remove_file(&oldest).expect("removes the oldest segment's file");
    std::fs::create_dir(&oldest).expect("puts a directory in its place");
    std::fs::write(oldest.join("in-the-way"), b"x").expect("and something in it");

    set(&mut client, &host, true).await;
    let report = until("the removal being refused", &mut client, |report| {
        report.sessions.iter().any(|owed| {
            owed.session_id == session_id
                && matches!(
                    &owed.standing,
                    PrivacySessionStanding::Unavailable { reason }
                        if reason.contains("could not be removed")
                )
        })
    })
    .await;
    assert!(!matches!(report.completion, PrivacyCompletion::Complete));
    for refused in [
        page(&mut client, session_id).await.err(),
        receipt(&mut client, session_id).await.err(),
    ] {
        assert_eq!(
            refused.expect("a read of what is owed is refused").code,
            ErrorCode::ResourceUnavailable
        );
    }

    // The daemon goes and another starts on the same tree: the obligation is on the disk. The
    // client is closed first, since the daemon is held by each connection it serves.
    drop(client);
    let host = host.restart().await;
    let mut client = host.client().await;
    let report = status(&mut client).await;
    assert!(
        report.enabled
            && report
                .sessions
                .iter()
                .any(|owed| owed.session_id == session_id),
        "{report:?}"
    );
    assert!(page(&mut client, session_id).await.is_err());

    std::fs::remove_dir_all(&oldest).expect("clears the way");
    until("the removal finishing", &mut client, |report| {
        matches!(report.completion, PrivacyCompletion::Complete)
    })
    .await;
    let page = page(&mut client, session_id).await.expect("a page");
    assert!(page.bytes.as_slice().is_empty());
    assert!(page.gap.0.is_some());
    host.stop().await;
}

/// KR-REQ-24.27 and KR-REQ-24.28: a session whose worker left no journal, and whose end only the
/// registry records, is settled as well. Its output is removed, a reader is told the range is gone,
/// and the change reports complete; the control is the same read before privacy mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn turning_privacy_mode_on_removes_what_a_session_only_the_registry_closed_retained() {
    let host = Host::start_unowned().await;
    let mut client = host.client().await;
    let session_id = plant_recorded(&host, false, None);

    let before = page(&mut client, session_id).await.expect("a page");
    assert_eq!(
        before.bytes.as_slice(),
        OUTPUT,
        "the control serves the output"
    );
    assert!(!segments(&host, session_id).is_empty());

    set(&mut client, &host, true).await;
    let report = until("the change taking effect", &mut client, |report| {
        matches!(report.completion, PrivacyCompletion::Complete)
    })
    .await;
    assert!(
        report.sessions.is_empty(),
        "nothing is owed once the archive has removed what the session retained: {:?}",
        report.sessions
    );
    assert!(segments(&host, session_id).is_empty(), "the output is gone");
    let after = page(&mut client, session_id).await.expect("a page");
    assert!(after.bytes.as_slice().is_empty(), "no byte is served");
    assert!(after.gap.0.is_some(), "and the range is said to be gone");
    host.stop().await;
}

/// KR-REQ-24.27 and KR-REQ-24.28: a session whose worker's end the daemon never confirmed keeps its
/// output while nothing proves the worker gone, and is settled once the kernel says the process the
/// launch ran has ended. The first session names no process, so a worker may still be writing its
/// stores: its output stays, and the report says why. The second names a process that has ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unconfirmed_worker_is_cleared_by_the_proof_that_its_process_ended() {
    let host = Host::start_unowned().await;
    let mut client = host.client().await;
    let ended = kr_ipc::identity::ended_process_identity(4_000_100);
    let unproved = plant_recorded(&host, true, None);
    let proved = plant_recorded(&host, true, Some(&ended));

    set(&mut client, &host, true).await;
    let report = until("the proved session being settled", &mut client, |report| {
        report.sessions.iter().all(|owed| owed.session_id != proved)
            && report
                .sessions
                .iter()
                .any(|owed| owed.session_id == unproved)
    })
    .await;
    assert!(
        segments(&host, proved).is_empty(),
        "the proved session's output is gone"
    );
    assert!(
        !segments(&host, unproved).is_empty(),
        "the control: output a worker may still write is not removed"
    );
    let owed = report
        .sessions
        .iter()
        .find(|owed| owed.session_id == unproved)
        .expect("the unproved session is owed");
    assert!(
        matches!(&owed.standing, PrivacySessionStanding::Unavailable { reason } if reason.contains("worker")),
        "the report says why: {owed:?}"
    );
    host.stop().await;
}

/// KR-REQ-24.27 and KR-REQ-24.28: a notice a closed session kept is not served once the archive has
/// removed what the session retained and the change reports complete, and turning privacy mode off
/// brings nothing back. The notice stays in the inbox, as one of a live session does, without its
/// words. The control is the same read before privacy mode, which shows them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_notice_a_closed_session_kept_is_not_served_once_its_removal_has_finished() {
    let host = Host::start_unowned().await;
    let mut client = host.client().await;
    let session_id = plant(&host, false);
    plant_notice(&host, session_id, "the build finished");
    host.controller()
        .retire(&closure(session_id))
        .await
        .expect("the closure is recorded");

    assert_eq!(
        notice_words(&mut client, session_id).await.as_deref(),
        Some("Normal: the build finished"),
        "the control serves the notice's words"
    );

    set(&mut client, &host, true).await;
    let report = until("the change taking effect", &mut client, |report| {
        matches!(report.completion, PrivacyCompletion::Complete)
    })
    .await;
    assert!(report.sessions.is_empty(), "{:?}", report.sessions);
    assert_eq!(
        notice_words(&mut client, session_id).await,
        None,
        "the removal is complete, so the session's notice is served without its words"
    );

    let off = set(&mut client, &host, false).await;
    assert!(!off.enabled);
    assert_eq!(
        notice_words(&mut client, session_id).await,
        None,
        "turning privacy mode off brings nothing back"
    );
    host.stop().await;
}

/// KR-REQ-24.28: a notice a closed session kept is not served while its removal is owed. A
/// directory stands where the oldest segment's file was, so the removal cannot finish, and the
/// inbox is read while the report says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_notice_a_closed_session_kept_is_not_served_while_its_removal_is_owed() {
    let host = Host::start_unowned().await;
    let mut client = host.client().await;
    let session_id = plant(&host, true);
    plant_notice(&host, session_id, "the build finished");
    let oldest = host
        .tree()
        .environment()
        .session_spool(session_id)
        .join(format!("{:020}.out", 0));
    std::fs::remove_file(&oldest).expect("removes the oldest segment's file");
    std::fs::create_dir(&oldest).expect("puts a directory in its place");
    std::fs::write(oldest.join("in-the-way"), b"x").expect("and something in it");
    host.controller()
        .retire(&closure(session_id))
        .await
        .expect("the closure is recorded");

    assert_eq!(
        notice_words(&mut client, session_id).await.as_deref(),
        Some("Normal: the build finished"),
        "the control serves the notice's words"
    );

    set(&mut client, &host, true).await;
    until("the removal being refused", &mut client, |report| {
        report.sessions.iter().any(|owed| {
            owed.session_id == session_id
                && matches!(
                    &owed.standing,
                    PrivacySessionStanding::Unavailable { reason }
                        if reason.contains("could not be removed")
                )
        })
    })
    .await;
    assert_eq!(
        notice_words(&mut client, session_id).await,
        None,
        "what the session retained is not served while its removal is owed"
    );
    host.stop().await;
}
