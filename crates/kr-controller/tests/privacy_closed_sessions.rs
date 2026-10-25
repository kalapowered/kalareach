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

/// A closed session as its worker left it: a journal that holds the summary, the closure and one
/// settled receipt with a result, and, with `spool`, sixteen bytes of retained output.
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
    Submission {
        actor_id: actor(),
        action_id: kr_worker::journal::action_id_from([7; 16]),
        method: Method::SessionClose.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        payload_digest: kr_protocol::scalars::Digest256::from_bytes([7; 32]),
        subject_digest: kr_protocol::scalars::Digest256::from_bytes([7; 32]),
        intent: vec![0xa0],
        accepted_deadline_ms: Some(TimestampMs::new(kr_ipc::now_ms().get() + 120_000)),
        now_ms: kr_ipc::now_ms(),
    }
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
