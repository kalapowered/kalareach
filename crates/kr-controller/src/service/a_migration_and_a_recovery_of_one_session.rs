//! A migration and a recovery of one session's journal, which the session's recovery lock keeps
//! apart.
//!
//! A store an earlier build wrote is brought forward by a write, and a closure is recorded from a
//! journal a recovery may be working on. Two writers on one store are what the lock is for, and
//! these cases run a real daemon over real stores to show that whichever holds it, the other is
//! told so and leaves the store as it is.

use kr_ipc::testing::TempHost;
use kr_protocol::ids::{SessionEpoch, SessionId};
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{
    ClosureReason, ClosureRecord, DisplayNumber, Durability, OwnershipCoverage, SessionState,
    SessionSummary,
};

use super::a_previous_boot_left_to_a_held_recovery::recorded_ended_worker;
use super::close::Watch;
use crate::archive::OwnershipRefusal;
use crate::service::Controller;
use crate::service::net::tests::daemon;

/// What a worker wrote of a session, with a directory no default would name.
pub(super) fn written(
    session_id: SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
) -> SessionSummary {
    SessionSummary {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        state: SessionState::Live,
        shell_mode: kr_protocol::session::ShellMode::NativeCompat,
        shell_path: "/bin/sh".to_owned(),
        cwd: RECOVERED.to_owned(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        desktop: kr_protocol::identity::DesktopBinding::none(),
        created_at_ms: kr_ipc::now_ms(),
        dimensions: kr_protocol::session::Dimensions::new(80, 24),
        attachment_count: kr_protocol::scalars::U64::new(1),
        application_state: Nullable::null(),
        root_process: Nullable::null(),
        closure: Nullable::null(),
        environment_sources: None,
        root: None,
        application: None,
    }
}

/// The directory a session's own journal names, which a summary built from the closure does not.
pub(super) const RECOVERED: &str = "/recovered";

pub(super) fn closure_of(session_id: SessionId) -> ClosureRecord {
    ClosureRecord {
        session_id,
        session_epoch: SessionEpoch::V1,
        reason: ClosureReason::CloseRequested,
        root_exit_code: Nullable::null(),
        root_signal: Nullable::null(),
        terminated: Vec::new(),
        surviving: Vec::new(),
        ownership_coverage: OwnershipCoverage::Complete,
        durability: Durability::Durable,
        closed_at_ms: kr_ipc::now_ms(),
    }
}

/// Writes a session's journal with its summary, and its own closure where `closure` is given.
pub(super) fn written_journal(
    controller: &Controller,
    session_id: SessionId,
    closure: Option<&ClosureRecord>,
) {
    let path = controller.paths().journal_database(session_id);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the journal directory");
    let mut journal = kr_worker::journal::Journal::open(&path).expect("opens");
    journal
        .record_session(&written(session_id, controller.paths().environment_id()))
        .expect("records the session");
    if let Some(closure) = closure {
        journal
            .record_closure(closure)
            .expect("records the closure");
    }
}

/// Puts a journal back to the schema an earlier build left: the version it recorded, and none of
/// the objects the steps after it added that migration does not create for itself. A migration
/// fixture rather than an exact copy of that build's store.
pub(super) fn put_back_to_an_earlier_schema(controller: &Controller, session_id: SessionId) {
    let path = controller.paths().journal_database(session_id);
    rusqlite::Connection::open(&path)
        .expect("opens the store")
        .execute_batch(
            "DROP TABLE privacy;
             DROP TABLE outbox;
             DROP TABLE outbox_cursors;
             DROP TABLE journal_gaps;
             UPDATE schema_version SET version = 3;",
        )
        .expect("puts it back to the earlier shape");
    assert_eq!(version_of(controller, session_id), 3);
}

/// Waits until the daemon's collection has ended its first pass, which starts with the daemon and
/// takes a closed session the registry holds no record of: it would migrate a journal a case has
/// just written, under an assertion about its version.
pub(super) async fn after_the_first_pass(controller: &Controller) {
    let mut passes = controller.collection().passes();
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        passes.wait_for(|ended| *ended >= 1),
    )
    .await
    .expect("the daemon's collection ran")
    .expect("the collection is still there");
}

/// How many times a case asks again for a migration that the daemon has put off.
const ASKS: usize = 10_000;

/// Asks again until `made` holds of the answer. The gate in front of a migration answers that a
/// worker may remain while another task of the daemon holds the registry, so one ask after an
/// explicit hold has ended can find the migration put off for that moment. The asks are bounded in
/// number and not in time, and yield between them.
pub(super) async fn until_made<T, Fut: std::future::Future<Output = T>>(
    mut ask: impl FnMut() -> Fut,
    made: impl Fn(&T) -> bool,
) -> T {
    let mut answer = ask().await;
    for _ in 0..ASKS {
        if made(&answer) {
            break;
        }
        tokio::task::yield_now().await;
        answer = ask().await;
    }
    answer
}

pub(super) fn version_of(controller: &Controller, session_id: SessionId) -> i64 {
    kr_worker::journal::Journal::recorded_schema_version(
        controller.paths().journal_database(session_id),
    )
    .expect("reads the version")
}

/// A closed session whose journal an earlier build wrote and whose closure the registry holds.
///
/// The closure is recorded in the registry alone, so that no closure tail runs and decides, on a
/// task of its own, when the journal is brought forward.
async fn closed_session_of_an_earlier_build(controller: &Controller) -> SessionId {
    let session_id = SessionId::new(kr_ipc::new_uuid());
    written_journal(controller, session_id, None);
    put_back_to_an_earlier_schema(controller, session_id);
    controller
        .registry
        .lock()
        .await
        .record_closure(&closure_of(session_id))
        .expect("the closure is recorded");
    session_id
}

/// KR-REQ-24.18: a migration is a write, and it is refused while a recovery holds the session. The
/// store is left as it is, and is brought forward once the recovery is done.
///
/// A safety claim (two writers on one store), so the second half is its control: with nothing
/// holding the session the same call migrates.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_migration_is_refused_while_a_recovery_holds_the_session() {
    let temp = TempHost::create();
    let controller = daemon(&temp).await;
    after_the_first_pass(&controller).await;
    let session_id = closed_session_of_an_earlier_build(&controller).await;
    let ended = kr_ipc::identity::ended_process_identity(4_000_011);
    let recovery = controller
        .archive()
        .take_ownership(session_id, DisplayNumber::new(1), &ended)
        .expect("a recovery holds the session");

    let held = controller
        .session_archive(session_id)
        .await
        .expect("the archive answers");
    assert_eq!(
        version_of(&controller, session_id),
        3,
        "a store another recovery holds is not migrated"
    );
    assert!(
        held.summary.is_none(),
        "and the answer does not carry what a migration would have read: {held:?}"
    );

    drop(recovery);
    let after = until_made(
        || controller.session_archive(session_id),
        |_| version_of(&controller, session_id) == kr_worker::persistence::migration::CURRENT,
    )
    .await
    .expect("the archive answers");
    assert_eq!(
        version_of(&controller, session_id),
        kr_worker::persistence::migration::CURRENT,
        "control: once nothing holds it the same call brings it forward"
    );
    assert_eq!(
        after.summary.map(|summary| summary.cwd),
        Some(RECOVERED.to_owned())
    );
}

/// KR-REQ-24.18: a recovery is refused while a migration holds the session. The migration runs to
/// its end, and a recovery taken after it succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recovery_is_refused_while_a_migration_holds_the_session() {
    let temp = TempHost::create();
    let controller = daemon(&temp).await;
    after_the_first_pass(&controller).await;
    let session_id = closed_session_of_an_earlier_build(&controller).await;
    let answer = std::sync::Arc::new(std::sync::Mutex::new(None));
    let archive = controller.archive();
    {
        let answer = std::sync::Arc::clone(&answer);
        let archive = archive.clone();
        crate::archive::while_migrating::run_once(session_id, move || {
            let ended = kr_ipc::identity::ended_process_identity(4_000_012);
            *answer.lock().expect("the answer") = Some(
                archive
                    .take_ownership(session_id, DisplayNumber::new(1), &ended)
                    .map(drop),
            );
        });
    }

    until_made(
        || controller.session_archive(session_id),
        |_| answer.lock().expect("the answer").is_some(),
    )
    .await
    .expect("the archive answers");

    let asked = answer.lock().expect("the answer").take();
    assert!(
        matches!(asked, Some(Err(OwnershipRefusal::Held { .. }))),
        "a recovery asked during the migration is refused: {asked:?}"
    );
    assert_eq!(
        version_of(&controller, session_id),
        kr_worker::persistence::migration::CURRENT,
        "and the migration was made"
    );
    let ended = kr_ipc::identity::ended_process_identity(4_000_012);
    assert!(
        archive
            .take_ownership(session_id, DisplayNumber::new(1), &ended)
            .is_ok(),
        "a recovery taken once the migration is done holds the session"
    );
}

/// KR-REQ-24.18: the closure a closing worker's watcher records is recorded under the session's
/// ownership. While another recovery holds the session the watcher records nothing, and once it is
/// done the watcher records the closure the worker wrote for itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closure_is_not_recorded_from_under_a_recovery() {
    let temp = TempHost::create();
    let controller = daemon(&temp).await;
    let session_id = recorded_ended_worker(&controller, &temp).await;
    let display = controller
        .registry
        .lock()
        .await
        .workers()
        .expect("the registry answers")
        .into_iter()
        .find(|row| row.session_id == session_id)
        .expect("the worker is recorded")
        .display_number;
    let wrote = closure_of(session_id);
    written_journal(&controller, session_id, Some(&wrote));
    let ended = kr_ipc::identity::ended_process_identity(4_000_003);
    let recovery = controller
        .archive()
        .take_ownership(session_id, display, &ended)
        .expect("a recovery holds the session");

    assert_eq!(
        controller
            .watch_closure_once(session_id, ClosureReason::CloseRequested)
            .await,
        Watch::Waiting,
        "the watcher leaves a session another recovery holds"
    );
    assert!(
        controller
            .registry
            .lock()
            .await
            .closure(session_id)
            .expect("the registry answers")
            .is_none(),
        "and records no closure from under it"
    );

    drop(recovery);
    assert_eq!(
        controller
            .watch_closure_once(session_id, ClosureReason::CloseRequested)
            .await,
        Watch::Over
    );
    assert_eq!(
        controller
            .registry
            .lock()
            .await
            .closure(session_id)
            .expect("the registry answers"),
        Some(wrote),
        "the closure is the one the worker wrote for itself"
    );
}
