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
use super::close::{Death, Watch, Whose};
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

/// Makes the registry refuse the write that records a closure.
fn refuse_closures(controller: &Controller) {
    rusqlite::Connection::open(controller.paths.registry_database())
        .expect("the registry opens beside the daemon's own handle")
        .execute_batch(
            "CREATE TRIGGER the_closure_is_not_kept BEFORE INSERT ON tombstones
             BEGIN SELECT RAISE(ABORT, 'the registry keeps no closure'); END;",
        )
        .expect("the registry is made to refuse the write that records a closure");
}

/// Lets the registry take a closure again.
fn take_closures_again(controller: &Controller) {
    rusqlite::Connection::open(controller.paths.registry_database())
        .expect("the registry opens beside the daemon's own handle")
        .execute_batch("DROP TRIGGER the_closure_is_not_kept;")
        .expect("the registry takes a closure again");
}

/// A worker that ended after the account it gave when it was asked to close, with a registry that
/// refused the write that records it.
struct AccountThatWasRefused {
    controller: std::sync::Arc<Controller>,
    session_id: SessionId,
    display: DisplayNumber,
    /// What the worker said of its closure: volatile, and not what this daemon would write of a
    /// worker that left nothing.
    account: ClosureRecord,
    /// Declared last: the directory is removed after everything that holds a file in it.
    _temp: TempHost,
}

/// Puts a directory back as it was, whatever the case ends with.
#[cfg(unix)]
struct Writable(std::path::PathBuf);

#[cfg(unix)]
impl Drop for Writable {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
    }
}

impl AccountThatWasRefused {
    async fn made() -> Self {
        let temp = TempHost::create();
        let controller = daemon(&temp).await;
        let session_id = recorded_ended_worker(&controller, &temp).await;
        let display = Self::display_of(&controller, session_id).await;
        Self::refused(temp, controller, session_id, display).await
    }

    /// As [`Self::made`], with the worker's endpoint published in a directory that cannot be
    /// written, so that a recovery cannot remove it. The endpoint is made before the first write is
    /// refused: that refusal starts the watch over the worker, and a watch that looks at an
    /// endpoint it can remove removes it.
    #[cfg(unix)]
    async fn made_with_an_endpoint_that_cannot_be_removed() -> (Self, Writable) {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = TempHost::create();
        let controller = daemon(&temp).await;
        let session_id = recorded_ended_worker(&controller, &temp).await;
        let display = Self::display_of(&controller, session_id).await;
        // The session's lock file is made before the directory is made unwritable. Another task of
        // the daemon may hold the session at this moment, so it is asked for until it is free.
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            while controller
                .archive()
                .own_closed(session_id, || Ok(false))
                .is_err()
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the session's lock is made");
        let endpoint = controller
            .paths
            .worker_endpoint(display)
            .expect("an endpoint");
        let directory = endpoint
            .as_path()
            .parent()
            .expect("a directory")
            .to_path_buf();
        std::fs::create_dir_all(&directory).expect("the directory");
        std::fs::write(endpoint.as_path(), b"a socket").expect("publishes the endpoint");
        let writable = Writable(directory.clone());
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500))
            .expect("makes the directory unwritable");
        let world = Self::refused(temp, controller, session_id, display).await;
        (world, writable)
    }

    async fn display_of(controller: &Controller, session_id: SessionId) -> DisplayNumber {
        controller
            .registry
            .lock()
            .await
            .workers()
            .expect("the registry answers")
            .into_iter()
            .find(|row| row.session_id == session_id)
            .expect("the worker is recorded")
            .display_number
    }

    /// Gives the daemon the worker's account while the registry refuses a closure, and proves
    /// that the first write of it was refused: the write is stopped before the answer is settled,
    /// let go once it has arrived, and the registry's lock, which the write holds until the
    /// registry has answered it, is taken and finds no closure. A write that is refused later than
    /// this would record the account itself, and what a recovery prefers would not show.
    async fn refused(
        temp: TempHost,
        controller: std::sync::Arc<Controller>,
        session_id: SessionId,
        display: DisplayNumber,
    ) -> Self {
        let account = ClosureRecord {
            durability: Durability::Volatile,
            ..closure_of(session_id)
        };
        refuse_closures(&controller);
        let (arrived, release) = controller.stall_the_next_closure_write();
        controller
            .settle_close_answer(
                session_id,
                &kr_protocol::session::SessionCloseResult {
                    session_id,
                    state: SessionState::Closed,
                    durability: account.durability,
                    closure: Nullable::some(account.clone()),
                    session: None,
                },
            )
            .await;
        let reached = tokio::task::spawn_blocking(move || {
            arrived.recv_timeout(std::time::Duration::from_secs(30))
        })
        .await;
        // Let go before any assertion, so that a write that did not arrive holds nothing.
        let _ = release.send(());
        reached
            .expect("the wait for the write ends")
            .expect("the account's write reaches the registry");
        let registry = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            controller.registry.lock(),
        )
        .await
        .expect("the registry is free once its write has been refused");
        assert!(
            registry
                .closure(session_id)
                .expect("the registry answers")
                .is_none(),
            "the first write of the account was refused: the registry holds no closure"
        );
        drop(registry);
        Self {
            _temp: temp,
            controller,
            session_id,
            display,
            account,
        }
    }

    /// The look of a recovery at the worker that ended, as the closure watcher makes it.
    async fn recovery_looks(&self) -> crate::error::Result<Option<ClosureRecord>> {
        self.controller
            .crash_flight(
                self.session_id,
                self.display,
                &kr_ipc::identity::ended_process_identity(4_000_003),
                ClosureReason::WorkerCrash,
            )
            .await
    }

    fn the_registry_takes_closures_again(&self) {
        take_closures_again(&self.controller);
    }

    /// What the registry holds once a recovery has recorded the closure.
    async fn recorded(&self) -> ClosureRecord {
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if let Some(closure) = self
                    .controller
                    .registry
                    .lock()
                    .await
                    .closure(self.session_id)
                    .expect("the registry answers")
                {
                    return closure;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the closure is recorded")
    }
}

/// The closure the worker gave when it was asked to close is its own account of how its session
/// ended. When the worker ends after a write of that account failed, a recovery that finds its
/// endpoint cannot be removed records the account, and not the daemon's own record of a worker
/// that left none.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_endpoint_that_cannot_be_removed_does_not_replace_the_account_a_worker_gave() {
    let (world, _writable) =
        AccountThatWasRefused::made_with_an_endpoint_that_cannot_be_removed().await;
    let endpoint = world
        .controller
        .paths
        .worker_endpoint(world.display)
        .expect("an endpoint");

    world.the_registry_takes_closures_again();
    let found = world
        .recovery_looks()
        .await
        .expect("the registry answers")
        .expect("the worker that ended is closed");
    assert!(
        endpoint.as_path().exists(),
        "the recovery took the path of an endpoint that cannot be removed: it left the endpoint"
    );
    assert_eq!(found, world.account, "the account the worker gave stands");
    assert_eq!(
        world.recorded().await,
        world.account,
        "and it is the one recorded: a record of a crash is not written over it"
    );
}

/// When the first write of the account a worker gave fails at the worker's end, the account is
/// still known, and the next look records it and not the daemon's own record of a worker that left
/// none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_write_at_the_end_of_a_worker_keeps_the_account_it_gave() {
    let world = AccountThatWasRefused::made().await;
    let refused = world.recovery_looks().await;
    assert!(
        refused.is_err(),
        "the write at the worker's end fails with the registry: {refused:?}"
    );
    assert!(
        world
            .controller
            .registry
            .lock()
            .await
            .closure(world.session_id)
            .expect("the registry answers")
            .is_none(),
        "and nothing is recorded"
    );

    world.the_registry_takes_closures_again();
    let found = world
        .recovery_looks()
        .await
        .expect("the registry answers")
        .expect("the worker that ended is closed");
    assert_eq!(found, world.account, "the account the worker gave stands");
    assert_eq!(world.recorded().await, world.account);
}

/// A record of this daemon's own, of a worker that left none, does not replace in memory the
/// account a worker gave. Where the write of the daemon's record fails, the account is what the
/// next look records.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_of_the_daemons_own_does_not_replace_the_account_a_worker_gave() {
    let world = AccountThatWasRefused::made().await;
    let own = ClosureRecord {
        reason: ClosureReason::WorkerCrash,
        ..closure_of(world.session_id)
    };
    let refused = world.controller.write_closure(&own, Whose::Daemon).await;
    assert!(
        refused.is_err(),
        "the write of the daemon's own record fails with the registry: {refused:?}"
    );

    world.the_registry_takes_closures_again();
    let found = world
        .recovery_looks()
        .await
        .expect("the registry answers")
        .expect("the worker that ended is closed");
    assert_eq!(found, world.account, "the account the worker gave stands");
    assert_eq!(
        world.recorded().await,
        world.account,
        "and it is the one recorded: the daemon's own record did not replace it"
    );
}

/// A record of this daemon's own that its registry refused gives its reason, and its reason alone,
/// to the record that the next look at the worker's end writes: that record is built from the next
/// look's own pass, and its reason is the kept record's, not the one that look was given.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_of_the_daemons_own_that_was_not_written_gives_its_reason_at_the_next_look() {
    let temp = TempHost::create();
    let controller = daemon(&temp).await;
    let session_id = recorded_ended_worker(&controller, &temp).await;
    let identity = kr_ipc::identity::ended_process_identity(4_000_003);
    let fenced = crate::archive::Fenced::nothing(session_id);
    let look = |reason| {
        controller.record_final(
            session_id,
            reason,
            &identity,
            &fenced,
            Death::ConfirmedBeforeAFence,
        )
    };

    refuse_closures(&controller);
    let refused = look(ClosureReason::WorkerCrash).await;
    assert!(
        refused.is_err(),
        "the write of the daemon's own record fails with the registry: {refused:?}"
    );
    take_closures_again(&controller);
    let written = look(ClosureReason::HostShutdown)
        .await
        .expect("the registry takes the record");
    assert_eq!(
        written.reason,
        ClosureReason::WorkerCrash,
        "the reason of the first look's record is the one written at the next look: {written:?}"
    );
    assert_eq!(
        controller
            .registry
            .lock()
            .await
            .closure(session_id)
            .expect("the registry answers"),
        Some(written),
        "and it is the one the registry holds"
    );
}

/// A worker that ended and left its own closure in its journal, after a first look at its end that
/// could not read that journal and whose record of this daemon's own the registry refused.
struct KeptRecordAndAJournalRead {
    controller: std::sync::Arc<Controller>,
    session_id: SessionId,
    /// What the worker wrote for itself, which is not what this daemon writes of a worker that left
    /// nothing.
    wrote: ClosureRecord,
    _temp: TempHost,
}

impl KeptRecordAndAJournalRead {
    async fn made() -> Self {
        let temp = TempHost::create();
        let controller = daemon(&temp).await;
        let session_id = recorded_ended_worker(&controller, &temp).await;
        let identity = kr_ipc::identity::ended_process_identity(4_000_003);
        refuse_closures(&controller);
        // The first look: the worker's journal is not read (its endpoint could not be removed), so
        // the record is this daemon's own, and the registry refuses it. It is kept.
        let refused = controller
            .record_final(
                session_id,
                ClosureReason::WorkerCrash,
                &identity,
                &crate::archive::Fenced::nothing(session_id),
                Death::ConfirmedBeforeAFence,
            )
            .await;
        assert!(
            refused.is_err(),
            "the first look's record is refused by the registry: {refused:?}"
        );
        assert!(
            controller
                .registry
                .lock()
                .await
                .closure(session_id)
                .expect("the registry answers")
                .is_none(),
            "and the registry holds no closure"
        );
        // The journal then gives the closure the worker wrote, and the registry takes closures.
        let wrote = closure_of(session_id);
        written_journal(&controller, session_id, Some(&wrote));
        take_closures_again(&controller);
        Self {
            controller,
            session_id,
            wrote,
            _temp: temp,
        }
    }

    /// What the registry holds once a look or a retry has recorded a closure.
    async fn recorded(&self) -> ClosureRecord {
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if let Some(closure) = self
                    .controller
                    .registry
                    .lock()
                    .await
                    .closure(self.session_id)
                    .expect("the registry answers")
                {
                    return closure;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a closure is recorded")
    }
}

/// A look at the worker's end reads the worker's journal before it writes a record of this daemon's
/// own that an earlier look kept: the journal could not be read then and can be now, and the
/// registry must hold the closure the worker wrote, not this daemon's account of a worker that left
/// none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_look_reads_the_journal_before_it_writes_the_record_an_earlier_look_kept() {
    let world = KeptRecordAndAJournalRead::made().await;
    let found = world
        .controller
        .reconcile(world.session_id)
        .await
        .expect("the registry answers")
        .expect("the worker that ended is closed");
    assert_eq!(found, world.wrote, "the closure the worker wrote stands");
    assert_eq!(
        world.recorded().await,
        world.wrote,
        "and it is the one recorded: the record that the first look kept is not written over it"
    );
}

/// A repeat close asks first whether this daemon knows how the session ended (`knows_how_it_ended`,
/// at the local door and at the device's), which starts the retry of a record that it kept. For a
/// record of this daemon's own the retry is a look at the worker's end, which reads the worker's
/// journal first, and the registry must hold the closure the worker wrote.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repeat_close_retries_a_kept_record_through_a_look_that_reads_the_journal() {
    let world = KeptRecordAndAJournalRead::made().await;
    assert!(
        world.controller.knows_how_it_ended(world.session_id),
        "a repeat close finds the record that the first look kept"
    );
    assert_eq!(
        world.recorded().await,
        world.wrote,
        "the retry recorded the closure the worker wrote, not the record that was kept"
    );
}

/// A record of this daemon's own that an earlier look kept gives its reason alone. What it says of
/// the journal, the endpoint and the session's processes is what the look that built it could read,
/// remove and stop; the look that writes the record has made its own fence pass, and the record
/// says what that pass found. The first look could not remove the endpoint, so its record says that
/// nothing was looked for or stopped; the second finds one process ended, and the registry must
/// hold the first reason, that process listed, and no item of an unfenced look.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_kept_record_of_the_daemons_own_gives_its_reason_and_a_later_look_gives_the_rest() {
    let temp = TempHost::create();
    let controller = daemon(&temp).await;
    let session_id = recorded_ended_worker(&controller, &temp).await;
    let identity = kr_ipc::identity::ended_process_identity(4_000_003);
    refuse_closures(&controller);
    let refused = controller
        .record_final(
            session_id,
            ClosureReason::WorkerCrash,
            &identity,
            &crate::archive::Fenced::unfenced(session_id, "Permission denied"),
            Death::ConfirmedBeforeAFence,
        )
        .await;
    assert!(
        refused.is_err(),
        "the first look's record is refused by the registry: {refused:?}"
    );
    assert!(
        controller
            .registry
            .lock()
            .await
            .closure(session_id)
            .expect("the registry answers")
            .is_none(),
        "and the registry holds no closure"
    );

    // The second look can remove the endpoint and read the journal, which holds no closure, and
    // its pass sees one process of the session end.
    written_journal(&controller, session_id, None);
    take_closures_again(&controller);
    let ended = crate::archive::Ended {
        identity: kr_ipc::identity::ended_process_identity(4_000_021),
        forced: false,
        root: false,
    };
    let mut pass = crate::archive::Fenced::nothing(session_id);
    pass.ended.push(ended.clone());
    pass.coverage = OwnershipCoverage::Complete;
    let written = controller
        .record_final(
            session_id,
            ClosureReason::HostShutdown,
            &identity,
            &pass,
            Death::Confirmed,
        )
        .await
        .expect("the registry takes the record");

    assert_eq!(
        written.reason,
        ClosureReason::WorkerCrash,
        "the reason of the first look's record is the one written: {written:?}"
    );
    assert!(
        written
            .terminated
            .iter()
            .any(|process| process.identity == ended.identity),
        "the process that this look's pass saw end is listed: {written:?}"
    );
    assert!(
        written.surviving.is_empty(),
        "and no item of an unfenced look is written: {written:?}"
    );
    assert_eq!(written.ownership_coverage, OwnershipCoverage::Complete);
    assert_eq!(
        controller
            .registry
            .lock()
            .await
            .closure(session_id)
            .expect("the registry answers"),
        Some(written),
        "and the registry holds it"
    );
}

/// A look at the worker's end whose own pass establishes a reason from a fact that the first look
/// could not have gives that reason, and not the reason of the record that the first look kept: the
/// worker's own record of its processes names an earlier boot, which a first look that could not
/// read it did not know (main records the host's restart), or the platform says only now that the
/// worker's desktop has gone. The host's restart outranks the desktop, and a look's default does
/// not replace a reason that rests on a fact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_later_look_gives_a_reason_that_rests_on_a_fact_the_first_look_could_not_have() {
    // The kept reason, the reason this look's pass establishes, whether the pass names an earlier
    // boot, and the reason that is written.
    for (first, later, earlier_boot, written) in [
        (
            ClosureReason::WorkerCrash,
            ClosureReason::HostShutdown,
            true,
            ClosureReason::HostShutdown,
        ),
        (
            ClosureReason::WorkerCrash,
            ClosureReason::DesktopLost,
            false,
            ClosureReason::DesktopLost,
        ),
        (
            ClosureReason::HostShutdown,
            ClosureReason::DesktopLost,
            false,
            ClosureReason::HostShutdown,
        ),
        (
            ClosureReason::DesktopLost,
            ClosureReason::WorkerCrash,
            false,
            ClosureReason::DesktopLost,
        ),
    ] {
        let temp = TempHost::create();
        let controller = daemon(&temp).await;
        let session_id = recorded_ended_worker(&controller, &temp).await;
        let identity = kr_ipc::identity::ended_process_identity(4_000_003);
        refuse_closures(&controller);
        let refused = controller
            .record_final(
                session_id,
                first,
                &identity,
                &crate::archive::Fenced::unfenced(session_id, "Permission denied"),
                Death::ConfirmedBeforeAFence,
            )
            .await;
        assert!(
            refused.is_err(),
            "the first look's record is refused by the registry: {refused:?}"
        );
        assert!(
            controller
                .registry
                .lock()
                .await
                .closure(session_id)
                .expect("the registry answers")
                .is_none(),
            "and the registry holds no closure"
        );

        written_journal(&controller, session_id, None);
        take_closures_again(&controller);
        let pass = if earlier_boot {
            crate::archive::Fenced::of_an_earlier_boot(session_id)
        } else {
            crate::archive::Fenced::nothing(session_id)
        };
        let record = controller
            .record_final(session_id, later, &identity, &pass, Death::Confirmed)
            .await
            .expect("the registry takes the record");
        assert_eq!(
            record.reason, written,
            "a first look's {first:?} and a later look's {later:?} give {written:?}: {record:?}"
        );
    }
}
