//! A change to privacy mode or to a session's name is written under the admission it carries, once
//! every wait it has is behind it.
//!
//! Each change waits for something the caller cannot see: a rename for the description store, and
//! privacy mode for the record's own transaction. What the admission said when the change was
//! accepted says nothing about what it says after such a wait, so it is asked again once the
//! change holds what it writes to. These tests stop the change where every wait it has is still
//! ahead of it, hold what it will wait for from outside, let it go on, let the admission lapse
//! while it waits, and read back that nothing was written: once because the action's deadline
//! passed, on a clock the test moves, and once because its connection was withdrawn.
//!
//! A create that launches a worker while privacy mode is on waits for the record too, and has the
//! session's obligation on the disk before it asks for the worker.
//!
//! The tick that decides which sessions have ended is tested here too: it takes a session for ended
//! only when the registry shows its launch is over, and forgets a launch that never produced a
//! worker.

use std::sync::Arc;
use std::time::Duration;

use kr_crypto::store::MemoryStore;
use kr_describe::store::DescriptionStore;
use kr_ipc::peer::PeerIdentity;
use kr_protocol::describe::SessionRenameParams;
use kr_protocol::envelope::{ActionTarget, MutationRequest, ParamsValue};
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, ActionWindowId, ActorId, BuildId, ConnectionId, EnvironmentId, RequestId,
    SessionEpoch, SessionId,
};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::privacy::PrivacySetParams;
use kr_protocol::scalars::{Digest256, DurationMs, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::session::{DisplayNumber, SessionState, SessionSummary, ShellMode};
use kr_transport::clock::ManualClock;

use crate::error::ControllerError;
use crate::privacy::PRIVACY_RECORD;
use crate::registry::LaunchPhase;
use crate::service::{Clocks, Controller, ControllerSetup, WallClock};
use crate::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};

/// A supervisor that starts nothing: these tests run no worker.
#[derive(Debug)]
struct NoWorkers;

impl WorkerSupervisor for NoWorkers {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

/// A supervisor that records what the privacy record held on the disk when it was asked to start a
/// worker, and starts nothing.
#[derive(Debug)]
struct Recording {
    state_dir: std::path::PathBuf,
    asked: Arc<std::sync::Mutex<Vec<(SessionId, i64)>>>,
}

impl WorkerSupervisor for Recording {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        let owed: i64 = rusqlite::Connection::open(self.state_dir.join(PRIVACY_RECORD))
            .expect("a second connection to the record")
            .query_row(
                "SELECT COUNT(*) FROM privacy_obligations WHERE session_id = ?1",
                [launch.session_id.to_string()],
                |row| row.get(0),
            )
            .expect("a count");
        self.asked
            .lock()
            .expect("the record is not poisoned")
            .push((launch.session_id, owed));
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that records the privacy record's obligations and starts nothing"
    }
}

/// A supervisor that cannot say what it started: a process may be running, and it reports `pid`.
#[derive(Debug)]
struct Uncertain {
    pid: Option<u32>,
}

impl WorkerSupervisor for Uncertain {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::Uncertain {
            detail: "this test's supervisor cannot say what it started".to_owned(),
            pid: self.pid,
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that cannot say what it started"
    }
}

/// A deadline that nothing in these tests reaches, unless a test moves its clock past it.
const STANDING: Duration = Duration::from_secs(60);

/// How long a change that has been let go has to reach the wait it goes on to. It is running when
/// this starts, and what it has left to do before it waits is a few statements.
const SETTLING: Duration = Duration::from_millis(300);

/// How the admission a change carries stops standing while the change waits.
#[derive(Clone, Copy, Debug)]
enum Lapse {
    /// The action's deadline passes.
    Deadline,
    /// The connection the action arrived on is withdrawn.
    Withdrawal,
}

impl Lapse {
    /// Lets the admission of the action that arrived on `connection_id` lapse.
    fn happens(self, controller: &Controller, clock: &ManualClock, connection_id: ConnectionId) {
        match self {
            Self::Deadline => clock.advance(STANDING + Duration::from_secs(1)),
            Self::Withdrawal => controller.deregister(connection_id),
        }
    }

    /// Whether the error is what this lapse is refused with.
    fn is_refused_by(self, error: &ControllerError) -> bool {
        match self {
            Self::Deadline => matches!(error, ControllerError::WindowExpired { .. }),
            Self::Withdrawal => matches!(error, ControllerError::PermissionDenied { .. }),
        }
    }
}

/// Waits until a change says it has reached the place it is stopped at, and fails the test when it
/// does not within thirty seconds.
async fn arrival(arrived: std::sync::mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)))
        .await
        .expect("the waiting thread finishes")
        .expect("the change reaches the place it is stopped at");
}

/// A daemon on a tree of its own, on a continuous clock the test moves, with a supervisor that
/// starts nothing.
async fn daemon() -> (kr_ipc::testing::TempHost, Arc<Controller>, ManualClock) {
    daemon_starting(|_| Box::new(NoWorkers)).await
}

/// A daemon as [`daemon`] starts one, whose supervisor `supervisor` makes from the environment's
/// state directory.
async fn daemon_starting(
    supervisor: impl FnOnce(&std::path::Path) -> Box<dyn WorkerSupervisor>,
) -> (kr_ipc::testing::TempHost, Arc<Controller>, ManualClock) {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let clock = ManualClock::new();
    let controller = Controller::start_on_clocks(
        ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                Ok(kr_ipc::verify::ControllerIdentity::open(
                    &MemoryStore::new(),
                    environment_id,
                    false,
                )
                .expect("an identity"))
            }),
            secret_store: kr_crypto::store::StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: supervisor(environment.state_dir()),
            worker_program: temp.root().join("kr-worker"),
            build_id: BuildId::new("kr-test/0").expect("a build identifier"),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(crate::supervision::NoTerminal),
        },
        Clocks {
            continuous: Arc::new(clock.clone()),
            wall: WallClock::system(),
        },
    )
    .await
    .expect("the daemon starts");
    (temp, controller, clock)
}

/// Registers one connection, the way a caller's handshake does, and returns the admission an
/// action arriving on it carries, with a deadline [`STANDING`] from now.
async fn admitted(
    controller: &Controller,
) -> (
    kr_protocol::ids::ActorId,
    crate::authority::AdmittedMutation,
) {
    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
    let actor_id = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
    controller
        .admit_connection(
            connection_id,
            &actor_id,
            &PeerIdentity {
                uid: kr_ipc::paths::current_uid(),
                gid: 0,
                pid: None,
            },
        )
        .await
        .expect("the connection is registered");
    let carried = crate::authority::AdmittedMutation {
        connection_id,
        admitted_revision: controller.leases.authority_revision(),
        deadline: controller.clock.now().checked_add(STANDING),
    };
    (actor_id, carried)
}

fn session_id() -> SessionId {
    SessionId::new(Uuid::from_bytes([0xa1; 16]))
}

fn summary(environment_id: EnvironmentId) -> SessionSummary {
    SessionSummary {
        session_id: session_id(),
        session_epoch: SessionEpoch::new(1),
        environment_id,
        display_number: DisplayNumber::new(3),
        state: SessionState::Live,
        shell_mode: ShellMode::Managed,
        shell_path: "/bin/zsh".to_owned(),
        cwd: "/work/kalareach".to_owned(),
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        created_at_ms: TimestampMs::new(1_000),
        dimensions: kr_protocol::session::INVISIBLE_DEFAULT_DIMENSIONS,
        attachment_count: U64::ZERO,
        application_state: Nullable::null(),
        root_process: Nullable::null(),
        closure: Nullable::null(),
    }
}

fn request<P: serde::Serialize>(
    method: Method,
    environment_id: EnvironmentId,
    params: &P,
) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(1),
        method: method.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget::environment(environment_id),
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("local:test").expect("a window"),
        requested_ttl_ms: DurationMs::new(30_000),
        params: ParamsValue::from_typed(params).expect("encodes"),
    }
}

fn rename(environment_id: EnvironmentId, title: &str) -> MutationRequest {
    request(
        Method::SessionRename,
        environment_id,
        &SessionRenameParams {
            session_id: session_id(),
            title: Nullable::some(title.to_owned()),
        },
    )
}

/// Holds the description store's own lock, as a slow reader or another rename would.
///
/// The lock is a synchronous one, so it is held on a blocking thread rather than across an await.
struct HeldStore {
    release: Option<std::sync::mpsc::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl HeldStore {
    fn hold(controller: &Arc<Controller>) -> Self {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (held, confirmed) = std::sync::mpsc::channel::<()>();
        let controller = Arc::clone(controller);
        let task = tokio::task::spawn_blocking(move || {
            let _store = controller.descriptions.store();
            held.send(()).expect("the test is waiting");
            // The receiver ends when the sender is dropped, so a test that panics does not leave
            // the store locked.
            let _ = wait.recv();
        });
        confirmed.recv().expect("the description store is held");
        Self {
            release: Some(release),
            task: Some(task),
        }
    }

    async fn release(mut self) {
        drop(self.release.take());
        if let Some(task) = self.task.take() {
            task.await.expect("the holding thread finishes");
        }
    }
}

/// A rename that waits for the description store while its admission lapses writes nothing, and
/// is refused as the lapse is; the same rename under an admission that stands then writes.
async fn a_rename_whose_admission_lapses_while_it_waits(lapse: Lapse) {
    let (temp, controller, clock) = daemon().await;
    let environment_id = temp.environment_id();
    let (actor_id, carried) = admitted(&controller).await;
    let connection_id = carried.connection_id;
    let mutation = rename(environment_id, "Release prep");

    // The rename runs to the place where it would take the store, and stops there. Somebody else
    // takes the store, and the rename goes on and waits for it.
    let (arrived, release) = controller.descriptions.pauses.before_store.arm();
    let renaming = tokio::spawn({
        let controller = Arc::clone(&controller);
        let actor_id = actor_id.clone();
        async move {
            controller
                .session_rename(&actor_id, &mutation, summary(environment_id), carried)
                .await
        }
    });
    arrival(arrived).await;
    let held = HeldStore::hold(&controller);
    release.send(()).expect("the rename goes on");
    tokio::time::sleep(SETTLING).await;
    assert!(!renaming.is_finished(), "the rename waits for the store");
    lapse.happens(&controller, &clock, connection_id);
    held.release().await;

    let refused = renaming
        .await
        .expect("the rename finishes")
        .expect_err("a rename whose admission lapsed while it waited writes nothing");
    assert!(lapse.is_refused_by(&refused), "{lapse:?}: {refused}");
    let store = DescriptionStore::open(temp.environment().state_dir()).expect("the store opens");
    assert!(
        store.pinned(&session_id()).expect("a read").is_none(),
        "{lapse:?}: nothing was pinned"
    );

    // The same rename under an admission that stands is written.
    let (actor_id, carried) = admitted(&controller).await;
    controller
        .session_rename(
            &actor_id,
            &rename(environment_id, "Release prep"),
            summary(environment_id),
            carried,
        )
        .await
        .expect("a rename under a standing admission is written");
    assert!(store.pinned(&session_id()).expect("a read").is_some());
}

/// KR-REQ-24.14: a rename's deadline passes while it waits for the description store.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rename_whose_deadline_passes_while_it_waits_for_the_store_writes_nothing() {
    a_rename_whose_admission_lapses_while_it_waits(Lapse::Deadline).await;
}

/// KR-REQ-24.14: the connection a rename arrived on is withdrawn while it waits for the
/// description store.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rename_whose_connection_is_withdrawn_while_it_waits_for_the_store_writes_nothing() {
    a_rename_whose_admission_lapses_while_it_waits(Lapse::Withdrawal).await;
}

/// A privacy change that waits for the record's own transaction while its admission lapses
/// records nothing, publishes nothing and fences nothing, and is refused as the lapse is.
async fn a_privacy_change_whose_admission_lapses_while_it_waits(lapse: Lapse) {
    let (temp, controller, clock) = daemon().await;
    let environment_id = temp.environment_id();
    let (_actor, carried) = admitted(&controller).await;
    let connection_id = carried.connection_id;
    let mutation = request(
        Method::PrivacySet,
        environment_id,
        &PrivacySetParams { enabled: true },
    );

    // The change runs to the place where every wait it has is still ahead of it, and stops there.
    // Another writer takes the record's write lock, and the change goes on and waits for its
    // transaction.
    let (arrived, release) = controller.privacy.before_change.arm();
    let changing = tokio::spawn({
        let controller = Arc::clone(&controller);
        async move { controller.privacy_set(&mutation, carried).await }
    });
    arrival(arrived).await;
    let holder = rusqlite::Connection::open(temp.environment().state_dir().join(PRIVACY_RECORD))
        .expect("a second connection to the record");
    holder
        .execute_batch("BEGIN IMMEDIATE;")
        .expect("the record's write lock is held");
    release.send(()).expect("the change goes on");
    tokio::time::sleep(SETTLING).await;
    assert!(
        !changing.is_finished(),
        "the change waits for the record's transaction"
    );
    lapse.happens(&controller, &clock, connection_id);
    holder
        .execute_batch("ROLLBACK;")
        .expect("the write lock is let go");

    let refused = changing
        .await
        .expect("the change finishes")
        .expect_err("a change whose admission lapsed while it waited changes nothing");
    assert!(lapse.is_refused_by(&refused), "{lapse:?}: {refused}");
    let report = controller.privacy.status(kr_ipc::now_ms());
    assert!(!report.enabled, "{lapse:?}: privacy mode is still off");
    assert!(!controller.privacy.state().is_private());
    assert_eq!(
        controller.backup().fenced_at().expect("a read"),
        None,
        "{lapse:?}: the backup service is not fenced"
    );

    // The same change under an admission that stands is recorded.
    let (_actor, carried) = admitted(&controller).await;
    let mutation = request(
        Method::PrivacySet,
        environment_id,
        &PrivacySetParams { enabled: true },
    );
    controller
        .privacy_set(&mutation, carried)
        .await
        .expect("a change under a standing admission is recorded");
    assert!(controller.privacy.state().is_private());
}

/// KR-REQ-24.27: a privacy change's deadline passes while it waits for the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_privacy_change_whose_deadline_passes_while_it_waits_for_the_record_changes_nothing() {
    a_privacy_change_whose_admission_lapses_while_it_waits(Lapse::Deadline).await;
}

/// KR-REQ-24.27: the connection a privacy change arrived on is withdrawn while it waits for the
/// record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_privacy_change_whose_connection_is_withdrawn_while_it_waits_for_the_record_changes_nothing()
 {
    a_privacy_change_whose_admission_lapses_while_it_waits(Lapse::Withdrawal).await;
}

/// Reserves a session, the way a create does before it starts anything, and records the phase its
/// launch has reached.
async fn reserved(controller: &Controller, token: u8, phase: LaunchPhase) -> SessionId {
    let mut registry = controller.registry.lock().await;
    let reservation = registry
        .reserve(
            &ActorId::new("local:501").expect("a principal"),
            Uuid::from_bytes([token; 16]),
            Digest256::from_bytes([3; 32]),
            b"intent",
            TimestampMs::new(1),
        )
        .expect("reserves")
        .reservation;
    if phase != LaunchPhase::Reserved {
        registry
            .set_phase(reservation.reservation_id, phase)
            .expect("the phase is recorded");
    }
    reservation.session_id
}

/// Reserves a session and has a worker claim it, as a rendezvous does, so the reservation records
/// the key that worker presented and is `claimed`. `then` says what became of the launch after.
async fn claimed(controller: &Controller, token: u8, then: Option<LaunchPhase>) -> SessionId {
    let session_id = reserved(controller, token, LaunchPhase::Spawned).await;
    let mut registry = controller.registry.lock().await;
    let reservation_id = registry
        .reservation_for_session(session_id)
        .expect("a read")
        .expect("the reservation")
        .reservation_id;
    registry
        .claim_rendezvous(
            reservation_id,
            kr_protocol::scalars::AuthorisationKey::from_bytes([token; 32]),
        )
        .expect("the claim is consumed");
    match then {
        Some(LaunchPhase::Fenced) => registry.fence(reservation_id).expect("fenced"),
        Some(phase) => {
            let _ = registry
                .resolve_claim(reservation_id, phase)
                .expect("resolved");
        }
        None => {}
    }
    session_id
}

/// Records that a create is still running for a reserved session, as the daemon does from before
/// its reservation moves to `spawned` until the create returns.
async fn creating(controller: &Controller, session_id: SessionId) {
    let reservation_id = controller
        .registry
        .lock()
        .await
        .reservation_for_session(session_id)
        .expect("a read")
        .expect("the reservation")
        .reservation_id;
    let (ready, _answer) = tokio::sync::oneshot::channel();
    controller
        .pending
        .lock()
        .await
        .insert(reservation_id, super::create::PendingCreate { ready });
}

/// Records that the create of a reserved session has returned.
async fn created(controller: &Controller, session_id: SessionId) {
    let reservation_id = controller
        .registry
        .lock()
        .await
        .reservation_for_session(session_id)
        .expect("a read")
        .expect("the reservation")
        .reservation_id;
    controller.pending.lock().await.remove(&reservation_id);
}

/// Has a worker claim the reservation of an already reserved, spawned session.
async fn claim_now(controller: &Controller, session_id: SessionId) {
    let mut registry = controller.registry.lock().await;
    let reservation_id = registry
        .reservation_for_session(session_id)
        .expect("a read")
        .expect("the reservation")
        .reservation_id;
    registry
        .claim_rendezvous(
            reservation_id,
            kr_protocol::scalars::AuthorisationKey::from_bytes([9; 32]),
        )
        .expect("the claim is consumed");
}

/// This process, as the launcher of a launch that is still running.
fn running_launcher() -> kr_protocol::identity::ProcessStartIdentity {
    kr_ipc::identity::current_process_start_identity().expect("this process")
}

/// A launcher that has ended.
fn ended_launcher() -> kr_protocol::identity::ProcessStartIdentity {
    kr_ipc::identity::ended_process_identity(4_000_000)
}

/// Records that the launcher of a reserved session is the process `identity`.
async fn launched_by(
    controller: &Controller,
    session_id: SessionId,
    identity: &kr_protocol::identity::ProcessStartIdentity,
) {
    let mut registry = controller.registry.lock().await;
    let reservation_id = registry
        .reservation_for_session(session_id)
        .expect("a read")
        .expect("the reservation")
        .reservation_id;
    registry
        .record_launch(reservation_id, identity)
        .expect("the launcher is recorded");
}

/// Records that the launch of an already reserved session has reached `phase`.
async fn recorded_as(controller: &Controller, session_id: SessionId, phase: LaunchPhase) {
    let mut registry = controller.registry.lock().await;
    let reservation_id = registry
        .reservation_for_session(session_id)
        .expect("a read")
        .expect("the reservation")
        .reservation_id;
    registry
        .set_phase(reservation_id, phase)
        .expect("the phase is recorded");
}

/// KR-REQ-24.28: what the registry shows of a session's launch decides what became of it. A
/// reservation that was claimed and then failed or closed, and a session the registry holds nothing
/// for, are over: a worker ran, or may have, and what it retained is the archive's. A launch that
/// failed or was fenced before any worker claimed it, whose launcher has ended without claiming, or
/// that recorded no launcher when its create returned, never handed out a specification, so no
/// shell ran: it is forgotten. Every other phase is a worker that may be starting or running, and
/// its session is neither.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_launch_is_over_only_when_no_worker_can_still_come_of_it() {
    let (_temp, controller, _clock) = daemon().await;
    let mut asked: Vec<SessionId> = Vec::new();
    let mut ended: Vec<SessionId> = Vec::new();
    let mut never_started: Vec<SessionId> = Vec::new();
    let mut token = 0_u8;
    let mut next = || {
        token += 1;
        token
    };
    // A reservation in a phase no worker has claimed it in: only a launch that cannot be claimed
    // any more never started. A spawned reservation whose create is still running has recorded no
    // launcher yet, and is not one that recorded none.
    for (phase, over) in [
        (LaunchPhase::Reserved, false),
        (LaunchPhase::Spawned, false),
        (LaunchPhase::Claimed, false),
        (LaunchPhase::Live, false),
        (LaunchPhase::Fenced, true),
        (LaunchPhase::Failed, true),
        (LaunchPhase::Closed, false),
    ] {
        let session_id = reserved(&controller, next(), phase).await;
        if phase == LaunchPhase::Spawned {
            creating(&controller, session_id).await;
        }
        asked.push(session_id);
        if over {
            never_started.push(session_id);
        }
        if phase == LaunchPhase::Closed {
            ended.push(session_id);
        }
    }
    // A claim consumed: a worker was given its specification, so what happens after is the
    // archive's, and a launch fenced after a claim may still have a worker.
    let after_a_claim_failed = claimed(&controller, next(), Some(LaunchPhase::Failed)).await;
    let after_a_claim_closed = claimed(&controller, next(), Some(LaunchPhase::Closed)).await;
    let after_a_claim_fenced = claimed(&controller, next(), Some(LaunchPhase::Fenced)).await;
    let after_a_claim = claimed(&controller, next(), None).await;
    asked.extend([
        after_a_claim_failed,
        after_a_claim_closed,
        after_a_claim_fenced,
        after_a_claim,
    ]);
    ended.extend([after_a_claim_failed, after_a_claim_closed]);

    // A launch whose launcher has ended without claiming can never be claimed: a claim comes from
    // the launcher's own process. One whose launcher is running still can.
    let gone = reserved(&controller, next(), LaunchPhase::Spawned).await;
    launched_by(&controller, gone, &ended_launcher()).await;
    let running = reserved(&controller, next(), LaunchPhase::Spawned).await;
    launched_by(&controller, running, &running_launcher()).await;
    asked.extend([gone, running]);
    never_started.push(gone);

    // A launch that recorded no launcher can never be claimed either, once its create has returned:
    // only the create records one, and a claim is refused without one. A create that is still
    // running may yet record it.
    let uncertain = reserved(&controller, next(), LaunchPhase::Spawned).await;
    asked.push(uncertain);
    never_started.push(uncertain);

    // A session the registry holds nothing for is over too: no launch can come of it.
    let unknown = SessionId::new(kr_ipc::new_uuid());
    asked.push(unknown);
    ended.push(unknown);

    let launches = super::start::launches_over(&controller, &asked).await;
    let sorted = |mut sessions: Vec<SessionId>| {
        sessions.sort_unstable();
        sessions
    };
    assert_eq!(sorted(launches.ended), sorted(ended));
    assert_eq!(sorted(launches.never_started), sorted(never_started));
    let none = super::start::launches_over(&controller, &[]).await;
    assert!(
        none.ended.is_empty() && none.never_started.is_empty(),
        "nothing asked, nothing over"
    );
}

/// KR-REQ-24.28: a claim, or a launcher, that arrives between the daemon asking about a launch and
/// reading it again makes it one a worker ran from, or may yet: the registry is read again before
/// a launch is believed never to have started. The controls are the same launches with nothing
/// arriving, which are never started.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_launch_that_changes_between_the_two_looks_is_not_taken_for_never_started() {
    let (_temp, controller, _clock) = daemon().await;
    // The launcher has ended, and a claim commits after it was found so.
    let claimed_after_the_launcher = reserved(&controller, 1, LaunchPhase::Spawned).await;
    launched_by(&controller, claimed_after_the_launcher, &ended_launcher()).await;
    // No launcher was recorded when its create returned, and one is recorded after.
    let launcher_after_the_create = reserved(&controller, 2, LaunchPhase::Spawned).await;
    // The same, claimed.
    let claimed_after_the_create = reserved(&controller, 3, LaunchPhase::Spawned).await;
    // Controls: nothing arrives.
    let control_launcher = reserved(&controller, 4, LaunchPhase::Spawned).await;
    launched_by(&controller, control_launcher, &ended_launcher()).await;
    let control_create = reserved(&controller, 5, LaunchPhase::Spawned).await;
    let asked = [
        claimed_after_the_launcher,
        launcher_after_the_create,
        claimed_after_the_create,
        control_launcher,
        control_create,
    ];

    let launches = super::start::launches_between(&controller, &asked, async {
        claim_now(&controller, claimed_after_the_launcher).await;
        launched_by(&controller, launcher_after_the_create, &running_launcher()).await;
        claim_now(&controller, claimed_after_the_create).await;
    })
    .await;
    assert!(launches.ended.is_empty(), "{:?}", launches.ended);
    let mut expected = vec![control_launcher, control_create];
    expected.sort_unstable();
    let mut found = launches.never_started;
    found.sort_unstable();
    assert_eq!(found, expected, "only the launches nothing arrived for");
}

/// Whether privacy mode's record reports the session's worker as ended.
fn is_ended(controller: &Controller, session_id: SessionId) -> bool {
    controller
        .privacy
        .status(kr_ipc::now_ms())
        .sessions
        .iter()
        .any(|owed| {
            owed.session_id == session_id
                && matches!(
                    owed.standing,
                    kr_protocol::privacy::PrivacySessionStanding::WorkerEnded
                )
        })
}

/// Waits until privacy mode's tick has taken every session in `sessions` for ended, and fails the
/// test when it has not within thirty seconds.
async fn ended(controller: &Controller, sessions: &[SessionId]) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !sessions
        .iter()
        .all(|session_id| is_ended(controller, *session_id))
    {
        assert!(
            std::time::Instant::now() < deadline,
            "the tick never took the sessions for ended: {:?}",
            controller.privacy.status(kr_ipc::now_ms()).sessions
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// KR-REQ-24.28: privacy mode's tick takes a session for ended only on the registry's evidence.
/// Two sessions owe their cleanup and have no worker: one whose launch was claimed, one whose
/// reservation was fenced after a claim. Through every pass of the tick each may still have a
/// worker, so turning privacy mode off is refused; it stays refused while one of them is left, and
/// once the registry records that the first launch failed the next pass takes it for ended, and
/// once it records the second as closed, privacy mode is turned off. A third, failed before any
/// worker claimed it, and a fourth, whose create returned without recording a launcher, ran no
/// shell: each is forgotten with its obligation, durably, and never reported as ended with the
/// archive named.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_tick_ends_a_session_only_once_the_registry_shows_its_launch_is_over() {
    let (temp, controller, _clock) = daemon().await;
    let claim = claimed(&controller, 1, None).await;
    let fenced = claimed(&controller, 2, Some(LaunchPhase::Fenced)).await;
    let unstarted = reserved(&controller, 3, LaunchPhase::Reserved).await;
    // A launch whose create is still running, and has recorded no launcher yet.
    let uncertain = reserved(&controller, 4, LaunchPhase::Spawned).await;
    creating(&controller, uncertain).await;
    let standing = |write: &mut dyn FnMut() -> crate::error::Result<()>| write();
    controller
        .privacy
        .enable(
            &[claim, fenced, unstarted, uncertain],
            kr_ipc::now_ms(),
            &standing,
        )
        .expect("privacy mode is turned on");

    // The tick passes over all four, more than once; none that may still have a worker is taken
    // for ended, so turning privacy mode off is refused.
    tokio::time::sleep(super::start::PRIVACY_TICK * 3).await;
    let refused = controller
        .privacy
        .disable(kr_ipc::now_ms(), &standing)
        .expect_err("a launch that may still produce a worker holds privacy mode on");
    for session_id in [claim, fenced, unstarted, uncertain] {
        assert!(
            refused.to_string().contains(&session_id.to_string()),
            "the refusal names the session: {refused}"
        );
    }

    // The third launch fails before any worker claimed it. The pass that follows forgets it: it is
    // not reported as ended, and no obligation of it is left on the disk.
    recorded_as(&controller, unstarted, LaunchPhase::Failed).await;
    forgotten(&controller, &[unstarted]).await;
    assert!(!is_ended(&controller, unstarted));
    assert_eq!(obligations_on_disk(&temp), 3, "the others are still owed");

    // The fourth is spawned, and its create returns without having recorded a launcher, as one that
    // could not say what it started does: no claim can be accepted for it any more, and it is
    // forgotten the same way.
    created(&controller, uncertain).await;
    forgotten(&controller, &[uncertain]).await;
    assert!(!is_ended(&controller, uncertain));
    assert_eq!(
        obligations_on_disk(&temp),
        2,
        "the other two are still owed"
    );
    let refused = controller
        .privacy
        .disable(kr_ipc::now_ms(), &standing)
        .expect_err("the other two still hold privacy mode on");
    assert!(
        !refused.to_string().contains(&unstarted.to_string()),
        "{refused}"
    );

    // One launch is over, and the other may still produce a worker. The pass that takes the first
    // for ended is a pass that has read the registry with the second fenced, so once it has been
    // seen the second is known to have been passed over, and it holds the change back.
    recorded_as(&controller, claim, LaunchPhase::Failed).await;
    ended(&controller, &[claim]).await;
    assert!(
        !is_ended(&controller, fenced),
        "the fenced launch may still produce a worker, so its session is not ended"
    );
    let refused = controller
        .privacy
        .disable(kr_ipc::now_ms(), &standing)
        .expect_err("the fenced launch still holds privacy mode on");
    assert!(
        refused.to_string().contains(&fenced.to_string()),
        "{refused}"
    );

    // Both are over: the next pass takes them for ended, and privacy mode is turned off. What each
    // had retained is the archive's, so their obligations stay.
    recorded_as(&controller, fenced, LaunchPhase::Closed).await;
    ended(&controller, &[claim, fenced]).await;
    let off = controller
        .privacy
        .disable(kr_ipc::now_ms(), &standing)
        .expect("sessions whose launches are over do not hold privacy mode on");
    assert!(!off.enabled);
    assert_eq!(obligations_on_disk(&temp), 2);
}

/// How many obligations privacy mode's record holds on the disk.
fn obligations_on_disk(temp: &kr_ipc::testing::TempHost) -> i64 {
    rusqlite::Connection::open(temp.environment().state_dir().join(PRIVACY_RECORD))
        .expect("a second connection to the record")
        .query_row("SELECT COUNT(*) FROM privacy_obligations", [], |row| {
            row.get(0)
        })
        .expect("a count")
}

/// Waits until privacy mode's tick has forgotten every session in `sessions`, and fails the test
/// when it has not within thirty seconds.
async fn forgotten(controller: &Controller, sessions: &[SessionId]) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let report = controller.privacy.status(kr_ipc::now_ms());
        if sessions.iter().all(|session_id| {
            report
                .sessions
                .iter()
                .all(|owed| owed.session_id != *session_id)
        }) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the tick never forgot the sessions: {:?}",
            report.sessions
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A create request for an invisible session.
fn create_request(environment_id: EnvironmentId) -> MutationRequest {
    request(
        Method::SessionCreate,
        environment_id,
        &kr_protocol::session::SessionCreateParams {
            environment_id,
            presentation: kr_protocol::session::Presentation::Invisible,
            shell: Nullable::null(),
            shell_mode: ShellMode::NativeCompat,
            cwd: Nullable::some("/".to_owned()),
            dimensions: Nullable::null(),
            worker_profile: WorkerProfile::HeadlessUser,
            environment_snapshot: Vec::new(),
            palette: Nullable::null(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
            terminal: Nullable::null(),
        },
    )
}

/// What a create that asked for its worker while privacy mode was `private` left: the sessions the
/// supervisor was asked to start, each with how many obligations the record held for it on the
/// disk at that moment.
async fn asked_after_a_create(private: bool) -> Vec<(SessionId, i64)> {
    let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (temp, controller, _clock) = daemon_starting(|state_dir| {
        Box::new(Recording {
            state_dir: state_dir.to_path_buf(),
            asked: Arc::clone(&asked),
        })
    })
    .await;
    if private {
        controller
            .privacy
            .enable(&[], kr_ipc::now_ms(), &|write| write())
            .expect("privacy mode is turned on");
    }
    let (actor_id, carried) = admitted(&controller).await;
    controller
        .session_create(&actor_id, &create_request(temp.environment_id()), carried)
        .await
        .expect_err("this test starts no workers");
    let asked = asked.lock().expect("the record is not poisoned");
    asked.clone()
}

/// KR-REQ-24.27: a session created while privacy mode is on has its obligation on the disk when its
/// worker is asked for, so turning privacy mode off waits for it from before its shell runs. The
/// control is the same create with privacy mode off, which has none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_created_while_privacy_mode_is_on_owes_cleanup_when_its_worker_is_asked_for() {
    let private = asked_after_a_create(true).await;
    assert_eq!(private.len(), 1, "the worker was asked for: {private:?}");
    assert_eq!(private[0].1, 1, "its obligation was on the disk");
    let off = asked_after_a_create(false).await;
    assert_eq!(off.len(), 1, "the worker was asked for: {off:?}");
    assert_eq!(off[0].1, 0, "and owed nothing while privacy mode was off");
}

/// A create that waits for a change of privacy mode that holds the record, while its admission
/// lapses, starts nothing and holds nothing: the registry stays free while it waits, its
/// reservation is resolved as failed, and the obligation it wrote once the change had finished is
/// forgotten by the tick, because no worker ever claimed it.
async fn a_create_whose_admission_lapses_while_it_waits_for_the_record(lapse: Lapse) {
    let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (temp, controller, clock) = daemon_starting(|state_dir| {
        Box::new(Recording {
            state_dir: state_dir.to_path_buf(),
            asked: Arc::clone(&asked),
        })
    })
    .await;
    let (actor_id, carried) = admitted(&controller).await;
    let connection_id = carried.connection_id;
    let mutation = create_request(temp.environment_id());

    // An enabling holds the record's mutex, as it does while it waits for what it must.
    let (arrived, release) = controller.privacy.before_change.arm();
    let enabling = tokio::task::spawn_blocking({
        let controller = Arc::clone(&controller);
        move || {
            controller
                .privacy
                .enable(&[], kr_ipc::now_ms(), &|write| write())
        }
    });
    arrival(arrived).await;

    let creating = tokio::spawn({
        let controller = Arc::clone(&controller);
        async move {
            controller
                .session_create(&actor_id, &mutation, carried)
                .await
        }
    });
    tokio::time::sleep(SETTLING).await;
    assert!(!creating.is_finished(), "the create waits for the record");
    assert!(
        asked.lock().expect("the record is not poisoned").is_empty(),
        "and has asked for no worker"
    );
    // The registry is free while it waits: the create holds no guard of it.
    drop(
        tokio::time::timeout(Duration::from_secs(10), controller.registry.lock())
            .await
            .expect("the registry is not held by a create that is waiting"),
    );
    lapse.happens(&controller, &clock, connection_id);
    release.send(()).expect("the enabling goes on");
    enabling
        .await
        .expect("the enabling finishes")
        .expect("privacy mode is turned on");

    let refused = creating
        .await
        .expect("the create finishes")
        .expect_err("a create whose admission lapsed while it waited starts nothing");
    assert!(lapse.is_refused_by(&refused), "{lapse:?}: {refused}");
    assert!(
        asked.lock().expect("the record is not poisoned").is_empty(),
        "{lapse:?}: no worker was asked for"
    );
    let failed = controller
        .registry
        .lock()
        .await
        .reservations_in(LaunchPhase::Failed)
        .expect("a read");
    assert_eq!(failed.len(), 1, "{lapse:?}: the reservation is resolved");
    // It wrote its obligation once the change had finished, and the tick forgets it: nothing ran.
    forgotten(&controller, &[failed[0].session_id]).await;
    assert_eq!(obligations_on_disk(&temp), 0);
    controller
        .privacy
        .disable(
            kr_ipc::now_ms(),
            &|write: &mut dyn FnMut() -> crate::error::Result<()>| write(),
        )
        .expect("a launch that never started does not hold privacy mode on");
}

/// KR-REQ-24.27: a create's deadline passes while it waits for a change of privacy mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_whose_deadline_passes_while_it_waits_for_the_record_starts_nothing() {
    a_create_whose_admission_lapses_while_it_waits_for_the_record(Lapse::Deadline).await;
}

/// KR-REQ-24.27: the connection a create arrived on is withdrawn while it waits for a change of
/// privacy mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_whose_connection_is_withdrawn_while_it_waits_for_the_record_starts_nothing() {
    a_create_whose_admission_lapses_while_it_waits_for_the_record(Lapse::Withdrawal).await;
}

/// KR-REQ-24.27: a create whose session's obligation cannot be written is refused with the store's
/// reason, and starts nothing: its reservation is resolved as failed, and nothing is owed for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_whose_obligation_cannot_be_written_starts_nothing() {
    let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (temp, controller, _clock) = daemon_starting(|state_dir| {
        Box::new(Recording {
            state_dir: state_dir.to_path_buf(),
            asked: Arc::clone(&asked),
        })
    })
    .await;
    controller
        .privacy
        .enable(&[], kr_ipc::now_ms(), &|write| write())
        .expect("privacy mode is turned on");
    rusqlite::Connection::open(temp.environment().state_dir().join(PRIVACY_RECORD))
        .expect("a second connection to the record")
        .execute_batch(
            "CREATE TRIGGER refuse_the_obligation BEFORE INSERT ON privacy_obligations
             BEGIN SELECT RAISE(ABORT, 'this store refused the obligation'); END;",
        )
        .expect("the store will refuse the obligation");
    let (actor_id, carried) = admitted(&controller).await;
    let refused = controller
        .session_create(&actor_id, &create_request(temp.environment_id()), carried)
        .await
        .expect_err("a create whose obligation cannot be recorded starts nothing");
    assert!(
        refused.to_string().contains("refused the obligation"),
        "{refused}"
    );
    assert!(
        asked.lock().expect("the record is not poisoned").is_empty(),
        "no worker was asked for"
    );
    let registry = controller.registry.lock().await;
    assert_eq!(
        registry
            .reservations_in(LaunchPhase::Failed)
            .expect("a read")
            .len(),
        1,
        "the reservation is resolved rather than left occupying the environment"
    );
    assert_eq!(registry.occupancy().expect("counts"), 0);
    drop(registry);
    assert!(
        controller
            .privacy
            .status(kr_ipc::now_ms())
            .sessions
            .is_empty(),
        "nothing is owed for a launch that was refused"
    );
}

/// KR-REQ-24.28: turning privacy mode on after a restart finds a launch whose worker was handed a
/// specification before it, which this daemon's own record of launches no longer holds and whose
/// worker has no journal or worker row yet: the registry says a worker may be running there, so
/// the session owes its cleanup. A reservation no worker can come of, one fenced before any worker
/// claimed it, and one not yet launched, owe nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn privacy_mode_turned_on_obliges_every_launch_a_worker_may_still_come_of() {
    let (temp, controller, _clock) = daemon().await;
    let environment_id = temp.environment_id();
    // Its launcher is running, so a claim may still come.
    let spawned = reserved(&controller, 1, LaunchPhase::Spawned).await;
    launched_by(&controller, spawned, &running_launcher()).await;
    let claim = claimed(&controller, 2, None).await;
    let fenced = claimed(&controller, 3, Some(LaunchPhase::Fenced)).await;
    let _reserved = reserved(&controller, 4, LaunchPhase::Reserved).await;
    let _failed = reserved(&controller, 5, LaunchPhase::Failed).await;
    let _closed = reserved(&controller, 6, LaunchPhase::Closed).await;
    // Fenced before any worker claimed it: nobody was handed a specification.
    let _fenced_before_a_claim = reserved(&controller, 7, LaunchPhase::Fenced).await;

    let (_actor, carried) = admitted(&controller).await;
    let report = controller
        .privacy_set(
            &request(
                Method::PrivacySet,
                environment_id,
                &PrivacySetParams { enabled: true },
            ),
            carried,
        )
        .await
        .expect("privacy mode is turned on");
    let report: kr_protocol::privacy::PrivacyReport = report.to_typed().expect("decodes");
    let mut owing: Vec<SessionId> = report.sessions.iter().map(|owed| owed.session_id).collect();
    owing.sort_unstable();
    let mut expected = vec![spawned, claim, fenced];
    expected.sort_unstable();
    assert_eq!(owing, expected);
    assert_eq!(obligations_on_disk(&temp), 3);
}

/// KR-REQ-24.28: a create whose supervisor cannot say what it started leaves its reservation
/// spawned, and what the launch owes depends on whether a claim can still come. With no process
/// reported, no launcher is recorded and no claim can be accepted, so the tick forgets the session
/// and its obligation; with the launcher's process reported and running, the launcher is recorded
/// and a worker may still claim, so the session stays owed and holds privacy mode on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_that_cannot_say_what_it_started_leaves_a_launch_forgotten_unless_its_launcher_runs()
 {
    for (pid, forgotten_by_the_tick) in [(None, true), (Some(std::process::id()), false)] {
        let (temp, controller, _clock) =
            daemon_starting(move |_| Box::new(Uncertain { pid })).await;
        controller
            .privacy
            .enable(&[], kr_ipc::now_ms(), &|write| write())
            .expect("privacy mode is turned on");
        let (actor_id, carried) = admitted(&controller).await;
        controller
            .session_create(&actor_id, &create_request(temp.environment_id()), carried)
            .await
            .expect_err("a create that cannot say what it started fails");
        let spawned = controller
            .registry
            .lock()
            .await
            .reservations_in(LaunchPhase::Spawned)
            .expect("a read");
        assert_eq!(spawned.len(), 1, "{pid:?}: the reservation stays spawned");
        assert_eq!(
            spawned[0].launcher_identity.is_some(),
            pid.is_some(),
            "{pid:?}: a launcher is recorded when a process was reported"
        );
        let session_id = spawned[0].session_id;
        if forgotten_by_the_tick {
            forgotten(&controller, &[session_id]).await;
            assert_eq!(obligations_on_disk(&temp), 0);
        } else {
            tokio::time::sleep(super::start::PRIVACY_TICK * 3).await;
            assert_eq!(
                obligations_on_disk(&temp),
                1,
                "{pid:?}: a worker may still claim, so the session stays owed"
            );
            controller
                .privacy
                .disable(
                    kr_ipc::now_ms(),
                    &|write: &mut dyn FnMut() -> crate::error::Result<()>| write(),
                )
                .expect_err("and holds privacy mode on");
        }
    }
}
