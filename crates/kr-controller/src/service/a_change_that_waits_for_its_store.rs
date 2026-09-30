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
//! The tick that decides which sessions have ended is tested here too: it takes a session for ended
//! only when the registry shows its launch is over.

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
pub(super) async fn daemon() -> (kr_ipc::testing::TempHost, Arc<Controller>, ManualClock) {
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
            supervisor: Box::new(NoWorkers),
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

/// KR-REQ-24.28: a reservation in any phase before its launch has failed or its session has
/// closed is a worker that may be starting or running, so its session is not over; a session the
/// registry holds no reservation for, one whose launch failed and one that closed are.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_launch_is_over_only_when_no_worker_can_still_come_of_it() {
    let (_temp, controller, _clock) = daemon().await;
    let mut asked: Vec<SessionId> = Vec::new();
    let mut expected: Vec<SessionId> = Vec::new();
    for (token, (phase, over)) in [
        (LaunchPhase::Reserved, false),
        (LaunchPhase::Spawned, false),
        (LaunchPhase::Claimed, false),
        (LaunchPhase::Live, false),
        (LaunchPhase::Fenced, false),
        (LaunchPhase::Failed, true),
        (LaunchPhase::Closed, true),
    ]
    .into_iter()
    .enumerate()
    {
        let session_id = reserved(
            &controller,
            u8::try_from(token).expect("a small token") + 1,
            phase,
        )
        .await;
        asked.push(session_id);
        if over {
            expected.push(session_id);
        }
    }
    // A session the registry holds nothing for is over too: no launch can come of it.
    let unknown = SessionId::new(kr_ipc::new_uuid());
    asked.push(unknown);
    expected.push(unknown);

    let mut over = super::start::launches_over(&controller, &asked).await;
    over.sort_unstable();
    expected.sort_unstable();
    assert_eq!(over, expected);
    assert!(
        super::start::launches_over(&controller, &[])
            .await
            .is_empty(),
        "nothing asked, nothing over"
    );
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
/// reservation was fenced. Through every pass of the tick each may still have a worker, so turning
/// privacy mode off is refused; it stays refused while one of them is left, and once the registry
/// records that both launches failed the next pass takes them for ended and privacy mode is turned
/// off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_tick_ends_a_session_only_once_the_registry_shows_its_launch_is_over() {
    let (_temp, controller, _clock) = daemon().await;
    let claimed = reserved(&controller, 1, LaunchPhase::Claimed).await;
    let fenced = reserved(&controller, 2, LaunchPhase::Fenced).await;
    let standing = |write: &mut dyn FnMut() -> crate::error::Result<()>| write();
    controller
        .privacy
        .enable(&[claimed, fenced], kr_ipc::now_ms(), &standing)
        .expect("privacy mode is turned on");

    // The tick passes over both, more than once, and neither is taken for ended.
    tokio::time::sleep(super::start::PRIVACY_TICK * 3).await;
    let refused = controller
        .privacy
        .disable(kr_ipc::now_ms(), &standing)
        .expect_err("a launch that may still produce a worker holds privacy mode on");
    for session_id in [claimed, fenced] {
        assert!(
            refused.to_string().contains(&session_id.to_string()),
            "the refusal names the session: {refused}"
        );
    }

    // One launch is over, and the other may still produce a worker. The pass that takes the first
    // for ended is a pass that has read the registry with the second fenced, so once it has been
    // seen the second is known to have been passed over, and it holds the change back.
    recorded_as(&controller, claimed, LaunchPhase::Failed).await;
    ended(&controller, &[claimed]).await;
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

    // Both are over: the next pass takes them for ended, and privacy mode is turned off.
    recorded_as(&controller, fenced, LaunchPhase::Failed).await;
    ended(&controller, &[claimed, fenced]).await;
    let off = controller
        .privacy
        .disable(kr_ipc::now_ms(), &standing)
        .expect("sessions whose launches are over do not hold privacy mode on");
    assert!(!off.enabled);
}
