use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_crypto::store::MemoryStore;
use kr_ipc::peer::PeerIdentity;
use kr_protocol::envelope::{ActionTarget, MutationRequest, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, ActionWindowId, BuildId, ConnectionId, RequestId};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{DurationMs, Nullable};
use kr_protocol::session::{LaunchProfile, Presentation, SessionCreateParams, ShellMode};
use kr_transport::window::{AcceptedDeadline, DeadlineBound};

use crate::error::ControllerError;
use crate::registry::LaunchPhase;
use crate::service::{Controller, ControllerSetup};
use crate::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};

/// A supervisor that records what it was asked to start, and starts nothing.
#[derive(Debug, Default)]
struct RecordingSupervisor {
    asked: Arc<Mutex<Vec<WorkerLaunch>>>,
}

impl WorkerSupervisor for RecordingSupervisor {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        self.asked
            .lock()
            .expect("the record is not poisoned")
            .push(launch.clone());
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that records every launch and starts nothing"
    }
}

/// A reservation recorded before the launch profile existed still names its session's context.
#[test]
fn a_create_request_recorded_by_an_earlier_build_is_read_with_the_defaults() {
    use kr_protocol::session::{LaunchProfile, Presentation, ShellMode};

    let environment_id =
        kr_protocol::ids::EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([3; 16]));
    let legacy = super::create::RecordedCreate {
        environment_id,
        presentation: Presentation::Terminal,
        shell: Nullable::some("zsh".to_owned()),
        shell_mode: ShellMode::Managed,
        cwd: Nullable::some("/work".to_owned()),
        dimensions: Nullable::null(),
        worker_profile: kr_protocol::identity::WorkerProfile::DesktopBound,
        environment_snapshot: Vec::new(),
        palette: Nullable::null(),
    };
    let recorded = kr_cbor::to_canonical_vec(&legacy).expect("encodes");
    let read =
        super::create::recorded_create(&recorded).expect("an earlier build's record still reads");
    assert_eq!(
        read.worker_profile,
        kr_protocol::identity::WorkerProfile::DesktopBound,
        "the execution context is the one that was recorded, never a substituted default"
    );
    assert_eq!(read.presentation, Presentation::Terminal);
    assert_eq!(read.launch_profile, LaunchProfile::default());
    assert!(read.terminal.0.is_none());

    // This build's own shape reads as itself, and a record that is neither is refused.
    let current = kr_cbor::to_canonical_vec(&create_params(environment_id)).expect("encodes");
    assert!(super::create::recorded_create(&current).is_ok());
    assert!(super::create::recorded_create(b"not a record").is_err());
}

fn create_params(environment_id: kr_protocol::ids::EnvironmentId) -> SessionCreateParams {
    SessionCreateParams {
        environment_id,
        presentation: Presentation::Invisible,
        shell: Nullable::null(),
        shell_mode: ShellMode::NativeCompat,
        cwd: Nullable::some("/".to_owned()),
        dimensions: Nullable::null(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        environment_snapshot: Vec::new(),
        palette: Nullable::null(),
        launch_profile: LaunchProfile::default(),
        terminal: Nullable::null(),
    }
}

fn create_request(environment_id: kr_protocol::ids::EnvironmentId) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(1),
        method: Method::SessionCreate.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget::environment(environment_id),
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("local:test").expect("a window"),
        requested_ttl_ms: DurationMs::new(30_000),
        params: ParamsValue::from_typed(&create_params(environment_id)).expect("encodes"),
    }
}

/// Starts a daemon on a tree of its own, with a supervisor that starts nothing.
/// The admission a create carries in these tests: this connection, the revision in force and
/// the deadline the host accepted.
fn carried(
    controller: &Controller,
    connection_id: ConnectionId,
    accepted: AcceptedDeadline,
) -> crate::authority::AdmittedMutation {
    crate::authority::AdmittedMutation {
        connection_id,
        admitted_revision: controller.leases.authority_revision(),
        deadline: Some(accepted.deadline),
    }
}

/// Holds this daemon's connection table the way a create's own transition reads it.
///
/// The table is a synchronous lock, so it is held on a blocking thread rather than across an
/// await: holding it in this task would stop the runtime the create needs rather than pause
/// the create.
struct HeldConnections {
    release: Option<std::sync::mpsc::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl HeldConnections {
    fn hold(controller: &Arc<Controller>) -> Self {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (held, confirmed) = std::sync::mpsc::channel::<()>();
        let controller = Arc::clone(controller);
        let task = tokio::task::spawn_blocking(move || {
            let _table = controller.admitted_table();
            held.send(()).expect("the test is waiting");
            // Held until the test releases it. The receiver ends when the sender is dropped,
            // so a test that panics does not leave the table locked for the rest of the suite.
            let _ = wait.recv();
        });
        confirmed.recv().expect("the connection table is held");
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

async fn daemon() -> (
    kr_ipc::testing::TempHost,
    Arc<Controller>,
    Arc<Mutex<Vec<WorkerLaunch>>>,
) {
    let temp = kr_ipc::testing::TempHost::create();
    let program = temp.root().join("kr-worker");
    let (controller, asked) = daemon_running(&temp, program, None).await;
    (temp, controller, asked)
}

/// Starts a daemon told to launch `program`, which may be a relative name.
///
/// `shell_packages` is where the daemon looks for qualified shell packages. A test that says
/// where they are describes an installation of its own rather than reading the one this machine
/// happens to have.
async fn daemon_running(
    temp: &kr_ipc::testing::TempHost,
    program: std::path::PathBuf,
    shell_packages: Option<std::path::PathBuf>,
) -> (Arc<Controller>, Arc<Mutex<Vec<WorkerLaunch>>>) {
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let controller =
        Controller::start(ControllerSetup {
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
            supervisor: Box::new(RecordingSupervisor {
                asked: Arc::clone(&asked),
            }),
            worker_program: program,
            build_id: BuildId::new("kr-test/0").expect("a build identifier"),
            release: "0".to_owned(),
            shell_packages,
            terminal: Box::new(crate::supervision::NoTerminal),
        })
        .await
        .expect("the daemon starts");
    (controller, asked)
}

/// Registers one connection, the way a caller's handshake does.
async fn admitted(controller: &Controller) -> (ConnectionId, kr_protocol::ids::ActorId) {
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
    (connection_id, actor_id)
}

/// Waits until the create under test has written its reservation, and fails the test when it
/// has not within thirty seconds: a create that stopped before its reservation would otherwise
/// hold the test, and the job running it, for ever.
async fn reserved(controller: &Controller) {
    const BOUND: Duration = Duration::from_secs(30);
    tokio::time::timeout(BOUND, async {
        loop {
            let registry = controller.registry.lock().await;
            let reserved = registry
                .reservations_in(LaunchPhase::Reserved)
                .expect("reads the reservations");
            drop(registry);
            if !reserved.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the create wrote no reservation within {BOUND:?}"));
}

/// KR-REQ-08.44: an invisible session has no terminal, so probed colours are refused.
///
/// Before the reservation, because this is a request the host can never serve rather than one
/// the environment happens to have no room for: nothing is started, nothing is reserved, and
/// the caller is told which of its own fields disagree.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invisible_creation_cannot_adopt_a_probed_palette() {
    use kr_protocol::projection::Rgb;
    use kr_protocol::session::{PalettePreset, PaletteRequest, ProbedPalette};

    let (temp, controller, asked) = daemon().await;
    let environment_id = temp.environment_id();
    let (connection_id, actor_id) = admitted(&controller).await;
    let accepted = AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(Duration::from_secs(30))
            .expect("a deadline half a minute out"),
        bound: DeadlineBound::RequestedTtl,
    };

    let mut probed = create_request(environment_id);
    probed.params = ParamsValue::from_typed(&SessionCreateParams {
        palette: Nullable::some(PaletteRequest::Probe(ProbedPalette {
            foreground: Rgb {
                red: 0xd0,
                green: 0xd0,
                blue: 0xd0,
            },
            background: Rgb {
                red: 0x10,
                green: 0x10,
                blue: 0x18,
            },
        })),
        ..create_params(environment_id)
    })
    .expect("encodes");
    let error = controller
        .session_create(
            &actor_id,
            &probed,
            carried(&controller, connection_id, accepted),
        )
        .await
        .expect_err("an invisible session has no terminal to have probed");
    assert_eq!(
        error.code(),
        ErrorCode::InvalidArgument,
        "the refusal is about the request rather than about this host: {error}"
    );
    assert!(
        error.to_string().contains("no terminal to probe"),
        "and it says which field disagrees with which: {error}"
    );
    assert!(
        asked.lock().expect("the record is not poisoned").is_empty(),
        "no worker is started for a create the host refused"
    );
    let registry = controller.registry.lock().await;
    assert_eq!(
        registry.occupancy().expect("counts"),
        0,
        "and the refusal takes no reservation at all"
    );
    drop(registry);

    // The same session, with a preset, is exactly what section 8 says an invisible creation
    // selects. It reaches the launch, which this supervisor refuses for its own reasons.
    let mut preset = create_request(environment_id);
    preset.params = ParamsValue::from_typed(&SessionCreateParams {
        palette: Nullable::some(PaletteRequest::Preset(PalettePreset::Dark)),
        ..create_params(environment_id)
    })
    .expect("encodes");
    let outcome = controller
        .session_create(
            &actor_id,
            &preset,
            carried(&controller, connection_id, accepted),
        )
        .await;
    assert!(
        outcome.is_err(),
        "this test's supervisor starts nothing, so the create cannot succeed"
    );
    let launches = asked.lock().expect("the record is not poisoned").len();
    assert_eq!(
        launches, 1,
        "but a preset is admitted and reaches the launch"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_that_waited_across_a_revocation_launches_nothing() {
    let (temp, controller, asked) = daemon().await;
    let environment_id = temp.environment_id();
    let (connection_id, actor_id) = admitted(&controller).await;

    let accepted = AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(Duration::from_secs(30))
            .expect("a deadline half a minute out"),
        bound: DeadlineBound::RequestedTtl,
    };
    let mutation = create_request(environment_id);

    // The create stops here, between its reservation and the transition to `spawned`.
    let paused_pending = controller.pending.lock().await;
    let create = tokio::spawn({
        let controller = Arc::clone(&controller);
        let actor_id = actor_id.clone();
        async move {
            controller
                .session_create(
                    &actor_id,
                    &mutation,
                    carried(&controller, connection_id, accepted),
                )
                .await
        }
    });
    // The reservation is durable before the launch, so its row is what says the create has
    // reached the point this test is about.
    reserved(&controller).await;

    // The revocation completes while the create waits: the revision is advanced and every
    // registration made under the old one is withdrawn.
    controller
        .revoke_authority()
        .await
        .expect("the revocation completes");
    drop(paused_pending);

    let outcome = create.await.expect("the create finishes");
    let error = outcome.expect_err("a create whose authority was withdrawn starts nothing");
    assert_eq!(
        error.code(),
        ErrorCode::PermissionDenied,
        "the receipt says the authority behind the create was withdrawn: {error}"
    );
    assert!(
        matches!(error, ControllerError::PermissionDenied { .. }),
        "the refusal names the withdrawn registration: {error}"
    );
    assert!(
        asked.lock().expect("the record is not poisoned").is_empty(),
        "no worker is started for a create the host refused"
    );
    let registry = controller.registry.lock().await;
    assert_eq!(
        registry
            .reservations_in(LaunchPhase::Failed)
            .expect("reads the reservations")
            .len(),
        1,
        "the refused create is resolved rather than left occupying the environment"
    );
    assert_eq!(
        registry.occupancy().expect("counts"),
        0,
        "the reservation it made is released"
    );
}

/// The deadline is the last thing checked before the launch.
///
/// Reading the registration waits, and a create that queues behind a revocation taking the
/// connection table can spend the rest of its accepted lifetime there. A registration that
/// still stands is not permission to start a shell under a deadline that has since passed.
/// KR-REQ-07.10: a create's accepted deadline bounds it, and past it nothing is launched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_whose_deadline_passed_while_it_waited_launches_nothing() {
    let (temp, controller, asked) = daemon().await;
    let environment_id = temp.environment_id();
    let (connection_id, actor_id) = admitted(&controller).await;

    let accepted = AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(Duration::from_millis(300))
            .expect("a deadline a moment out"),
        bound: DeadlineBound::RequestedTtl,
    };
    let mutation = create_request(environment_id);

    // The create stops at the transition to `spawned`, which reads the connection table.
    let paused = HeldConnections::hold(&controller);
    let create = tokio::spawn({
        let controller = Arc::clone(&controller);
        let actor_id = actor_id.clone();
        async move {
            controller
                .session_create(
                    &actor_id,
                    &mutation,
                    carried(&controller, connection_id, accepted),
                )
                .await
        }
    });
    // Long enough for the deadline to pass while the create is held here. The registry lock
    // is held by the create while it waits for the connection table, so nothing here asks the
    // registry what the create has reached: the deadline is absolute, and a create that has
    // not started yet still finds it spent by the time it looks.
    tokio::time::sleep(Duration::from_millis(600)).await;
    paused.release().await;

    let outcome = create.await.expect("the create finishes");
    let error = outcome.expect_err("a create whose deadline has passed starts nothing");
    assert_eq!(
        error.code(),
        ErrorCode::PermissionDenied,
        "an expired freshness window is refused as such: {error}"
    );
    assert!(
        matches!(error, ControllerError::WindowExpired { .. }),
        "the receipt says the deadline passed: {error}"
    );
    assert!(
        asked.lock().expect("the record is not poisoned").is_empty(),
        "no worker is started for a create the host refused"
    );
    let registry = controller.registry.lock().await;
    assert_eq!(
        registry.occupancy().expect("counts"),
        0,
        "the reservation it made is released"
    );
}

/// A create whose registration survived a revocation is still refused: it was admitted under
/// the revision before it.
///
/// One device's revocation advances the revision and leaves every other connection registered,
/// at the revision now in force. What that connection may do is submit new work; what it may
/// not do is finish work admitted before the revocation, and the admission this create carries
/// is what says which this is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_admitted_before_a_revision_is_refused_though_its_connection_stands() {
    let (temp, controller, asked) = daemon().await;
    let environment_id = temp.environment_id();
    let (connection_id, actor_id) = admitted(&controller).await;

    let accepted = AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(Duration::from_secs(30))
            .expect("a deadline half a minute out"),
        bound: DeadlineBound::RequestedTtl,
    };
    // The admission this create carries, taken at the revision in force now.
    let admitted_at = carried(&controller, connection_id, accepted);

    // The revision advances and this connection keeps its registration *at the revision now in
    // force*, which is exactly what a revocation of somebody else's device leaves behind.
    {
        let mut registry = controller.registry.lock().await;
        registry
            .advance_authority_revision()
            .expect("the revision advances");
        let revision = registry
            .authority_revision()
            .expect("the revision in force");
        let mut admitted = controller.admitted_table();
        for connection in admitted.values_mut() {
            connection.admitted_revision = revision;
        }
    }
    // So new work from that connection is admitted: what is refused below is not the
    // registration but the revision this create was admitted under.
    {
        let registry = controller.registry.lock().await;
        let fresh = crate::authority::AdmittedMutation {
            connection_id,
            admitted_revision: registry
                .authority_revision()
                .expect("the revision in force"),
            deadline: Some(accepted.deadline),
        };
        controller
            .check_admission(&registry, &fresh)
            .expect("new work from this connection is admitted at the revision in force");
    }

    let error = controller
        .session_create(&actor_id, &create_request(environment_id), admitted_at)
        .await
        .expect_err("a create admitted under the revision before is refused");
    assert!(
        matches!(error, ControllerError::PermissionDenied { .. }),
        "the authority it was admitted under was withdrawn: {error}"
    );
    assert!(
        asked.lock().expect("the record is not poisoned").is_empty(),
        "no worker is started for a create the host refused"
    );
    let registry = controller.registry.lock().await;
    assert_eq!(
        registry.occupancy().expect("counts"),
        0,
        "the reservation it made is released"
    );
}

/// A managed create with no qualified package is refused on the path every ingress takes.
///
/// The local endpoint checks its own envelope before it dispatches; a caller on the network
/// reaches `session_create` directly. The package check belongs to the create itself, so this
/// drives the create the way the network path does and expects the same named refusal, with
/// nothing reserved and nothing started.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_managed_create_that_did_not_pass_a_local_envelope_is_refused_the_same_way() {
    let temp = kr_ipc::testing::TempHost::create();
    // An installation of this test's own, with no package in it, so the refusal is this
    // request's shell rather than whatever this machine happens to have installed.
    let packages = temp.root().join("packages");
    std::fs::create_dir_all(&packages).expect("creates the package root");
    let (controller, asked) =
        daemon_running(&temp, temp.root().join("kr-worker"), Some(packages)).await;
    let environment_id = temp.environment_id();
    let (connection_id, actor_id) = admitted(&controller).await;

    let error = controller
        .session_create(
            &actor_id,
            &managed_request(environment_id),
            carried(&controller, connection_id, half_a_minute(&controller)),
        )
        .await
        .expect_err("a shell no package qualifies is refused");
    assert_eq!(
        error.code(),
        kr_protocol::error::ErrorCode::ShellIntegrationUnsupported,
        "{error}"
    );
    assert!(
        asked.lock().expect("the record is not poisoned").is_empty(),
        "nothing is started for a shell no package qualifies"
    );
    let registry = controller.registry.lock().await;
    assert_eq!(
        registry.occupancy().expect("counts"),
        0,
        "and nothing is reserved either"
    );
}

/// A worker's own report never waits behind a look at somebody else's silent process.
///
/// A look and a publication take one reservation between them, because a challenge presents a
/// generation token and one presented mid-publication fences the connection the daemon has just
/// opened. Two reservations are two different questions: a worker that reported itself must not
/// sit behind a challenge to a process that will never answer, because its create is waiting on
/// a deadline of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_report_does_not_wait_for_a_look_at_another_reservation() {
    use kr_crypto::keys::AuthorisationKeyPair;
    use kr_ipc::endpoint::Listener;

    let (temp, controller, _asked) = daemon().await;
    let environment = temp.environment();
    let actor_id = kr_protocol::ids::ActorId::new("local:test").expect("a principal");

    // One claimed reservation whose worker accepts a connection and answers nothing, so a look
    // at it waits out the whole challenge.
    let silent = seed_claim(&controller, &actor_id).await;
    let silent_endpoint = environment
        .worker_endpoint(silent.display_number)
        .expect("an endpoint");
    let _silent_listener = Listener::bind(&silent_endpoint).expect("binds a silent worker");

    // Another reservation, whose worker is about to report itself.
    let ready = seed_claim(&controller, &actor_id).await;
    let keys = AuthorisationKeyPair::generate().expect("a key");
    let process = kr_ipc::identity::current_process_start_identity().expect("this process");
    let claim = kr_protocol::worker::WorkerRendezvous {
        reservation_id: kr_protocol::worker::ReservationId::new(ready.reservation_id.get()),
        session_id: ready.session_id,
        worker_public_key: *keys.public(),
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        process_start_identity: process.clone(),
        // The claim is not verified here: `record_ready` records what an admitted claim said.
        signature: kr_crypto::sign::sign_elements(&keys, "kr-test/record-ready", Vec::new())
            .expect("a signature"),
    };
    let report = kr_protocol::worker::WorkerReady {
        session_id: ready.session_id,
        endpoint: environment
            .worker_endpoint(ready.display_number)
            .expect("an endpoint")
            .as_text(),
        root_process: process,
        shell_path: "/bin/cat".to_owned(),
        dimensions: kr_protocol::session::Dimensions::new(80, 24),
        session: Box::new(
            super::a_close_a_worker_never_answers::read_result(ready.session_id).session,
        ),
    };

    // The look starts first and is still inside the silent worker's challenge.
    let looking = {
        let controller = Arc::clone(&controller);
        tokio::spawn(async move { controller.recover_claims().await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!looking.is_finished(), "the look is inside its challenge");

    // The report goes through on its own reservation, without waiting for that look.
    tokio::time::timeout(
        Duration::from_secs(2),
        controller.record_ready(ready.reservation_id, &claim, &report),
    )
    .await
    .expect("a report does not wait for another reservation's look")
    .expect("records the worker");
    assert!(
        controller
            .directory
            .lock()
            .await
            .get(ready.session_id)
            .is_some(),
        "and the session it published is there"
    );
    looking.abort();
}

/// A worker's own report and a look at *its* reservation do not overlap.
///
/// The hold is per reservation, and the point of it is this: a challenge presents a generation
/// token, and one presented while that reservation's own report is being published fences the
/// connection the daemon has just opened. The two therefore take turns, and which of them goes
/// first does not matter as long as neither is inside the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_report_waits_for_a_look_at_its_own_reservation() {
    use kr_crypto::keys::AuthorisationKeyPair;
    use kr_ipc::endpoint::Listener;

    let (temp, controller, _asked) = daemon().await;
    let environment = temp.environment();
    let actor_id = kr_protocol::ids::ActorId::new("local:test").expect("a principal");

    // One reservation, whose worker accepts a connection and answers nothing. A look at it
    // therefore stays inside its challenge for as long as this test needs.
    let reservation = seed_claim(&controller, &actor_id).await;
    let endpoint = environment
        .worker_endpoint(reservation.display_number)
        .expect("an endpoint");
    let _listener = Listener::bind(&endpoint).expect("binds the silent worker");

    let keys = AuthorisationKeyPair::generate().expect("a key");
    let process = kr_ipc::identity::current_process_start_identity().expect("this process");
    let claim = kr_protocol::worker::WorkerRendezvous {
        reservation_id: kr_protocol::worker::ReservationId::new(reservation.reservation_id.get()),
        session_id: reservation.session_id,
        worker_public_key: *keys.public(),
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        process_start_identity: process.clone(),
        signature: kr_crypto::sign::sign_elements(&keys, "kr-test/record-ready", Vec::new())
            .expect("a signature"),
    };
    let report = kr_protocol::worker::WorkerReady {
        session_id: reservation.session_id,
        endpoint: endpoint.as_text(),
        root_process: process,
        shell_path: "/bin/cat".to_owned(),
        dimensions: kr_protocol::session::Dimensions::new(80, 24),
        session: Box::new(
            super::a_close_a_worker_never_answers::read_result(reservation.session_id).session,
        ),
    };

    // The look starts first and is inside this reservation's challenge.
    let looking = {
        let controller = Arc::clone(&controller);
        tokio::spawn(async move { controller.recover_claims().await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!looking.is_finished(), "the look is inside its challenge");

    // The report is about the same reservation, so it waits rather than publishing underneath
    // a challenge that is still in flight.
    let held = tokio::time::timeout(
        Duration::from_secs(1),
        controller.record_ready(reservation.reservation_id, &claim, &report),
    )
    .await;
    assert!(
        held.is_err(),
        "a report does not publish while a look at its own reservation is in flight"
    );
    assert!(
        controller
            .directory
            .lock()
            .await
            .get(reservation.session_id)
            .is_none(),
        "and nothing of it reached the directory"
    );

    // The look ends, and the report goes through on its own.
    looking.abort();
    let _ = looking.await;
    tokio::time::timeout(
        Duration::from_secs(5),
        controller.record_ready(reservation.reservation_id, &claim, &report),
    )
    .await
    .expect("the report goes through once the look has let go")
    .expect("records the worker");
    assert!(
        controller
            .directory
            .lock()
            .await
            .get(reservation.session_id)
            .is_some(),
        "and the session it published is there"
    );
}

/// Records a reservation in the phase a worker's claim leaves it in.
async fn seed_claim(
    controller: &Controller,
    actor_id: &kr_protocol::ids::ActorId,
) -> crate::registry::Reservation {
    seed_claim_as(
        controller,
        actor_id,
        kr_protocol::identity::WorkerProfile::HeadlessUser,
        |_| {
            *kr_crypto::keys::AuthorisationKeyPair::generate()
                .expect("a key")
                .public()
        },
    )
    .await
}

/// As [`seed_claim`], for a session of `profile`, with the key the claim names chosen once the
/// reservation, and so the session, is known: a worker that is to answer a challenge for the
/// session has to be made for it.
async fn seed_claim_as(
    controller: &Controller,
    actor_id: &kr_protocol::ids::ActorId,
    profile: kr_protocol::identity::WorkerProfile,
    key_of: impl FnOnce(&crate::registry::Reservation) -> kr_protocol::scalars::AuthorisationKey,
) -> crate::registry::Reservation {
    let mut registry = controller.registry.lock().await;
    // A reservation records the create request it was made for, because that is what a later
    // launch and a later publication both read the session's own context out of.
    let intent = kr_cbor::to_canonical_vec(&SessionCreateParams {
        worker_profile: profile,
        ..create_params(controller.paths.environment_id())
    })
    .expect("encodes");
    let admission = registry
        .reserve(
            actor_id,
            kr_ipc::new_uuid(),
            kr_protocol::scalars::Digest256::from_bytes([0x3c; 32]),
            &intent,
            kr_ipc::now_ms(),
        )
        .expect("reserves");
    let reservation_id = admission.reservation.reservation_id;
    registry
        .set_phase(reservation_id, LaunchPhase::Spawned)
        .expect("spawned");
    let key = key_of(&admission.reservation);
    registry
        .claim_rendezvous(reservation_id, key)
        .expect("claims")
}

/// A worker that answers the daemon's challenge as the worker of `identity`'s session and, when
/// its session is read, describes the session `described` as bound to `desktop`.
fn worker_stating(
    listener: kr_ipc::endpoint::Listener,
    identity: Arc<kr_ipc::verify::WorkerIdentity>,
    endpoint_text: String,
    described: kr_protocol::ids::SessionId,
    desktop: kr_protocol::identity::DesktopBinding,
) -> tokio::task::JoinHandle<()> {
    use kr_protocol::envelope::{ControlFrame, Outcome, Response};
    use kr_protocol::frame::StreamKind;
    use kr_protocol::scalars::CanonicalSet;

    tokio::spawn(async move {
        loop {
            let Ok((connection, peer)) = listener.accept().await else {
                return;
            };
            let identity = Arc::clone(&identity);
            let endpoint_text = endpoint_text.clone();
            let desktop = desktop.clone();
            tokio::spawn(async move {
                let (mut reader, mut writer) =
                    kr_ipc::framed::split(connection, StreamKind::Control);
                let connection_id = ConnectionId::new(kr_ipc::new_uuid());
                while let Ok(frame) = reader.read_message::<ControlFrame>().await {
                    let answers = match super::a_close_a_worker_never_answers::handshake(
                        &frame,
                        &identity,
                        &endpoint_text,
                        connection_id,
                        &peer,
                        &CanonicalSet::new(),
                    ) {
                        Some(answers) => answers,
                        None => match frame {
                            ControlFrame::Request(request)
                                if request.method == Method::SessionRead.into() =>
                            {
                                let mut read =
                                    super::a_close_a_worker_never_answers::read_result(described);
                                read.session.desktop = desktop.clone();
                                vec![ControlFrame::Response(Response {
                                    request_id: request.request_id,
                                    outcome: Outcome::Ok(
                                        ParamsValue::from_typed(&read).expect("encodes"),
                                    ),
                                })]
                            }
                            _ => Vec::new(),
                        },
                    };
                    for answer in answers {
                        if writer.write_message(&answer).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    })
}

/// KR-REQ-24.01: the desktop identity a worker states in its ready report is recorded with its
/// row, and a daemon that starts again on the environment reads it back: the desktop session and
/// the login-session generation the worker is bound to, not what this host reads of its own
/// desktop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_workers_desktop_identity_is_recorded_from_its_report_and_read_back_after_a_restart() {
    use kr_protocol::identity::{DesktopBinding, WorkerProfile};
    use kr_protocol::ids::DesktopSessionId;
    use kr_protocol::scalars::U64;

    let (temp, controller, _asked) = daemon().await;
    let environment = temp.environment();
    let actor_id = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
    let mut worker = None;
    let reservation = seed_claim_as(
        &controller,
        &actor_id,
        WorkerProfile::DesktopBound,
        |reservation| {
            let made = Arc::new(
                kr_ipc::verify::WorkerIdentity::generate(
                    reservation.session_id,
                    kr_protocol::ids::SessionEpoch::V1,
                    kr_ipc::identity::boot_identity().expect("a boot identity"),
                    kr_ipc::identity::process_start_identity(std::process::id())
                        .expect("this process's start identity"),
                    kr_protocol::hello::PROTOCOL_VERSION,
                )
                .expect("a worker identity"),
            );
            let key = *made.public_key();
            worker = Some(made);
            key
        },
    )
    .await;
    let identity = worker.expect("the worker was made for its claim");
    let claim = identity
        .rendezvous(kr_protocol::worker::ReservationId::new(
            reservation.reservation_id.get(),
        ))
        .expect("a startup claim");
    let desktop = DesktopBinding {
        desktop_session_id: Nullable::some(
            DesktopSessionId::new("desktop-501-boot-9-login-4").expect("a desktop identity"),
        ),
        login_generation: Nullable::some(U64::new(4)),
    };
    let mut session =
        super::a_close_a_worker_never_answers::read_result(reservation.session_id).session;
    session.desktop = desktop.clone();
    let report = kr_protocol::worker::WorkerReady {
        session_id: reservation.session_id,
        endpoint: environment
            .worker_endpoint(reservation.display_number)
            .expect("an endpoint")
            .as_text(),
        root_process: identity.process_start_identity().clone(),
        shell_path: "/bin/zsh".to_owned(),
        dimensions: kr_protocol::session::INVISIBLE_DEFAULT_DIMENSIONS,
        session: Box::new(session),
    };
    controller
        .record_ready(reservation.reservation_id, &claim, &report)
        .await
        .expect("records the worker from its report");
    let environment_id = controller.paths.environment_id();
    drop(controller);

    let reopened = crate::registry::Registry::open(environment.registry_database(), environment_id)
        .expect("the registry opens again");
    assert_eq!(
        reopened.desktop_of(reservation.session_id).expect("reads"),
        Some(desktop),
        "the desktop the worker said it was bound to comes back"
    );
}

/// KR-REQ-24.01: a daemon that stopped after a worker took its claim and before the worker's
/// report was recorded recovers the worker by challenge, and its registry row keeps the desktop
/// the worker says it is bound to, as one recorded by the report does. A worker bound to none is
/// recovered as one bound to none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_recovered_by_its_claim_keeps_the_desktop_it_states() {
    use kr_protocol::identity::{DesktopBinding, WorkerProfile};
    use kr_protocol::ids::DesktopSessionId;
    use kr_protocol::scalars::U64;

    let bound = DesktopBinding {
        desktop_session_id: Nullable::some(
            DesktopSessionId::new("desktop-501-boot-9-login-4").expect("a desktop identity"),
        ),
        login_generation: Nullable::some(U64::new(4)),
    };
    // What the worker describes, who it describes, and what the recovered row then holds.
    for (case, profile, stated, describes_another_session, held) in [
        (
            "a worker bound to a desktop",
            WorkerProfile::DesktopBound,
            bound.clone(),
            false,
            bound.clone(),
        ),
        (
            "a worker bound to none",
            WorkerProfile::HeadlessUser,
            DesktopBinding::none(),
            false,
            DesktopBinding::none(),
        ),
        (
            // A description of another session says nothing of this worker's desktop, and what it
            // states is not taken for it.
            "a worker that describes another session",
            WorkerProfile::DesktopBound,
            bound,
            true,
            DesktopBinding::none(),
        ),
    ] {
        let (temp, controller, _asked) = daemon().await;
        let environment = temp.environment();
        let actor_id = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
        let mut worker = None;
        let reservation = seed_claim_as(&controller, &actor_id, profile, |reservation| {
            let identity = Arc::new(
                kr_ipc::verify::WorkerIdentity::generate(
                    reservation.session_id,
                    kr_protocol::ids::SessionEpoch::V1,
                    kr_ipc::identity::boot_identity().expect("a boot identity"),
                    kr_ipc::identity::process_start_identity(std::process::id())
                        .expect("this process's start identity"),
                    kr_protocol::hello::PROTOCOL_VERSION,
                )
                .expect("a worker identity"),
            );
            let key = *identity.public_key();
            worker = Some(identity);
            key
        })
        .await;
        let identity = worker.expect("the worker was made for its claim");
        let endpoint = environment
            .worker_endpoint(reservation.display_number)
            .expect("an endpoint");
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the worker");
        let described = if describes_another_session {
            kr_protocol::ids::SessionId::new(kr_ipc::new_uuid())
        } else {
            reservation.session_id
        };
        let serving = worker_stating(listener, identity, endpoint.as_text(), described, stated);

        controller
            .recover_claims()
            .await
            .expect("the claim is recovered");

        // Read from the file by a registry opened again, as a daemon that starts after this one
        // reads it, and not through the handle that wrote the row.
        let reopened = crate::registry::Registry::open(
            environment.registry_database(),
            controller.paths.environment_id(),
        )
        .expect("the registry opens again");
        assert_eq!(
            reopened
                .desktop_of(reservation.session_id)
                .expect("the registry reads"),
            Some(held),
            "{case}: the recovered row holds what the worker stated of its own session"
        );
        serving.abort();
    }
}

/// KR-REQ-07.09: a daemon starting after a crash settles every launch its predecessor left
/// unresolved before anything could replace it, and launches nothing while it does. A launch
/// whose process is confirmed gone never started a shell and is resolved as failed; a launch
/// whose process may still be running keeps its place rather than being started again; and a
/// worker that took its claim and is gone is recorded as a session that ended abnormally,
/// never as one that did not run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_daemon_settles_every_unresolved_launch_and_launches_nothing() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment_id = temp.environment_id();
    let actor_id = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
    let intent = kr_cbor::to_canonical_vec(&create_params(environment_id)).expect("encodes");
    // An identifier this host watched end, which no process can be mistaken for, and this
    // process, which is certainly running.
    let gone = kr_ipc::identity::ended_process_identity(4_000_000);
    let running =
        kr_ipc::identity::current_process_start_identity().expect("this process's identity");
    let (ended_launch, running_launch, claimed_and_gone) = {
        let mut registry =
            crate::registry::Registry::open(temp.environment().registry_database(), environment_id)
                .expect("the registry a crashed daemon left");
        let mut launched = |launcher: &kr_protocol::identity::ProcessStartIdentity| {
            let reservation = registry
                .reserve(
                    &actor_id,
                    kr_ipc::new_uuid(),
                    kr_protocol::scalars::Digest256::from_bytes([0x5d; 32]),
                    &intent,
                    kr_ipc::now_ms(),
                )
                .expect("reserves")
                .reservation;
            registry
                .record_launch(reservation.reservation_id, launcher)
                .expect("records the launcher");
            registry
                .set_phase(reservation.reservation_id, LaunchPhase::Spawned)
                .expect("spawned");
            reservation
        };
        let ended_launch = launched(&gone);
        let running_launch = launched(&running);
        let claimed_and_gone = launched(&gone);
        registry
            .claim_rendezvous(
                claimed_and_gone.reservation_id,
                *kr_crypto::keys::AuthorisationKeyPair::generate()
                    .expect("a key")
                    .public(),
            )
            .expect("the worker claimed its reservation");
        (ended_launch, running_launch, claimed_and_gone)
    };

    let (controller, asked) = daemon_running(&temp, temp.root().join("kr-worker"), None).await;
    let registry = controller.registry.lock().await;
    let phase = |reservation: &crate::registry::Reservation| {
        registry
            .reservation(reservation.reservation_id)
            .expect("reads")
            .expect("still recorded")
            .phase
    };
    assert_eq!(
        phase(&ended_launch),
        LaunchPhase::Failed,
        "a launch whose process is gone, and which never reached its claim, started nothing"
    );
    assert_eq!(
        phase(&running_launch),
        LaunchPhase::Spawned,
        "a launch that may still be running is kept rather than started again"
    );
    let closure = registry
        .closure(claimed_and_gone.session_id)
        .expect("reads")
        .expect("the claimed launch that is gone is recorded as a session that ended");
    assert_eq!(
        closure.reason,
        kr_protocol::session::ClosureReason::WorkerCrash
    );
    assert_eq!(
        registry.occupancy().expect("counts"),
        1,
        "only the launch that may still be running keeps its place"
    );
    drop(registry);
    assert!(
        asked.lock().expect("the launches").is_empty(),
        "settling what was left launched nothing"
    );
}

/// KR-REQ-24.04: a daemon rebuilds its directory from workers that answer its challenge, not
/// from what its records say. A recorded worker whose endpoint answers nobody and whose process
/// is gone is a stale hint: it is not published again, and the session is recorded as ended
/// rather than listed as running.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recorded_worker_that_answers_nobody_is_not_published_again() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment_id = temp.environment_id();
    let actor_id = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
    let intent = kr_cbor::to_canonical_vec(&create_params(environment_id)).expect("encodes");
    let gone = kr_ipc::identity::ended_process_identity(4_000_001);
    let session_id = {
        let mut registry =
            crate::registry::Registry::open(temp.environment().registry_database(), environment_id)
                .expect("the registry a crashed daemon left");
        let reservation = registry
            .reserve(
                &actor_id,
                kr_ipc::new_uuid(),
                kr_protocol::scalars::Digest256::from_bytes([0x6e; 32]),
                &intent,
                kr_ipc::now_ms(),
            )
            .expect("reserves")
            .reservation;
        registry
            .record_launch(reservation.reservation_id, &gone)
            .expect("records the launcher");
        registry
            .set_phase(reservation.reservation_id, LaunchPhase::Spawned)
            .expect("spawned");
        let key = *kr_crypto::keys::AuthorisationKeyPair::generate()
            .expect("a key")
            .public();
        registry
            .claim_rendezvous(reservation.reservation_id, key)
            .expect("claims");
        // Everything a record can say about a worker, and nothing that proves it is there.
        registry
            .record_worker(
                reservation.reservation_id,
                &crate::registry::WorkerRecord {
                    session_id: reservation.session_id,
                    display_number: reservation.display_number,
                    public_key: key,
                    process_identity: gone.clone(),
                    endpoint: temp
                        .environment()
                        .worker_endpoint(reservation.display_number)
                        .expect("an endpoint")
                        .as_text(),
                    profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                    state: kr_protocol::session::SessionState::Live,
                    acknowledged_revision: kr_protocol::ids::AuthorityRevision::new(0),
                },
                &kr_protocol::identity::DesktopBinding::none(),
            )
            .expect("records the worker");
        reservation.session_id
    };

    let (controller, asked) = daemon_running(&temp, temp.root().join("kr-worker"), None).await;
    assert!(
        controller.directory.lock().await.get(session_id).is_none(),
        "a record nobody answers for is not a worker this daemon publishes"
    );
    let closure = controller
        .registry
        .lock()
        .await
        .closure(session_id)
        .expect("reads")
        .expect("the session whose worker is gone is recorded as ended");
    assert_eq!(
        closure.reason,
        kr_protocol::session::ClosureReason::WorkerCrash
    );
    assert!(
        asked.lock().expect("the launches").is_empty(),
        "and nothing was launched in its place"
    );
}

/// A create token that already has a reservation is answered from it, not refused again.
///
/// Section 9: a retry resolves to what its first attempt produced. What this pins is that the
/// package check has no say over a token the registry already knows, whatever that check would
/// answer now: an installation whose package was removed, replaced or made unreadable between
/// the two attempts must not turn a recorded action into a refusal. The reservation here is
/// recorded through the registry's own method, which is what a first attempt leaves behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retry_of_an_admitted_create_is_not_refused_because_its_package_went_away() {
    let temp = kr_ipc::testing::TempHost::create();
    let packages = temp.root().join("packages");
    std::fs::create_dir_all(&packages).expect("creates the package root");
    let (controller, asked) =
        daemon_running(&temp, temp.root().join("kr-worker"), Some(packages)).await;
    let environment_id = temp.environment_id();
    let (connection_id, actor_id) = admitted(&controller).await;
    let request = managed_request(environment_id);

    // What a first attempt leaves: a reservation under this token. The package root is empty,
    // so a create that let the package check speak before reading the token would refuse this
    // retry instead of answering it.
    let create: SessionCreateParams = super::parse(&request.params).expect("decodes");
    let digest =
        kr_protocol::digest::mutation_digest(&request, &actor_id).expect("a mutation digest");
    let intent = kr_cbor::to_canonical_vec(&create).expect("encodes the intent");
    {
        let mut registry = controller.registry.lock().await;
        registry
            .reserve(
                &actor_id,
                request.action_id.get(),
                digest,
                &intent,
                kr_ipc::now_ms(),
            )
            .expect("records the first attempt's reservation");
    }

    let error = controller
        .session_create(
            &actor_id,
            &request,
            carried(&controller, connection_id, half_a_minute(&controller)),
        )
        .await
        .expect_err("the reservation has no worker behind it in this test");
    assert_ne!(
        error.code(),
        kr_protocol::error::ErrorCode::ShellIntegrationUnsupported,
        "a retry is answered from its own reservation rather than refused again: {error}"
    );
    assert!(
        error.to_string().contains("already recorded"),
        "and the answer is the recorded one: {error}"
    );
    assert!(
        asked.lock().expect("the record is not poisoned").is_empty(),
        "a retry starts nothing of its own"
    );
}

/// A create request for a managed session whose shell no package can qualify.
fn managed_request(environment_id: kr_protocol::ids::EnvironmentId) -> MutationRequest {
    let mut request = create_request(environment_id);
    let mut params = create_params(environment_id);
    params.shell_mode = ShellMode::Managed;
    params.shell = Nullable::some("/bin/ksh".to_owned());
    request.params = ParamsValue::from_typed(&params).expect("encodes");
    request
}

/// An accepted deadline half a minute out, which nothing in these tests reaches.
fn half_a_minute(controller: &Controller) -> AcceptedDeadline {
    AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(Duration::from_secs(30))
            .expect("a deadline half a minute out"),
        bound: DeadlineBound::RequestedTtl,
    }
}

/// What the launch needs is prepared before the create is admitted, and a preparation that
/// fails resolves the reservation rather than leaving it occupying the environment.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_whose_directory_cannot_be_made_releases_its_reservation() {
    let (temp, controller, asked) = daemon().await;
    let environment_id = temp.environment_id();
    let (connection_id, actor_id) = admitted(&controller).await;

    // The directory every worker's own directory goes under is replaced by a file, so making
    // one under it fails the way a full disk or a wrong permission would.
    let workers = temp.environment().workers_dir();
    std::fs::remove_dir_all(&workers).expect("clears the workers directory");
    std::fs::write(&workers, b"not a directory").expect("puts a file in its place");

    let accepted = AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(Duration::from_secs(30))
            .expect("a deadline half a minute out"),
        bound: DeadlineBound::RequestedTtl,
    };
    let error = controller
        .session_create(
            &actor_id,
            &create_request(environment_id),
            carried(&controller, connection_id, accepted),
        )
        .await
        .expect_err("a create that cannot be prepared starts nothing");
    assert!(
        asked.lock().expect("the record is not poisoned").is_empty(),
        "no worker is started for a create the host could not prepare: {error}"
    );
    let registry = controller.registry.lock().await;
    assert_eq!(
        registry.occupancy().expect("counts"),
        0,
        "the reservation it made is released"
    );
    assert_eq!(
        registry
            .reservations_in(LaunchPhase::Failed)
            .expect("reads the reservations")
            .len(),
        1,
        "and it is resolved rather than left to recovery"
    );
}

/// Returns the sessions that still have a directory under this environment's workers folder.
///
/// A directory that cannot be read is a failure rather than an empty answer: an assertion that
/// treated it as empty would pass for the wrong reason.
fn worker_dirs(temp: &kr_ipc::testing::TempHost) -> Vec<String> {
    let directory = temp.environment().workers_dir();
    let mut names: Vec<String> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("reads {}: {error}", directory.display()))
        .map(|entry| {
            entry.unwrap_or_else(|error| {
                panic!("reads an entry of {}: {error}", directory.display())
            })
        })
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .collect();
    names.sort();
    names
}

/// A launch that is confirmed not to have started gives its directory back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_whose_launch_never_started_leaves_no_directory() {
    let (temp, controller, asked) = daemon().await;
    let environment_id = temp.environment_id();
    let (connection_id, actor_id) = admitted(&controller).await;
    let accepted = AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(Duration::from_secs(30))
            .expect("a deadline half a minute out"),
        bound: DeadlineBound::RequestedTtl,
    };
    controller
        .session_create(
            &actor_id,
            &create_request(environment_id),
            carried(&controller, connection_id, accepted),
        )
        .await
        .expect_err("this supervisor starts nothing");
    assert_eq!(
        asked.lock().expect("the record is not poisoned").len(),
        1,
        "the launch was prepared and attempted"
    );
    assert!(
        worker_dirs(&temp).is_empty(),
        "and the directory it was prepared with is given back: {:?}",
        worker_dirs(&temp)
    );
}

/// The directory a create is refused before its launch goes back with the reservation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_create_leaves_no_directory() {
    let (temp, controller, asked) = daemon().await;
    let environment_id = temp.environment_id();
    let (connection_id, actor_id) = admitted(&controller).await;
    let accepted = AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(Duration::from_millis(300))
            .expect("a deadline a moment out"),
        bound: DeadlineBound::RequestedTtl,
    };
    let mutation = create_request(environment_id);
    let paused = HeldConnections::hold(&controller);
    let create = tokio::spawn({
        let controller = Arc::clone(&controller);
        let actor_id = actor_id.clone();
        async move {
            controller
                .session_create(
                    &actor_id,
                    &mutation,
                    carried(&controller, connection_id, accepted),
                )
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(600)).await;
    paused.release().await;
    create
        .await
        .expect("the create finishes")
        .expect_err("a create whose deadline has passed starts nothing");
    assert!(asked.lock().expect("the record is not poisoned").is_empty());
    assert!(
        worker_dirs(&temp).is_empty(),
        "the directory goes with the reservation: {:?}",
        worker_dirs(&temp)
    );
}

/// The sweep keeps what a reservation still claims and removes what nothing does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_sweep_removes_only_the_directories_no_session_claims() {
    let (temp, controller, _asked) = daemon().await;
    let environment = temp.environment();
    // One directory belonging to a reservation that is still unresolved, and one belonging to
    // nothing at all.
    let reserved = {
        let mut registry = controller.registry.lock().await;
        registry
            .reserve(
                &kr_protocol::ids::ActorId::new("local:test").expect("a principal"),
                kr_ipc::new_uuid(),
                kr_protocol::scalars::Digest256::from_bytes([7; 32]),
                &[0xa0],
                kr_ipc::now_ms(),
            )
            .expect("reserves")
            .reservation
            .session_id
    };
    let stray = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid());
    for session_id in [reserved, stray] {
        kr_ipc::paths::create_private_tree(
            environment.state_root(),
            &environment.worker_dir(session_id),
        )
        .expect("makes the directory");
    }

    controller
        .sweep_worker_dirs()
        .await
        .expect("the sweep runs");
    assert_eq!(
        worker_dirs(&temp),
        vec![reserved.to_string()],
        "a reservation nothing has settled keeps its directory; a session nobody knows does not"
    );
}

/// Every path a launch carries is one the worker can use from a directory of its own.
///
/// The worker is started somewhere this daemon chose, so a name this daemon was given
/// relatively would be looked for beneath that instead. This one is told to launch a relative
/// name on purpose.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_launch_carries_paths_the_worker_can_use_from_its_own_directory() {
    let temp = kr_ipc::testing::TempHost::create();
    let (controller, asked) =
        daemon_running(&temp, std::path::PathBuf::from("kr-worker-relative"), None).await;
    let environment_id = temp.environment_id();
    let (connection_id, actor_id) = admitted(&controller).await;
    let accepted = AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(Duration::from_secs(30))
            .expect("a deadline half a minute out"),
        bound: DeadlineBound::RequestedTtl,
    };
    controller
        .session_create(
            &actor_id,
            &create_request(environment_id),
            carried(&controller, connection_id, accepted),
        )
        .await
        .expect_err("this supervisor starts nothing");

    let asked = asked.lock().expect("the record is not poisoned");
    let launch = asked.first().expect("the supervisor was asked to launch");
    for (what, path) in [
        ("the executable", &launch.program),
        ("the runtime root", &launch.runtime_directory),
        ("the state root", &launch.state_directory),
        ("the jobs directory", &launch.jobs_directory),
        ("the working directory", &launch.working_directory),
    ] {
        assert!(
            path.is_absolute(),
            "{what} is a path the worker can use from anywhere: {}",
            path.display()
        );
    }
    // The rendezvous endpoint is a socket path on Unix and a pipe name on Windows. What the
    // launch carries is whatever names the endpoint this daemon bound, unchanged.
    assert_eq!(
        launch.rendezvous,
        controller
            .paths
            .rendezvous_endpoint()
            .expect("an endpoint")
            .as_path(),
        "the launch names the endpoint this daemon bound"
    );
    #[cfg(unix)]
    assert!(
        launch.rendezvous.is_absolute(),
        "and where that is a path, it is one the worker can use from anywhere: {}",
        launch.rendezvous.display()
    );
    assert_eq!(
        launch.program,
        std::env::current_dir()
            .expect("this process has a directory")
            .join("kr-worker-relative"),
        "the relative name is resolved where the daemon was started, not where the worker runs"
    );
}

/// The check a service makes again from inside work that has already begun.
///
/// A project mutation reaches its service through a blocking task, and a clone or a
/// materialisation takes long enough that authority can go while it waits. The service asks
/// again before it acts, from memory, so the answer costs nothing and can be asked from a
/// blocking thread. What this covers is the two revocations a host performs: one that
/// withdraws every registration, and one that withdraws a device's and stamps the rest with
/// the revision it advanced to. It does not stage a queued effect; what it establishes is that
/// the check itself answers each of those correctly, and where it is called is read from
/// `project_mutation` and `ProjectModule::write`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_admission_a_service_checks_again_answers_both_revocations() {
    let (_temp, controller, _asked) = daemon().await;
    let (connection_id, _actor_id) = admitted(&controller).await;
    let admitted_revision = controller
        .admitted_revision(connection_id)
        .expect("the connection is registered");
    let live = crate::authority::AdmittedMutation {
        connection_id,
        admitted_revision,
        deadline: Some(
            controller
                .clock
                .now()
                .checked_add(Duration::from_secs(60))
                .expect("a deadline"),
        ),
    };
    controller
        .check_registration(&live)
        .expect("a live admission stands");

    // A deadline that has passed refuses a first admission, and says so as freshness rather
    // than as authority: the two are answered differently by the caller.
    let spent = crate::authority::AdmittedMutation {
        deadline: Some(controller.clock.now()),
        ..live
    };
    assert!(matches!(
        controller.check_registration(&spent),
        Err(ControllerError::WindowExpired { .. })
    ));

    // A revocation takes the registration, and the check then refuses whatever was waiting.
    controller
        .revoke_authority()
        .await
        .expect("the revocation completes");
    assert!(matches!(
        controller.check_registration(&live),
        Err(ControllerError::PermissionDenied { .. })
    ));

    // A revocation that withdraws one device leaves every other connection registered and
    // stamps it with the revision it advanced to, which is what `Network::revoke_device`
    // does. A mutation admitted before that point then finds its registration standing under a
    // later revision than the one it carries, and that is the authority it was admitted under
    // having been replaced.
    let (surviving, _actor_id) = admitted(&controller).await;
    let carried_before = crate::authority::AdmittedMutation {
        connection_id: surviving,
        admitted_revision: controller
            .admitted_revision(surviving)
            .expect("the connection is registered"),
        ..live
    };
    controller
        .check_registration(&carried_before)
        .expect("nothing has been revoked yet");
    {
        let mut registry = controller.registry.lock().await;
        registry
            .advance_authority_revision()
            .expect("the revision advances");
        let revision = registry
            .authority_revision()
            .expect("the revision in force");
        let mut admitted = controller.admitted_table();
        for connection in admitted.values_mut() {
            connection.admitted_revision = revision;
        }
    }
    assert!(
        matches!(
            controller.check_registration(&carried_before),
            Err(ControllerError::PermissionDenied { .. })
        ),
        "a mutation admitted before the revocation is refused although its connection stands"
    );

    // And the connection's own next mutation, admitted at the revision now in force, is not.
    let carried_after = crate::authority::AdmittedMutation {
        admitted_revision: controller
            .admitted_revision(surviving)
            .expect("the connection is registered"),
        ..carried_before
    };
    controller
        .check_registration(&carried_after)
        .expect("one device's revocation is not everybody's reconnection");
}

/// A live admission, as a connection this daemon registered carries it.
fn live_admission(
    controller: &Controller,
    connection_id: ConnectionId,
) -> crate::authority::AdmittedMutation {
    crate::authority::AdmittedMutation {
        connection_id,
        admitted_revision: controller
            .admitted_revision(connection_id)
            .expect("the connection is registered"),
        deadline: Some(
            controller
                .clock
                .now()
                .checked_add(Duration::from_secs(60))
                .expect("a deadline"),
        ),
    }
}

/// A withdrawal whose fence could not be raised did not advance the revision, so every
/// registration still stands under the revision it carries. The check a service asks again
/// from inside its work refuses while that fence is owed, and so does the admission every
/// service is handed; once the fence is no longer owed, the same admission stands again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_admission_a_service_checks_again_refuses_while_a_fence_is_owed() {
    let (_temp, controller, _asked) = daemon().await;
    let (connection_id, _actor_id) = admitted(&controller).await;
    let live = live_admission(&controller, connection_id);
    controller
        .check_registration(&live)
        .expect("a live admission stands");

    controller.hold_fence(true);
    let refused = controller
        .check_registration(&live)
        .expect_err("a fence this host owes stops it");
    assert!(
        matches!(refused, ControllerError::PermissionDenied { .. }),
        "{refused:?}"
    );
    assert!(
        refused.to_string().contains("could not be raised"),
        "{refused}"
    );
    let asked = controller.admission_in_service(live);
    assert_eq!(
        asked().expect_err("the admission a service is handed").code,
        ErrorCode::PermissionDenied
    );

    controller.hold_fence(false);
    controller
        .check_registration(&live)
        .expect("the admission stands again once the fence is no longer owed");
    asked().expect("and so does the one a service holds");
}

/// A project mutation that passed the daemon's first check does not act while a fence this
/// host owes stops dispatch. The project service asks the admission it is handed from inside
/// its own work, after looking for a retained record and before it acts, and the repository
/// the mutation asked for is never made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_project_mutation_does_not_act_while_a_fence_is_owed() {
    let (temp, controller, _asked) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let carried = live_admission(&controller, connection_id);
    let parent = temp.root().join("projects");
    std::fs::create_dir_all(&parent).expect("a directory for the repository");
    let params = kr_protocol::project::ProjectInitParams {
        destination: kr_protocol::project::DestinationRequest {
            environment_id: temp.environment_id(),
            parent: kr_protocol::project::DestinationParent::Host {
                path: parent.display().to_string(),
            },
            name: "fenced".to_owned(),
        },
        label: "fenced".to_owned(),
        initial_branch: Nullable::null(),
    };
    let mutation = MutationRequest {
        request_id: RequestId::new(1),
        method: Method::ProjectInit.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget::environment(temp.environment_id()),
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("local:test").expect("a window"),
        requested_ttl_ms: DurationMs::new(30_000),
        params: ParamsValue::from_typed(&params).expect("encodes"),
    };

    // The daemon's first answer was given; the withdrawal's fence fails after it.
    controller.hold_fence(true);
    let refused = controller
        .project
        .write(
            &actor_id,
            &mutation,
            Method::ProjectInit,
            controller.admission_in_service(carried),
            None,
        )
        .await
        .expect_err("the project service's own check refuses it");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        refused.message.contains("could not be raised"),
        "{refused:?}"
    );
    assert!(!parent.join("fenced").exists(), "no repository was made");
}

/// A standing voice grant as the coordinator plans one: for a device of its own, over one
/// session, permitting status.
fn voice_plan(controller: &Controller) -> kr_voice::VoiceGrantPlan {
    kr_voice::VoiceGrantPlan {
        parent_grant_id: None,
        issuer_device_id: controller.sharing.host_device_id(),
        recipient_device_id: kr_protocol::ids::DeviceId::new(kr_ipc::new_uuid()),
        environment_id: controller.paths.environment_id(),
        session_selector: kr_protocol::grant::SessionSelector::These {
            session_ids: [kr_protocol::ids::SessionId::new(kr_ipc::new_uuid())]
                .into_iter()
                .collect(),
        },
        actions: [kr_protocol::voice::VoiceAction::Status]
            .into_iter()
            .collect(),
        rights: [
            kr_protocol::rights::ActionRight::VoiceUse,
            kr_protocol::rights::ActionRight::SessionView,
        ]
        .into_iter()
        .collect(),
        history: kr_protocol::grant::HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: true,
            named_questions: kr_protocol::scalars::CanonicalSet::from_iter([]),
            named_approvals: kr_protocol::scalars::CanonicalSet::from_iter([]),
        },
        expiry: kr_protocol::grant::GrantExpiry::Never,
        authority_revision: controller.policy().authority_revision(),
    }
}

/// The voice service's grant seam writes and withdraws only under the admission every service
/// asks from inside its work. While a fence is owed it writes no voice grant and withdraws
/// none, and what the caller is told is the fence's own refusal; once the fence is no longer
/// owed, the same admission writes. A registration this host withdrew after the admission stops
/// the write as well, which a deadline alone would not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_voice_grant_seam_writes_only_under_the_admission_every_service_asks() {
    use kr_voice::seams::VoiceAuthority as _;

    let (_temp, controller, _asked) = daemon().await;
    let (connection_id, _actor_id) = admitted(&controller).await;
    let authority = crate::voice::GrantAuthority::new(
        Arc::clone(&controller.sharing),
        Arc::clone(&controller.devices),
        controller.sharing.host_device_id(),
        Arc::downgrade(&controller),
    );
    let plan = voice_plan(&controller);
    let held = |device_id| {
        controller
            .sharing
            .grants()
            .records_for_device(device_id)
            .expect("the store answers")
    };
    let admission =
        |carried| super::voice_actions::VoiceAdmission::new(Arc::clone(&controller), carried);
    let not_this = || ControllerError::InvalidArgument("not the refusal".to_owned());

    // A fence owed after the admission: nothing is written, and the fence is what the caller
    // is told.
    let fenced = admission(live_admission(&controller, connection_id));
    controller.hold_fence(true);
    let refused = authority
        .issue(&plan, &fenced)
        .expect_err("the fence stops the write");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    let told = fenced.refused_or(not_this());
    assert!(
        matches!(told, ControllerError::PermissionDenied { .. }),
        "{told:?}"
    );
    assert!(told.to_string().contains("could not be raised"), "{told}");
    assert!(
        held(plan.recipient_device_id).is_empty(),
        "no voice grant was written"
    );

    // The same admission once the fence is no longer owed.
    controller.hold_fence(false);
    let written = authority
        .issue(
            &plan,
            &admission(live_admission(&controller, connection_id)),
        )
        .expect("the admission stands again once the fence is no longer owed");

    // A withdrawal under a fence owed is refused inside the store's own transaction, and the
    // grant stays as it was.
    controller.hold_fence(true);
    let withdrawing = admission(live_admission(&controller, connection_id));
    authority
        .revoke(written.grant_id, 5, &withdrawing)
        .expect_err("the fence stops the withdrawal");
    let told = withdrawing.refused_or(not_this());
    assert!(told.to_string().contains("could not be raised"), "{told}");
    assert!(
        held(plan.recipient_device_id)
            .iter()
            .all(|record| record.revoked_at_ms.is_none()),
        "nothing was withdrawn"
    );
    controller.hold_fence(false);

    // A registration withdrawn after the admission: the deadline still has time on it, and the
    // write is refused all the same.
    let carried = live_admission(&controller, connection_id);
    controller.deregister(connection_id);
    let deregistered = admission(carried);
    let other = voice_plan(&controller);
    authority
        .issue(&other, &deregistered)
        .expect_err("a withdrawn registration stops the write");
    let told = deregistered.refused_or(not_this());
    assert!(
        matches!(told, ControllerError::PermissionDenied { .. }),
        "{told:?}"
    );
    assert_eq!(
        told.to_string(),
        crate::authority::AdmissionLapse::Deregistered.to_string()
    );
    assert!(
        held(other.recipient_device_id).is_empty(),
        "no voice grant was written"
    );
}

/// A voice grant's withdrawal owes no fence. Withdrawing one through the seam, as stopping a
/// call or replacing a standing grant does, writes no debt, publishes none and advances no
/// revision: no worker holds work under a grant that carries `voice.use`. The control: a grant
/// delegated from a voice grant that is not one itself is withdrawn with it, and the debt it
/// owes is published the moment the store commits and retired by one barrier.
///
/// On one thread, so the spawned barrier cannot run before the publication is checked.
#[tokio::test]
async fn a_voice_grants_withdrawal_through_the_seam_fences_nothing() {
    use kr_voice::seams::VoiceAuthority as _;

    let (_temp, controller, _asked) = daemon().await;
    let (connection_id, _actor_id) = admitted(&controller).await;
    let authority = crate::voice::GrantAuthority::new(
        Arc::clone(&controller.sharing),
        Arc::clone(&controller.devices),
        controller.sharing.host_device_id(),
        Arc::downgrade(&controller),
    );
    let admission =
        |carried| super::voice_actions::VoiceAdmission::new(Arc::clone(&controller), carried);
    let revision = || {
        let controller = Arc::clone(&controller);
        async move {
            controller
                .registry
                .lock()
                .await
                .authority_revision()
                .expect("readable")
                .get()
        }
    };
    let before = revision().await;

    let plan = voice_plan(&controller);
    let voice = authority
        .issue(
            &plan,
            &admission(live_admission(&controller, connection_id)),
        )
        .expect("a voice grant");
    authority
        .revoke(
            voice.grant_id,
            5,
            &admission(live_admission(&controller, connection_id)),
        )
        .expect("withdrawn");
    assert!(
        controller
            .sharing
            .grants()
            .fence_owed()
            .expect("readable")
            .is_empty(),
        "a voice grant's withdrawal writes no debt"
    );
    assert!(
        controller.debts().published.is_empty(),
        "and publishes none"
    );
    controller.check_fence().expect("so nothing is refused");
    assert_eq!(revision().await, before, "and no barrier advances");

    // The control: a standing voice grant that may share, and a grant delegated from it that
    // carries no voice right.
    let mut sharing_plan = voice_plan(&controller);
    sharing_plan
        .rights
        .insert(kr_protocol::rights::ActionRight::SessionShare);
    let voice = authority
        .issue(
            &sharing_plan,
            &admission(live_admission(&controller, connection_id)),
        )
        .expect("a voice grant that may share");
    let delegated = kr_protocol::grant::Grant {
        grant_id: kr_protocol::ids::GrantId::new(kr_ipc::new_uuid()),
        parent_grant_id: Nullable::some(voice.grant_id),
        issuer_device_id: voice.recipient_device_id,
        recipient_device_id: kr_protocol::ids::DeviceId::new(kr_ipc::new_uuid()),
        actions: [kr_protocol::rights::ActionRight::SessionView]
            .into_iter()
            .collect(),
        ..voice.clone()
    };
    controller
        .sharing
        .grants()
        .issue(
            &crate::grants::GrantRecord {
                grant: delegated,
                session_id: None,
                issued_at_ms: 1,
                activated_at_ms: Some(1),
                revoked_at_ms: None,
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("a delegated grant");
    authority
        .revoke(
            voice.grant_id,
            6,
            &admission(live_admission(&controller, connection_id)),
        )
        .expect("withdrawn with what was delegated from it");
    let owed = controller.sharing.grants().fence_owed().expect("readable");
    assert_eq!(owed.len(), 1, "the delegated grant owes one debt");
    assert!(
        controller.debts().published.contains_key(&owed[0]),
        "published the moment the store committed"
    );
    controller
        .check_fence()
        .expect_err("every admission is refused until its barrier");
    controller
        .raise_owed_barrier()
        .await
        .expect("the barrier is raised");
    assert_eq!(revision().await, before + 1, "one barrier retires it");
    assert!(
        controller
            .sharing
            .grants()
            .fence_owed()
            .expect("readable")
            .is_empty()
    );
    controller.check_fence().expect("and nothing is refused");
}

/// The voice admission, asked through a probe that first records whether the grant store held
/// its write lock at that moment.
///
/// A second connection to the store's database tries to take the write lock without waiting.
/// It is refused only while another writer holds that lock, and the only writer here is the
/// store itself.
#[derive(Debug)]
struct AskedUnderTheStoreLock {
    admission: super::voice_actions::VoiceAdmission,
    database: std::path::PathBuf,
    held: Mutex<Vec<bool>>,
}

impl kr_voice::Admission for AskedUnderTheStoreLock {
    fn still_admitted(&self) -> bool {
        let other = rusqlite::Connection::open(&self.database).expect("opens the store's database");
        other
            .busy_timeout(Duration::ZERO)
            .expect("asks without waiting");
        let held = match other.execute_batch("BEGIN IMMEDIATE") {
            Ok(()) => {
                other
                    .execute_batch("ROLLBACK")
                    .expect("gives the lock back");
                false
            }
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::DatabaseBusy =>
            {
                true
            }
            Err(error) => panic!("the probe could not ask the store: {error}"),
        };
        self.held.lock().expect("the record").push(held);
        self.admission.still_admitted()
    }
}

/// The voice grant seam asks its admission while the grant store holds its write lock: inside
/// the transaction that writes, after the wait for that lock and before the record changes. A
/// fence that becomes owed while a write waits for the lock is therefore what the admission
/// sees. Asked before the store, as the seam once asked for an issue, the probe finds the lock
/// free.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_voice_grant_seam_asks_its_admission_while_the_store_holds_its_write_lock() {
    use kr_voice::seams::VoiceAuthority as _;

    let (_temp, controller, _asked) = daemon().await;
    let (connection_id, _actor_id) = admitted(&controller).await;
    let authority = crate::voice::GrantAuthority::new(
        Arc::clone(&controller.sharing),
        Arc::clone(&controller.devices),
        controller.sharing.host_device_id(),
        Arc::downgrade(&controller),
    );
    let probe = |carried| AskedUnderTheStoreLock {
        admission: super::voice_actions::VoiceAdmission::new(Arc::clone(&controller), carried),
        database: controller.paths.registry_database(),
        held: Mutex::new(Vec::new()),
    };
    let asked = |probe: &AskedUnderTheStoreLock| probe.held.lock().expect("the record").clone();

    // An admission that stands: asked once, under the lock, and the grant is written.
    let standing = probe(live_admission(&controller, connection_id));
    let plan = voice_plan(&controller);
    let written = authority
        .issue(&plan, &standing)
        .expect("a standing admission writes");
    assert_eq!(asked(&standing), vec![true], "an issue asks under the lock");

    // A withdrawal is asked the same way.
    let withdrawing = probe(live_admission(&controller, connection_id));
    authority
        .revoke(written.grant_id, 5, &withdrawing)
        .expect("a standing admission withdraws");
    assert_eq!(
        asked(&withdrawing),
        vec![true],
        "a revocation asks under the lock"
    );

    // A fence owed: asked under the lock all the same, refused with the fence's own refusal,
    // and nothing written.
    controller.hold_fence(true);
    let fenced = probe(live_admission(&controller, connection_id));
    let other = voice_plan(&controller);
    authority
        .issue(&other, &fenced)
        .expect_err("the fence stops the write");
    assert_eq!(asked(&fenced), vec![true]);
    let told = fenced
        .admission
        .refused_or(ControllerError::InvalidArgument(
            "not the refusal".to_owned(),
        ));
    assert!(told.to_string().contains("could not be raised"), "{told}");
    assert!(
        controller
            .sharing
            .grants()
            .records_for_device(other.recipient_device_id)
            .expect("the store answers")
            .is_empty(),
        "no voice grant was written"
    );
    controller.hold_fence(false);
}

/// A mutation forwarded to a worker is asked the admission it arrived under at the last point
/// before it is forwarded, after the lease: a fence this host owes stops it, and so does a
/// registration withdrawn after the admission. The envelope is a local one, which needs no
/// worker lease, so nothing but the admission can refuse it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forward_to_a_worker_asks_the_admission_it_arrived_under() {
    let (_temp, controller, _asked) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let envelope = kr_protocol::actor::ActorEnvelope {
        actor_id,
        ingress: kr_protocol::actor::ActorIngress::LocalIpc,
        device_id: Nullable::null(),
        grant_id: Nullable::null(),
        grant_revision: Nullable::some(
            controller
                .admitted_revision(connection_id)
                .expect("the connection is registered"),
        ),
        controller_generation: controller.generation,
        connection_id,
    };
    let accepted = AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(Duration::from_secs(60))
            .expect("a deadline"),
        bound: DeadlineBound::RequestedTtl,
    };
    let session_id = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid());
    controller
        .forwarded_deadline(session_id, &envelope, accepted)
        .await
        .expect("a standing admission is forwarded");

    controller.hold_fence(true);
    let refused = controller
        .forwarded_deadline(session_id, &envelope, accepted)
        .await
        .expect_err("a fence this host owes stops the forward");
    assert!(
        matches!(refused, ControllerError::PermissionDenied { .. }),
        "{refused:?}"
    );
    assert!(
        refused.to_string().contains("could not be raised"),
        "{refused}"
    );
    controller.hold_fence(false);

    controller.deregister(connection_id);
    let refused = controller
        .forwarded_deadline(session_id, &envelope, accepted)
        .await
        .expect_err("a withdrawn registration stops the forward");
    assert_eq!(
        refused.to_string(),
        crate::authority::AdmissionLapse::Deregistered.to_string()
    );
}

/// An installation is checked at its marker against the revision its connection was admitted
/// at when the daemon accepted it, not one read after the wait. A revocation of another device
/// stamps every surviving registration with the revision it advanced to; a change admitted
/// before that is refused at its marker, and nothing is written.
#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_installation_admitted_before_a_revocation_is_refused_at_its_marker() {
    use kr_protocol::envelope::{ControlFrame, Outcome, Response};

    let (temp, controller, _asked) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admitted_at = controller
        .admitted_revision(connection_id)
        .expect("the connection is registered");
    // Another device's revocation, landing while the installation waited.
    {
        let mut registry = controller.registry.lock().await;
        registry
            .advance_authority_revision()
            .expect("the revision advances");
        let revision = registry
            .authority_revision()
            .expect("the revision in force");
        let mut registrations = controller.admitted_table();
        for connection in registrations.values_mut() {
            connection.admitted_revision = revision;
        }
    }
    let project = tempfile::TempDir::new().expect("a project directory on the internal disk");
    let params = kr_protocol::skill::AgentToolsParams {
        agent: kr_protocol::skill::AgentTarget::Codex,
        scope: kr_protocol::skill::InstallScope::Project,
        project_dir: Nullable::some(project.path().display().to_string()),
    };
    let mutation = MutationRequest {
        request_id: RequestId::new(1),
        method: Method::AgentToolsInstall.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget::environment(temp.environment_id()),
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("local:test").expect("a window"),
        requested_ttl_ms: DurationMs::new(30_000),
        params: ParamsValue::from_typed(&params).expect("encodes"),
    };
    let accepted = AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(Duration::from_secs(60))
            .expect("a deadline"),
        bound: DeadlineBound::RequestedTtl,
    };

    let answered = controller
        .write_method(
            &actor_id,
            &mutation,
            Method::AgentToolsInstall,
            connection_id,
            None,
            Some(accepted),
            Some(admitted_at),
        )
        .await;

    let ControlFrame::Response(Response {
        outcome: Outcome::Error(refused),
        ..
    }) = answered
    else {
        panic!("the installation is refused: {answered:?}");
    };
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert_eq!(
        refused.message,
        crate::authority::AdmissionLapse::Revoked.to_string()
    );
    assert!(
        std::fs::read_dir(project.path())
            .expect("reads the project directory")
            .next()
            .is_none(),
        "nothing was written into the project"
    );
    let actions = temp.environment().state_dir().join("agent-tools/actions");
    assert!(
        !actions.exists()
            || std::fs::read_dir(&actions)
                .expect("reads the directory")
                .next()
                .is_none(),
        "no dispatch marker was written"
    );
}
