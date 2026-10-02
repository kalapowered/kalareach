//! A dispatch lease that runs out while its action waits at a real worker.
//!
//! Section 9's lease lets a worker dispatch for at most five seconds on the strength of what the
//! daemon last said, and the barrier a revocation raises is complete only when the worker has
//! acknowledged the revision or ended. These tests run that sequence against a real worker, whose
//! serial boundary a test holds shut, on one continuous clock the test moves by hand for the daemon
//! and the worker both: an action holds a lease, a revocation is raised that the worker never hears
//! of, the clock passes the lease, and the worker refuses the action as expired, shows pending, and
//! leaves the fence owed. With no debt owed, the same lapse leaves the next action its lease.
//!
//! One clock is moved by hand, and it is the continuous clock each side decides its deadlines on.
//! The deadline an action crosses from the daemon to the worker is read on the machine's own boot
//! clock, which neither side lets a test move, so what is left of a lease counts down in real time
//! from the moment the daemon takes it until the worker anchors it on arrival: some microseconds,
//! against the five seconds a lease lasts. The worker's record of a forwarded frame is made once it
//! has anchored, and a test waits on that record before it moves the clock.

use std::sync::Arc;
use std::time::Duration;

use kr_crypto::store::open_store_in;
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::envelope::{ActionTarget, MutationRequest, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, ActionWindowId, ActorId, ConnectionId, ControllerGeneration, DeviceId, EnvironmentId,
    RequestId, SessionEpoch, SessionId,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, U64, Uuid};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_transport::clock::ManualClock;
use kr_transport::window::{AcceptedDeadline, DeadlineBound};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

use crate::service::{Clocks, Controller, WallClock};

/// How long a test waits for something it waits for by condition, and fails after. Nothing is
/// decided by it: a worker that never gets there is the one thing that runs it out.
const WAIT: Duration = Duration::from_secs(60);

/// How long a deadline a test hands an action lasts, on the clock the test moves.
const STANDING: Duration = Duration::from_secs(60);

/// How long the whole test is given, its runtime's end included, before it fails naming the step it
/// was at. Like [`WAIT`] it decides nothing: the test takes a second or two, and a test that has
/// not finished by now is waiting for something that is not coming.
const WHOLE: Duration = Duration::from_secs(180);

/// The step the test has reached, kept where the deadline that runs out can say it.
#[derive(Clone, Default)]
struct Steps(Arc<std::sync::Mutex<&'static str>>);

impl Steps {
    fn at(&self, step: &'static str) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = step;
    }

    fn reached(&self) -> &'static str {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Runs a test's body on a multi-threaded runtime of sixteen threads, on a thread of its own, and
/// fails the test when the body, and the end of the runtime it ran on, have not finished within
/// [`WHOLE`].
///
/// The deadline is kept by the test's own thread, outside that runtime, so it holds whatever the
/// runtime is stuck on: an await that never completes, a thread blocked on a lock, or the runtime's
/// wait for a blocking thread that does not end. The failure names the step the test had reached,
/// and the thread that is stuck is left to end with the process. A body that panics fails the test
/// with its own message.
fn within_the_whole<Body, Test>(body: Body)
where
    Body: FnOnce(Steps) -> Test + Send + 'static,
    Test: std::future::Future<Output = ()>,
{
    let steps = Steps::default();
    let (finished, ended) = std::sync::mpsc::channel::<()>();
    let running = {
        let steps = steps.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(16)
                .enable_all()
                .build()
                .expect("a runtime for the test");
            runtime.block_on(body(steps.clone()));
            steps.at("ending the test's runtime");
            drop(runtime);
            let _ = finished.send(());
        })
    };
    match ended.recv_timeout(WHOLE) {
        Ok(()) => running.join().expect("the test's thread ends"),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => match running.join() {
            Err(panicked) => std::panic::resume_unwind(panicked),
            Ok(()) => panic!("the test's thread ended without finishing"),
        },
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
            "the test had not finished within {WHOLE:?}; it was at this step: {}",
            steps.reached()
        ),
    }
}

/// One daemon and one real worker on a clock the test moves.
struct World {
    _daemon_tree: kr_ipc::testing::TempHost,
    _worker_tree: kr_ipc::testing::TempHost,
    controller: Arc<Controller>,
    clock: ManualClock,
    runtime: Arc<SessionRuntime>,
    service: Arc<WorkerService>,
    /// The runtime the worker's service runs on, apart from the test's and the daemon's.
    ///
    /// A worker holds its session for the whole of an action, on the thread that serves it, and its
    /// process is its own. Here it shares this one, and a thread blocked in it would stand between
    /// the test's own tasks and the reactor they wait on; so it has threads of its own.
    worker_runtime: Option<tokio::runtime::Runtime>,
    /// The runtime the worker's session runs its own tasks on (the task that ingests its terminal's
    /// output, its watch on the shell, its paste timer), apart from the test's and from the
    /// service's.
    ///
    /// Each of those tasks takes the session's lock when it wakes, and the test holds that lock to
    /// keep the serial boundary shut. A task that wakes then blocks the thread it runs on, and when
    /// that thread is the one a runtime's reactor and timers are driven from, the runtime has none
    /// to drive them until the lock is let go: the test's own waits, which are timers, never end,
    /// and neither does the frame the service is to read. So nothing the test waits on runs here.
    session_runtime: Option<tokio::runtime::Runtime>,
    session_id: SessionId,
    environment_id: EnvironmentId,
    /// The link the worker has to a daemon of generation one, over which a forward is sent.
    link: Option<LocalClient>,
    actor: ActorEnvelope,
}

/// Starts the daemon and the worker on one manual clock, with the worker's serial boundary free
/// and the daemon holding the worker's acknowledgement of the revision in force, its fence
/// reported, as a worker that has answered an announcement is.
async fn world(steps: &Steps) -> World {
    steps.at("starting the daemon");
    let clock = ManualClock::new();
    let daemon_tree = kr_ipc::testing::TempHost::create();
    let controller = Controller::start_on_clocks(
        super::a_floor_owed_its_record::setup(&daemon_tree),
        Clocks {
            continuous: Arc::new(clock.clone()),
            wall: WallClock::system(),
        },
    )
    .await
    .expect("the daemon starts");

    steps.at("starting the worker's session");
    let worker_tree = kr_ipc::testing::TempHost::create();
    let environment = worker_tree.environment();
    let environment_id = worker_tree.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            process,
            PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );
    let store = open_store_in(&environment.secrets_dir()).expect("a secret store");
    let controller_identity = Arc::new(
        ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity"),
    );
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script("exec cat"),
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let session_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime of the session's own");
    let started = session_runtime.spawn(async move {
        SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
    });
    let runtime = Arc::new(
        started
            .await
            .expect("the session is started")
            .expect("starts the runtime"),
    );
    let endpoint = environment
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let build = kr_protocol::ids::BuildId::new("kr-test/0").expect("a build identifier");
    let binding = ServiceBinding {
        environment_id,
        boot_identity: boot.clone(),
        controller_public_key: *controller_identity.public_key(),
        controller_generation: ControllerGeneration::new(1),
        journal_path: Some(environment.journal_database(session_id)),
        build_id: build.clone(),
    };
    let worker_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime of the worker's own");
    steps.at("starting the worker's service");
    let service = {
        let runtime = Arc::clone(&runtime);
        let endpoint = endpoint.clone();
        let clock = clock.clone();
        worker_runtime
            .spawn(async move {
                let listener = Listener::bind(&endpoint).expect("binds the endpoint");
                let service = Arc::new(
                    WorkerService::new(runtime, identity, endpoint, binding)
                        .expect("a worker service")
                        .on_clock(Arc::new(clock)),
                );
                tokio::spawn(Arc::clone(&service).serve(listener));
                service
            })
            .await
            .expect("the worker is started")
    };

    steps.at("connecting to the worker");
    let mut link = LocalClient::connect(&endpoint, LocalClientKind::Controller, build)
        .await
        .expect("connects");
    let proving = Arc::clone(&controller_identity);
    steps.at("presenting the daemon's generation to the worker");
    link.present_generation(move |nonce| {
        proving
            .generation_token(ControllerGeneration::new(1), &boot, nonce)
            .map_err(kr_ipc::IpcError::from)
    })
    .await
    .expect("the worker accepts the generation");

    // The daemon holds this worker's acknowledgement of the revision in force, with its fence
    // reported: complete for it, until something withdraws.
    let revision = controller.leases.authority_revision();
    let binding = controller.leases.bind(session_id);
    assert!(controller.leases.acknowledge(
        session_id,
        binding,
        revision,
        Some(kr_protocol::action::FenceEvidence {
            rejected_actions: Vec::new(),
            possibly_executed: Vec::new(),
            remaining: U64::ZERO,
            omitted: U64::ZERO,
        }),
    ));
    assert!(
        controller
            .leases
            .begin_round()
            .report(revision, [session_id])
            .holds()
    );

    // A paired device whose connection this daemon admitted at that revision.
    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
    let actor_id = ActorId::new("device:a-test-phone").expect("a principal");
    controller.admitted_table().insert(
        connection_id,
        super::AdmittedConnection::new(actor_id.clone(), revision),
    );
    let actor = ActorEnvelope {
        actor_id,
        ingress: ActorIngress::PairedDevice,
        device_id: Nullable::some(DeviceId::new(Uuid::from_bytes([4; 16]))),
        grant_id: Nullable::some(kr_protocol::ids::GrantId::new(Uuid::from_bytes([5; 16]))),
        grant_revision: Nullable::some(revision),
        controller_generation: ControllerGeneration::new(1),
        connection_id,
    };
    World {
        _daemon_tree: daemon_tree,
        _worker_tree: worker_tree,
        controller,
        clock,
        runtime,
        service,
        worker_runtime: Some(worker_runtime),
        session_runtime: Some(session_runtime),
        session_id,
        environment_id,
        link: Some(link),
        actor,
    }
}

impl Drop for World {
    fn drop(&mut self) {
        // Dropped from inside a runtime, which a runtime of its own may not be: they are let go of
        // without waiting for their threads.
        if let Some(runtime) = self.worker_runtime.take() {
            runtime.shutdown_background();
        }
        if let Some(runtime) = self.session_runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl World {
    /// A deadline the daemon accepted an action under, a minute from now on the moved clock.
    fn accepted(&self) -> AcceptedDeadline {
        AcceptedDeadline {
            deadline: self
                .controller
                .clock
                .now()
                .checked_add(STANDING)
                .expect("a deadline"),
            bound: DeadlineBound::RequestedTtl,
        }
    }

    /// An attach the worker admits for a device holding `session.view`, under a fresh identifier.
    fn attach(&self) -> MutationRequest {
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        MutationRequest {
            request_id: RequestId::new(1),
            method: Method::SessionAttach.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(kr_ipc::new_uuid()),
            grant_id: Nullable::null(),
            target: ActionTarget {
                environment_id: self.environment_id,
                session_id: Nullable::some(self.session_id),
                session_epoch: Nullable::some(SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            expected: ParamsValue::empty(),
            action_window_id: ActionWindowId::new("forwarded").expect("a window identifier"),
            requested_ttl_ms: kr_protocol::limits::DEFAULT_MUTATION_TTL,
            params: ParamsValue::from_typed(&SessionAttachParams {
                session_id: self.session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested,
            })
            .expect("encodes"),
        }
    }

    /// Sends the attach to the worker over its link, as the daemon's forward does, with the
    /// deadline a lease gave it, on a task of its own so a test can stand between the worker's
    /// receiving it and its answering. The task ends with the link and the worker's answer.
    fn forward_in_the_background(
        &mut self,
        deadline: U64,
    ) -> tokio::task::JoinHandle<(LocalClient, Result<ParamsValue, ProtocolError>)> {
        let mut link = self.link.take().expect("the link is free");
        let mutation = self.attach();
        let actor = self.actor.clone();
        let rights: CanonicalSet<ActionRight> = [ActionRight::SessionView].into_iter().collect();
        tokio::spawn(async move {
            let answer = link
                .forward(&mutation, &actor, &rights, deadline)
                .await
                .expect("the forward reaches the worker");
            (link, answer)
        })
    }

    /// Waits until the worker has recorded `count` mutations, which it does once it holds the frame
    /// and has anchored what is left of its deadline on its own clock.
    async fn until_the_worker_holds(&self, count: usize) {
        let deadline = tokio::time::Instant::now() + WAIT;
        while self.service.received().len() < count {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the worker was not sent the action within {WAIT:?}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Takes the lease an action for this device needs, the way a forward does.
    async fn lease(&self) -> Result<U64, crate::error::ControllerError> {
        self.controller
            .forwarded_deadline(self.session_id, &self.actor, self.accepted())
            .await
    }
}

/// Waits for a forward to end, and fails the test when it does not within [`WAIT`].
async fn ended(
    forward: tokio::task::JoinHandle<(LocalClient, Result<ParamsValue, ProtocolError>)>,
) -> (LocalClient, Result<ParamsValue, ProtocolError>) {
    tokio::time::timeout(WAIT, forward)
        .await
        .unwrap_or_else(|_| panic!("the forward did not end within {WAIT:?}"))
        .expect("the forward ends")
}

/// Holds the worker's session until it is released, which is how a test holds its serial boundary
/// shut: a forwarded mutation that arrives waits there, after the worker has anchored its deadline.
///
/// It runs on a blocking thread rather than in the test, because the lock is not reentrant.
struct Shut {
    release: Option<std::sync::mpsc::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Shut {
    async fn hold(runtime: &Arc<SessionRuntime>) -> Self {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (held, confirmed) = std::sync::mpsc::channel::<()>();
        let runtime = Arc::clone(runtime);
        let task = tokio::task::spawn_blocking(move || {
            let _session = runtime.session();
            held.send(()).expect("the test is waiting");
            // Held until the test releases it, and until it is dropped should it panic first.
            let _ = wait.recv();
        });
        tokio::task::spawn_blocking(move || confirmed.recv().expect("the session is held"))
            .await
            .expect("the waiting thread finishes");
        Self {
            release: Some(release),
            task: Some(task),
        }
    }

    async fn open(mut self) {
        drop(self.release.take());
        if let Some(task) = self.task.take() {
            task.await.expect("the holding thread finishes");
        }
    }
}

/// KR-REQ-09.12 and 26.16: a lease taken just before a revocation is raised bounds the action that
/// holds it to its five seconds, and nothing renews it for a worker that never hears of the
/// revocation. The action waits at the worker's serial boundary while the revocation's barrier is
/// raised and the clock passes the lease: the worker refuses it as expired. The daemon then gives
/// that worker no lease, the worker shows pending for the new revision, and the fence stays owed
/// until a barrier completes, which only the worker's acknowledgement or its end can do.
///
/// The control comes first, with no revocation: the same lapse leaves the next action its lease, and
/// the worker runs it.
#[test]
fn a_lease_that_runs_out_at_a_worker_is_not_renewed_while_a_fence_is_owed() {
    within_the_whole(|steps| async move {
        the_lease_runs_out_and_is_not_renewed(&steps).await;
    });
}

async fn the_lease_runs_out_and_is_not_renewed(steps: &Steps) {
    let mut world = world(steps).await;

    // The control. An action holds its lease at the worker's shut serial boundary, the clock passes
    // the lease, and the worker refuses the action as expired: that much the lapse does by itself.
    steps.at("the control: taking the action's lease");
    let deadline = world.lease().await.expect("the action is given its lease");
    steps.at("the control: shutting the worker's serial boundary");
    let shut = Shut::hold(&world.runtime).await;
    let waiting = world.forward_in_the_background(deadline);
    steps.at("the control: waiting for the worker to hold the action");
    world.until_the_worker_holds(1).await;
    world.clock.advance(Duration::from_secs(6));
    steps.at("the control: opening the worker's serial boundary");
    shut.open().await;
    steps.at("the control: waiting for the worker to refuse the action");
    let (link, answer) = ended(waiting).await;
    world.link = Some(link);
    let refused = answer.expect_err("the lapse expires the action at the worker");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        refused
            .message
            .contains("the accepted deadline for this action has passed"),
        "the worker refused it as expired: {refused:?}"
    );

    // With no debt owed the next action is given a fresh lease, and the worker runs it.
    steps.at("the control: taking the next action's lease");
    let deadline = world
        .lease()
        .await
        .expect("with no fence owed the next action is given a new lease");
    let waiting = world.forward_in_the_background(deadline);
    steps.at("the control: waiting for the worker to run the next action");
    let (link, answer) = ended(waiting).await;
    world.link = Some(link);
    answer.expect("the worker runs the action that holds a lease");

    // The revocation. An action holds a fresh lease at the shut serial boundary.
    steps.at("the revocation: taking the action's lease");
    let deadline = world.lease().await.expect("the action is given its lease");
    steps.at("the revocation: shutting the worker's serial boundary");
    let shut = Shut::hold(&world.runtime).await;
    let waiting = world.forward_in_the_background(deadline);
    steps.at("the revocation: waiting for the worker to hold the action");
    world.until_the_worker_holds(3).await;
    let held_at = world.controller.leases.authority_revision();

    // A restriction is made and its barrier raised, with the worker out of the directory it would
    // be announced to: nothing it does can acknowledge the revision this advances to.
    steps.at("the revocation: reading the fence owed before the restriction");
    assert_eq!(
        world.controller.fence_owed().await.0,
        None,
        "no fence is owed before the restriction"
    );
    steps.at("the revocation: raising the barrier");
    let barrier = world
        .controller
        .revoke_authority()
        .await
        .expect("the barrier is raised");
    let moved = world.controller.leases.authority_revision();
    assert!(moved > held_at, "the revocation advanced the revision");
    assert!(
        !barrier.holds(),
        "the barrier is not complete for a worker that has not acknowledged: {barrier:?}"
    );

    // The clock passes the lease, and the worker refuses the action that held it.
    world.clock.advance(Duration::from_secs(6));
    steps.at("the revocation: opening the worker's serial boundary");
    shut.open().await;
    steps.at("the revocation: waiting for the worker to refuse the action");
    let (link, answer) = ended(waiting).await;
    world.link = Some(link);
    let refused = answer.expect_err("the lease ran out before the action was dispatched");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        refused
            .message
            .contains("the accepted deadline for this action has passed"),
        "the worker refused it as expired: {refused:?}"
    );

    // Nothing renews it: the next action for this worker is given no lease.
    steps.at("the revocation: asking for the next action's lease");
    let before = world.controller.leases.current_lease(world.session_id);
    let refused = world
        .controller
        .dispatch_lease(world.session_id, &world.actor)
        .await
        .expect_err("a worker that has not acknowledged the revocation holds no lease");
    assert!(
        matches!(refused, super::LeaseDenied::NotAcknowledged(_)),
        "{refused:?}"
    );
    assert_eq!(
        world.controller.leases.current_lease(world.session_id),
        before,
        "no lease was issued"
    );
    let report = world
        .controller
        .leases
        .begin_round()
        .report(moved, [world.session_id]);
    assert!(!report.holds(), "the worker is pending: {report:?}");
    assert_eq!(
        report.workers[0].state,
        kr_protocol::action::BarrierState::Pending
    );
    steps.at("the revocation: reading the fence still owed");
    let (owed, unreadable) = world.controller.fence_owed().await;
    assert!(unreadable.is_none());
    assert_eq!(
        owed,
        Some(moved),
        "the fence the revocation owes is still owed: only an acknowledgement or an end retires it"
    );
}
