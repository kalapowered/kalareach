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

/// One daemon and one real worker on a clock the test moves.
struct World {
    _daemon_tree: kr_ipc::testing::TempHost,
    _worker_tree: kr_ipc::testing::TempHost,
    controller: Arc<Controller>,
    clock: ManualClock,
    runtime: Arc<SessionRuntime>,
    service: Arc<WorkerService>,
    /// The runtime the worker runs on, apart from the test's and the daemon's.
    ///
    /// A worker holds its session for the whole of an action, on the thread that serves it, and its
    /// process is its own. Here it shares this one, and a thread blocked in it would stand between
    /// the test's own tasks and the reactor they wait on; so it has threads of its own.
    worker_runtime: Option<tokio::runtime::Runtime>,
    session_id: SessionId,
    environment_id: EnvironmentId,
    /// The link the worker has to a daemon of generation one, over which a forward is sent.
    link: Option<LocalClient>,
    actor: ActorEnvelope,
}

/// Starts the daemon and the worker on one manual clock, with the worker's serial boundary free
/// and the daemon holding the worker's acknowledgement of the revision in force, its fence
/// reported, as a worker that has answered an announcement is.
async fn world() -> World {
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
    let runtime = Arc::new(
        SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
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

    let mut link = LocalClient::connect(&endpoint, LocalClientKind::Controller, build)
        .await
        .expect("connects");
    let proving = Arc::clone(&controller_identity);
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
    assert!(controller.leases.report(revision, [session_id]).holds());

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
        session_id,
        environment_id,
        link: Some(link),
        actor,
    }
}

impl Drop for World {
    fn drop(&mut self) {
        // Dropped from inside a runtime, which a runtime of its own may not be: it is let go of
        // without waiting for its threads.
        if let Some(runtime) = self.worker_runtime.take() {
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
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn a_lease_that_runs_out_at_a_worker_is_not_renewed_while_a_fence_is_owed() {
    let mut world = world().await;

    // The control. An action holds its lease at the worker's shut serial boundary, the clock passes
    // the lease, and the worker refuses the action as expired: that much the lapse does by itself.
    let deadline = world.lease().await.expect("the action is given its lease");
    let shut = Shut::hold(&world.runtime).await;
    let waiting = world.forward_in_the_background(deadline);
    world.until_the_worker_holds(1).await;
    world.clock.advance(Duration::from_secs(6));
    shut.open().await;
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
    let deadline = world
        .lease()
        .await
        .expect("with no fence owed the next action is given a new lease");
    let waiting = world.forward_in_the_background(deadline);
    let (link, answer) = ended(waiting).await;
    world.link = Some(link);
    answer.expect("the worker runs the action that holds a lease");

    // The revocation. An action holds a fresh lease at the shut serial boundary.
    let deadline = world.lease().await.expect("the action is given its lease");
    let shut = Shut::hold(&world.runtime).await;
    let waiting = world.forward_in_the_background(deadline);
    world.until_the_worker_holds(3).await;
    let held_at = world.controller.leases.authority_revision();

    // A restriction is made and its barrier raised, with the worker out of the directory it would
    // be announced to: nothing it does can acknowledge the revision this advances to.
    assert_eq!(
        world.controller.fence_owed().await.0,
        None,
        "no fence is owed before the restriction"
    );
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
    shut.open().await;
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
    let report = world.controller.leases.report(moved, [world.session_id]);
    assert!(!report.holds(), "the worker is pending: {report:?}");
    assert_eq!(
        report.workers[0].state,
        kr_protocol::action::BarrierState::Pending
    );
    let (owed, unreadable) = world.controller.fence_owed().await;
    assert!(unreadable.is_none());
    assert_eq!(
        owed,
        Some(moved),
        "the fence the revocation owes is still owed: only an acknowledgement or an end retires it"
    );
}
