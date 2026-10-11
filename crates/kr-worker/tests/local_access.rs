//! What a session's worker lets its local owner do on a host that holds the owner to a membership
//! lease (KR-REQ-17.54, the exclusive clause).
//!
//! The worker serves a local caller directly, so the hold is the worker's own as well as the
//! control daemon's. These tests use a real worker service on its real endpoint, a real shell, the
//! real handshake, and the daemon's side played by a connection that proves a controller
//! generation exactly as the daemon does. The machine's clocks are driven by hand, so a lease ends
//! when a test says it does and no test waits for time to pass.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{LIVENESS_DEADLINE, carries, produced, retained};
use kr_ipc::client::LocalClient;
use kr_ipc::clock::ManualSharedClock;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::envelope::{ActionTarget, ControlFrame, Outcome};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, AttachmentId, BuildId, ControllerGeneration, InputLeaseEpoch, InputSequence,
    SessionEpoch, SessionId,
};
use kr_protocol::input::{InputAcquireParams, InputWriteParams};
use kr_protocol::local::{ControllerConnectionRole, LocalClientKind};
use kr_protocol::method::Method;
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::scalars::{Bytes, CanonicalSet, Nullable, TimestampMs, U64};
use kr_protocol::session::{Dimensions, DisplayNumber, SessionReadParams, ShellMode};
use kr_protocol::worker::{LocalAccess, LocalBound};
use kr_worker::action::adapter::{RecordedTimeAdapter, UnixTimex, classify_unix};
use kr_worker::action::time::{ManualActiveClock, ManualWallClock, TimeSources, WallClock as _};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

/// How long the leases these tests tell a worker last, on whichever clock a test lets run out.
const LEASE_MS: u64 = 10_000;

/// A lease long enough that no clock a test drives reaches it.
const FAR_MS: u64 = 3_600_000;

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// The machine's three clocks and the floor the control daemon would publish, driven by hand.
struct Machine {
    continuous: ManualSharedClock,
    active: ManualActiveClock,
    wall: ManualWallClock,
    adapter: RecordedTimeAdapter,
    floor: Option<Arc<kr_ipc::floor::SharedFloor>>,
}

impl Machine {
    /// A machine whose time service keeps its clock. `with_floor` says whether the worker maps the
    /// host's clock floor, which a worker needs to decide any expiry stated in UTC.
    fn new(with_floor: bool) -> Self {
        let synchronised = classify_unix(
            "macos",
            "ntp_adjtime(2)",
            UnixTimex {
                time_state: kr_worker::action::adapter::unix_model::TIME_OK,
                status: kr_worker::action::adapter::unix_model::STA_PLL,
                maxerror_us: 62_192,
                esterror_us: 500,
            },
            TimestampMs::new(1_700_000_000_000),
        );
        Self {
            continuous: ManualSharedClock::new(),
            active: ManualActiveClock::new(),
            wall: ManualWallClock::new(1_700_000_000_000),
            adapter: RecordedTimeAdapter::new(synchronised),
            floor: with_floor.then(|| Arc::new(kr_ipc::floor::SharedFloor::in_process(0))),
        }
    }

    fn sources(&self) -> TimeSources {
        TimeSources {
            continuous: Arc::new(self.continuous.clone()),
            active: Arc::new(self.active.clone()),
            wall: Arc::new(self.wall.clone()),
            adapter: Arc::new(self.adapter.clone()),
            floor: self.floor.clone(),
        }
    }

    /// The machine runs awake for `duration`: all three clocks count it.
    fn runs(&self, duration: Duration) {
        self.continuous.advance(duration);
        self.active.advance(duration);
        self.wall.advance(duration);
    }

    /// The continuous clock now, in milliseconds since this boot.
    fn boot_ms(&self) -> u64 {
        kr_ipc::clock::SharedClock::boot_elapsed_ms(&self.continuous)
    }

    /// The wall clock now, in UTC milliseconds.
    fn utc_ms(&self) -> u64 {
        self.wall.now_ms().get()
    }

    /// The statement that a lease is live and ends `lasting` from now on the continuous clock and
    /// `lasting_utc` from now in UTC.
    fn lease(&self, sequence: u64, lasting: u64, lasting_utc: u64) -> LocalAccess {
        LocalAccess {
            sequence: U64::new(sequence),
            bound: LocalBound::Until {
                boot_deadline_ms: U64::new(self.boot_ms() + lasting),
                utc_deadline_ms: U64::new(self.utc_ms() + lasting_utc),
            },
        }
    }
}

fn open(sequence: u64) -> LocalAccess {
    LocalAccess {
        sequence: U64::new(sequence),
        bound: LocalBound::Open,
    }
}

fn closed(sequence: u64) -> LocalAccess {
    LocalAccess {
        sequence: U64::new(sequence),
        bound: LocalBound::Closed,
    }
}

/// A worker its daemon launched: born closed, told nothing yet.
struct World {
    _temp: kr_ipc::testing::TempHost,
    service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
    machine: Machine,
}

async fn world(script: &str, with_floor: bool) -> World {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let machine = Machine::new(with_floor);
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
    let store =
        kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
    let controller = Arc::new(
        ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity"),
    );
    let mut session = Session::open(SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script(script),
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
        time: machine.sources(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    })
    .expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime = Arc::new(
        SessionRuntime::start(session, Arc::new(machine.continuous.clone()))
            .expect("starts the runtime"),
    );
    let endpoint = environment
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let service = Arc::new(
        WorkerService::new(
            Arc::clone(&runtime),
            identity,
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot.clone(),
                controller_public_key: *controller.public_key(),
                controller_generation: ControllerGeneration::new(1),
                build_id: build(),
                journal_path: None,
            },
        )
        .expect("a worker service"),
    );
    // What the launch specification of a worker its daemon tells does before the endpoint serves.
    service.hold_local_access_until_told();
    tokio::spawn(Arc::clone(&service).serve(listener));
    World {
        _temp: temp,
        service,
        runtime,
        session_id,
        environment_id,
        endpoint,
        controller,
        boot,
        machine,
    }
}

impl World {
    /// One of the owner's own windows: a connection on the worker's own socket, as `kr attach`
    /// makes one.
    async fn window(&self) -> LocalClient {
        LocalClient::connect(&self.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects")
    }

    /// One of the control daemon's connections, for `generation`, in `role`.
    async fn daemon(&self, generation: u64, role: ControllerConnectionRole) -> LocalClient {
        let mut daemon = LocalClient::connect(&self.endpoint, LocalClientKind::Controller, build())
            .await
            .expect("connects as the daemon");
        daemon
            .writer()
            .write_message(&ControlFrame::ControllerRole(role))
            .await
            .expect("declares the role");
        match daemon.recv().await.expect("the worker answers") {
            ControlFrame::ControllerRole(declared) => assert_eq!(declared, role),
            other => panic!("the worker answered {other:?}"),
        }
        let identity = Arc::clone(&self.controller);
        let boot = self.boot.clone();
        daemon
            .present_generation(move |nonce| {
                identity
                    .generation_token(ControllerGeneration::new(generation), &boot, nonce)
                    .map_err(kr_ipc::IpcError::from)
            })
            .await
            .expect("the worker accepts the generation");
        daemon
    }

    /// The daemon's authority connection for `generation`.
    async fn authority(&self, generation: u64) -> LocalClient {
        self.daemon(generation, ControllerConnectionRole::Authority)
            .await
    }

    fn target(&self) -> ActionTarget {
        ActionTarget {
            environment_id: self.environment_id,
            session_id: Nullable::some(self.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    /// A read of the session, which is held to the lease. Returns what the worker answered.
    async fn read(&self, window: &mut LocalClient) -> Result<(), ProtocolError> {
        window
            .request(
                Method::SessionRead,
                &SessionReadParams {
                    session_id: self.session_id,
                },
            )
            .await
            .expect("the worker answers")
            .map(|_| ())
    }

    /// Attaches a terminal that observes and types, in one of the owner's windows.
    async fn attach(&self, window: &mut LocalClient) -> AttachmentId {
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        let attached: kr_protocol::attachment::SessionAttachResult = window
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(),
                &SessionAttachParams {
                    session_id: self.session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(Dimensions::new(80, 24)),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the attach is admitted")
            .to_typed()
            .expect("an attachment");
        attached.attachment.attachment_id
    }

    /// Takes the input lease for `attachment_id` and returns its epoch.
    async fn acquire(&self, window: &mut LocalClient, attachment_id: AttachmentId) -> u64 {
        let acquired: kr_protocol::input::InputAcquireResult = window
            .mutate(
                Method::InputAcquire,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(),
                &InputAcquireParams {
                    session_id: self.session_id,
                    attachment_id,
                    expected_epoch: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the lease is granted")
            .to_typed()
            .expect("a lease");
        acquired.lease.epoch.get()
    }

    /// Subscribes `attachment_id` to the session's output.
    async fn subscribe(&self, window: &mut LocalClient, attachment_id: AttachmentId) {
        let mut streams = CanonicalSet::new();
        streams.insert(EventStream::Output);
        window
            .request(
                Method::EventsSubscribe,
                &EventsSubscribeParams {
                    session_id: self.session_id,
                    attachment_id,
                    streams,
                    from_cursor: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the subscription is admitted");
    }

    /// Types `bytes` as the lease holder.
    async fn type_as(
        &self,
        window: &mut LocalClient,
        attachment_id: AttachmentId,
        epoch: u64,
        sequence: u64,
        bytes: &[u8],
    ) -> Result<(), ProtocolError> {
        window
            .request(
                Method::InputWrite,
                &InputWriteParams {
                    session_id: self.session_id,
                    attachment_id,
                    epoch: InputLeaseEpoch::new(epoch),
                    sequence: InputSequence::new(sequence),
                    bytes: Bytes::new(bytes.to_vec()),
                },
            )
            .await
            .expect("the worker answers")
            .map(|_| ())
    }

    /// Whether the session holds an input lease, and an attachment, at this moment.
    fn holds_nothing(&self) -> bool {
        let session = self.runtime.session();
        session.lease().holder.0.is_none() && session.attachments().is_empty()
    }

    fn close(&self) {
        self.runtime
            .close(kr_protocol::session::ClosureReason::CloseRequested)
            .1
            .release();
    }
}

/// Tells the worker over `daemon` and returns the sequence it holds afterwards.
async fn tell(daemon: &mut LocalClient, access: LocalAccess) -> u64 {
    daemon
        .announce_local_access(access)
        .await
        .expect("the worker takes the statement")
        .sequence
        .get()
}

/// Asserts that the worker refused a held request, for a reason that mentions `why`.
fn refused(answer: Result<(), ProtocolError>, why: &str) {
    let error = answer.expect_err("the held request is refused");
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
    assert!(error.message.contains(why), "{error:?}");
}

/// Waits until `check` holds, which must happen before the deadline.
async fn eventually(what: &str, mut check: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + LIVENESS_DEADLINE;
    while !check() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "it did not happen: {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// KR-REQ-17.54: only the control daemon's authority connection says what the local owner may do.
///
/// A window on the worker's socket, which is the local owner, cannot lift its own hold by telling
/// the worker the host is open, and neither can a daemon connection that is not the authority
/// connection. The control: the authority connection's statement is taken, and serves the window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_daemons_authority_connection_says_what_the_local_owner_may_do() {
    let world = world("sleep 30", true).await;
    let mut window = world.window().await;
    refused(world.read(&mut window).await, "not yet told");

    window
        .writer()
        .write_message(&ControlFrame::LocalAccess(open(1)))
        .await
        .expect("writes the statement");
    let ControlFrame::Response(response) = window.recv().await.expect("the worker answers") else {
        panic!("a statement from a window is answered with a refusal");
    };
    let Outcome::Error(error) = response.outcome else {
        panic!("a window cannot say what the local owner may do");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
    refused(world.read(&mut window).await, "not yet told");

    let mut proxy = world.daemon(1, ControllerConnectionRole::Proxy).await;
    proxy
        .announce_local_access(open(1))
        .await
        .expect_err("a proxy connection of the daemon does not speak for the host");
    refused(world.read(&mut window).await, "not yet told");

    let mut authority = world.authority(1).await;
    assert_eq!(tell(&mut authority, open(1)).await, 1);
    world
        .read(&mut window)
        .await
        .expect("the authority connection's statement serves the window");
    world.close();
}

/// KR-REQ-17.54: the worker applies the daemon's statements in order, within the generation that
/// sends them, and a newer generation's first statement replaces what an older one said whatever
/// its sequence.
///
/// A statement of a lower sequence is answered with the sequence the worker holds and changes
/// nothing. The same sequence with another content is refused. A newer daemon starts again from a
/// low sequence, and its statement stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_worker_applies_the_daemons_statements_in_order_and_a_newer_generation_replaces_them() {
    let world = world("sleep 30", true).await;
    let mut window = world.window().await;
    let mut first = world.authority(1).await;

    assert_eq!(tell(&mut first, closed(2)).await, 2);
    refused(world.read(&mut window).await, "not live");
    assert_eq!(
        tell(&mut first, open(1)).await,
        2,
        "an older statement is answered with the one held"
    );
    refused(world.read(&mut window).await, "not live");
    first
        .announce_local_access(open(2))
        .await
        .expect_err("the same sequence with another content is a conflict");
    refused(world.read(&mut window).await, "not live");
    assert_eq!(tell(&mut first, open(3)).await, 3);
    world.read(&mut window).await.expect("open serves");

    // A newer daemon: its first statement has a lower sequence than the last of the old one.
    let mut second = world.authority(2).await;
    world
        .read(&mut window)
        .await
        .expect("a bound that carries no lease stands until the newer daemon speaks");
    assert_eq!(tell(&mut second, closed(1)).await, 1);
    refused(world.read(&mut window).await, "not live");

    // And a closed host stays closed across a still newer daemon until it says otherwise.
    let _third = world.authority(3).await;
    refused(world.read(&mut window).await, "not live");
    world.close();
}

/// KR-REQ-17.54: a daemon that has been superseded cannot reopen what a newer one closed.
///
/// The newer daemon's connection fences the older one's, so a statement of the old generation is
/// refused whatever it says, and the host stays as the newer daemon left it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_superseded_daemon_cannot_reopen_what_a_newer_one_closed() {
    let world = world("sleep 30", true).await;
    let mut window = world.window().await;
    let mut old = world.authority(1).await;
    tell(&mut old, open(1)).await;
    world.read(&mut window).await.expect("open serves");

    let mut new = world.authority(2).await;
    assert_eq!(tell(&mut new, closed(1)).await, 1);
    refused(world.read(&mut window).await, "not live");

    old.announce_local_access(open(9))
        .await
        .expect_err("the superseded daemon's statement is refused");
    refused(world.read(&mut window).await, "not live");
    world.close();
}

/// KR-REQ-17.54: a lease the daemon told does not outlive the daemon that told it.
///
/// A worker that holds a lease when a newer daemon takes over waits to be told again: the old
/// daemon's lease might have been withdrawn by a record the new one holds. An open host does not
/// wait, and a window attached to it keeps its stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_does_not_outlive_the_daemon_that_told_it_and_an_open_host_keeps_serving() {
    let world = world("sleep 30", true).await;
    let mut window = world.window().await;
    let mut first = world.authority(1).await;
    tell(&mut first, world.machine.lease(1, FAR_MS, FAR_MS)).await;
    world.read(&mut window).await.expect("the lease serves");

    let mut second = world.authority(2).await;
    refused(world.read(&mut window).await, "not yet told");
    assert_eq!(tell(&mut second, open(1)).await, 1);
    world.read(&mut window).await.expect("open serves");

    // An attachment made under an open host is not withdrawn when a newer daemon takes over.
    let attachment = world.attach(&mut window).await;
    let _third = world.authority(3).await;
    world
        .read(&mut window)
        .await
        .expect("the window is served as before");
    assert!(
        world
            .runtime
            .session()
            .attachments()
            .iter()
            .any(|summary| summary.attachment_id == attachment),
        "the window's attachment stands"
    );
    world.close();
}

/// KR-REQ-17.54: a lease ends the local owner's access on the worker's own continuous clock, with
/// no word from the daemon, and the next one serves the same connection again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_ends_on_the_continuous_clock_and_a_new_one_serves_the_same_connection_again() {
    let world = world("sleep 30", true).await;
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;

    tell(&mut daemon, world.machine.lease(1, LEASE_MS, FAR_MS)).await;
    world.read(&mut window).await.expect("the lease serves");
    world.machine.runs(Duration::from_millis(LEASE_MS - 1));
    world
        .read(&mut window)
        .await
        .expect("the lease serves until its end");
    world.machine.runs(Duration::from_millis(2));
    refused(world.read(&mut window).await, "has ended");

    tell(&mut daemon, world.machine.lease(2, FAR_MS, FAR_MS)).await;
    world
        .read(&mut window)
        .await
        .expect("a new lease serves the same connection");
    world.close();
}

/// KR-REQ-17.54: a lease's UTC end is decided through the worker's time contract, so a wall clock
/// set forward ends a lease the continuous clock has not reached.
///
/// Only the wall clock moves. A worker that watched the continuous end alone would serve on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_ends_when_the_wall_clock_passes_its_utc_end_with_the_continuous_clock_held() {
    let world = world("sleep 30", true).await;
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;

    tell(&mut daemon, world.machine.lease(1, FAR_MS, LEASE_MS)).await;
    world.read(&mut window).await.expect("the lease serves");
    world
        .machine
        .wall
        .advance(Duration::from_millis(LEASE_MS + 1));
    refused(world.read(&mut window).await, "has ended");
    world.close();
}

/// KR-REQ-17.54: a worker that maps no clock floor cannot decide a lease's UTC end, so it serves
/// none; the end that is not decided is refused rather than assumed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_with_no_clock_floor_serves_no_lease() {
    let world = world("sleep 30", false).await;
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, world.machine.lease(1, FAR_MS, FAR_MS)).await;
    refused(world.read(&mut window).await, "has ended");
    assert_eq!(tell(&mut daemon, open(2)).await, 2);
    world
        .read(&mut window)
        .await
        .expect("a host that needs no lease needs no clock");
    world.close();
}

/// KR-REQ-17.54: a statement that takes access away ends what a local connection holds: its
/// attachment and its input lease.
///
/// The connection is withdrawn, so the input lease it held is released and its attachment is
/// detached. A statement that gives more than the one before it does none of this. The connection
/// holds no subscription and the shell is quiet, so no frame is written to it that could end it:
/// only the statement does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_statement_that_takes_access_away_withdraws_what_a_local_connection_holds() {
    let world = world("sleep 30", true).await;
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, world.machine.lease(1, FAR_MS, FAR_MS)).await;

    let attachment = world.attach(&mut window).await;
    world.acquire(&mut window, attachment).await;
    assert!(!world.holds_nothing());

    // A later end gives more: nothing is taken.
    tell(&mut daemon, world.machine.lease(2, 2 * FAR_MS, 2 * FAR_MS)).await;
    assert!(!world.holds_nothing());

    tell(&mut daemon, closed(3)).await;
    eventually("the lease and the attachment are released", || {
        world.holds_nothing()
    })
    .await;
    world.close();
}

/// KR-REQ-17.54: a lease that runs out while a stream is open ends the stream with no word from
/// the daemon: the first frame the worker may not write is not written, and the connection's
/// holdings are withdrawn, so the input lease it held is released.
///
/// The shell prints a line every second, so the stream has a next frame to refuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_that_runs_out_ends_the_stream_the_worker_was_sending() {
    let world = world("while true; do printf 'line\\n'; sleep 1; done", true).await;
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, world.machine.lease(1, LEASE_MS, FAR_MS)).await;

    let attachment = world.attach(&mut window).await;
    world.acquire(&mut window, attachment).await;
    world.subscribe(&mut window, attachment).await;
    loop {
        if let ControlFrame::Notification(notification) =
            window.recv().await.expect("the stream delivers")
            && notification.event_type.as_str() == "session.output"
        {
            break;
        }
    }

    world.machine.runs(Duration::from_millis(LEASE_MS + 1));
    eventually("the lease and the attachment are released", || {
        world.holds_nothing()
    })
    .await;
    world.close();
}

/// KR-REQ-17.54: a mutation inside the dispatch boundary when the host restricts its local owner
/// is not dispatched, even if the host is open again by the time it is released.
///
/// The worker stops the mutation the moment it holds the boundary. The daemon closes the host and
/// opens it again. The gate allows the mutation now, and what refuses it is that the owner was
/// restricted while it waited: it was admitted under a state that has since been taken away.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_mutation_inside_the_dispatch_boundary_when_the_host_restricts_its_owner_is_not_dispatched()
 {
    let world = world("sleep 30", true).await;
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;

    let (inside, release) = world.service.pause_inside_boundary();
    let target = world.target();
    let session_id = world.session_id;
    let attaching = tokio::spawn(async move {
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        let outcome = window
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &SessionAttachParams {
                    session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(Dimensions::new(80, 24)),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
            .expect("the call reaches the worker");
        (window, outcome)
    });
    let arrived =
        tokio::task::spawn_blocking(move || inside.recv_timeout(LIVENESS_DEADLINE).is_ok())
            .await
            .expect("the waiting thread finishes");
    assert!(arrived, "the mutation never took the dispatch boundary");

    tell(&mut daemon, closed(2)).await;
    tell(&mut daemon, open(3)).await;
    release.send(()).expect("lets the mutation go");

    let (_window, outcome) = attaching.await.expect("the mutation ends");
    let error = outcome.expect_err("a mutation admitted before a restriction is not dispatched");
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
    assert!(
        world.runtime.session().attachments().is_empty(),
        "nothing was attached"
    );
    world.close();
}

/// KR-REQ-17.54: input that a local owner's connection had sent and the worker had not yet taken
/// the session for is not written once the host restricts the owner.
///
/// The batch has passed the lease check and stands before the session. The daemon closes the host
/// and it opens again. A second window then types, and the worker's writer is serial, so once the
/// second window's bytes have reached the application the first window's either arrived before
/// them or never will.
///
/// The connection holding the attachment is withdrawn by the restriction, which refuses the batch
/// as well, so this does not show the recheck inside the session by itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn input_waiting_for_the_session_when_the_host_restricts_its_owner_is_not_written() {
    let world = world("stty raw -echo; printf 'kr-ready.'; exec cat", true).await;
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;

    let attachment = world.attach(&mut window).await;
    let epoch = world.acquire(&mut window, attachment).await;
    world
        .type_as(&mut window, attachment, epoch, 0, b"kr-early")
        .await
        .expect("input under an open host is written");

    let (arrived, release) = world.service.pause_input_before_the_session();
    let session_id = world.session_id;
    let typing = tokio::spawn(async move {
        let outcome = window
            .request(
                Method::InputWrite,
                &InputWriteParams {
                    session_id,
                    attachment_id: attachment,
                    epoch: InputLeaseEpoch::new(epoch),
                    sequence: InputSequence::new(1),
                    bytes: Bytes::new(b"kr-late".to_vec()),
                },
            )
            .await;
        drop(window);
        outcome
    });
    let reached =
        tokio::task::spawn_blocking(move || arrived.recv_timeout(LIVENESS_DEADLINE).is_ok())
            .await
            .expect("the waiting thread finishes");
    assert!(reached, "the batch never reached the pause");

    tell(&mut daemon, closed(2)).await;
    tell(&mut daemon, open(3)).await;
    release.send(()).expect("lets the batch go");
    let _ = typing.await.expect("the request ends");

    let mut second = world.window().await;
    let again = world.attach(&mut second).await;
    let epoch = world.acquire(&mut second, again).await;
    world
        .type_as(&mut second, again, epoch, 0, b"kr-after")
        .await
        .expect("a new window types");
    produced(&world.runtime, b"kr-after").await;
    let seen = retained(&world.runtime);
    assert!(
        carries(&seen, b"kr-early"),
        "input under an open host was written: {seen:?}"
    );
    assert!(
        !carries(&seen, b"kr-late"),
        "the batch the restriction overtook was not written: {seen:?}"
    );
    world.close();
}

/// KR-REQ-17.54: bytes accepted under a lease whose end passes in UTC while they wait for the
/// terminal are not written after it.
///
/// The writer asks again, at the boundary that hands bytes to the application, whether the lease
/// they were accepted under is still live. Only the UTC end passes here: the continuous clock is
/// held, so a writer that watched the continuous end alone would write them. The wall clock is
/// stepped forward between the acceptance and the hand-over.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bytes_queued_under_a_lease_whose_utc_end_passes_while_they_wait_are_never_written() {
    use kr_worker::session::InputAuthority;

    let world = world("stty raw -echo; printf 'kr-ready.'; exec cat", true).await;
    produced(&world.runtime, b"kr-ready.").await;
    let (attachment, epoch) = {
        let mut session = world.runtime.session();
        let attachment = AttachmentId::new(kr_ipc::new_uuid());
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        session
            .attach(
                &SessionAttachParams {
                    session_id: world.session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(Dimensions::new(80, 24)),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested: requested.clone(),
                },
                requested,
                attachment,
            )
            .expect("attaches");
        let held = session
            .acquire_input(
                attachment,
                kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid()),
                None,
            )
            .expect("the keys");
        (attachment, held.lease.epoch.get())
    };
    let queue = |sequence: u64, bytes: &[u8], ends_at: u64| {
        let mut session = world.runtime.session();
        session
            .write_input_until(
                attachment,
                epoch,
                sequence,
                bytes,
                InputAuthority {
                    boot_ms: None,
                    utc_ms: Some(ends_at),
                },
                std::time::Instant::now(),
            )
            .expect("accepted");
        world.runtime.flush_locked(&mut session);
    };

    queue(0, b"kr-inside", world.machine.utc_ms() + LEASE_MS);
    produced(&world.runtime, b"kr-inside").await;

    // Accepted while the lease stood, handed to the writer after its UTC end had passed.
    {
        let mut session = world.runtime.session();
        session
            .write_input_until(
                attachment,
                epoch,
                1,
                b"kr-expired",
                InputAuthority {
                    boot_ms: None,
                    utc_ms: Some(world.machine.utc_ms() + LEASE_MS),
                },
                std::time::Instant::now(),
            )
            .expect("accepted");
        world
            .machine
            .wall
            .advance(Duration::from_millis(LEASE_MS + 1));
        world.runtime.flush_locked(&mut session);
    }
    // The writer is serial: once the batch behind it has arrived, the one in front of it has
    // either arrived or was never written.
    queue(2, b"kr-after", world.machine.utc_ms() + FAR_MS);
    produced(&world.runtime, b"kr-after").await;
    let seen = retained(&world.runtime);
    assert!(
        !carries(&seen, b"kr-expired"),
        "nothing written after the lease's UTC end reaches the application: {seen:?}"
    );
    world.close();
}
