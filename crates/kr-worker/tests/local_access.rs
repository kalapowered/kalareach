//! What a session's worker lets its local owner do on a host that holds the owner to a membership
//! lease, the exclusive clause.
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
use kr_ipc::client::{BoundLink, Client, Codec, LocalClient};
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
use kr_protocol::input::{InputAcquireParams, InputContent, InputWriteParams};
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
    service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
    machine: Machine,
    // Declared last: the directory is removed after every field above has let go of its files.
    _temp: kr_ipc::testing::TempHost,
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
    async fn daemon(&self, generation: u64, role: ControllerConnectionRole) -> BoundLink {
        let mut daemon = BoundLink::connect(&self.endpoint, build())
            .await
            .expect("connects as the daemon");
        daemon
            .send(&ControlFrame::ControllerRole(role))
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
    async fn authority(&self, generation: u64) -> BoundLink {
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
    async fn read(&self, window: &mut Client<impl Codec>) -> Result<(), ProtocolError> {
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
    async fn attach(&self, window: &mut Client<impl Codec>) -> AttachmentId {
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
    async fn acquire(&self, window: &mut Client<impl Codec>, attachment_id: AttachmentId) -> u64 {
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
    async fn subscribe(&self, window: &mut Client<impl Codec>, attachment_id: AttachmentId) {
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
        window: &mut Client<impl Codec>,
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
                    input: InputContent::Bytes {
                        bytes: Bytes::new(bytes.to_vec()),
                    },
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
async fn tell(daemon: &mut Client<impl Codec>, access: LocalAccess) -> u64 {
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
        .send(&ControlFrame::LocalAccess(open(1)))
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
    let world = world("exec cat", true).await;
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

/// KR-REQ-17.54: a lease that runs out while a stream is open ends what the connection holds with
/// no word from the daemon: the first frame the worker may not write is not written and the
/// connection's holdings are withdrawn, so the input lease it held is released. What the test
/// shows is the release; that no frame follows the end is the writer's rule, shown beside the
/// request-identifier cases in the gate's own tests.
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

/// KR-REQ-17.54: a mutation that was admitted before the host restricted its local owner, and
/// takes the dispatch boundary after, is not dispatched, even if the host is open again by the
/// time it takes it.
///
/// The worker stops the mutation after the checks of its entry and before it takes the boundary.
/// The daemon closes the host and opens it again. The gate allows the mutation now, and what
/// refuses it is that the owner was restricted while it waited: it was admitted under a state that
/// has since been taken away. A mutation that already holds the boundary is not in this case: the
/// statement is acknowledged only after it has ended, as the case that follows shows.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_mutation_admitted_before_the_host_restricts_its_owner_is_not_dispatched_after_the_restriction()
 {
    let world = world("exec cat", true).await;
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;

    let (inside, release) = world.service.pause_before_the_boundary();
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
    assert!(
        arrived,
        "the mutation never reached the stop before the dispatch boundary"
    );

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
///
/// The first window's input is waited for before the host closes. The worker answers a write once
/// the bytes are queued for its writer, and the restriction ends the window's lease, which drops
/// whatever the writer has not yet put on the terminal. The control that an open host writes is
/// input the application has read.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn input_waiting_for_the_session_when_the_host_restricts_its_owner_is_not_written() {
    let world = world("stty raw -echo; printf 'kr-ready.'; exec cat", true).await;
    // Waited for, because until the program has put the terminal into raw mode with the echo off
    // the line discipline echoes what is typed and the program never reads it.
    produced(&world.runtime, b"kr-ready.").await;
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;

    let attachment = world.attach(&mut window).await;
    let epoch = world.acquire(&mut window, attachment).await;
    // The shell sets the terminal raw before it prints its marker: input typed before that is
    // taken by the line discipline of a terminal that is not raw yet.
    produced(&world.runtime, b"kr-ready.").await;
    world
        .type_as(&mut window, attachment, epoch, 0, b"kr-early")
        .await
        .expect("input under an open host is written");
    produced(&world.runtime, b"kr-early").await;

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
                    input: InputContent::Bytes {
                        bytes: Bytes::new(b"kr-late".to_vec()),
                    },
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
        world.runtime.flush_input();
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
        world.runtime.flush_input();
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

/// A method the registry lists and the worker has no row for in its table of what it serves is
/// refused as unlisted, as a read and as a mutation, before a parameter is read. The table is what
/// a level of the protocol fixes of a worker, so a method outside it is not served. The control: a
/// method with a row is served on the same connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_method_the_worker_does_not_serve_is_refused_as_unlisted() {
    let world = world("sleep 30", false).await;
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;
    world
        .read(&mut window)
        .await
        .expect("session.read has a row");

    let params = SessionReadParams {
        session_id: world.session_id,
    };
    let read = window
        .request(Method::HostInfo, &params)
        .await
        .expect("the worker answers")
        .expect_err("host.info is the daemon's");
    assert_eq!(read.code, ErrorCode::PermissionDenied, "{read:?}");
    assert_eq!(read.message, kr_protocol::local::METHOD_NOT_REACHABLE);

    let mutation = window
        .mutate(
            Method::TerminalPaletteSet,
            ActionId::new(kr_ipc::new_uuid()),
            world.target(),
            &params,
        )
        .await
        .expect("the worker answers")
        .expect_err("terminal.palette.set is not served");
    assert_eq!(mutation.code, ErrorCode::PermissionDenied, "{mutation:?}");
    assert_eq!(mutation.message, kr_protocol::local::METHOD_NOT_REACHABLE);
    world.close();
}

/// Runs `work` as a task and waits for its end on a thread of the blocking pool, until `deadline`.
///
/// While a path of the worker is held, or stuck, the runtime's own timers are not a wait to rely
/// on, so the wait is a thread that does not belong to the runtime's workers. Returns what `work`
/// gave, or nothing when it had not ended by `deadline`.
async fn ends_by<T: Send + 'static>(
    deadline: std::time::Instant,
    work: impl std::future::Future<Output = T> + Send + 'static,
) -> Option<T> {
    let (done, ended) = std::sync::mpsc::channel();
    tokio::spawn(async move {
        let _ = done.send(work.await);
    });
    tokio::task::spawn_blocking(move || {
        ended
            .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            .ok()
    })
    .await
    .ok()
    .flatten()
}

/// Whether `condition` holds by `deadline`, looked at on a thread of the blocking pool.
async fn holds_by(
    deadline: std::time::Instant,
    condition: impl Fn() -> bool + Send + 'static,
) -> bool {
    tokio::task::spawn_blocking(move || {
        while !condition() {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        true
    })
    .await
    .unwrap_or(false)
}

/// Waits on a thread of the blocking pool for a message on `end`, until `deadline`.
async fn received_by<T: Send + 'static>(
    deadline: std::time::Instant,
    end: std::sync::mpsc::Receiver<T>,
) -> Option<T> {
    tokio::task::spawn_blocking(move || {
        end.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            .ok()
    })
    .await
    .ok()
    .flatten()
}

/// Sends the daemon's statement `access` on a task of its own. Returns the flag that says the
/// daemon has its acknowledgement, and the end that gives the daemon's connection back.
fn start_the_statement(
    daemon: BoundLink,
    access: LocalAccess,
) -> (
    Arc<std::sync::atomic::AtomicBool>,
    std::sync::mpsc::Receiver<BoundLink>,
) {
    let acknowledged = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&acknowledged);
    let (given_back, daemon_end) = std::sync::mpsc::channel();
    tokio::spawn(async move {
        let mut daemon = daemon;
        tell(&mut daemon, access).await;
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = given_back.send(daemon);
    });
    (acknowledged, daemon_end)
}

/// Whether the flag is set.
fn is_set(flag: &std::sync::atomic::AtomicBool) -> bool {
    flag.load(std::sync::atomic::Ordering::SeqCst)
}

/// What the meeting of a withdrawal and a delivery's start came to.
struct Meeting {
    withdrawal_ended: bool,
    delivery_ended: bool,
    withdrawn: bool,
}

/// One connection that attaches and subscribes between a withdrawal's look at its empty attachment
/// list and its look at its delivery slot, and whose delivery's start holds that slot while it
/// waits for the connection registry.
///
/// Returns what the schedule came to, or the step that did not happen.
///
/// The session's shell does not end by itself, so the session stays open for as long as the
/// schedule's own deadline allows.
async fn the_meeting_of_a_withdrawal_and_a_delivery_start() -> Result<Meeting, &'static str> {
    let world = Arc::new(world("exec cat", true).await);
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;
    world
        .read(&mut window)
        .await
        .expect("the window is served under an open host");

    let (withdrawal_arrived, withdrawal_go) = world.service.stall_withdrawal_after_an_empty_look();
    let (slot_arrived, slot_go) = world.service.stall_delivery_after_its_slot();
    let (end_arrived, end_go) = world.service.stall_delivery_at_the_end_of_its_start();
    // The end of the start is only watched: nothing holds it.
    drop(end_go);
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;

    // The host takes access away with a lease that is still valid, so the window is served again
    // under it. The worker withdraws what the window holds, and stops after its look at the
    // window's empty list.
    let lease = world.machine.lease(2, FAR_MS, FAR_MS);
    let (told, told_end) = std::sync::mpsc::channel();
    tokio::spawn(async move {
        tell(&mut daemon, lease).await;
        let _ = told.send(());
    });
    if ends_by(deadline, async move { withdrawal_arrived.await.is_ok() }).await != Some(true) {
        return Err("the withdrawal never reached its look at the window's empty list");
    }

    // While it stands there, the window attaches and subscribes, and the delivery's start takes
    // the window's slot.
    let attached = Arc::clone(&world);
    let subscribed = ends_by(deadline, async move {
        let attachment = attached.attach(&mut window).await;
        attached.subscribe(&mut window, attachment).await;
        window
    })
    .await;
    let Some(window) = subscribed else {
        return Err("the window did not attach and subscribe");
    };
    if ends_by(deadline, async move { slot_arrived.await.is_ok() }).await != Some(true) {
        return Err("the delivery's start never took the window's slot");
    }

    withdrawal_go.send(()).expect("lets the withdrawal go");
    slot_go.send(()).expect("lets the delivery's start go");

    // Both have to end. Where they wait for each other, neither does.
    let withdrawal_ended = tokio::task::spawn_blocking(move || {
        told_end
            .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            .is_ok()
    })
    .await
    .unwrap_or(false);
    let delivery_ended =
        ends_by(deadline, async move { end_arrived.await.is_ok() }).await == Some(true);
    let held = Arc::clone(&world);
    let withdrawn = holds_by(deadline, move || held.holds_nothing()).await;
    if withdrawal_ended && delivery_ended && withdrawn {
        drop(window);
        world.close();
    }
    Ok(Meeting {
        withdrawal_ended,
        delivery_ended,
        withdrawn,
    })
}

/// KR-REQ-17.54: a withdrawal of the local owner's connections and the start of a delivery on one
/// of them do not wait for each other.
///
/// The host takes access away from the local owner with a lease that is still valid. The worker
/// has looked at a window that holds nothing when the window attaches and subscribes, and the
/// start of its delivery holds the window's delivery slot while it waits for the connection
/// registry. The withdrawal goes on to the slot, and has to find the window holding a delivery and
/// withdraw it. A withdrawal that held the registry while it waited for the slot would wait for a
/// delivery that waits for the registry, and the worker would stop answering.
///
/// The two paths run on the runtime's threads, and what the test waits on is a thread of its own,
/// with a deadline. Where they do wait for each other their threads never come back, so the
/// runtime is let go of without waiting for them.
#[test]
fn a_withdrawal_and_a_delivery_start_on_one_connection_both_end() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("a runtime");
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(the_meeting_of_a_withdrawal_and_a_delivery_start())
    }));
    runtime.shutdown_background();
    let meeting = match outcome {
        Ok(Ok(meeting)) => meeting,
        Ok(Err(step)) => panic!("the schedule did not come about: {step}"),
        Err(panic) => std::panic::resume_unwind(panic),
    };
    assert!(
        meeting.withdrawal_ended && meeting.delivery_ended,
        "the withdrawal and the delivery's start did not both end (withdrawal ended: {}, \
         delivery's start ended: {}): each waits for the lock the other holds",
        meeting.withdrawal_ended,
        meeting.delivery_ended,
    );
    assert!(
        meeting.withdrawn,
        "the window that held a delivery was not withdrawn"
    );
}

/// What the session holds of attachments and geometry at one moment.
#[derive(Debug, PartialEq)]
struct Held {
    attachments: Vec<AttachmentId>,
    geometry: kr_protocol::attachment::GeometryState,
}

fn held(world: &World) -> Held {
    let session = world.runtime.session();
    Held {
        attachments: session
            .attachments()
            .into_iter()
            .map(|summary| summary.attachment_id)
            .collect(),
        geometry: session.geometry(),
    }
}

/// What the meeting of an attach and a statement that takes access away came to.
struct Landing {
    attach_ended: bool,
    at_the_acknowledgement: Held,
    afterwards: Held,
    /// What the session held before the attach.
    before: Held,
}

/// One window whose attach has passed the dispatch boundary's check of the local owner's access
/// and stands before the session, and a statement that takes access away and is acknowledged
/// while it stands.
///
/// The attach claims the geometry with a size of its own, so it resizes the session and resets
/// what every subscriber is shown. Returns what the session held when the statement was
/// acknowledged, and what it holds once the attach has ended, or the step that did not happen.
///
/// The session's shell does not end by itself, so the session stays open for as long as the
/// schedule's own deadline allows.
async fn the_meeting_of_an_attach_and_a_statement() -> Result<Landing, &'static str> {
    let world = Arc::new(world("exec cat", true).await);
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;
    world
        .read(&mut window)
        .await
        .expect("the window is served under an open host");

    let before = held(&world);
    let (checked, go) = world.service.stall_a_mutation_after_its_dispatch_check();
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;

    // The window attaches and claims a size of its own. Its attach passes the check under the
    // open host and stops before the session.
    let attach_ended = start_the_geometry_attach(&world, window);
    if ends_by(deadline, async move { checked.await.is_ok() }).await != Some(true) {
        return Err("the attach never passed the dispatch boundary's check");
    }

    // The host takes access away with a lease that is still valid. What the session holds is
    // read at the moment the daemon has its acknowledgement.
    let lease = world.machine.lease(2, FAR_MS, FAR_MS);
    let acknowledged: Arc<std::sync::Mutex<Option<Held>>> = Arc::default();
    let at_the_acknowledgement = Arc::clone(&acknowledged);
    let reader = Arc::clone(&world);
    tokio::spawn(async move {
        tell(&mut daemon, lease).await;
        let seen = tokio::task::spawn_blocking(move || held(&reader))
            .await
            .expect("the session is read");
        *at_the_acknowledgement
            .lock()
            .expect("the record is not poisoned") = Some(seen);
        daemon
    });
    // The statement either is acknowledged at once, which leaves the attach standing before the
    // session, or it waits for the hold that the attach is in. Either way the attach is let go
    // now, and the acknowledgement is waited for after.
    let waiting = Arc::clone(&acknowledged);
    let service = Arc::clone(&world.service);
    if !holds_by(deadline, move || {
        waiting
            .lock()
            .expect("the record is not poisoned")
            .is_some()
            || service.statements_waiting_for_tests() > 0
    })
    .await
    {
        return Err("the statement was neither acknowledged nor waiting");
    }

    go.send(()).expect("lets the attach go");
    let waiting = Arc::clone(&acknowledged);
    if !holds_by(deadline, move || {
        waiting
            .lock()
            .expect("the record is not poisoned")
            .is_some()
    })
    .await
    {
        return Err("the statement was never acknowledged");
    }
    let window = tokio::task::spawn_blocking(move || {
        attach_ended
            .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            .ok()
    })
    .await
    .ok()
    .flatten();
    let attach_ended = window.is_some();
    let afterwards = {
        let reader = Arc::clone(&world);
        tokio::task::spawn_blocking(move || held(&reader))
            .await
            .expect("the session is read")
    };
    let at_the_acknowledgement = acknowledged
        .lock()
        .expect("the record is not poisoned")
        .take()
        .expect("the acknowledgement was recorded");
    drop(window);
    world.close();
    Ok(Landing {
        attach_ended,
        at_the_acknowledgement,
        afterwards,
        before,
    })
}

/// KR-REQ-17.54: an attach that was checked before the host took its owner's access away does not
/// land after the statement that did it has been acknowledged.
///
/// The attach has passed the dispatch boundary's check under the open host and stands before the
/// session when the statement arrives. The attach claims the geometry, so landing resizes the
/// session and resets what every subscriber is shown, and none of that can be taken back by
/// withdrawing the window. Whatever the attach does to the session is done before the
/// acknowledgement, and the statement's withdrawal then finds the attachment; nothing of it
/// happens after.
///
/// The paths run on the runtime's threads, and what the test waits on is a thread of its own, with
/// a deadline.
#[test]
fn an_attach_checked_before_the_host_restricts_its_owner_does_not_land_after_the_statement_is_acknowledged()
 {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("a runtime");
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(the_meeting_of_an_attach_and_a_statement())
    }));
    runtime.shutdown_background();
    let landing = match outcome {
        Ok(Ok(landing)) => landing,
        Ok(Err(step)) => panic!("the schedule did not come about: {step}"),
        Err(panic) => std::panic::resume_unwind(panic),
    };
    assert!(landing.attach_ended, "the attach did not end");
    assert!(
        landing.at_the_acknowledgement.attachments.is_empty(),
        "the statement was acknowledged while the window's attachment was in the session: {:?}",
        landing.at_the_acknowledgement
    );
    assert_eq!(
        landing.afterwards, landing.at_the_acknowledgement,
        "the attach changed the session after the statement was acknowledged"
    );
    assert_ne!(
        landing.at_the_acknowledgement.geometry, landing.before.geometry,
        "the attach was not applied before the acknowledgement: its resize is missing"
    );
    assert_eq!(
        landing.at_the_acknowledgement.geometry.dimensions,
        Dimensions::new(100, 30),
        "the attach's claimed size was not applied before the acknowledgement"
    );
}

/// Runs `work` on a runtime of its own, and lets the runtime go without waiting for the threads
/// that a failing case left stuck.
fn on_a_runtime<T>(work: impl std::future::Future<Output = T>) -> T {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("a runtime");
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runtime.block_on(work)));
    runtime.shutdown_background();
    match outcome {
        Ok(done) => done,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// What a statement that waits for a hold of the dispatch boundary has already done to the
/// requests of a window that holds an attachment and the input lease: the gate refuses them from
/// the moment the worker has the statement, not from the moment it can withdraw.
async fn the_requests_of_a_window_while_a_statement_waits() {
    let world = Arc::new(world("exec cat", true).await);
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;
    let attachment = world.attach(&mut window).await;
    let epoch = world.acquire(&mut window, attachment).await;
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;

    // The boundary is held on a thread of its own, as a mutation that is between its check and its
    // outcome holds it.
    let (held, held_end) = std::sync::mpsc::channel();
    let (let_go, go) = std::sync::mpsc::channel::<()>();
    let holder = Arc::clone(&world);
    std::thread::spawn(move || {
        let _boundary = holder.service.hold_the_dispatch_boundary();
        let _ = held.send(());
        let _ = go.recv();
    });
    let holding = tokio::task::spawn_blocking(move || {
        held_end
            .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            .is_ok()
    })
    .await
    .unwrap_or(false);
    assert!(holding, "the boundary was never held");

    // The statement closes the host, and waits for the hold. Either it waits, or it is
    // acknowledged: the first step that can tell which is where the state is read.
    let (acknowledged, told_end) = start_the_statement(daemon, closed(2));
    let waiting = Arc::clone(&world.service);
    let answered = Arc::clone(&acknowledged);
    assert!(
        holds_by(deadline, move || {
            waiting.statements_waiting_for_tests() > 0 || is_set(&answered)
        })
        .await,
        "the statement neither waited for the hold nor was acknowledged"
    );
    assert!(
        !is_set(&acknowledged),
        "the statement was acknowledged while a hold of the dispatch boundary that may have checked \
         under the earlier statement stood"
    );

    // Held, the window's requests meet the host that is closed: they are refused while the hold
    // stands.
    let asking = Arc::clone(&world);
    let (window, read) = ends_by(deadline, async move {
        let answer = asking.read(&mut window).await;
        (window, answer)
    })
    .await
    .expect("the read was answered");
    let error = read.expect_err("a read is refused while the statement waits");
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
    let typing = Arc::clone(&world);
    let (window, typed) = ends_by(deadline, async move {
        let mut window = window;
        let answer = typing
            .type_as(&mut window, attachment, epoch, 1, b"x")
            .await;
        (window, answer)
    })
    .await
    .expect("the input was answered");
    let error = typed.expect_err("input is refused while the statement waits");
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");

    // Let the hold go: the statement is acknowledged, and the window holds nothing.
    let _ = let_go.send(());
    assert!(
        received_by(deadline, told_end).await.is_some(),
        "the statement was never acknowledged"
    );
    let nothing = Arc::clone(&world);
    assert!(
        holds_by(deadline, move || nothing.holds_nothing()).await,
        "the window still holds something after the acknowledgement"
    );
    drop(window);
    world.close();
}

/// KR-REQ-17.54: a statement that takes access away changes what the gate refuses at once, and
/// acknowledges only when it has withdrawn what the window held.
///
/// A holder keeps the dispatch boundary and the statement waits for it. While it waits, a held
/// read and an input write of the window are refused, since the gate already has the statement;
/// when the hold ends the statement is acknowledged and the window holds nothing.
#[test]
fn a_statement_that_waits_for_a_hold_of_the_boundary_has_already_refused_what_a_window_asks() {
    on_a_runtime(the_requests_of_a_window_while_a_statement_waits());
}

/// A window whose connection a restriction withdrew, and that attaches again once the host is open.
async fn the_attach_of_a_withdrawn_connection() {
    let world = Arc::new(world("exec cat", true).await);
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;
    let _first = world.attach(&mut window).await;
    tell(&mut daemon, closed(2)).await;
    let nothing = Arc::clone(&world);
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;
    assert!(
        holds_by(deadline, move || nothing.holds_nothing()).await,
        "the restriction did not withdraw the window"
    );
    tell(&mut daemon, open(3)).await;
    let geometry_before = world.runtime.session().geometry();

    // The attach claims the geometry with a size of its own, which a refusal at the push would
    // already have applied: only a refusal before the dispatch marker leaves the session as it was.
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Geometry);
    let target = world.target();
    let session_id = world.session_id;
    let attaching = ends_by(deadline, async move {
        let outcome = window
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &SessionAttachParams {
                    session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: true,
                    dimensions: Nullable::some(Dimensions::new(100, 30)),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await;
        (window, outcome)
    })
    .await
    .expect("the attach was answered");
    // A connection that the worker withdrew attaches nothing: the answer is a refusal, or the
    // connection is gone, and the session holds no attachment either way.
    if let Ok(Ok(_)) = attaching.1 {
        panic!("a withdrawn connection attached again after the host opened");
    }
    assert!(world.holds_nothing(), "the session holds an attachment");
    assert_eq!(
        world.runtime.session().geometry(),
        geometry_before,
        "the refused attach changed the session's geometry"
    );
    world.close();
}

/// KR-REQ-17.54: a connection that a restriction withdrew does not attach again when the host is
/// open again: nothing would withdraw what it attached, since it is no longer in the registry.
#[test]
fn a_connection_that_a_restriction_withdrew_does_not_attach_again_when_the_host_opens() {
    on_a_runtime(the_attach_of_a_withdrawn_connection());
}

/// Starts the window's attach, which claims the geometry with a size of its own, on a task, and
/// returns the end that gives the window back when the attach has been answered or its connection
/// has ended.
fn start_the_geometry_attach(
    world: &World,
    window: LocalClient,
) -> std::sync::mpsc::Receiver<LocalClient> {
    let target = world.target();
    let params = geometry_attach_params(world.session_id);
    let (attach_done, attach_ended) = std::sync::mpsc::channel();
    tokio::spawn(async move {
        let mut window = window;
        let _ = window
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &params,
            )
            .await;
        let _ = attach_done.send(window);
    });
    attach_ended
}

/// The parameters of an attach that claims the geometry with a size of its own.
fn geometry_attach_params(session_id: SessionId) -> SessionAttachParams {
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Input);
    requested.insert(AttachmentCapability::Geometry);
    SessionAttachParams {
        session_id,
        mode: AttachMode::Terminal,
        claim_geometry: true,
        dimensions: Nullable::some(Dimensions::new(100, 30)),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested,
    }
}

/// What the meeting of a second statement and a pending withdrawal came to.
struct SecondMeeting {
    /// The first statement was acknowledged while the hold that may have checked under the earlier
    /// statement still stood, so nothing after it was scheduled.
    first_answered_while_held: bool,
    at_the_answer: Held,
}

/// A statement that waits for the hold of an attach that was checked before it, the answer to it
/// stopped once the hold has ended, and then a second statement from another connection: the host
/// repeats the first one on a replacement connection, or a newer daemon says its first. Returns
/// whether the first statement was acknowledged while the hold stood, and what the session held
/// when the second statement was answered.
async fn the_second_statement_meets_a_pending_withdrawal(
    generation: u64,
    repeated: bool,
) -> Result<SecondMeeting, &'static str> {
    let world = Arc::new(world("exec cat", true).await);
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;
    world
        .read(&mut window)
        .await
        .expect("the window is served under an open host");
    let (checked, go_attach) = world.service.stall_a_mutation_after_its_dispatch_check();
    let (at_the_hold, go_statement) = world.service.stall_a_statement_after_its_hold();
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;
    let attach_ended = start_the_geometry_attach(&world, window);
    if ends_by(deadline, async move { checked.await.is_ok() }).await != Some(true) {
        return Err("the attach never passed the dispatch boundary's check");
    }

    // The host takes access away: the statement has changed the gate and waits for the hold. A
    // newer daemon's presentation withdraws what a lease held, so for that variant the statement
    // is a closed one, which a presentation leaves as it is: only the newer daemon's own first
    // statement can then be answered with or without the sweep.
    let first = if repeated {
        world.machine.lease(2, FAR_MS, FAR_MS)
    } else {
        closed(2)
    };
    let (acknowledged, _daemon_end) = start_the_statement(daemon, first);
    let waiting = Arc::clone(&world.service);
    let answered = Arc::clone(&acknowledged);
    if !holds_by(deadline, move || {
        waiting.statements_waiting_for_tests() > 0 || is_set(&answered)
    })
    .await
    {
        return Err("the first statement neither waited for the hold nor was acknowledged");
    }
    if is_set(&acknowledged) {
        // Acknowledged while the hold stood: the case is decided, and nothing more is scheduled.
        let _ = go_attach.send(());
        let reader = Arc::clone(&world);
        let at_the_answer = tokio::task::spawn_blocking(move || held(&reader))
            .await
            .expect("the session is read");
        world.close();
        return Ok(SecondMeeting {
            first_answered_while_held: true,
            at_the_answer,
        });
    }
    go_attach.send(()).expect("lets the attach go");
    if ends_by(deadline, async move { at_the_hold.await.is_ok() }).await != Some(true) {
        return Err("the statement never reached the end of its wait");
    }

    // The second statement arrives while the first has not run its withdrawal.
    let (second, statement) = if repeated {
        (world.authority(generation).await, first)
    } else {
        (world.authority(generation).await, closed(1))
    };
    let answered = ends_by(deadline, async move {
        let mut second = second;
        tell(&mut second, statement).await;
        second
    })
    .await;
    if answered.is_none() {
        return Err("the second statement was never answered");
    }
    let reader = Arc::clone(&world);
    let at_the_answer = tokio::task::spawn_blocking(move || held(&reader))
        .await
        .expect("the session is read");
    go_statement.send(()).expect("lets the first statement go");
    let window = tokio::task::spawn_blocking(move || {
        attach_ended
            .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            .ok()
    })
    .await
    .ok()
    .flatten();
    drop(window);
    world.close();
    Ok(SecondMeeting {
        first_answered_while_held: false,
        at_the_answer,
    })
}

/// KR-REQ-17.54: a repeat of a statement on a replacement connection is not answered while the
/// withdrawal the first one owes is pending.
///
/// The first statement waits for the hold of an attach that was checked before it; once the hold
/// has ended its answer is stopped before it runs the withdrawal. The host's replacement
/// connection repeats the statement, which the worker already holds. Its answer says the
/// withdrawal is complete, so the window holds nothing when it comes.
#[test]
fn a_repeated_statement_is_not_answered_while_the_withdrawal_the_first_owes_is_pending() {
    let meeting = on_a_runtime(the_second_statement_meets_a_pending_withdrawal(1, true))
        .expect("the schedule came about");
    assert!(
        !meeting.first_answered_while_held,
        "the first statement was acknowledged while the hold of the attach stood"
    );
    assert!(
        meeting.at_the_answer.attachments.is_empty(),
        "the repeat was answered while the window's attachment was in the session: {:?}",
        meeting.at_the_answer
    );
}

/// KR-REQ-17.54: a newer daemon's first statement is not answered while the withdrawal an earlier
/// statement owes is pending, even though it changes nothing the gate holds.
#[test]
fn a_newer_daemons_first_statement_is_not_answered_while_an_earlier_withdrawal_is_pending() {
    let meeting = on_a_runtime(the_second_statement_meets_a_pending_withdrawal(2, false))
        .expect("the schedule came about");
    assert!(
        !meeting.first_answered_while_held,
        "the first statement was acknowledged while the hold of the attach stood"
    );
    assert!(
        meeting.at_the_answer.attachments.is_empty(),
        "the statement was answered while the window's attachment was in the session: {:?}",
        meeting.at_the_answer
    );
}

/// How a window's connection comes to be withdrawn by its own writer.
#[derive(Clone, Copy)]
enum Ends {
    /// The host takes access away by a statement.
    ByStatement,
    /// The lease the host gave ends on the continuous clock, and no statement follows.
    ByClock,
}

/// What a writer's withdrawal of a window whose attach is in flight came to.
struct WriterOrder {
    /// The first attachment of the window.
    first: AttachmentId,
    /// The statement was acknowledged while the hold of the attach stood.
    answered_while_held: bool,
    /// How many answers and withdrawals waited, and what the session held, at the first step that
    /// can tell whether the writer's withdrawal waits for the hold.
    waiting_at_the_hold: usize,
    /// What the session held at that step. The clock's order reads nothing there: the attach holds
    /// the session from its check to its push, as it does on the way to the marker.
    at_the_hold: Option<Held>,
    /// What the session held when the withdrawal and the acknowledgement were complete, the end of
    /// the window's connection being stopped before it detached anything.
    when_complete: Held,
}

/// A window with a live stream whose second attach was checked before the host took access away,
/// and the writer of its connection, which stops the stream's next frame and withdraws the window
/// itself. The host takes access away by a statement, or by the lease ending on the clock.
///
/// The end of the window's connection is stopped before it detaches anything: the attach's
/// reply is a frame the withdrawal refuses, and a connection whose reply is refused ends and
/// detaches what its list holds by itself, which would hide what the writer's withdrawal left.
async fn the_writer_withdraws_a_window_whose_attach_is_in_flight(
    ends: Ends,
) -> Result<WriterOrder, &'static str> {
    let world = Arc::new(world("while true; do printf 'line\\n'; sleep 0.1; done", true).await);
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;
    match ends {
        Ends::ByStatement => {
            tell(&mut daemon, open(1)).await;
        }
        Ends::ByClock => {
            tell(&mut daemon, world.machine.lease(1, 1_000, FAR_MS)).await;
        }
    }
    // The clock's order has the stream's next frame in the delivery's hand before the attach takes
    // the session, and written only once the lease has ended: the attach holds the session, and no
    // frame is made while it does.
    let frame = matches!(ends, Ends::ByClock)
        .then(|| world.service.stall_a_delivery_before_its_next_frame());
    let first = world.attach(&mut window).await;
    world.subscribe(&mut window, first).await;
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;
    let go_frame = match frame {
        Some((arrived, go_frame)) => {
            if ends_by(deadline, async move { arrived.await.is_ok() }).await != Some(true) {
                return Err("the stream's delivery never had a frame in hand");
            }
            Some(go_frame)
        }
        None => None,
    };
    // A lease that ends is caught by the attach's own check of its lease and deadline, so the
    // clock's order stops the attach after those and before its marker, with the session held.
    let (checked, go_attach) = match ends {
        Ends::ByStatement => world.service.stall_a_mutation_after_its_dispatch_check(),
        Ends::ByClock => world.service.stall_a_mutation_after_its_deadline_check(),
    };
    let (_at_the_end, go_end) = world.service.stall_a_connection_at_its_end();
    let before = Arc::new(held(&world));
    let attach_ended = start_the_geometry_attach(&world, window);
    if ends_by(deadline, async move { checked.await.is_ok() }).await != Some(true) {
        return Err("the second attach never passed the dispatch boundary's check");
    }

    // The host takes access away: the gate changes at once, the next frame of the stream is
    // refused, and the writer's withdrawal, and a statement's answer, wait for the attach's hold.
    let (statement, daemon_kept, wanted) = match ends {
        Ends::ByStatement => (Some(start_the_statement(daemon, closed(2))), None, 2),
        Ends::ByClock => {
            world.machine.runs(Duration::from_millis(1_001));
            if let Some(go_frame) = go_frame {
                let _ = go_frame.send(());
            }
            (None, Some(daemon), 1)
        }
    };
    let acknowledged = statement
        .as_ref()
        .map(|(acknowledged, _)| Arc::clone(acknowledged));
    // Either they wait for the hold, or the writer's withdrawal has gone ahead and taken the
    // window's first attachment out of the session, or the statement was acknowledged.
    let waiting = Arc::clone(&world);
    let answered = acknowledged.clone();
    let by_clock = matches!(ends, Ends::ByClock);
    if !holds_by(deadline, move || {
        waiting.service.statements_waiting_for_tests() >= wanted
            || answered.as_ref().is_some_and(|flag| is_set(flag))
            // The session is free only in the statement's order; in the clock's, the attach holds
            // it and nothing may look at it before the attach is let go.
            || (!by_clock && waiting.holds_nothing())
    })
    .await
    {
        return Err("the withdrawal did not wait for the hold, and nothing else came about");
    }
    let answered_while_held = acknowledged.as_ref().is_some_and(|flag| is_set(flag));
    let waiting_at_the_hold = world.service.statements_waiting_for_tests();
    let at_the_hold = if by_clock {
        None
    } else {
        let reader = Arc::clone(&world);
        Some(
            tokio::task::spawn_blocking(move || held(&reader))
                .await
                .expect("the session is read"),
        )
    };

    go_attach.send(()).expect("lets the attach go");
    let when_complete = match statement {
        Some((_, daemon_end)) => {
            if received_by(deadline, daemon_end).await.is_none() {
                return Err("the statement was never acknowledged");
            }
            let reader = Arc::clone(&world);
            tokio::task::spawn_blocking(move || held(&reader))
                .await
                .expect("the session is read")
        }
        None => {
            // The attach has landed once the geometry has moved, whatever the withdrawal does to
            // its attachment, and the writer's withdrawal is complete once nothing waits.
            let landed = Arc::clone(&world);
            let from = Arc::clone(&before);
            if !holds_by(deadline, move || held(&landed).geometry != from.geometry).await {
                return Err("the attach never landed");
            }
            let idle = Arc::clone(&world);
            if !holds_by(deadline, move || {
                idle.service.statements_waiting_for_tests() == 0
            })
            .await
            {
                return Err("the writer's withdrawal never ended");
            }
            let reader = Arc::clone(&world);
            tokio::task::spawn_blocking(move || held(&reader))
                .await
                .expect("the session is read")
        }
    };
    let _ = go_end.send(());
    drop(received_by(deadline, attach_ended).await);
    drop(daemon_kept);
    world.close();
    Ok(WriterOrder {
        first,
        answered_while_held,
        waiting_at_the_hold,
        at_the_hold,
        when_complete,
    })
}

/// KR-REQ-17.54: the writer's own withdrawal of a window waits for the hold of an attach that was
/// checked before the restriction, so the attach's attachment is withdrawn with the window's.
///
/// The window's stream has frames. The attach is stopped after its check, the host takes access
/// away by a statement, and the writer meets the next frame under the new statement. The attach
/// ends as applied and the withdrawal takes its attachment back, or the push refuses it: either
/// way no attachment of the window is left. The end of the window's connection is held, so that
/// the acknowledgement is read before it can detach anything.
#[test]
fn a_window_the_writer_withdraws_does_not_keep_the_attach_that_was_in_flight() {
    let order = on_a_runtime(the_writer_withdraws_a_window_whose_attach_is_in_flight(
        Ends::ByStatement,
    ))
    .expect("the schedule came about");
    assert!(
        order.when_complete.attachments.is_empty(),
        "the statement was acknowledged while an attachment of the window was in the session: {:?}",
        order.when_complete
    );
}

/// KR-REQ-17.54: the writer's withdrawal does not run while the hold that may have checked under
/// the earlier statement stands, and the statement is not acknowledged either.
#[test]
fn a_window_the_writer_withdraws_waits_for_the_hold_of_the_attach_that_was_in_flight() {
    let order = on_a_runtime(the_writer_withdraws_a_window_whose_attach_is_in_flight(
        Ends::ByStatement,
    ))
    .expect("the schedule came about");
    assert!(
        !order.answered_while_held,
        "the statement was acknowledged while the hold of the attach stood"
    );
    assert!(
        order.waiting_at_the_hold >= 2,
        "the statement and the writer's withdrawal did not both wait for the hold: {}",
        order.waiting_at_the_hold
    );
    let at_the_hold = order.at_the_hold.expect("the session was read at the hold");
    assert_eq!(
        at_the_hold.attachments,
        vec![order.first],
        "the writer's withdrawal ran while the hold of the attach stood"
    );
}

/// KR-REQ-17.54: a lease that ends on the clock while an attach is between its check and its push
/// leaves no attachment behind once the writer's withdrawal is complete.
///
/// No statement follows: the lease the host gave ends, the writer meets the next frame of the
/// window's stream, and its withdrawal waits for the hold the attach is in. The attach ends as
/// applied and the withdrawal takes its attachment back, or the push refuses it: either way no
/// attachment of the window is left.
#[test]
fn a_window_the_writer_withdraws_when_its_lease_ends_does_not_keep_the_attach_that_was_in_flight() {
    let order = on_a_runtime(the_writer_withdraws_a_window_whose_attach_is_in_flight(
        Ends::ByClock,
    ))
    .expect("the schedule came about");
    assert!(
        order.when_complete.attachments.is_empty(),
        "the writer's withdrawal was complete while an attachment of the window was in the session: {:?}",
        order.when_complete
    );
}

/// KR-REQ-17.54: when a lease ends on the clock under a frame that the writer holds, the writer
/// asks for the withdrawal of its window while the attach that was checked under the lease is
/// still in flight.
///
/// The case reads only the ask. In the clock's order the attach holds the session, so nothing can
/// tell a withdrawal that waits for the hold from one that waits for the session; the statement's
/// cases, which read the session at the hold, hold the wait itself.
#[test]
fn the_writer_asks_for_the_withdrawal_of_a_window_when_its_lease_ends_under_an_attach_that_was_in_flight()
 {
    let order = on_a_runtime(the_writer_withdraws_a_window_whose_attach_is_in_flight(
        Ends::ByClock,
    ))
    .expect("the schedule came about");
    assert!(
        order.waiting_at_the_hold >= 1,
        "the writer did not ask for the withdrawal while the attach's hold stood: {}",
        order.waiting_at_the_hold
    );
}

/// What a window's requests, and a stream's frame, came to while the attach of another window was
/// held after its check and a statement had taken access away.
struct WhileHeld {
    answered_while_held: bool,
    waiting_at_the_hold: usize,
    read: Result<(), ProtocolError>,
    typed: Result<(), ProtocolError>,
    when_complete: Held,
}

/// One window that holds an attachment, the input lease and a subscription to a shell that prints
/// on its own, another window whose attach has passed the dispatch boundary's check and stands
/// before the session, and a statement that takes access away.
///
/// While the attach stays held, the first window's read and input write are asked. Returns what
/// they were answered, how many answers and withdrawals waited (the writer's withdrawal of the
/// first window waits once the writer has met a frame of its stream under the new statement), and
/// what the session held when the statement was acknowledged after the attach was let go.
async fn the_requests_of_a_window_while_the_attach_of_another_is_held()
-> Result<WhileHeld, &'static str> {
    let world = Arc::new(world("while true; do printf 'line\\n'; sleep 0.1; done", true).await);
    let mut first = world.window().await;
    let second = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;
    let attachment = world.attach(&mut first).await;
    let epoch = world.acquire(&mut first, attachment).await;
    world.subscribe(&mut first, attachment).await;
    let (checked, go_attach) = world.service.stall_a_mutation_after_its_dispatch_check();
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;
    let attach_ended = start_the_geometry_attach(&world, second);
    if ends_by(deadline, async move { checked.await.is_ok() }).await != Some(true) {
        return Err("the attach never passed the dispatch boundary's check");
    }

    let (acknowledged, daemon_end) = start_the_statement(daemon, closed(2));
    let waiting = Arc::clone(&world.service);
    let answered = Arc::clone(&acknowledged);
    let nothing = Arc::clone(&world);
    if !holds_by(deadline, move || {
        waiting.statements_waiting_for_tests() >= 2 || is_set(&answered) || nothing.holds_nothing()
    })
    .await
    {
        return Err("the statement and the writer's withdrawal did not both wait for the hold");
    }
    let answered_while_held = is_set(&acknowledged);
    let waiting_at_the_hold = world.service.statements_waiting_for_tests();

    // The attach stays held. The window's requests meet the host that is closed.
    let asking = Arc::clone(&world);
    let Some((first, read)) = ends_by(deadline, async move {
        let answer = asking.read(&mut first).await;
        (first, answer)
    })
    .await
    else {
        return Err("the read was never answered");
    };
    let typing = Arc::clone(&world);
    let Some((first, typed)) = ends_by(deadline, async move {
        let mut first = first;
        let answer = typing.type_as(&mut first, attachment, epoch, 1, b"x").await;
        (first, answer)
    })
    .await
    else {
        return Err("the input was never answered");
    };

    go_attach.send(()).expect("lets the attach go");
    if received_by(deadline, daemon_end).await.is_none() {
        return Err("the statement was never acknowledged");
    }
    let reader = Arc::clone(&world);
    let when_complete = tokio::task::spawn_blocking(move || held(&reader))
        .await
        .expect("the session is read");
    drop(received_by(deadline, attach_ended).await);
    drop(first);
    world.close();
    Ok(WhileHeld {
        answered_while_held,
        waiting_at_the_hold,
        read,
        typed,
        when_complete,
    })
}

/// KR-REQ-17.54: while an attach that was checked under the earlier statement is held, a read, an
/// input write and a frame of a stream of another window meet the statement that took access away,
/// and the acknowledgement comes only after every detach.
///
/// The attach stays paused after its check. The statement has changed the gate: the first
/// window's read and input write are refused with the permission refusal, and the writer of its
/// stream has met a frame under the new statement and holds it back (it waits to withdraw the
/// window, which is counted). When the attach is let go, the acknowledgement follows the
/// withdrawal of both windows.
#[test]
fn a_read_an_input_write_and_a_stream_frame_meet_the_statement_while_an_attach_is_held() {
    let outcome = on_a_runtime(the_requests_of_a_window_while_the_attach_of_another_is_held())
        .expect("the schedule came about");
    assert!(
        !outcome.answered_while_held,
        "the statement was acknowledged while the hold of the attach stood"
    );
    assert!(
        outcome.waiting_at_the_hold >= 2,
        "the stream's frame was not held back under the new statement: {}",
        outcome.waiting_at_the_hold
    );
    let error = outcome
        .read
        .expect_err("a read is refused while the attach is held");
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
    let error = outcome
        .typed
        .expect_err("input is refused while the attach is held");
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
    assert!(
        outcome.when_complete.attachments.is_empty(),
        "the statement was acknowledged while an attachment was in the session: {:?}",
        outcome.when_complete
    );
}

/// Holds the dispatch boundary on a thread of its own, as a mutation between its check and its
/// outcome holds it. Returns the end that lets it go, once the boundary is held.
async fn hold_the_boundary(
    world: &Arc<World>,
    deadline: std::time::Instant,
) -> Option<std::sync::mpsc::Sender<()>> {
    let (held, held_end) = std::sync::mpsc::channel();
    let (let_go, go) = std::sync::mpsc::channel::<()>();
    let holder = Arc::clone(world);
    std::thread::spawn(move || {
        let _boundary = holder.service.hold_the_dispatch_boundary();
        let _ = held.send(());
        let _ = go.recv();
    });
    received_by(deadline, held_end).await.map(|()| let_go)
}

/// What the maintenance pass did to a withdrawal that a statement owes.
struct Maintenance {
    answered_while_held: bool,
    held_before_the_pass: bool,
    held_after_the_pass: bool,
    answered_by_the_pass: bool,
}

/// A statement that took access away while the boundary was held, whose answer is stopped once the
/// hold has ended and before it runs the withdrawal it owes, as an answer is whose connection has
/// gone: the maintenance pass runs the withdrawal under its own hold of the boundary.
async fn the_maintenance_pass_and_a_withdrawal_that_a_statement_owes()
-> Result<Maintenance, &'static str> {
    let world = Arc::new(world("exec cat", true).await);
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;
    let _attachment = world.attach(&mut window).await;
    let (at_the_hold, go_statement) = world.service.stall_a_statement_after_its_hold();
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;
    let Some(let_go) = hold_the_boundary(&world, deadline).await else {
        return Err("the boundary was never held");
    };

    let (acknowledged, daemon_end) = start_the_statement(daemon, closed(2));
    let waiting = Arc::clone(&world.service);
    let answered = Arc::clone(&acknowledged);
    if !holds_by(deadline, move || {
        waiting.statements_waiting_for_tests() > 0 || is_set(&answered)
    })
    .await
    {
        return Err("the statement neither waited for the hold nor was acknowledged");
    }
    let answered_while_held = is_set(&acknowledged);

    // The hold ends, and the statement stands before the withdrawal it owes.
    let _ = let_go.send(());
    if ends_by(deadline, async move { at_the_hold.await.is_ok() }).await != Some(true) {
        return Err("the statement never reached the end of its wait");
    }
    let looking = Arc::clone(&world);
    let held_before_the_pass = !tokio::task::spawn_blocking(move || looking.holds_nothing())
        .await
        .expect("the session is read");

    // The pass runs the withdrawal that the statement owes, with the statement still stopped.
    let service = Arc::clone(&world.service);
    tokio::task::spawn_blocking(move || service.maintain_now())
        .await
        .expect("the pass ends");
    let looking = Arc::clone(&world);
    let held_after_the_pass = !tokio::task::spawn_blocking(move || looking.holds_nothing())
        .await
        .expect("the session is read");
    let answered_by_the_pass = is_set(&acknowledged);

    let _ = go_statement.send(());
    if received_by(deadline, daemon_end).await.is_none() {
        return Err("the statement was never acknowledged");
    }
    drop(window);
    world.close();
    Ok(Maintenance {
        answered_while_held,
        held_before_the_pass,
        held_after_the_pass,
        answered_by_the_pass,
    })
}

/// KR-REQ-17.54: the maintenance pass runs a withdrawal that a restriction owes, under its own
/// hold of the dispatch boundary, so that a statement whose task is gone leaves nothing owed.
#[test]
fn the_maintenance_pass_runs_the_withdrawal_that_a_statement_owes() {
    let pass = on_a_runtime(the_maintenance_pass_and_a_withdrawal_that_a_statement_owes())
        .expect("the schedule came about");
    assert!(
        !pass.answered_while_held,
        "the statement was acknowledged while the boundary was held"
    );
    assert!(
        pass.held_before_the_pass,
        "the window held nothing before the pass: the statement had run its withdrawal"
    );
    assert!(
        !pass.held_after_the_pass,
        "the pass left the window's attachment in the session"
    );
    assert!(
        !pass.answered_by_the_pass,
        "the statement was acknowledged by the pass, not by its own answer"
    );
}

/// What the end of a connection owed while the session was held.
struct EndOwes {
    answered_with_a_detach_pending: bool,
    waits: usize,
    when_answered: Held,
    settled_by_the_service: u64,
}

/// A window with an attachment whose connection ends while the session is held by somebody else,
/// so the end owes the detach to the service, and a statement that takes access away after it.
async fn the_end_of_a_connection_that_owes_a_detach() -> Result<EndOwes, &'static str> {
    let world = Arc::new(world("exec cat", true).await);
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;
    let _attachment = world.attach(&mut window).await;
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;

    // The session is held on a thread of its own, so that no detach can be made.
    let (session_held, session_held_end) = std::sync::mpsc::channel();
    let (release_session, go) = std::sync::mpsc::channel::<()>();
    let holder = Arc::clone(&world);
    std::thread::spawn(move || {
        let _session = holder.runtime.session();
        let _ = session_held.send(());
        let _ = go.recv();
    });
    if received_by(deadline, session_held_end).await.is_none() {
        return Err("the session was never held");
    }

    // The window goes away: its connection ends, and the detach of its attachment is owed.
    drop(window);
    let ended = Arc::clone(&world);
    if !holds_by(deadline, move || {
        ended.service.connections_held_for_tests() == 1
    })
    .await
    {
        return Err("the window's connection never ended");
    }

    let (acknowledged, daemon_end) = start_the_statement(daemon, closed(2));
    let waiting = Arc::clone(&world.service);
    let answered = Arc::clone(&acknowledged);
    if !holds_by(deadline, move || {
        waiting.detach_waits_for_tests() > 0 || is_set(&answered)
    })
    .await
    {
        return Err("the statement neither waited for the detach nor was acknowledged");
    }
    let answered_with_a_detach_pending = is_set(&acknowledged);
    let waits = world.service.detach_waits_for_tests();

    let _ = release_session.send(());
    if received_by(deadline, daemon_end).await.is_none() {
        return Err("the statement was never acknowledged");
    }
    let reader = Arc::clone(&world);
    let when_answered = tokio::task::spawn_blocking(move || held(&reader))
        .await
        .expect("the session is read");
    let settled_by_the_service = world.service.owed_done_for_tests().1;
    world.close();
    Ok(EndOwes {
        answered_with_a_detach_pending,
        waits,
        when_answered,
        settled_by_the_service,
    })
}

/// KR-REQ-17.54: a statement is not acknowledged while the end of a connection still owes the
/// detach of an attachment the connection made under the earlier statement.
///
/// The window's connection ends while somebody holds the session, which leaves its detach to the
/// service's own pass. The statement that takes access away is answered only when the pass has
/// made it.
#[test]
fn a_statement_is_not_acknowledged_while_the_end_of_a_connection_owes_a_detach() {
    let owed = on_a_runtime(the_end_of_a_connection_that_owes_a_detach())
        .expect("the schedule came about");
    assert!(
        !owed.answered_with_a_detach_pending,
        "the statement was acknowledged while a detach of the connection's end was owed"
    );
    assert!(
        owed.waits > 0,
        "the statement did not wait for the detach: {}",
        owed.waits
    );
    assert!(
        owed.when_answered.attachments.is_empty(),
        "the statement was acknowledged while the attachment was in the session: {:?}",
        owed.when_answered
    );
    assert_eq!(
        owed.settled_by_the_service, 1,
        "the service's own pass did not make the owed detach"
    );
}

/// KR-REQ-17.54: the count that a hold of the dispatch boundary leaves when it ends is raised
/// before the lock goes, so a statement that waits for that hold is not made to wait for the next
/// one.
///
/// A second taker waits for the boundary while the first holds it. The moment the second has it,
/// it reads the count, which already includes the first hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hold_of_the_dispatch_boundary_is_counted_before_the_next_holder_has_the_boundary() {
    let world = Arc::new(world("exec cat", true).await);
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;
    // The host's own maintenance takes the boundary too, and keeps out of the way for the case.
    let (maintenance_held, maintenance_end) = std::sync::mpsc::channel();
    let (release_maintenance, keep) = std::sync::mpsc::channel::<()>();
    let keeper = Arc::clone(&world);
    std::thread::spawn(move || {
        let _maintenance = keeper.service.hold_maintenance();
        let _ = maintenance_held.send(());
        let _ = keep.recv();
    });
    received_by(deadline, maintenance_end)
        .await
        .expect("the maintenance pass was kept out");
    let first = world.service.hold_the_dispatch_boundary();
    let before = world.service.releases_of_the_dispatch_boundary_for_tests();
    let second = Arc::clone(&world);
    let (seen, seen_end) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _boundary = second.service.hold_the_dispatch_boundary();
        let _ = seen.send(second.service.releases_of_the_dispatch_boundary_for_tests());
    });
    drop(first);
    let counted = received_by(deadline, seen_end)
        .await
        .expect("the second holder took the boundary");
    // Nobody else holds the boundary in between, so the count is exactly one more: a count that is
    // not raised stays where it was, and one raised after the lock goes can be raised by a holder
    // that comes between.
    assert_eq!(
        counted,
        before + 1,
        "the second holder had the boundary and the first hold was not counted once: {counted} after {before}"
    );
    let _ = release_maintenance.send(());
    world.close();
}

/// What the meeting of a statement's answer and a writer's withdrawal that has taken its
/// registration out of the registry came to.
struct InTheGap {
    /// The statement was acknowledged while that withdrawal had not detached anything.
    answered_while_undetached: bool,
    /// How many times the answer found a detach pending and waited for it.
    waits: usize,
    when_complete: Held,
}

/// A window with a live stream and an attachment, a statement that takes access away and is
/// stopped once its hold has ended and before it sweeps, and the writer's withdrawal of the
/// window, which is stopped right after it took the window out of the registry.
///
/// The statement is let go there: its sweep finds no registration, and what it may answer is
/// decided by whether the withdrawal that is under way is counted. Returns whether it answered
/// at once, and what the session held when the withdrawal was let go and the statement answered.
async fn a_statement_meets_a_withdrawal_that_has_left_the_registry()
-> Result<InTheGap, &'static str> {
    let world = Arc::new(world("while true; do printf 'line\\n'; sleep 0.1; done", true).await);
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;
    let attachment = world.attach(&mut window).await;
    world.subscribe(&mut window, attachment).await;
    let (at_the_hold, go_statement) = world.service.stall_a_statement_after_its_hold();
    let (at_the_gap, go_gap) = world.service.stall_a_withdrawal_after_its_remove();
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;

    let (acknowledged, daemon_end) = start_the_statement(daemon, closed(2));
    if ends_by(deadline, async move { at_the_hold.await.is_ok() }).await != Some(true) {
        return Err("the statement never reached the end of its wait");
    }
    if ends_by(deadline, async move { at_the_gap.await.is_ok() }).await != Some(true) {
        return Err("the writer's withdrawal never reached the registry's remove");
    }

    // The statement sweeps now: the registry holds no window, and a withdrawal is under way.
    let _ = go_statement.send(());
    let waiting = Arc::clone(&world.service);
    let answered = Arc::clone(&acknowledged);
    if !holds_by(deadline, move || {
        waiting.detach_waits_for_tests() > 0 || is_set(&answered)
    })
    .await
    {
        return Err("the statement neither waited for the withdrawal nor was acknowledged");
    }
    let answered_while_undetached = is_set(&acknowledged);
    let waits = world.service.detach_waits_for_tests();

    let _ = go_gap.send(());
    if received_by(deadline, daemon_end).await.is_none() {
        return Err("the statement was never acknowledged");
    }
    let reader = Arc::clone(&world);
    let when_complete = tokio::task::spawn_blocking(move || held(&reader))
        .await
        .expect("the session is read");
    drop(window);
    world.close();
    Ok(InTheGap {
        answered_while_undetached,
        waits,
        when_complete,
    })
}

/// KR-REQ-17.54: a statement is not acknowledged while a withdrawal that its own sweep cannot see
/// is under way.
///
/// The writer's withdrawal has taken the window out of the registry and has not detached its
/// attachment. The statement's sweep finds no registration; the withdrawal is counted from before
/// the registry's remove, so the answer waits for it.
#[test]
fn a_statement_is_not_acknowledged_while_a_withdrawal_it_cannot_sweep_is_under_way() {
    let meeting = on_a_runtime(a_statement_meets_a_withdrawal_that_has_left_the_registry())
        .expect("the schedule came about");
    assert!(
        !meeting.answered_while_undetached,
        "the statement was acknowledged while a withdrawal had taken the window out of the \
         registry and detached nothing"
    );
    assert!(
        meeting.waits > 0,
        "the statement did not wait for the withdrawal: {}",
        meeting.waits
    );
    assert!(
        meeting.when_complete.attachments.is_empty(),
        "the statement was acknowledged while the attachment was in the session: {:?}",
        meeting.when_complete
    );
}

/// The session's holdings recorded at the moment the daemon has its acknowledgement of a
/// statement, or the reason it has none.
type Answered = Arc<std::sync::Mutex<Option<Result<Held, String>>>>;

/// Sends `access` over `daemon` on a task, and records what the session holds when the daemon has
/// its acknowledgement.
fn tell_and_read(world: &Arc<World>, daemon: BoundLink, access: LocalAccess) -> Answered {
    let answered: Answered = Arc::default();
    let record = Arc::clone(&answered);
    let reader = Arc::clone(world);
    tokio::spawn(async move {
        let mut daemon = daemon;
        let outcome = match daemon.announce_local_access(access).await {
            Ok(_) => Ok(tokio::task::spawn_blocking(move || held(&reader))
                .await
                .expect("the session is read")),
            Err(error) => Err(format!("{error:?}")),
        };
        *record.lock().expect("the record is not poisoned") = Some(outcome);
        drop(daemon);
    });
    answered
}

/// Whether a statement sent by `tell_and_read` has been answered.
fn is_answered(answered: &Answered) -> bool {
    answered
        .lock()
        .expect("the record is not poisoned")
        .is_some()
}

/// Sends `access` over `daemon` on a task and cares for no answer: the daemon's link may be one
/// that a replacement has fenced, whose answer is never written.
fn tell_and_forget(daemon: BoundLink, access: LocalAccess) {
    tokio::spawn(async move {
        let mut daemon = daemon;
        let _ = daemon.announce_local_access(access).await;
    });
}

/// Takes what a statement recorded, once it is there.
fn recorded(answered: &Answered) -> Result<Held, String> {
    answered
        .lock()
        .expect("the record is not poisoned")
        .take()
        .expect("the answer was recorded")
}

/// A statement that has changed the gate and is held after its wait, a replacement authority
/// connection, an attach that was checked under the first statement and a further restriction that
/// arrives on the replacement while the attach holds the boundary. Returns whether the further
/// statement was answered while the attach held the boundary, and what the session held when it was
/// answered.
///
/// The first statement is let go once the further one waits. Whatever the first marks as done, the
/// further statement must still sweep for the restriction it owes after the attach has landed.
async fn a_statement_marks_what_a_later_statement_owes() -> Result<(bool, Held), &'static str> {
    let world = Arc::new(world("exec cat", true).await);
    let mut window = world.window().await;
    let mut first = world.authority(1).await;
    tell(&mut first, open(1)).await;
    world
        .read(&mut window)
        .await
        .expect("the window is served under an open host");
    let (at_the_hold, go_first) = world.service.stall_a_statement_after_its_hold();
    let (checked, go_attach) = world.service.stall_a_mutation_after_its_dispatch_check();
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;

    // The first statement takes the lease that the host gave, which is still live, and stops at the
    // end of its wait, before it runs the withdrawal it owes.
    tell_and_forget(first, world.machine.lease(2, FAR_MS, FAR_MS));
    if ends_by(deadline, async move { at_the_hold.await.is_ok() }).await != Some(true) {
        return Err("the first statement never reached the end of its wait");
    }
    // The daemon's replacement connection presents the same generation. The first statement's task
    // goes on although its link is fenced.
    let second = world.authority(1).await;
    // The window's attach passes the check under the lease and stops inside the boundary.
    let attach_ended = start_the_geometry_attach(&world, window);
    if ends_by(deadline, async move { checked.await.is_ok() }).await != Some(true) {
        return Err("the attach never passed the dispatch boundary's check");
    }
    // The host closes: the second statement owes a restriction of its own and waits for the attach.
    let answered = tell_and_read(&world, second, closed(3));
    let waiting = Arc::clone(&world.service);
    let record = Arc::clone(&answered);
    if !holds_by(deadline, move || {
        waiting.statements_waiting_for_tests() >= 2
            || record.lock().expect("the record is not poisoned").is_some()
    })
    .await
    {
        return Err("the second statement neither waited for the attach nor was answered");
    }
    let answered_while_held = is_answered(&answered);

    // The first statement is let go and ends: only the second is waiting.
    go_first.send(()).expect("lets the first statement go");
    let waiting = Arc::clone(&world.service);
    let record = Arc::clone(&answered);
    if !holds_by(deadline, move || {
        waiting.statements_waiting_for_tests() <= 1
            || record.lock().expect("the record is not poisoned").is_some()
    })
    .await
    {
        return Err("the first statement never ended");
    }
    // The attach lands.
    go_attach.send(()).expect("lets the attach go");
    let record = Arc::clone(&answered);
    if !holds_by(deadline, move || {
        record.lock().expect("the record is not poisoned").is_some()
    })
    .await
    {
        return Err("the second statement was never answered");
    }
    let at_the_answer = recorded(&answered).map_err(|_| "the second statement failed")?;
    drop(received_by(deadline, attach_ended).await);
    world.close();
    Ok((answered_while_held, at_the_answer))
}

/// KR-REQ-17.54: a statement completes only the withdrawal it owes. An earlier statement that is
/// still running must not mark done the withdrawal of a later restriction whose attach has not
/// landed yet.
///
/// The first statement is let go while the second waits for an attach that was checked under the
/// first. The attach then lands, and the second statement's answer must come with the window's
/// attachment withdrawn.
#[test]
fn an_earlier_statement_does_not_complete_the_withdrawal_a_later_one_owes() {
    let (answered_while_held, at_the_answer) =
        on_a_runtime(a_statement_marks_what_a_later_statement_owes())
            .expect("the schedule came about");
    assert!(
        !answered_while_held,
        "the second statement was answered while the attach held the boundary"
    );
    assert!(
        at_the_answer.attachments.is_empty(),
        "the second statement was answered while the attach's attachment was in the session: {at_the_answer:?}"
    );
}

/// A window that holds an attachment, a first statement that closes the host and is stopped right
/// after the gate has changed, and a second statement on a replacement connection: the first
/// generation's repeat, or a newer daemon's first. Returns what the session held when the second
/// statement was answered.
async fn the_second_statement_meets_a_gate_that_has_just_changed(
    generation: u64,
    statement: LocalAccess,
) -> Result<Held, &'static str> {
    let world = Arc::new(world("exec cat", true).await);
    let mut window = world.window().await;
    let mut first = world.authority(1).await;
    tell(&mut first, open(1)).await;
    let _attachment = world.attach(&mut window).await;
    let (at_the_change, go_first) = world.service.stall_a_statement_after_the_gate_changes();
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;

    tell_and_forget(first, closed(2));
    if ends_by(deadline, async move { at_the_change.await.is_ok() }).await != Some(true) {
        return Err("the first statement never reached the end of its change");
    }
    let second = world.authority(generation).await;
    let answered = tell_and_read(&world, second, statement);
    let record = Arc::clone(&answered);
    let was_answered = holds_by(deadline, move || {
        record.lock().expect("the record is not poisoned").is_some()
    })
    .await;
    let _ = go_first.send(());
    if !was_answered {
        return Err("the second statement was never answered");
    }
    let at_the_answer = recorded(&answered).map_err(|_| "the second statement failed")?;
    drop(window);
    world.close();
    Ok(at_the_answer)
}

/// KR-REQ-17.54: a repeat of a statement on a replacement connection, answered right after the
/// first statement changed the gate, is not answered before the withdrawal the first one owes.
#[test]
fn a_repeated_statement_meets_the_withdrawal_that_the_change_it_repeats_owes() {
    let at_the_answer = on_a_runtime(the_second_statement_meets_a_gate_that_has_just_changed(
        1,
        closed(2),
    ))
    .expect("the schedule came about");
    assert!(
        at_the_answer.attachments.is_empty(),
        "the repeat was answered while the window's attachment was in the session: {at_the_answer:?}"
    );
}

/// KR-REQ-17.54: a newer daemon's first statement, which changes nothing the gate holds, is not
/// answered before the withdrawal the earlier daemon's last statement owes.
#[test]
fn a_newer_daemons_statement_meets_the_withdrawal_that_the_change_before_it_owes() {
    let at_the_answer = on_a_runtime(the_second_statement_meets_a_gate_that_has_just_changed(
        2,
        closed(1),
    ))
    .expect("the schedule came about");
    assert!(
        at_the_answer.attachments.is_empty(),
        "the statement was answered while the window's attachment was in the session: {at_the_answer:?}"
    );
}

/// A window with an attachment whose connection has ended and taken its attachment list but not
/// yet counted or detached anything, and a statement that closes the host meanwhile. Returns whether
/// the statement was answered before the end made its detach, and what the session held when it was
/// answered.
async fn a_statement_meets_a_connection_that_has_taken_its_attachments()
-> Result<(bool, Held), &'static str> {
    let world = Arc::new(world("exec cat", true).await);
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;
    let _attachment = world.attach(&mut window).await;
    let (at_the_take, go_end) = world
        .service
        .stall_a_connection_after_its_attachments_are_taken();
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;

    drop(window);
    if ends_by(deadline, async move { at_the_take.await.is_ok() }).await != Some(true) {
        return Err("the window's connection never reached the end of its take");
    }
    let answered = tell_and_read(&world, daemon, closed(2));
    let waiting = Arc::clone(&world.service);
    let record = Arc::clone(&answered);
    let neither = !holds_by(deadline, move || {
        waiting.detach_waits_for_tests() > 0
            || record.lock().expect("the record is not poisoned").is_some()
    })
    .await;
    if neither {
        let _ = go_end.send(());
        return Err("the statement neither waited for the end's detach nor was answered");
    }
    let answered_before_the_detach = is_answered(&answered);
    let _ = go_end.send(());
    let record = Arc::clone(&answered);
    if !holds_by(deadline, move || {
        record.lock().expect("the record is not poisoned").is_some()
    })
    .await
    {
        return Err("the statement was never answered");
    }
    let at_the_answer = recorded(&answered).map_err(|_| "the statement failed")?;
    world.close();
    Ok((answered_before_the_detach, at_the_answer))
}

/// KR-REQ-17.54: a statement is not answered between the moment a connection's end takes its
/// attachment list and the moment it counts the detaches it owes.
#[test]
fn a_statement_is_not_answered_between_a_connections_take_of_its_attachments_and_their_count() {
    let (answered_before_the_detach, at_the_answer) =
        on_a_runtime(a_statement_meets_a_connection_that_has_taken_its_attachments())
            .expect("the schedule came about");
    assert!(
        !answered_before_the_detach,
        "the statement was answered while the end of a connection had taken its attachments and detached none"
    );
    assert!(
        at_the_answer.attachments.is_empty(),
        "the statement was answered while the attachment was in the session: {at_the_answer:?}"
    );
}

/// A window that holds an attachment, a statement that tightens to a live lease and is stopped
/// after its wait, a second attach of the window that is checked under the lease and stopped inside
/// the boundary, and the end of the window's connection, stopped before it takes its attachments.
/// The statement is let go and withdraws the window; the attach lands; a further statement closes
/// the host. Returns what the session held when the further statement was answered.
async fn a_push_meets_the_withdrawal_of_its_connection() -> Result<Held, &'static str> {
    let world = Arc::new(world("exec cat", true).await);
    let mut window = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;
    let _first_attachment = world.attach(&mut window).await;
    let (at_the_hold, go_statement) = world.service.stall_a_statement_after_its_hold();
    let (checked, go_attach) = world.service.stall_a_mutation_after_its_dispatch_check();
    let (at_the_end, go_end) = world.service.stall_a_connection_at_its_end();
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;

    let (_acknowledged, daemon_end) =
        start_the_statement(daemon, world.machine.lease(2, FAR_MS, FAR_MS));
    if ends_by(deadline, async move { at_the_hold.await.is_ok() }).await != Some(true) {
        return Err("the statement never reached the end of its wait");
    }
    // The window's second attach passes the check under the lease, and the latch check of its
    // connection, and stops inside the boundary.
    let attach_ended = start_the_geometry_attach(&world, window);
    if ends_by(deadline, async move { checked.await.is_ok() }).await != Some(true) {
        return Err("the attach never passed the dispatch boundary's check");
    }
    // The statement sweeps: it withdraws the window's connection, which takes its list.
    go_statement.send(()).expect("lets the statement go");
    let Some(daemon) = received_by(deadline, daemon_end).await else {
        let _ = go_attach.send(());
        let _ = go_end.send(());
        return Err("the statement was never acknowledged");
    };
    // The attach pushes into the list the withdrawal took, or finds the connection withdrawn; the
    // connection's own end is then stopped before it takes anything.
    go_attach.send(()).expect("lets the attach go");
    if ends_by(deadline, async move { at_the_end.await.is_ok() }).await != Some(true) {
        let _ = go_end.send(());
        return Err("the window's connection never reached its end");
    }
    // The host closes, and the connection's end has still detached nothing.
    let answered = tell_and_read(&world, daemon, closed(3));
    let record = Arc::clone(&answered);
    let was_answered = holds_by(deadline, move || {
        record.lock().expect("the record is not poisoned").is_some()
    })
    .await;
    let _ = go_end.send(());
    if !was_answered {
        return Err("the further statement was never answered");
    }
    let at_the_answer = recorded(&answered).map_err(|_| "the further statement failed")?;
    drop(received_by(deadline, attach_ended).await);
    world.close();
    Ok(at_the_answer)
}

/// KR-REQ-17.54: an attach that was checked before a withdrawal does not leave an attachment in a
/// list that no registry holds.
///
/// The withdrawal of the window's connection takes its list while the attach waits inside the
/// boundary. The attach then pushes its attachment; it must find the connection withdrawn and
/// detach it, because the connection's own end has not yet taken anything and the further statement
/// that closes the host cannot find the window any more.
#[test]
fn an_attach_that_lands_after_the_withdrawal_of_its_connection_leaves_nothing_in_the_session() {
    let at_the_answer = on_a_runtime(a_push_meets_the_withdrawal_of_its_connection())
        .expect("the schedule came about");
    assert!(
        at_the_answer.attachments.is_empty(),
        "the further statement was answered while the attach's attachment was in the session: {at_the_answer:?}"
    );
}

/// What a statement's sweep did to the requests of a second window while a withdrawal that it runs
/// waited for a lock, on a runtime with one worker thread.
struct OnOneThread {
    answered_while_held: bool,
    /// What the second window's read was answered, or nothing when it was not answered by the bound.
    read: Option<Result<(), ProtocolError>>,
    answered_after_the_release: bool,
    holds_nothing_at_the_end: bool,
}

/// One window that holds an attachment, a second window that holds nothing, the attention fence's
/// own lock held on a thread of its own (what a statement of a privacy transition holds across a
/// read of the journal, and what a withdrawal's unbind waits for), and a statement that closes the
/// host.
///
/// The second window's read is asked once the sweep of the statement waits for the lock. With one
/// worker thread, a sweep that ran on that thread would stop every other connection's frames, the
/// refusal of this read among them; the answer is looked for within a short bound that is the
/// case's own, and the lock is let go before the case says what it found.
async fn a_sweep_waits_for_a_lock_on_a_runtime_with_one_thread() -> Result<OnOneThread, &'static str>
{
    let world = Arc::new(world("exec cat", true).await);
    let mut holder_window = world.window().await;
    let mut second = world.window().await;
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;
    let _attachment = world.attach(&mut holder_window).await;
    world
        .read(&mut second)
        .await
        .expect("the second window is served under an open host");
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;

    // The host's own maintenance pass owes the same withdrawal and waits for the same lock, and it
    // runs off the executor: with it out of the way, the counter of withdrawals that wait for the
    // fence's lock is the statement's own, and a sweep on the executor's thread cannot be hidden
    // by a pass that raised it.
    let (maintenance_held, maintenance_end) = std::sync::mpsc::channel();
    let (release_maintenance, keep) = std::sync::mpsc::channel::<()>();
    let keeper = Arc::clone(&world);
    std::thread::spawn(move || {
        let _maintenance = keeper.service.hold_maintenance();
        let _ = maintenance_held.send(());
        let _ = keep.recv();
    });
    if received_by(deadline, maintenance_end).await.is_none() {
        return Err("the maintenance pass was never kept out");
    }

    let (held, held_end) = std::sync::mpsc::channel();
    let (let_go, go) = std::sync::mpsc::channel::<()>();
    let holder = Arc::clone(&world);
    std::thread::spawn(move || {
        let _fence = holder.service.hold_the_attention_fence_for_tests();
        let _ = held.send(());
        let _ = go.recv();
    });
    if received_by(deadline, held_end).await.is_none() {
        return Err("the attention fence's lock was never held");
    }

    // The statement closes the host. Its sweep withdraws the first window, and the withdrawal waits
    // for the fence's lock.
    let (acknowledged, daemon_end) = start_the_statement(daemon, closed(2));
    let waiting = Arc::clone(&world.service);
    let answered = Arc::clone(&acknowledged);
    if !holds_by(deadline, move || {
        waiting.unbinds_waiting_for_tests() > 0 || is_set(&answered)
    })
    .await
    {
        let _ = let_go.send(());
        return Err("the sweep never reached the withdrawal's wait for the fence's lock");
    }
    let answered_while_held = is_set(&acknowledged);

    // The second window asks for a read: the gate already refuses it, and the worker's one thread is
    // there to say so.
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let asking = Arc::clone(&world);
    let read = ends_by(bound, async move { asking.read(&mut second).await }).await;
    let _ = let_go.send(());

    let answered_after_the_release = received_by(deadline, daemon_end).await.is_some();
    let nothing = Arc::clone(&world);
    let holds_nothing_at_the_end = holds_by(deadline, move || nothing.holds_nothing()).await;
    drop(holder_window);
    let _ = release_maintenance.send(());
    world.close();
    Ok(OnOneThread {
        answered_while_held,
        read,
        answered_after_the_release,
        holds_nothing_at_the_end,
    })
}

/// KR-REQ-17.54: a statement's sweep and the writer's withdrawal run off the executor. A withdrawal
/// waits for the attention fence's lock, which a privacy transition holds across a read of the
/// journal; on a worker with one executor thread, a sweep that waited on that thread would stop the
/// refusal that every other local connection is owed under the new statement.
#[test]
fn a_sweep_that_waits_for_a_lock_does_not_stop_the_refusals_of_the_other_windows() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("a runtime");
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(a_sweep_waits_for_a_lock_on_a_runtime_with_one_thread())
    }));
    runtime.shutdown_background();
    let outcome = match outcome {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(step)) => panic!("the schedule did not come about: {step}"),
        Err(panic) => std::panic::resume_unwind(panic),
    };
    assert!(
        !outcome.answered_while_held,
        "the statement was acknowledged while its withdrawal waited for the fence's lock"
    );
    let read = outcome.read.expect(
        "the second window's read was not answered within the bound while the sweep waited for a \
         lock: the sweep stopped the worker's one thread",
    );
    let error = read.expect_err("a read is refused under the new statement");
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
    assert!(
        outcome.answered_after_the_release,
        "the statement was not acknowledged after the lock was let go"
    );
    assert!(
        outcome.holds_nothing_at_the_end,
        "the first window still holds something after the acknowledgement"
    );
}

/// Ends the connection of `window`, which holds an attachment, and stops the end right after it
/// has taken the attachments it owns and before it has detached any: those detaches are pending.
/// Returns the end that lets the connection's end go on.
async fn end_a_window_at_its_take(
    world: &World,
    window: LocalClient,
    deadline: std::time::Instant,
) -> Result<std::sync::mpsc::Sender<()>, &'static str> {
    let (at_the_take, release) = world
        .service
        .stall_a_connection_after_its_attachments_are_taken();
    drop(window);
    if ends_by(deadline, async move { at_the_take.await.is_ok() }).await != Some(true) {
        return Err("a window's connection never reached the end of its take");
    }
    Ok(release)
}

/// Whether, by `deadline`, a statement has either waited for a detach that is pending or been
/// acknowledged. The count of waits is cumulative, so `sample` is its value read before the
/// statement started: a wait that an earlier statement made does not count for this one.
async fn waits_or_is_answered(
    world: &Arc<World>,
    acknowledged: &Arc<std::sync::atomic::AtomicBool>,
    sample: usize,
    deadline: std::time::Instant,
) -> bool {
    let waiting = Arc::clone(&world.service);
    let answered = Arc::clone(acknowledged);
    holds_by(deadline, move || {
        waiting.detach_waits_for_tests() > sample || is_set(&answered)
    })
    .await
}

/// Asks to attach a terminal in `window` and gives what the worker answered.
async fn try_to_attach(
    world: &World,
    window: &mut Client<impl Codec>,
) -> Result<(), ProtocolError> {
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    window
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            world.target(),
            &SessionAttachParams {
                session_id: world.session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested,
            },
        )
        .await
        .expect("the call reaches the worker")
        .map(|_| ())
}

/// What the session held when a statement was acknowledged while the detach of a window's end that
/// came after the statement had looked was still to be made.
struct LaterEnd {
    answered_before_the_first_detach: bool,
    at_the_answer: Held,
    second: AttachmentId,
}

/// Two windows that hold an attachment each, the end of the first stopped before its detach, a
/// statement that waits for that detach, and then the end of the second, stopped before its detach
/// too. The first detach is made: the statement must be acknowledged then, with the second end's
/// detach still to be made, since the second end began after the statement had looked.
///
/// Under a count of every running detach the acknowledgement does not come while ends of
/// connections go on; the wait for it is the case's own bound.
async fn a_statement_meets_the_end_of_a_connection_that_comes_after_it()
-> Result<LaterEnd, &'static str> {
    let world = Arc::new(world("exec cat", true).await);
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;
    let mut first_window = world.window().await;
    let _first = world.attach(&mut first_window).await;
    let mut second_window = world.window().await;
    let second = world.attach(&mut second_window).await;
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;

    let release_first = end_a_window_at_its_take(&world, first_window, deadline).await?;
    let sample = world.service.detach_waits_for_tests();
    let (acknowledged, daemon_end) = start_the_statement(daemon, open(2));
    if !waits_or_is_answered(&world, &acknowledged, sample, deadline).await {
        let _ = release_first.send(());
        return Err("the statement neither waited for the first end's detach nor was acknowledged");
    }
    let answered_before_the_first_detach = is_set(&acknowledged);

    let release_second = match end_a_window_at_its_take(&world, second_window, deadline).await {
        Ok(release) => release,
        Err(step) => {
            let _ = release_first.send(());
            return Err(step);
        }
    };
    let _ = release_first.send(());
    if received_by(deadline, daemon_end).await.is_none() {
        let _ = release_second.send(());
        return Err(
            "the statement was never acknowledged while the detach of a later end was still to be made",
        );
    }
    let reader = Arc::clone(&world);
    let at_the_answer = tokio::task::spawn_blocking(move || held(&reader))
        .await
        .expect("the session is read");
    let _ = release_second.send(());
    let nothing = Arc::clone(&world);
    if !holds_by(deadline, move || nothing.holds_nothing()).await {
        return Err("the second end never detached its attachment");
    }
    world.close();
    Ok(LaterEnd {
        answered_before_the_first_detach,
        at_the_answer,
        second,
    })
}

/// KR-REQ-17.54: a statement is acknowledged when the detaches that were pending when it looked
/// are made, however many connections end after that.
///
/// The statement answers for what the earlier statement left. A window that ends after the
/// statement has looked made its attachment under the statement that is in force, and the statement
/// that follows is the one to wait for it.
#[test]
fn a_statement_is_acknowledged_while_the_detach_of_a_connection_that_ended_after_it_is_pending() {
    let landed = on_a_runtime(a_statement_meets_the_end_of_a_connection_that_comes_after_it())
        .expect("the schedule came about");
    assert!(
        !landed.answered_before_the_first_detach,
        "the statement was acknowledged while the first end's detach was pending"
    );
    assert_eq!(
        landed.at_the_answer.attachments,
        vec![landed.second],
        "the statement was acknowledged with the first window's attachment in the session, or without the second's: {:?}",
        landed.at_the_answer
    );
}

/// What came of an `Open` statement under ends of connections and of the `Closed` statement that
/// follows it.
struct OpenThenClosed {
    closed_answered_with_a_detach_pending: bool,
    attach_after_the_closed: Result<(), ProtocolError>,
    nothing_held_at_the_end: bool,
}

/// The order of a worker that reconnects to its daemon while windows attach and end. The end of
/// the first window is stopped before its detach, the daemon's `Open` statement waits for it, and
/// the end of the second window comes after. When the `Open` statement is acknowledged the daemon
/// tells `Closed`: the gate must change at once, a third window's attach is refused, and the
/// statement is acknowledged when the second end's detach, which it waits for, is made.
async fn an_open_statement_under_churn_and_the_closed_that_follows()
-> Result<OpenThenClosed, &'static str> {
    let world = Arc::new(world("exec cat", true).await);
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;
    let mut first_window = world.window().await;
    let _first = world.attach(&mut first_window).await;
    let mut second_window = world.window().await;
    let _second = world.attach(&mut second_window).await;
    let third_window = world.window().await;
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;

    let release_first = end_a_window_at_its_take(&world, first_window, deadline).await?;
    let sample = world.service.detach_waits_for_tests();
    let (acknowledged, daemon_end) = start_the_statement(daemon, open(2));
    if !waits_or_is_answered(&world, &acknowledged, sample, deadline).await {
        let _ = release_first.send(());
        return Err(
            "the Open statement neither waited for the first end's detach nor was acknowledged",
        );
    }
    let release_second = match end_a_window_at_its_take(&world, second_window, deadline).await {
        Ok(release) => release,
        Err(step) => {
            let _ = release_first.send(());
            return Err(step);
        }
    };
    let _ = release_first.send(());
    let Some(daemon) = received_by(deadline, daemon_end).await else {
        let _ = release_second.send(());
        return Err(
            "the Open statement was never acknowledged while later ends of connections went on",
        );
    };

    // The host's policy has changed to Closed meanwhile: the daemon tells it.
    let (closed_acknowledged, closed_end) = start_the_statement(daemon, closed(3));
    let waiting = Arc::clone(&world.service);
    let answered = Arc::clone(&closed_acknowledged);
    if !holds_by(deadline, move || {
        waiting.statements_waiting_for_tests() > 0 || is_set(&answered)
    })
    .await
    {
        let _ = release_second.send(());
        return Err(
            "the Closed statement never reached the worker's gate: it was never acknowledged nor waiting",
        );
    }
    let closed_answered_with_a_detach_pending = is_set(&closed_acknowledged);
    let attaching = Arc::clone(&world);
    let attach_after_the_closed = ends_by(deadline, async move {
        let mut window = third_window;
        let answer = try_to_attach(&attaching, &mut window).await;
        drop(window);
        answer
    })
    .await;
    let _ = release_second.send(());
    let Some(attach_after_the_closed) = attach_after_the_closed else {
        return Err("the third window's attach was never answered");
    };
    if received_by(deadline, closed_end).await.is_none() {
        return Err("the Closed statement was never acknowledged");
    }
    let nothing = Arc::clone(&world);
    let nothing_held_at_the_end = holds_by(deadline, move || nothing.holds_nothing()).await;
    world.close();
    Ok(OpenThenClosed {
        closed_answered_with_a_detach_pending,
        attach_after_the_closed,
        nothing_held_at_the_end,
    })
}

/// KR-REQ-17.54: an `Open` statement is acknowledged while windows end, and the `Closed` statement
/// that follows reaches the gate and is applied: the local owner cannot hold a restriction away
/// from the worker by making windows attach and end.
#[test]
fn an_open_statement_under_churn_is_acknowledged_and_the_closed_that_follows_is_applied() {
    let order = on_a_runtime(an_open_statement_under_churn_and_the_closed_that_follows())
        .expect("the schedule came about");
    let error = order
        .attach_after_the_closed
        .expect_err("a local attach is refused once the Closed statement is applied");
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
    assert!(
        !order.closed_answered_with_a_detach_pending,
        "the Closed statement was acknowledged while the detach of the second window's end was pending"
    );
    assert!(
        order.nothing_held_at_the_end,
        "the session holds an attachment or a lease after the Closed statement was acknowledged"
    );
}

/// Whether a statement was acknowledged before the session was let go, what the session held when
/// the service's own pass had made the owed detach and the statement was acknowledged, and how
/// many detaches that pass made.
struct OwedAndLater {
    answered_before_the_session_was_let_go: bool,
    at_the_answer: Held,
    second: AttachmentId,
    settled_by_the_service: u64,
}

/// Two windows that hold an attachment each; the session is held, so the end of the first owes its
/// detach to the service, whose pass waits for the session. A statement waits for that owed detach,
/// and the end of the second window, stopped before its detach, comes after it. The session is
/// let go: the pass makes the owed detach and the statement must be acknowledged then, with the
/// second end's detach still to be made.
async fn a_statement_meets_a_detach_that_a_connections_end_owed()
-> Result<OwedAndLater, &'static str> {
    let world = Arc::new(world("exec cat", true).await);
    let mut daemon = world.authority(1).await;
    tell(&mut daemon, open(1)).await;
    let mut first_window = world.window().await;
    let _first = world.attach(&mut first_window).await;
    let mut second_window = world.window().await;
    let second = world.attach(&mut second_window).await;
    let deadline = std::time::Instant::now() + LIVENESS_DEADLINE;

    let (session_held, session_held_end) = std::sync::mpsc::channel();
    let (release_session, go) = std::sync::mpsc::channel::<()>();
    let holder = Arc::clone(&world);
    std::thread::spawn(move || {
        let _session = holder.runtime.session();
        let _ = session_held.send(());
        let _ = go.recv();
    });
    if received_by(deadline, session_held_end).await.is_none() {
        return Err("the session was never held");
    }

    drop(first_window);
    let ended = Arc::clone(&world);
    if !holds_by(deadline, move || {
        ended.service.connections_held_for_tests() == 2
    })
    .await
    {
        let _ = release_session.send(());
        return Err("the first window's connection never ended");
    }
    let sample = world.service.detach_waits_for_tests();
    let (acknowledged, daemon_end) = start_the_statement(daemon, open(2));
    if !waits_or_is_answered(&world, &acknowledged, sample, deadline).await {
        let _ = release_session.send(());
        return Err("the statement neither waited for the owed detach nor was acknowledged");
    }
    let answered_before_the_session_was_let_go = is_set(&acknowledged);
    let release_second = match end_a_window_at_its_take(&world, second_window, deadline).await {
        Ok(release) => release,
        Err(step) => {
            let _ = release_session.send(());
            return Err(step);
        }
    };
    let _ = release_session.send(());
    if received_by(deadline, daemon_end).await.is_none() {
        let _ = release_second.send(());
        return Err(
            "the statement was never acknowledged after the owed detach was made while the detach of a later end was still to be made",
        );
    }
    let reader = Arc::clone(&world);
    let at_the_answer = tokio::task::spawn_blocking(move || held(&reader))
        .await
        .expect("the session is read");
    let settled_by_the_service = world.service.owed_done_for_tests().1;
    let _ = release_second.send(());
    let nothing = Arc::clone(&world);
    if !holds_by(deadline, move || nothing.holds_nothing()).await {
        return Err("the second end never detached its attachment");
    }
    world.close();
    Ok(OwedAndLater {
        answered_before_the_session_was_let_go,
        at_the_answer,
        second,
        settled_by_the_service,
    })
}

/// KR-REQ-17.54: the ticket of a detach that the end of a connection owed to the service is
/// completed by the service's own pass, and the statement that waited for it is acknowledged then,
/// whatever other connections have ended since.
#[test]
fn a_statement_is_acknowledged_when_the_service_makes_the_detach_that_a_connections_end_owed() {
    let landed = on_a_runtime(a_statement_meets_a_detach_that_a_connections_end_owed())
        .expect("the schedule came about");
    assert!(
        !landed.answered_before_the_session_was_let_go,
        "the statement was acknowledged while the session was held and the owed detach was pending"
    );
    assert_eq!(
        landed.settled_by_the_service, 1,
        "the service's own pass did not make the owed detach"
    );
    assert_eq!(
        landed.at_the_answer.attachments,
        vec![landed.second],
        "the statement was acknowledged with the first window's attachment in the session, or without the second's: {:?}",
        landed.at_the_answer
    );
}
