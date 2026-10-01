//! A worker launched while privacy mode is on is told so by its launch specification.
//!
//! A real daemon, on its local socket, and this process playing the worker the daemon asks for: the
//! specification a worker is handed is read as it arrives, before any shell could run. What each
//! test reads is what the daemon decided, from the record it keeps and the specification it sent.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-24.27 | a worker launched while privacy mode is on is given the generation and that it is on, before its shell runs, and the state it is given is the one in force when its claim is accepted |
//! | KR-REQ-24.28 | a session whose launch has handed out its specification when privacy mode is turned on owes its cleanup, across a daemon restart too, and turning privacy mode off waits for it; one launched while privacy mode is on owes it from before its worker runs |

use std::sync::Arc;
use std::time::Duration;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::envelope::{ActionTarget, ControlFrame};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId, SessionEpoch};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::privacy::{PrivacyReport, PrivacySetParams, PrivacyStatusParams};
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::session::{LaunchProfile, Presentation, SessionCreateParams, ShellMode};
use kr_protocol::worker::{PrivacyLaunch, WorkerLaunchSpec};

/// How long a test waits for what the daemon does by itself.
const PATIENCE: Duration = Duration::from_secs(30);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// A supervisor that starts nothing and reports this process as the worker it started, so this
/// process can perform the worker's side of the rendezvous.
#[derive(Debug)]
struct RendezvousSupervisor {
    launched: std::sync::Mutex<std::sync::mpsc::Sender<WorkerLaunch>>,
    /// Set by a test that wants the next launch to start nothing.
    refuse: Arc<std::sync::atomic::AtomicBool>,
}

impl WorkerSupervisor for RendezvousSupervisor {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        let _ = self
            .launched
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .send(launch.clone());
        if self.refuse.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return LaunchOutcome::NotStarted {
                detail: "this test's supervisor starts nothing this time".to_owned(),
            };
        }
        LaunchOutcome::Started(
            kr_ipc::identity::current_process_start_identity().expect("a process identity"),
        )
    }

    fn describe(&self) -> &'static str {
        "a supervisor that hands the rendezvous to this process"
    }
}

/// A daemon on a tree of its own, asked for workers through [`RendezvousSupervisor`].
struct Daemon {
    temp: kr_ipc::testing::TempHost,
    client_endpoint: kr_ipc::paths::Endpoint,
    rendezvous_endpoint: kr_ipc::paths::Endpoint,
    environment_id: EnvironmentId,
    launches: std::sync::mpsc::Receiver<WorkerLaunch>,
    refuse: Arc<std::sync::atomic::AtomicBool>,
    controller: Arc<Controller>,
    serving: Vec<tokio::task::JoinHandle<kr_controller::Result<()>>>,
}

async fn daemon() -> Daemon {
    start(kr_ipc::testing::TempHost::create()).await
}

/// Starts a daemon on `temp`, whose environment may already hold what an earlier daemon left.
async fn start(temp: kr_ipc::testing::TempHost) -> Daemon {
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    environment.create().expect("the environment's directories");
    let secrets = environment.secrets_dir();
    let (launched, launches) = std::sync::mpsc::channel();
    let refuse = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let controller = kr_controller::testing::taken_over(|| {
        let secrets = secrets.clone();
        let launched = launched.clone();
        let refuse = Arc::clone(&refuse);
        Controller::start(ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                let store =
                    open_store_in(&secrets).expect("a secret store for the test environment");
                Ok(
                    ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                        .expect("an identity"),
                )
            }),
            secret_store: StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(RendezvousSupervisor {
                launched: std::sync::Mutex::new(launched),
                refuse,
            }),
            worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        })
    })
    .await
    .expect("the daemon starts");
    let client_endpoint = environment.controller_endpoint().expect("an endpoint");
    let rendezvous_endpoint = environment.rendezvous_endpoint().expect("an endpoint");
    let serving =
        vec![
            tokio::spawn(Arc::clone(&controller).serve_clients(
                Listener::bind(&client_endpoint).expect("binds the client endpoint"),
            )),
            tokio::spawn(Arc::clone(&controller).serve_rendezvous(
                Listener::bind(&rendezvous_endpoint).expect("binds the rendezvous endpoint"),
            )),
        ];
    Daemon {
        temp,
        client_endpoint,
        rendezvous_endpoint,
        environment_id,
        launches,
        refuse,
        controller,
        serving,
    }
}

impl Daemon {
    /// Stops this daemon the way its process exiting would, and keeps the environment's tree.
    async fn stop(self) -> kr_ipc::testing::TempHost {
        let Self {
            temp,
            controller,
            serving,
            ..
        } = self;
        for task in &serving {
            task.abort();
        }
        for task in serving {
            let _ = task.await;
        }
        drop(controller);
        temp
    }

    /// Has the supervisor start nothing for the next launch it is asked for.
    fn refuse_the_next_launch(&self) {
        self.refuse.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    async fn client(&self) -> LocalClient {
        LocalClient::connect(&self.client_endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects")
    }

    fn target(&self) -> ActionTarget {
        ActionTarget::environment(self.environment_id)
    }

    /// Turns privacy mode on or off at the daemon's local socket.
    async fn set(&self, enabled: bool) -> Result<PrivacyReport, kr_protocol::error::ProtocolError> {
        self.client()
            .await
            .mutate(
                Method::PrivacySet,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(),
                &PrivacySetParams { enabled },
            )
            .await
            .expect("the call reaches the daemon")
            .map(|value| value.to_typed().expect("decodes"))
    }

    /// Reads where privacy mode stands.
    async fn status(&self) -> PrivacyReport {
        self.client()
            .await
            .request(Method::PrivacyStatus, &PrivacyStatusParams {})
            .await
            .expect("the call reaches the daemon")
            .expect("privacy mode's report")
            .to_typed()
            .expect("decodes")
    }

    /// Asks for a session, performs the worker's side of its rendezvous as far as the launch
    /// specification, and returns what the daemon asked its supervisor to start with the
    /// specification it handed that worker. This process goes no further, so the create is not
    /// waited for.
    async fn launched(&self) -> (WorkerLaunch, WorkerLaunchSpec) {
        let creating = tokio::spawn({
            let endpoint = self.client_endpoint.clone();
            let environment_id = self.environment_id;
            async move {
                let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
                    .await
                    .expect("connects");
                client
                    .mutate(
                        Method::SessionCreate,
                        ActionId::new(kr_ipc::new_uuid()),
                        ActionTarget::environment(environment_id),
                        &create(environment_id),
                    )
                    .await
            }
        });
        let launch = self
            .launches
            .recv_timeout(PATIENCE)
            .expect("the daemon asks for a worker");
        let specification = self.present_claim(&launch).await;
        creating.abort();
        (launch, specification)
    }

    /// Presents the startup claim of the worker `launch` asked for, and reads what the daemon
    /// answers it.
    async fn present_claim(&self, launch: &WorkerLaunch) -> WorkerLaunchSpec {
        let identity = WorkerIdentity::generate(
            launch.session_id,
            SessionEpoch::V1,
            kr_ipc::identity::boot_identity().expect("a boot identity"),
            kr_ipc::identity::current_process_start_identity().expect("a process identity"),
            PROTOCOL_VERSION,
        )
        .expect("a session key");
        let connection = kr_ipc::endpoint::Connection::connect(&self.rendezvous_endpoint)
            .await
            .expect("connects to the rendezvous");
        let (mut reader, mut writer) =
            kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
        writer
            .write_message(&ControlFrame::Hello(kr_protocol::local::LocalHello {
                offered_versions: vec![PROTOCOL_VERSION],
                build_id: build(),
                client: LocalClientKind::Worker,
                capabilities: kr_protocol::scalars::CanonicalSet::new(),
                max_receive: kr_protocol::hello::ReceiveLimits::default(),
            }))
            .await
            .expect("writes the hello");
        let acknowledgement: ControlFrame =
            reader.read_message().await.expect("the daemon answers");
        assert!(
            matches!(acknowledgement, ControlFrame::HelloAck(_)),
            "the daemon acknowledges the worker: {acknowledgement:?}"
        );
        writer
            .write_message(&ControlFrame::Rendezvous(
                identity
                    .rendezvous(launch.reservation_id)
                    .expect("a startup claim"),
            ))
            .await
            .expect("writes the startup claim");
        let specification: ControlFrame = tokio::time::timeout(PATIENCE, reader.read_message())
            .await
            .expect("the daemon answers in time")
            .expect("the daemon answers");
        let ControlFrame::LaunchSpec(specification) = specification else {
            panic!("the daemon sends a launch specification: {specification:?}");
        };
        *specification
    }
}

/// A create request for an invisible session.
fn create(environment_id: EnvironmentId) -> SessionCreateParams {
    SessionCreateParams {
        environment_id,
        presentation: Presentation::Invisible,
        shell: Nullable::null(),
        shell_mode: ShellMode::NativeCompat,
        cwd: Nullable::some("/".to_owned()),
        dimensions: Nullable::null(),
        worker_profile: WorkerProfile::HeadlessUser,
        environment_snapshot: Vec::new(),
        palette: Nullable::null(),
        launch_profile: LaunchProfile::default(),
        terminal: Nullable::null(),
    }
}

fn state(generation: u64, enabled: bool) -> PrivacyLaunch {
    PrivacyLaunch {
        generation: U64::new(generation),
        enabled,
    }
}

/// KR-REQ-24.27: a worker launched while privacy mode is on is given the generation in force and
/// that it is on, in the specification it reads before it starts its shell.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_27_a_worker_launched_while_privacy_mode_is_on_is_given_the_generation() {
    let daemon = daemon().await;
    let on = daemon.set(true).await.expect("privacy mode is turned on");
    assert!(on.enabled);
    let (_launch, specification) = daemon.launched().await;
    assert_eq!(specification.privacy, state(on.generation.get(), true));
    assert_eq!(on.generation.get(), 1);
}

/// KR-REQ-24.27: a worker launched in an environment that has never turned privacy mode on is
/// given the initial generation, off; one launched after it was turned on and off again is given
/// the generation that turning it off recorded, off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_27_a_worker_is_given_the_state_in_force_when_its_claim_is_accepted() {
    let never = daemon().await;
    let (_launch, specification) = never.launched().await;
    assert_eq!(specification.privacy, state(0, false));

    let after = daemon().await;
    after.set(true).await.expect("privacy mode is turned on");
    let off = after.set(false).await.expect("and off again");
    assert!(!off.enabled);
    assert_eq!(off.generation.get(), 2);
    let (_launch, specification) = after.launched().await;
    assert_eq!(specification.privacy, state(2, false));
}

/// Where each session the report names stands, by session.
fn owing(report: &PrivacyReport) -> Vec<kr_protocol::ids::SessionId> {
    report.sessions.iter().map(|owed| owed.session_id).collect()
}

/// KR-REQ-24.28: a worker that was handed a specification saying privacy mode was off, and has not
/// reported yet, owes its cleanup when privacy mode is turned on after: it has no journal and no
/// worker row for a list to find, and is told the generation by the daemon's notice once it runs.
/// Turning privacy mode off is refused, naming it, until it answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_28_a_launch_under_way_when_privacy_mode_is_turned_on_owes_its_cleanup() {
    let daemon = daemon().await;
    let (launch, specification) = daemon.launched().await;
    assert_eq!(specification.privacy, state(0, false));
    let before = daemon.status().await;
    assert!(owing(&before).is_empty(), "nothing is owed while it is off");

    let on = daemon.set(true).await.expect("privacy mode is turned on");
    assert_eq!(owing(&on), vec![launch.session_id], "the launch owes it");
    let refused = daemon
        .set(false)
        .await
        .expect_err("a worker that may still start holds privacy mode on");
    assert!(
        refused.message.contains(&launch.session_id.to_string()),
        "the refusal names the session: {refused:?}"
    );
}

/// KR-REQ-24.28: the same, across a restart of the daemon between the specification and the change.
/// The new daemon holds no record in memory of the launch, and the worker has no journal or row yet,
/// so the registry's reservation is what says a worker may be running there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_28_a_launch_under_way_across_a_restart_owes_its_cleanup() {
    let first = daemon().await;
    let (launch, specification) = first.launched().await;
    assert_eq!(specification.privacy, state(0, false));
    let temp = first.stop().await;

    let second = start(temp).await;
    let on = second.set(true).await.expect("privacy mode is turned on");
    assert_eq!(
        owing(&on),
        vec![launch.session_id],
        "the reservation says a worker may be running"
    );
    second
        .set(false)
        .await
        .expect_err("and it holds privacy mode on");
}

/// KR-REQ-24.27: a worker launched while privacy mode is on owes its cleanup from before it runs:
/// the obligation is on the disk when its specification is read, and turning privacy mode off is
/// refused, naming it, whatever the daemon's tick has or has not seen.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_27_a_worker_launched_while_privacy_mode_is_on_owes_cleanup_before_it_runs() {
    let daemon = daemon().await;
    daemon.set(true).await.expect("privacy mode is turned on");
    let (launch, specification) = daemon.launched().await;
    assert_eq!(specification.privacy, state(1, true));

    let recorded: i64 = rusqlite::Connection::open(
        daemon
            .temp
            .environment()
            .state_dir()
            .join(kr_controller::privacy::PRIVACY_RECORD),
    )
    .expect("a second connection to the record")
    .query_row(
        "SELECT COUNT(*) FROM privacy_obligations WHERE session_id = ?1",
        [launch.session_id.to_string()],
        |row| row.get(0),
    )
    .expect("a count");
    assert_eq!(recorded, 1, "the obligation is on the disk");
    assert_eq!(owing(&daemon.status().await), vec![launch.session_id]);
    let refused = daemon
        .set(false)
        .await
        .expect_err("a worker that may still start holds privacy mode on");
    assert!(
        refused.message.contains(&launch.session_id.to_string()),
        "{refused:?}"
    );
}

/// KR-REQ-24.28: a launch the supervisor could not start owes nothing and is not reported as ended
/// with the archive named: no worker claimed it, so no shell ran, and the tick forgets it with its
/// obligation. The control is the launch above, whose worker did claim.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_28_a_launch_that_started_nothing_is_forgotten_not_reported_as_ended() {
    let daemon = daemon().await;
    daemon.set(true).await.expect("privacy mode is turned on");
    // The supervisor starts nothing this time: it reports the launch as not started.
    daemon.refuse_the_next_launch();
    let created = daemon
        .client()
        .await
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            daemon.target(),
            &create(daemon.environment_id),
        )
        .await
        .expect("the call reaches the daemon");
    assert!(created.is_err(), "a launch that starts nothing fails");
    let launch = daemon
        .launches
        .recv_timeout(PATIENCE)
        .expect("the daemon asked for a worker");
    // A few passes of the tick, and the session is neither owed nor ended.
    let deadline = std::time::Instant::now() + PATIENCE;
    loop {
        let report = daemon.status().await;
        if owing(&report).is_empty() {
            assert!(
                report.completion == kr_protocol::privacy::PrivacyCompletion::Complete,
                "{:?}",
                report.completion
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the tick never forgot {}: {:?}",
            launch.session_id,
            report.sessions
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    daemon
        .set(false)
        .await
        .expect("a launch that never started does not hold privacy mode on");
}

/// KR-REQ-24.27: the state a worker is given is the one in force when its claim is committed, not
/// the one in force when its create arrived. Privacy mode is turned on after the claim is committed
/// and before the daemon builds the specification; the worker is told it is on, and its session
/// owes its cleanup from that change, though its create saw privacy mode off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_27_a_worker_is_given_the_state_in_force_when_its_claim_is_committed() {
    let daemon = daemon().await;
    let (mut arrived, release) = daemon.controller.pause_rendezvous_after_claim();
    let creating = tokio::spawn({
        let endpoint = daemon.client_endpoint.clone();
        let environment_id = daemon.environment_id;
        async move {
            let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
                .await
                .expect("connects");
            client
                .mutate(
                    Method::SessionCreate,
                    ActionId::new(kr_ipc::new_uuid()),
                    ActionTarget::environment(environment_id),
                    &create(environment_id),
                )
                .await
        }
    });
    let launch = daemon
        .launches
        .recv_timeout(PATIENCE)
        .expect("the daemon asks for a worker");
    let claiming = daemon.present_claim(&launch);
    tokio::pin!(claiming);
    tokio::select! {
        _ = &mut arrived => {}
        _ = &mut claiming => panic!("the daemon answered the claim before its pause"),
    }
    assert!(
        owing(&daemon.status().await).is_empty(),
        "privacy mode is off"
    );

    // The claim is committed and the specification is not built: privacy mode is turned on here.
    let on = daemon.set(true).await.expect("privacy mode is turned on");
    assert_eq!(
        owing(&on),
        vec![launch.session_id],
        "its create saw privacy mode off"
    );
    release.send(()).expect("the daemon goes on");
    let specification = claiming.await;
    assert_eq!(specification.privacy, state(1, true));
    creating.abort();
}

/// KR-REQ-24.28: launches the daemon's recovery fails at a start, one reserved and never spawned
/// and one spawned that recorded no launcher, own an obligation their daemon wrote while privacy
/// mode was on; read back from the disk before any worker is seen, each is forgotten once the
/// registry shows its launch never produced a worker, and does not keep privacy mode on or the
/// report from saying so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_28_launches_recovery_fails_are_forgotten_with_their_obligations() {
    let first = daemon().await;
    first.set(true).await.expect("privacy mode is turned on");
    let temp = first.stop().await;

    // While no daemon runs, the launches a daemon that stopped part way through two creates left.
    let environment = temp.environment();
    let mut registry = kr_controller::registry::Registry::open(
        environment.registry_database(),
        environment.environment_id(),
    )
    .expect("the registry");
    let mut left = Vec::new();
    for token in [1_u8, 2] {
        let reservation = registry
            .reserve(
                &kr_protocol::ids::ActorId::new("local:501").expect("a principal"),
                kr_protocol::scalars::Uuid::from_bytes([token; 16]),
                kr_protocol::scalars::Digest256::from_bytes([3; 32]),
                b"intent",
                kr_protocol::scalars::TimestampMs::new(1),
            )
            .expect("reserves")
            .reservation;
        if token == 2 {
            registry
                .set_phase(
                    reservation.reservation_id,
                    kr_controller::registry::LaunchPhase::Spawned,
                )
                .expect("the phase is recorded");
        }
        left.push(reservation.session_id);
    }
    drop(registry);
    let record = rusqlite::Connection::open(
        environment
            .state_dir()
            .join(kr_controller::privacy::PRIVACY_RECORD),
    )
    .expect("the privacy record");
    for session_id in &left {
        record
            .execute(
                "INSERT INTO privacy_obligations (session_id, generation, recorded_at_ms)
                 VALUES (?1, 1, 1)",
                [session_id.to_string()],
            )
            .expect("the obligation the stopped daemon wrote");
    }
    drop(record);

    let second = start(temp).await;
    let deadline = std::time::Instant::now() + PATIENCE;
    loop {
        let report = second.status().await;
        if owing(&report).is_empty() {
            assert!(
                report.completion == kr_protocol::privacy::PrivacyCompletion::Complete,
                "{:?}",
                report.completion
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the tick never forgot {left:?}: {:?}",
            report.sessions
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    second
        .set(false)
        .await
        .expect("launches that never started do not hold privacy mode on");
}
