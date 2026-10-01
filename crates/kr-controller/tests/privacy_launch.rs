//! A worker launched while privacy mode is on is told so by its launch specification.
//!
//! A real daemon, on its local socket, and this process playing the worker the daemon asks for: the
//! specification a worker is handed is read as it arrives, before any shell could run. What each
//! test reads is what the daemon decided, from the record it keeps and the specification it sent.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-24.27 | a worker launched while privacy mode is on is given the generation and that it is on, before its shell runs, and the state it is given is the one in force when its claim is accepted |
//! | KR-REQ-24.28 | a session whose launch has handed out its specification when privacy mode is turned on owes its cleanup, and turning privacy mode off waits for it |

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
}

impl WorkerSupervisor for RendezvousSupervisor {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        let _ = self
            .launched
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .send(launch.clone());
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
    _temp: kr_ipc::testing::TempHost,
    client_endpoint: kr_ipc::paths::Endpoint,
    rendezvous_endpoint: kr_ipc::paths::Endpoint,
    environment_id: EnvironmentId,
    launches: std::sync::mpsc::Receiver<WorkerLaunch>,
    _controller: Arc<Controller>,
}

async fn daemon() -> Daemon {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    environment.create().expect("the environment's directories");
    let secrets = environment.secrets_dir();
    let (launched, launches) = std::sync::mpsc::channel();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store for the test environment");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(RendezvousSupervisor {
            launched: std::sync::Mutex::new(launched),
        }),
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: build(),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    })
    .await
    .expect("the daemon starts");
    let client_endpoint = environment.controller_endpoint().expect("an endpoint");
    tokio::spawn(
        Arc::clone(&controller)
            .serve_clients(Listener::bind(&client_endpoint).expect("binds the client endpoint")),
    );
    let rendezvous_endpoint = environment.rendezvous_endpoint().expect("an endpoint");
    tokio::spawn(Arc::clone(&controller).serve_rendezvous(
        Listener::bind(&rendezvous_endpoint).expect("binds the rendezvous endpoint"),
    ));
    Daemon {
        _temp: temp,
        client_endpoint,
        rendezvous_endpoint,
        environment_id,
        launches,
        _controller: controller,
    }
}

impl Daemon {
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
