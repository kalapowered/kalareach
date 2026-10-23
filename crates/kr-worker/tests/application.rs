//! What a session's application is doing, as the worker reports it in the session's summary.
//!
//! Each case runs a worker service over a real session and a real shell, installs the Codex-shaped
//! test package on the service's own broker as a launch does, and opens a connection whose owner
//! the case drives by hand: what the server says goes in through the upstream end. The state is
//! read back from the session's summary, which is what the control daemon reads when it decides
//! whether the host is kept awake. No foreground watch runs here, so everything a case sees comes
//! from what the broker and the question ledger hold.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-03.27 | an approval a connector's table answers and a binding interpreted is the application's state until it is settled, and one nothing interpreted never is; an open question is, until it is answered or cancelled; a turn the connector's table names is, until it ends; an approval outranks a question and a question outranks a turn; and a session that has closed describes nothing, and names no application |

#![cfg(unix)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::broker::IntegrationMode;
use kr_protocol::gateway::NativeFraming;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{
    DesktopBinding, ProcessStartIdentity, ProcessStartSource, WorkerProfile,
};
use kr_protocol::ids::{
    ApplicationInstanceId, BrokerBindingId, BuildId, ConnectionId, ControllerGeneration,
    EnvironmentId, SessionEpoch, SessionId, UpstreamRequestId,
};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, Uuid};
use kr_protocol::session::{ApplicationState, Dimensions, DisplayNumber, ShellMode};
use kr_worker::broker::binder::MatchedExecutable;
use kr_worker::broker::catalogue::{Admissions, testing};
use kr_worker::broker::connectors::{
    ConnectorSources, InstalledConnector, QualifiedExecutable, fixture,
};
use kr_worker::broker::{
    BrokerTransport, Carried, Credential, Duplex, Framing, ManagedProcess, TransportHandle,
};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};
use tokio::io::AsyncReadExt as _;

/// How long a case waits for a state it expects, before it calls it a failure.
const LIVENESS: Duration = Duration::from_secs(60);

const NOW: TimestampMs = TimestampMs::new(10);

fn session_id() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

fn instance() -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
}

fn process() -> ProcessStartIdentity {
    ProcessStartIdentity::new(41, ProcessStartSource::MacosProcBsdInfo, 900)
}

fn executable() -> Digest256 {
    Digest256::from_bytes([3; 32])
}

/// A directory of the case's own, removed when it is dropped.
struct Store(std::path::PathBuf);

impl Drop for Store {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A worker service over a live session, with one gateway instance bound to the answering package
/// and a connection open on its tables.
struct World {
    _temp: kr_ipc::testing::TempHost,
    _store: Store,
    service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    owner: Arc<Duplex>,
    /// What the owner wrote to the server.
    upstream: tokio::io::DuplexStream,
    /// What the owner wrote to the terminal.
    _client: tokio::io::DuplexStream,
    writes: tokio::task::JoinHandle<()>,
    connection: kr_protocol::ids::GatewayConnectionId,
}

impl World {
    async fn new() -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let current =
            kr_ipc::identity::current_process_start_identity().expect("a process identity");
        let identity = Arc::new(
            WorkerIdentity::generate(
                session_id(),
                SessionEpoch::V1,
                boot.clone(),
                current,
                PROTOCOL_VERSION,
            )
            .expect("a session key"),
        );
        let secrets =
            kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
        let controller = Arc::new(
            ControllerIdentity::initialise(secrets.store.as_ref(), environment_id)
                .expect("a controller identity"),
        );
        let journal_path = environment.journal_database(session_id());
        if let Some(parent) = journal_path.parent() {
            std::fs::create_dir_all(parent).expect("the journal directory");
        }
        let config = SessionConfig {
            session_id: session_id(),
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: DisplayNumber::new(1),
            shell: kr_worker::testing::posix_script("exec cat"),
            shell_mode: ShellMode::NativeCompat,
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: DesktopBinding::none(),
            dimensions: Dimensions::new(80, 24),
            journal_path: Some(journal_path.clone()),
            spool_directory: Some(environment.session_spool(session_id())),
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
        let listener = Listener::bind(&endpoint).expect("binds the endpoint");
        let service = Arc::new(
            WorkerService::new(
                Arc::clone(&runtime),
                identity,
                endpoint,
                ServiceBinding {
                    environment_id,
                    boot_identity: boot,
                    controller_public_key: *controller.public_key(),
                    controller_generation: ControllerGeneration::new(1),
                    journal_path: Some(journal_path),
                    build_id: BuildId::new("kr-test/0").expect("a build identifier"),
                },
            )
            .expect("a worker service"),
        );
        tokio::spawn(Arc::clone(&service).serve(listener));

        let root = std::env::temp_dir().join(format!("kr-application-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&root).expect("a store directory");
        let store = Store(root);
        let mut source = fixture::package(
            &store.0,
            Path::new(fixture::FORWARDER),
            &fixture::Shape::codex_backend_answering(),
        )
        .expect("the package is written");
        source.qualified = vec![QualifiedExecutable {
            digest: executable(),
            version: fixture::GATEWAY_QUALIFIED_VERSION.to_owned(),
        }];
        let connector = InstalledConnector::read(source.clone()).expect("the package is read");
        let broker = service.broker();
        let admissions = Admissions::new();
        let sources = ConnectorSources::new();
        let frame = testing::admit(
            &admissions,
            &sources,
            broker,
            vec![testing::admitted(&source)],
            1,
        );
        broker
            .register_instance(
                instance(),
                IntegrationMode::Gateway,
                None,
                Some(ManagedProcess::new(
                    instance(),
                    process(),
                    TransportHandle {
                        transport: BrokerTransport::PrivateSocket,
                        application_instance_id: instance(),
                        executable_digest: executable(),
                        process: process(),
                    },
                    Credential::from_bytes([9; 32]),
                    TimestampMs::new(1),
                )),
            )
            .expect("the instance is registered");
        broker
            .bind(
                BrokerBindingId::new(Uuid::from_bytes([7; 16])),
                instance(),
                source.package_digest,
                frame,
                MatchedExecutable {
                    path: "/usr/local/bin/codex".to_owned(),
                    digest: executable(),
                },
                NOW,
            )
            .expect("the package is bound");
        broker
            .withhold_thread(instance())
            .expect("the instance withholds its thread");
        let tables = broker
            .pin_compiled(instance(), &connector, &executable())
            .expect("the compiled tables are pinned");
        let connection = broker
            .open_native_connection(
                instance(),
                &[9; 32],
                &process(),
                &connector.plugin_id(),
                &tables.protocol_version,
            )
            .expect("a native connection opens");
        let (upstream_here, upstream) = tokio::io::duplex(1 << 20);
        let (client_here, client) = tokio::io::duplex(1 << 20);
        let (owner, writes) = Duplex::new(
            Arc::clone(broker),
            connection,
            Framing::new(NativeFraming::JsonLines),
            upstream_here,
            client_here,
            EnvironmentId::new(Uuid::from_bytes([4; 16])),
            "agent-user",
        );
        let dispatch = owner.dispatch().expect("the connection has a dispatch");
        broker.bind_connection_dispatch(connection, dispatch.clone());
        broker
            .bind_dispatch(instance(), dispatch)
            .expect("the instance has a transport");
        Self {
            _temp: temp,
            _store: store,
            service,
            runtime,
            owner,
            upstream,
            _client: client,
            writes: tokio::spawn(writes),
            connection,
        }
    }

    /// The state the session's summary shows now.
    fn state(&self) -> Option<ApplicationState> {
        self.runtime.session().summary().application_state.0
    }

    /// The name the session's summary shows now for its foreground application.
    fn name(&self) -> Option<String> {
        self.runtime.session().summary().application
    }

    /// Waits until the session's summary names `expected`, which it must do within [`LIVENESS`].
    async fn names(&self, expected: Option<&str>) {
        let deadline = tokio::time::Instant::now() + LIVENESS;
        loop {
            let held = self.name();
            if held.as_deref() == expected {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the session names {expected:?}, and named {held:?} for {LIVENESS:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Waits until the session's summary shows `expected`, which it must do within [`LIVENESS`].
    async fn shows(&self, expected: Option<ApplicationState>) {
        let deadline = tokio::time::Instant::now() + LIVENESS;
        loop {
            let held = self.state();
            if held == expected {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the session shows {expected:?}, and showed {held:?} for {LIVENESS:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// The server says something of its own.
    async fn server_says(&self, frame: &str) {
        self.owner
            .from_upstream(frame.as_bytes(), NOW)
            .await
            .expect("the frame is carried");
    }

    /// The terminal sends a request the server has not answered, and the host's identifier for it.
    async fn terminal_asks(&self, frame: &str) -> UpstreamRequestId {
        match self
            .owner
            .from_client(frame.as_bytes(), NOW)
            .await
            .expect("the request is carried")
        {
            Carried::ClientRequest {
                upstream_request_id,
                ..
            } => upstream_request_id,
            other => panic!("not a request of the terminal's: {other:?}"),
        }
    }

    /// Reads the next line the owner wrote to the server.
    async fn server_reads(&mut self) -> serde_json::Value {
        let mut line = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            self.upstream.read_exact(&mut byte).await.expect("a byte");
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
        }
        serde_json::from_slice(&line).expect("a frame")
    }

    /// The terminal selects a thread, and the server answers, so the binding names it.
    async fn terminal_selects(&mut self, thread: &str) {
        let selecting = self.terminal_asks(START).await;
        assert_eq!(self.server_reads().await["method"], "thread/start");
        let frame = format!(
            r#"{{"id":{},"result":{{"thread":{{"id":"{thread}"}}}}}}"#,
            selecting.as_str()
        );
        self.owner
            .from_upstream(frame.as_bytes(), NOW)
            .await
            .expect("the answer is carried");
    }

    /// An agent asks a question the person is to answer.
    fn ask(&self, request: &str) -> kr_protocol::question::Question {
        let source = kr_worker::questions::VerifiedSource {
            process: kr_ipc::identity::current_process_start_identity()
                .expect("a process identity"),
            executable: Some("/bin/agent".to_owned()),
            session_member: true,
            ancestry: true,
            launch_channel: true,
            connection_id: ConnectionId::new(kr_ipc::new_uuid()),
        };
        self.service
            .questions()
            .create(
                &source,
                &kr_protocol::question::QuestionCreateParams {
                    session_id: session_id(),
                    request_id: request.to_owned(),
                    agent_name: Nullable::some("an agent".to_owned()),
                    context: "two ways to do it".to_owned(),
                    question: "which one".to_owned(),
                    kind: kr_protocol::question::QuestionKind::Confirm,
                    choices: Vec::new(),
                    requested_expiry_ms: Nullable::null(),
                    wait_ms: Nullable::null(),
                },
                question_clock(),
            )
            .expect("a verified source creates a question")
            .0
            .question
    }

    /// The person withdraws a question.
    fn withdraw(&self, question: &kr_protocol::question::Question) {
        self.service
            .questions()
            .cancel(
                &kr_protocol::question::QuestionCancelParams {
                    session_id: session_id(),
                    question_id: question.question_id,
                    expected_revision: question.revision,
                },
                question_clock(),
            )
            .expect("the question is withdrawn");
    }
}

impl Drop for World {
    fn drop(&mut self) {
        self.writes.abort();
    }
}

fn question_clock() -> kr_worker::questions::Now {
    kr_worker::questions::Now {
        utc_ms: kr_ipc::now_ms(),
        boot_ms: kr_ipc::clock::boot_elapsed_ms(),
    }
}

const START: &str = r#"{"id":1,"method":"thread/start","params":{}}"#;
const ASK: &str = r#"{"id":"approval-1","method":"item/commandExecution/requestApproval","params":{"itemId":"item-1","startedAtMs":0,"threadId":"thread-1","turnId":"turn-1"}}"#;
const RESOLVED: &str = r#"{"method":"serverRequest/resolved","params":{"threadId":"thread-1","requestId":"approval-1"}}"#;
const STARTED: &str =
    r#"{"method":"turn/started","params":{"threadId":"thread-1","turn":{"id":"turn-7"}}}"#;
const COMPLETED: &str =
    r#"{"method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-7"}}}"#;

/// KR-REQ-03.27: an approval the connector's table answers, and a binding interpreted, is the
/// application's state until it is settled; the state is back to the prompt's once the server
/// clears it. A reverse request nothing interpreted never is: it is an opaque request, not an
/// approval a person can decide.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_03_27_an_approval_is_the_applications_state_until_it_is_settled() {
    let world = World::new().await;
    world.shows(Some(ApplicationState::ShellReady)).await;

    // The opaque request first, and then a question whose state is waited for: the producer reads
    // the broker whenever it is woken, so by the time it has shown the question it has read the
    // opaque request too.
    world
        .service
        .broker()
        .forward_native(
            world.connection,
            br#"{"id":"opaque-1","method":"fs/write_text_file","params":{}}"#,
            NOW,
        )
        .expect("the request is recorded");
    let question = world.ask("req-1");
    world.shows(Some(ApplicationState::AwaitingInput)).await;
    world.withdraw(&question);
    world.shows(Some(ApplicationState::ShellReady)).await;

    world.server_says(ASK).await;
    world.shows(Some(ApplicationState::AwaitingApproval)).await;
    world.server_says(RESOLVED).await;
    world.shows(Some(ApplicationState::ShellReady)).await;
}

/// KR-REQ-03.27: an open question is the application's state until it is answered, cancelled or
/// expired, with nothing but the question ledger having changed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_03_27_an_open_question_is_the_applications_state_until_it_is_withdrawn() {
    let world = World::new().await;
    let question = world.ask("req-1");
    world.shows(Some(ApplicationState::AwaitingInput)).await;
    world.withdraw(&question);
    world.shows(Some(ApplicationState::ShellReady)).await;
}

/// KR-REQ-03.27: a turn the connector's table names is the application's state until it ends; an
/// open question outranks it and an approval outranks both, and each gives way to the next.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_03_27_a_running_turn_is_busy_and_gives_way_to_what_waits_for_a_person() {
    let mut world = World::new().await;
    world.terminal_selects("thread-1").await;
    world.shows(Some(ApplicationState::ShellReady)).await;

    world.server_says(STARTED).await;
    world.shows(Some(ApplicationState::AgentBusy)).await;

    let question = world.ask("req-1");
    world.shows(Some(ApplicationState::AwaitingInput)).await;
    world.server_says(ASK).await;
    world.shows(Some(ApplicationState::AwaitingApproval)).await;

    world.server_says(RESOLVED).await;
    world.shows(Some(ApplicationState::AwaitingInput)).await;
    world.withdraw(&question);
    world.shows(Some(ApplicationState::AgentBusy)).await;

    world.server_says(COMPLETED).await;
    world.shows(Some(ApplicationState::ShellReady)).await;
}

/// KR-REQ-03.27: a session that has closed describes nothing, and nothing the worker learns
/// afterwards describes it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_03_27_a_closed_session_describes_nothing() {
    let world = World::new().await;
    let _question = world.ask("req-1");
    world.shows(Some(ApplicationState::AwaitingInput)).await;
    world
        .service
        .application()
        .observe_holder(kr_worker::application::Holder::Program(Some(
            "claude".to_owned(),
        )));
    world.names(Some("claude")).await;

    let (_, gate) = world
        .runtime
        .close(kr_protocol::session::ClosureReason::CloseRequested);
    gate.release();
    tokio::time::timeout(LIVENESS, world.runtime.wait_closed())
        .await
        .expect("the session closes");
    world.shows(None).await;
    world.names(None).await;

    world
        .service
        .application()
        .observe_evidence(kr_worker::application::Evidence {
            approval_pending: true,
            ..kr_worker::application::Evidence::default()
        });
    world
        .service
        .application()
        .observe_holder(kr_worker::application::Holder::Program(Some(
            "other".to_owned(),
        )));
    assert_eq!(
        world.state(),
        None,
        "a session that closed shows no state however the worker's evidence changes"
    );
    assert_eq!(
        world.name(),
        None,
        "and names no application whatever holds its terminal"
    );
}
