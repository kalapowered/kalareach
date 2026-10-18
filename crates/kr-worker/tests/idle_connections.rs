//! What a session's connections make its host do while nobody is using them (KR-PERF-003).
//!
//! Twenty idle sessions have to cost less than one per cent of a core between them. The control
//! daemon holds three connections to each of them whether or not anybody is looking at the
//! session, and a person can leave a terminal attached to one for days. A clock on every one of
//! those connections woke each host several times in ten seconds for nothing. The one reader of a
//! local stream that waits on silence is a process bridge's invoker, so the connection a bridge's
//! helper makes is sent a keepalive and no other connection is.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-PERF-003 | the control daemon's three connections to a session, a command line that has attached nothing and one that has attached a terminal are sent no keepalive, while a connection a process bridge made is sent them |
//!
//! This uses a real worker service on its real endpoint and a real shell. The keepalive's period
//! is shortened so that the case sees several of them, and what it waits for is a count of the
//! keepalives the bridge's connection has been sent, not a length of time: by then every other
//! connection that was opened before it has had the same number of chances to be sent one.

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::framed::{FrameReader, FrameWriter};
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::actor::ActorIngress;
use kr_protocol::envelope::{ActionTarget, ControlEvent, ControlFrame};
use kr_protocol::hello::{PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, BuildId, ControllerGeneration, EnvironmentId, SessionEpoch, SessionId,
};
use kr_protocol::local::{BridgeOrigin, ControllerConnectionRole, LocalClientKind};
use kr_protocol::method::Method;
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

/// How often the worker under test sends a connection that holds an attachment a keepalive.
const PERIOD: Duration = Duration::from_millis(100);

/// How many keepalives the bridge's connection is waited for before the others are looked at.
const BEATS: usize = 8;

/// The longest the bridge's connection is waited on for a single keepalive. A bound on a failure,
/// not a duration the case depends on.
const BEAT_BOUND: Duration = Duration::from_secs(60);

/// How long a connection is read for a keepalive that is already waiting in it. Everything the
/// worker has written to it is there to be read at once, so this is the time to find that none is
/// there and not a wait for anything to happen.
const LOOK: Duration = Duration::from_millis(300);

struct Host {
    _temp: kr_ipc::testing::TempHost,
    session_id: SessionId,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

async fn host() -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
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
    let store =
        kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
    let controller = Arc::new(
        ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity"),
    );
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script("sleep 300"),
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
                journal_path: Some(environment.journal_database(session_id)),
                build_id: build(),
            },
        )
        .expect("a worker service")
        .with_keepalive(PERIOD),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));
    Host {
        _temp: temp,
        session_id,
        environment_id,
        endpoint,
        controller,
        boot,
    }
}

/// A connection as its two ends are read and written raw, because the ordinary client absorbs a
/// keepalive on its caller's behalf and this case is about whether the worker sends one.
struct Raw {
    reader: FrameReader,
    /// Held so the connection stays open: a writer that is dropped closes it.
    _writer: FrameWriter,
}

impl Raw {
    fn of(mut client: LocalClient) -> Self {
        // What the host pushed while a call of this client's was outstanding is the client's to
        // collect before it is split.
        while client.take_held().is_some() {}
        let (reader, writer, _acknowledgement) = client.into_halves();
        Self {
            reader,
            _writer: writer,
        }
    }

    /// Reads the next keepalive, whatever else arrives first.
    async fn keepalive(&mut self) {
        tokio::time::timeout(BEAT_BOUND, async {
            loop {
                let frame: ControlFrame = self
                    .reader
                    .read_message()
                    .await
                    .expect("the worker keeps the connection open");
                if matches!(frame, ControlFrame::Event(ControlEvent::Keepalive)) {
                    return;
                }
            }
        })
        .await
        .expect("a bridge's connection is sent a keepalive");
    }

    /// Whether a keepalive is waiting in this connection, or arrives while it is looked at.
    async fn holds_a_keepalive(&mut self) -> bool {
        tokio::time::timeout(LOOK, async {
            loop {
                let frame: ControlFrame = self
                    .reader
                    .read_message()
                    .await
                    .expect("the worker keeps the connection open");
                if matches!(frame, ControlFrame::Event(ControlEvent::Keepalive)) {
                    return;
                }
            }
        })
        .await
        .is_ok()
    }
}

/// A connection of the daemon's, declared for `role` and speaking for generation one.
async fn daemon(host: &Host, role: ControllerConnectionRole) -> Raw {
    let mut client = LocalClient::connect_receiving(
        &host.endpoint,
        LocalClientKind::Controller,
        build(),
        ReceiveLimits::default(),
    )
    .await
    .expect("connects");
    client
        .writer()
        .write_message(&ControlFrame::ControllerRole(role))
        .await
        .expect("declares the role");
    match client.recv().await.expect("the worker answers") {
        ControlFrame::ControllerRole(declared) => assert_eq!(declared, role),
        other => panic!("the worker answered {other:?}"),
    }
    let identity = Arc::clone(&host.controller);
    let boot = host.boot.clone();
    client
        .present_generation(move |nonce| {
            identity
                .generation_token(ControllerGeneration::new(1), &boot, nonce)
                .map_err(kr_ipc::IpcError::from)
        })
        .await
        .expect("the worker accepts the generation");
    Raw::of(client)
}

async fn cli(host: &Host) -> LocalClient {
    LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects")
}

/// A connection a process bridge's helper made for an invoker in another environment.
async fn bridged(host: &Host) -> LocalClient {
    LocalClient::connect_for_bridge(
        &host.endpoint,
        build(),
        BridgeOrigin {
            environment_id: host.environment_id,
            ingress: ActorIngress::LocalIpc,
            clipboard_writes: true,
        },
    )
    .await
    .expect("connects")
}

/// Attaches a terminal to the session over `client`, and returns it raw.
async fn attached(host: &Host, mut client: LocalClient) -> Raw {
    let mut requested = CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    let _attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                environment_id: host.environment_id,
                session_id: Nullable::some(host.session_id),
                session_epoch: Nullable::some(SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &kr_protocol::attachment::SessionAttachParams {
                session_id: host.session_id,
                mode: kr_protocol::attachment::AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested,
            },
        )
        .await
        .expect("reaches the worker")
        .expect("the terminal attaches")
        .to_typed()
        .expect("decodes");
    Raw::of(client)
}

/// KR-PERF-003: a connection a process bridge made is sent a keepalive, and no other connection is.
/// The control daemon's three connections to a session, a command line that has attached nothing
/// and one that has a terminal attached are open before the bridge's connection is, so it being
/// sent its eighth keepalive means each of them has had the same chances to be sent eight.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_perf_003_only_a_bridges_connection_is_sent_a_keepalive() {
    let host = host().await;
    let mut idle = vec![
        (
            "the daemon's authority connection",
            daemon(&host, ControllerConnectionRole::Authority).await,
        ),
        (
            "the daemon's attention connection",
            daemon(&host, ControllerConnectionRole::Attention).await,
        ),
        (
            "the daemon's descriptions connection",
            daemon(&host, ControllerConnectionRole::Descriptions).await,
        ),
        (
            "a command line that has attached nothing",
            Raw::of(cli(&host).await),
        ),
        (
            "a command line with a terminal attached",
            attached(&host, cli(&host).await).await,
        ),
    ];
    let mut bridge = Raw::of(bridged(&host).await);
    for _ in 0..BEATS {
        bridge.keepalive().await;
    }
    for (what, connection) in &mut idle {
        assert!(
            !connection.holds_a_keepalive().await,
            "{what} was not made by a process bridge, so it is sent no keepalive"
        );
    }
}
