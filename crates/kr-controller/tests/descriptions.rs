//! Session descriptions through the control daemon: a real daemon, real workers it adopts, and the
//! stub description process the daemon starts, over its real pipes.
//!
//! The daemon is started the way a host starts one, on the loopback network, and finds each worker
//! the way a daemon that restarted finds the workers it left running: by the registry's row, the
//! published descriptor and a challenge. A worker is the worker's own service in this process, with
//! its journal, its spool and its shell. The stub is a copy of `kr-stub-inference` on the internal
//! disk, started once so the operating system's check of a new executable is paid before anything
//! is timed; it serves the process's own code over a model that answers from the prompt. What each
//! test asserts is read back from what the daemon answers (`session.describe`, the attention
//! inbox, `session.read`) and from the host's own figures.
//!
//! Nothing here waits for a measured delay. A test waits for a condition (a description shown, a
//! pause named, a process marked) and fails at a bound that is generous for a machine under load;
//! what must not happen is shown by a later event that would have been preceded by it.

mod net_support;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kr_controller::registry::{Registry, WorkerRecord};
use kr_controller::service::Controller;
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::open_store_in;
use kr_describe::budget::GIB;
use kr_describe::resource::{HostConditions, PowerSource, ThermalState};
use kr_describe::testing::{
    CATALOGUE_VARIABLE, Output, SCRIPT_VARIABLE, STARTED_PREFIX, Script, TestAsset, TestCatalogue,
    TestProfile,
};
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::attention::{AttentionItem, AttentionReadParams, AttentionReadResult};
use kr_protocol::describe::{
    DescriptionDownload, DescriptionDownloadAction, DescriptionDownloadParams,
    DescriptionFreshness, DescriptionPause, DescriptionState, LabelSource, SessionDescribeParams,
    SessionDescribeResult,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, AttachmentId, AuthorityRevision, BuildId, ControllerGeneration, EnvironmentId,
    RequestId, SessionEpoch, SessionId,
};
use kr_protocol::method::Method;
use kr_protocol::privacy::{PrivacyReport, PrivacySetParams};
use kr_protocol::root::{CwdRevision, PromptGeneration, RootCommandBlockParams};
use kr_protocol::scalars::{DurationMs, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::session::{Dimensions, DisplayNumber, SessionState, ShellMode};
use kr_protocol::worker::WorkerDescriptor;
use kr_worker::fence::{CommandHook, Effects, Step};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

use net_support::Host;

/// How long a test waits for something the daemon or a worker has to do.
const PATIENCE: Duration = Duration::from_secs(90);

/// The view every worker's one attachment is, which holds the input lease.
const VIEW: AttachmentId = AttachmentId::new(Uuid::from_bytes([5; 16]));

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn now() -> TimestampMs {
    kr_ipc::now_ms()
}

/// Waits until `holds` says it does, or the patience runs out.
async fn until(what: &str, mut holds: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while !holds() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} did not happen in time"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ---------------------------------------------------------------------------------------------
// A worker in this process
// ---------------------------------------------------------------------------------------------

/// A worker for one session, in this process, on an environment tree a daemon of it serves.
struct Worker {
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    epoch: u64,
    sequence: u64,
    _view: kr_worker::output::OutputStream,
    _service: Arc<WorkerService>,
}

impl Worker {
    /// Starts a worker for one session whose shell prints a terminal query and then reads its
    /// input, and records it the way a daemon records one it adopts: a registry row and a published
    /// descriptor. No daemon may be running on the tree while this runs.
    async fn start(tree: &kr_ipc::testing::TempHost, display: u64) -> Self {
        let environment = tree.environment();
        let environment_id = tree.environment_id();
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let controller_key = {
            let store = open_store_in(&environment.secrets_dir()).expect("a secret store");
            *ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                .expect("the daemon's identity")
                .public_key()
        };
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let display_number = DisplayNumber::new(display);
        let process =
            kr_ipc::identity::current_process_start_identity().expect("a process identity");
        let identity = Arc::new(
            WorkerIdentity::generate(
                session_id,
                SessionEpoch::V1,
                boot.clone(),
                process.clone(),
                PROTOCOL_VERSION,
            )
            .expect("a session key"),
        );
        let journal_path = environment.journal_database(session_id);
        if let Some(parent) = journal_path.parent() {
            std::fs::create_dir_all(parent).expect("the journal directory");
        }
        let config = SessionConfig {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number,
            shell: kr_worker::testing::posix_script("printf '\\033[c\\033[6n'; exec cat"),
            shell_mode: ShellMode::NativeCompat,
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: DesktopBinding::none(),
            dimensions: Dimensions::new(80, 24),
            journal_path: Some(journal_path.clone()),
            spool_directory: Some(environment.session_spool(session_id)),
            worker_endpoint: None,
            send_queue_bytes: 1024 * 1024,
            resident_bytes: 64 * 1024,
            time: kr_worker::action::time::TimeSources::system(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
        };
        let mut session = Session::open(config).expect("opens the session");
        session.launch().expect("launches the shell");
        let mut requested = kr_protocol::scalars::CanonicalSet::new();
        for capability in [
            kr_protocol::attachment::AttachmentCapability::ObserveTerminal,
            kr_protocol::attachment::AttachmentCapability::Input,
            kr_protocol::attachment::AttachmentCapability::Geometry,
        ] {
            requested.insert(capability);
        }
        let params = kr_protocol::attachment::SessionAttachParams {
            session_id,
            mode: kr_protocol::attachment::AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(Dimensions::new(80, 24)),
            terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
            requested: requested.clone(),
        };
        session.attach(&params, requested, VIEW).expect("attaches");
        let view = session.subscribe(VIEW).expect("subscribes");
        session
            .acquire_input(
                VIEW,
                kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid()),
                None,
            )
            .expect("takes the lease");
        let epoch = session.lease().epoch.get();
        let runtime = Arc::new(
            SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
                .expect("starts the runtime"),
        );
        let endpoint = environment
            .worker_endpoint(display_number)
            .expect("an endpoint");
        let listener = Listener::bind(&endpoint).expect("binds the endpoint");
        let public_key = *identity.public_key();
        let service = Arc::new(
            WorkerService::new(
                Arc::clone(&runtime),
                identity,
                endpoint.clone(),
                ServiceBinding {
                    environment_id,
                    boot_identity: boot.clone(),
                    controller_public_key: controller_key,
                    controller_generation: ControllerGeneration::new(1),
                    journal_path: Some(journal_path),
                    build_id: build(),
                },
            )
            .expect("a worker service"),
        );
        tokio::spawn(Arc::clone(&service).serve(listener));
        let mut registry =
            Registry::open(environment.registry_database(), environment_id).expect("the registry");
        registry
            .adopt_worker(
                &WorkerRecord {
                    session_id,
                    display_number,
                    public_key,
                    process_identity: process.clone(),
                    endpoint: endpoint.as_text(),
                    profile: WorkerProfile::HeadlessUser,
                    state: SessionState::Live,
                    acknowledged_revision: AuthorityRevision::new(0),
                },
                Some(&DesktopBinding::none()),
            )
            .expect("the worker is recorded");
        drop(registry);
        kr_ipc::descriptor::publish(
            &environment,
            &WorkerDescriptor {
                session_id,
                session_epoch: SessionEpoch::V1,
                environment_id,
                display_number,
                boot_identity: boot,
                process_start_identity: process,
                protocol_version: PROTOCOL_VERSION,
                endpoint: endpoint.as_text(),
                worker_public_key: public_key,
                worker_profile: WorkerProfile::HeadlessUser,
                published_at_ms: now(),
            },
        )
        .expect("the worker's descriptor is published");
        Self {
            runtime,
            session_id,
            epoch,
            sequence: 0,
            _view: view,
            _service: service,
        }
    }

    /// Reports a command block to the session as the shell integration's hook does.
    fn report(&self, command: &str, cwd: &str, status: Option<u64>) {
        let block = RootCommandBlockParams {
            session_id: self.session_id,
            prompt_generation: PromptGeneration::new(1),
            command: command.to_owned(),
            started_at_ms: TimestampMs::new(1),
            duration_ms: Nullable(status.map(|_| DurationMs::new(1))),
            exit_status: Nullable(status.map(U64::new)),
            cwd: cwd.to_owned(),
            cwd_revision: CwdRevision::new(0),
        };
        let _ = self.runtime.session().apply_fence_effects(Effects {
            steps: vec![Step::CommandHook(
                RequestId::new(1),
                Box::new(CommandHook::Block(Box::new(block))),
            )],
            ..Effects::default()
        });
    }

    /// Types into the terminal as the view holding the lease does.
    fn type_in(&mut self, bytes: &[u8]) {
        self.runtime
            .session()
            .write_input(
                VIEW,
                self.epoch,
                self.sequence,
                bytes,
                None,
                std::time::Instant::now(),
            )
            .expect("the input is accepted");
        self.sequence += 1;
        self.runtime.flush_input();
    }

    /// Waits until the session's retained output carries `marker` `count` times: the terminal's
    /// own echo of what was typed, and the program's answer to it.
    async fn until_echoed(&self, marker: &str, count: usize) {
        let marker = marker.as_bytes();
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let mut seen = Vec::new();
            let mut cursor = 0_u64;
            loop {
                let page = self
                    .runtime
                    .session()
                    .history_page(cursor, 1024 * 1024)
                    .expect("reads the retained output");
                if page.bytes.as_slice().is_empty() {
                    break;
                }
                seen.extend_from_slice(page.bytes.as_slice());
                cursor = page.next_cursor.get();
            }
            if seen
                .windows(marker.len())
                .filter(|window| *window == marker)
                .count()
                >= count
            {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the typed input was not echoed in time"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// The facts revision the worker has reached, which only a fact moves.
    fn revision(&self, generation: u64) -> u64 {
        self._service
            .description_facts()
            .read(0, Some(generation))
            .facts
            .map_or(0, |facts| facts.revision.get())
    }
}

// ---------------------------------------------------------------------------------------------
// A daemon that adopts them, with the stub placed under it
// ---------------------------------------------------------------------------------------------

/// What a test asks of the daemon's description host.
struct Setup {
    /// What the stub does.
    script: Script,
    /// How many sessions there are.
    sessions: usize,
    /// What the host reads of its own machine.
    conditions: HostConditions,
    /// Whether the process is left running when the daemon's host stops.
    abandon: bool,
    /// The profiles the daemon and the process choose from, when a test needs its own.
    catalogue: Option<TestCatalogue>,
    /// Whether the model's files are on this host when the daemon starts.
    held: bool,
    /// The real description process in place of the stub, which then chooses from the profiles
    /// this build ships, and the files that are linked in as the model's.
    real: Option<Real>,
}

/// The real description process, and the files linked in place of the model's.
struct Real {
    program: PathBuf,
    files: Vec<(String, PathBuf)>,
}

impl Setup {
    fn new() -> Self {
        Self {
            script: Script::default(),
            sessions: 1,
            conditions: roomy(),
            abandon: false,
            catalogue: None,
            held: true,
            real: None,
        }
    }
}

/// What the default profile's one file holds.
const WEIGHTS: &[u8] = b"the weights of a tiny model";

/// The file's name.
const WEIGHTS_FILE: &str = "tiny.gguf";

fn roomy() -> HostConditions {
    HostConditions::measured(
        16 * GIB,
        12 * GIB,
        PowerSource::Mains,
        ThermalState::Nominal,
    )
}

/// The profiles the daemon may choose from here: one default that lists this build's target, so
/// the selection is made on every machine these tests run on.
fn catalogue() -> TestCatalogue {
    TestCatalogue::sign(&[TestProfile {
        profile_id: "tiny-default".to_owned(),
        revision: 1,
        candidate: false,
        targets: Some(vec![kr_describe::environment::build_target().to_owned()]),
        assets: vec![TestAsset {
            file_name: WEIGHTS_FILE.to_owned(),
            url: "http://127.0.0.1:1/tiny.gguf".to_owned(),
            bytes: WEIGHTS.to_vec(),
        }],
    }])
}

/// A catalogue whose one profile is at `revision` and whose one file `contents` is fetched from
/// `url`.
fn catalogue_at(revision: u64, url: String, contents: &[u8]) -> TestCatalogue {
    TestCatalogue::sign(&[TestProfile {
        profile_id: "tiny-default".to_owned(),
        revision,
        candidate: false,
        targets: Some(vec![kr_describe::environment::build_target().to_owned()]),
        assets: vec![TestAsset {
            file_name: WEIGHTS_FILE.to_owned(),
            url,
            bytes: contents.to_vec(),
        }],
    }])
}

// ---------------------------------------------------------------------------------------------
// A server the model's files are fetched from
// ---------------------------------------------------------------------------------------------

/// What the fixture answers a request for a path with.
#[derive(Clone, Debug)]
enum Reply {
    /// The whole body, with its length declared.
    Body(Vec<u8>),
    /// A length declared at `declared` bytes, and then as much of `body` as there is.
    Declares { declared: u64, body: Vec<u8> },
    /// No length declared, and `body` sent in chunks.
    Chunked(Vec<u8>),
    /// The whole length declared, half of the body sent, and then nothing until the client leaves.
    HalfThenHold(Vec<u8>),
    /// The request read and no answer, until the client leaves.
    Silent,
}

/// A local HTTP server that answers each path the way a test says, and records what was asked.
struct Fixture {
    address: std::net::SocketAddr,
    replies: Arc<Mutex<BTreeMap<String, Reply>>>,
    requests: Arc<Mutex<Vec<String>>>,
    half_sent: Arc<tokio::sync::Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a local port");
        let address = listener.local_addr().expect("its address");
        let replies = Arc::new(Mutex::new(BTreeMap::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let half_sent = Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn({
            let (replies, requests, half_sent) = (
                Arc::clone(&replies),
                Arc::clone(&requests),
                Arc::clone(&half_sent),
            );
            async move {
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(Self::serve(
                        stream,
                        Arc::clone(&replies),
                        Arc::clone(&requests),
                        Arc::clone(&half_sent),
                    ));
                }
            }
        });
        Self {
            address,
            replies,
            requests,
            half_sent,
            task,
        }
    }

    async fn serve(
        mut stream: tokio::net::TcpStream,
        replies: Arc<Mutex<BTreeMap<String, Reply>>>,
        requests: Arc<Mutex<Vec<String>>>,
        half_sent: Arc<tokio::sync::Notify>,
    ) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut seen = Vec::new();
        let mut chunk = [0_u8; 1024];
        while !seen.windows(4).any(|window| window == b"\r\n\r\n") {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => seen.extend_from_slice(&chunk[..read]),
            }
        }
        let text = String::from_utf8_lossy(&seen).into_owned();
        let path = text
            .lines()
            .next()
            .and_then(|line| line.split(' ').nth(1))
            .unwrap_or("/")
            .to_owned();
        requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(path.clone());
        let reply = replies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&path)
            .cloned();
        let ok = |length: u64| {
            format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n")
        };
        let _ = match reply {
            None => {
                stream
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
            }
            Some(Reply::Body(body)) => {
                stream
                    .write_all(ok(body.len() as u64).as_bytes())
                    .await
                    .ok();
                stream.write_all(&body).await
            }
            Some(Reply::Declares { declared, body }) => {
                stream.write_all(ok(declared).as_bytes()).await.ok();
                stream.write_all(&body).await
            }
            Some(Reply::Chunked(body)) => {
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .ok();
                for piece in body.chunks(8) {
                    stream
                        .write_all(format!("{:x}\r\n", piece.len()).as_bytes())
                        .await
                        .ok();
                    stream.write_all(piece).await.ok();
                    stream.write_all(b"\r\n").await.ok();
                }
                stream.write_all(b"0\r\n\r\n").await
            }
            Some(Reply::Silent) => {
                // Held until the client leaves: reading answers nothing but its end.
                let _ = stream.read(&mut chunk).await;
                return;
            }
            Some(Reply::HalfThenHold(body)) => {
                stream
                    .write_all(ok(body.len() as u64).as_bytes())
                    .await
                    .ok();
                stream.write_all(&body[..body.len() / 2]).await.ok();
                stream.flush().await.ok();
                half_sent.notify_one();
                // Held until the client leaves: reading answers nothing but its end.
                let _ = stream.read(&mut chunk).await;
                return;
            }
        };
        let _ = stream.shutdown().await;
    }

    /// Answers `path` with `reply` from now on.
    fn reply(&self, path: &str, reply: Reply) {
        self.replies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(path.to_owned(), reply);
    }

    /// The address a catalogue names for a file at `path`.
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    /// The host and port a fetch from here reaches, as setup shows it.
    fn source(&self) -> String {
        self.address.to_string()
    }

    /// Every path that has been asked for, in order.
    fn requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Waits until a reply of [`Reply::HalfThenHold`] has sent its half.
    async fn until_half_sent(&self) {
        tokio::time::timeout(PATIENCE, self.half_sent.notified())
            .await
            .expect("half of a body was sent in time");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A daemon with its workers, and the stub it starts.
struct Environment {
    host: Host,
    workers: Vec<Worker>,
    placed: kr_controller::describe::hooks::Placed,
    runtime_dir: PathBuf,
    state_dir: PathBuf,
    /// The profiles the daemon chooses from.
    catalogue: kr_describe::Catalogue,
}

impl Environment {
    async fn start(setup: Setup) -> Self {
        let owner = DeviceKeys::generate().expect("owner keys");
        let host = Host::start(&owner).await;
        let stopped = host.shut_down().await;
        let tree = stopped.tree();
        let state_dir = tree.environment().state_dir().to_path_buf();
        let runtime_dir = tree.environment().runtime_dir().to_path_buf();
        // The process, on the internal disk, started once so the operating system has checked it:
        // the stub, or the real one a run names.
        let program = tree.root().join("kr-stub-inference");
        let (source, selected, environment) = match &setup.real {
            Some(real) => (
                real.program.clone(),
                kr_describe::Catalogue::builtin().expect("the profiles this build ships"),
                Vec::new(),
            ),
            None => {
                let signed = setup.catalogue.unwrap_or_else(catalogue);
                let bundle = tree.root().join("catalogue.json");
                signed.write_to(&bundle);
                let mut script = setup.script;
                script.mark_start = true;
                script.mark_work = true;
                (
                    PathBuf::from(env!("CARGO_BIN_EXE_kr-stub-inference")),
                    signed.catalogue(),
                    vec![
                        (SCRIPT_VARIABLE.into(), script.to_env().into()),
                        (CATALOGUE_VARIABLE.into(), bundle.into()),
                    ],
                )
            }
        };
        kr_ipc::testing::place_and_start_once(&source, &program, &["--version"]);
        let placed = kr_controller::describe::hooks::place(
            &state_dir,
            program,
            environment,
            selected.clone(),
            setup.conditions,
            setup.abandon,
        );
        match (&setup.real, setup.held) {
            (Some(real), true) => {
                let files: Vec<(&str, &std::path::Path)> = real
                    .files
                    .iter()
                    .map(|(name, path)| (name.as_str(), path.as_path()))
                    .collect();
                kr_controller::describe::hooks::link_assets(&state_dir, &selected, &files);
            }
            (None, true) => kr_controller::describe::hooks::hold_assets(
                &state_dir,
                &selected,
                &[(WEIGHTS_FILE, WEIGHTS)],
            ),
            (_, false) => {}
        }
        let mut workers = Vec::new();
        for display in 1..=setup.sessions as u64 {
            workers.push(Worker::start(tree, display).await);
        }
        let settings = stopped.settings().clone();
        let host = stopped.start(settings).await;
        let environment = Self {
            host,
            workers,
            placed,
            runtime_dir,
            state_dir,
            catalogue: selected,
        };
        for worker in &environment.workers {
            environment.until_adopted(worker.session_id).await;
        }
        environment
    }

    fn controller(&self) -> &Arc<Controller> {
        self.host.controller()
    }

    fn environment_id(&self) -> EnvironmentId {
        self.host.environment_id
    }

    async fn until_adopted(&self, session_id: SessionId) {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let mut client = self.host.client().await;
            let read = client
                .request(
                    Method::SessionRead,
                    &kr_protocol::session::SessionReadParams { session_id },
                )
                .await
                .expect("the call reaches the daemon");
            if read.is_ok() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the daemon never reached the worker: {read:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Reads one session's name and description at the daemon's local socket.
    async fn describe(&self, session_id: SessionId) -> SessionDescribeResult {
        let mut client = self.host.client().await;
        client
            .request(
                Method::SessionDescribe,
                &SessionDescribeParams { session_id },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the session's name")
            .to_typed()
            .expect("decodes")
    }

    /// Reads the session until `holds` says it does, or the patience runs out.
    async fn describe_until(
        &self,
        what: &str,
        session_id: SessionId,
        holds: impl Fn(&SessionDescribeResult) -> bool,
    ) -> SessionDescribeResult {
        self.describe_within(PATIENCE, what, session_id, holds)
            .await
    }

    /// Reads the session until `holds` says it does, or `patience` runs out.
    async fn describe_within(
        &self,
        patience: Duration,
        what: &str,
        session_id: SessionId,
        holds: impl Fn(&SessionDescribeResult) -> bool,
    ) -> SessionDescribeResult {
        let deadline = tokio::time::Instant::now() + patience;
        loop {
            let described = self.describe(session_id).await;
            if holds(&described) {
                return described;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "{what} did not happen: {described:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// What the daemon's description host has done.
    fn figures(&self) -> kr_controller::describe::Figures {
        self.controller()
            .descriptions()
            .figures()
            .expect("the daemon runs the description host")
    }

    /// How many description processes have marked their start.
    fn stubs_started(&self) -> usize {
        std::fs::read_dir(&self.runtime_dir)
            .expect("the runtime directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(STARTED_PREFIX)
            })
            .count()
    }

    /// How many models stubs have loaded, as they marked it.
    fn loaded(&self) -> usize {
        std::fs::read_dir(&self.runtime_dir)
            .expect("the runtime directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(kr_describe::testing::LOADED_PREFIX)
            })
            .count()
    }

    /// Starts or cancels the fetch of the model's files at the daemon's local socket.
    async fn download(
        &self,
        action: DescriptionDownloadAction,
    ) -> kr_protocol::describe::DescriptionSetup {
        let mut client = self.host.client().await;
        client
            .mutate(
                Method::DescriptionDownload,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(self.environment_id()),
                &DescriptionDownloadParams { action },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the fetch is started or cancelled")
            .to_typed()
            .expect("decodes")
    }

    /// Reads what setup shows until `holds` says it does, or the patience runs out.
    async fn setup_until(
        &self,
        what: &str,
        holds: impl Fn(&kr_protocol::describe::DescriptionSetup) -> bool,
    ) -> kr_protocol::describe::DescriptionSetup {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let shown = self.setup().await;
            if holds(&shown) {
                return shown;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "{what} did not happen: {shown:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Where the daemon keeps the files of the profile it selected.
    fn files(&self) -> PathBuf {
        kr_controller::describe::hooks::assets_directory(&self.state_dir, &self.catalogue)
    }

    /// The names in the files' directory that are still being fetched.
    fn partials(&self) -> Vec<String> {
        std::fs::read_dir(self.files())
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .filter(|name| name.ends_with(".partial"))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether the marker that says the files are held is on disk.
    fn marker(&self) -> bool {
        self.files().join("held.json").exists()
    }

    /// Stops the daemon and starts another on the same tree, which finds the workers still running.
    async fn restart(self) -> Self {
        let Self {
            host,
            workers,
            placed,
            runtime_dir,
            state_dir,
            catalogue,
        } = self;
        let host = host.restart().await;
        let environment = Self {
            host,
            workers,
            placed,
            runtime_dir,
            state_dir,
            catalogue,
        };
        for worker in &environment.workers {
            environment.until_adopted(worker.session_id).await;
        }
        environment
    }

    /// Stops the daemon and starts another on the same tree with other profiles to choose from,
    /// which finds the workers still running and the stub told of the same profiles.
    async fn restart_with(self, script: Script, signed: TestCatalogue, abandon: bool) -> Self {
        let Self {
            host,
            workers,
            placed,
            runtime_dir,
            state_dir,
            catalogue: _,
        } = self;
        let stopped = host.shut_down().await;
        let tree = stopped.tree();
        let stub = tree.root().join("kr-stub-inference");
        let bundle = tree.root().join("catalogue.json");
        signed.write_to(&bundle);
        let mut script = script;
        script.mark_start = true;
        script.mark_work = true;
        // The new placement replaces the old one under the same state directory.
        drop(placed);
        let placed = kr_controller::describe::hooks::place(
            &state_dir,
            stub,
            vec![
                (SCRIPT_VARIABLE.into(), script.to_env().into()),
                (CATALOGUE_VARIABLE.into(), bundle.into()),
            ],
            signed.catalogue(),
            roomy(),
            abandon,
        );
        let settings = stopped.settings().clone();
        let host = stopped.start(settings).await;
        let environment = Self {
            host,
            workers,
            placed,
            runtime_dir,
            state_dir,
            catalogue: signed.catalogue(),
        };
        for worker in &environment.workers {
            environment.until_adopted(worker.session_id).await;
        }
        environment
    }

    /// Makes the store refuse to remove generated descriptions, as a store that cannot be written
    /// would, by taking their table away under its name; and gives it back.
    fn set_removal_refused(&self, refused: bool) {
        let connection = rusqlite::Connection::open(self.state_dir.join("descriptions.sqlite3"))
            .expect("the store's file opens");
        let (from, to) = if refused {
            ("describe_generated", "describe_generated_held")
        } else {
            ("describe_generated_held", "describe_generated")
        };
        connection
            .execute_batch(&format!("ALTER TABLE {from} RENAME TO {to}"))
            .expect("the table is renamed");
    }

    /// Whether a process is running, as the operating system says.
    fn alive(pid: u32) -> bool {
        matches!(
            kr_ipc::identity::query_process(pid),
            kr_ipc::identity::ProcessQuery::Present(_)
        )
    }

    /// Ends a process by its identifier, as the platform does it.
    fn end(pid: u32) {
        #[cfg(unix)]
        {
            let pid = rustix::process::Pid::from_raw(i32::try_from(pid).expect("a pid in range"))
                .expect("a process identifier");
            rustix::process::kill_process(pid, rustix::process::Signal::TERM)
                .expect("the process is signalled");
        }
        #[cfg(windows)]
        {
            let ended = std::process::Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/F"])
                .status()
                .expect("the process is ended");
            assert!(ended.success());
        }
    }

    /// Whether a stub has begun a piece of work of this kind.
    fn began(&self, kind: &str) -> bool {
        let prefix = format!("{}{kind}-", kr_describe::testing::BEGAN_PREFIX);
        std::fs::read_dir(&self.runtime_dir)
            .expect("the runtime directory")
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
    }

    /// Turns privacy mode on or off at the daemon's local socket.
    async fn privacy(&self, enabled: bool) -> PrivacyReport {
        let mut client = self.host.client().await;
        client
            .mutate(
                Method::PrivacySet,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(self.environment_id()),
                &PrivacySetParams { enabled },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("privacy mode is set")
            .to_typed()
            .expect("decodes")
    }

    /// Reads what setup shows at the daemon's local socket.
    async fn setup(&self) -> kr_protocol::describe::DescriptionSetup {
        let mut client = self.host.client().await;
        client
            .request(
                Method::DescriptionSetup,
                &kr_protocol::describe::DescriptionSetupParams {},
            )
            .await
            .expect("the call reaches the daemon")
            .expect("setup reads")
            .to_typed()
            .expect("decodes")
    }

    /// Changes the owner's settings at the daemon's local socket.
    async fn configure(
        &self,
        enabled: Option<bool>,
        on_battery: Option<bool>,
    ) -> kr_protocol::describe::DescriptionSetup {
        let mut client = self.host.client().await;
        client
            .mutate(
                Method::DescriptionConfigure,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(self.environment_id()),
                &kr_protocol::describe::DescriptionConfigureParams {
                    enabled: Nullable(enabled),
                    on_battery: Nullable(on_battery),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the settings are changed")
            .to_typed()
            .expect("decodes")
    }

    /// Reads privacy mode's report at the daemon's local socket.
    async fn privacy_status(&self) -> PrivacyReport {
        let mut client = self.host.client().await;
        client
            .request(
                Method::PrivacyStatus,
                &kr_protocol::privacy::PrivacyStatusParams {},
            )
            .await
            .expect("the call reaches the daemon")
            .expect("privacy mode's report")
            .to_typed()
            .expect("decodes")
    }

    /// Waits until privacy mode's last change has finished taking effect.
    async fn until_privacy_settled(&self) {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let mut client = self.host.client().await;
            let report: PrivacyReport = client
                .request(
                    Method::PrivacyStatus,
                    &kr_protocol::privacy::PrivacyStatusParams {},
                )
                .await
                .expect("the call reaches the daemon")
                .expect("privacy mode's report")
                .to_typed()
                .expect("decodes");
            if matches!(
                report.completion,
                kr_protocol::privacy::PrivacyCompletion::Complete
            ) {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "privacy mode's change did not finish: {report:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Reads the owner's inbox at the daemon's local socket.
    async fn inbox(&self) -> Vec<AttentionItem> {
        let mut client = self.host.client().await;
        let read: AttentionReadResult = client
            .request(
                Method::AttentionRead,
                &AttentionReadParams {
                    session_id: Nullable::null(),
                    include_acknowledged: true,
                    max_items: U64::new(50),
                    after: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the inbox reads")
            .to_typed()
            .expect("decodes");
        read.items
    }

    /// Reads one session at the daemon's local socket.
    async fn state_of(&self, session_id: SessionId) -> SessionState {
        let mut client = self.host.client().await;
        let read: kr_protocol::session::SessionReadResult = client
            .request(
                Method::SessionRead,
                &kr_protocol::session::SessionReadParams { session_id },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the session reads")
            .to_typed()
            .expect("decodes");
        read.session.state
    }

    async fn stop(self) {
        self.host.stop().await;
    }
}

// ---------------------------------------------------------------------------------------------
// The rows
// ---------------------------------------------------------------------------------------------

/// KR-REQ-01.14, KR-REQ-22.05: a working-directory change publishes a title, and keystrokes, a
/// resize and a terminal query make no page and no job. After the first description, input of
/// every kind goes in, and then a change that does produce a job is described: when that is
/// published the host has run exactly two jobs, so the input made none, and its facts moved the
/// revision of none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_directory_change_publishes_a_title_and_input_makes_no_page_and_no_job() {
    let mut environment = Environment::start(Setup::new()).await;
    let session_id = environment.workers[0].session_id;
    let first = environment.describe(session_id).await;
    assert_eq!(
        first.source,
        LabelSource::Metadata,
        "nothing has happened yet"
    );

    environment.workers[0].report("cargo test", "/home/a/kalareach", None);
    let described = environment
        .describe_until("a generated description", session_id, |described| {
            described.source == LabelSource::Generated
        })
        .await;
    assert!(described.activity_text.0.is_some(), "{described:?}");
    assert_eq!(
        described
            .provenance
            .0
            .as_ref()
            .map(|provenance| provenance.profile_id.as_str()),
        Some("tiny-default")
    );
    assert_eq!(described.state, DescriptionState::Resident);
    assert_eq!(described.paused.0, None);
    assert_eq!(environment.figures().jobs.published, 1);
    assert!(
        environment.figures().gated,
        "every publication is held under privacy mode's admission"
    );

    // Keystrokes, a resize and a bracketed paste: the terminal's own answers to its query went in
    // as the session started. None of them reaches the facts.
    let revision = environment.workers[0].revision(0);
    environment.workers[0].type_in(b"echo hello\n");
    environment.workers[0].type_in(b"\x1b[200~pasted\x1b[201~");
    {
        let mut session = environment.workers[0].runtime.session();
        session.configure(VIEW, true).expect("claims the geometry");
        let epoch = session.geometry().epoch.get();
        session
            .resize(VIEW, Dimensions::new(100, 30), epoch)
            .expect("the owner resizes");
    }
    // The shell has read the input once its terminal has echoed the line back and the program has
    // answered it: only then is "no fact moved" a statement about the input.
    environment.workers[0].until_echoed("hello", 2).await;
    assert_eq!(
        environment.workers[0].revision(0),
        revision,
        "no input moved a fact"
    );

    // A change that does make a job: when it is published, the host has run two jobs and no more.
    environment.workers[0].report("make", "/home/a/other", None);
    environment
        .describe_until("the second description", session_id, |described| {
            described
                .activity_text
                .0
                .as_ref()
                .is_some_and(|_| environment.figures().jobs.published >= 2)
        })
        .await;
    assert_eq!(
        environment.figures().jobs.published,
        2,
        "the input made no job"
    );
    assert_eq!(environment.figures().started, 1, "one process served both");
    environment.stop().await;
}

/// KR-REQ-01.14, KR-REQ-22.05: with the stub stopped in the middle of a job, input, a query and a
/// resize still answer, and so do the daemon's reads of the session. The control is the same
/// reads with nothing in flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_a_job_stopped_in_the_process_input_queries_and_resize_still_answer() {
    let mut environment = Environment::start(Setup {
        script: Script {
            generate_until_cancelled: true,
            ..Script::default()
        },
        ..Setup::new()
    })
    .await;
    let session_id = environment.workers[0].session_id;
    // The control, with nothing in flight.
    assert_eq!(environment.state_of(session_id).await, SessionState::Live);
    environment.describe(session_id).await;

    environment.workers[0].report("cargo build", "/home/a/kalareach", None);
    until("a job in the process", || {
        environment.began("job") && environment.figures().in_flight == 1
    })
    .await;
    environment.workers[0].type_in(b"echo still typing\n");
    {
        let mut session = environment.workers[0].runtime.session();
        session.configure(VIEW, true).expect("claims the geometry");
        let epoch = session.geometry().epoch.get();
        session
            .resize(VIEW, Dimensions::new(90, 28), epoch)
            .expect("the owner resizes");
        assert_eq!(session.geometry().dimensions, Dimensions::new(90, 28));
    }
    // The input was delivered while the job was stopped: the terminal echoed the line, and the
    // program answered it. Terminal queries have no path to the facts or the job, which the
    // worker's own suite exercises with the shell's queries in play.
    environment.workers[0].until_echoed("still typing", 2).await;
    assert_eq!(environment.state_of(session_id).await, SessionState::Live);
    let described = environment.describe(session_id).await;
    assert_eq!(
        described.source,
        LabelSource::Metadata,
        "the job has not ended"
    );
    assert_eq!(
        environment.figures().in_flight,
        1,
        "and it is still in the process"
    );
    environment.stop().await;
}

/// KR-REQ-22.03: twenty sessions are described by one process holding one mapping. The control is
/// one session, which shows the same figures.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn twenty_sessions_are_served_by_one_process_with_one_mapping() {
    let environment = Environment::start(Setup {
        sessions: 20,
        ..Setup::new()
    })
    .await;
    for (number, worker) in environment.workers.iter().enumerate() {
        worker.report("ls", &format!("/home/a/project-{number}"), None);
    }
    for worker in &environment.workers {
        environment
            .describe_until("every session described", worker.session_id, |described| {
                described.source == LabelSource::Generated
            })
            .await;
    }
    let figures = environment.figures();
    assert_eq!(figures.jobs.published, 20);
    assert_eq!(figures.started, 1, "one process");
    assert_eq!(figures.mapped, 1, "one mapping");
    assert_eq!(
        environment.stubs_started(),
        1,
        "and the stub marked one start"
    );
    environment.stop().await;
}

/// KR-REQ-22.20: a stub that claims passed tests and an approval is shown as generated, and
/// nothing about the session's state, its attention inbox or its review moves because of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn text_that_claims_a_pass_or_an_approval_is_labelled_generated_and_changes_nothing() {
    let environment = Environment::start(Setup {
        script: Script {
            output: Output::Claims,
            ..Script::default()
        },
        ..Setup::new()
    })
    .await;
    let session_id = environment.workers[0].session_id;
    let inbox_before = environment.inbox().await;
    let state_before = environment.state_of(session_id).await;
    environment.workers[0].report("cargo test", "/home/a/kalareach", None);
    let described = environment
        .describe_until("the claim shown", session_id, |described| {
            described.source == LabelSource::Generated
        })
        .await;
    assert!(
        described.title.to_lowercase().contains("all tests passed"),
        "{described:?}"
    );
    assert_eq!(environment.state_of(session_id).await, state_before);
    assert_eq!(
        environment.inbox().await.len(),
        inbox_before.len(),
        "no attention item, no review, no approval came of it"
    );
    environment.stop().await;
}

/// KR-REQ-22.07: pressure pauses inference and says why, and a title is still shown; no process is
/// started while it lasts, and when the pressure goes the same queue is described. Bad output is
/// refused and the session keeps the title it had.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pressure_and_bad_output_never_replace_a_title_and_describe_says_why() {
    let on_battery = HostConditions::measured(
        16 * GIB,
        12 * GIB,
        PowerSource::Battery,
        ThermalState::Nominal,
    );
    let environment = Environment::start(Setup {
        conditions: on_battery,
        ..Setup::new()
    })
    .await;
    let session_id = environment.workers[0].session_id;
    environment.workers[0].report("make", "/home/a/kalareach", None);
    let paused = environment
        .describe_until(
            "the battery's reason and the job waiting",
            session_id,
            |described| {
                described.paused.0 == Some(DescriptionPause::Battery)
                    && described.queued_age_ms.0.is_some()
            },
        )
        .await;
    assert_eq!(paused.state, DescriptionState::ResourcePaused);
    assert_eq!(
        paused.source,
        LabelSource::Metadata,
        "the title is still shown"
    );
    // KR-REQ-22.14: what a client is shown while the job waits: how long it has waited, and the
    // cadence the host is running at, which is not a promise about this session.
    assert!(paused.queued_age_ms.0.is_some(), "{paused:?}");
    assert!(paused.cadence_ms.get() > 0);
    assert_eq!(environment.figures().started, 0, "no process while paused");
    assert_eq!(environment.stubs_started(), 0);

    // The control: the pressure goes, and the same queue is described.
    environment.placed.set_conditions(roomy());
    environment.controller().descriptions().wake();
    environment
        .describe_until("the description after the pause", session_id, |described| {
            described.source == LabelSource::Generated
        })
        .await;
    assert_eq!(environment.figures().started, 1);
    environment.stop().await;

    // Bad output: refused, counted, and the session keeps the title it had.
    let environment = Environment::start(Setup {
        script: Script {
            output: Output::Malformed,
            ..Script::default()
        },
        ..Setup::new()
    })
    .await;
    let session_id = environment.workers[0].session_id;
    environment.workers[0].report("make", "/home/a/kalareach", None);
    until("the output refused", || {
        environment.figures().jobs.refused >= 1
    })
    .await;
    let described = environment.describe(session_id).await;
    assert_eq!(described.source, LabelSource::Metadata);
    assert_eq!(described.freshness, DescriptionFreshness::None);
    environment.stop().await;
}

/// KR-REQ-24.11, KR-REQ-22.05: privacy mode removes the generated description and shows the
/// metadata title at once, nothing captured while it is on is described, and turning it off lets
/// the session be described again under the new generation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn privacy_mode_removes_the_description_and_describes_nothing_captured_while_it_is_on() {
    let environment = Environment::start(Setup::new()).await;
    let session_id = environment.workers[0].session_id;
    environment.workers[0].report("make", "/home/a/kalareach", None);
    environment
        .describe_until("the first description", session_id, |described| {
            described.source == LabelSource::Generated
        })
        .await;
    assert_eq!(environment.figures().jobs.published, 1);

    let report = environment.privacy(true).await;
    assert!(report.enabled);
    environment.until_privacy_settled().await;
    let private = environment.describe(session_id).await;
    assert_eq!(
        private.source,
        LabelSource::Metadata,
        "nothing generated is shown"
    );

    // Captured while private: the worker records nothing, so there is nothing to describe.
    environment.workers[0].report("secret", "/home/a/while-private", None);
    // Turned off: a fresh change is described under the new generation, and the one from while
    // private never is.
    environment.privacy(false).await;
    environment.until_privacy_settled().await;
    environment.workers[0].report("make", "/home/a/after", None);
    environment
        .describe_until(
            "a description after privacy mode",
            session_id,
            |described| described.source == LabelSource::Generated,
        )
        .await;
    assert_eq!(
        environment.figures().jobs.published,
        2,
        "one before privacy mode and one after, none for what was captured in between"
    );
    environment.stop().await;
}

/// KR-REQ-22.21: a process that ends inside a job is restarted at the next admitted work and the
/// job is tried again; when the next process fails it as well the job is not tried a third time,
/// the session keeps the title it had, and input and reads still answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_process_that_ends_inside_a_job_is_restarted_and_the_session_keeps_its_title() {
    let mut environment = Environment::start(Setup {
        script: Script {
            crash_in_generate: true,
            ..Script::default()
        },
        ..Setup::new()
    })
    .await;
    let session_id = environment.workers[0].session_id;
    environment.workers[0].report("make", "/home/a/kalareach", None);
    until("a second process after the first ended", || {
        environment.figures().started >= 2
    })
    .await;
    until("the job given up on", || {
        environment.figures().jobs.failed >= 1
    })
    .await;
    let figures = environment.figures();
    assert!(figures.restarts >= 1, "{figures:?}");
    assert_eq!(figures.jobs.published, 0);
    let described = environment.describe(session_id).await;
    assert_eq!(described.source, LabelSource::Metadata);
    environment.workers[0].type_in(b"echo still typing\n");
    environment.workers[0].until_echoed("still typing", 2).await;
    assert_eq!(environment.state_of(session_id).await, SessionState::Live);
    environment.stop().await;
}

/// KR-REQ-22.21: a host that has had no sessions for fifteen minutes unloads the model, which ends
/// the process. The clock the host reads is moved forward by the test, so nothing waits fifteen
/// minutes; the control is the same host before the clock moves, which still holds its process.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_with_no_sessions_unloads_its_model_after_fifteen_minutes() {
    let environment = Environment::start(Setup::new()).await;
    let session_id = environment.workers[0].session_id;
    environment.workers[0].report("make", "/home/a/kalareach", None);
    environment
        .describe_until("the description", session_id, |described| {
            described.source == LabelSource::Generated
        })
        .await;
    assert!(environment.figures().pid.is_some(), "the model is loaded");

    // The session closes, as it does when its worker hands over the account of how it ended, and
    // the host has none.
    environment
        .controller()
        .retire(&kr_protocol::session::ClosureRecord {
            session_id,
            session_epoch: SessionEpoch::V1,
            reason: kr_protocol::session::ClosureReason::RootExit,
            root_exit_code: Nullable::some(U64::new(0)),
            root_signal: Nullable::null(),
            terminated: Vec::new(),
            surviving: Vec::new(),
            ownership_coverage: kr_protocol::session::OwnershipCoverage::Incomplete,
            durability: kr_protocol::session::Durability::Durable,
            closed_at_ms: now(),
        })
        .await
        .expect("the closure is recorded");
    // The host has been told, and has none.
    until("the host tracking no session", || {
        environment.figures().sessions == 0
    })
    .await;
    // Fourteen minutes on: the host has taken a turn at that time, and has unloaded nothing.
    let before = environment.figures().read_at_ms;
    environment.placed.advance(14 * 60 * 1_000);
    environment.controller().descriptions().wake();
    until("a host turn at the clock fourteen minutes on", || {
        environment.figures().read_at_ms >= before + 14 * 60 * 1_000
    })
    .await;
    assert!(
        environment.figures().pid.is_some(),
        "fourteen minutes is not fifteen: {:?}",
        environment.figures()
    );
    // Past fifteen: the process ends.
    environment.placed.advance(2 * 60 * 1_000);
    environment.controller().descriptions().wake();
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while environment.figures().pid.is_some() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the idle unload did not happen: {:?}",
            environment.figures()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(environment.figures().started, 1, "it was never restarted");
    environment.stop().await;
}

/// KR-REQ-22.01: setup shows the exact size, where the fetch would reach and that no account is
/// needed before anything is fetched; the owner's settings are written to the configuration
/// document and apply at once, and turning descriptions off ends the process and shows the pause,
/// while turning them on again lets the same host describe. The control is the setup answer before
/// any setting changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn setup_shows_the_cost_first_and_a_setting_applies_at_once_and_disabling_ends_the_process() {
    let environment = Environment::start(Setup::new()).await;
    let session_id = environment.workers[0].session_id;
    let shown = environment.setup().await;
    assert!(shown.offered && shown.enabled && !shown.on_battery);
    assert_eq!(shown.profile_id.0.as_deref(), Some("tiny-default"));
    assert_eq!(
        shown.asset_bytes.get(),
        27,
        "the exact size, before any fetch"
    );
    assert_eq!(shown.sources, vec!["127.0.0.1:1".to_owned()]);
    assert!(!shown.needs_hosted_account);
    assert!(shown.can_disable);

    environment.workers[0].report("make", "/home/a/kalareach", None);
    environment
        .describe_until("the description", session_id, |described| {
            described.source == LabelSource::Generated
        })
        .await;
    assert!(environment.figures().pid.is_some(), "the model is loaded");

    // Off: the document says so, the answer says so, the process ends and describe says why.
    let off = environment.configure(Some(false), None).await;
    assert!(!off.enabled);
    let resolver = environment.controller().configuration();
    let document = resolver.loaded();
    assert_eq!(
        document
            .document
            .as_ref()
            .and_then(|document| document.descriptions.enabled()),
        Some(false)
    );
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while environment.figures().pid.is_some() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "disabling did not end the process: {:?}",
            environment.figures()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let paused = environment
        .describe_until("the disabled pause", session_id, |described| {
            described.paused.0 == Some(DescriptionPause::Disabled)
        })
        .await;
    assert_eq!(paused.state, DescriptionState::ResourcePaused);

    // The battery setting is its own, and a null leaves the other as it was.
    let battery = environment.configure(None, Some(true)).await;
    assert!(battery.on_battery && !battery.enabled);

    // On again: the same host describes, with a process of its own.
    environment.configure(Some(true), None).await;
    environment.workers[0].report("make", "/home/a/other", None);
    until("a second process serving the next description", || {
        environment.figures().started >= 2 && environment.figures().jobs.published >= 2
    })
    .await;
    environment.stop().await;
}

/// KR-REQ-22.03: across a daemon replacement while the old description process still lives, a
/// session described before it is shown as stale at once, and described again after it; the new
/// process loads nothing until the old one has gone, so there is never a second mapping, and when
/// the old one goes the new one loads and describes. The control is the load marks: one while the
/// old process lives, two after.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_replaced_while_the_old_process_lives_loads_nothing_until_it_has_gone() {
    let environment = Environment::start(Setup {
        script: Script {
            mark_loads: true,
            ..Script::default()
        },
        abandon: true,
        ..Setup::new()
    })
    .await;
    let session_id = environment.workers[0].session_id;
    environment.workers[0].report("make", "/home/a/kalareach", None);
    let before = environment
        .describe_until("the first description", session_id, |described| {
            described.source == LabelSource::Generated
        })
        .await;
    assert_eq!(before.freshness, DescriptionFreshness::Current);
    let old = environment.figures().pid.expect("the old process runs");
    assert_eq!(environment.loaded(), 1);

    let environment = environment.restart().await;
    assert!(
        Environment::alive(old),
        "the old process outlives its daemon"
    );
    // From before the replacement: shown, and stale, at once.
    let carried = environment.describe(session_id).await;
    assert_eq!(carried.source, LabelSource::Generated);
    assert_eq!(carried.freshness, DescriptionFreshness::Stale);

    // The new daemon reads the worker's facts and asks for a load, and the new process finds the
    // old one's lock held and waits for it: nothing is mapped twice while it lives. The old
    // process took the lock without finding it held, so the mark is the new one's.
    until("the new process finding the lock held", || {
        let figures = environment.figures();
        figures.loading && figures.started == 1 && environment.began("lock-held")
    })
    .await;
    assert!(Environment::alive(old));
    assert_eq!(
        environment.loaded(),
        1,
        "no second mapping while the old process lives"
    );
    assert_eq!(environment.figures().jobs.published, 0);
    // The description from before is still shown as it was, and still stale: a revision the new
    // daemon settled may be the number the old one's was produced at, which says nothing here.
    let waiting = environment.describe(session_id).await;
    assert_eq!(waiting.source, LabelSource::Generated);
    assert_eq!(
        waiting.freshness,
        DescriptionFreshness::Stale,
        "a description from an earlier daemon is stale until a newer one replaces it"
    );

    // The old process goes, and the new one loads and describes.
    Environment::end(old);
    until("the new process describing", || {
        environment.figures().jobs.published >= 1
    })
    .await;
    assert_eq!(environment.loaded(), 2);
    let after = environment.describe(session_id).await;
    assert_eq!(after.source, LabelSource::Generated);
    assert_eq!(after.freshness, DescriptionFreshness::Current);
    environment.stop().await;
}

/// KR-REQ-24.11: a load in flight when privacy mode is enabled is cancelled, and privacy mode's
/// change is not complete until it has answered; nothing is loaded for a session captured before.
/// The stub holds the load until it is cancelled, so nothing but the cancellation ends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_load_in_flight_is_cancelled_when_privacy_mode_is_enabled() {
    let environment = Environment::start(Setup {
        script: Script {
            load_until_cancelled: true,
            ..Script::default()
        },
        ..Setup::new()
    })
    .await;
    environment.workers[0].report("make", "/home/a/kalareach", None);
    until("a load in the process", || {
        environment.began("load") && environment.figures().loading
    })
    .await;
    let report = environment.privacy(true).await;
    assert!(report.enabled);
    environment.until_privacy_settled().await;
    until("the load cancelled", || !environment.figures().loading).await;
    assert_eq!(environment.figures().jobs.published, 0);
    environment.stop().await;
}

/// KR-REQ-24.11: a refused removal of the stored descriptions does not keep the memory the service
/// holds: the queue is forgotten and the load in flight is cancelled while the store still
/// refuses, privacy mode's change is not complete while the removal is owed, and it completes once
/// the store takes the removal. The control is the load before privacy mode, which goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_load_is_cancelled_by_privacy_mode_though_the_stored_rows_cannot_be_removed() {
    let environment = Environment::start(Setup {
        script: Script {
            load_until_cancelled: true,
            ..Script::default()
        },
        ..Setup::new()
    })
    .await;
    environment.workers[0].report("make", "/home/a/kalareach", None);
    until("a load in the process", || {
        environment.began("load") && environment.figures().loading
    })
    .await;

    environment.set_removal_refused(true);
    let report = environment.privacy(true).await;
    assert!(report.enabled);
    until("the load cancelled while the store refuses", || {
        !environment.figures().loading
    })
    .await;
    assert_eq!(environment.figures().jobs.published, 0);
    assert!(
        !matches!(
            environment.privacy_status().await.completion,
            kr_protocol::privacy::PrivacyCompletion::Complete
        ),
        "the removal is owed while the store refuses it"
    );

    environment.set_removal_refused(false);
    environment.until_privacy_settled().await;
    environment.stop().await;
}

/// KR-REQ-24.11: a result that arrives after privacy mode was enabled is never published, though
/// the process was in the middle of the job and did not look at its cancellation: privacy mode's
/// change is not complete until the job has answered, nothing was published, and turning privacy
/// mode off brings back nothing from before. The control is the same job left alone, which
/// publishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_result_that_arrives_after_privacy_mode_was_enabled_is_never_published() {
    // The control: the same session and the same job, left alone, is published.
    let environment = Environment::start(Setup::new()).await;
    let session_id = environment.workers[0].session_id;
    environment.workers[0].report("make", "/home/a/kalareach", None);
    environment
        .describe_until("the control's description", session_id, |described| {
            described.source == LabelSource::Generated
        })
        .await;
    environment.stop().await;

    // The job runs until it is cancelled and then answers all the same, as a model that does not
    // look at its token would: the result can only arrive after privacy mode was enabled.
    let environment = Environment::start(Setup {
        script: Script {
            generate_until_cancelled: true,
            produce_when_cancelled: true,
            ..Script::default()
        },
        ..Setup::new()
    })
    .await;
    let session_id = environment.workers[0].session_id;
    environment.workers[0].report("make", "/home/a/kalareach", None);
    until("a job in the process", || environment.began("job")).await;
    assert!(environment.privacy(true).await.enabled);
    environment.until_privacy_settled().await;
    assert_eq!(environment.figures().in_flight, 0, "the job has answered");
    let counted = environment.figures().jobs;
    assert_eq!(
        counted.published, 0,
        "and what it produced was not published"
    );
    assert!(
        counted.refused + counted.cancelled >= 1,
        "the job was ended, and counted so: {counted:?}"
    );
    let shown = environment.describe(session_id).await;
    assert_eq!(shown.source, LabelSource::Metadata);

    assert!(!environment.privacy(false).await.enabled);
    let after = environment.describe(session_id).await;
    assert_eq!(
        after.source,
        LabelSource::Metadata,
        "nothing from before privacy mode comes back"
    );
    assert_eq!(after.freshness, DescriptionFreshness::None);
    environment.stop().await;
}

/// KR-REQ-22.14: what a client is shown of the queue and of the last success. The age of a waiting
/// job grows with the clock; nothing has succeeded until something has; the last success is the
/// time the last description was published and stays there while a newer job waits; and a
/// description the session has moved on from is shown as stale, with the wait beside it and its
/// own text kept. The control is the same host once the pressure goes: the job runs, the wait is
/// gone, and the last success moves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_display_shows_the_age_of_a_waiting_job_and_the_time_of_the_last_success() {
    let on_battery = HostConditions::measured(
        16 * GIB,
        12 * GIB,
        PowerSource::Battery,
        ThermalState::Nominal,
    );
    let environment = Environment::start(Setup {
        conditions: on_battery,
        ..Setup::new()
    })
    .await;
    let session_id = environment.workers[0].session_id;
    environment.workers[0].report("make", "/home/a/kalareach", None);
    let waiting = environment
        .describe_until("the job waiting", session_id, |described| {
            described.queued_age_ms.0.is_some()
        })
        .await;
    assert_eq!(waiting.last_success_ms.0, None, "nothing has succeeded yet");
    let age = waiting.queued_age_ms.0.expect("a queued age").get();

    // A minute on: the wait is that much longer.
    environment.placed.advance(60_000);
    environment.controller().descriptions().wake();
    environment
        .describe_until("the wait to follow the clock", session_id, |described| {
            described
                .queued_age_ms
                .0
                .is_some_and(|waited| waited.get() >= age + 60_000)
        })
        .await;

    // The pressure goes and the job runs: nothing waits, and the last success is when it ended.
    environment.placed.set_conditions(roomy());
    environment.controller().descriptions().wake();
    let first = environment
        .describe_until("the first description", session_id, |described| {
            described.source == LabelSource::Generated && described.queued_age_ms.0.is_none()
        })
        .await;
    assert_eq!(first.freshness, DescriptionFreshness::Current);
    let succeeded = first.last_success_ms.0.expect("a last success");
    assert_eq!(
        Some(succeeded),
        first
            .provenance
            .0
            .as_ref()
            .map(|provenance| provenance.produced_at_ms),
        "the last success is when the description was produced"
    );

    // The pressure comes back and the session moves on: the description is stale with a wait
    // beside it, still its own text, and the last success has not moved.
    environment.placed.set_conditions(on_battery);
    environment.controller().descriptions().wake();
    environment
        .describe_until("the pause", session_id, |described| {
            described.paused.0 == Some(DescriptionPause::Battery)
        })
        .await;
    environment.workers[0].report("make", "/home/a/other", None);
    let stale = environment
        .describe_until("a stale description and a wait", session_id, |described| {
            described.freshness == DescriptionFreshness::Stale
                && described.queued_age_ms.0.is_some()
        })
        .await;
    assert_eq!(stale.source, LabelSource::Generated);
    assert_eq!(stale.activity_text, first.activity_text);
    assert_eq!(stale.last_success_ms.0, Some(succeeded));

    // The control: the pressure goes, the job runs, the wait is gone and the last success moved.
    environment.placed.set_conditions(roomy());
    environment.controller().descriptions().wake();
    let second = environment
        .describe_until("the second description", session_id, |described| {
            described.freshness == DescriptionFreshness::Current
                && described.queued_age_ms.0.is_none()
                && described
                    .last_success_ms
                    .0
                    .is_some_and(|moved| moved.get() > succeeded.get())
        })
        .await;
    assert_eq!(second.source, LabelSource::Generated);
    environment.stop().await;
}

// ---------------------------------------------------------------------------------------------
// The model's files: fetched on request, checked, kept, and found again
// ---------------------------------------------------------------------------------------------

/// KR-REQ-22.01: nothing is fetched until the owner asks, and setup shows the exact size and the
/// address first. A session is shown its title from metadata while the files are not here. The
/// fetch writes the file, has the description process check it, keeps it with a marker and no
/// partial left, and the process that checked goes with the check: no process lingers and nothing
/// was loaded. Then the same session is described by the model, in a process of its own, and a
/// daemon that replaces this one finds the marker and fetches nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fetch_begins_only_when_asked_and_leaves_checked_files_and_no_process_behind() {
    let fixture = Fixture::start().await;
    fixture.reply("/tiny.gguf", Reply::Body(WEIGHTS.to_vec()));
    let environment = Environment::start(Setup {
        catalogue: Some(catalogue_at(1, fixture.url("/tiny.gguf"), WEIGHTS)),
        held: false,
        script: Script {
            mark_loads: true,
            ..Script::default()
        },
        ..Setup::new()
    })
    .await;
    let session_id = environment.workers[0].session_id;

    let shown = environment.setup().await;
    assert!(shown.offered && shown.enabled);
    assert_eq!(shown.asset_bytes.get(), 27, "the exact size, first");
    assert_eq!(shown.sources, vec![fixture.source()]);
    assert_eq!(shown.download, DescriptionDownload::NotStarted);
    assert_eq!(shown.paused.0, Some(DescriptionPause::NotDownloaded));
    assert!(!shown.needs_hosted_account);

    // A session is shown its title from metadata, and nothing asks for a file or a process.
    let titled = environment
        .describe_until("the title from metadata", session_id, |described| {
            described.paused.0 == Some(DescriptionPause::NotDownloaded)
        })
        .await;
    assert_eq!(titled.source, LabelSource::Metadata);
    assert!(fixture.requests().is_empty(), "nothing is fetched unasked");
    assert_eq!(environment.figures().started, 0);
    assert!(!environment.marker() && environment.partials().is_empty());

    // Asked for: the answer shows the fetch, and then the files are here.
    let started = environment.download(DescriptionDownloadAction::Start).await;
    assert!(
        matches!(
            started.download,
            DescriptionDownload::Running | DescriptionDownload::Verified
        ),
        "{started:?}"
    );
    let done = environment
        .setup_until("the fetch verified", |shown| {
            shown.download == DescriptionDownload::Verified
        })
        .await;
    assert_eq!(done.fetched_bytes.get(), 27);
    assert_eq!(fixture.requests(), vec!["/tiny.gguf".to_owned()]);
    assert_eq!(
        std::fs::read(environment.files().join(WEIGHTS_FILE)).expect("the file"),
        WEIGHTS
    );
    assert!(environment.marker(), "the files are marked held");
    assert!(environment.partials().is_empty(), "no partial is left");

    // The process that checked went with the check, and nothing was loaded.
    until("no process left behind", || {
        environment.figures().pid.is_none()
    })
    .await;
    assert!(environment.began("check"), "the process checked the file");
    assert_eq!(environment.loaded(), 0);
    assert_eq!(environment.figures().mapped, 0);

    // Now the model describes the session, in a process of its own.
    environment.workers[0].report("make", "/home/a/other", None);
    let described = environment
        .describe_until("the generated description", session_id, |described| {
            described.source == LabelSource::Generated
        })
        .await;
    assert_eq!(described.paused.0, None);
    assert_eq!(environment.loaded(), 1);
    assert_eq!(
        environment.figures().started,
        2,
        "one to check, one to load"
    );

    // Asked for again while the files are held, nothing is fetched and nothing is taken away.
    let held = environment.download(DescriptionDownloadAction::Start).await;
    assert_eq!(held.download, DescriptionDownload::Verified);
    assert_eq!(
        fixture.requests().len(),
        1,
        "held files are not fetched again"
    );
    assert!(environment.marker());

    // A daemon that replaces this one finds the marker and fetches nothing.
    let environment = environment.restart().await;
    let again = environment.setup().await;
    assert_eq!(again.download, DescriptionDownload::Verified);
    assert_eq!(again.paused.0, None);
    assert_eq!(fixture.requests().len(), 1, "nothing is fetched again");
    environment.stop().await;
}

/// KR-REQ-22.01: cancelling a fetch while its body is arriving stops it and deletes what it had
/// written, and no file of the profile is left. A fetch asked for afterwards starts from nothing
/// and completes. The server holds half the body until the client leaves, so only the cancellation
/// ends the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fetch_cancelled_mid_body_leaves_no_file_and_a_new_fetch_starts_from_nothing() {
    let fixture = Fixture::start().await;
    fixture.reply("/tiny.gguf", Reply::HalfThenHold(WEIGHTS.to_vec()));
    let environment = Environment::start(Setup {
        catalogue: Some(catalogue_at(1, fixture.url("/tiny.gguf"), WEIGHTS)),
        held: false,
        ..Setup::new()
    })
    .await;

    let started = environment.download(DescriptionDownloadAction::Start).await;
    assert_eq!(started.download, DescriptionDownload::Running);
    assert!(started.can_cancel);
    fixture.until_half_sent().await;
    until("the partial file", || !environment.partials().is_empty()).await;

    let cancelled = environment
        .download(DescriptionDownloadAction::Cancel)
        .await;
    assert!(
        matches!(
            cancelled.download,
            DescriptionDownload::Running | DescriptionDownload::Cancelled
        ),
        "{cancelled:?}"
    );
    environment
        .setup_until("the cancelled fetch", |shown| {
            shown.download == DescriptionDownload::Cancelled
        })
        .await;
    assert!(environment.partials().is_empty(), "what it wrote is gone");
    assert!(!environment.files().join(WEIGHTS_FILE).exists());
    assert!(!environment.marker());
    assert_eq!(environment.figures().started, 0, "no process was needed");

    // The control: a fetch asked for afterwards completes.
    fixture.reply("/tiny.gguf", Reply::Body(WEIGHTS.to_vec()));
    environment.download(DescriptionDownloadAction::Start).await;
    environment
        .setup_until("the second fetch verified", |shown| {
            shown.download == DescriptionDownload::Verified
        })
        .await;
    assert!(environment.marker());
    assert_eq!(fixture.requests().len(), 2);
    environment.stop().await;
}

/// KR-REQ-22.01: turning descriptions off stops a running fetch, as it stops the other work in
/// flight, and what it had written is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn turning_descriptions_off_stops_a_running_fetch() {
    let fixture = Fixture::start().await;
    fixture.reply("/tiny.gguf", Reply::HalfThenHold(WEIGHTS.to_vec()));
    let environment = Environment::start(Setup {
        catalogue: Some(catalogue_at(1, fixture.url("/tiny.gguf"), WEIGHTS)),
        held: false,
        ..Setup::new()
    })
    .await;
    environment.download(DescriptionDownloadAction::Start).await;
    fixture.until_half_sent().await;
    until("the partial file", || !environment.partials().is_empty()).await;

    let off = environment.configure(Some(false), None).await;
    assert!(!off.enabled);
    environment
        .setup_until("the cancelled fetch", |shown| {
            shown.download == DescriptionDownload::Cancelled
        })
        .await;
    assert!(environment.partials().is_empty());
    assert!(!environment.files().join(WEIGHTS_FILE).exists());
    environment.stop().await;
}

/// KR-REQ-22.01, KR-REQ-22.09: a body larger than the profile records fails the fetch, whether the
/// server declares the size or sends the body in chunks, and so does a body of the recorded size
/// that is not the profile's file, which the description process finds when it checks it. Each
/// leaves no file, no partial and no marker, and no process behind. The control is the file the
/// profile records, which is kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_body_that_is_too_large_or_not_the_profiles_fails_the_fetch_and_keeps_nothing() {
    let fixture = Fixture::start().await;
    let environment = Environment::start(Setup {
        catalogue: Some(catalogue_at(1, fixture.url("/tiny.gguf"), WEIGHTS)),
        held: false,
        ..Setup::new()
    })
    .await;

    let mut oversize = WEIGHTS.to_vec();
    oversize.extend_from_slice(b" and some more, which the profile does not record");
    let cases = [
        (
            "a declared size past the profile's",
            Reply::Declares {
                declared: oversize.len() as u64,
                body: WEIGHTS.to_vec(),
            },
            "27 bytes",
        ),
        (
            "a chunked body past the profile's",
            Reply::Chunked(oversize),
            "more than the 27 bytes",
        ),
        (
            "a body of the recorded size that is another file",
            Reply::Body(b"the weights of a tiny molde".to_vec()),
            "is not the file the profile records",
        ),
    ];
    for (case, reply, said) in cases {
        fixture.reply("/tiny.gguf", reply);
        environment.download(DescriptionDownloadAction::Start).await;
        let failed = environment
            .setup_until(case, |shown| shown.download == DescriptionDownload::Failed)
            .await;
        let why = failed.failure.0.expect("it says how it failed");
        assert!(why.contains(said), "{case}: {why}");
        assert!(
            !environment.files().join(WEIGHTS_FILE).exists(),
            "{case}: no file is kept"
        );
        assert!(environment.partials().is_empty(), "{case}");
        assert!(!environment.marker(), "{case}");
        until("no process left behind", || {
            environment.figures().pid.is_none()
        })
        .await;
        assert_eq!(environment.loaded(), 0, "{case}");
    }
    assert_eq!(fixture.requests().len(), 3);

    fixture.reply("/tiny.gguf", Reply::Body(WEIGHTS.to_vec()));
    environment.download(DescriptionDownloadAction::Start).await;
    environment
        .setup_until("the right file verified", |shown| {
            shown.download == DescriptionDownload::Verified
        })
        .await;
    assert!(environment.marker());
    environment.stop().await;
}

/// KR-REQ-22.01: a fetch of a profile of two files that fails on the second leaves neither behind,
/// the one it had already checked and put in place included: nothing of a profile is kept unless
/// every file of it is. The control is the same fetch with the right second file, which keeps both.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fetch_that_fails_on_a_later_file_leaves_none_of_the_earlier_ones() {
    let fixture = Fixture::start().await;
    let second = b"a second file".to_vec();
    let signed = TestCatalogue::sign(&[TestProfile {
        profile_id: "tiny-default".to_owned(),
        revision: 1,
        candidate: false,
        targets: Some(vec![kr_describe::environment::build_target().to_owned()]),
        assets: vec![
            TestAsset {
                file_name: WEIGHTS_FILE.to_owned(),
                url: fixture.url("/tiny.gguf"),
                bytes: WEIGHTS.to_vec(),
            },
            TestAsset {
                file_name: "second.bin".to_owned(),
                url: fixture.url("/second.bin"),
                bytes: second.clone(),
            },
        ],
    }]);
    fixture.reply("/tiny.gguf", Reply::Body(WEIGHTS.to_vec()));
    fixture.reply("/second.bin", Reply::Body(b"a second flle".to_vec()));
    let environment = Environment::start(Setup {
        catalogue: Some(signed),
        held: false,
        ..Setup::new()
    })
    .await;

    environment.download(DescriptionDownloadAction::Start).await;
    let failed = environment
        .setup_until("the failure", |shown| {
            shown.download == DescriptionDownload::Failed
        })
        .await;
    assert!(
        failed
            .failure
            .0
            .is_some_and(|why| why.contains("second.bin")),
        "it names the file"
    );
    assert_eq!(fixture.requests(), vec!["/tiny.gguf", "/second.bin"]);
    assert!(!environment.files().join(WEIGHTS_FILE).exists());
    assert!(!environment.files().join("second.bin").exists());
    assert!(environment.partials().is_empty());
    assert!(!environment.marker());

    fixture.reply("/second.bin", Reply::Body(second.clone()));
    environment.download(DescriptionDownloadAction::Start).await;
    environment
        .setup_until("both files verified", |shown| {
            shown.download == DescriptionDownload::Verified
        })
        .await;
    assert_eq!(
        std::fs::read(environment.files().join("second.bin")).expect("the second file"),
        second
    );
    assert!(environment.files().join(WEIGHTS_FILE).exists());
    assert!(environment.marker());
    environment.stop().await;
}

/// KR-REQ-22.01: a fetch that would not fit on the disk is refused before any request is made, and
/// says how much room it needed. The control is the same fetch with room, which is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fetch_that_would_not_fit_is_refused_before_any_request() {
    let fixture = Fixture::start().await;
    fixture.reply("/tiny.gguf", Reply::Body(WEIGHTS.to_vec()));
    let environment = Environment::start(Setup {
        catalogue: Some(catalogue_at(1, fixture.url("/tiny.gguf"), WEIGHTS)),
        held: false,
        ..Setup::new()
    })
    .await;

    // Room for the file and not for the margin beside it.
    environment.placed.set_free_space(Some(1_000));
    environment.download(DescriptionDownloadAction::Start).await;
    let refused = environment
        .setup_until("the refusal", |shown| {
            shown.download == DescriptionDownload::Failed
        })
        .await;
    let why = refused.failure.0.expect("it says why");
    assert!(
        why.contains("1000 bytes free") && why.contains("27 bytes"),
        "{why}"
    );
    assert!(fixture.requests().is_empty(), "no request was made");
    assert!(!environment.files().join(WEIGHTS_FILE).exists());

    environment.placed.set_free_space(Some(64 * GIB));
    environment.download(DescriptionDownloadAction::Start).await;
    environment
        .setup_until("the fetch with room", |shown| {
            shown.download == DescriptionDownload::Verified
        })
        .await;
    assert_eq!(fixture.requests().len(), 1);
    environment.stop().await;
}

/// KR-REQ-22.01, KR-REQ-22.09: a file that is changed after it was kept is refused by the process
/// at the load, and that is no failure of inference: the session keeps its title from metadata,
/// setup shows nothing fetched and the model's files as missing, the marker is gone, no restart is
/// counted, and a new fetch recovers it. The control is the same host before the file was changed,
/// which describes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_load_refused_for_a_changed_file_clears_the_marker_and_a_new_fetch_recovers() {
    let fixture = Fixture::start().await;
    fixture.reply("/tiny.gguf", Reply::Body(WEIGHTS.to_vec()));
    let environment = Environment::start(Setup {
        catalogue: Some(catalogue_at(1, fixture.url("/tiny.gguf"), WEIGHTS)),
        script: Script {
            verify_on_load: true,
            mark_loads: true,
            ..Script::default()
        },
        ..Setup::new()
    })
    .await;
    let session_id = environment.workers[0].session_id;
    assert!(environment.marker());
    // The file is changed under a daemon that has not loaded it yet.
    std::fs::write(
        environment.files().join(WEIGHTS_FILE),
        b"the weights of a tiny molde",
    )
    .expect("the file is changed");

    environment.workers[0].report("make", "/home/a/kalareach", None);
    let shown = environment
        .setup_until("the files shown as missing", |shown| {
            shown.paused.0 == Some(DescriptionPause::NotDownloaded)
        })
        .await;
    assert_eq!(shown.download, DescriptionDownload::NotStarted);
    until("the marker gone", || !environment.marker()).await;
    let titled = environment.describe(session_id).await;
    assert_eq!(titled.source, LabelSource::Metadata);
    assert_eq!(environment.figures().restarts, 0, "no failure of inference");
    assert_eq!(environment.loaded(), 0);
    assert!(!environment.figures().assets_held);

    // A new fetch recovers it, and the session is described.
    environment.download(DescriptionDownloadAction::Start).await;
    environment
        .setup_until("the recovery", |shown| {
            shown.download == DescriptionDownload::Verified
        })
        .await;
    assert_eq!(
        std::fs::read(environment.files().join(WEIGHTS_FILE)).expect("the file"),
        WEIGHTS
    );
    environment.workers[0].report("make", "/home/a/other", None);
    environment
        .describe_until("the generated description", session_id, |described| {
            described.source == LabelSource::Generated
        })
        .await;
    assert_eq!(environment.loaded(), 1);
    assert_eq!(environment.figures().restarts, 0);
    environment.stop().await;
}

/// KR-REQ-22.03: a daemon replaced by one whose catalogue has the profile at a new revision does
/// not take the old files for the new revision's: setup shows nothing fetched and the files as
/// missing, and the description from before is stale. After the new revision is fetched the new
/// daemon loads it, but only once the old process has gone, so there is never a second mapping.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_changed_catalogue_is_fetched_afresh_and_loads_only_once_the_old_process_has_gone() {
    let fixture = Fixture::start().await;
    fixture.reply("/tiny.gguf", Reply::Body(WEIGHTS.to_vec()));
    let script = Script {
        mark_loads: true,
        ..Script::default()
    };
    let environment = Environment::start(Setup {
        catalogue: Some(catalogue_at(1, fixture.url("/tiny.gguf"), WEIGHTS)),
        script: script.clone(),
        abandon: true,
        ..Setup::new()
    })
    .await;
    let session_id = environment.workers[0].session_id;
    environment.workers[0].report("make", "/home/a/kalareach", None);
    environment
        .describe_until("the first description", session_id, |described| {
            described.source == LabelSource::Generated
        })
        .await;
    let old = environment.figures().pid.expect("the old process runs");
    assert_eq!(environment.loaded(), 1);

    let environment = environment
        .restart_with(
            script,
            catalogue_at(2, fixture.url("/tiny.gguf"), WEIGHTS),
            false,
        )
        .await;
    assert!(
        Environment::alive(old),
        "the old process outlives its daemon"
    );
    let shown = environment.setup().await;
    assert_eq!(shown.download, DescriptionDownload::NotStarted);
    assert_eq!(shown.paused.0, Some(DescriptionPause::NotDownloaded));
    assert!(
        !environment.marker(),
        "the old revision's files are not this one's"
    );
    let old_revision = environment
        .files()
        .parent()
        .expect("the profile's directory")
        .join("1");
    assert!(
        old_revision.exists(),
        "the old revision's files are still there"
    );
    let carried = environment.describe(session_id).await;
    assert_eq!(carried.source, LabelSource::Generated);
    assert_eq!(carried.freshness, DescriptionFreshness::Stale);

    // The new revision is fetched; its process is told to load, and waits for the old one's lock.
    environment.download(DescriptionDownloadAction::Start).await;
    environment
        .setup_until("the new revision fetched", |shown| {
            shown.download == DescriptionDownload::Verified
        })
        .await;
    assert!(
        !old_revision.exists(),
        "the files of the profile's other revisions go once the new ones are kept"
    );
    environment.workers[0].report("make", "/home/a/other", None);
    until("the new process finding the lock held", || {
        environment.began("lock-held")
    })
    .await;
    assert!(Environment::alive(old));
    assert_eq!(
        environment.loaded(),
        1,
        "no second mapping while the old process lives"
    );
    assert_eq!(environment.figures().jobs.published, 0);

    Environment::end(old);
    until("the new process describing", || {
        environment.figures().jobs.published >= 1
    })
    .await;
    assert_eq!(environment.loaded(), 2);
    let after = environment.describe(session_id).await;
    assert_eq!(after.freshness, DescriptionFreshness::Current);
    environment.stop().await;
}

// ---------------------------------------------------------------------------------------------
// The real description process
// ---------------------------------------------------------------------------------------------

/// The real description process this run names, or a failure that says how to name one: a run that
/// asked for the real process and has none does not pass.
fn real_process() -> PathBuf {
    std::env::var_os("KR_DESCRIBE_INFERENCE")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .unwrap_or_else(|| {
            panic!(
                "KR_DESCRIBE_INFERENCE names no executable: build kr-describe-inference with \
                 `cargo build -p kr-describe-model --bin kr-describe-inference` and name the file"
            )
        })
}

/// A host with room for the real model, so the policy admits it and the test is about the process.
fn real_conditions() -> HostConditions {
    HostConditions::measured(
        64 * GIB,
        48 * GIB,
        PowerSource::Mains,
        ThermalState::Nominal,
    )
}

/// The default profile this build ships, and its weights file.
fn shipped_weights() -> (kr_describe::profile::Asset, kr_describe::Catalogue) {
    let catalogue = kr_describe::Catalogue::builtin().expect("the profiles this build ships");
    let weights = catalogue
        .default_profile()
        .assets()
        .iter()
        .find(|asset| asset.role == "weights")
        .expect("the profile names its weights")
        .clone();
    (weights, catalogue)
}

/// KR-REQ-22.01, KR-REQ-22.09: the real description process refuses, at the daemon's load, a file
/// of the recorded size that is not the profile's, and the host answers as it does for the stub:
/// the model's files are shown as missing, the marker is gone, the session keeps its title from
/// metadata and no failure of inference is counted. The file is sparse, so no weights are needed.
///
/// It runs with `--ignored` and names the executable in `KR_DESCRIBE_INFERENCE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the real description process that KR_DESCRIBE_INFERENCE names; it runs with --ignored"]
async fn the_real_process_refuses_a_file_that_is_not_the_profiles_and_the_host_shows_it_missing() {
    let program = real_process();
    let (weights, _) = shipped_weights();
    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    let sparse = directory.path().join(&weights.file_name);
    std::fs::File::create(&sparse)
        .and_then(|file| file.set_len(weights.bytes))
        .expect("a sparse file of the recorded size");
    let environment = Environment::start(Setup {
        real: Some(Real {
            program,
            files: vec![(weights.file_name.clone(), sparse)],
        }),
        conditions: real_conditions(),
        ..Setup::new()
    })
    .await;
    let session_id = environment.workers[0].session_id;
    assert!(environment.marker());

    environment.workers[0].report("make", "/home/a/kalareach", None);
    let shown = environment
        .setup_until("the files shown as missing", |shown| {
            shown.paused.0 == Some(DescriptionPause::NotDownloaded)
        })
        .await;
    assert_eq!(shown.download, DescriptionDownload::NotStarted);
    until("the marker gone", || !environment.marker()).await;
    assert_eq!(
        environment.describe(session_id).await.source,
        LabelSource::Metadata
    );
    assert_eq!(environment.figures().restarts, 0, "no failure of inference");
    environment.stop().await;
}

/// KR-REQ-22.05, KR-REQ-22.14: the real description process, with the real weights, describes a
/// session the daemon serves, in one process with one mapping, and the description is labelled as
/// generated. The weights are the ones the benchmark keeps (`KR_DESCRIBE_MODEL_CACHE`, or the
/// platform's cache directory), linked in and never written.
///
/// It runs with `--ignored` and names the executable in `KR_DESCRIBE_INFERENCE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the real description process that KR_DESCRIBE_INFERENCE names and the real weights; it runs with --ignored"]
async fn the_real_process_describes_a_session_from_the_real_weights() {
    let program = real_process();
    let (weights, _) = shipped_weights();
    let cache = std::env::var_os("KR_DESCRIBE_MODEL_CACHE")
        .map(PathBuf::from)
        .or_else(|| {
            let home = PathBuf::from(std::env::var_os("HOME")?);
            Some(if cfg!(target_os = "macos") {
                home.join("Library/Caches/kalareach-describe")
            } else {
                home.join(".cache/kalareach-describe")
            })
        })
        .expect("a cache directory");
    let cached = cache.join(&weights.file_name);
    assert_eq!(
        std::fs::metadata(&cached).map(|about| about.len()).ok(),
        Some(weights.bytes),
        "the real weights are not at {}; fill the cache with scripts/bench-descriptions.sh",
        cached.display()
    );
    let environment = Environment::start(Setup {
        real: Some(Real {
            program,
            files: vec![(weights.file_name.clone(), cached)],
        }),
        conditions: real_conditions(),
        ..Setup::new()
    })
    .await;
    let session_id = environment.workers[0].session_id;

    environment.workers[0].report("make", "/home/a/kalareach", None);
    let described = environment
        .describe_within(
            Duration::from_secs(900),
            "the real model's description",
            session_id,
            |described| described.source == LabelSource::Generated,
        )
        .await;
    assert_eq!(described.paused.0, None);
    assert_eq!(environment.figures().mapped, 1, "one mapping");
    assert_eq!(environment.figures().started, 1, "one process");
    environment.stop().await;
}

/// KR-REQ-22.01: a server that takes the connection and never answers, and one that sends half a
/// body and stops, each fail the fetch at the bound the fetch waits for the server, and say which
/// it was; no partial or marker is left. The bound is shortened for the test, and the control is a
/// server that answers, which the same fetch completes against.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_server_that_goes_silent_fails_the_fetch_at_the_bound_and_keeps_nothing() {
    let fixture = Fixture::start().await;
    let environment = Environment::start(Setup {
        catalogue: Some(catalogue_at(1, fixture.url("/tiny.gguf"), WEIGHTS)),
        held: false,
        ..Setup::new()
    })
    .await;
    environment
        .placed
        .set_fetch_stall(Some(Duration::from_secs(1)));

    for (case, reply, said) in [
        (
            "no answer",
            Reply::Silent,
            "did not answer within 1 seconds",
        ),
        (
            "a body that stops",
            Reply::HalfThenHold(WEIGHTS.to_vec()),
            "sent nothing for 1 seconds",
        ),
    ] {
        fixture.reply("/tiny.gguf", reply);
        environment.download(DescriptionDownloadAction::Start).await;
        let failed = environment
            .setup_until(case, |shown| shown.download == DescriptionDownload::Failed)
            .await;
        let why = failed.failure.0.expect("it says how it failed");
        assert!(why.contains(said), "{case}: {why}");
        assert!(environment.partials().is_empty(), "{case}");
        assert!(!environment.files().join(WEIGHTS_FILE).exists(), "{case}");
        assert!(!environment.marker(), "{case}");
    }

    fixture.reply("/tiny.gguf", Reply::Body(WEIGHTS.to_vec()));
    environment.download(DescriptionDownloadAction::Start).await;
    environment
        .setup_until("the fetch from a server that answers", |shown| {
            shown.download == DescriptionDownload::Verified
        })
        .await;
    environment.stop().await;
}

/// KR-REQ-22.01: a cancellation that comes while the process is checking the last file wins over
/// the check, even when the process answers that the file passed before it read the cancellation:
/// no file is kept and no marker is written. The stub reads the check's cancellation only after it
/// has answered, as a process that was already past the last block does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancellation_during_the_last_check_wins_over_a_check_that_passed() {
    let fixture = Fixture::start().await;
    fixture.reply("/tiny.gguf", Reply::Body(WEIGHTS.to_vec()));
    let environment = Environment::start(Setup {
        catalogue: Some(catalogue_at(1, fixture.url("/tiny.gguf"), WEIGHTS)),
        held: false,
        script: Script {
            verify_ignore_token_ms: 800,
            verify_finishes_after_cancel: true,
            ..Script::default()
        },
        ..Setup::new()
    })
    .await;
    environment.download(DescriptionDownloadAction::Start).await;
    until("the check", || environment.began("check")).await;
    environment
        .download(DescriptionDownloadAction::Cancel)
        .await;
    environment
        .setup_until("the cancelled fetch", |shown| {
            shown.download == DescriptionDownload::Cancelled
        })
        .await;
    assert!(!environment.files().join(WEIGHTS_FILE).exists(), "no file");
    assert!(environment.partials().is_empty());
    assert!(!environment.marker(), "no marker");
    assert!(!environment.figures().assets_held);
    environment.stop().await;
}

/// KR-REQ-22.01: descriptions turned off by a change to the configuration that did not come
/// through `description.configure` (a document the owner edited by hand reaches the daemon the same
/// way) stop a running fetch as well, and what it had written is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn descriptions_turned_off_in_the_configuration_stop_a_running_fetch() {
    let fixture = Fixture::start().await;
    fixture.reply("/tiny.gguf", Reply::HalfThenHold(WEIGHTS.to_vec()));
    let environment = Environment::start(Setup {
        catalogue: Some(catalogue_at(1, fixture.url("/tiny.gguf"), WEIGHTS)),
        held: false,
        ..Setup::new()
    })
    .await;
    environment.download(DescriptionDownloadAction::Start).await;
    fixture.until_half_sent().await;
    until("the partial file", || !environment.partials().is_empty()).await;

    environment
        .controller()
        .apply_configuration(
            &kr_protocol::hostinfo::configuration::Change::Descriptions {
                enabled: Some(false),
                on_battery: None,
            },
        )
        .await
        .expect("the document is changed");
    environment
        .setup_until("the cancelled fetch", |shown| {
            shown.download == DescriptionDownload::Cancelled
        })
        .await;
    assert!(environment.partials().is_empty());
    assert!(!environment.files().join(WEIGHTS_FILE).exists());
    assert!(!environment.marker());
    environment.stop().await;
}

/// KR-REQ-22.01: the model's files may be fetched while descriptions are off, so that they are
/// here when the owner turns descriptions on. The process that checks them goes with the check,
/// nothing is loaded while descriptions are off, and turning them on then describes a session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_files_may_be_fetched_while_descriptions_are_off_and_nothing_loads_until_they_are_on() {
    let fixture = Fixture::start().await;
    fixture.reply("/tiny.gguf", Reply::Body(WEIGHTS.to_vec()));
    let environment = Environment::start(Setup {
        catalogue: Some(catalogue_at(1, fixture.url("/tiny.gguf"), WEIGHTS)),
        held: false,
        script: Script {
            mark_loads: true,
            ..Script::default()
        },
        ..Setup::new()
    })
    .await;
    let session_id = environment.workers[0].session_id;
    environment.configure(Some(false), None).await;

    environment.download(DescriptionDownloadAction::Start).await;
    environment
        .setup_until("the fetch verified", |shown| {
            shown.download == DescriptionDownload::Verified
        })
        .await;
    assert!(environment.marker());
    until("no process left behind", || {
        environment.figures().pid.is_none()
    })
    .await;
    environment.workers[0].report("make", "/home/a/kalareach", None);
    let titled = environment.describe(session_id).await;
    assert_eq!(titled.source, LabelSource::Metadata);
    assert_eq!(environment.loaded(), 0, "nothing loads while they are off");

    environment.configure(Some(true), None).await;
    environment
        .describe_until("the generated description", session_id, |described| {
            described.source == LabelSource::Generated
        })
        .await;
    assert_eq!(environment.loaded(), 1);
    environment.stop().await;
}

/// KR-REQ-22.01: a partial file a daemon left when it went in the middle of a fetch is removed
/// when the next daemon starts, and the files the marker holds are left alone: the kept file beside
/// the partial stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_partial_left_by_a_daemon_that_went_mid_fetch_is_removed_at_the_next_start() {
    let environment = Environment::start(Setup::new()).await;
    let partial = environment.files().join(format!("{WEIGHTS_FILE}.partial"));
    std::fs::write(&partial, b"half a body").expect("a partial file");
    assert_eq!(environment.partials().len(), 1);

    let environment = environment.restart().await;
    assert!(environment.partials().is_empty(), "the partial is gone");
    assert!(
        environment.files().join(WEIGHTS_FILE).exists(),
        "the kept file stays"
    );
    assert!(environment.marker());
    assert_eq!(
        environment.setup().await.download,
        DescriptionDownload::Verified
    );
    environment.stop().await;
}

/// KR-REQ-22.01: a fetch the owner asked for while descriptions are off goes on through the
/// requests that read the configuration (every `kr new`, `kr status` and `kr doctor` does) and
/// through a change to the other setting; only the change to off stops a fetch. The control is the
/// same fetch stopped by turning descriptions on and then off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fetch_asked_for_while_descriptions_are_off_goes_on_through_other_acceptances() {
    let fixture = Fixture::start().await;
    fixture.reply("/tiny.gguf", Reply::HalfThenHold(WEIGHTS.to_vec()));
    let environment = Environment::start(Setup {
        catalogue: Some(catalogue_at(1, fixture.url("/tiny.gguf"), WEIGHTS)),
        held: false,
        ..Setup::new()
    })
    .await;
    environment.configure(Some(false), None).await;
    environment.download(DescriptionDownloadAction::Start).await;
    fixture.until_half_sent().await;
    until("the partial file", || !environment.partials().is_empty()).await;

    // Each of these accepts the configuration again with descriptions still off.
    environment.configure(None, Some(true)).await;
    environment
        .controller()
        .apply_configuration(
            &kr_protocol::hostinfo::configuration::Change::Descriptions {
                enabled: None,
                on_battery: Some(false),
            },
        )
        .await
        .expect("the document is changed");
    let still = environment.setup().await;
    assert_eq!(still.download, DescriptionDownload::Running, "{still:?}");
    assert!(
        !environment.partials().is_empty(),
        "the partial is still being written"
    );

    // Turned on and then off again, the change to off stops it.
    environment.configure(Some(true), None).await;
    environment.configure(Some(false), None).await;
    environment
        .setup_until("the cancelled fetch", |shown| {
            shown.download == DescriptionDownload::Cancelled
        })
        .await;
    assert!(environment.partials().is_empty());
    environment.stop().await;
}
