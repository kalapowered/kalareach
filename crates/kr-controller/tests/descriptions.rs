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

use std::path::PathBuf;
use std::sync::Arc;
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
            .adopt_worker(&WorkerRecord {
                session_id,
                display_number,
                public_key,
                process_identity: process.clone(),
                endpoint: endpoint.as_text(),
                profile: WorkerProfile::HeadlessUser,
                state: SessionState::Live,
                acknowledged_revision: AuthorityRevision::new(0),
            })
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
}

impl Setup {
    fn new() -> Self {
        Self {
            script: Script::default(),
            sessions: 1,
            conditions: roomy(),
            abandon: false,
        }
    }
}

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
            file_name: "tiny.gguf".to_owned(),
            url: "http://127.0.0.1:1/tiny.gguf".to_owned(),
            bytes: b"the weights of a tiny model".to_vec(),
        }],
    }])
}

/// A daemon with its workers, and the stub it starts.
struct Environment {
    host: Host,
    workers: Vec<Worker>,
    placed: kr_controller::describe::hooks::Placed,
    runtime_dir: PathBuf,
}

impl Environment {
    async fn start(setup: Setup) -> Self {
        let owner = DeviceKeys::generate().expect("owner keys");
        let host = Host::start(&owner).await;
        let stopped = host.shut_down().await;
        let tree = stopped.tree();
        let state_dir = tree.environment().state_dir().to_path_buf();
        let runtime_dir = tree.environment().runtime_dir().to_path_buf();
        // The stub, on the internal disk, started once so the operating system has checked it.
        let stub = tree.root().join("kr-stub-inference");
        kr_ipc::testing::place_and_start_once(
            std::path::Path::new(env!("CARGO_BIN_EXE_kr-stub-inference")),
            &stub,
            &["--version"],
        );
        let signed = catalogue();
        let bundle = tree.root().join("catalogue.json");
        signed.write_to(&bundle);
        let mut script = setup.script;
        script.mark_start = true;
        script.mark_work = true;
        let placed = kr_controller::describe::hooks::place(
            &state_dir,
            stub,
            vec![
                (SCRIPT_VARIABLE.into(), script.to_env().into()),
                (CATALOGUE_VARIABLE.into(), bundle.into()),
            ],
            signed.catalogue(),
            setup.conditions,
            setup.abandon,
        );
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
        let deadline = tokio::time::Instant::now() + PATIENCE;
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

    /// Stops the daemon and starts another on the same tree, which finds the workers still running.
    async fn restart(self) -> Self {
        let Self {
            host,
            workers,
            placed,
            runtime_dir,
        } = self;
        let host = host.restart().await;
        let environment = Self {
            host,
            workers,
            placed,
            runtime_dir,
        };
        for worker in &environment.workers {
            environment.until_adopted(worker.session_id).await;
        }
        environment
    }

    /// Whether a process is running, as the operating system says.
    fn alive(pid: u32) -> bool {
        std::process::Command::new("/bin/kill")
            .args(["-0", &pid.to_string()])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
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
    }
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
    // Fourteen minutes on: nothing is unloaded yet.
    environment.placed.advance(14 * 60 * 1_000);
    environment.controller().descriptions().wake();
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

    // The new daemon reads the worker's facts and asks for a load, and the load waits for the old
    // process's lock: nothing is mapped twice while it lives.
    until("the new process asked to load", || {
        let figures = environment.figures();
        figures.loading && figures.started == 1
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
    let ended = std::process::Command::new("/bin/kill")
        .args(["-TERM", &old.to_string()])
        .status()
        .expect("the old process is signalled");
    assert!(ended.success());
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
/// The control is the same load left alone, which the stub holds until it is cancelled.
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
    assert!(
        environment.figures().loading,
        "left alone, the load goes on"
    );

    let report = environment.privacy(true).await;
    assert!(report.enabled);
    environment.until_privacy_settled().await;
    until("the load cancelled", || !environment.figures().loading).await;
    assert_eq!(environment.figures().jobs.published, 0);
    environment.stop().await;
}
