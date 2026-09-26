//! Section 27's stress run: fifty sessions with sustained output and attached views, on a real host.
//!
//! The daemon runs in this process, and every session is a real worker process with a real shell in
//! a real pseudo-terminal, started the way the daemon starts them. Each of the fifty sessions runs a
//! program that writes terminal output at a steady rate as its shell's foreground command, which is
//! what a session running a build or an agent looks like to the host, and each has a view attached
//! that reads everything it is sent.
//!
//! While that runs, for a fixed window, this measures:
//!
//! * memory: every process's resident size, sampled through the window, with the product's own
//!   processes (the daemon and the workers) apart from the applications (the shells and their
//!   programs), and the whole host with the plugin host serving a fixture package beside them;
//! * processor: each process's processor time over the window, by kind, and what the adoption
//!   watch costs while a command holds the terminal, from two probe sessions that differ only in
//!   that;
//! * queue bounds: an observer that stops reading one session is told to resynchronise and, once
//!   it resubscribes, receives output again, while every other view keeps receiving;
//! * input latency with KR-PERF-001's method: single-byte writes to an echoing session, each timed
//!   to the echo arriving back at the client.
//!
//! Each figure is recorded in `kr-perf-stress.md` under `KR_TEST_ARTIFACTS_DIR`, headed by the
//! identifier it bears on, before anything is asserted. Nothing runs the description model here,
//! and the whole-host record says so.
//!
//! The worker and the plugin host are the release build's own programs, found beside this test in
//! the build directory, so the workspace's release profile is built first; `scripts/bench-all.sh`
//! does that and runs this. Every program is copied to the internal disk before it is started, and
//! every directory a session or a program uses is there too.
//!
//! Unix only: the sessions run a POSIX shell.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{
    DetachedSupervisor, JobRetirement, LaunchOutcome, ServiceLaunch, WorkerSupervisor,
};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::paths::{Endpoint, EnvironmentPaths};
use kr_ipc::verify::ControllerIdentity;
use kr_perf::{process, record};
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::identity::PluginIdentity;
use kr_plugin_sdk::version::PackageVersion;
use kr_plugin_service::client::{PluginClient, new_binding_id};
use kr_plugin_service::launcher::{
    self, HostFence, HostJobRetirement, HostLaunchPlan, HostStartOutcome, HostSupervisor,
};
use kr_plugin_service::protocol::ComponentSource;
use kr_plugin_service::vocabulary::{
    BindingActivity, BindingFacts, ScopedSourceEvent, SourceProvenance,
};
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
};
use kr_protocol::envelope::{ActionTarget, ControlFrame, Outcome, ParamsValue, Request};
use kr_protocol::ids::{
    ActionId, AttachmentId, BuildId, EnvironmentId, InputLeaseEpoch, InputSequence, PluginId,
    RepositoryGeneration, RequestId, SessionEpoch, SessionId, SourceEventHandle,
};
use kr_protocol::input::{
    InputAcquireParams, InputAcquireResult, InputWriteParams, InputWriteResult,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::recovery::{
    EventStream, EventsSubscribeParams, OutputEvent, ResyncReason, ResyncRequired,
};
use kr_protocol::scalars::{Bytes, CanonicalSet, Nullable};
use kr_protocol::session::{
    Presentation, SessionCloseParams, SessionCreateParams, SessionCreateResult, SessionListParams,
    SessionListResult, SessionState, ShellMode,
};

#[path = "../../../crates/kr-controller/tests/teardown/mod.rs"]
mod teardown;

/// How many sessions section 27's stress run names.
const SESSIONS: usize = 50;

/// What each session's program writes, in bytes a second.
const RATE: u64 = 32 * 1024;

/// What the session the slow observer is attached to writes, in bytes a second: enough to fill the
/// observer's send queue well inside the window.
const FAST_RATE: u64 = 512 * 1024;

/// How long the figures are taken over.
const WINDOW: Duration = Duration::from_secs(120);

/// How often memory and every view's progress are read through the window.
const SAMPLE: Duration = Duration::from_secs(5);

/// How many keystrokes the latency measurement sends, as KR-PERF-001's does.
const KEYSTROKES: usize = 1_000;

/// The bound section 27 puts on the ninety-fifth percentile of added input latency.
const P95_BOUND: Duration = Duration::from_millis(5);

/// The bound section 27 puts on the ninety-ninth percentile.
const P99_BOUND: Duration = Duration::from_millis(15);

/// How long every session is given to start writing, and any single wait for the host.
const LIVENESS: Duration = Duration::from_secs(120);

/// How many bytes a view has to have read before its session counts as writing: more than a
/// prompt and a typed command make.
const WRITING: u64 = 16 * 1024;

/// How many times one process group is enumerated to time what a look costs.
const LOOKS: u32 = 20;

/// The record this measurement's figures are kept in.
const RECORD: &str = "kr-perf-stress.md";

/// The root program of the session the keystrokes go to: it echoes what it reads, with the terminal
/// in raw mode, as KR-PERF-001's does.
const ECHO_ROOT: &str = "#!/bin/sh\nstty raw -echo\nprintf 'kr-ready.'\nexec cat\n";

/// The fixture package the plugin host serves.
const COMPONENT: &str = "well-behaved";

fn build() -> BuildId {
    BuildId::new("kr-perf/0").expect("a build identifier")
}

/// A size for a person to read: kibibytes below a mebibyte, mebibytes from there.
fn size(bytes: u64) -> String {
    if bytes < 1024 * 1024 {
        return format!("{} KiB", bytes.div_ceil(1024));
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "a figure for a person to read, far inside f64's exact range"
    )]
    let value = bytes as f64 / (1024.0 * 1024.0);
    format!("{value:.1} MiB")
}

/// A rate over `over`, in mebibytes a second, for a person to read.
fn per_second(bytes: u64, over: Duration) -> String {
    #[expect(
        clippy::cast_precision_loss,
        reason = "a figure for a person to read, far inside f64's exact range"
    )]
    let rate = bytes as f64 / over.as_secs_f64() / (1024.0 * 1024.0);
    format!("{rate:.2} MiB a second")
}

fn milliseconds(duration: Duration) -> String {
    format!("{:.3} ms", duration.as_secs_f64() * 1000.0)
}

/// Finds one of the release build's programs beside this test.
fn built(name: &str) -> PathBuf {
    let mut directory = std::env::current_exe().expect("this test's own path");
    directory.pop();
    if directory.file_name().is_some_and(|last| last == "deps") {
        directory.pop();
    }
    let program = directory.join(name);
    assert!(
        program.is_file(),
        "{} is not built: build the workspace's release profile first (scripts/bench-all.sh does)",
        program.display()
    );
    program
}

struct Host {
    /// The host tree, which ends every process its daemon started before it goes.
    temp: teardown::Tree,
    environment_id: EnvironmentId,
    controller: Arc<Controller>,
    writer: PathBuf,
    echo_root: PathBuf,
    plugin_host: PathBuf,
}

async fn host() -> Host {
    let temp = teardown::Tree::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    // Every program on the internal disk, and each started once here, where nothing is measured,
    // so the operating system's check of a new executable is in no figure below.
    let worker = temp.root().join("kr-worker");
    kr_ipc::testing::place_and_start_once(&built("kr-worker"), &worker, &["--version"]);
    let writer = temp.root().join("kr-perf-writer");
    kr_ipc::testing::place_and_start_once(
        Path::new(env!("CARGO_BIN_EXE_kr-perf-writer")),
        &writer,
        &["--version"],
    );
    let plugin_host = temp.root().join("kr-plugin-host");
    kr_ipc::testing::place_program(&built("kr-plugin-host"), &plugin_host);
    let echo_root = temp.root().join("echo-root");
    std::fs::write(&echo_root, ECHO_ROOT).expect("the echoing root program");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&echo_root, std::fs::Permissions::from_mode(0o700))
            .expect("the echoing root program runs");
    }
    let secrets = environment.secrets_dir();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: temp.supervisor(Box::new(DetachedSupervisor::new())),
        worker_program: worker,
        build_id: build(),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    })
    .await
    .expect("the daemon starts");
    let rendezvous = Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
        .expect("binds the rendezvous");
    let clients = Listener::bind(&environment.controller_endpoint().expect("an endpoint"))
        .expect("binds the client endpoint");
    tokio::spawn(Arc::clone(&controller).serve_rendezvous(rendezvous));
    tokio::spawn(Arc::clone(&controller).serve_clients(clients));
    Host {
        temp,
        environment_id,
        controller,
        writer,
        echo_root,
        plugin_host,
    }
}

impl Host {
    fn daemon(&self) -> Result<Endpoint, String> {
        self.temp
            .environment()
            .controller_endpoint()
            .map_err(|error| format!("the daemon's endpoint: {error}"))
    }

    fn target(&self, session_id: SessionId) -> ActionTarget {
        ActionTarget {
            environment_id: self.environment_id,
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }
}

/// What this run started, which it ends whatever the measurement did.
#[derive(Default)]
struct Run {
    sessions: Vec<SessionId>,
    plugin: Option<PluginHost>,
}

impl Run {
    /// Creates a session whose root program is `shell`, recording it before anything else is done
    /// with it.
    async fn create(&mut self, host: &Host, shell: &str) -> Result<SessionCreateResult, String> {
        let mut client = LocalClient::connect(&host.daemon()?, LocalClientKind::Cli, build())
            .await
            .map_err(|error| format!("connect to the daemon: {error}"))?;
        let created: SessionCreateResult = client
            .mutate(
                Method::SessionCreate,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &SessionCreateParams {
                    environment_id: host.environment_id,
                    presentation: Presentation::Invisible,
                    shell: Nullable::some(shell.to_owned()),
                    shell_mode: ShellMode::NativeCompat,
                    cwd: Nullable::some(host.temp.root().display().to_string()),
                    dimensions: Nullable::null(),
                    worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                    palette: Nullable::null(),
                    environment_snapshot: vec![kr_protocol::session::EnvironmentVariable {
                        name: "PATH".to_owned(),
                        value: "/usr/bin:/bin".to_owned(),
                    }],
                    launch_profile: kr_protocol::session::LaunchProfile::default(),
                    terminal: Nullable::null(),
                },
            )
            .await
            .map_err(|error| format!("the create call: {error}"))?
            .map_err(|error| format!("the daemon refused a create: {error}"))?
            .to_typed()
            .map_err(|error| format!("the create result: {error}"))?;
        self.sessions.push(created.session.session_id);
        Ok(created)
    }

    /// Ends the plugin host, closes every session and waits for the daemon to record each closure.
    ///
    /// Whatever this does not reach, the host tree ends when it is dropped.
    async fn end(&mut self, host: &Host) -> Result<(), String> {
        if let Some(plugin) = self.plugin.take() {
            plugin.end(&host.temp.environment());
        }
        let endpoint = host.daemon()?;
        let mut refused = Vec::new();
        for &session_id in &self.sessions {
            let closed = async {
                let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
                    .await
                    .map_err(|error| format!("connect: {error}"))?;
                client
                    .mutate(
                        Method::SessionClose,
                        ActionId::new(kr_ipc::new_uuid()),
                        host.target(session_id),
                        &SessionCloseParams { session_id },
                    )
                    .await
                    .map_err(|error| format!("the close call: {error}"))?
                    .map_err(|error| format!("the daemon refused: {error}"))
                    .map(|_| ())
            }
            .await;
            if let Err(failure) = closed {
                refused.push(format!("{session_id}: {failure}"));
            }
        }
        let deadline = Instant::now() + LIVENESS;
        loop {
            let open: Vec<SessionId> = listed(&endpoint, true)
                .await?
                .into_iter()
                .filter(|(session_id, state)| {
                    self.sessions.contains(session_id) && *state != SessionState::Closed
                })
                .map(|(session_id, _)| session_id)
                .collect();
            if open.is_empty() {
                break;
            }
            if Instant::now() >= deadline {
                refused.push(format!(
                    "still open {LIVENESS:?} after the closes: {open:?}"
                ));
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        if refused.is_empty() {
            Ok(())
        } else {
            Err(refused.join("; "))
        }
    }
}

/// Every session the daemon holds, with its state.
async fn listed(
    endpoint: &Endpoint,
    include_closed: bool,
) -> Result<Vec<(SessionId, SessionState)>, String> {
    let mut client = LocalClient::connect(endpoint, LocalClientKind::Cli, build())
        .await
        .map_err(|error| format!("connect to the daemon: {error}"))?;
    let listed: SessionListResult = client
        .request(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::null(),
                include_closed,
            },
        )
        .await
        .map_err(|error| format!("the list call: {error}"))?
        .map_err(|error| format!("the list failed: {error}"))?
        .to_typed()
        .map_err(|error| format!("the list result: {error}"))?;
    Ok(listed
        .sessions
        .iter()
        .map(|summary| (summary.session_id, summary.state))
        .collect())
}

/// One attachment to one session, subscribed to its output.
struct View {
    client: LocalClient,
    target: ActionTarget,
    session_id: SessionId,
    attachment_id: AttachmentId,
    lease: Option<InputLeaseEpoch>,
    sequence: u64,
}

impl View {
    /// Attaches to the session `created` names, subscribes to its output, and with `input` takes
    /// its input lease.
    async fn attach(
        host: &Host,
        created: &SessionCreateResult,
        input: bool,
    ) -> Result<Self, String> {
        let endpoint = Endpoint::from_path(
            created
                .endpoint
                .as_ref()
                .ok_or_else(|| "a live session has an endpoint".to_owned())?,
        )
        .map_err(|error| format!("a session's endpoint: {error}"))?;
        Self::attach_at(
            &endpoint,
            host.target(created.session.session_id),
            created.session.session_id,
            input,
        )
        .await
    }

    async fn attach_at(
        endpoint: &Endpoint,
        target: ActionTarget,
        session_id: SessionId,
        input: bool,
    ) -> Result<Self, String> {
        let mut client = LocalClient::connect(endpoint, LocalClientKind::Cli, build())
            .await
            .map_err(|error| format!("connect to a worker: {error}"))?;
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        if input {
            requested.insert(AttachmentCapability::Input);
        }
        let attached: SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                target.clone(),
                &SessionAttachParams {
                    session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: false,
                    // The session's own size, with a terminal declared, so the view is sent the
                    // stream itself rather than a rendering of the screen.
                    dimensions: Nullable::some(kr_protocol::session::INVISIBLE_DEFAULT_DIMENSIONS),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
            .map_err(|error| format!("the attach call: {error}"))?
            .map_err(|error| format!("the attach failed: {error}"))?
            .to_typed()
            .map_err(|error| format!("the attach result: {error}"))?;
        let mut view = Self {
            client,
            target,
            session_id,
            attachment_id: attached.attachment.attachment_id,
            lease: None,
            sequence: 0,
        };
        view.subscribe().await?;
        if input {
            let acquired: InputAcquireResult = view
                .client
                .mutate(
                    Method::InputAcquire,
                    ActionId::new(kr_ipc::new_uuid()),
                    view.target.clone(),
                    &InputAcquireParams {
                        session_id,
                        attachment_id: view.attachment_id,
                        expected_epoch: Nullable::null(),
                    },
                )
                .await
                .map_err(|error| format!("the input call: {error}"))?
                .map_err(|error| format!("the input lease was refused: {error}"))?
                .to_typed()
                .map_err(|error| format!("the input lease: {error}"))?;
            view.lease = Some(acquired.lease.epoch);
        }
        Ok(view)
    }

    /// Subscribes to output from wherever the session is now, which is also how a view answers a
    /// resynchronisation.
    async fn subscribe(&mut self) -> Result<(), String> {
        let mut streams = CanonicalSet::new();
        streams.insert(EventStream::Output);
        self.client
            .request(
                Method::EventsSubscribe,
                &EventsSubscribeParams {
                    session_id: self.session_id,
                    attachment_id: self.attachment_id,
                    streams,
                    from_cursor: Nullable::null(),
                },
            )
            .await
            .map_err(|error| format!("the subscribe call: {error}"))?
            .map_err(|error| format!("the subscription failed: {error}"))
            .map(|_| ())
    }

    /// Writes `bytes` as input, as a person typing them would.
    async fn type_in(&mut self, bytes: &[u8]) -> Result<(), String> {
        let epoch = self
            .lease
            .ok_or_else(|| "this view holds no input lease".to_owned())?;
        let params = InputWriteParams {
            session_id: self.session_id,
            attachment_id: self.attachment_id,
            epoch,
            sequence: InputSequence::new(self.sequence),
            bytes: Bytes::new(bytes.to_vec()),
        };
        self.sequence += 1;
        self.client
            .request(Method::InputWrite, &params)
            .await
            .map_err(|error| format!("the write call: {error}"))?
            .map_err(|error| format!("the write was refused: {error}"))
            .map(|_| ())
    }
}

/// What a reading view has received.
#[derive(Default)]
struct Progress {
    bytes: AtomicU64,
    resyncs: AtomicU64,
    ended: Mutex<Option<String>>,
}

/// A view that reads everything it is sent, as a terminal attached to a busy session does.
struct Reader {
    progress: Arc<Progress>,
    task: tokio::task::JoinHandle<()>,
}

impl Reader {
    fn spawn(mut view: View) -> Self {
        let progress = Arc::new(Progress::default());
        let counting = Arc::clone(&progress);
        let task = tokio::spawn(async move {
            let ended = loop {
                match view.client.recv().await {
                    Ok(ControlFrame::Notification(notification)) => {
                        match notification.event_type.as_str() {
                            "session.output" => {
                                if let Ok(event) = notification.payload.to_typed::<OutputEvent>() {
                                    counting.bytes.fetch_add(
                                        event.bytes.as_slice().len() as u64,
                                        Ordering::Relaxed,
                                    );
                                }
                            }
                            // A view that fell behind is told so, and answers by subscribing again
                            // from where the session is now, as a terminal does.
                            "session.resync" => {
                                counting.resyncs.fetch_add(1, Ordering::Relaxed);
                                if let Err(failure) = view.subscribe().await {
                                    break format!(
                                        "resubscribing after a resynchronisation: {failure}"
                                    );
                                }
                            }
                            _ => {}
                        }
                    }
                    Ok(_) => {}
                    Err(error) => break format!("the connection ended: {error}"),
                }
            };
            *counting
                .ended
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(ended);
        });
        Self { progress, task }
    }

    fn bytes(&self) -> u64 {
        self.progress.bytes.load(Ordering::Relaxed)
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The plugin host, serving one binding of the fixture package.
struct PluginHost {
    pid: u32,
    label: String,
    _client: PluginClient,
    _fence: HostFence,
}

/// The supervisor the plugin host is started through: the host tree's own, so the tree's teardown
/// counts it among what it ends. It keeps the job's label, which its retirement needs.
struct Supervised {
    inner: Box<dyn WorkerSupervisor>,
    label: Arc<Mutex<Option<String>>>,
}

impl HostSupervisor for Supervised {
    fn start(&self, plan: &HostLaunchPlan) -> HostStartOutcome {
        let launch = ServiceLaunch {
            label: plan.label.clone(),
            program: plan.program.clone(),
            arguments: plan.arguments.clone(),
            jobs_directory: plan.jobs_directory.clone(),
            working_directory: plan.working_directory.clone(),
        };
        *self.label.lock().unwrap_or_else(PoisonError::into_inner) = Some(plan.label.clone());
        match self.inner.start_service(&launch) {
            LaunchOutcome::Started(identity) => HostStartOutcome::Started(identity),
            LaunchOutcome::NotStarted { detail } => HostStartOutcome::NotStarted { detail },
            LaunchOutcome::Uncertain { detail, pid } => HostStartOutcome::Uncertain { detail, pid },
        }
    }

    fn retire(&self, jobs_directory: &Path, label: &str) -> HostJobRetirement {
        match kr_controller::supervision::retire_service_job(jobs_directory, label) {
            JobRetirement::Gone => HostJobRetirement::Gone,
            JobRetirement::StillRunning => HostJobRetirement::StillRunning,
            JobRetirement::Unsettled(detail) => HostJobRetirement::Unsettled(detail),
        }
    }
}

impl PluginHost {
    /// Starts the plugin host with the fixture package installed and a binding of it answering, or
    /// says why it cannot be measured here.
    async fn start(host: &Host) -> Result<Result<(Self, String), String>, String> {
        let component = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/plugins/components/build")
            .join(format!("{COMPONENT}.wasm"));
        let Ok(wasm) = std::fs::read(&component) else {
            let reason = format!(
                "the fixture package is not built at {}; scripts/build-plugin-fixtures.sh builds it",
                component.display()
            );
            return if std::env::var("KR_REQUIRE_PLUGIN_FIXTURES").is_ok_and(|value| value == "1") {
                Err(reason)
            } else {
                Ok(Err(reason))
            };
        };
        let environment = host.temp.environment();
        // Owner-only: the plugin host refuses a packages directory anybody else could write to.
        let packages = environment.state_dir().join("packages");
        kr_ipc::paths::create_private_directory(&packages)
            .map_err(|error| format!("the packages directory: {error}"))?;
        let installed = packages.join(format!("{COMPONENT}.wasm"));
        std::fs::write(&installed, &wasm)
            .map_err(|error| format!("the fixture package is installed: {error}"))?;
        let source = ComponentSource {
            path: installed.display().to_string(),
            digest: PayloadDigest::of(&wasm),
            bytes: wasm.len() as u64,
        };
        let label = Arc::new(Mutex::new(None));
        let supervisor: Arc<dyn HostSupervisor> = Arc::new(Supervised {
            inner: host.temp.supervisor(Box::new(DetachedSupervisor::new())),
            label: Arc::clone(&label),
        });
        let (descriptor, fence) = launcher::start(
            &environment,
            &host.plugin_host,
            &packages,
            &supervisor,
            LIVENESS,
        )
        .await
        .map_err(|error| format!("the plugin host did not start: {error}"))?;
        let pid = u32::try_from(descriptor.process_start_identity.pid.get())
            .map_err(|_| "the plugin host's process identifier".to_owned())?;
        let label = label
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .unwrap_or_default();
        let deadline = Instant::now() + LIVENESS;
        let client = loop {
            match PluginClient::connect(&environment).await {
                Ok(client) => break client,
                Err(error) if Instant::now() >= deadline => {
                    return Err(format!(
                        "the plugin host never accepted a connection: {error}"
                    ));
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        };
        let started = Self {
            pid,
            label,
            _client: client,
            _fence: fence,
        };
        let binding = new_binding_id();
        let plugin_id = PluginId::new(format!("kalareach/{COMPONENT}"))
            .map_err(|error| format!("a plugin identifier: {error}"))?;
        started
            ._client
            .register(
                binding,
                &PluginIdentity::new(
                    plugin_id,
                    PackageVersion::parse("1.0.0")
                        .map_err(|error| format!("a version: {error}"))?,
                    source.digest,
                    RepositoryGeneration::new(1),
                ),
                &BindingFacts {
                    plugin_id: format!("kalareach/{COMPONENT}"),
                    binding_revision: 1,
                    activity: BindingActivity::Running,
                    thread_id: None,
                    turn_id: None,
                    updated_at_ms: 0,
                    held_rights: Vec::new(),
                },
                "/bin/sh",
                &source,
            )
            .await
            .map_err(|error| format!("the fixture package's binding: {error}"))?;
        for index in 0..8 {
            let handle = SourceEventHandle::new(format!("se-{index}"))
                .map_err(|error| format!("an event handle: {error}"))?;
            started
                ._client
                .deliver(
                    binding,
                    &ScopedSourceEvent::new(
                        handle,
                        SourceProvenance::TerminalScrape,
                        0,
                        None,
                        b"output".to_vec(),
                    ),
                )
                .await
                .map_err(|error| format!("an event for the binding: {error}"))?;
        }
        let answered = started
            ._client
            .snapshot(binding, Duration::from_secs(5))
            .await
            .map_err(|error| format!("the binding's snapshot: {error}"))?
            .answered();
        if !answered {
            return Err("the fixture package's binding did not answer a snapshot".to_owned());
        }
        Ok(Ok((
            started,
            format!(
                "the fixture package {COMPONENT}, one binding registered, sent eight events and answering"
            ),
        )))
    }

    /// Ends the plugin host by the process identifier this run recorded, and what the service
    /// manager keeps of it.
    fn end(self, environment: &EnvironmentPaths) {
        let _ = std::process::Command::new("/bin/kill")
            .arg("-KILL")
            .arg(self.pid.to_string())
            .status();
        let deadline = Instant::now() + Duration::from_secs(10);
        while process::resident_kib(&[self.pid]).is_ok() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ =
            kr_controller::supervision::retire_service_job(&environment.jobs_dir(), &self.label);
        let _ = launcher::retire_descriptor(environment);
    }
}

/// The processes of the host, by what they are.
#[derive(Default)]
struct Processes {
    /// Each writing session's worker, the one the slow observer is attached to first.
    workers: Vec<u32>,
    /// Each writing session's shell and the program it runs.
    applications: Vec<u32>,
    /// The workers and root programs of the echoing session and the two probes.
    others: Vec<u32>,
    /// The probe at its prompt, and the probe whose shell runs a command.
    at_prompt: u32,
    holding: u32,
    /// The group of one writing session's foreground command.
    foreground_group: Option<u32>,
}

impl Processes {
    fn all(&self, plugin_host: Option<u32>) -> Vec<u32> {
        let mut all: Vec<u32> = std::iter::once(std::process::id())
            .chain(self.workers.iter().copied())
            .chain(self.applications.iter().copied())
            .chain(self.others.iter().copied())
            .chain(plugin_host)
            .collect();
        all.sort_unstable();
        all.dedup();
        all
    }
}

/// The root program and the worker of a session.
fn root_and_worker(created: &SessionCreateResult) -> Result<(u32, u32), String> {
    let root = created
        .session
        .root_process
        .as_ref()
        .ok_or_else(|| "every live session names its root process".to_owned())?;
    let root = u32::try_from(root.pid.get()).map_err(|_| "a process identifier".to_owned())?;
    let worker = process::parent_of(root)
        .ok_or_else(|| format!("the process table names the worker of root program {root}"))?;
    Ok((root, worker))
}

/// Sends keystrokes to the echoing session with KR-PERF-001's method and returns the sorted
/// samples and the host's conditions while they were taken.
async fn keystrokes(
    endpoint: Endpoint,
    target: ActionTarget,
    session_id: SessionId,
) -> Result<(Vec<Duration>, record::Conditions), String> {
    let mut view = View::attach_at(&endpoint, target, session_id, true).await?;
    // The root program says it is reading, and whatever the attachment was sent while it joined
    // stops arriving, before anything is timed.
    let mut seen = Vec::new();
    let deadline = Instant::now() + LIVENESS;
    while !seen.windows(9).any(|window| window == b"kr-ready.") {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, view.client.recv()).await {
            Ok(Ok(ControlFrame::Notification(notification)))
                if notification.event_type.as_str() == "session.output" =>
            {
                if let Ok(event) = notification.payload.to_typed::<OutputEvent>() {
                    seen.extend_from_slice(event.bytes.as_slice());
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) => return Err(format!("the echoing session's connection: {error}")),
            Err(_) => return Err("the echoing root program never said it was reading".to_owned()),
        }
    }
    let quiet_by = Instant::now() + Duration::from_secs(30);
    loop {
        match tokio::time::timeout(Duration::from_millis(500), view.client.recv()).await {
            Err(_) => break,
            Ok(Err(error)) => return Err(format!("the echoing session's connection: {error}")),
            Ok(Ok(_)) if Instant::now() >= quiet_by => {
                return Err("the echoing session's opening output never stopped".to_owned());
            }
            Ok(Ok(_)) => {}
        }
    }

    let epoch = view
        .lease
        .ok_or_else(|| "the keystrokes' view holds the input lease".to_owned())?;
    let window = record::Window::open();
    let mut samples = Vec::with_capacity(KEYSTROKES);
    for sequence in 0..KEYSTROKES {
        let params = InputWriteParams {
            session_id,
            attachment_id: view.attachment_id,
            epoch,
            sequence: InputSequence::new(sequence as u64),
            bytes: Bytes::new(b"x".to_vec()),
        };
        let request_id = RequestId::new((1 << 32) + sequence as u64);
        let encoded = ParamsValue::from_typed(&params)
            .map_err(|error| format!("the write did not encode: {error}"))?;
        // Written rather than asked, because the answer and the echo arrive on the same connection
        // in either order, and the figure is the time to the echo.
        let started = Instant::now();
        view.client
            .writer()
            .write_message(&ControlFrame::Request(Request {
                request_id,
                method: Method::InputWrite.into(),
                method_version: MethodVersion::V1,
                params: encoded,
            }))
            .await
            .map_err(|error| format!("the write did not reach the worker: {error}"))?;
        let mut answered = false;
        let mut echoed = None;
        while !answered || echoed.is_none() {
            let frame = tokio::time::timeout(Duration::from_secs(10), view.client.recv())
                .await
                .map_err(|_| format!("keystroke {sequence}'s answer or echo never arrived"))?
                .map_err(|error| format!("the connection ended: {error}"))?;
            match frame {
                ControlFrame::Response(response) if response.request_id == request_id => {
                    let Outcome::Ok(value) = response.outcome else {
                        return Err(format!("keystroke {sequence} was refused"));
                    };
                    let accepted: InputWriteResult = value
                        .to_typed()
                        .map_err(|error| format!("the answer did not decode: {error}"))?;
                    if accepted.forwarded_bytes.get() != 1 {
                        return Err(format!(
                            "a single ordinary byte was forwarded whole: {} forwarded",
                            accepted.forwarded_bytes.get()
                        ));
                    }
                    answered = true;
                }
                ControlFrame::Notification(notification)
                    if notification.event_type.as_str() == "session.output" =>
                {
                    let event: OutputEvent = notification
                        .payload
                        .to_typed()
                        .map_err(|error| format!("the output did not decode: {error}"))?;
                    if echoed.is_none() && !event.bytes.as_slice().is_empty() {
                        echoed = Some(started.elapsed());
                    }
                }
                ControlFrame::Response(response) => {
                    return Err(format!(
                        "an answer to request {} arrived while keystroke {sequence} was in flight",
                        response.request_id
                    ));
                }
                _ => {}
            }
        }
        samples.extend(echoed);
    }
    let conditions = window.close();
    samples.sort_unstable();
    Ok((samples, conditions))
}

/// The percentile of a sorted sample set, by nearest rank, as KR-PERF-001's is read.
fn percentile(sorted: &[Duration], fraction: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    #[expect(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a rank inside a sample set of a thousand is exact in both directions"
    )]
    let rank = (sorted.len() as f64 * fraction).ceil() as usize;
    sorted[rank.max(1).min(sorted.len()) - 1]
}

fn median(values: &mut [u64]) -> u64 {
    values.sort_unstable();
    values.get(values.len() / 2).copied().unwrap_or_default()
}

/// What the assertions are made on, once everything this run started has been ended.
struct Figures {
    samples: Vec<Duration>,
    resync: Option<ResyncReason>,
    resumed: bool,
    stalled: Vec<String>,
    failed_views: Vec<String>,
    not_live: Vec<SessionId>,
}

/// Section 27's stress run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs for several minutes by design; scripts/bench-all.sh runs it"]
async fn fifty_sessions_with_sustained_output() {
    let host = host().await;
    let mut run = Run::default();
    let measured = stress(&host, &mut run).await;
    let ended = run.end(&host).await;
    let figures = measured.unwrap_or_else(|failure| panic!("the measurement: {failure}"));
    ended.unwrap_or_else(|failure| panic!("what this measurement started: {failure}"));

    let p95 = percentile(&figures.samples, 0.95);
    let p99 = percentile(&figures.samples, 0.99);
    assert!(
        figures.not_live.is_empty(),
        "every session was still live at the end of the window: {:?} were not",
        figures.not_live
    );
    assert!(
        figures.failed_views.is_empty(),
        "every reading view kept its connection: {:?}",
        figures.failed_views
    );
    assert!(
        figures.stalled.is_empty(),
        "every reading view received output in every interval: {:?}",
        figures.stalled
    );
    assert_eq!(
        figures.resync,
        Some(ResyncReason::SendQueueFull),
        "the observer that stopped reading was told to resynchronise because its queue was full"
    );
    assert!(
        figures.resumed,
        "the observer received output again once it had resubscribed"
    );
    assert!(
        p95 < P95_BOUND && p99 < P99_BOUND,
        "input latency under the stress is within section 27's bounds: p95 {p95:?}, p99 {p99:?}"
    );
    let _ = &host.controller;
}

#[expect(
    clippy::too_many_lines,
    reason = "one measurement, read top to bottom in the order it is taken"
)]
async fn stress(host: &Host, run: &mut Run) -> Result<Figures, String> {
    // The sessions: fifty that write, one the keystrokes go to, and the two probes.
    let shell = "/bin/sh";
    let mut writing = Vec::with_capacity(SESSIONS);
    for _ in 0..SESSIONS {
        writing.push(run.create(host, shell).await?);
    }
    let echo_root = host.echo_root.display().to_string();
    let echoing = run.create(host, &echo_root).await?;
    let at_prompt = run.create(host, shell).await?;
    let holding = run.create(host, shell).await?;

    // Each writing session is given its program by a view that then reads everything it is sent.
    let mut readers = Vec::with_capacity(SESSIONS);
    for (index, created) in writing.iter().enumerate() {
        let rate = if index == 0 { FAST_RATE } else { RATE };
        let mut view = View::attach(host, created, true).await?;
        view.type_in(format!("'{}' {rate}\n", host.writer.display()).as_bytes())
            .await?;
        readers.push(Reader::spawn(view));
    }
    // The probes differ only in whether a command holds the terminal.
    let prompt_view = View::attach(host, &at_prompt, true).await?;
    let mut holding_view = View::attach(host, &holding, true).await?;
    holding_view.type_in(b"sleep 100000\n").await?;

    let deadline = Instant::now() + LIVENESS;
    loop {
        let quiet: Vec<usize> = (0..readers.len())
            .filter(|&index| readers[index].bytes() < WRITING)
            .collect();
        if quiet.is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "sessions {quiet:?} had not started writing {LIVENESS:?} after being told to"
            ));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Every process, by what it is.
    let mut processes = Processes::default();
    for created in &writing {
        let (shell, worker) = root_and_worker(created)?;
        let programs = process::children_of(shell);
        if programs.is_empty() {
            return Err(format!("shell {shell} runs no program"));
        }
        processes.workers.push(worker);
        processes.applications.push(shell);
        processes.applications.extend(programs.iter().copied());
        if processes.foreground_group.is_none() {
            processes.foreground_group = programs.first().copied();
        }
    }
    for created in [&echoing, &at_prompt, &holding] {
        let (root, worker) = root_and_worker(created)?;
        processes.others.push(root);
        processes.others.push(worker);
        processes.others.extend(process::children_of(root));
    }
    processes.at_prompt = root_and_worker(&at_prompt)?.1;
    processes.holding = root_and_worker(&holding)?.1;

    // The plugin host, serving a fixture package beside the sessions.
    let plugin = PluginHost::start(host).await?;
    let (plugin_pid, serving) = match plugin {
        Ok((started, serving)) => {
            let pid = started.pid;
            run.plugin = Some(started);
            (Some(pid), serving)
        }
        Err(reason) => (None, format!("not measured: {reason}")),
    };

    // The observer that stops reading, on the session that writes fastest.
    let slow = View::attach(host, &writing[0], false).await?;

    // The window.
    let all = processes.all(plugin_pid);
    let window = record::Window::open();
    let started = Instant::now();
    let spent_before = process::processor_seconds(&all)?;
    let mut resident_peak: BTreeMap<u32, u64> = BTreeMap::new();
    let mut product_peak = 0_u64;
    let mut host_peak = 0_u64;
    let mut last_resident = BTreeMap::new();
    let mut previous: Vec<u64> = readers.iter().map(Reader::bytes).collect();
    let received_at_start = previous.clone();
    let mut least = u64::MAX;
    let mut stalled = Vec::new();
    let mut latency: Option<std::thread::JoinHandle<Result<_, String>>> = None;
    while started.elapsed() < WINDOW {
        tokio::time::sleep(SAMPLE.min(WINDOW.saturating_sub(started.elapsed()))).await;
        let resident = process::resident_kib(&all)?;
        let product: u64 = std::iter::once(std::process::id())
            .chain(processes.workers.iter().copied())
            .chain(processes.others.iter().copied())
            .filter_map(|pid| resident.get(&pid))
            .sum();
        product_peak = product_peak.max(product);
        host_peak = host_peak.max(resident.values().sum());
        for (&pid, &kib) in &resident {
            let peak = resident_peak.entry(pid).or_default();
            *peak = (*peak).max(kib);
        }
        last_resident = resident;
        for (index, reader) in readers.iter().enumerate() {
            let now = reader.bytes();
            let gained = now.saturating_sub(previous[index]);
            least = least.min(gained);
            if gained == 0 {
                stalled.push(format!(
                    "session {index} received nothing in the {SAMPLE:?} before {:.0} s",
                    started.elapsed().as_secs_f64()
                ));
            }
            previous[index] = now;
        }
        // The keystrokes, a quarter of the way in, on a runtime of their own so that nothing this
        // process does for the reading views is in their figure.
        if latency.is_none() && started.elapsed() >= WINDOW / 4 {
            let endpoint = Endpoint::from_path(
                echoing
                    .endpoint
                    .as_ref()
                    .ok_or_else(|| "the echoing session has an endpoint".to_owned())?,
            )
            .map_err(|error| format!("the echoing session's endpoint: {error}"))?;
            let target = host.target(echoing.session.session_id);
            let session_id = echoing.session.session_id;
            latency = Some(std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| format!("a runtime for the keystrokes: {error}"))?
                    .block_on(keystrokes(endpoint, target, session_id))
            }));
        }
    }
    let elapsed = started.elapsed();
    let spent_after = process::processor_seconds(&all)?;
    let conditions = window.close();
    let received: Vec<u64> = readers.iter().map(Reader::bytes).collect();
    let (samples, keystroke_conditions) = match latency {
        Some(handle) => tokio::task::spawn_blocking(move || handle.join())
            .await
            .map_err(|error| format!("the keystrokes' thread: {error}"))?
            .map_err(|_| "the keystrokes' thread panicked".to_owned())??,
        None => return Err("the keystrokes never started".to_owned()),
    };

    // What one look through a foreground's processes costs on this host now, as the adoption
    // watch would read it, timed by enumerating one writing session's foreground group.
    let look = processes.foreground_group.map(|group| {
        let timed = Instant::now();
        let mut read = 0;
        for _ in 0..LOOKS {
            read = kr_ipc::identity::processes_in_group(group).map_or(0, |found| found.len());
        }
        (timed.elapsed() / LOOKS, read)
    });
    let on_host = process::count().unwrap_or_default();

    // Every session still live, and every reading view still reading.
    let not_live: Vec<SessionId> = {
        let listed = listed(&host.daemon()?, false).await?;
        run.sessions
            .iter()
            .copied()
            .filter(|session_id| {
                !listed
                    .iter()
                    .any(|(listed, state)| listed == session_id && *state == SessionState::Live)
            })
            .collect()
    };
    let failed_views: Vec<String> = readers
        .iter()
        .enumerate()
        .filter_map(|(index, reader)| {
            reader
                .progress
                .ended
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
                .map(|ended| format!("session {index}: {ended}"))
        })
        .collect();
    let resyncs: u64 = readers
        .iter()
        .map(|reader| reader.progress.resyncs.load(Ordering::Relaxed))
        .sum();

    // The observer that stopped reading reads what it was sent, finds the marker, and resubscribes.
    let mut slow = slow;
    let mut unread = 0_u64;
    let mut marker: Option<ResyncRequired> = None;
    let deadline = Instant::now() + LIVENESS;
    while marker.is_none() && Instant::now() < deadline {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, slow.client.recv()).await {
            Ok(Ok(ControlFrame::Notification(notification))) => {
                match notification.event_type.as_str() {
                    "session.output" => {
                        if let Ok(event) = notification.payload.to_typed::<OutputEvent>() {
                            unread += event.bytes.as_slice().len() as u64;
                        }
                    }
                    "session.resync" => {
                        marker = notification.payload.to_typed::<ResyncRequired>().ok();
                    }
                    _ => {}
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(_)) | Err(_) => break,
        }
    }
    let mut resumed_in = None;
    if let Some(marker) = &marker {
        let asked = Instant::now();
        slow.subscribe().await?;
        let deadline = asked + LIVENESS;
        while resumed_in.is_none() && Instant::now() < deadline {
            let left = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(left, slow.client.recv()).await {
                Ok(Ok(ControlFrame::Notification(notification)))
                    if notification.event_type.as_str() == "session.output" =>
                {
                    if let Ok(event) = notification.payload.to_typed::<OutputEvent>()
                        && event.cursor.get() >= marker.cursor.get()
                        && !event.bytes.as_slice().is_empty()
                    {
                        resumed_in = Some(asked.elapsed());
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(_)) | Err(_) => break,
            }
        }
    }
    drop(slow);
    drop(prompt_view);
    drop(holding_view);

    // The figures.
    let spent = |pid: u32| -> f64 {
        spent_after.get(&pid).copied().unwrap_or_default()
            - spent_before.get(&pid).copied().unwrap_or_default()
    };
    let window_seconds = elapsed.as_secs_f64();
    let cores = |seconds: f64| seconds / window_seconds;
    let in_workers: f64 = processes.workers.iter().map(|&pid| spent(pid)).sum();
    let mut per_worker: Vec<f64> = processes.workers.iter().map(|&pid| spent(pid)).collect();
    per_worker.sort_by(f64::total_cmp);
    let in_applications: f64 = processes.applications.iter().map(|&pid| spent(pid)).sum();
    let in_this_process = spent(std::process::id());
    let watch = (spent(processes.holding) - spent(processes.at_prompt)) / window_seconds;
    let offered = (SESSIONS as u64 - 1) * RATE + FAST_RATE;
    let delivered: u64 = received
        .iter()
        .zip(&received_at_start)
        .map(|(now, before)| now - before)
        .sum();
    let mut worker_peaks: Vec<u64> = processes
        .workers
        .iter()
        .filter_map(|pid| resident_peak.get(pid).copied())
        .collect();
    let slow_worker_peak = resident_peak
        .get(&processes.workers[0])
        .copied()
        .unwrap_or_default();
    let median_worker_peak = median(&mut worker_peaks);
    let largest_worker_peak = worker_peaks.last().copied().unwrap_or_default();
    let applications_now: u64 = processes
        .applications
        .iter()
        .filter_map(|pid| last_resident.get(pid))
        .sum();
    let this_process_now = last_resident
        .get(&std::process::id())
        .copied()
        .unwrap_or_default();
    let workers_now: u64 = processes
        .workers
        .iter()
        .chain(processes.others.iter())
        .filter_map(|pid| last_resident.get(pid))
        .sum();
    let plugin_now = plugin_pid.and_then(|pid| last_resident.get(&pid).copied());
    let host_now: u64 = last_resident.values().sum();
    let kib = |value: u64| size(value * 1024);
    let configuration = format!(
        "{SESSIONS} sessions, each a shell whose foreground command writes terminal output at a \
         steady rate, {} a second in one and {} in each of the others, each with a view reading \
         everything it is sent; beside them a session the keystrokes go to and two probe sessions; \
         the figures are taken over {:.0} s",
        size(FAST_RATE),
        size(RATE),
        window_seconds
    );

    let p95 = percentile(&samples, 0.95);
    let p99 = percentile(&samples, 0.99);
    let mut lines = keystroke_conditions.lines();
    lines.push(format!(
        "  measurement       {KEYSTROKES} single-byte writes from a client on the session's own \
         local socket, each timed to the byte arriving back at that client after the application \
         echoed it, as KR-PERF-001 is measured, taken while {configuration}"
    ));
    lines.push(format!(
        "  samples           {}: median {}, p95 {}, p99 {}, worst {}",
        samples.len(),
        milliseconds(percentile(&samples, 0.5)),
        milliseconds(p95),
        milliseconds(p99),
        milliseconds(samples.last().copied().unwrap_or_default())
    ));
    lines.push(format!(
        "  target            p95 below {} and p99 below {}",
        milliseconds(P95_BOUND),
        milliseconds(P99_BOUND)
    ));
    lines.push(format!(
        "  verdict           {}",
        if samples.len() == KEYSTROKES && p95 < P95_BOUND && p99 < P99_BOUND {
            "the target is met under the stress on this host"
        } else {
            "the target is not met under the stress on this host"
        }
    ));
    record::report(
        RECORD,
        "KR-PERF-001 input latency under the 50-session stress",
        &lines,
    );

    let mut lines = conditions.lines();
    lines.push(format!("  measurement       {configuration}"));
    lines.push(format!(
        "  output            {} a second offered by the programs, {} delivered to the views; \
         {resyncs} resynchronisations of reading views",
        size(offered),
        per_second(delivered, elapsed)
    ));
    lines.push(format!(
        "  processor         workers {:.3} of one core in all ({:.4} the median worker, {:.4} the \
         busiest); shells and their programs {:.3}; this process {:.3}, which is the daemon and \
         also every reading view's client end",
        cores(in_workers),
        cores(
            per_worker
                .get(per_worker.len() / 2)
                .copied()
                .unwrap_or_default()
        ),
        cores(per_worker.last().copied().unwrap_or_default()),
        cores(in_applications),
        cores(in_this_process)
    ));
    lines.push(format!(
        "  adoption watch    a command holding the terminal costs {:.3} ms of processor a second \
         in one worker (the probe whose shell runs a command, less the probe at its prompt), {:.4} \
         of one core across the {SESSIONS} sessions; the workers here hold no connectors, so the \
         watch never reads through the foreground's processes",
        watch * 1000.0,
        watch * SESSIONS as f64
    ));
    lines.push(match look {
        Some((each, read)) => format!(
            "  a look's reading  enumerating one foreground group ({read} process{}) takes {} of \
             wall time here, with {on_host} processes on the host; a worker that holds a \
             connector reads it four times a second while a command has the terminal, which in \
             each of {SESSIONS} sessions would be {:.3} of one core",
            if read == 1 { "" } else { "es" },
            milliseconds(each),
            each.as_secs_f64() * 4.0 * SESSIONS as f64
        ),
        None => "  a look's reading  not read: no writing session's program was found".to_owned(),
    });
    lines.push(format!(
        "  resident          peak {} for the daemon and the workers ({} the median writing \
         session's worker, {} the largest), sampled every {:.0} s; the shells and their programs \
         {} at the end",
        kib(product_peak),
        kib(median_worker_peak),
        kib(largest_worker_peak),
        SAMPLE.as_secs_f64(),
        kib(applications_now)
    ));
    lines.push(
        "  bound             section 27 sets none for the stress run; KR-PERF-003's bounds are \
         for the idle configuration"
            .to_owned(),
    );
    record::report(
        RECORD,
        "KR-PERF-003 host resources under the 50-session stress",
        &lines,
    );

    let mut lines = conditions.lines();
    lines.push(format!(
        "  measurement       every process of the host at the end of the stress window: {configuration}"
    ));
    lines.push(format!(
        "  resident          {} in all, peak {}: this process (the daemon and the views' client \
         ends) {}, workers {}, shells and programs {}, plugin host {}",
        kib(host_now),
        kib(host_peak),
        kib(this_process_now),
        kib(workers_now),
        kib(applications_now),
        plugin_now.map_or_else(|| "not running".to_owned(), kib)
    ));
    lines.push(format!("  plugin host       {serving}"));
    lines.push("  description model not active in this run".to_owned());
    lines.push(
        "  bound             section 27 asks for this figure to be reported and sets no bound on it"
            .to_owned(),
    );
    record::report(
        RECORD,
        "KR-PERF-003 whole host with the plugin host serving, under the 50-session stress",
        &lines,
    );

    let resynchronised = marker.as_ref().map(|marker| marker.reason);
    let mut lines = conditions.lines();
    lines.push(format!(
        "  measurement       an observer attached to the session writing {} a second reads \
         nothing for the whole window, while {configuration}",
        size(FAST_RATE)
    ));
    lines.push(format!(
        "  observer          {}",
        match (&marker, resumed_in) {
            (Some(marker), Some(resumed)) => format!(
                "told to resynchronise ({:?}) after {} it had not read; it resubscribed and \
                 received output again {} later",
                marker.reason,
                size(unread),
                milliseconds(resumed)
            ),
            (Some(marker), None) => format!(
                "told to resynchronise ({:?}) after {} it had not read, and received no output \
                 after it resubscribed",
                marker.reason,
                size(unread)
            ),
            (None, _) => format!(
                "never told to resynchronise, after {} it had not read",
                size(unread)
            ),
        }
    ));
    lines.push(format!(
        "  everyone else     {}; the observed session's own reading view received {}",
        if stalled.is_empty() {
            format!(
                "every reading view received output in every {:.0} s interval, the least any \
                 received in one being {}",
                SAMPLE.as_secs_f64(),
                size(least)
            )
        } else {
            format!(
                "{} intervals in which a view received nothing",
                stalled.len()
            )
        },
        per_second(received[0] - received_at_start[0], elapsed)
    ));
    lines.push(format!(
        "  queue bound       the observer's worker peaked at {}, the median writing session's \
         worker at {}; a worker holds at most 8 MiB for a view before it resynchronises it",
        kib(slow_worker_peak),
        kib(median_worker_peak)
    ));
    lines.push(format!(
        "  verdict           {}",
        if resynchronised == Some(ResyncReason::SendQueueFull)
            && resumed_in.is_some()
            && stalled.is_empty()
            && failed_views.is_empty()
        {
            "the target is met: the slow observer resynchronised and stalled no one"
        } else {
            "the target is not met"
        }
    ));
    record::report(
        RECORD,
        "KR-PERF-007 a slow observer under the 50-session stress",
        &lines,
    );

    drop(readers);
    Ok(Figures {
        samples,
        resync: resynchronised,
        resumed: resumed_in.is_some(),
        stalled,
        failed_views,
        not_live,
    })
}
