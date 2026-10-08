//! A real plugin host process, beside a real worker session with a real shell.
//!
//! What these tests are for is the part that cannot be shown in one process: that a worker
//! draining a pseudo-terminal is not behind a component that has stopped responding, that a
//! component that never returns costs its own binding and nothing else, and that a host started
//! through the launcher runs in a directory of its own with no secret in its arguments.
//!
//! The host here is started by the launcher over a supervisor of this suite's own, which stands in
//! for the control daemon. That the daemon starts it, lazily and outside its own kill tree, that a
//! host which ends takes no worker with it and is started again, and that a daemon which restarts
//! finds the host it left, are shown against a real daemon in
//! `crates/kr-controller/tests/plugin_runtime.rs`.
//!
//! Every path is on the internal disk and the plugin host is copied there before it is started. A
//! process a service manager launches has its own privacy identity to the operating system, and one
//! that reaches a removable volume asks the person at the machine for permission; a test suite must
//! never do that.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kr_controller::supervision::{
    DetachedSupervisor, JobRetirement, LaunchOutcome, ServiceLaunch, WorkerSupervisor,
};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::WorkerIdentity;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::identity::PluginIdentity;
use kr_plugin_sdk::version::PackageVersion;
use kr_plugin_service::client::{PluginClient, new_binding_id};
use kr_plugin_service::launcher::{
    self, HostJobRetirement, HostLaunchPlan, HostStartOutcome, HostSupervisor,
};
use kr_plugin_service::protocol::{ComponentSource, HostDescriptor};
use kr_plugin_service::vocabulary::{
    BindingActivity, BindingFacts, BindingId, ScopedSourceEvent, SourceProvenance,
};
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
};
use kr_protocol::envelope::{ActionTarget, ControlFrame};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, BuildId, ControllerGeneration, PluginId, RepositoryGeneration, SessionEpoch,
    SessionId, SourceEventHandle,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

/// The environment variable that makes an unbuilt component set a failure.
const REQUIRE_FIXTURES: &str = "KR_REQUIRE_PLUGIN_FIXTURES";

/// How long a plugin host is given to report itself.
const RENDEZVOUS_DEADLINE: Duration = Duration::from_secs(30);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// Loads one built test component, or says why the test cannot run.
fn component(name: &str) -> Option<Vec<u8>> {
    let directory =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugins/components/build");
    if !directory.is_dir() {
        let required = std::env::var(REQUIRE_FIXTURES).is_ok_and(|value| value == "1");
        assert!(
            !required,
            "{REQUIRE_FIXTURES}=1 and the test components are not built; run scripts/build-plugin-fixtures.sh"
        );
        eprintln!(
            "skipping: the test components are not built. Run scripts/build-plugin-fixtures.sh"
        );
        return None;
    }
    let path = directory.join(format!("{name}.wasm"));
    Some(std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "the component build directory exists and {} is not in it: {error}",
            path.display()
        )
    }))
}

/// A host tree on the internal disk, with the plugin host executable beside it.
struct Host {
    temp: kr_ipc::testing::TempHost,
    plugin_host: PathBuf,
    packages: PathBuf,
}

impl Host {
    fn create() -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        // Copied to the internal disk before it is started. The build tree may be on a removable
        // volume, and a launched process that reaches one prompts the person at the machine.
        let plugin_host = temp.root().join("kr-plugin-host");
        kr_ipc::testing::place_program(
            std::path::Path::new(env!("CARGO_BIN_EXE_kr-plugin-host")),
            &plugin_host,
        );
        // Owner-only: it holds the payloads this host compiles, and the host refuses a packages
        // directory anybody else could write to.
        let packages = temp.environment().state_dir().join("packages");
        kr_ipc::paths::create_private_directory(&packages).expect("the packages directory");
        Self {
            temp,
            plugin_host,
            packages,
        }
    }

    fn environment(&self) -> kr_ipc::paths::EnvironmentPaths {
        self.temp.environment()
    }

    /// Puts a component in the packages directory and returns how a worker names it.
    fn install(&self, name: &str, wasm: &[u8]) -> ComponentSource {
        let path = self.packages.join(format!("{name}.wasm"));
        std::fs::write(&path, wasm).expect("the component is installed");
        ComponentSource {
            path: path.display().to_string(),
            digest: PayloadDigest::of(wasm),
            bytes: wasm.len() as u64,
        }
    }

    /// Starts a plugin host through the platform's own service manager.
    async fn start_plugin_host(&self) -> Started {
        let recorded: Arc<std::sync::Mutex<Option<ServiceLaunch>>> =
            Arc::new(std::sync::Mutex::new(None));
        let seen: Arc<std::sync::Mutex<Option<u32>>> = Arc::new(std::sync::Mutex::new(None));
        let supervisor: Arc<dyn HostSupervisor> = Arc::new(Recorded {
            recorded: Arc::clone(&recorded),
            seen: Arc::clone(&seen),
        });
        let outcome = launcher::start(
            &self.environment(),
            &self.plugin_host,
            &self.packages,
            &supervisor,
            RENDEZVOUS_DEADLINE,
        )
        .await;
        let launch = recorded
            .lock()
            .expect("the recording")
            .clone()
            .expect("a launch plan");
        match outcome {
            Ok((descriptor, fence)) => Started {
                descriptor,
                launch: Some(launch),
                fence: Some(fence),
            },
            Err(error) => {
                // A host that failed before it had a connection has one place to say why: the
                // job's diagnostics file in the owner-only state directory. Whatever the service
                // manager left behind is booted out before this test gives up, so a failure does
                // not leave a job loaded on the machine.
                let diagnostics = format!(
                    "{}\n{}\nlaunched process: {}",
                    self.diagnostics(),
                    job_state(&launch.label),
                    launched_state(seen.lock().ok().and_then(|slot| *slot))
                );
                retire_job(&launch.label);
                panic!("the plugin host did not start and report itself: {error}\n{diagnostics}");
            }
        }
    }

    /// Returns whatever the started jobs wrote to their diagnostics files.
    fn diagnostics(&self) -> String {
        let Ok(entries) = self.environment().jobs_dir().read_dir() else {
            return "no job definitions were written".to_owned();
        };
        let mut seen = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|kind| kind == "diagnostics") {
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                seen.push(format!(
                    "{}: {}",
                    path.display(),
                    if text.trim().is_empty() {
                        "(nothing)"
                    } else {
                        text.trim()
                    }
                ));
            }
        }
        if seen.is_empty() {
            "no diagnostics were written".to_owned()
        } else {
            seen.join("\n")
        }
    }

    async fn plugin_client(&self) -> PluginClient {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match PluginClient::connect(&self.environment()).await {
                Ok(client) => return client,
                Err(error) => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the plugin host never accepted a connection: {error}"
                    );
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
}

/// The supervisor these tests start a plugin host through, recording what it was asked to start
/// and the process it reported.
///
/// The detached supervisor, deliberately, and not the platform's choice. All three supervisors go
/// through the same trait and the same launcher, and this is the one a headless macOS or
/// non-systemd Unix host uses. The alternative here would bootstrap jobs into the operator's own
/// login domain, which is not something a test should do to the machine it ran on. A job is
/// retired the way the daemon retires one, which for the detached supervisor finds nothing to take
/// away.
struct Recorded {
    recorded: Arc<std::sync::Mutex<Option<ServiceLaunch>>>,
    seen: Arc<std::sync::Mutex<Option<u32>>>,
}

impl HostSupervisor for Recorded {
    fn start(&self, plan: &HostLaunchPlan) -> HostStartOutcome {
        let launch = ServiceLaunch {
            label: plan.label.clone(),
            program: plan.program.clone(),
            arguments: plan.arguments.clone(),
            jobs_directory: plan.jobs_directory.clone(),
            working_directory: plan.working_directory.clone(),
        };
        if let Ok(mut slot) = self.recorded.lock() {
            *slot = Some(launch.clone());
        }
        match DetachedSupervisor::new().start_service(&launch) {
            LaunchOutcome::Started(identity) => {
                if let Ok(mut slot) = self.seen.lock() {
                    *slot = u32::try_from(identity.pid.get()).ok();
                }
                HostStartOutcome::Started(identity)
            }
            LaunchOutcome::NotStarted { detail } => HostStartOutcome::NotStarted { detail },
            LaunchOutcome::Uncertain { detail, pid } => HostStartOutcome::Uncertain { detail, pid },
        }
    }

    fn retire(&self, jobs_directory: &std::path::Path, label: &str) -> HostJobRetirement {
        match kr_controller::supervision::retire_service_job(jobs_directory, label) {
            JobRetirement::Gone => HostJobRetirement::Gone,
            JobRetirement::StillRunning => HostJobRetirement::StillRunning,
            JobRetirement::Unsettled(detail) => HostJobRetirement::Unsettled(detail),
        }
    }
}

/// A plugin host that is running, and the job it was started as.
///
/// Ending it is the whole of the cleanup, and it happens on drop so that a failing assertion does
/// not leave a service manager holding a job whose executable this test is about to delete.
struct Started {
    descriptor: HostDescriptor,
    launch: Option<ServiceLaunch>,
    /// Held for the host's life: it keeps the reservation's endpoint this launcher's, so a second
    /// claim on it is refused rather than accepted by somebody else's listener.
    fence: Option<launcher::HostFence>,
}

impl Started {
    fn pid(&self) -> u32 {
        u32::try_from(self.descriptor.process_start_identity.pid.get())
            .expect("a process identifier")
    }

    /// Returns how many second claims this launch's reservation has refused.
    fn duplicate_claims(&self) -> u64 {
        self.fence
            .as_ref()
            .map_or(0, launcher::HostFence::duplicate_claims)
    }

    fn label(&self) -> &str {
        self.launch
            .as_ref()
            .map_or("", |launch| launch.label.as_str())
    }

    fn launch(&self) -> &ServiceLaunch {
        self.launch.as_ref().expect("a recorded launch plan")
    }

    /// Kills the host, by the process identifier this test recorded and no other.
    fn kill(&self) {
        let pid = self.pid();
        let killed = std::process::Command::new("/bin/kill")
            .arg("-KILL")
            .arg(pid.to_string())
            .status();
        assert!(
            killed.is_ok_and(|status| status.success()),
            "process {pid} could not be ended"
        );
    }
}

impl Drop for Started {
    fn drop(&mut self) {
        if alive(self.pid()) {
            let _ = std::process::Command::new("/bin/kill")
                .arg("-KILL")
                .arg(self.pid().to_string())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        retire_job(self.label());
    }
}

/// Returns what the operating system says about a launched process, for a failure that needs it.
fn launched_state(pid: Option<u32>) -> String {
    let Some(pid) = pid else {
        return "the launcher reported none".to_owned();
    };
    let output = std::process::Command::new("/bin/ps")
        .args([
            "-o",
            "pid=,ppid=,pgid=,state=,command=",
            "-p",
            &pid.to_string(),
        ])
        .output();
    match output {
        Ok(output) if output.status.success() && !output.stdout.is_empty() => {
            format!("{pid}: {}", String::from_utf8_lossy(&output.stdout).trim())
        }
        Ok(_) => format!("{pid}: gone"),
        Err(error) => format!("{pid}: unreadable: {error}"),
    }
}

/// Returns what the service manager says about one job, for a failure that needs explaining.
fn job_state(label: &str) -> String {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("/bin/launchctl")
            .arg("print")
            .arg(format!("gui/{}/{label}", kr_ipc::paths::current_uid()))
            .output();
        match output {
            Ok(output) => format!(
                "launchctl print {label}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(error) => format!("launchctl print {label} failed: {error}"),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        format!("no job state is collected for {label} on this platform")
    }
}

/// Unloads one job from the platform's service manager, by its exact label.
///
/// A job that stays loaded after its executable has been deleted is litter on the machine this
/// test ran on, and enough of them make the next run behave differently.
fn retire_job(label: &str) {
    if label.is_empty() {
        return;
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("/bin/launchctl")
            .arg("bootout")
            .arg(format!("gui/{}/{label}", kr_ipc::paths::current_uid()))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "reset-failed", label])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = label;
    }
}

/// Returns true when a process is still running.
///
/// A process this test started and then killed stays in the process table until somebody reaps it,
/// and this test never waits on its children, so a signal check alone would report a dead process
/// as alive for ever. The state is what settles it: `Z` is a process that has ended and is waiting
/// to be collected.
fn alive(pid: u32) -> bool {
    let Ok(output) = std::process::Command::new("/bin/ps")
        .args(["-o", "state=", "-p", &pid.to_string()])
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let state = String::from_utf8_lossy(&output.stdout);
    let state = state.trim();
    !state.is_empty() && !state.starts_with('Z')
}

/// A worker session in this process, with a real shell in a real pseudo-terminal.
struct WorkerSession {
    _service: Arc<WorkerService>,
    _runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
}

/// A shell that prints a numbered line and then sleeps, so its output is observable and ordered.
///
/// The number is what makes output fresh rather than merely present: a test that waited during a
/// component call and saw a line could have been seeing what was already buffered, and a line whose
/// number is higher than the last one seen before the call could not have been.
const COUNTING_SHELL: &str =
    "i=0; while [ $i -lt 900 ]; do echo kalareach-$i; i=$((i+1)); sleep 0.02; done";

/// The same, and it asks the terminal a question every time round and waits for the answer.
///
/// `ESC [ c` is a device-attributes query. Section 11 says the host answers it into the
/// application's own input and that answering never waits for a component, so a shell that stops
/// until it is answered is a shell whose output continuing is proof the answer arrived. The line
/// discipline is put in raw mode first, because a reply with no newline in it would otherwise sit
/// in the terminal's line buffer unread.
const ASKING_SHELL: &str = "stty -icanon -echo min 1 time 0 2>/dev/null; i=0; \
     while [ $i -lt 900 ]; do echo kalareach-$i; printf '\\033[c'; \
     answer=$(dd bs=1 count=9 2>/dev/null | tr -d '\\033'); echo \"answered-$i-$answer\"; \
     i=$((i+1)); sleep 0.02; done";

impl WorkerSession {
    /// Opens a session whose shell prints a numbered line and then sleeps.
    fn open(host: &Host) -> Self {
        Self::running(host, COUNTING_SHELL)
    }

    /// Opens a session running one shell command.
    fn running(host: &Host, script: &str) -> Self {
        let environment = host.environment();
        let environment_id = host.temp.environment_id();
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let process =
            kr_ipc::identity::current_process_start_identity().expect("a process identity");
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
        // A public key, not a controller. These tests never present a generation token, and
        // opening the environment's real secret store would write into the operating system's own
        // keychain, which a test has no business doing.
        let controller =
            kr_crypto::keys::AuthorisationKeyPair::generate().expect("a controller keypair");

        let config = SessionConfig {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: DisplayNumber::new(1),
            shell: ShellCommand {
                program: "/bin/sh".to_owned(),
                arguments: vec!["-c".to_owned(), script.to_owned()],
                cwd: "/".to_owned(),
                environment: vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
            },
            shell_mode: ShellMode::NativeCompat,
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: DesktopBinding::none(),
            dimensions: Dimensions::new(80, 24),
            journal_path: Some(environment.journal_database(session_id)),
            spool_directory: Some(environment.session_spool(session_id)),
            worker_endpoint: None,
            send_queue_bytes: 1024 * 1024,
            resident_bytes: 1024 * 1024,
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
                    boot_identity: boot,
                    controller_public_key: *controller.public(),
                    controller_generation: ControllerGeneration::new(1),
                    build_id: build(),
                    journal_path: Some(environment.journal_database(session_id)),
                },
            )
            .expect("a worker service"),
        );
        tokio::spawn(Arc::clone(&service).serve(listener));
        Self {
            _service: service,
            _runtime: runtime,
            session_id,
            environment_id,
            endpoint,
        }
    }

    /// Attaches a terminal and subscribes it to output.
    async fn attach(&self) -> LocalClient {
        let mut client = LocalClient::connect(&self.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects to the worker");
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        let attached: SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget {
                    environment_id: self.environment_id,
                    session_id: Nullable::some(self.session_id),
                    session_epoch: Nullable::some(SessionEpoch::V1),
                    application_instance_id: Nullable::null(),
                    agent_binding_revision: Nullable::null(),
                },
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
            .expect("the attach succeeds")
            .to_typed()
            .expect("decodes");
        let mut streams = CanonicalSet::new();
        streams.insert(EventStream::Output);
        client
            .request(
                Method::EventsSubscribe,
                &EventsSubscribeParams {
                    session_id: self.session_id,
                    attachment_id: attached.attachment.attachment_id,
                    streams,
                    from_cursor: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the subscription succeeds");
        client
    }
}

/// Collects terminal output for `window`, returning what arrived.
async fn collect(client: &mut LocalClient, window: Duration) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + window;
    let mut seen = Vec::new();
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        let Ok(Ok(frame)) = tokio::time::timeout(remaining, client.recv()).await else {
            break;
        };
        if let ControlFrame::Notification(notification) = frame
            && notification.event_type.as_str() == "session.output"
            && let Ok(event) = notification
                .payload
                .to_typed::<kr_protocol::recovery::OutputEvent>()
        {
            seen.extend_from_slice(event.bytes.as_slice());
        }
    }
    seen
}

fn identity(plugin: &str, digest: PayloadDigest) -> PluginIdentity {
    PluginIdentity::new(
        PluginId::new(format!("kalareach/{plugin}")).expect("a bounded identifier"),
        PackageVersion::parse("1.0.0").expect("a semantic version"),
        digest,
        RepositoryGeneration::new(1),
    )
}

fn facts(plugin: &str) -> BindingFacts {
    BindingFacts {
        plugin_id: format!("kalareach/{plugin}"),
        binding_revision: 1,
        activity: BindingActivity::Running,
        thread_id: None,
        turn_id: None,
        updated_at_ms: 0,
        held_rights: Vec::new(),
    }
}

fn scrape(handle: &str, text: &str) -> ScopedSourceEvent {
    ScopedSourceEvent::new(
        SourceEventHandle::new(handle).expect("a bounded handle"),
        SourceProvenance::TerminalScrape,
        0,
        None,
        text.as_bytes().to_vec(),
    )
}

// A host the launcher starts runs in a directory of its own, is given no secret, and is the only
// process that holds its reservation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plugin_host_runs_in_a_directory_of_its_own_and_is_given_no_secret() {
    let host = Host::create();
    let environment = host.environment();
    let started = host.start_plugin_host().await;
    let pid = started.pid();

    assert!(
        !started
            .launch()
            .arguments
            .iter()
            .any(|argument| argument.contains("secret") || argument.contains("key")),
        "a secret reached the job definition"
    );

    // It serves: a worker connects, challenges it and gets an answer.
    let client = host.plugin_client().await;
    let health = client.health().await.expect("the host reports itself");
    assert_eq!(health.live_bindings, 0);

    // One reservation, one host. Nothing else claimed this one, and the launcher still holds the
    // endpoint a second claim would have to arrive on.
    assert_eq!(started.duplicate_claims(), 0);

    // And it runs in a directory of its own, inside the environment's state directory: a process a
    // service manager started would otherwise run in the system's directory, or in whatever
    // directory the daemon that started it was in, which on this host is a removable volume.
    let launch = started.launch.as_ref().expect("a launch plan");
    assert!(
        launch
            .working_directory
            .starts_with(environment.state_dir()),
        "the host runs in {}, which is outside {}",
        launch.working_directory.display(),
        environment.state_dir().display()
    );
    assert!(
        launch.working_directory.is_dir(),
        "the host's own directory was not made before it was started"
    );
    assert!(
        !launch.working_directory.starts_with("/Volumes"),
        "the host runs on a removable volume: {}",
        launch.working_directory.display()
    );

    // And the process is actually in it. The plan naming a directory would be satisfied by a
    // supervisor that never applied it, so the kernel is asked what the child's directory is.
    if let Some(running_in) = working_directory_of(pid) {
        assert_eq!(
            running_in.canonicalize().ok(),
            launch.working_directory.canonicalize().ok(),
            "the host is running in {}, not in {}",
            running_in.display(),
            launch.working_directory.display()
        );
    }

    started.kill();
    let _ = launcher::retire_descriptor(&environment);
}

// A component that never returns costs its own binding and nothing else: the worker's terminal goes
// on draining beside the process it is stuck in, and a second binding on the same host answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_component_that_never_returns_costs_its_own_binding_and_not_the_terminal_or_another_binding()
 {
    let Some(stuck) = component("infinite-loop") else {
        return;
    };
    let Some(well_behaved) = component("well-behaved") else {
        return;
    };
    let host = Host::create();
    let environment = host.environment();

    // A real worker session: a real shell, a real pseudo-terminal, a real journal.
    let session = WorkerSession::open(&host);
    let mut terminal = session.attach().await;

    // A real plugin host, started through the launcher.
    let started = host.start_plugin_host().await;
    let plugin = host.plugin_client().await;

    let stuck_component = host.install("infinite-loop", &stuck);
    let good_component = host.install("well-behaved", &well_behaved);

    let stuck_binding = new_binding_id();
    plugin
        .register(
            stuck_binding,
            &identity("infinite-loop", stuck_component.digest),
            &facts("infinite-loop"),
            "/bin/sh",
            &stuck_component,
        )
        .await
        .expect("the stuck binding registers");

    // The component is now spending every call running past its deadline, and the worker's terminal
    // keeps producing. What this shows is process isolation: the stuck component is in another
    // process and the session is unaffected by it. The measured claim about the terminal path is
    // the test below this one.
    for index in 0..8 {
        plugin
            .deliver(stuck_binding, &scrape(&format!("se-{index}"), "output"))
            .await
            .expect("the event is offered");
    }
    let output = collect(&mut terminal, Duration::from_millis(1_500)).await;
    let drained = String::from_utf8_lossy(&output);
    assert!(
        drained.contains("kalareach-"),
        "the terminal drained nothing while a component was stuck: {} bytes",
        output.len()
    );

    // A second binding that behaves is unaffected by the first one's state.
    let good_binding = new_binding_id();
    plugin
        .register(
            good_binding,
            &identity("well-behaved", good_component.digest),
            &facts("well-behaved"),
            "/bin/sh",
            &good_component,
        )
        .await
        .expect("the well-behaved binding registers");
    let snapshot = plugin
        .snapshot(good_binding, Duration::from_millis(500))
        .await
        .expect("the snapshot runs");
    assert!(snapshot.answered());

    started.kill();
    let _ = launcher::retire_descriptor(&environment);
}

// KR-REQ-11.39: the terminal path is never behind a component.
//
// Everything here is measured while a component is working, and what keeps it working is this
// test, not an amount of work sized for some machine. The binding is given observations at a
// steady pace until the test opens a gate, so the component goes on finishing calls through the
// whole window and after it, however fast or slow the machine is. That is continued activity, a
// short call after a short call, not one call that lasts the window. Each call is one short
// observation that ends far inside its deadline, so a slow machine does not overrun it. A machine
// that stalls outright can still hold a call past its deadline now and then, which the runtime
// records as a fault and the binding survives until three come within a minute; nothing here
// measures how long a call takes, so such a fault is not a failure. A disabled binding would leave
// a window with nothing running in it, so that fails the test, and whether it happened is read
// from the binding itself after the window, since disabling is final.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_39_a_terminal_drains_and_is_answered_while_a_component_runs() {
    let Some(well_behaved) = component("well-behaved") else {
        return;
    };
    let host = Host::create();
    let environment = host.environment();

    // A shell that asks the terminal a question every time round and stops until it is answered.
    let session = WorkerSession::running(&host, ASKING_SHELL);
    let mut terminal = session.attach().await;

    let started = host.start_plugin_host().await;
    let plugin = host.plugin_client().await;
    let installed = host.install("well-behaved", &well_behaved);
    let binding = new_binding_id();
    plugin
        .register(
            binding,
            &identity("well-behaved", installed.digest),
            &facts("well-behaved"),
            "/bin/sh",
            &installed,
        )
        .await
        .expect("the binding registers");
    let plugin = Arc::new(plugin);

    // Where the session had got to before the component was given anything to do.
    let before = collect(&mut terminal, Duration::from_millis(400)).await;
    let before = String::from_utf8_lossy(&before).into_owned();
    highest_line(&before).expect("the shell is producing numbered output");

    // The component's work, held open until the gate opens. Observations are handed over by the
    // path a worker's terminal loop uses, which waits for nothing: no frame is written and no
    // answer is read.
    let registered = finished_calls(&plugin).await;
    let (open, gate) = tokio::sync::oneshot::channel();
    let supplying = tokio::spawn(supply(Arc::clone(&plugin), binding, gate));

    // The component is at work once it has finished a call for one of those observations. Waiting
    // for that is what makes the window below a window with a component running in it.
    assert!(
        calls_finished_after(&plugin, registered).await,
        "the component never finished an observation"
    );

    // Now, with the component running, the session has to keep producing and the host has to keep
    // answering the shell's questions. A shell that was not answered would stop at its `dd` and
    // produce no higher-numbered line at all.
    // Everything the session had already produced is drained first, immediately before the window,
    // so a higher line number inside the window is output the shell produced during it rather than
    // output that was waiting in a buffer.
    let drained = collect(&mut terminal, Duration::from_millis(150)).await;
    let high_water = highest_line(&String::from_utf8_lossy(&drained))
        .or_else(|| highest_line(&before))
        .expect("the shell is producing numbered output");

    // The gate is shut for the whole of the window, so the component is being given observations
    // throughout it rather than for part of it. The call count is what turns that from an
    // expectation into evidence: it counts calls the component finished, so a count that grew
    // across the window is a component that was executing inside it.
    let window = std::time::Instant::now();
    let before_calls = finished_calls(&plugin).await;
    let during = collect(&mut terminal, Duration::from_millis(800)).await;
    let after_calls = finished_calls(&plugin).await;
    // Measured from before the first sample to after the second, so the bound below covers the
    // whole stretch the two samples bracket rather than the collection alone.
    let bracketed = window.elapsed();
    assert!(
        after_calls > before_calls,
        "the component finished no calls during the window: {before_calls} before, {after_calls} \
         after, so the terminal's progress was measured around nothing"
    );
    // The two samples bracket the collection and little else: a component that finished calls
    // between them finished them while the terminal was being collected from, not before or after
    // some much longer stretch.
    assert!(
        bracketed < Duration::from_millis(1_600),
        "the samples bracket {bracketed:?}, which is more than the collection they are for"
    );
    let during = String::from_utf8_lossy(&during).into_owned();
    let after = highest_line(&during).unwrap_or(0);
    assert!(
        after > high_water,
        "the terminal produced nothing new while a component was running: it was at \
         {high_water} before and {after} after"
    );
    let answers = during.matches("answered-").count();
    assert!(
        answers > 0 && during.contains("[?6"),
        "the host answered no device query while a component was running ({answers} answers)"
    );

    assert!(
        bracketed >= Duration::from_millis(800),
        "the window was shorter than it was asked to be"
    );

    // And the component was still at work when that window closed, rather than having stopped
    // partway through and left the rest of the window measuring nothing: with the gate still shut,
    // it goes on finishing calls after the window.
    assert!(
        calls_finished_after(&plugin, after_calls).await,
        "the component had stopped working before the window closed"
    );
    let health = plugin.health().await.expect("a health report");
    assert_eq!(
        health.live_bindings, 1,
        "the binding did not last the window this test measured"
    );
    assert_eq!(health.connection_bindings, 1);

    // The gate opens only now, and the component is given nothing more.
    let _ = open.send(());
    let taken = supplying.await.expect("the observations were supplied");
    // Handing an observation over waits for nothing, so it is quick every time but when the machine
    // stalls the whole test, which holds up only the one it happens to catch. A path that waited on
    // the runtime would be slow far more often than one time in a hundred.
    let bound = Duration::from_millis(50);
    let slow = taken.iter().filter(|took| **took >= bound).count();
    assert!(
        slow <= taken.len().div_ceil(100),
        "{slow} of {} observations took {bound:?} or more to hand over, more than one in a \
         hundred, so the terminal path waited on the runtime",
        taken.len()
    );

    // And what the terminal produced goes to the runtime by the same handoff, which is what a
    // worker's observation path does with its output.
    let handed_back = plugin.offer(binding, &scrape("se-drained", &during));
    assert!(
        matches!(
            handed_back,
            kr_plugin_service::client::Handoff::Accepted
                | kr_plugin_service::client::Handoff::Refused { .. }
        ),
        "the drained output could not be handed to the runtime: {handed_back:?}"
    );

    // And the binding was never disabled. That is read from the binding itself rather than from the
    // notices it sent, which go on arriving for as long as it runs: disabling is final, and a
    // disabled binding answers every call it is asked for by saying so before it runs anything, so
    // any other answer now comes from a binding that was not disabled at any point before, the
    // window included. How the call itself ends does not matter: one a stalled machine holds past
    // its deadline is a fault the binding survives, and a fault that does not disable it leaves a
    // component at work, which is all the window needs.
    let asking = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match plugin.snapshot(binding, Duration::from_secs(2)).await {
            Ok(_) | Err(kr_plugin_service::error::ServiceError::Protocol { .. }) => break,
            Err(kr_plugin_service::error::ServiceError::Disabled { reason }) => {
                panic!("the binding was disabled: {reason}")
            }
            Err(kr_plugin_service::error::ServiceError::CallerDeadline { .. })
                if std::time::Instant::now() < asking => {}
            Err(other) => panic!("the binding could not be asked for a call: {other}"),
        }
    }

    started.kill();
    let _ = launcher::retire_descriptor(&environment);
}

/// How often a binding is given an observation while a test holds its work open.
///
/// Often enough that a window of a few hundred milliseconds holds dozens of calls, and seldom
/// enough that the calls cost the machine little, which leaves few of them where a stalled machine
/// can hold one past its deadline.
const OBSERVATION_PACE: Duration = Duration::from_millis(10);

/// Gives a binding one observation each [`OBSERVATION_PACE`] until the gate opens, and returns how
/// long each took to hand over.
///
/// This is what holds a component's work open. Observations handed over in advance last as long as
/// the machine takes to work through them, which is a guess about the machine: on a fast one the
/// component finishes before a window closes, and a component given enough work in each call to
/// outlast a window on a fast one runs past its deadline on a slow one. Supplied until the test
/// says otherwise, the component has work for as long as the gate is shut, at any speed.
///
/// An observation is handed over by the path a worker's terminal loop uses, which waits for
/// nothing. A gate dropped without being opened ends the supply as well, so a test that fails
/// before it opens the gate leaves nothing running.
async fn supply(
    plugin: Arc<PluginClient>,
    binding: BindingId,
    mut gate: tokio::sync::oneshot::Receiver<()>,
) -> Vec<Duration> {
    let mut pace = tokio::time::interval(OBSERVATION_PACE);
    pace.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut taken = Vec::new();
    for index in 0_u64.. {
        tokio::select! {
            biased;
            _ = &mut gate => break,
            _ = pace.tick() => {}
        }
        let offered = std::time::Instant::now();
        let handed = plugin.offer(binding, &scrape(&format!("se-{index}"), "output"));
        taken.push(offered.elapsed());
        assert!(
            matches!(
                handed,
                kr_plugin_service::client::Handoff::Accepted
                    | kr_plugin_service::client::Handoff::Refused { .. }
            ),
            "an observation was handed over as {handed:?}"
        );
    }
    taken
}

/// Returns how many calls into a component this connection's bindings have finished.
async fn finished_calls(plugin: &PluginClient) -> u64 {
    plugin
        .health()
        .await
        .expect("a health report")
        .component_calls
}

/// Waits until this connection's bindings have finished more than `past` calls, and says whether
/// they did.
///
/// A liveness bound rather than a measurement: it fails when the calls never come, and a loaded
/// machine that takes a while is slow rather than broken.
async fn calls_finished_after(plugin: &PluginClient, past: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if finished_calls(plugin).await > past {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Returns the directory a running process is in, as the kernel reports it.
///
/// Nothing when this platform has no such tool, which is the only case this test skips. A tool that
/// is there and answers with something else is a failure rather than a reason to assert less.
fn working_directory_of(pid: u32) -> Option<PathBuf> {
    let tool = std::path::Path::new("/usr/sbin/lsof");
    if !tool.exists() {
        return None;
    }
    let output = std::process::Command::new(tool)
        .args(["-a", "-p", &pid.to_string(), "-d", "cwd", "-Fn"])
        .output()
        .expect("the tool that reports a process's directory runs");
    assert!(
        output.status.success(),
        "asking for process {pid}'s directory failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reported = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix('n').map(PathBuf::from));
    Some(reported.expect("the tool named the process's directory"))
}

/// Returns the highest `kalareach-N` in `text`, if there is one.
fn highest_line(text: &str) -> Option<u64> {
    text.match_indices("kalareach-")
        .filter_map(|(at, _)| {
            let rest = &text[at + "kalareach-".len()..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            digits.parse::<u64>().ok()
        })
        .max()
}
