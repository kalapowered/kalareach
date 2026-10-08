//! The plugin runtime as the product starts it: a real daemon, real workers with real shells, a
//! real plugin host process, and a package that ships a real component.
//!
//! Nothing here starts the plugin host but the daemon. A package whose package ships a component is
//! installed and enabled through the catalogue; a program it recognises runs in a session; the
//! worker binds the package, asks the daemon for the runtime, and registers the binding's
//! component with the process the daemon started. What the tests look at is what a person's host
//! has: the processes the supervisor was asked to start, the descriptor the daemon published, the
//! runtime's own report of what it holds, and what each worker reports of its bindings.
//!
//! Everything a launched process opens is on the internal disk, under the test's own tree, and the
//! three programs it launches (the worker, the plugin host and the stand-in agent) are copies placed
//! there. The test components are built by `scripts/build-plugin-fixtures.sh`.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{
    LaunchOutcome, ServiceLaunch, WorkerLaunch, WorkerSupervisor, detect,
};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::identity::ProcessState;
use kr_ipc::paths::EnvironmentPaths;
use kr_ipc::verify::ControllerIdentity;
use kr_plugin_catalogue::transport::RepositoryTransport;
use kr_plugin_catalogue::{
    CapabilityCeiling, Catalogue, Enrolment, InstallationGrant, RepositoryId, RepositoryKind,
};
use kr_plugin_service::client::PluginClient;
use kr_plugin_service::launcher;
use kr_plugin_service::protocol::HostHealth;
use kr_protocol::admission::{ComponentState, PluginRuntimeState, PluginRuntimeWanted};
use kr_protocol::envelope::{ActionTarget, ControlFrame};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId, PluginId, SessionEpoch, SessionId};
use kr_protocol::local::{LocalClientKind, LocalHello};
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{Presentation, SessionCreateParams, SessionCreateResult, ShellMode};

mod teardown;

/// The catalogue's own builder of signed generations, for a package this test writes.
#[allow(dead_code)]
#[path = "../../kr-plugin-catalogue/tests/support/mod.rs"]
mod generations;

/// How long a test waits for something the product does on its own. Generous, because a loaded
/// machine is slow and none of these waits is timed by the product itself.
const PATIENCE: Duration = Duration::from_secs(90);

/// The variable that makes a placed copy of this binary a program a person starts in a session: it
/// sleeps for as many seconds as it names.
const STAND_IN: &str = "KR_RUNTIME_STAND_IN";

/// The variable that names a file the stand-in writes its process identifier to once it runs.
const STAND_IN_RUNNING: &str = "KR_RUNTIME_STAND_IN_RUNNING";

/// The variable that makes the stand-in print a numbered line every so often while it runs.
const STAND_IN_TICKS: &str = "KR_RUNTIME_STAND_IN_TICKS";

/// The environment variable that makes an unbuilt component set a failure.
const REQUIRE_FIXTURES: &str = "KR_REQUIRE_PLUGIN_FIXTURES";

/// The stand-in program's body. Run by the test harness with nothing set, it does nothing.
#[test]
fn the_stand_in_program() {
    if let Ok(seconds) = std::env::var(STAND_IN) {
        if let Some(running) = std::env::var_os(STAND_IN_RUNNING) {
            std::fs::write(running, std::process::id().to_string()).expect("says it is running");
        }
        let until = std::time::Instant::now() + Duration::from_secs(seconds.parse().unwrap_or(60));
        // A program that keeps the terminal busy: a numbered line every so often, so what the
        // session shows after something happens can be told from what it had already shown.
        if std::env::var_os(STAND_IN_TICKS).is_some() {
            let mut tick = 0_u64;
            while std::time::Instant::now() < until {
                println!("tick-{tick}");
                tick += 1;
                std::thread::sleep(Duration::from_millis(50));
            }
        } else {
            std::thread::sleep(until.saturating_duration_since(std::time::Instant::now()));
        }
    }
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn plugin() -> PluginId {
    PluginId::new("kalareach/example-declarative").expect("an identifier")
}

/// Loads the built test component the package ships, or says why the test cannot run.
fn well_behaved() -> Option<Vec<u8>> {
    let directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugins/components/build");
    if !directory.is_dir() {
        let required = std::env::var(REQUIRE_FIXTURES).is_ok_and(|value| value == "1");
        assert!(
            !required,
            "{REQUIRE_FIXTURES}=1 and the test components are not built; run \
             scripts/build-plugin-fixtures.sh"
        );
        eprintln!(
            "skipping: the test components are not built. Run scripts/build-plugin-fixtures.sh"
        );
        return None;
    }
    Some(
        std::fs::read(directory.join("well-behaved.wasm"))
            .expect("the component build directory holds well-behaved.wasm"),
    )
}

/// Returns a program this workspace built, which sits beside this test's own binary.
fn beside_this_test(name: &str) -> PathBuf {
    let mut directory = std::env::current_exe().expect("the test binary");
    directory.pop();
    if directory.file_name().is_some_and(|name| name == "deps") {
        directory.pop();
    }
    let program = directory.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    assert!(
        program.is_file(),
        "this test starts {name} and there is none at {}; build it with `cargo build -p {name}`, or \
         run the whole workspace's tests, which build it",
        program.display()
    );
    program
}

fn directory_url(path: &Path) -> url::Url {
    url::Url::from_directory_path(std::fs::canonicalize(path).expect("an existing directory"))
        .expect("an absolute path")
}

/// Writes the example declarative package with `component` shipped in it, into `into`.
fn write_package(into: &Path, component: &[u8]) {
    let example = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/plugins/valid/example-declarative");
    std::fs::create_dir_all(into).expect("a package directory");
    std::fs::copy(
        example.join("presentation.json"),
        into.join("presentation.json"),
    )
    .expect("the presentation");
    let mut manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(example.join("plugin.json")).expect("the example manifest"),
    )
    .expect("a manifest");
    manifest["payloads"]
        .as_array_mut()
        .expect("the manifest lists its payloads")
        .push(serde_json::json!({
            "role": "component",
            "path": "component.wasm",
            "digest": kr_plugin_sdk::digest::PayloadDigest::of(component).to_string(),
            "size_bytes": component.len().to_string(),
        }));
    std::fs::write(
        into.join("plugin.json"),
        serde_json::to_vec_pretty(&manifest).expect("a manifest"),
    )
    .expect("the manifest");
    std::fs::write(into.join("component.wasm"), component).expect("the component");
}

/// What the daemon asked its supervisor to start.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Requested {
    /// A session's worker.
    Worker(SessionId),
    /// A service that is not a worker, by its job label.
    Service(String),
}

/// What the supervisor was asked to start, in order, with the process each start produced.
type Record = Arc<Mutex<Vec<(Requested, Option<ProcessStartIdentity>)>>>;

/// The tree's own supervisor, recording what it is asked to start, and the processes that came of
/// it.
#[derive(Debug)]
struct Recording {
    inner: Box<dyn WorkerSupervisor>,
    requested: Record,
}

impl Recording {
    fn note(&self, what: Requested, outcome: &LaunchOutcome) {
        let process = match outcome {
            LaunchOutcome::Started(identity) => Some(identity.clone()),
            _ => None,
        };
        self.requested
            .lock()
            .expect("the record is not poisoned")
            .push((what, process));
    }
}

impl WorkerSupervisor for Recording {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        let outcome = self.inner.start(launch);
        self.note(Requested::Worker(launch.session_id), &outcome);
        outcome
    }

    fn start_service(&self, launch: &ServiceLaunch) -> LaunchOutcome {
        let outcome = self.inner.start_service(launch);
        self.note(Requested::Service(launch.label.clone()), &outcome);
        outcome
    }

    fn describe(&self) -> &'static str {
        "the platform's supervisor, recording what it starts"
    }
}

/// Ends every plugin host the daemon started that is still running, by the identity it was
/// started under, before the tree that holds it goes. A host is not a worker, so the tree's own
/// teardown does not ask it to close.
///
/// A daemon in a process of its own is not seen by this test's supervisor, so the host it
/// published is ended too.
struct HostEnding {
    requested: Record,
    environment: EnvironmentPaths,
}

impl Drop for HostEnding {
    fn drop(&mut self) {
        let mut hosts: Vec<ProcessStartIdentity> = self
            .requested
            .lock()
            .map(|requested| {
                requested
                    .iter()
                    .filter(|(what, _)| matches!(what, Requested::Service(_)))
                    .filter_map(|(_, process)| process.clone())
                    .collect()
            })
            .unwrap_or_default();
        if let Ok(Some(published)) = launcher::read_descriptor(&self.environment) {
            hosts.push(published.process_start_identity);
        }
        for host in hosts {
            kill(&host);
        }
    }
}

/// The daemon this test started as a process of its own, in a process group of its own, ended
/// with that group however the test ends.
struct Apart {
    child: Option<std::process::Child>,
}

impl Apart {
    /// Ends the daemon and everything else in its group, as a terminal closing or a service
    /// manager stopping a unit that holds it would, and waits for it.
    fn end_with_its_group(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if let Some(group) = i32::try_from(child.id())
            .ok()
            .and_then(rustix::process::Pid::from_raw)
        {
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        }
        let _ = child.wait();
    }
}

impl Drop for Apart {
    fn drop(&mut self) {
        self.end_with_its_group();
    }
}

/// Ends a process the daemon started, by the identity it was started under, after checking that it
/// is still that process.
fn kill(process: &ProcessStartIdentity) {
    if kr_ipc::identity::process_state(process) != ProcessState::Running {
        return;
    }
    let pid = rustix::process::Pid::from_raw(i32::try_from(process.pid.get()).expect("a pid"))
        .expect("a process");
    let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
}

/// Stops a process that is running, as a signal from a terminal would, after checking that it is
/// still the process it was. It is not ended: it answers nothing until it is ended.
fn stop(process: &ProcessStartIdentity) {
    assert_eq!(
        kr_ipc::identity::process_state(process),
        ProcessState::Running,
        "the process is still the one it was"
    );
    let pid = rustix::process::Pid::from_raw(i32::try_from(process.pid.get()).expect("a pid"))
        .expect("a process");
    rustix::process::kill_process(pid, rustix::process::Signal::STOP).expect("stopped");
}

/// Waits until the kernel says `process` has ended.
async fn ended(process: &ProcessStartIdentity) {
    until("the process to end", || async {
        (kr_ipc::identity::process_state(process) == ProcessState::Ended).then_some(())
    })
    .await;
}

/// Asks `check` until it answers, or the patience runs out.
async fn until<T, Fut>(what: &str, mut check: impl FnMut() -> Fut) -> T
where
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        if let Some(found) = check().await {
            return found;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "waited {PATIENCE:?} for {what}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A person at a session's terminal: an attachment that holds the input lease and types.
struct Typist {
    client: LocalClient,
    session_id: SessionId,
    attachment_id: kr_protocol::ids::AttachmentId,
    epoch: kr_protocol::ids::InputLeaseEpoch,
    sequence: u64,
}

impl Typist {
    /// Types `text` into the terminal.
    async fn send(&mut self, text: &str) {
        self.client
            .request(
                Method::InputWrite,
                &kr_protocol::input::InputWriteParams {
                    session_id: self.session_id,
                    attachment_id: self.attachment_id,
                    epoch: self.epoch,
                    sequence: kr_protocol::ids::InputSequence::new(self.sequence),
                    bytes: kr_protocol::scalars::Bytes::new(text.as_bytes().to_vec()),
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the bytes reach the terminal");
        self.sequence += 1;
    }
}

/// A daemon hosting real workers over a catalogue whose package ships a component.
struct World {
    controller: Option<Arc<Controller>>,
    serving: Vec<tokio::task::JoinHandle<kr_controller::error::Result<()>>>,
    endpoint: kr_ipc::paths::Endpoint,
    environment_id: EnvironmentId,
    worker: PathBuf,
    /// The program the package recognises, placed on the internal disk.
    agent: PathBuf,
    requested: Record,
    /// How much of `requested` an earlier daemon of this tree made: what the current one was asked
    /// to start is what follows.
    counted_from: usize,
    _published: tempfile::TempDir,
    /// Before the hosts, so a daemon in a process of its own is gone before they are ended.
    apart: Apart,
    /// Before the tree, so every host the daemon started is ended before the tree goes.
    _hosts: HostEnding,
    /// Last: it ends every worker the daemon started.
    tree: teardown::Tree,
}

impl World {
    /// A world whose daemon runs in this process.
    async fn start(component: &[u8]) -> Self {
        let mut world = Self::prepare(component).await;
        world.run().await;
        world
    }

    /// A world whose daemon runs as a process of its own, in a group of its own, started with
    /// `services` selecting how it starts a service that is not a worker.
    async fn start_apart(component: &[u8], services: &str) -> Self {
        let mut world = Self::prepare(component).await;
        world.spawn_daemon(services).await;
        world
    }

    /// The tree, the three programs placed on it, and the package installed, with no daemon.
    async fn prepare(component: &[u8]) -> Self {
        let tree = teardown::Tree::create();
        // Placed on the internal disk and started once here, where nothing is timed. The runtime
        // is found beside the worker.
        let worker = tree.root().join("kr-worker");
        kr_ipc::testing::place_and_start_once(
            &beside_this_test("kr-worker"),
            &worker,
            &["--version"],
        );
        kr_ipc::testing::place_and_start_once(
            &beside_this_test("kr-plugin-host"),
            &tree
                .root()
                .join(format!("kr-plugin-host{}", std::env::consts::EXE_SUFFIX)),
            &["--version"],
        );
        let agent = tree.root().join("example-agent");
        kr_ipc::testing::place_and_start_once(
            &std::env::current_exe().expect("this test's own binary"),
            &agent,
            &["--exact", "the_stand_in_program", "--test-threads", "1"],
        );

        let published = tempfile::tempdir().expect("a directory on the internal disk");
        let package = published.path().join("package");
        write_package(&package, component);
        let generation = generations::Generation::build(
            published.path(),
            generations::GenerationSpec {
                package: Some(package),
                ..generations::GenerationSpec::default()
            },
        )
        .await;
        install(&tree, &generation).await;

        let requested = Arc::default();
        let environment = tree.environment();
        Self {
            controller: None,
            serving: Vec::new(),
            endpoint: environment.controller_endpoint().expect("an endpoint"),
            environment_id: tree.environment_id(),
            worker,
            agent,
            requested: Arc::clone(&requested),
            counted_from: 0,
            _published: published,
            apart: Apart { child: None },
            _hosts: HostEnding {
                requested,
                environment,
            },
            tree,
        }
    }

    /// Starts the daemon as a process of its own and waits until it answers.
    async fn spawn_daemon(&mut self, services: &str) {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.tree.root().join("daemon.log"))
            .expect("opens the daemon's log");
        let child = {
            use std::os::unix::process::CommandExt as _;
            std::process::Command::new(std::env::current_exe().expect("this test's own binary"))
                .args([
                    "--exact",
                    DAEMON_HALF,
                    "--include-ignored",
                    "--nocapture",
                    "--test-threads",
                    "1",
                ])
                .env(DAEMON_ROOT, self.tree.root())
                .env(DAEMON_WORKER, &self.worker)
                .env(DAEMON_SERVICES, services)
                .current_dir(self.tree.root())
                .stdin(std::process::Stdio::null())
                .stdout(log.try_clone().expect("duplicates the log"))
                .stderr(log)
                // A group of its own, so that ending it ends what is in the group and nothing of
                // this test.
                .process_group(0)
                .spawn()
                .unwrap_or_else(|error| panic!("the daemon starts: {error:?}"))
        };
        self.apart.child = Some(child);
        let endpoint = self.endpoint.clone();
        let root = self.tree.root().to_path_buf();
        until("the daemon to answer", || async {
            let found = LocalClient::connect(&endpoint, LocalClientKind::Cli, build()).await;
            if found.is_err() {
                assert!(
                    std::fs::read_to_string(root.join("daemon.log"))
                        .map_or(true, |log| !log.contains("panicked")),
                    "the daemon did not start: {}",
                    std::fs::read_to_string(root.join("daemon.log")).unwrap_or_default()
                );
            }
            found.ok()
        })
        .await;
    }

    fn environment(&self) -> EnvironmentPaths {
        self.tree.environment()
    }

    /// Starts the daemon on the tree, serving its clients and its workers' rendezvous.
    async fn run(&mut self) {
        let environment = self.environment();
        let environment_id = self.environment_id;
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
            supervisor: Box::new(Recording {
                inner: self.tree.supervisor(detect()),
                requested: Arc::clone(&self.requested),
            }),
            worker_program: self.worker.clone(),
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        })
        .await
        .expect("the daemon starts");
        let listener = Listener::bind(&self.endpoint).expect("binds the endpoint");
        self.serving.push(tokio::spawn(
            Arc::clone(&controller).serve_clients(listener),
        ));
        let rendezvous = Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
            .expect("binds the rendezvous");
        self.serving.push(tokio::spawn(
            Arc::clone(&controller).serve_rendezvous(rendezvous),
        ));
        self.controller = Some(controller);
    }

    /// Stops the daemon and starts another on the same tree, the way a restart of the host does:
    /// every durable record stays, nothing held in memory does, and the workers and the plugin
    /// runtime go on running. What the new daemon is asked to start is counted from here.
    async fn restart(&mut self) {
        for serving in self.serving.drain(..) {
            serving.abort();
            let _ = serving.await;
        }
        let controller = self.controller.take().expect("a daemon");
        until("the stopped daemon to be let go", || async {
            (Arc::strong_count(&controller) == 1).then_some(())
        })
        .await;
        drop(controller);
        self.counted_from = self
            .requested
            .lock()
            .expect("the record is not poisoned")
            .len();
        self.run().await;
    }

    fn controller(&self) -> &Arc<Controller> {
        self.controller.as_ref().expect("a daemon")
    }

    async fn client(&self) -> LocalClient {
        LocalClient::connect(&self.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects")
    }

    fn target(&self, session: Option<(SessionId, SessionEpoch)>) -> ActionTarget {
        ActionTarget {
            environment_id: self.environment_id,
            session_id: Nullable::from(session.map(|(session_id, _)| session_id)),
            session_epoch: Nullable::from(session.map(|(_, epoch)| epoch)),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    /// Creates a session with a real worker, and returns it once it is live.
    async fn session(&self) -> SessionCreateResult {
        self.client()
            .await
            .mutate(
                Method::SessionCreate,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(None),
                &SessionCreateParams {
                    environment_id: self.environment_id,
                    presentation: Presentation::Invisible,
                    shell: Nullable::some("/bin/sh".to_owned()),
                    shell_mode: ShellMode::NativeCompat,
                    cwd: Nullable::some(self.tree.root().display().to_string()),
                    dimensions: Nullable::null(),
                    worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                    environment_snapshot: Vec::new(),
                    palette: Nullable::null(),
                    launch_profile: kr_protocol::session::LaunchProfile::default(),
                    terminal: Nullable::null(),
                },
            )
            .await
            .expect("reaches the daemon")
            .expect("the session is created")
            .to_typed()
            .expect("decodes")
    }

    /// Attaches to a session's terminal as a person at it does, with the input lease. Returns the
    /// attachment, which types.
    async fn attach_typist(&self, created: &SessionCreateResult) -> Typist {
        let session = &created.session;
        let endpoint = self
            .environment()
            .worker_endpoint(session.display_number)
            .expect("the worker's endpoint");
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects to the session's worker");
        let target = self.target(Some((session.session_id, session.session_epoch)));
        let mut requested = kr_protocol::scalars::CanonicalSet::new();
        requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
        requested.insert(kr_protocol::attachment::AttachmentCapability::Input);
        let attached: kr_protocol::attachment::SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                target.clone(),
                &kr_protocol::attachment::SessionAttachParams {
                    session_id: session.session_id,
                    mode: kr_protocol::attachment::AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(kr_protocol::session::Dimensions::new(80, 24)),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the attachment is accepted")
            .to_typed()
            .expect("decodes");
        let acquired: kr_protocol::input::InputAcquireResult = client
            .mutate(
                Method::InputAcquire,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &kr_protocol::input::InputAcquireParams {
                    session_id: session.session_id,
                    attachment_id: attached.attachment.attachment_id,
                    expected_epoch: Nullable::null(),
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the lease is acquired")
            .to_typed()
            .expect("decodes");
        Typist {
            client,
            session_id: session.session_id,
            attachment_id: attached.attachment.attachment_id,
            epoch: acquired.lease.epoch,
            sequence: 0,
        }
    }

    /// Runs the program the package recognises in a session, and returns the attachment that typed
    /// it and the process once it is running. The worker finds the program in the terminal's
    /// foreground and binds the package to it.
    async fn run_agent(&self, created: &SessionCreateResult) -> (Typist, ProcessStartIdentity) {
        self.run_agent_with(created, "").await
    }

    /// [`Self::run_agent`], with `more` among the variables the program is started with.
    async fn run_agent_with(
        &self,
        created: &SessionCreateResult,
        more: &str,
    ) -> (Typist, ProcessStartIdentity) {
        let mut typing = self.attach_typist(created).await;
        let process = self.start_agent(&mut typing, more).await;
        (typing, process)
    }

    /// Types the program the package recognises at an attachment's prompt, and returns its process
    /// once it is running.
    async fn start_agent(&self, typing: &mut Typist, more: &str) -> ProcessStartIdentity {
        let running = self
            .tree
            .root()
            .join(format!("agent-running-{}", kr_ipc::new_uuid()));
        typing
            .send(&format!(
                "{STAND_IN}=300 {more} {STAND_IN_RUNNING}='{}' '{}' --exact \
                 the_stand_in_program --test-threads 1 --nocapture\n",
                running.display(),
                self.agent.display()
            ))
            .await;
        let pid = until("the program the line started to run", || async {
            std::fs::read_to_string(&running)
                .ok()
                .and_then(|said| said.trim().parse::<u32>().ok())
        })
        .await;
        kr_ipc::identity::process_start_identity(pid).expect("the program runs")
    }

    /// Asks the daemon for the plugin runtime in the name of `session_id`, as this test's own
    /// process, which no session's worker is.
    async fn ask_as_this_process(&self, session_id: SessionId) -> PluginRuntimeState {
        let rendezvous = self
            .environment()
            .rendezvous_endpoint()
            .expect("an endpoint");
        let connection = kr_ipc::endpoint::Connection::connect(&rendezvous)
            .await
            .expect("connects to the rendezvous endpoint");
        let (mut reader, mut writer) =
            kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
        writer
            .write_message(&ControlFrame::Hello(LocalHello {
                offered_versions: vec![PROTOCOL_VERSION],
                build_id: build(),
                client: LocalClientKind::Worker,
                capabilities: kr_protocol::scalars::CanonicalSet::new(),
                max_receive: kr_protocol::hello::ReceiveLimits::default(),
                origin: None,
            }))
            .await
            .expect("the hello is written");
        let acknowledged: ControlFrame = reader.read_message().await.expect("acknowledged");
        assert!(matches!(acknowledged, ControlFrame::HelloAck(_)));
        writer
            .write_message(&ControlFrame::PluginRuntimeWanted(PluginRuntimeWanted {
                session_id,
            }))
            .await
            .expect("the request is written");
        let answer: ControlFrame = reader.read_message().await.expect("answered");
        let ControlFrame::PluginRuntimeState(state) = answer else {
            panic!("the daemon answered {answer:?}");
        };
        state
    }

    /// What the daemon was asked to start, in order.
    fn requested(&self) -> Vec<Requested> {
        self.requested
            .lock()
            .expect("the record is not poisoned")
            .iter()
            .skip(self.counted_from)
            .map(|(what, _)| what.clone())
            .collect()
    }

    /// The services the daemon was asked to start.
    fn services(&self) -> Vec<String> {
        self.requested()
            .into_iter()
            .filter_map(|what| match what {
                Requested::Service(label) => Some(label),
                Requested::Worker(_) => None,
            })
            .collect()
    }

    /// The process identity the descriptor names, where a plugin runtime is published.
    fn published_host(&self) -> Option<ProcessStartIdentity> {
        launcher::read_descriptor(&self.environment())
            .ok()
            .flatten()
            .map(|descriptor| descriptor.process_start_identity)
    }

    /// What the plugin runtime says it holds, asked as a connection of this test's own, which the
    /// runtime counts across every connection in its `live_bindings`.
    async fn health(&self) -> Option<HostHealth> {
        let client = PluginClient::connect(&self.environment()).await.ok()?;
        client.health().await.ok()
    }

    /// Waits until the plugin runtime holds `bindings` bindings, and returns what it reports.
    async fn holding(&self, bindings: u64) -> HostHealth {
        until("the plugin runtime to hold the bindings", || async {
            self.health()
                .await
                .filter(|health| health.live_bindings == bindings)
        })
        .await
    }

    /// Where each worker's last report says a binding's component stands, after every worker has
    /// been asked again.
    async fn components(&self) -> Vec<(ComponentState, Option<String>)> {
        self.reported()
            .await
            .into_iter()
            .map(|(_, report)| (report.state, report.reason.0))
            .collect()
    }

    /// Every binding whose package ships a component, as the workers report it after each has
    /// been asked again, or nothing when a worker did not answer in time and the reports are the
    /// last ones accepted.
    async fn reported_fresh(
        &self,
    ) -> Option<
        Vec<(
            kr_protocol::ids::BrokerBindingId,
            kr_protocol::admission::ComponentReport,
        )>,
    > {
        let controller = self.controller();
        controller.refresh_admissions().await.then(|| {
            controller
                .reported_components()
                .into_iter()
                .map(|(_, binding_id, report)| (binding_id, report))
                .collect()
        })
    }

    /// Every binding whose package ships a component, as the workers last reported it after each
    /// has been asked again.
    async fn reported(
        &self,
    ) -> Vec<(
        kr_protocol::ids::BrokerBindingId,
        kr_protocol::admission::ComponentReport,
    )> {
        let controller = self.controller();
        controller.refresh_admissions().await;
        controller
            .reported_components()
            .into_iter()
            .map(|(_, binding_id, report)| (binding_id, report))
            .collect()
    }

    /// The worker of a session, as the daemon's registry records it, for a daemon this test does
    /// not run in its own process.
    fn worker_in_registry(&self, session_id: SessionId) -> ProcessStartIdentity {
        kr_ipc::descriptor::read_all(&self.environment())
            .expect("the worker descriptors are readable")
            .into_iter()
            .filter_map(|entry| entry.descriptor.ok())
            .find(|descriptor| descriptor.session_id == session_id)
            .expect("the worker published its descriptor")
            .process_start_identity
    }

    /// The worker the daemon started for a session, as the supervisor reported it.
    fn worker_of(&self, session_id: SessionId) -> ProcessStartIdentity {
        self.requested
            .lock()
            .expect("the record is not poisoned")
            .iter()
            .find_map(|(what, process)| match what {
                Requested::Worker(started) if *started == session_id => process.clone(),
                _ => None,
            })
            .expect("the supervisor reported the worker's process")
    }

    /// Attaches to a session's terminal and subscribes to its output.
    async fn observe(&self, created: &SessionCreateResult) -> LocalClient {
        let session = &created.session;
        let endpoint = self
            .environment()
            .worker_endpoint(session.display_number)
            .expect("the worker's endpoint");
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects to the session's worker");
        let mut requested = kr_protocol::scalars::CanonicalSet::new();
        requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
        let attached: kr_protocol::attachment::SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(Some((session.session_id, session.session_epoch))),
                &kr_protocol::attachment::SessionAttachParams {
                    session_id: session.session_id,
                    mode: kr_protocol::attachment::AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(kr_protocol::session::Dimensions::new(80, 24)),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the attachment is accepted")
            .to_typed()
            .expect("decodes");
        let mut streams = kr_protocol::scalars::CanonicalSet::new();
        streams.insert(kr_protocol::recovery::EventStream::Output);
        client
            .request(
                Method::EventsSubscribe,
                &kr_protocol::recovery::EventsSubscribeParams {
                    session_id: session.session_id,
                    attachment_id: attached.attachment.attachment_id,
                    streams,
                    from_cursor: Nullable::null(),
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the subscription succeeds");
        client
    }

    /// Waits until every binding the workers report has its component in `state`, and there are
    /// `count` of them.
    async fn components_are(
        &self,
        count: usize,
        state: ComponentState,
    ) -> Vec<(ComponentState, Option<String>)> {
        until("the workers to report the components", || async {
            let found = self.components().await;
            (found.len() == count && found.iter().all(|(reported, _)| *reported == state))
                .then_some(found)
        })
        .await
    }
}

/// Enrols the generation as the owner acting directly, synchronises it, and installs and enables
/// its package, before any daemon opens the catalogue.
async fn install(tree: &teardown::Tree, generation: &generations::Generation) {
    let environment = tree.environment();
    let published = generation.directory();
    let mut catalogue = Catalogue::open(
        &environment.state_dir().join("catalogue"),
        Arc::new(RepositoryTransport::local_only(
            "this test reads its repository from disk",
        )),
    )
    .expect("an openable catalogue");
    let id = RepositoryId::new("development").expect("an identifier");
    catalogue
        .enrol(
            Enrolment::new(
                id.clone(),
                RepositoryKind::Local,
                directory_url(&published.join("metadata")),
                directory_url(&published.join("targets")),
                std::fs::read(published.join("root.json")).expect("a trust root"),
                kr_plugin_sdk::limits::RepositoryBudgets::defaults(),
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrollable repository"),
            true,
        )
        .expect("the owner adopted the root");
    catalogue.sync(&id).await.expect("a generation");
    let version = kr_plugin_sdk::version::PackageVersion::parse("0.1.0").expect("a version");
    let digest = catalogue
        .index(&id)
        .expect("activated")
        .find(&plugin(), &version)
        .expect("the package")
        .manifest_digest;
    catalogue
        .install(
            &id,
            tree.environment_id(),
            &plugin(),
            &version,
            digest,
            InstallationGrant::none(),
        )
        .await
        .expect("installed");
    catalogue
        .set_enabled(tree.environment_id(), &plugin(), true)
        .await
        .expect("enabled");
}

/// KR-REQ-05.06 and KR-REQ-05.08: the plugin runtime is started by the daemon when a worker first
/// wants a component, and not before.
///
/// A session that runs nothing a package recognises, with the package installed and enabled and its
/// component admitted, leaves the supervisor asked for the worker and for nothing else, publishes no
/// runtime and has nothing listening for one. The first program the package recognises is what
/// starts it, as a job of its own beside the worker's, and the next session's binding is given the
/// same process rather than a second.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_plugin_runtime_starts_with_the_first_binding_that_wants_a_component_and_not_before() {
    let Some(component) = well_behaved() else {
        return;
    };
    let world = World::start(&component).await;
    let environment = world.environment();

    // The daemon has started, seeded nothing and been asked for nothing.
    assert!(world.published_host().is_none());
    assert!(world.services().is_empty());

    // A session with a worker and a shell, and a round of admissions answered by that worker: the
    // package is admitted to it, and nothing in it wants a component.
    let first = world.session().await;
    world.controller().refresh_admissions().await;
    assert_eq!(
        world.requested(),
        [Requested::Worker(first.session.session_id)],
        "the daemon was asked for the worker and nothing else"
    );
    assert!(world.published_host().is_none());
    assert!(
        PluginClient::connect(&environment).await.is_err(),
        "nothing is listening for a plugin runtime"
    );
    assert!(world.components().await.is_empty());

    // The program the package recognises runs, and its binding wants the component.
    let (_typing, _agent) = world.run_agent(&first).await;
    let health = world.holding(1).await;
    assert!(health.deadlines_enforceable);
    let services = world.services();
    assert_eq!(services.len(), 1, "{services:?}");
    assert!(services[0].starts_with("kr-plugin-host-"), "{services:?}");
    let host = world.published_host().expect("the runtime is published");
    world.components_are(1, ComponentState::Registered).await;

    // And it is a job of its own: the process the daemon's supervisor started is not in this
    // process's group, so a signal aimed at this process's group does not reach it. (Where the
    // platform has no service manager it is this process's child, in a group of its own.)
    assert_ne!(
        process_group(u32::try_from(host.pid.get()).expect("a pid")),
        process_group(std::process::id())
    );

    // A second session's binding is given the process that is running.
    let second = world.session().await;
    let (_typing_again, _agent_again) = world.run_agent(&second).await;
    world.holding(2).await;
    world.components_are(2, ComponentState::Registered).await;
    assert_eq!(world.services(), services, "no second runtime was started");
    assert_eq!(world.published_host(), Some(host));
}

/// Only the process the daemon recorded for a session can have the plugin runtime started for it.
///
/// Starting the runtime gives a requester no authority over anything, but it spends the daemon's
/// allowance of starts, so another process of the same user does not get to. This test's own
/// process asks in the name of a live session and of one nobody recorded, and is refused each time
/// with the reason and told when to ask again; nothing is started. The worker of the first session
/// is the control: it asks through the same endpoint in every other test here and is answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_process_that_is_not_a_sessions_worker_cannot_have_the_plugin_runtime_started() {
    let Some(component) = well_behaved() else {
        return;
    };
    let world = World::start(&component).await;
    let created = world.session().await;

    for (session_id, why) in [
        (
            created.session.session_id,
            "is not the worker this daemon recorded",
        ),
        (
            SessionId::new(kr_ipc::new_uuid()),
            "has not recorded that session's worker",
        ),
    ] {
        let PluginRuntimeState::Unavailable(told) = world.ask_as_this_process(session_id).await
        else {
            panic!("a process that is not the session's worker was told the runtime is running");
        };
        assert!(told.reason.contains(why), "{}", told.reason);
        assert!(told.retry_after_ms.get() > 0);
    }
    assert!(world.services().is_empty());
    assert!(world.published_host().is_none());
}

/// The group a process is in, as the operating system reports it.
fn process_group(pid: u32) -> u32 {
    let output = std::process::Command::new("/bin/ps")
        .args(["-o", "pgid=", "-p", &pid.to_string()])
        .output()
        .expect("lists the process");
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("a group")
}

/// How many updates of the screen a terminal has been sent, counted as they arrive.
///
/// The program the test runs prints a numbered line every moment, so the screen changes all the
/// time and every change is sent to an attached terminal. Counted all the time and not in windows:
/// a terminal that nobody reads for a while is resynchronised, and what a test then reads is the
/// resynchronisation. It stops reading when it is dropped.
struct Traffic {
    sent: Arc<std::sync::atomic::AtomicU64>,
    reading: tokio::task::JoinHandle<()>,
}

impl Traffic {
    fn watch(mut client: LocalClient) -> Self {
        let sent = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counted = Arc::clone(&sent);
        let reading = tokio::spawn(async move {
            while let Ok(frame) = client.recv().await {
                if let kr_protocol::envelope::ControlFrame::Notification(notification) = frame
                    && notification
                        .event_type
                        .as_str()
                        .starts_with("session.projection.")
                {
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        });
        Self { sent, reading }
    }

    /// How many updates have arrived so far.
    fn count(&self) -> u64 {
        self.sent.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for Traffic {
    fn drop(&mut self) {
        self.reading.abort();
    }
}

/// KR-REQ-05.07: a plugin runtime that ends with a registration unanswered takes no worker with it,
/// and its bindings come back.
///
/// A worker is running a program the package recognises, whose terminal changes every moment, in
/// the background of its session, and its binding is registered on the worker's connection to the
/// runtime. The runtime is stopped, which is what a runtime is that has hung: it is running and
/// answers nothing. A second program the package recognises is run in the same session; the worker
/// binds it and sends its registration on the connection it has, and that request is left
/// unanswered, which shows as the binding's report: pending, registering with the plugin runtime.
/// The runtime is then killed by the identity it was started under while that request is
/// outstanding. The worker and both programs go on, the terminal goes on being sent what it had not
/// been sent, both bindings are the same bindings, and the daemon starts a replacement under its
/// bound, which the worker registers both with again.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_plugin_runtime_that_ends_with_a_registration_unanswered_takes_no_worker_with_it_and_its_bindings_come_back()
 {
    let Some(component) = well_behaved() else {
        return;
    };
    let world = World::start(&component).await;
    let created = world.session().await;
    let traffic = Traffic::watch(world.observe(&created).await);
    let (mut typing, first_agent) = world
        .run_agent_with(&created, &format!("{STAND_IN_TICKS}=1"))
        .await;
    world.holding(1).await;
    world.components_are(1, ComponentState::Registered).await;
    let first_binding = world.reported().await[0].0;
    let host = world.published_host().expect("the runtime is published");

    // The first program goes to the background of the session, still printing, and the runtime
    // hangs. The second program is run at the prompt it leaves.
    typing.send("\u{1a}").await;
    typing.send("bg\n").await;
    stop(&host);
    let second_agent = world.start_agent(&mut typing, "").await;

    // The worker has bound it and sent the registration, and nothing answers it.
    let registering = |report: &kr_protocol::admission::ComponentReport| {
        report.state == ComponentState::Pending
            && report.reason.0.as_deref() == Some("registering with the plugin runtime")
    };
    let second_binding = until(
        "the second binding's registration to be sent and left unanswered",
        || async {
            world
                .reported()
                .await
                .into_iter()
                .find(|(binding, report)| *binding != first_binding && registering(report))
                .map(|(binding, _)| binding)
        },
    )
    .await;

    // The terminal goes on being sent updates while that request is unanswered, and the runtime
    // ends in the same look that finds both true: the registration is still outstanding then, and
    // a registration that had run out its limit and been sent again would not satisfy it.
    let sent = traffic.count();
    until(
        "the terminal to be sent updates while the registration is unanswered",
        || async {
            // A look the worker answered after it was asked, and not the last one accepted.
            let outstanding = world
                .reported_fresh()
                .await?
                .iter()
                .any(|(binding, report)| *binding == second_binding && registering(report));
            (outstanding && traffic.count() > sent + 20).then_some(())
        },
    )
    .await;
    kill(&host);
    ended(&host).await;

    // A replacement is the daemon's doing, on the worker's asking: a process that is not the first,
    // and the same two bindings registered with it.
    until("a replacement runtime to be published", || async {
        world
            .published_host()
            .filter(|published| *published != host)
    })
    .await;
    world.holding(2).await;
    world.components_are(2, ComponentState::Registered).await;
    assert_eq!(world.services().len(), 2, "{:?}", world.services());
    let bindings: Vec<_> = world
        .reported()
        .await
        .into_iter()
        .map(|(binding, _)| binding)
        .collect();
    assert!(bindings.contains(&first_binding) && bindings.contains(&second_binding));

    // And nothing else went with it: the worker, the programs, and the terminal, which is sent
    // updates it had not been sent before the runtime ended.
    assert_eq!(
        kr_ipc::identity::process_state(&world.worker_of(created.session.session_id)),
        ProcessState::Running
    );
    for agent in [&first_agent, &second_agent] {
        assert_eq!(
            kr_ipc::identity::process_state(agent),
            ProcessState::Running
        );
    }
    let after_the_end = traffic.count();
    until("the terminal to be sent updates after the end", || async {
        Some(traffic.count()).filter(|count| *count > after_the_end + 20)
    })
    .await;
}

/// KR-REQ-05.07: a plugin runtime that keeps ending is not started without end, and the workers
/// are told why.
///
/// The daemon starts at most five in ten minutes. The runtime is killed each time it is running;
/// after the fifth start the next request is answered that the runtime cannot be reached, and the
/// binding's component is reported unavailable with that reason, where it had been registered. A
/// program run after that, while the worker holds off for the time the daemon named, has its
/// binding told the same reason as soon as it is made, and not left pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_plugin_runtime_that_keeps_ending_is_started_five_times_and_the_binding_is_told_why() {
    let Some(component) = well_behaved() else {
        return;
    };
    let attempts = kr_controller::service::plugin_runtime::START_ATTEMPTS;
    let world = World::start(&component).await;
    let created = world.session().await;
    let (mut typing, agent) = world.run_agent(&created).await;
    world.holding(1).await;
    world.components_are(1, ComponentState::Registered).await;

    for started in 1..=attempts {
        assert_eq!(world.services().len(), started);
        let host = world.published_host().expect("the runtime is published");
        kill(&host);
        ended(&host).await;
        if started < attempts {
            until("a replacement runtime to be published", || async {
                world
                    .published_host()
                    .filter(|published| *published != host)
            })
            .await;
            world.holding(1).await;
            world.components_are(1, ComponentState::Registered).await;
        }
    }

    // The sixth is not started: the worker's binding says so.
    let reported = until(
        "the binding to be told the runtime is not started again",
        || async {
            world
                .components()
                .await
                .into_iter()
                .find(|(state, reason)| {
                    *state == ComponentState::Unavailable
                        && reason
                            .as_deref()
                            .is_some_and(|reason| reason.contains("not started again"))
                })
        },
    )
    .await;
    assert_eq!(reported.0, ComponentState::Unavailable);
    assert_eq!(world.services().len(), attempts);

    // A program run after that, while the worker holds off for the time the daemon named, is told
    // why its component is not registered as soon as it is bound, and not left pending.
    typing.send("\u{1a}").await;
    typing.send("bg\n").await;
    let _second_agent = world.start_agent(&mut typing, "").await;
    until("both bindings to be told why", || async {
        let found = world.components().await;
        (found.len() == 2
            && found.iter().all(|(state, reason)| {
                *state == ComponentState::Unavailable
                    && reason
                        .as_deref()
                        .is_some_and(|reason| reason.contains("not started again"))
            }))
        .then_some(())
    })
    .await;
    assert_eq!(world.services().len(), attempts);
    // And that cost the worker and its program nothing.
    assert_eq!(
        kr_ipc::identity::process_state(&world.worker_of(created.session.session_id)),
        ProcessState::Running
    );
    assert_eq!(
        kr_ipc::identity::process_state(&agent),
        ProcessState::Running
    );
}

/// KR-REQ-05.06: a daemon that restarts finds the plugin runtime where it was, and keeps it.
///
/// The runtime is a job of its own, so the daemon that started it can go. The workers hold their
/// connections to it directly, so their bindings are not interrupted, and a binding made after the
/// restart is given the same process: the new daemon looks for the runtime its predecessor
/// published, finds it answering, and starts nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_daemon_that_restarts_adopts_the_plugin_runtime_it_finds_and_starts_none() {
    let Some(component) = well_behaved() else {
        return;
    };
    let mut world = World::start(&component).await;
    let first = world.session().await;
    let (_typing, _agent) = world.run_agent(&first).await;
    world.holding(1).await;
    let host = world.published_host().expect("the runtime is published");

    world.restart().await;

    // The first binding stayed registered through the restart, with no daemon to ask.
    assert_eq!(world.published_host(), Some(host.clone()));
    world.holding(1).await;
    let second = world.session().await;
    let (_typing_again, _agent_again) = world.run_agent(&second).await;
    world.holding(2).await;
    world.components_are(2, ComponentState::Registered).await;
    assert_eq!(world.published_host(), Some(host));
    assert!(
        world.services().is_empty(),
        "the restarted daemon was asked to start {:?}",
        world.services()
    );
}

/// A binding that ends frees its place in the plugin runtime, and only its own.
///
/// One worker holds two bindings, which is two programs the package recognises in one session: the
/// first is put in the background and the second run in front of it. The first exits. The runtime
/// holds one binding then, the second's, which is still the same binding and still registered. A
/// session that has run its program and finished does not keep an instance of its component, which
/// a connection could otherwise be made to hold sixty-four of. What this does not show is that the
/// worker's connection to the runtime stayed the same one: the host reports no connections, and a
/// link that closed its connection and registered the other binding again would pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_binding_that_ends_is_unbound_in_the_plugin_runtime_and_the_other_is_left_registered() {
    let Some(component) = well_behaved() else {
        return;
    };
    let world = World::start(&component).await;
    let created = world.session().await;
    let (mut typing, first_agent) = world.run_agent(&created).await;
    world.holding(1).await;
    world.components_are(1, ComponentState::Registered).await;
    let first_binding = world.reported().await[0].0;

    // The first program is stopped from the terminal and continued in the background, and the
    // second is run at the prompt it leaves.
    typing.send("\u{1a}").await;
    typing.send("bg\n").await;
    let _second_agent = world.start_agent(&mut typing, "").await;
    world.holding(2).await;
    world.components_are(2, ComponentState::Registered).await;
    let second_binding = world
        .reported()
        .await
        .into_iter()
        .map(|(binding, _)| binding)
        .find(|binding| *binding != first_binding)
        .expect("a second binding");

    kill(&first_agent);
    ended(&first_agent).await;

    world.holding(1).await;
    world.components_are(1, ComponentState::Registered).await;
    let surviving = world.reported().await;
    assert_eq!(surviving.len(), 1);
    assert_eq!(
        surviving[0].0, second_binding,
        "the binding that is left is the one whose program is still running"
    );
}

/// Where the daemon half finds the tree it serves.
const DAEMON_ROOT: &str = "KR_RUNTIME_DAEMON_ROOT";

/// The worker executable the daemon half starts.
const DAEMON_WORKER: &str = "KR_RUNTIME_DAEMON_WORKER";

/// How the daemon half starts a service that is not a worker: `job` through the platform's own
/// service manager, as the product does, or `child` as an ordinary child of the daemon.
const DAEMON_SERVICES: &str = "KR_RUNTIME_DAEMON_SERVICES";

/// The name of the daemon half, as the test harness selects it.
const DAEMON_HALF: &str = "serve_a_control_daemon_for_the_runtime_test";

/// The daemon half: serves a control daemon for the tree `KR_RUNTIME_DAEMON_ROOT` names until it is
/// killed. It does nothing at all unless a test started it.
#[test]
#[ignore = "the daemon half of the kill-tree test, run only as that test's own child process"]
fn serve_a_control_daemon_for_the_runtime_test() {
    let (Some(root), Some(worker)) = (
        std::env::var_os(DAEMON_ROOT),
        std::env::var_os(DAEMON_WORKER),
    ) else {
        return;
    };
    let services = std::env::var(DAEMON_SERVICES).unwrap_or_default();
    let root = PathBuf::from(root);
    let worker = PathBuf::from(worker);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(async move {
            let paths = kr_ipc::paths::HostPaths::new(root.join("r"), root.join("s"))
                .expect("the host's roots");
            let environment_id = paths.open_environment_id().expect("the environment");
            let environment = paths.environment(environment_id);
            // A killed daemon's environment lock goes with its process; the start waits for the
            // kernel to let go of it, which is a liveness condition, not a measurement.
            let controller = kr_controller::testing::taken_over(|| {
                let secrets = environment.secrets_dir();
                Controller::start(ControllerSetup {
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
                    supervisor: if services == "child" {
                        Box::new(AsChild { inner: detect() })
                    } else {
                        detect()
                    },
                    worker_program: worker.clone(),
                    build_id: build(),
                    release: "0".to_owned(),
                    shell_packages: None,
                    terminal: Box::new(kr_controller::supervision::NoTerminal),
                })
            })
            .await
            .unwrap_or_else(|error| panic!("the daemon did not start: {error}"));
            let rendezvous =
                Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
                    .expect("binds the rendezvous");
            let clients = Listener::bind(&environment.controller_endpoint().expect("an endpoint"))
                .expect("binds the client endpoint");
            let serving = tokio::spawn(Arc::clone(&controller).serve_rendezvous(rendezvous));
            let _ = Arc::clone(&controller).serve_clients(clients).await;
            let _ = serving.await;
        });
}

/// A supervisor that starts a worker as the platform does and a service as an ordinary child of
/// the daemon, in the daemon's own process group: what a plugin runtime would be if the daemon did
/// not start it as a job of its own. The control for the kill-tree test.
#[derive(Debug)]
struct AsChild {
    inner: Box<dyn WorkerSupervisor>,
}

impl WorkerSupervisor for AsChild {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        self.inner.start(launch)
    }

    fn start_service(&self, launch: &ServiceLaunch) -> LaunchOutcome {
        match std::process::Command::new(&launch.program)
            .args(&launch.arguments)
            .current_dir(&launch.working_directory)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(child) => kr_controller::supervision::settle(child.id()),
            Err(error) => LaunchOutcome::NotStarted {
                detail: error.to_string(),
            },
        }
    }

    fn describe(&self) -> &'static str {
        "the platform's supervisor for a worker, and a child of the daemon for a service"
    }
}

/// KR-REQ-05.06: the plugin runtime is a job of its own, outside the daemon's kill tree.
///
/// The daemon is a process of its own in a group of its own, and a worker's binding is registered
/// with the runtime the daemon started. Everything in the daemon's group is killed, as it is when
/// what holds a daemon ends it. The runtime, the worker and the registration are as they were, and
/// a new daemon finds the runtime and is not asked to start another for the next binding.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_plugin_runtime_is_a_job_of_its_own_and_outlives_the_daemon_that_started_it() {
    let Some(component) = well_behaved() else {
        return;
    };
    let mut world = World::start_apart(&component, "job").await;
    let first = world.session().await;
    let (_typing, _agent) = world.run_agent(&first).await;
    world.holding(1).await;
    let host = world.published_host().expect("the runtime is published");
    let worker = world.worker_in_registry(first.session.session_id);

    world.apart.end_with_its_group();

    // Nothing of the daemon's group was the runtime, the worker, or the worker's registration.
    assert_eq!(
        kr_ipc::identity::process_state(&host),
        ProcessState::Running
    );
    assert_eq!(
        kr_ipc::identity::process_state(&worker),
        ProcessState::Running
    );
    world.holding(1).await;

    // A new daemon is asked for a runtime by the next binding, and the one that is running is the
    // one it finds.
    world.spawn_daemon("job").await;
    let second = world.session().await;
    let (_typing_again, _agent_again) = world.run_agent(&second).await;
    world.holding(2).await;
    assert_eq!(world.published_host(), Some(host));
}

/// The control for the test above: a plugin runtime that is an ordinary child of the daemon ends
/// with the daemon's group. If this did not end it, the test above would show nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_plugin_runtime_started_as_a_child_of_the_daemon_ends_with_the_daemons_group() {
    let Some(component) = well_behaved() else {
        return;
    };
    let mut world = World::start_apart(&component, "child").await;
    let created = world.session().await;
    let (_typing, _agent) = world.run_agent(&created).await;
    world.holding(1).await;
    let host = world.published_host().expect("the runtime is published");

    world.apart.end_with_its_group();

    ended(&host).await;
}
