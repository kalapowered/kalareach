//! The daemon's half of the plugin runtime on every platform the product ships on: a real daemon
//! starts a real plugin host through the platform's own way of starting a service, a worker's
//! request is the only thing that does it, and a host that ends is replaced without the worker
//! being touched.
//!
//! The worker here is this test process, which is how `barrier.rs` hosts one: the daemon's
//! supervisor reports this process as the worker it started, so the daemon records this process
//! for the session, and the request for the plugin runtime that the daemon answers only from the
//! process it recorded comes from the one process that is it. The component is registered with the
//! runtime by this process too, through the client a worker links. What the worker's own link does
//! with its broker is shown against real workers in `plugin_runtime.rs`, on the platforms that
//! adopt a program into a binding; the claims that depend on the platform are these:
//!
//! * the platform starts the host, and the host is not in this process's group, so what ends this
//!   process's group does not reach it (on Windows, a process outside this test's job);
//! * the endpoint a worker reaches the host on, a socket or a named pipe, is the one the daemon
//!   published, and the host answers a challenge on it;
//! * a component compiles and runs in the host on this platform;
//! * a host that is killed is replaced by the next request;
//! * a daemon that starts again finds the host it left and starts none.
//!
//! Everything a launched process opens is on the internal disk, under the test's own tree.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, ServiceLaunch, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::identity::ProcessState;
use kr_ipc::paths::EnvironmentPaths;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::identity::PluginIdentity;
use kr_plugin_sdk::ids::RepositoryGeneration;
use kr_plugin_sdk::version::PackageVersion;
use kr_plugin_service::client::{PluginClient, new_binding_id};
use kr_plugin_service::launcher;
use kr_plugin_service::protocol::ComponentSource;
use kr_plugin_service::vocabulary::{BindingActivity, BindingFacts};
use kr_protocol::admission::{PluginRuntimeState, PluginRuntimeWanted};
use kr_protocol::envelope::{ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, ProcessStartIdentity, WorkerProfile};
use kr_protocol::ids::{
    ActionId, BuildId, EnvironmentId, PluginId, RequestId, SessionEpoch, SessionId,
};
use kr_protocol::local::{LocalClientKind, LocalHello};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{DurationMs, Nullable};
use kr_protocol::session::{Dimensions, Presentation, SessionCreateParams, ShellMode};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

/// How long a test waits for something the product does on its own. Generous, because a loaded
/// machine is slow and none of these waits is timed by the product itself.
const PATIENCE: Duration = Duration::from_secs(120);

/// The environment variable that makes an unbuilt component set a failure.
const REQUIRE_FIXTURES: &str = "KR_REQUIRE_PLUGIN_FIXTURES";

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// The built test component, or why this test cannot run.
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
        "this test starts {name} and there is none at {}; build it with `cargo build -p {name}`",
        program.display()
    );
    program
}

/// What the daemon asked its supervisor to start that is not a worker, with the process each start
/// produced.
type Services = Arc<Mutex<Vec<(String, Option<ProcessStartIdentity>)>>>;

/// The daemon's supervisor: a worker is this process, and a service is started the way the
/// platform's daemon starts one.
///
/// Nothing is spawned for the worker: the rendezvous checks the connecting process against the
/// identity the launcher reported, so a test that performs the worker's side of the rendezvous
/// itself reports its own identity here.
#[derive(Debug)]
struct Supervisor {
    launched: Mutex<Option<std::sync::mpsc::Sender<WorkerLaunch>>>,
    services: Services,
    service: Box<dyn WorkerSupervisor>,
}

/// The supervisor a daemon is given, which a daemon started again on the same tree is given again.
#[derive(Debug)]
struct Handle(Arc<Supervisor>);

impl WorkerSupervisor for Handle {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        self.0.start(launch)
    }

    fn start_service(&self, launch: &ServiceLaunch) -> LaunchOutcome {
        self.0.start_service(launch)
    }

    fn describe(&self) -> &'static str {
        self.0.describe()
    }
}

impl WorkerSupervisor for Supervisor {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        if let Some(sender) = self
            .launched
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            let _ = sender.send(launch.clone());
        }
        LaunchOutcome::Started(
            kr_ipc::identity::current_process_start_identity().expect("a process identity"),
        )
    }

    fn start_service(&self, launch: &ServiceLaunch) -> LaunchOutcome {
        let outcome = self.service.start_service(launch);
        let process = match &outcome {
            LaunchOutcome::Started(identity) => Some(identity.clone()),
            _ => None,
        };
        self.services
            .lock()
            .expect("the record is not poisoned")
            .push((launch.label.clone(), process));
        outcome
    }

    fn describe(&self) -> &'static str {
        "this process for a worker, the platform's own start for a service"
    }
}

/// The platform's supervisor for a service, and what must live as long as it does.
///
/// Unix: the daemon's own choice. Windows: the environment's scheduled task, whose starter creates
/// the process outside this test's job, as it does for every suite that hosts a daemon.
fn platform_supervisor(
    environment: &EnvironmentPaths,
) -> (Box<dyn WorkerSupervisor>, Option<Box<dyn std::any::Any>>) {
    #[cfg(windows)]
    {
        let (task, supervisor) =
            kr_controller::supervision::windows::testing::supervisor(environment)
                .unwrap_or_else(|failure| panic!("the environment's task: {failure}"));
        (Box::new(supervisor), Some(Box::new(task)))
    }
    #[cfg(not(windows))]
    {
        let _ = environment;
        (kr_controller::supervision::detect(), None)
    }
}

/// Ends a process by the identity it was started under, after checking that it is still that
/// process.
fn kill(process: &ProcessStartIdentity) {
    if kr_ipc::identity::process_state(process) != ProcessState::Running {
        return;
    }
    let pid = process.pid.get();
    #[cfg(unix)]
    {
        let pid =
            rustix::process::Pid::from_raw(i32::try_from(pid).expect("a pid")).expect("a process");
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
    }
    #[cfg(windows)]
    {
        let system = PathBuf::from(std::env::var_os("SystemRoot").expect("the system directory"))
            .join("System32")
            .join("taskkill.exe");
        let _ = std::process::Command::new(system)
            .args(["/PID", &pid.to_string(), "/F"])
            .output();
    }
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

/// Ends the plugin hosts the daemon started, and takes their jobs away, before the tree that holds
/// them goes.
///
/// A job the service manager keeps after its process has ended (launchd does) is removed by the
/// daemon's watch, which looks once a second and gives up when the job's definition is gone; the
/// definition is in the tree, and a tree that goes first leaves the job loaded on the machine for
/// good. So each job is removed here, and a job that is still there fails the test.
struct HostEnding {
    services: Services,
    environment: EnvironmentPaths,
}

impl Drop for HostEnding {
    fn drop(&mut self) {
        let mut hosts: Vec<ProcessStartIdentity> = Vec::new();
        let mut labels: Vec<String> = Vec::new();
        if let Ok(services) = self.services.lock() {
            for (label, process) in services.iter() {
                labels.push(label.clone());
                hosts.extend(process.clone());
            }
        }
        if let Ok(Some(published)) = launcher::read_descriptor(&self.environment) {
            hosts.push(published.process_start_identity);
        }
        for host in &hosts {
            kill(host);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while hosts
            .iter()
            .any(|host| kr_ipc::identity::process_state(host) != ProcessState::Ended)
            && std::time::Instant::now() < deadline
        {
            // A host the system could not be asked about is killed again once it answers.
            for host in &hosts {
                kill(host);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let running: Vec<String> = hosts
            .iter()
            .filter_map(|host| match kr_ipc::identity::process_state(host) {
                ProcessState::Ended => None,
                state => Some(format!("{}: {state:?}", host.pid.get())),
            })
            .collect();
        let jobs = self.environment.jobs_dir();
        let mut left = Vec::new();
        for label in labels {
            let gone = loop {
                let outcome = kr_controller::supervision::retire_service_job(&jobs, &label);
                if matches!(outcome, kr_controller::supervision::JobRetirement::Gone) {
                    break None;
                }
                if std::time::Instant::now() >= deadline {
                    break Some(format!("{label}: {outcome:?}"));
                }
                std::thread::sleep(Duration::from_millis(100));
            };
            left.extend(gone);
        }
        assert!(
            (left.is_empty() && running.is_empty()) || std::thread::panicking(),
            "this test left plugin hosts that were not seen to end ({running:?}) or jobs registered \
             with the service manager ({left:?})"
        );
    }
}

/// One daemon, and this process as the worker it started.
struct Hosted {
    controller: Option<Arc<Controller>>,
    serving: Vec<tokio::task::JoinHandle<kr_controller::error::Result<()>>>,
    services: Services,
    /// How many of `services` an earlier daemon of this tree started.
    counted_from: usize,
    supervisor: Arc<Supervisor>,
    session_id: SessionId,
    environment_id: EnvironmentId,
    worker: PathBuf,
    /// The worker's session, which goes on after the daemon.
    _runtime: Arc<SessionRuntime>,
    _service: Arc<WorkerService>,
    _task: Option<Box<dyn std::any::Any>>,
    _hosts: HostEnding,
    /// Last. The daemon starts no worker of its own here, so the tree has none to end.
    tree: kr_ipc::testing::TempHost,
}

impl Hosted {
    fn environment(&self) -> EnvironmentPaths {
        self.tree.environment()
    }

    /// How many services the daemon has been asked to start so far.
    fn started(&self) -> usize {
        self.services
            .lock()
            .expect("the record")
            .len()
            .saturating_sub(self.counted_from)
    }

    /// The process the descriptor names, where a plugin host is published.
    fn published(&self) -> Option<ProcessStartIdentity> {
        launcher::read_descriptor(&self.environment())
            .ok()
            .flatten()
            .map(|descriptor| descriptor.process_start_identity)
    }

    /// Asks the daemon for the plugin runtime as the worker, which is this process.
    async fn ask(&self) -> PluginRuntimeState {
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
                session_id: self.session_id,
            }))
            .await
            .expect("the request is written");
        let answer: ControlFrame = reader.read_message().await.expect("answered");
        let ControlFrame::PluginRuntimeState(state) = answer else {
            panic!("the daemon answered {answer:?}");
        };
        state
    }

    /// Asks until the daemon says the runtime is running, and connects to it. A runtime that is
    /// never reached fails the test with the daemon's last reason.
    async fn runtime(&self) -> PluginClient {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let said;
            match self.ask().await {
                PluginRuntimeState::Running => {
                    match PluginClient::connect(&self.environment()).await {
                        Ok(client) => return client,
                        Err(error) => said = format!("the runtime was running and: {error}"),
                    }
                }
                PluginRuntimeState::Unavailable(told) => said = told.reason,
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "waited {PATIENCE:?} for the plugin runtime to be running; the daemon last said: \
                 {said}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Stops the daemon and starts another on the same tree, as a restart of the host does: every
    /// durable record stays, nothing held in memory does, and the plugin host goes on running.
    /// What the new daemon is asked to start is counted from here.
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
        // The jobs of the hosts the earlier daemon started are still to be taken away, so the
        // record keeps them; what the new daemon is asked to start is what follows.
        self.counted_from = self.services.lock().expect("the record").len();
        let (controller, serving) = start_daemon(
            &self.environment(),
            self.environment_id,
            &self.worker,
            &self.supervisor,
        )
        .await;
        self.serving = serving;
        self.controller = Some(controller);
    }
}

/// Starts a daemon on the tree, serving its clients and its workers' rendezvous.
async fn start_daemon(
    environment: &EnvironmentPaths,
    environment_id: EnvironmentId,
    worker: &Path,
    supervisor: &Arc<Supervisor>,
) -> (
    Arc<Controller>,
    Vec<tokio::task::JoinHandle<kr_controller::error::Result<()>>>,
) {
    let secrets = environment.secrets_dir();
    let controller = kr_controller::testing::taken_over(|| {
        let secrets = secrets.clone();
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
            supervisor: Box::new(Handle(Arc::clone(supervisor))),
            worker_program: worker.to_path_buf(),
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        })
    })
    .await
    .expect("the daemon starts");
    let serving = vec![
        tokio::spawn(
            Arc::clone(&controller).serve_clients(
                Listener::bind(&environment.controller_endpoint().expect("an endpoint"))
                    .expect("binds the client endpoint"),
            ),
        ),
        tokio::spawn(
            Arc::clone(&controller).serve_rendezvous(
                Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
                    .expect("binds the rendezvous endpoint"),
            ),
        ),
    ];
    (controller, serving)
}

/// A daemon, a session whose worker is this process with a shell of its own, and the plugin host
/// placed where the daemon looks for it.
async fn hosted() -> Hosted {
    let tree = kr_ipc::testing::TempHost::create();
    let environment = tree.environment();
    let environment_id = tree.environment_id();

    // The daemon looks for the plugin host beside the worker it was told, so both are placed there.
    let worker = tree
        .root()
        .join(format!("kr-worker{}", std::env::consts::EXE_SUFFIX));
    std::fs::write(&worker, b"").expect("a stand-in for the worker program");
    kr_ipc::testing::place_and_start_once(
        &beside_this_test("kr-plugin-host"),
        &tree
            .root()
            .join(format!("kr-plugin-host{}", std::env::consts::EXE_SUFFIX)),
        &["--version"],
    );

    let (launched, launches) = std::sync::mpsc::channel::<WorkerLaunch>();
    let (service, task) = platform_supervisor(&environment);
    let services = Services::default();
    let supervisor = Arc::new(Supervisor {
        launched: Mutex::new(Some(launched)),
        services: Arc::clone(&services),
        service,
    });
    let (controller, serving) =
        start_daemon(&environment, environment_id, &worker, &supervisor).await;

    // The create goes on its own task: the daemon answers it only once the worker it started has
    // reported ready, and reporting ready is what this test does next.
    let client_endpoint = environment.controller_endpoint().expect("an endpoint");
    let creating = tokio::spawn(async move {
        let mut client = LocalClient::connect(&client_endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects");
        let create = MutationRequest {
            request_id: RequestId::new(1),
            method: Method::SessionCreate.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(kr_ipc::new_uuid()),
            grant_id: Nullable::null(),
            target: ActionTarget {
                environment_id,
                session_id: Nullable::null(),
                session_epoch: Nullable::null(),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            expected: ParamsValue::empty(),
            action_window_id: client.action_window().action_window_id.clone(),
            requested_ttl_ms: DurationMs::new(kr_protocol::limits::MAX_MUTATION_TTL.get()),
            params: ParamsValue::from_typed(&SessionCreateParams {
                environment_id,
                presentation: Presentation::Invisible,
                shell: Nullable::null(),
                shell_mode: ShellMode::NativeCompat,
                cwd: Nullable::some("/".to_owned()),
                dimensions: Nullable::null(),
                worker_profile: WorkerProfile::HeadlessUser,
                environment_snapshot: Vec::new(),
                palette: Nullable::null(),
                launch_profile: kr_protocol::session::LaunchProfile::default(),
                terminal: Nullable::null(),
            })
            .expect("encodes"),
        };
        submit(&mut client, create).await
    });

    // The launch the daemon asked for. Nothing was started, so this process answers for it.
    let launch = tokio::task::spawn_blocking(move || {
        launches
            .recv_timeout(Duration::from_secs(60))
            .expect("the daemon asks for a worker")
    })
    .await
    .expect("the waiting thread finishes");
    let session_id = launch.session_id;
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            kr_ipc::identity::current_process_start_identity().expect("a process identity"),
            PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );
    let rendezvous = environment.rendezvous_endpoint().expect("an endpoint");
    let connection = kr_ipc::endpoint::Connection::connect(&rendezvous)
        .await
        .expect("connects to the rendezvous");
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
        .expect("writes the hello");
    let acknowledgement: ControlFrame = reader.read_message().await.expect("the daemon answers");
    assert!(matches!(acknowledgement, ControlFrame::HelloAck(_)));
    writer
        .write_message(&ControlFrame::Rendezvous(
            identity
                .rendezvous(launch.reservation_id)
                .expect("a startup claim"),
        ))
        .await
        .expect("writes the startup claim");
    let specification: ControlFrame = reader.read_message().await.expect("the daemon answers");
    let ControlFrame::LaunchSpec(specification) = specification else {
        panic!("the daemon sends a launch specification: {specification:?}");
    };

    // The session this worker owns, on the endpoint its display number names.
    let journal_path = environment.journal_database(session_id);
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: specification.display_number,
        shell: kr_worker::testing::posix_script("exec cat"),
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
    let runtime = Arc::new(
        SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
            .expect("starts the runtime"),
    );
    let endpoint = environment
        .worker_endpoint(specification.display_number)
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the worker endpoint");
    let service = Arc::new(
        WorkerService::new(
            Arc::clone(&runtime),
            Arc::clone(&identity),
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot,
                controller_public_key: specification.controller_public_key,
                controller_generation: specification.controller_generation,
                journal_path: Some(journal_path),
                build_id: build(),
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));
    let ready = {
        let session = runtime.session();
        kr_protocol::worker::WorkerReady {
            session_id,
            endpoint: endpoint.as_text(),
            root_process: session.root_identity().expect("a root process"),
            shell_path: kr_worker::testing::posix_shell(),
            dimensions: session.geometry().dimensions,
            session: Box::new(session.summary()),
        }
    };
    writer
        .write_message(&ControlFrame::WorkerReady(ready))
        .await
        .expect("reports ready");
    let created = tokio::time::timeout(Duration::from_secs(60), creating)
        .await
        .expect("the daemon answers the create")
        .expect("the creating task finishes");
    assert!(
        matches!(created, Outcome::Ok(_)),
        "the session is created: {created:?}"
    );

    Hosted {
        controller: Some(controller),
        serving,
        services: Arc::clone(&services),
        counted_from: 0,
        supervisor,
        session_id,
        environment_id,
        worker,
        _runtime: runtime,
        _service: service,
        _task: task,
        _hosts: HostEnding {
            services,
            environment,
        },
        tree,
    }
}

/// Puts the component where the daemon says components are, and returns how a worker names it:
/// by its path below the directory that holds every repository's store.
fn install(environment: &EnvironmentPaths, wasm: &[u8]) -> ComponentSource {
    let store = environment
        .state_dir()
        .join("catalogue")
        .join("repositories");
    let directory = store.join("enrolment");
    std::fs::create_dir_all(&directory).expect("a store directory");
    std::fs::write(directory.join("component.wasm"), wasm).expect("the component");
    ComponentSource {
        path: "enrolment/component.wasm".to_owned(),
        digest: PayloadDigest::of(wasm),
        bytes: wasm.len() as u64,
    }
}

/// Registers the component with the runtime the way a worker does, and asks it for a document.
async fn register_and_snapshot(runtime: &PluginClient, component: &ComponentSource) {
    let binding = new_binding_id();
    runtime
        .register(
            binding,
            &PluginIdentity::new(
                PluginId::new("kalareach/well-behaved").expect("an identifier"),
                PackageVersion::parse("1.0.0").expect("a version"),
                component.digest,
                RepositoryGeneration::new(1),
            ),
            &BindingFacts {
                plugin_id: "kalareach/well-behaved".to_owned(),
                binding_revision: 1,
                activity: BindingActivity::Idle,
                thread_id: None,
                turn_id: None,
                updated_at_ms: 0,
                held_rights: Vec::new(),
            },
            "/bin/sh",
            component,
        )
        .await
        .expect("the component registers in the runtime on this platform");
    let snapshot = runtime
        .snapshot(binding, Duration::from_secs(5))
        .await
        .expect("the component answers");
    assert!(snapshot.answered());
}

/// KR-REQ-05.06, KR-REQ-05.07 and KR-REQ-05.08 on this platform: the daemon starts the plugin host
/// only when the worker asks, through the platform's own start; the host is not in this process's
/// group and a worker reaches it on the endpoint the daemon published; a component runs in it; a
/// host that is killed ends the worker's connection to it and is replaced by the next request;
/// and a daemon that starts again finds the host it left and starts none. The worker here is this
/// process and has no link of its own to the host, so this shows the daemon's half and the host:
/// the end of a worker's connection to a host that is killed, the replacement, and the adoption.
/// What a worker's own link does with its bindings through that is shown against real workers in
/// `plugin_runtime.rs`, where the platform adopts a program into a binding.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_plugin_host_is_started_by_the_platform_when_the_worker_asks_and_replaced_when_it_ends()
{
    let Some(wasm) = well_behaved() else {
        return;
    };
    let mut hosted = hosted().await;
    let component = install(&hosted.environment(), &wasm);

    // Asked for nothing, the daemon has started nothing: no service, no descriptor, and nothing
    // listening on the endpoint a worker would reach it on.
    assert_eq!(hosted.started(), 0);
    assert!(hosted.published().is_none());
    assert!(PluginClient::connect(&hosted.environment()).await.is_err());

    // The worker asks. The platform starts the host, and the component runs in it.
    let mut runtime = hosted.runtime().await;
    assert_eq!(hosted.started(), 1);
    let host = hosted.published().expect("the host is published");
    // Not in this process's group, so a signal aimed at this process's group does not reach it.
    // (Where the platform has no service manager the host is this process's child, in a group of
    // its own.)
    #[cfg(unix)]
    assert_ne!(
        group_of(host.pid.get()),
        group_of(u64::from(std::process::id())),
        "the host is in this process's group, so what ends this process's group ends it"
    );
    register_and_snapshot(&runtime, &component).await;

    // The host is killed, as a crash kills it. The worker's connection to it ends.
    kill(&host);
    // What the host had said is read out, and then the connection is over.
    assert!(
        tokio::time::timeout(PATIENCE, async {
            while runtime.notice().await.is_some() {}
        })
        .await
        .is_ok(),
        "the worker's connection to the host never ended"
    );
    until("the host to end", || async {
        (kr_ipc::identity::process_state(&host) == ProcessState::Ended).then_some(())
    })
    .await;

    // The next request starts a replacement, and the component runs in that.
    let runtime = hosted.runtime().await;
    assert_eq!(hosted.started(), 2);
    let replacement = hosted.published().expect("the replacement is published");
    assert_ne!(replacement, host);
    register_and_snapshot(&runtime, &component).await;

    // A daemon that starts again finds the host it left, and the next request starts no other.
    drop(runtime);
    hosted.restart().await;
    let _runtime = hosted.runtime().await;
    assert_eq!(hosted.started(), 0, "the restarted daemon started a host");
    assert_eq!(hosted.published(), Some(replacement));
}

/// The process group a process is in, as the operating system reports it.
#[cfg(unix)]
fn group_of(pid: u64) -> u32 {
    let output = std::process::Command::new("/bin/ps")
        .args(["-o", "pgid=", "-p", &pid.to_string()])
        .output()
        .expect("lists the process");
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("a process group")
}

/// Sends one mutation and returns the daemon's answer to it.
async fn submit(client: &mut LocalClient, mutation: MutationRequest) -> Outcome {
    client
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .expect("writes the mutation");
    loop {
        match client.recv().await.expect("the daemon answers") {
            ControlFrame::Response(response) => return response.outcome,
            ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
            other => panic!("the daemon answered {other:?}"),
        }
    }
}
