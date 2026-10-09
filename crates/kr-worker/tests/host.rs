//! The whole host path, with real processes.
//!
//! A control daemon, a worker it started, a real shell in a real pseudo-terminal, and the things
//! the specification says must survive: a daemon that restarts while the shell is producing
//! output, a session limit that refuses before anything is spawned, and a create token that is
//! retried.
//!
//! Every path these tests use is on the internal disk: the worker is copied there before it is
//! started, and the host gives it a working directory of its own there rather than letting it
//! inherit this process's. A process a service manager launches is its own identity to the
//! operating system, and one that reaches a removable volume asks the person sitting at the
//! machine for permission; a test suite must never do that, so every create checks what the
//! kernel actually gave the process it started, where the platform can be asked for it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_controller::registry::Registry;
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{
    DetachedSupervisor, LaunchOutcome, ServiceLaunch, WorkerLaunch, WorkerSupervisor,
};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{
    Presentation, SessionCloseParams, SessionCloseResult, SessionCreateParams, SessionCreateResult,
    SessionListParams, SessionListResult, SessionState, ShellMode,
};

#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;

/// Starts the worker through this host's own supervisor, and names its package root.
///
/// The daemon passes its own environment on to the process it starts, so a test that wants the
/// worker to look somewhere else has to say so on the child: the variable is added to what the
/// launch sets for the worker, which every supervisor here gives the process it starts.
#[derive(Debug)]
struct WorkerWithPackageRoot {
    packages: PathBuf,
    inner: Box<dyn WorkerSupervisor>,
}

impl WorkerSupervisor for WorkerWithPackageRoot {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        let mut told = launch.clone();
        told.desktop_environment.push((
            kr_shell_integration::host::package::PACKAGE_ROOT_VARIABLE.to_owned(),
            self.packages.display().to_string(),
        ));
        self.inner.start(&told)
    }

    fn describe(&self) -> &'static str {
        "this host's supervisor, with the worker told where this test's packages are"
    }
}

/// One request the daemon made of its supervisor.
#[derive(Clone, Debug)]
struct Launch {
    /// What was asked for.
    what: Requested,
    /// For a worker, what the environment's registry held for its session at that moment, read
    /// from the database on disk through a connection of its own: the reservation's phase and its
    /// create token, or why nothing could be read.
    reserved: Option<String>,
}

/// What the daemon asked its supervisor to start.
///
/// A worker's program is compared as a path, one component at a time, and not as text. The daemon
/// resolves the program it is given before it launches it, and resolving drops what changes only
/// the spelling, such as a doubled separator in the temporary directory this host was made under.
/// Two spellings of one path are the same program.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Requested {
    /// A session's worker, by its program.
    Worker(PathBuf),
    /// A separately supervised service, such as the plugin runtime, by its label.
    Service(String),
}

/// Starts what this host's supervisor starts, and keeps a list of every request.
///
/// A worker and a separately supervised service, such as the plugin runtime, are both started
/// through the daemon's supervisor, so the list is everything the daemon asked the platform to run
/// for this environment.
#[derive(Debug)]
struct RecordingSupervisor {
    launched: Arc<std::sync::Mutex<Vec<Launch>>>,
    registry: PathBuf,
    inner: Box<dyn WorkerSupervisor>,
}

impl RecordingSupervisor {
    fn note(&self, launch: Launch) {
        self.launched
            .lock()
            .expect("the launch list is not poisoned")
            .push(launch);
    }

    /// The durable reservation for `session_id`, as another reader of the database sees it.
    fn reserved(&self, session_id: SessionId) -> String {
        rusqlite::Connection::open_with_flags(
            &self.registry,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .and_then(|connection| {
            connection.query_row(
                "SELECT phase, lower(hex(create_token)) FROM reservations WHERE session_id = ?1",
                [session_id.get().as_bytes().as_slice()],
                |row| {
                    Ok(format!(
                        "{} {}",
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?
                    ))
                },
            )
        })
        .unwrap_or_else(|error| format!("nothing readable: {error}"))
    }
}

impl WorkerSupervisor for RecordingSupervisor {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        self.note(Launch {
            what: Requested::Worker(launch.program.clone()),
            reserved: Some(self.reserved(launch.session_id)),
        });
        self.inner.start(launch)
    }

    fn start_service(&self, launch: &ServiceLaunch) -> LaunchOutcome {
        self.note(Launch {
            what: Requested::Service(launch.label.clone()),
            reserved: None,
        });
        self.inner.start_service(launch)
    }

    fn describe(&self) -> &'static str {
        "this host's supervisor, with every request remembered"
    }
}

struct Host {
    /// The host tree, which ends every worker its daemon started before it goes.
    temp: teardown::Tree,
    /// The environment's scheduled task, through which a Windows daemon here starts each worker,
    /// when this run takes that path. Declared after the tree, so it is removed once the tree has
    /// ended what was started; removing it would not end a running worker in any case.
    #[cfg(windows)]
    task: Option<kr_controller::supervision::windows::testing::TestTask>,
    worker: PathBuf,
    environment_id: EnvironmentId,
    /// Where this daemon looks for qualified shell packages, when a test gives it an installation.
    shell_packages: Option<PathBuf>,
    /// Where the worker this daemon starts looks for its own, when a test gives it one.
    worker_packages: Option<PathBuf>,
    /// Everything the daemon asked its supervisor to start, when a test keeps the list.
    launched: Option<Arc<std::sync::Mutex<Vec<Launch>>>>,
    /// Whether the daemon starts its workers through the supervisor the shipping daemon chooses on
    /// this platform, rather than as detached processes of its own.
    platform_service: bool,
}

impl Host {
    fn create() -> Self {
        let temp = teardown::Tree::create();
        let environment_id = temp.environment_id();
        // The worker is copied to the internal disk before it is started. The build tree may live
        // on a removable volume, and a launched process that reaches one prompts the person at the
        // machine for permission. The copy is started once here, where nothing is timed, so the
        // operating system's check of a new executable is not paid inside a create's rendezvous.
        let worker = temp.root().join(if cfg!(windows) {
            "kr-worker.exe"
        } else {
            "kr-worker"
        });
        kr_ipc::testing::place_and_start_once(
            std::path::Path::new(env!("CARGO_BIN_EXE_kr-worker")),
            &worker,
            &["--version"],
        );
        #[cfg(windows)]
        let task = starts_through_the_task().then(|| {
            kr_controller::supervision::windows::testing::TestTask::register(
                &temp.environment(),
                &kr_controller::supervision::windows::testing::built_binary("kr-controller")
                    .unwrap_or_else(|missing| panic!("{missing}")),
            )
            .unwrap_or_else(|failure| panic!("the environment's task: {failure}"))
        });
        Self {
            #[cfg(windows)]
            task,
            temp,
            worker,
            environment_id,
            shell_packages: None,
            worker_packages: None,
            launched: None,
            platform_service: false,
        }
    }

    /// The supervisor this host's daemon starts workers through.
    ///
    /// On Windows, the environment's scheduled task, whose starter creates each worker: this
    /// daemon runs inside `cargo test`'s job, which kills its members when it closes and forbids
    /// breakaway, so a worker it created itself would die with the test or never start. Elsewhere,
    /// and on Windows when a run asks for the path the shipping daemon still takes, a detached
    /// process of the daemon's own.
    fn platform_supervisor(&self) -> Box<dyn WorkerSupervisor> {
        #[cfg(windows)]
        if let Some(task) = &self.task {
            return Box::new(task.supervisor(&self.paths()));
        }
        if self.platform_service {
            return kr_controller::supervision::detect();
        }
        Box::new(DetachedSupervisor::new())
    }

    /// Starts the daemon's workers through the supervisor the shipping daemon chooses here.
    fn through_the_platform(mut self) -> Self {
        self.platform_service = true;
        self
    }

    /// Installs a qualified Zsh package for the daemon, and none for the worker.
    ///
    /// The daemon is told where this installation's packages are, so a managed create naming that
    /// shell is admitted. The package it resolves travels to the worker, and the binary that
    /// package names cannot be executed, so the worker starts, claims its reservation, fails to
    /// start the root shell and says so. Everything here is this test's own: nothing depends on
    /// what the machine happens to have installed.
    /// Keeps a list of everything the daemon asks its supervisor to start.
    fn recording_launches(mut self) -> Self {
        self.launched = Some(Arc::default());
        self
    }

    /// Every request the daemon has made of its supervisor so far.
    fn requests(&self) -> Vec<Launch> {
        self.launched
            .as_ref()
            .expect("this host keeps a list of launches")
            .lock()
            .expect("the launch list is not poisoned")
            .clone()
    }

    /// What the daemon has asked its supervisor to start so far.
    fn launches(&self) -> Vec<Requested> {
        self.requests()
            .into_iter()
            .map(|launch| launch.what)
            .collect()
    }

    fn with_shell_package(mut self) -> Self {
        use kr_shell_integration::contract::qualification::ShellKind;
        use kr_shell_integration::host::package::{
            CURRENT_BASENAME, MANIFEST_BASENAME, PackageManifest, PackageShell, PackageStartupEntry,
        };

        let identity = "identity-1";
        let root = self.temp.root().join("packages");
        let directory = root.join(ShellKind::Zsh.as_str()).join(identity);
        std::fs::create_dir_all(directory.join("bin")).expect("creates the package");
        let executable = directory.join("bin").join("zsh");
        kr_ipc::testing::place_program(std::path::Path::new("/bin/cat"), &executable);
        // A file the package record can name and the worker cannot run. Both the daemon's check
        // and the worker's read ask whether the executable is a file, which it is; what fails is
        // starting it, which is the worker's own work and the only part of it this test is about.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o600))
                .expect("a program this worker cannot execute");
        }
        std::fs::create_dir_all(directory.join("startup")).expect("creates the entry directory");
        std::fs::write(
            directory.join("startup/entry"),
            b"# the package's own entry\n",
        )
        .expect("writes the entry");
        let manifest = PackageManifest {
            identity: identity.to_owned(),
            shell: PackageShell {
                kind: ShellKind::Zsh,
                executable,
                upstream_version: "5.9".to_owned(),
                editor_abi: "zle-5.9".to_owned(),
                integration_version: "1".to_owned(),
                patches: Vec::new(),
                modules: Vec::new(),
            },
            startup_entry: PackageStartupEntry {
                file: "startup/entry".to_owned(),
            },
        };
        std::fs::write(
            directory.join(MANIFEST_BASENAME),
            serde_json::to_string(&manifest).expect("encodes"),
        )
        .expect("writes the record");
        std::fs::write(
            root.join(ShellKind::Zsh.as_str()).join(CURRENT_BASENAME),
            identity,
        )
        .expect("names the identity this installation uses");

        // Where the worker this daemon starts looks for its own packages: a directory this test
        // made and left empty. The value is set on the child rather than on this process, whose
        // environment every other test in this binary shares. A managed create carries the
        // package the daemon resolved, so this decides nothing for one; what it does is keep the
        // worker away from the installation's own root on every other path.
        let empty = self.temp.root().join("no-packages");
        std::fs::create_dir_all(&empty).expect("creates an empty package root");
        self.worker_packages = Some(empty);
        self.shell_packages = Some(root);
        self
    }

    fn paths(&self) -> kr_ipc::paths::EnvironmentPaths {
        self.temp.environment()
    }

    async fn start(&self) -> RunningDaemon {
        let environment = self.paths();
        // The daemon this one replaces may not have let go of the environment yet, which the start
        // waits out: what a restart test asserts is that the replacement takes the environment
        // over, not how soon the runtime drops the last reference to the one before it. Anything
        // else fails at once.
        let started = std::time::Instant::now();
        kr_controller::testing::taken_over(|| {
            let supervisor = self.temp.supervisor(
                match (self.worker_packages.clone(), self.launched.clone()) {
                    (Some(packages), _) => Box::new(WorkerWithPackageRoot {
                        packages,
                        inner: self.platform_supervisor(),
                    }),
                    (None, Some(launched)) => Box::new(RecordingSupervisor {
                        launched,
                        registry: environment.registry_database(),
                        inner: self.platform_supervisor(),
                    }),
                    (None, None) => self.platform_supervisor(),
                },
            );
            start_daemon(
                &environment,
                supervisor,
                self.worker.clone(),
                self.shell_packages.clone(),
            )
        })
        .await
        .unwrap_or_else(|error| {
            panic!(
                "the daemon did not start in {:.1?}: {error}",
                started.elapsed()
            )
        })
    }

    async fn client(&self) -> LocalClient {
        LocalClient::connect(
            &self.paths().controller_endpoint().expect("an endpoint"),
            LocalClientKind::Cli,
            build(),
        )
        .await
        .expect("connects to the daemon")
    }
}

/// Starts a control daemon for `environment`, starting its workers through `supervisor`, and
/// serves its rendezvous and client endpoints.
async fn start_daemon(
    environment: &kr_ipc::paths::EnvironmentPaths,
    supervisor: Box<dyn WorkerSupervisor>,
    worker: PathBuf,
    shell_packages: Option<PathBuf>,
) -> kr_controller::Result<RunningDaemon> {
    let environment_id = environment.environment_id();
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
        supervisor,
        worker_program: worker,
        build_id: build(),
        release: "0".to_owned(),
        shell_packages,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    })
    .await?;
    let rendezvous = Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
        .expect("binds the rendezvous");
    let clients = Listener::bind(&environment.controller_endpoint().expect("an endpoint"))
        .expect("binds the client endpoint");
    let generation = controller.generation();
    let serving = vec![
        tokio::spawn(Arc::clone(&controller).serve_rendezvous(rendezvous)),
        tokio::spawn(Arc::clone(&controller).serve_clients(clients)),
    ];
    Ok(RunningDaemon {
        controller,
        serving,
        generation,
    })
}

/// Whether this run starts workers through the environment's scheduled task.
///
/// Every Windows run does, except one that asks for the path the shipping daemon still takes, a
/// detached process of the daemon's own. The continuous-integration step that runs this suite's
/// executable outside cargo asks for that with `KR_HOST_TEST_SUPERVISOR=detached`, so both paths
/// stay tested until the task is the only one.
#[cfg(windows)]
fn starts_through_the_task() -> bool {
    std::env::var_os("KR_HOST_TEST_SUPERVISOR").is_none_or(|value| value != "detached")
}

/// A control daemon that is running, and the tasks that are serving for it.
///
/// Stopping one in a test is the same thing as the process exiting: the tasks end, the last
/// reference goes, and the environment's singleton lock is released with it.
struct RunningDaemon {
    controller: Arc<Controller>,
    serving: Vec<tokio::task::JoinHandle<kr_controller::Result<()>>>,
    generation: kr_protocol::ids::ControllerGeneration,
}

impl RunningDaemon {
    /// Ends this daemon the way its process exiting would.
    async fn stop(self) {
        for task in &self.serving {
            task.abort();
        }
        for task in self.serving {
            let _ = task.await;
        }
        drop(self.controller);
        // The lock is released when the last reference goes, and references the runtime still has
        // to drop, or a task this test never awaited, can keep it a moment longer. The next start
        // waits for it rather than assuming a fixed delay is enough.
    }
}

/// How long a wait for something to appear is given.
///
/// A liveness wait is not a measurement. What it is for is to fail when something never happens,
/// and every second above that is patience rather than looseness: these suites run beside each
/// other and beside other work, and a host that needs half a minute to publish a closure record is
/// slow rather than broken. Thirty seconds was inside the range the slowest reference hosts reach,
/// which turned each of these waits into a coin toss; two minutes is outside it. The poll intervals
/// are unchanged, so a wait that succeeds costs what it always did, and each failure says how long
/// it actually waited.
const LIVENESS_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// A shell that prints a marker and then waits, so its output is observable and it does not exit.
fn create_params(environment_id: EnvironmentId, cwd: &Path) -> SessionCreateParams {
    SessionCreateParams {
        environment_id,
        presentation: Presentation::Attach,
        shell: Nullable::some(kr_worker::testing::posix_shell()),
        shell_mode: ShellMode::NativeCompat,
        cwd: Nullable::some(cwd.display().to_string()),
        dimensions: Nullable::null(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        palette: Nullable::null(),
        environment_snapshot: vec![
            kr_protocol::session::EnvironmentVariable {
                name: "PATH".to_owned(),
                value: "/usr/bin:/bin".to_owned(),
            },
            kr_protocol::session::EnvironmentVariable {
                name: "PS1".to_owned(),
                value: String::new(),
            },
        ],
        launch_profile: kr_protocol::session::LaunchProfile::default(),
        terminal: Nullable::null(),
    }
}

async fn create(client: &mut LocalClient, host: &Host) -> SessionCreateResult {
    create_with(client, host, &[]).await
}

/// Creates a session whose shell is also given `extra` variables.
async fn create_with(
    client: &mut LocalClient,
    host: &Host,
    extra: &[(&str, &str)],
) -> SessionCreateResult {
    let mut params = create_params(host.environment_id, host.temp.root());
    params
        .environment_snapshot
        .extend(
            extra
                .iter()
                .map(|(name, value)| kr_protocol::session::EnvironmentVariable {
                    name: (*name).to_owned(),
                    value: (*value).to_owned(),
                }),
        );
    let outcome = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &params,
        )
        .await
        .expect("the call reaches the daemon");
    let created: SessionCreateResult = outcome
        .map(|value| value.to_typed().expect("decodes"))
        .unwrap_or_else(|error| panic!("the create failed: {error}"));
    runs_where_the_host_put_it(host, created.session.session_id);
    created
}

/// Returns the working directory the operating system gave a running process.
///
/// Read from the process table rather than from anything this test arranged: what is being checked
/// is what the process actually got, and a launch that quietly inherited a directory looks exactly
/// like one that was given the right one until the kernel is asked. Linux and macOS answer that
/// for another process, and a refusal to answer fails here. Windows has no supported query for
/// another process's working directory, so this is not built there.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn working_directory_of(pid: u32) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/cwd")).unwrap_or_else(|error| {
            panic!("the working directory of process {pid} could not be read: {error}")
        })
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("/usr/sbin/lsof")
            .args(["-a", "-d", "cwd", "-p", &pid.to_string(), "-Fn"])
            .output()
            .unwrap_or_else(|error| panic!("the process table could not be read: {error}"));
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| line.strip_prefix('n').map(PathBuf::from))
            .unwrap_or_else(|| {
                panic!("the process table named no working directory for process {pid}")
            })
    }
}

/// Asserts that the worker this host started runs in the directory the host gave it.
///
/// A worker is deliberately not a child of the process that asked for it, so it inherits nothing
/// worth having: a directory inherited from the daemon belongs to whoever started the daemon, and
/// on this machine that is a build tree on a removable volume. A process holding one open is a
/// volume the person at the machine cannot eject and, on macOS, a permission prompt for every
/// rebuilt binary.
///
/// On Linux and macOS the kernel's own answer for the running worker is compared. Windows has no
/// supported query for another process's working directory, so there what is checked is the
/// directory the host configured and the binary it started.
fn runs_where_the_host_put_it(host: &Host, session_id: SessionId) {
    let registry = Registry::open(host.paths().registry_database(), host.environment_id)
        .expect("opens the registry");
    let worker = registry
        .workers()
        .expect("reads the worker records")
        .into_iter()
        .find(|worker| worker.session_id == session_id)
        .expect("the created session has a worker record");
    let pid = u32::try_from(worker.process_identity.pid.get()).expect("a process identifier");
    let expected = std::fs::canonicalize(host.paths().worker_dir(session_id))
        .expect("the worker's own directory exists");
    // Checked whatever the process table can be asked: the directory the host configured and the
    // binary it started are both outside the workspace, which may be on a removable volume.
    let workspace = workspace_root();
    assert!(
        !expected.starts_with(&workspace),
        "no process this suite starts has a working directory inside the workspace: {}",
        expected.display()
    );
    assert!(
        !host.worker.starts_with(&workspace),
        "and the binary it started is not inside it either: {}",
        host.worker.display()
    );
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let actual = working_directory_of(pid);
        assert_eq!(
            std::fs::canonicalize(&actual).unwrap_or(actual),
            expected,
            "the worker runs in the directory the host configured"
        );
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = pid;
}

/// Returns the workspace this test was built from.
fn workspace_root() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // `<workspace>/crates/<crate>`.
    root.pop();
    root.pop();
    std::fs::canonicalize(&root).unwrap_or(root)
}

/// KR-REQ-02.03, KR-REQ-24.04: the control daemon restarting does not close the shell: the root
/// shell keeps running, the replacement advances the generation, and it rebuilds its directory by
/// finding the worker again and proving it rather than by trusting a list of processes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "on Windows the worker's rendezvous does not complete across a daemon restart yet, so the worker does not report itself in time"
)]
async fn a_daemon_restart_keeps_the_session_and_its_shell() {
    let host = Host::create();
    let first = host.start().await;
    let mut client = host.client().await;
    let created = create(&mut client, &host).await;
    assert_eq!(created.session.state, SessionState::Live);
    let session_id = created.session.session_id;
    let root = created
        .session
        .root_process
        .as_ref()
        .cloned()
        .expect("the session names its root shell");
    drop(client);

    // The daemon goes. Nothing about the session does: the worker is not this process's child, and
    // a restart is not a reason to end a shell.
    let generation = first.generation;
    first.stop().await;
    let second = host.start().await;
    assert!(
        second.generation.get() > generation.get(),
        "a replacement daemon advances the generation"
    );
    assert_eq!(
        kr_ipc::identity::process_state(&root),
        kr_ipc::identity::ProcessState::Running,
        "the root shell is still running after the daemon restarted"
    );

    let mut client = host.client().await;
    let listed: SessionListResult = client
        .request(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::null(),
                include_closed: false,
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the list succeeds")
        .to_typed()
        .expect("decodes");
    assert!(
        listed
            .sessions
            .iter()
            .any(|summary| summary.session_id == session_id && summary.state == SessionState::Live),
        "the replacement daemon found the session again and proved its worker"
    );
    // And the directory that worker is running in is still there. A replacement daemon sweeps
    // what no session claims, and an adopted session claims its own.
    runs_where_the_host_put_it(&host, session_id);

    close(&mut client, &host, session_id).await;
    second.stop().await;
}

/// A terminal attached on this machine the way `kr attach` attaches.
///
/// The descriptor is read from the environment's runtime directory, the worker named in it is
/// reached on its own endpoint and made to answer a challenge only it can answer, and the attach,
/// the input lease and the subscription are the worker's own. No control daemon takes part.
struct LocalTerminal {
    client: LocalClient,
    session_id: SessionId,
    attachment_id: kr_protocol::ids::AttachmentId,
    epoch: Option<kr_protocol::ids::InputLeaseEpoch>,
    sequence: u64,
    seen: String,
}

impl LocalTerminal {
    async fn attach(
        host: &Host,
        session_id: SessionId,
        dimensions: kr_protocol::session::Dimensions,
        keys: bool,
    ) -> Self {
        use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
        use kr_protocol::scalars::CanonicalSet;

        let descriptor = kr_ipc::descriptor::read_all(&host.paths())
            .expect("reads the runtime directory")
            .into_iter()
            .filter_map(|entry| entry.descriptor.ok())
            .find(|descriptor| descriptor.session_id == session_id)
            .expect("the session's descriptor is published");
        let endpoint =
            kr_ipc::paths::Endpoint::from_path(&descriptor.endpoint).expect("an endpoint");
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("reaches the worker");
        client
            .verify_worker(&descriptor)
            .await
            .expect("the worker answers the descriptor's challenge");
        let target = ActionTarget {
            environment_id: descriptor.environment_id,
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        };
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        let attached: kr_protocol::attachment::SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                target.clone(),
                &SessionAttachParams {
                    session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(dimensions),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the worker attaches the terminal")
            .to_typed()
            .expect("decodes");
        let attachment_id = attached.attachment.attachment_id;
        let epoch = if keys {
            let lease: kr_protocol::input::InputAcquireResult = client
                .mutate(
                    Method::InputAcquire,
                    ActionId::new(kr_ipc::new_uuid()),
                    target,
                    &kr_protocol::input::InputAcquireParams {
                        session_id,
                        attachment_id,
                        expected_epoch: Nullable::null(),
                    },
                )
                .await
                .expect("the call reaches the worker")
                .expect("the worker hands this terminal the keys")
                .to_typed()
                .expect("decodes");
            Some(lease.lease.epoch)
        } else {
            None
        };
        // The subscription is the last call, because a client drops what arrives while it waits
        // for an answer of its own and the screen it is drawn is queued the moment it subscribes.
        let mut streams = CanonicalSet::new();
        streams.insert(kr_protocol::recovery::EventStream::Output);
        client
            .request(
                Method::EventsSubscribe,
                &kr_protocol::recovery::EventsSubscribeParams {
                    session_id,
                    attachment_id,
                    streams,
                    from_cursor: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the worker subscribes the terminal");
        Self {
            client,
            session_id,
            attachment_id,
            epoch,
            sequence: 0,
            seen: String::new(),
        }
    }

    /// Types one line into the session, under this terminal's lease.
    async fn type_line(&mut self, line: &str) {
        let epoch = self.epoch.expect("this terminal holds the keys");
        let _: kr_protocol::input::InputWriteResult = self
            .client
            .request(
                Method::InputWrite,
                &kr_protocol::input::InputWriteParams {
                    session_id: self.session_id,
                    attachment_id: self.attachment_id,
                    epoch,
                    sequence: kr_protocol::ids::InputSequence::new(self.sequence),
                    bytes: kr_protocol::scalars::Bytes::new(format!("{line}\n").into_bytes()),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the worker takes the line")
            .to_typed()
            .expect("decodes");
        self.sequence += 1;
    }

    /// How many times `marker` has reached this terminal so far.
    fn count(&self, marker: &str) -> usize {
        self.seen.matches(marker).count()
    }

    /// Waits until `marker` has reached this terminal `times` times in all.
    async fn shown(&mut self, marker: &str, times: usize) {
        let started = tokio::time::Instant::now();
        let deadline = started + LIVENESS_DEADLINE;
        while self.count(marker) < times {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, self.client.recv()).await {
                Ok(Ok(kr_protocol::envelope::ControlFrame::Notification(notification)))
                    if notification.event_type.as_str() == "session.output" =>
                {
                    if let Ok(event) = notification
                        .payload
                        .to_typed::<kr_protocol::recovery::OutputEvent>()
                    {
                        self.seen
                            .push_str(&String::from_utf8_lossy(event.bytes.as_slice()));
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(error)) => panic!(
                    "waited {:?} for {times} of {marker:?} and the connection ended ({error}): \
                     {:?}",
                    started.elapsed(),
                    self.seen
                ),
                Err(_) => panic!(
                    "waited {:?} for {times} of {marker:?}: {:?}",
                    started.elapsed(),
                    self.seen
                ),
            }
        }
    }
}

/// KR-REQ-02.03, KR-REQ-05.01: the control daemon ends while the shell is producing output. The
/// terminal attached on this machine keeps receiving it; a new terminal attaches through the
/// worker's own descriptor and endpoint while no daemon is running, and types into the shell;
/// and once a replacement daemon has taken over, the session is live with both terminals still
/// attached, and a terminal attaching then is drawn the screen as it now is: the text, the title
/// and the mode the application set before the daemon went are all still in it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_restart_during_output_keeps_the_local_terminals_and_the_screen() {
    let host = Host::create();
    let first = host.start().await;
    let mut client = host.client().await;
    let created = create(&mut client, &host).await;
    let session_id = created.session.session_id;
    let dimensions = created.session.dimensions;
    drop(client);

    // A terminal attached on this machine starts a ticker in the shell: output that keeps coming
    // whatever the daemon is doing, until a file appears in the session's own directory. What the
    // shell echoes of the command is `kr-%s`, so only the ticker itself produces `kr-tick`. Each
    // tick returns to the start of its line rather than starting a new one, so the ticks do not
    // scroll the screen and what was written before the daemon went stays on it.
    let mut watching = LocalTerminal::attach(&host, session_id, dimensions, true).await;
    watching
        .type_line("(while [ ! -e kr-stop ]; do printf 'kr-%s\\r' tick; sleep 0.2; done) &")
        .await;
    watching.shown("kr-tick", 1).await;
    // State of the terminal's own, set before the daemon goes: a line of text, a title and a mode.
    // Each is spelled so that only the output produces it, never the shell's echo of the command.
    watching
        .type_line("printf '\\033]2;kr-%s\\007\\033[?2004hkr-%s-%s\\n' title before restart")
        .await;
    watching.shown("kr-before-restart", 1).await;

    // The daemon goes while the ticker is writing, and the output keeps arriving.
    let generation = first.generation;
    first.stop().await;
    let ticks = watching.count("kr-tick");
    watching.shown("kr-tick", ticks + 3).await;

    // A new terminal attaches with no daemon running, takes the keys and types. The line runs in
    // the shell and reaches the terminal that was already watching.
    let mut typing = LocalTerminal::attach(&host, session_id, dimensions, true).await;
    typing.type_line("printf 'kr-%s\\n' during-restart").await;
    watching.shown("kr-during-restart", 1).await;

    // A replacement daemon takes the environment over and finds the session again, with both
    // terminals still attached, and the output never stopped.
    let second = host.start().await;
    assert!(
        second.generation.get() > generation.get(),
        "a replacement daemon advances the generation"
    );
    let ticks = watching.count("kr-tick");
    watching.shown("kr-tick", ticks + 3).await;
    let mut client = host.client().await;
    let read: kr_protocol::session::SessionReadResult = client
        .request(
            Method::SessionRead,
            &kr_protocol::session::SessionReadParams { session_id },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the daemon reads the session")
        .to_typed()
        .expect("decodes");
    assert_eq!(read.session.state, SessionState::Live);
    assert_eq!(
        read.session.attachment_count.get(),
        2,
        "both terminals are still attached"
    );

    // The screen is right: the ticker stops and a last line is printed, and a terminal attaching
    // now is drawn that line as part of the screen it is given.
    typing
        .type_line(": > kr-stop; printf 'kr-%s\\n' settled")
        .await;
    watching.shown("kr-settled", 1).await;
    let mut late = LocalTerminal::attach(&host, session_id, dimensions, false).await;
    late.shown("kr-settled", 1).await;
    for (what, drawn) in [
        ("the line written before the restart", "kr-before-restart"),
        ("the title set before it", "\u{1b}]2;kr-title"),
        ("and the mode set before it", "\u{1b}[?2004h"),
    ] {
        assert!(
            late.seen.contains(drawn),
            "the screen a terminal is drawn after the restart holds {what}: {:?}",
            late.seen
        );
    }

    close(&mut client, &host, session_id).await;
    second.stop().await;
}

/// KR-REQ-05.03: the daemon publishes each worker's descriptor in the environment's runtime
/// directory, whole and owner-only, and a reader finds the worker from it with no request to
/// anybody: the session's identity and number, the boot, the worker's own process-start identity,
/// the protocol and the endpoint, and nothing secret.
/// KR-REQ-02.04: each worker has a SQLite receipt journal of its own and a private endpoint of its
/// own; no two sessions share either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "on Windows the worker's rendezvous times out before the descriptor is published, so the worker does not report itself in time"
)]
async fn the_descriptor_is_published_whole_and_owner_only_and_names_the_worker() {
    let host = Host::create();
    let daemon = host.start().await;
    let mut client = host.client().await;
    let paths = host.paths();

    // Every read made while the daemon publishes finds whole descriptors or none: a reader is
    // never shown part of a file.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader = std::thread::spawn({
        let paths = paths.clone();
        let stop = Arc::clone(&stop);
        move || {
            let mut reads = 0_u64;
            let mut unreadable = Vec::new();
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                for entry in kr_ipc::descriptor::read_all(&paths).expect("reads the directory") {
                    if let Err(error) = entry.descriptor {
                        unreadable.push(error.to_string());
                    }
                }
                reads += 1;
            }
            (reads, unreadable)
        }
    });
    let mut created = Vec::new();
    for _ in 0..3 {
        created.push(create(&mut client, &host).await);
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let (reads, unreadable) = reader.join().expect("the reader finishes");
    assert!(reads > 0, "the directory was read while it was written");

    // Each worker keeps its receipts in a database of its own and is reached on an endpoint of its
    // own.
    let mut journals = std::collections::BTreeSet::new();
    let mut endpoints = std::collections::BTreeSet::new();
    for session in &created {
        let session_id = session.session.session_id;
        let journal = paths.journal_database(session_id);
        let header = std::fs::read(&journal)
            .unwrap_or_else(|error| panic!("reads {}: {error}", journal.display()));
        assert!(
            header.starts_with(b"SQLite format 3\0"),
            "{} is a SQLite database",
            journal.display()
        );
        journals.insert(journal);
        let descriptor = kr_ipc::descriptor::read(&paths, session_id)
            .expect("reads the runtime directory")
            .expect("the descriptor is published");
        endpoints.insert(descriptor.endpoint);
    }
    assert_eq!(journals.len(), created.len(), "one journal per worker");
    assert_eq!(endpoints.len(), created.len(), "one endpoint per worker");
    assert!(
        unreadable.is_empty(),
        "no read found a descriptor it could not decode: {unreadable:?}"
    );

    // The daemon goes. Everything below needs nothing but the files and the workers.
    drop(client);
    daemon.stop().await;
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    for session in &created {
        let session_id = session.session.session_id;
        let file = paths.descriptor_file(session_id);
        let bytes = std::fs::read(&file).expect("the descriptor is published");
        let descriptor: kr_protocol::worker::WorkerDescriptor =
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("a descriptor");
        // Nothing but a descriptor's own fields, none of them a key or a token: the file is the
        // canonical encoding of exactly those fields.
        assert_eq!(
            kr_cbor::to_canonical_vec(&descriptor).expect("encodes"),
            bytes,
            "the file holds the descriptor and nothing else"
        );
        assert_eq!(descriptor.session_id, session_id);
        assert_eq!(descriptor.display_number, session.session.display_number);
        assert_eq!(descriptor.environment_id, host.environment_id);
        assert_eq!(descriptor.boot_identity, boot);
        assert_eq!(
            descriptor.protocol_version,
            kr_protocol::hello::PROTOCOL_VERSION
        );
        assert_eq!(
            kr_ipc::identity::process_state(&descriptor.process_start_identity),
            kr_ipc::identity::ProcessState::Running,
            "the descriptor names the running worker"
        );
        assert_ne!(
            session.session.root_process.as_ref(),
            Some(&descriptor.process_start_identity),
            "and it is the worker, not the shell"
        );
        // The endpoint answers, and the worker behind it proves it is the one described.
        let endpoint =
            kr_ipc::paths::Endpoint::from_path(&descriptor.endpoint).expect("an endpoint");
        let mut worker = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("reaches the worker");
        worker
            .verify_worker(&descriptor)
            .await
            .expect("the worker answers the descriptor's challenge");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mode = |path: &Path| {
                std::fs::metadata(path)
                    .expect("reads the permissions")
                    .permissions()
                    .mode()
                    & 0o777
            };
            assert_eq!(mode(&file), 0o600, "{} is owner-only", file.display());
            assert_eq!(
                mode(&paths.descriptors_dir()),
                0o700,
                "and so is the directory it is in"
            );
        }
    }

    let daemon = host.start().await;
    let mut client = host.client().await;
    for session in &created {
        close(&mut client, &host, session.session.session_id).await;
    }
    daemon.stop().await;
}

/// KR-REQ-24.27: through a real daemon and a real worker process, a worker created while privacy
/// mode is on reads the state from its launch specification and holds it in its journal by the
/// time the daemon publishes it, which is after its ready report and before the daemon's tick can
/// find it to tell it anything.
///
/// The journal says when it recorded the state and the worker's descriptor says when the daemon
/// published the worker. That the state is held before the shell prints is proved where there is no
/// tick to compete with, in the worker's own privacy tests. The control is a worker created with
/// privacy mode off, whose journal says the initial generation, off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "on Windows the worker's rendezvous times out before the descriptor is published, so the worker does not report itself in time"
)]
async fn a_worker_created_while_privacy_mode_is_on_holds_the_generation_before_it_is_recorded() {
    for private in [true, false] {
        let host = Host::create();
        let daemon = host.start().await;
        let mut client = host.client().await;
        if private {
            let on = client
                .mutate(
                    Method::PrivacySet,
                    ActionId::new(kr_ipc::new_uuid()),
                    ActionTarget::environment(host.environment_id),
                    &kr_protocol::privacy::PrivacySetParams { enabled: true },
                )
                .await
                .expect("the call reaches the daemon")
                .unwrap_or_else(|error| panic!("privacy mode is turned on: {error}"));
            let report: kr_protocol::privacy::PrivacyReport = on.to_typed().expect("decodes");
            assert!(report.enabled);
        }
        let created = create(&mut client, &host).await;
        let session_id = created.session.session_id;
        let paths = host.paths();
        let descriptor = kr_ipc::descriptor::read(&paths, session_id)
            .expect("reads the runtime directory")
            .expect("the descriptor is published");
        let (generation, enabled, recorded_at_ms): (i64, i64, i64) =
            rusqlite::Connection::open_with_flags(
                paths.journal_database(session_id),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .expect("opens the worker's journal")
            .query_row(
                "SELECT generation, enabled, recorded_at_ms FROM privacy WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("the worker's privacy record");
        if private {
            assert_eq!((generation, enabled), (1, 1));
            assert!(
                u64::try_from(recorded_at_ms).expect("a time") <= descriptor.published_at_ms.get(),
                "the worker held the generation ({recorded_at_ms}) before the daemon recorded it \
                 as running ({})",
                descriptor.published_at_ms.get()
            );
        } else {
            assert_eq!((generation, enabled), (0, 0));
        }
        close(&mut client, &host, session_id).await;
        drop(client);
        daemon.stop().await;
    }
}

/// KR-REQ-07.02: a create presented for attaching makes the session at the creating terminal's
/// size, and that terminal then attaches to it.
/// KR-REQ-07.03: the size of the terminal a session is created from travels in the create request
/// and is the pseudo-terminal's size before the root shell starts: the shell's own first command,
/// run as it starts and before anything attaches or types, reads that size.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_creating_terminals_size_is_the_shells_from_the_start() {
    let host = Host::create();
    let daemon = host.start().await;
    let mut client = host.client().await;
    let size = kr_protocol::session::Dimensions::new(100, 30);
    let mut params = create_params(host.environment_id, host.temp.root());
    params.presentation = Presentation::Attach;
    params.dimensions = Nullable::some(size);
    // An interactive POSIX shell runs the file `ENV` names as it starts, before its first prompt,
    // so the size this file records is the one the shell was started at.
    let startup = host.temp.root().join("kr-measure-at-start.sh");
    let measured = host.temp.root().join("kr-size-at-start");
    std::fs::write(&startup, format!("stty size > '{}'\n", measured.display()))
        .expect("writes the shell's startup file");
    params
        .environment_snapshot
        .push(kr_protocol::session::EnvironmentVariable {
            name: "ENV".to_owned(),
            value: startup.display().to_string(),
        });
    let created: SessionCreateResult = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &params,
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the create succeeds")
        .to_typed()
        .expect("decodes");
    assert_eq!(created.session.dimensions, size);
    let started = std::time::Instant::now();
    let at_start = loop {
        if let Ok(text) = std::fs::read_to_string(&measured)
            && text.ends_with('\n')
        {
            break text;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "waited {:?} for the shell to measure its terminal as it started",
            started.elapsed()
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    assert_eq!(
        at_start.trim(),
        "30 100",
        "the shell started at the creating terminal's size"
    );
    // A terminal of that size attaches without claiming it, and the shell still says the same.
    let mut terminal = LocalTerminal::attach(&host, created.session.session_id, size, true).await;
    terminal.type_line("stty size").await;
    terminal.shown("30 100", 1).await;
    close(&mut client, &host, created.session.session_id).await;
    daemon.stop().await;
}

/// KR-REQ-05.02: a worker is reached on a private endpoint that carries the operating system's
/// access control: a socket only its owner may open, in a directory only its owner may enter.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_workers_endpoint_is_open_to_its_owner_alone() {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};

    let host = Host::create();
    let _daemon = host.start().await;
    let mut client = host.client().await;
    let created = create(&mut client, &host).await;
    let descriptor = kr_ipc::descriptor::read(&host.paths(), created.session.session_id)
        .expect("reads the runtime directory")
        .expect("the session's descriptor is published");
    let endpoint = PathBuf::from(&descriptor.endpoint);
    let socket = std::fs::symlink_metadata(&endpoint).expect("the endpoint exists");
    assert!(
        socket.file_type().is_socket(),
        "{} is the worker's socket",
        endpoint.display()
    );
    assert_eq!(
        socket.permissions().mode() & 0o777,
        0o600,
        "only its owner may open it"
    );
    assert_eq!(socket.uid(), kr_ipc::paths::current_uid());
    let directory = endpoint.parent().expect("the socket's directory");
    assert_eq!(
        std::fs::metadata(directory)
            .expect("reads the directory")
            .permissions()
            .mode()
            & 0o777,
        0o700,
        "and only its owner may reach it"
    );
    close(&mut client, &host, created.session.session_id).await;
}

/// KR-REQ-05.08: an idle session that has been asked to run nothing is its worker and its root
/// shell. The daemon asks its supervisor to start the worker and nothing else: no plugin runtime
/// or other separately supervised service, lazily or otherwise. And nothing the worker itself
/// starts beside the shell stays running.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_session_runs_nothing_beside_its_shell() {
    let host = Host::create().recording_launches();
    let _controller = host.start().await;
    let mut client = host.client().await;
    let created = create(&mut client, &host).await;
    let root = u32::try_from(
        created
            .session
            .root_process
            .as_ref()
            .expect("the session names its root shell")
            .pid
            .get(),
    )
    .expect("a process identifier");
    let worker = processes()
        .into_iter()
        .find_map(|(pid, parent)| (pid == root).then_some(parent))
        .expect("the root shell has a parent");

    // For a second of idling, every process whose parent is the worker is noted.
    let mut beside_the_shell = std::collections::BTreeSet::new();
    for _ in 0..10 {
        for (pid, parent) in processes() {
            if parent == worker && pid != root {
                beside_the_shell.insert(pid);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    // A worker asks its platform short questions, such as whether its desktop is still there, and
    // each of those is a process that ends at once. A backend is a process that stays, so whatever
    // the worker started beside the shell is looked for again a second later, twice.
    for _ in 0..2 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let running = processes();
        beside_the_shell.retain(|pid| {
            running
                .iter()
                .any(|(other, parent)| other == pid && *parent == worker)
        });
    }
    assert!(
        beside_the_shell.is_empty(),
        "nothing the worker started beside its shell is still running: {beside_the_shell:?}"
    );
    // Everything the daemon asked the platform to run for this environment, over the whole of it.
    let launched = host.launches();
    assert_eq!(
        launched,
        [Requested::Worker(host.worker.clone())],
        "the daemon started the worker and nothing else"
    );
    close(&mut client, &host, created.session.session_id).await;
}

/// Every process on this machine, with its parent.
#[cfg(unix)]
fn processes() -> Vec<(u32, u32)> {
    let output = std::process::Command::new("ps")
        .args(["-A", "-o", "pid=,ppid="])
        .output()
        .expect("lists the processes");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            Some((fields.next()?.parse().ok()?, fields.next()?.parse().ok()?))
        })
        .collect()
}

/// A worker that reports it could not start resolves its own reservation, and the directory the
/// host prepared for it goes back.
///
/// A root shell that cannot be started is the thing a worker reports before it has a session. The
/// daemon admits the create, resolves the package and sends it; the binary that package names is a
/// file the worker cannot execute, so the worker starts, claims its reservation, says it cannot go
/// on, and exits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "it places a POSIX /bin/cat as a stand-in shell binary, which this platform has not got"
)]
async fn a_worker_that_reports_it_could_not_start_leaves_no_directory() {
    let host = Host::create().with_shell_package();
    let _controller = host.start().await;
    let mut client = host.client().await;
    let mut params = create_params(host.environment_id, host.temp.root());
    params.shell_mode = ShellMode::Managed;
    params.shell = Nullable::some("zsh".to_owned());

    let refused = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &params,
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("a worker that cannot serve managed mode says so");
    // The daemon reports that it could not start a worker, and carries the worker's own words.
    assert_eq!(refused.code, ErrorCode::ResourceUnavailable);
    assert!(
        refused.message.contains("start the root shell"),
        "the worker's own words reach the caller: {refused}"
    );
    assert!(
        refused.message.to_lowercase().contains("denied")
            || refused.message.to_lowercase().contains("permission"),
        "and they are the report this test arranged, made when the root shell would not start: \
         {refused}"
    );
    // The reservation the report resolved stops occupying the environment, and what was prepared
    // for that worker is given back with it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let left = worker_dirs(&host);
        if left.is_empty() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the directory prepared for a worker that never started is still there: {left:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Returns the sessions that still have a directory under this environment's workers folder.
///
/// A directory that cannot be read is a failure rather than an empty answer: an assertion that
/// treated it as empty would pass for the wrong reason.
fn worker_dirs(host: &Host) -> Vec<String> {
    let directory = host.paths().workers_dir();
    let mut names: Vec<String> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("reads {}: {error}", directory.display()))
        .map(|entry| {
            entry.unwrap_or_else(|error| {
                panic!("reads an entry of {}: {error}", directory.display())
            })
        })
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .collect();
    names.sort();
    names
}

/// KR-REQ-07.14: a create past the environment's limit is refused with `SESSION_LIMIT` before
/// anything is spawned: the daemon's only request of its supervisor is the first session's worker.
/// The session already running is not evicted to make room.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_environment_limit_refuses_before_anything_is_spawned() {
    let host = Host::create().recording_launches();
    {
        // The limit is part of the environment's record, so it is set before the daemon starts.
        let mut registry = Registry::open(host.paths().registry_database(), host.environment_id)
            .expect("opens the registry");
        registry.set_session_limit(1).expect("sets the limit");
    }
    let _controller = host.start().await;
    let mut client = host.client().await;
    let created = create(&mut client, &host).await;

    let refused = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &create_params(host.environment_id, host.temp.root()),
        )
        .await
        .expect("the call reaches the daemon");
    assert_eq!(
        refused.err().map(|error| error.code),
        Some(ErrorCode::SessionLimit),
        "the environment is full and nothing is evicted to make room"
    );
    let listed: SessionListResult = client
        .request(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::null(),
                include_closed: true,
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the list succeeds")
        .to_typed()
        .expect("decodes");
    assert_eq!(
        listed.sessions.len(),
        1,
        "the refused create left no session behind: {:?}",
        listed.sessions
    );
    assert_eq!(listed.sessions[0].session_id, created.session.session_id);
    assert_eq!(
        listed.sessions[0].state,
        SessionState::Live,
        "and the session that was running still is"
    );
    assert_eq!(
        host.launches(),
        [Requested::Worker(host.worker.clone())],
        "the refused create launched nothing"
    );
    close(&mut client, &host, created.session.session_id).await;
}

/// KR-REQ-07.07, KR-REQ-24.05: by the time the daemon asks its supervisor for the worker, the create
/// is already durable: another reader of the registry's database finds its reservation, under its
/// create token, in the spawned phase. A create retried with that token resolves to the session its
/// first attempt made, and the environment holds one session, one launch and one worker for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_create_token_returns_the_same_session() {
    let host = Host::create().recording_launches();
    let _controller = host.start().await;
    let mut client = host.client().await;
    let token = ActionId::new(kr_ipc::new_uuid());
    let params = create_params(host.environment_id, host.temp.root());

    let first: SessionCreateResult = client
        .mutate(
            Method::SessionCreate,
            token,
            ActionTarget::environment(host.environment_id),
            &params,
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the create succeeds")
        .to_typed()
        .expect("decodes");
    let second: SessionCreateResult = client
        .mutate(
            Method::SessionCreate,
            token,
            ActionTarget::environment(host.environment_id),
            &params,
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the retry succeeds")
        .to_typed()
        .expect("decodes");
    assert_eq!(
        second.session.session_id, first.session.session_id,
        "one token, one session"
    );
    assert!(second.deduplicated, "the retry says it is one");
    assert_eq!(
        second.session.root_process, first.session.root_process,
        "and it names the one shell the first attempt started"
    );
    let listed: SessionListResult = client
        .request(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::null(),
                include_closed: true,
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the list succeeds")
        .to_typed()
        .expect("decodes");
    assert_eq!(
        listed.sessions.len(),
        1,
        "one token, one execution: {:?}",
        listed.sessions
    );
    assert_eq!(worker_dirs(&host).len(), 1, "and one worker was prepared");
    let requests = host.requests();
    assert_eq!(requests.len(), 1, "and launched: {requests:?}");
    let token_hex: String = token
        .get()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        requests[0].reserved.as_deref(),
        Some(format!("spawned {token_hex}").as_str()),
        "the reservation was on disk, under this create's token, when the worker was asked for"
    );
    close(&mut client, &host, first.session.session_id).await;
}

/// KR-REQ-05.05: a closed session's descriptor is retired, the daemon answers a reader asking about
/// the session with the closure record its worker wrote, and asking launches nothing: the only
/// process the daemon ever asked its supervisor for is the session's original worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closed_session_answers_with_the_record_its_worker_wrote() {
    let host = Host::create().recording_launches();
    let _controller = host.start().await;
    let mut client = host.client().await;
    let created = create(&mut client, &host).await;
    let session_id = created.session.session_id;
    let shell = created.session.shell_path.clone();

    let closed = close(&mut client, &host, session_id).await;
    assert_eq!(closed.session_id, session_id);

    // The worker's own record, not a reconstruction: the shell it ran survives the session.
    //
    // A close is accepted before anything is signalled, so the tombstone appears once the daemon
    // has seen the worker end. The list is asked until it does, rather than once and immediately:
    // asking once would be a test of how busy the machine is.
    let started = std::time::Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    let summary = loop {
        let listed: SessionListResult = client
            .request(
                Method::SessionList,
                &SessionListParams {
                    environment_id: Nullable::null(),
                    include_closed: true,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the list succeeds")
            .to_typed()
            .expect("decodes");
        let found = listed
            .sessions
            .iter()
            .find(|summary| summary.session_id == session_id)
            .cloned();
        if let Some(summary) = found {
            break summary;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "waited {:?} for the closed session to be listed",
            started.elapsed()
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };
    assert_eq!(summary.state, SessionState::Closed);
    assert_eq!(
        summary.shell_path, shell,
        "the closed session still says which shell it ran"
    );
    assert!(
        summary.closure.is_present(),
        "a closed session carries its closure record"
    );

    // Nothing on disk still points at an endpoint for it: the descriptor is retired.
    let descriptor = host.paths().descriptor_file(session_id);
    let started = std::time::Instant::now();
    while descriptor.exists() {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the closed session's descriptor is still published: {}",
            descriptor.display()
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    // Asking the daemon about it answers with the record, and starts nothing in its place.
    let read: kr_protocol::session::SessionReadResult = client
        .request(
            Method::SessionRead,
            &kr_protocol::session::SessionReadParams { session_id },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the daemon answers for a closed session")
        .to_typed()
        .expect("decodes");
    assert_eq!(read.session.state, SessionState::Closed);
    assert!(read.session.closure.is_present());
    let running: SessionListResult = client
        .request(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::null(),
                include_closed: false,
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the list succeeds")
        .to_typed()
        .expect("decodes");
    assert!(
        running.sessions.is_empty(),
        "reading a closed session started nothing: {:?}",
        running.sessions
    );
    assert_eq!(
        host.launches(),
        [Requested::Worker(host.worker.clone())],
        "and no process was launched for it after the first"
    );
}

async fn close(client: &mut LocalClient, host: &Host, session_id: SessionId) -> SessionCloseResult {
    let outcome = client
        .mutate(
            Method::SessionClose,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                environment_id: host.environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &SessionCloseParams { session_id },
        )
        .await
        .expect("the call reaches the daemon");
    let closed: SessionCloseResult = outcome
        .map(|value| value.to_typed().expect("decodes"))
        .unwrap_or_else(|error| panic!("the close failed: {error}"));
    // The acceptance says `closing`; the closure finishes afterwards. Waiting for the record is
    // what makes the next assertion about the record rather than about the acceptance.
    let started = tokio::time::Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    while tokio::time::Instant::now() < deadline {
        let listed: SessionListResult = client
            .request(
                Method::SessionList,
                &SessionListParams {
                    environment_id: Nullable::null(),
                    include_closed: true,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the list succeeds")
            .to_typed()
            .expect("decodes");
        if listed.sessions.iter().any(|summary| {
            summary.session_id == session_id && summary.state == SessionState::Closed
        }) {
            return closed;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!(
        "waited {:?} for the session to finish closing",
        started.elapsed()
    );
}

/// KR-REQ-07.58: a Windows worker must be a process independent of the daemon, outside the
/// daemon's kill-on-close job, so the start asks to break away from that job. Inside a job that
/// does not permit breakaway, such as the one `cargo` runs its tests in, the start is refused, and
/// the daemon names the cause and the setup rather than the bare access denial, and fails at once
/// rather than waiting.
#[cfg(windows)]
#[test]
fn a_worker_start_that_must_break_away_is_refused_inside_a_job_that_forbids_it() {
    use kr_ipc::starter::{BREAKAWAY_OK, KILL_ON_JOB_CLOSE, SILENT_BREAKAWAY_OK};

    let flags = kr_ipc::paths::current_job_limit_flags().expect("this process's job");
    if !flags.is_some_and(|flags| {
        flags & KILL_ON_JOB_CLOSE != 0 && flags & (BREAKAWAY_OK | SILENT_BREAKAWAY_OK) == 0
    }) {
        eprintln!(
            "skipped: this process is not in a job that kills on close and forbids breakaway \
             (limit flags {flags:?}), as it is under cargo"
        );
        return;
    }
    let temp = teardown::Tree::create();
    let jobs = temp.root().join("jobs");
    std::fs::create_dir_all(&jobs).expect("a jobs directory");
    let launch = ServiceLaunch {
        label: "kr-breakaway-probe".to_owned(),
        program: std::path::PathBuf::from(
            std::env::var_os("COMSPEC").expect("a command shell on PATH"),
        ),
        // If the start were somehow admitted, this exits at once and leaves nothing behind.
        arguments: vec!["/c".to_owned(), "exit".to_owned()],
        jobs_directory: jobs,
        working_directory: temp.root().to_path_buf(),
    };
    match DetachedSupervisor::new().start_service(&launch) {
        LaunchOutcome::NotStarted { detail } => {
            assert!(
                detail.contains("breakaway") && detail.contains("per-user service"),
                "the failure names the job that forbids breakaway and the setup: {detail}"
            );
        }
        other => {
            panic!("a start that must break away should be refused inside this job, got {other:?}")
        }
    }
}

/// What the helper below is told: the host tree's roots, the worker and the starter.
#[cfg(windows)]
const DAEMON_RUNTIME_ROOT: &str = "KR_HOST_TEST_DAEMON_RUNTIME_ROOT";
#[cfg(windows)]
const DAEMON_STATE_ROOT: &str = "KR_HOST_TEST_DAEMON_STATE_ROOT";
#[cfg(windows)]
const DAEMON_WORKER: &str = "KR_HOST_TEST_DAEMON_WORKER";
#[cfg(windows)]
const DAEMON_STARTER: &str = "KR_HOST_TEST_DAEMON_STARTER";

/// The supervisor the daemon in the nested jobs starts its worker through: the environment's task.
#[cfg(windows)]
fn nested_daemon_supervisor(
    environment: &kr_ipc::paths::EnvironmentPaths,
    starter: &Path,
) -> Box<dyn WorkerSupervisor> {
    use kr_controller::supervision::windows::TaskSupervisor;
    use kr_controller::supervision::windows::testing::definition;

    let expected = definition(environment, starter).expect("the task's definition");
    let through_the_task = TaskSupervisor::for_definition(environment.clone(), expected);
    Box::new(through_the_task)
}

/// Hosts a control daemon for its parent's host tree, inside the jobs its parent built, until
/// those jobs end it.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a helper process of the nested-job test below, which starts it itself"]
async fn a_daemon_for_its_parents_tree() {
    let (Some(runtime_root), Some(state_root), Some(worker), Some(starter)) = (
        std::env::var_os(DAEMON_RUNTIME_ROOT),
        std::env::var_os(DAEMON_STATE_ROOT),
        std::env::var_os(DAEMON_WORKER),
        std::env::var_os(DAEMON_STARTER),
    ) else {
        return;
    };
    let paths = kr_ipc::paths::HostPaths::new(runtime_root, state_root).expect("the roots");
    let environment_id = paths
        .recorded_environment_id()
        .expect("the tree's identity")
        .expect("the tree has an environment");
    let environment = paths.environment(environment_id);
    let mut word = String::new();
    std::io::stdin()
        .read_line(&mut word)
        .expect("the parent's word that the jobs are in place");
    let supervisor = nested_daemon_supervisor(&environment, Path::new(&starter));
    let _daemon = start_daemon(&environment, supervisor, PathBuf::from(worker), None)
        .await
        .expect("the daemon starts");
    println!("daemon ready");
    std::future::pending::<()>().await;
}

/// KR-REQ-07.58: a worker outlives every job the daemon that asked for it runs in, however those
/// jobs are nested. The daemon runs in the nesting a breakaway decision cannot see through: an
/// outer job that ends its members when it closes and does not let them leave, over an inner one
/// that lets them. A worker the daemon created itself, even one asked to break away, would still
/// be in the outer job and end with it. This one is created by the environment's task's starter,
/// so it was never in either: when the jobs close and take the daemon with them, the worker runs
/// on, and the host's cleanup still finds it by the identity the daemon recorded and closes it.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_outlives_the_nested_jobs_its_daemon_ran_in() {
    use std::io::{BufRead as _, Write as _};
    use std::os::windows::io::AsHandle as _;

    use kr_ipc::starter::{BREAKAWAY_OK, Job, KILL_ON_JOB_CLOSE};

    if !starts_through_the_task() {
        eprintln!("skipped: this run starts workers the way the shipping daemon does");
        return;
    }
    let host = Host::create();
    let starter = host
        .task
        .as_ref()
        .expect("the environment's task")
        .definition()
        .starter
        .clone();
    let hosts = host.temp.paths().clone();
    let mut daemon = std::process::Command::new(std::env::current_exe().expect("this test"))
        .args([
            "a_daemon_for_its_parents_tree",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(DAEMON_RUNTIME_ROOT, hosts.runtime_root())
        .env(DAEMON_STATE_ROOT, hosts.state_root())
        .env(DAEMON_WORKER, &host.worker)
        .env(DAEMON_STARTER, &starter)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("the daemon's process starts");
    let outer = Job::create(KILL_ON_JOB_CLOSE).expect("the outer job");
    outer
        .assign(daemon.as_handle())
        .expect("the daemon is in the outer job");
    let inner = Job::create(BREAKAWAY_OK).expect("the inner job");
    inner
        .assign(daemon.as_handle())
        .expect("the daemon is in the inner job, beneath the outer");
    writeln!(daemon.stdin.take().expect("its input"), "go").expect("the word is given");
    // Its output is read to the end on a thread of its own, so the helper never writes into a
    // closed pipe; the first line that says it is ready is passed on.
    let output = daemon.stdout.take().expect("its output");
    let (ready, is_ready) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(output)
            .lines()
            .map_while(std::result::Result::ok)
        {
            if line.contains("daemon ready") {
                let _ = ready.send(());
            }
        }
    });
    is_ready
        .recv_timeout(kr_controller::testing::ENVIRONMENT_HANDOVER_DEADLINE)
        .expect("the daemon in the nested jobs is ready");

    let mut client = host.client().await;
    let created = create(&mut client, &host).await;
    drop(client);
    let registry = Registry::open(host.paths().registry_database(), host.environment_id)
        .expect("opens the registry");
    let worker = registry
        .workers()
        .expect("reads the worker records")
        .into_iter()
        .find(|worker| worker.session_id == created.session.session_id)
        .expect("the created session has a worker record")
        .process_identity;
    drop(registry);

    // The jobs close. The outer one ends every process in it, the daemon among them.
    assert!(
        daemon.try_wait().expect("the daemon's state").is_none(),
        "the daemon was still running when its jobs closed"
    );
    drop(inner);
    drop(outer);
    // Closing a job that kills on close ends its members as `TerminateJobObject` does, with the
    // exit code it is given, which is zero: that the daemon has ended is what the wait shows.
    tokio::task::spawn_blocking(move || daemon.wait())
        .await
        .expect("the wait")
        .expect("the jobs ended the daemon, and its process is collected");
    let _ = reader.join();
    assert_eq!(
        kr_ipc::identity::process_state(&worker),
        kr_ipc::identity::ProcessState::Running,
        "the worker outlived every job its daemon ran in"
    );

    // The host's cleanup finds the worker by the identity the daemon recorded, and the worker
    // closes its own session when asked.
    let environment = host.paths();
    let unresolved = tokio::task::spawn_blocking(move || {
        teardown::end_what_the_daemon_started(&environment, Vec::new())
    })
    .await
    .expect("the cleanup");
    assert_eq!(unresolved, Vec::<String>::new(), "the cleanup ended it");
    assert_ne!(
        kr_ipc::identity::process_state(&worker),
        kr_ipc::identity::ProcessState::Running,
        "the worker closed when it was asked"
    );
}

/// Removing the environment's task, as clearing the setup does, leaves a worker it started
/// running: removing a task ends no process it started.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_the_environments_task_leaves_its_running_worker_running() {
    if !starts_through_the_task() {
        eprintln!("skipped: this run starts workers the way the shipping daemon does");
        return;
    }
    let host = Host::create();
    let daemon = host.start().await;
    let mut client = host.client().await;
    let created = create(&mut client, &host).await;
    let session_id = created.session.session_id;
    let definition = host
        .task
        .as_ref()
        .expect("the environment's task")
        .definition()
        .clone();
    assert!(
        kr_controller::supervision::windows::remove(&definition).expect("removed"),
        "the task was there to remove"
    );
    let registry = Registry::open(host.paths().registry_database(), host.environment_id)
        .expect("opens the registry");
    let worker = registry
        .workers()
        .expect("reads the worker records")
        .into_iter()
        .find(|worker| worker.session_id == session_id)
        .expect("the created session has a worker record")
        .process_identity;
    drop(registry);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert_eq!(
        kr_ipc::identity::process_state(&worker),
        kr_ipc::identity::ProcessState::Running,
        "the worker runs on after its task has gone"
    );
    let closed = close(&mut client, &host, session_id).await;
    assert_eq!(closed.session_id, session_id, "and closes as usual");
    drop(client);
    daemon.stop().await;
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-07.66, KR-REQ-24.25: what a crashed worker leaves, and who stops it
// ---------------------------------------------------------------------------------------------

/// The root shell's startup file, which builds the session's tree and writes each member's process
/// number where the test reads it.
///
/// `plain` is a background job. `stubborn` ignores hang-up and terminate, and writes its number
/// only once its traps are in place. `orphan` is the same with its parent gone. `escaped` (Unix)
/// calls `setsid` in a child of its own, so it leaves the terminal's session, and keeps its parent
/// alive. `jobonly` (Windows) is made with a console of its own, so only the session's job holds
/// it.
const TREE: &str = r#"
n() { p=$2; if [ -r "/proc/$p/winpid" ]; then p=$(cat "/proc/$p/winpid"); fi; printf '%s
' "$p" > "$1.pid"; }
sleep 600 &
n plain $!
case $(uname) in
  MINGW*|MSYS*)
    ( trap '' HUP TERM; exec sleep 601 ) &
    n stubborn $!
    ( ( trap '' HUP TERM; exec sleep 602 ) & n orphan $! )
    "${SYSTEMROOT:-/c/Windows}/System32/WindowsPowerShell/v1.0/powershell.exe" -NoProfile -Command '$p = Start-Process -FilePath "$env:SystemRoot\System32\PING.EXE" -ArgumentList "-n","605","127.0.0.1" -WindowStyle Hidden -PassThru; Set-Content -Path jobonly.pid -Value $p.Id'
    ;;
  *)
    sh -c 'trap "" HUP TERM; echo $$ > stubborn.pid; exec sleep 601' &
    ( sh -c 'trap "" HUP TERM; echo $$ > orphan.pid; exec sleep 602' & )
    perl -e 'use POSIX qw(setsid); $SIG{HUP} = "IGNORE"; $SIG{TERM} = "IGNORE"; if (fork() == 0) { setsid() or die "setsid: $!"; open(F, ">escaped.pid"); print F $$; close F; exec "sleep", "603"; } sleep 600' &
    ;;
esac
"#;

/// What the root shell goes on to do once the test says so, on a Linux host with a service manager:
/// it makes `drifter`, which ignores hang-up and terminate, calls `setsid` and has its parent end
/// at once, so it is in no list of the session's tree and the service's control group is all that
/// holds it.
const DRIFTER: &str = r#"
while [ ! -e kr-go ]; do sleep 0.05; done
perl -e 'use POSIX qw(setsid); $SIG{HUP} = "IGNORE"; $SIG{TERM} = "IGNORE"; exit 0 if fork(); setsid() or die "setsid: $!"; open(F, ">drifter.pid"); print F $$; close F; exec "sleep", "604";'
"#;

/// Everything the crash tests started, ended by identity when a test is over however it ended.
struct Members(Vec<kr_protocol::identity::ProcessStartIdentity>);

impl Drop for Members {
    fn drop(&mut self) {
        for identity in &self.0 {
            let _ = kr_ipc::identity::stop_process(identity, kr_ipc::identity::Stop::Kill);
        }
    }
}

/// How a crash test starts its worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Start {
    /// As the daemon starts one on this platform without a service manager: a detached process on
    /// Unix, and on Windows the environment's task.
    Plain,
    /// Through the service manager the shipping daemon chooses: launchd on macOS, a transient user
    /// service on Linux.
    Service,
}

/// Reads the number a member of the tree wrote, once it has written one.
fn member_of(host: &Host, name: &str) -> Option<kr_protocol::identity::ProcessStartIdentity> {
    let text = std::fs::read_to_string(host.temp.root().join(format!("{name}.pid"))).ok()?;
    let pid = text.trim().parse::<u32>().ok()?;
    kr_ipc::identity::process_start_identity(pid).ok()
}

/// Waits for `check` to give something, polling, for at most [`LIVENESS_DEADLINE`].
async fn until<T>(what: &str, mut check: impl FnMut() -> Option<T>) -> T {
    let started = tokio::time::Instant::now();
    loop {
        if let Some(found) = check() {
            return found;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "waited {LIVENESS_DEADLINE:?} for {what}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// What the worker has recorded of its session's processes, read as the control daemon reads it.
fn recorded_by(host: &Host, session_id: SessionId) -> Option<kr_worker::ownership::OwnedRecord> {
    let journal =
        kr_worker::journal::Journal::open_read_only(host.paths().journal_database(session_id))
            .ok()?;
    journal.read_owned(session_id).ok().flatten()
}

/// The identity of a session's worker, from the registry the daemon wrote.
fn worker_of(host: &Host, session_id: SessionId) -> kr_protocol::identity::ProcessStartIdentity {
    let registry = Registry::open(host.paths().registry_database(), host.environment_id)
        .expect("opens the registry");
    registry
        .workers()
        .expect("reads the worker records")
        .into_iter()
        .find(|worker| worker.session_id == session_id)
        .expect("a worker record")
        .process_identity
}

/// Stops the worker where it is, without ending it: it runs nothing more until it is killed.
/// Asks for the stop and returns whether every thread of the worker has stopped.
#[cfg(target_os = "linux")]
fn hold_still(worker: &kr_protocol::identity::ProcessStartIdentity) -> bool {
    let pid = rustix::process::Pid::from_raw(i32::try_from(worker.pid.get()).expect("a pid"))
        .expect("a process number");
    rustix::process::kill_process(pid, rustix::process::Signal::STOP).expect("stops it");
    let Ok(threads) = std::fs::read_dir(format!("/proc/{}/task", worker.pid.get())) else {
        return false;
    };
    let mut all = true;
    for thread in threads.flatten() {
        let state = std::fs::read_to_string(thread.path().join("stat"))
            .ok()
            .and_then(|stat| {
                stat.rsplit_once(')')
                    .and_then(|(_, rest)| rest.split_whitespace().next().map(str::to_owned))
            });
        all &= matches!(state.as_deref(), Some("T" | "t"));
    }
    all
}

/// Kills the worker, the way a crash does: no chance to say anything.
fn crash(worker: &kr_protocol::identity::ProcessStartIdentity) {
    assert_eq!(
        kr_ipc::identity::process_state(worker),
        kr_ipc::identity::ProcessState::Running,
        "the worker is running before it is killed"
    );
    #[cfg(unix)]
    {
        let pid = rustix::process::Pid::from_raw(i32::try_from(worker.pid.get()).expect("a pid"))
            .expect("a process number");
        rustix::process::kill_process(pid, rustix::process::Signal::KILL).expect("kills it");
    }
    #[cfg(windows)]
    {
        let status = std::process::Command::new("taskkill.exe")
            .args(["/PID", &worker.pid.get().to_string(), "/F"])
            .status()
            .expect("taskkill runs");
        assert!(status.success(), "taskkill ended the worker");
    }
}

/// Lists the closed sessions through the daemon until `session_id` is one, and returns its closure.
async fn closure_of(
    client: &mut LocalClient,
    session_id: SessionId,
) -> kr_protocol::session::ClosureRecord {
    let started = tokio::time::Instant::now();
    loop {
        let listed: SessionListResult = client
            .request(
                Method::SessionList,
                &SessionListParams {
                    environment_id: Nullable::null(),
                    include_closed: true,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the list succeeds")
            .to_typed()
            .expect("decodes");
        if let Some(closure) = listed
            .sessions
            .iter()
            .find(|summary| {
                summary.session_id == session_id && summary.state == SessionState::Closed
            })
            .and_then(|summary| summary.closure.0.clone())
        {
            return closure;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "waited {LIVENESS_DEADLINE:?} for the closure"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// What a crashed worker's session must have had stopped by the time its closure is visible, and
/// what its coverage says.
struct Expect {
    /// The members the platform's boundary or the worker's record holds.
    ended: Vec<&'static str>,
    /// The members that ignore the request to end, which the cleanup has to force.
    forced: Vec<&'static str>,
    /// Whether the closure claims every owned process was accounted for.
    complete: bool,
}

impl Expect {
    fn of(start: Start) -> Self {
        let mut ended = vec!["plain", "stubborn", "orphan"];
        let mut forced = Vec::new();
        let mut complete = false;
        if cfg!(windows) {
            ended.push("jobonly");
            complete = true;
        } else {
            forced.extend(["stubborn", "orphan"]);
            if cfg!(target_os = "linux") {
                // The worker is the child subreaper, so a process that left the root's session
                // while its parent lives is in its tree.
                ended.push("escaped");
                forced.push("escaped");
                if start == Start::Service {
                    // A process in no list at all, held by the service's control group.
                    ended.push("drifter");
                    forced.push("drifter");
                    complete = true;
                }
            }
        }
        Self {
            ended,
            forced,
            complete,
        }
    }
}

/// Builds the tree, crashes the worker and checks what is left when the closure can be read.
///
/// With `daemon_down` the daemon is stopped before the worker is killed and started again
/// afterwards, so it is the start of a daemon that finds a worker dead.
async fn a_crashed_workers_session_is_stopped_before_its_closure_is_recorded(
    start: Start,
    daemon_down: bool,
) {
    let host = match start {
        Start::Plain => Host::create(),
        Start::Service => Host::create().through_the_platform(),
    }
    .recording_launches();
    let drifts = cfg!(target_os = "linux") && start == Start::Service;
    let script = host.temp.root().join("tree.sh");
    std::fs::write(
        &script,
        if drifts {
            format!("{TREE}{DRIFTER}")
        } else {
            TREE.to_owned()
        },
    )
    .expect("writes the tree");
    let daemon = host.start().await;
    let client_first = host.client().await;
    let mut client = client_first;
    let created = create_with(
        &mut client,
        &host,
        &[("ENV", script.to_str().expect("a path"))],
    )
    .await;
    let session_id = created.session.session_id;
    let root = created
        .session
        .root_process
        .as_ref()
        .cloned()
        .expect("the session names its root shell");
    let expect = Expect::of(start);
    let mut named: Vec<(&str, kr_protocol::identity::ProcessStartIdentity)> =
        vec![("root", root.clone())];
    for name in &expect.ended {
        if *name == "drifter" {
            continue;
        }
        let identity = until(&format!("{name} to write its number"), || {
            member_of(&host, name)
        })
        .await;
        named.push((*name, identity));
    }
    #[cfg_attr(not(unix), expect(unused_mut, reason = "only Unix adds a late member"))]
    let mut members = Members(named.iter().map(|(_, identity)| identity.clone()).collect());
    // The one process the platform leaves for ever (macOS) is the test's to end by identity.
    #[cfg(unix)]
    if !expect.ended.contains(&"escaped") {
        let escaped = until("escaped to write its number", || {
            member_of(&host, "escaped")
        })
        .await;
        members.0.push(escaped);
    }
    // The worker has recorded them: this is what the cleanup acts on.
    until("the worker to record its session's processes", || {
        let record = recorded_by(&host, session_id)?;
        named
            .iter()
            .all(|(_, identity)| record.processes.contains(identity))
            .then_some(())
    })
    .await;
    let worker = worker_of(&host, session_id);
    // A process that is in no list of the session's tree and is in the service's control group.
    // The worker is held still first, so that it can look at nothing and write nothing while the
    // shell makes it: the record the worker leaves cannot name it, and only the group can end it.
    #[cfg(target_os = "linux")]
    if drifts {
        // The stop of the one process that ignores the request is refused, as the kernel refuses
        // one that belongs to another account: only the service manager can end it, and the
        // closure must say it was forced.
        let stubborn = named
            .iter()
            .find(|(name, _)| *name == "stubborn")
            .map(|(_, identity)| identity.clone())
            .expect("the tree's stubborn member");
        kr_controller::testing::refuse_stopping(stubborn.clone());
        // That one is also moved into a control group below the service's, as a process of a
        // session can be by what it runs: the manager's kill reaches it there, and the cleanup
        // has to read it as the group's member to say it was forced. The service's group is the
        // account's own to make groups in under a user service manager.
        let below = Path::new("/sys/fs/cgroup")
            .join(
                recorded_by(&host, session_id)
                    .and_then(|record| record.cgroup)
                    .expect("the worker recorded its group")
                    .trim_start_matches('/'),
            )
            .join("below");
        std::fs::create_dir(&below).expect("makes a control group below the service's");
        std::fs::write(below.join("cgroup.procs"), stubborn.pid.get().to_string())
            .expect("moves the stubborn process into it");
        let now = std::fs::read_to_string(format!("/proc/{}/cgroup", stubborn.pid.get()))
            .expect("its group");
        assert!(
            now.trim().ends_with("/below"),
            "the stubborn process is in the group below the service's: {now}"
        );
        until("the worker to stop, every thread of it", || {
            hold_still(&worker).then_some(())
        })
        .await;
        std::fs::write(host.temp.root().join("kr-go"), b"").expect("lets the shell go on");
        let drifter = until("the drifter to write its number", || {
            member_of(&host, "drifter")
        })
        .await;
        members.0.push(drifter.clone());
        let record = recorded_by(&host, session_id).expect("the record");
        let group = record
            .cgroup
            .as_deref()
            .expect("the worker recorded its group");
        let ran_in = std::fs::read_to_string(format!("/proc/{}/cgroup", drifter.pid.get()))
            .expect("its group");
        assert!(
            ran_in.trim().ends_with(group),
            "the drifter is in the service's control group: {ran_in} against {group}"
        );
        assert!(
            !record.processes.contains(&drifter),
            "the record does not name the drifter: {record:?}"
        );
        named.push(("drifter", drifter));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = drifts;
    let descriptor = kr_ipc::descriptor::read(&host.paths(), session_id)
        .expect("reads the runtime directory")
        .expect("the session's descriptor is published");
    let (daemon, mut client) = if daemon_down {
        drop(client);
        daemon.stop().await;
        crash(&worker);
        (host.start().await, host.client().await)
    } else {
        crash(&worker);
        (daemon, client)
    };
    let closure = closure_of(&mut client, session_id).await;

    // Nothing more is waited for from here: the closure is written after the cleanup.
    assert_eq!(
        closure.reason,
        kr_protocol::session::ClosureReason::WorkerCrash
    );
    for (name, identity) in &named {
        assert_eq!(
            kr_ipc::identity::process_state(identity),
            kr_ipc::identity::ProcessState::Ended,
            "{name} was still there when the closure was written: {closure:?}"
        );
        let listed = closure
            .terminated
            .iter()
            .find(|terminated| terminated.identity == *identity);
        if *name != "drifter" {
            // The control group's members are ended by the manager, which this host does not list
            // by identity; a process the worker recorded is listed whoever ended it.
            let listed = listed.unwrap_or_else(|| panic!("{name} is named in the closure"));
            assert_eq!(
                listed.forced,
                expect.forced.contains(name),
                "{name} forced or not as expected: {closure:?}"
            );
        }
    }
    assert_eq!(
        closure.ownership_coverage,
        if expect.complete {
            kr_protocol::session::OwnershipCoverage::Complete
        } else {
            kr_protocol::session::OwnershipCoverage::Incomplete
        },
        "{closure:?}"
    );
    if !expect.complete {
        assert!(
            closure
                .surviving
                .iter()
                .any(|resource| resource.kind == "unestablished"),
            "an incomplete closure says what was not found: {closure:?}"
        );
    }
    // The worker's endpoint and descriptor are gone, and the daemon started one worker.
    assert!(
        kr_ipc::descriptor::read(&host.paths(), session_id)
            .expect("reads the runtime directory")
            .is_none(),
        "the descriptor was fenced"
    );
    #[cfg(unix)]
    assert!(
        !Path::new(&descriptor.endpoint).exists(),
        "the endpoint was fenced"
    );
    #[cfg(windows)]
    let _ = descriptor;
    assert_eq!(
        host.launches()
            .iter()
            .filter(|launch| matches!(launch, Requested::Worker(_)))
            .count(),
        1,
        "the crash started no second worker"
    );
    // The record the dead worker left does not name what only the service's group held: it was
    // stopped before the shell made the process, so nothing could have written it in since.
    #[cfg(target_os = "linux")]
    if let Some((_, drifter)) = named.iter().find(|(name, _)| *name == "drifter") {
        let record = recorded_by(&host, session_id).expect("the record the worker left");
        assert!(
            !record.processes.contains(drifter),
            "the final record does not name the drifter either: {record:?}"
        );
    }
    drop(members);
    drop(client);
    daemon.stop().await;
}

/// KR-REQ-07.66, KR-REQ-24.25: a crash is cleaned up before the session's identity is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_crashed_workers_tree_is_stopped_before_its_closure_is_recorded() {
    a_crashed_workers_session_is_stopped_before_its_closure_is_recorded(Start::Plain, false).await;
}

/// The same when it is the start of a daemon that finds the worker dead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_crashed_workers_tree_is_stopped_by_the_daemon_that_starts_after_it() {
    a_crashed_workers_session_is_stopped_before_its_closure_is_recorded(Start::Plain, true).await;
}

/// The same under the service manager the shipping daemon chooses, whose control group also holds
/// what the worker never saw.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    target_os = "linux",
    ignore = "needs a user service manager for this account (`systemctl --user`), which a hosted CI \
              runner's account does not have; it runs with --ignored on a Linux host whose account \
              has one"
)]
async fn a_crashed_workers_tree_is_stopped_under_the_platforms_service_manager() {
    a_crashed_workers_session_is_stopped_before_its_closure_is_recorded(Start::Service, false)
        .await;
}

/// The client half of the survivor test, run only as the survivor process itself.
///
/// It is started by the session's root shell with hang-up and terminate ignored, and it waits for
/// the test to say the worker is gone. Then it does what a process left behind by a session can do
/// to act as that session, and writes down what came of each attempt: it reaches for the worker's
/// old endpoint, asks the daemon to attach to the old session, and writes to the terminal it was
/// given.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "the client half of the survivor test, run only as its own process"]
async fn a_survivor_of_a_crashed_session_tries_to_act_as_it() {
    let Some(directory) = std::env::var_os("KR_SURVIVOR_DIR").map(PathBuf::from) else {
        return;
    };
    let config = loop {
        if directory.join("survivor.go").exists()
            && let Ok(text) = std::fs::read_to_string(directory.join("survivor.config"))
        {
            break text;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    let mut lines = config.lines();
    let (worker_endpoint, controller_endpoint, session) = (
        lines.next().expect("the worker's endpoint").to_owned(),
        lines.next().expect("the daemon's endpoint").to_owned(),
        lines.next().expect("the session").to_owned(),
    );
    let session_id: SessionId = session.parse().expect("the session identifier");
    let mut said = Vec::new();

    // The worker's own endpoint, which the session's worker answered on.
    said.push(match kr_ipc::paths::Endpoint::from_path(&worker_endpoint) {
        Ok(endpoint) => {
            match LocalClient::connect(&endpoint, LocalClientKind::Cli, build()).await {
                Ok(_) => "worker_endpoint=connected".to_owned(),
                Err(_) => "worker_endpoint=refused".to_owned(),
            }
        }
        Err(_) => "worker_endpoint=refused".to_owned(),
    });

    // The daemon, asked to put a prompt to the agent of the session this process belongs to.
    let endpoint = kr_ipc::paths::Endpoint::from_path(&controller_endpoint).expect("an endpoint");
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("the daemon is there to be asked");
    let environment_id = EnvironmentId::new(
        std::env::var("KR_SURVIVOR_ENVIRONMENT")
            .expect("the environment")
            .parse()
            .expect("an environment identifier"),
    );
    let instance = kr_protocol::ids::ApplicationInstanceId::new(kr_ipc::new_uuid());
    let outcome = client
        .mutate(
            Method::AgentPromptSubmit,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::some(instance),
                agent_binding_revision: Nullable::some(
                    kr_protocol::ids::AgentBindingRevision::new(1),
                ),
            },
            &kr_protocol::agent::AgentPromptParams {
                target: kr_protocol::agent::AgentMutationTarget {
                    subject: kr_protocol::agent::AgentSubject {
                        session_id,
                        application_instance_id: instance,
                    },
                    binding_revision: kr_protocol::ids::AgentBindingRevision::new(1),
                },
                draft_id: Nullable::null(),
                text: Nullable::some(
                    kr_protocol::agent::PromptText::new("run this").expect("a prompt"),
                ),
            },
        )
        .await;
    said.push(match outcome {
        Ok(Err(error)) => format!("daemon_prompt=refused:{}", error.code.as_str()),
        Err(error) => format!("daemon_prompt=failed:{error}"),
        Ok(Ok(_)) => "daemon_prompt=accepted".to_owned(),
    });

    // The terminal this process was given, whose other end went with the worker.
    let written = {
        use std::io::Write as _;
        let mut out = std::io::stdout();
        out.write_all(b"x\n").and_then(|()| out.flush())
    };
    said.push(if written.is_err() {
        "terminal_write=refused".to_owned()
    } else {
        "terminal_write=written".to_owned()
    });

    // Written whole and then named, so a reader never meets it half written.
    std::fs::write(directory.join("survivor.out.part"), said.join("\n"))
        .expect("writes what came of it");
    std::fs::rename(
        directory.join("survivor.out.part"),
        directory.join("survivor.out"),
    )
    .expect("names what came of it");
    // And stays, as a survivor does, until the test ends it.
    tokio::time::sleep(std::time::Duration::from_secs(600)).await;
}

/// The contract for a process that outlasts the cleanup: it is named in the closure by
/// identifier, start and where it ran, with incomplete coverage; the session's endpoint,
/// descriptor and terminal are gone, so nothing it holds lets it act as the session; and no later
/// session shares its identity.
///
/// The process is real, started by the session's shell, and keeps running. The platform's refusal
/// to stop it is the only part supplied (a test has no second account to make a process that
/// refuses a signal), through the hook the controller offers its tests.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_process_that_outlasts_the_cleanup_is_named_and_cannot_act_as_the_session() {
    let host = Host::create().recording_launches();
    let half = host.temp.root().join("survivor-half");
    kr_ipc::testing::place_and_start_once(
        &std::env::current_exe().expect("this test's own path"),
        &half,
        &["--list"],
    );
    let script = host.temp.root().join("survivor.sh");
    std::fs::write(
        &script,
        format!(
            "export KR_SURVIVOR_DIR='{root}' KR_SURVIVOR_ENVIRONMENT='{environment}'\n\
             sleep 600 &\n\
             echo $! > plain.pid\n\
             sh -c 'trap \"\" HUP TERM; echo $$ > survivor.pid; exec \"$0\" --ignored --exact \
             a_survivor_of_a_crashed_session_tries_to_act_as_it --nocapture' '{half}' &\n",
            root = host.temp.root().display(),
            environment = host.environment_id,
            half = half.display(),
        ),
    )
    .expect("writes the startup file");
    let daemon = host.start().await;
    let mut client = host.client().await;
    let created = create_with(
        &mut client,
        &host,
        &[("ENV", script.to_str().expect("a path"))],
    )
    .await;
    let session_id = created.session.session_id;
    let plain = until("plain to write its number", || member_of(&host, "plain")).await;
    let survivor = until("the survivor to write its number", || {
        member_of(&host, "survivor")
    })
    .await;
    let _members = Members(vec![plain.clone(), survivor.clone()]);
    until("the worker to record the survivor", || {
        recorded_by(&host, session_id)?
            .processes
            .contains(&survivor)
            .then_some(())
    })
    .await;
    let descriptor = kr_ipc::descriptor::read(&host.paths(), session_id)
        .expect("reads the runtime directory")
        .expect("the session's descriptor is published");
    let cgroup = recorded_by(&host, session_id).and_then(|record| record.cgroup);
    kr_controller::testing::refuse_stopping(survivor.clone());
    std::fs::write(
        host.temp.root().join("survivor.config"),
        format!(
            "{}\n{}\n{}\n",
            descriptor.endpoint,
            host.paths()
                .controller_endpoint()
                .expect("an endpoint")
                .as_text(),
            session_id
        ),
    )
    .expect("writes the survivor's instructions");

    crash(&worker_of(&host, session_id));
    let closure = closure_of(&mut client, session_id).await;

    // The closure names it, and does not claim it gone.
    assert_eq!(
        closure.reason,
        kr_protocol::session::ClosureReason::WorkerCrash
    );
    let named = closure
        .surviving
        .iter()
        .find(|resource| resource.kind == "process")
        .unwrap_or_else(|| panic!("the survivor is in the closure: {closure:?}"));
    assert!(
        named
            .detail
            .contains(&format!("process {} ", survivor.pid.get()))
            && named
                .detail
                .contains(&format!("started {}", survivor.start_value.get())),
        "by identifier and start: {named:?}"
    );
    assert!(
        named.detail.contains("ran in"),
        "and by where it ran: {named:?} (the worker's group was {cgroup:?})"
    );
    assert!(
        !closure
            .terminated
            .iter()
            .any(|terminated| terminated.identity == survivor),
        "it is not claimed gone"
    );
    assert_eq!(
        closure.ownership_coverage,
        kr_protocol::session::OwnershipCoverage::Incomplete
    );
    assert_eq!(
        kr_ipc::identity::process_state(&survivor),
        kr_ipc::identity::ProcessState::Running,
        "it is still there"
    );
    assert_eq!(
        kr_ipc::identity::process_state(&plain),
        kr_ipc::identity::ProcessState::Ended,
        "and what could be stopped was"
    );

    // Nothing it holds lets it act as the session.
    assert!(
        kr_ipc::descriptor::read(&host.paths(), session_id)
            .expect("reads the runtime directory")
            .is_none(),
        "the descriptor is gone"
    );
    std::fs::write(host.temp.root().join("survivor.go"), b"").expect("lets the survivor try");
    let said = until("the survivor to say what came of its attempts", || {
        std::fs::read_to_string(host.temp.root().join("survivor.out")).ok()
    })
    .await;
    eprintln!("what the survivor's attempts came to: {said}");
    assert!(said.contains("worker_endpoint=refused"), "{said}");
    assert!(
        said.contains("daemon_prompt=refused:SESSION_CLOSED"),
        "{said}"
    );
    assert!(said.contains("terminal_write=refused"), "{said}");

    // And no later session shares its identity.
    let second = create(&mut client, &host).await;
    let registry = Registry::open(host.paths().registry_database(), host.environment_id)
        .expect("opens the registry");
    let first_reservation = registry
        .reservation_for_session(session_id)
        .expect("reads")
        .expect("the first session's reservation");
    let second_reservation = registry
        .reservation_for_session(second.session.session_id)
        .expect("reads")
        .expect("the second session's reservation");
    assert_ne!(
        first_reservation.reservation_id, second_reservation.reservation_id,
        "so the service and the control group named from it differ"
    );
    assert!(
        second_reservation.display_number.get() > first_reservation.display_number.get(),
        "and so does the number of the endpoint"
    );
    drop(registry);
    close(&mut client, &host, second.session.session_id).await;
    drop(client);
    daemon.stop().await;
}

/// Adds one variable to the environment of the worker the daemon starts, as every supervisor here
/// hands the process it starts.
#[cfg(unix)]
#[derive(Debug)]
struct WorkerWithVariable {
    name: &'static str,
    value: String,
    inner: Box<dyn WorkerSupervisor>,
}

#[cfg(unix)]
impl WorkerSupervisor for WorkerWithVariable {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        let mut told = launch.clone();
        told.desktop_environment
            .push((self.name.to_owned(), self.value.clone()));
        self.inner.start(&told)
    }

    fn start_service(&self, launch: &ServiceLaunch) -> LaunchOutcome {
        self.inner.start_service(launch)
    }

    fn describe(&self) -> &'static str {
        "this host's supervisor, with a variable added to the worker's environment"
    }
}

/// KR-REQ-07.66, KR-REQ-24.25: a worker that dies after its claim and before it reports itself has
/// started a shell, and what that shell started is stopped before the session identity is released.
///
/// The worker is held between its shell and its ready report by a seam compiled in for tests, so
/// the state is reached by construction: the registry shows the reservation claimed and no worker
/// row, and the create that was waiting for the report gives up when the worker dies.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_that_dies_after_its_claim_and_before_it_reports_has_its_tree_stopped() {
    let host = Host::create().recording_launches();
    let release = host.temp.root().join("kr-ready-go");
    let script = host.temp.root().join("tree.sh");
    std::fs::write(&script, TREE).expect("writes the tree");
    // The worker is started with the hold; the daemon's supervisor adds the variable.
    let environment = host.paths();
    let supervisor = host.temp.supervisor(Box::new(WorkerWithVariable {
        name: "KR_TEST_HOLD_READY",
        value: release.display().to_string(),
        inner: Box::new(DetachedSupervisor::new()),
    }));
    let daemon = start_daemon(&environment, supervisor, host.worker.clone(), None)
        .await
        .expect("the daemon starts");
    let mut client = host.client().await;
    let mut params = create_params(host.environment_id, host.temp.root());
    params
        .environment_snapshot
        .push(kr_protocol::session::EnvironmentVariable {
            name: "ENV".to_owned(),
            value: script.display().to_string(),
        });
    let create = tokio::spawn(async move {
        client
            .mutate(
                Method::SessionCreate,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(params.environment_id),
                &params,
            )
            .await
    });
    let session_id = until("the reservation to be claimed", || {
        let registry =
            Registry::open(host.paths().registry_database(), host.environment_id).ok()?;
        let claimed = registry
            .reservations_in(kr_controller::registry::LaunchPhase::Claimed)
            .ok()?;
        claimed.first().map(|reservation| reservation.session_id)
    })
    .await;
    let mut named = Vec::new();
    for name in ["plain", "stubborn", "orphan"] {
        named.push((
            name,
            until(&format!("{name} to write its number"), || {
                member_of(&host, name)
            })
            .await,
        ));
    }
    let _members = Members(named.iter().map(|(_, identity)| identity.clone()).collect());
    until("the worker to record its session's processes", || {
        let record = recorded_by(&host, session_id)?;
        named
            .iter()
            .all(|(_, identity)| record.processes.contains(identity))
            .then_some(())
    })
    .await;
    let launcher = {
        let registry = Registry::open(host.paths().registry_database(), host.environment_id)
            .expect("opens the registry");
        registry
            .reservation_for_session(session_id)
            .expect("reads")
            .expect("the reservation")
            .launcher_identity
            .expect("the launch recorded the worker")
    };
    assert!(
        Registry::open(host.paths().registry_database(), host.environment_id)
            .expect("opens the registry")
            .workers()
            .expect("reads")
            .iter()
            .all(|worker| worker.session_id != session_id),
        "the worker has not reported, so the registry holds no worker for the session"
    );
    crash(&launcher);
    let _ = create.await;

    let mut client = host.client().await;
    let closure = closure_of(&mut client, session_id).await;
    assert_eq!(
        closure.reason,
        kr_protocol::session::ClosureReason::WorkerCrash
    );
    for (name, identity) in &named {
        assert_eq!(
            kr_ipc::identity::process_state(identity),
            kr_ipc::identity::ProcessState::Ended,
            "{name} was still there when the closure was written: {closure:?}"
        );
        assert!(
            closure
                .terminated
                .iter()
                .any(|terminated| terminated.identity == *identity),
            "{name} is named in the closure: {closure:?}"
        );
    }
    assert_eq!(
        closure.ownership_coverage,
        kr_protocol::session::OwnershipCoverage::Incomplete
    );
    drop(client);
    daemon.stop().await;
}

/// KR-REQ-07.66, KR-REQ-24.25: a worker that accepted a close and died before it recorded its own
/// closure is a crash, and what its session owned is stopped before the daemon records the closure.
///
/// The worker is stopped (not ended) once it has accepted the close, so it can neither signal its
/// tree nor write a closure, and then ended; the test reads the journal to show it left none.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_that_dies_after_accepting_a_close_has_its_tree_stopped_by_the_daemon() {
    let host = Host::create().recording_launches();
    let script = host.temp.root().join("tree.sh");
    std::fs::write(&script, TREE).expect("writes the tree");
    let daemon = host.start().await;
    let mut client = host.client().await;
    let created = create_with(
        &mut client,
        &host,
        &[("ENV", script.to_str().expect("a path"))],
    )
    .await;
    let session_id = created.session.session_id;
    let mut named = Vec::new();
    for name in ["plain", "stubborn", "orphan"] {
        named.push((
            name,
            until(&format!("{name} to write its number"), || {
                member_of(&host, name)
            })
            .await,
        ));
    }
    let _members = Members(named.iter().map(|(_, identity)| identity.clone()).collect());
    until("the worker to record its session's processes", || {
        let record = recorded_by(&host, session_id)?;
        named
            .iter()
            .all(|(_, identity)| record.processes.contains(identity))
            .then_some(())
    })
    .await;
    let worker = worker_of(&host, session_id);
    let pid = rustix::process::Pid::from_raw(i32::try_from(worker.pid.get()).expect("a pid"))
        .expect("a process number");

    // The close is accepted, and the worker is stopped before it can do anything with it.
    let accepted: SessionCloseResult = client
        .mutate(
            Method::SessionClose,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                environment_id: host.environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &SessionCloseParams { session_id },
        )
        .await
        .expect("the call reaches the daemon")
        .map(|value| value.to_typed().expect("decodes"))
        .unwrap_or_else(|error| panic!("the close failed: {error}"));
    rustix::process::kill_process(pid, rustix::process::Signal::STOP).expect("stops the worker");
    assert!(
        accepted.closure.0.is_none(),
        "the worker accepted the close and had recorded no closure: {accepted:?}"
    );
    let journal =
        kr_worker::journal::Journal::open_read_only(host.paths().journal_database(session_id))
            .expect("opens the journal");
    assert!(
        journal.read_closure(session_id).expect("reads").is_none(),
        "the journal holds no closure, so what follows is the daemon's"
    );
    drop(journal);
    crash(&worker);

    let closure = closure_of(&mut client, session_id).await;
    for (name, identity) in &named {
        assert_eq!(
            kr_ipc::identity::process_state(identity),
            kr_ipc::identity::ProcessState::Ended,
            "{name} was still there when the closure was written: {closure:?}"
        );
    }
    assert!(
        closure
            .terminated
            .iter()
            .any(|terminated| terminated.identity == named[1].1 && terminated.forced),
        "the process that ignores the request was forced by the daemon: {closure:?}"
    );
    drop(client);
    daemon.stop().await;
}
