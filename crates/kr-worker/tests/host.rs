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
//! kernel actually gave the process it started.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_controller::registry::Registry;
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{
    DetachedSupervisor, LaunchOutcome, ServiceLaunch, WorkerLaunch, WorkerSupervisor, settle,
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

/// A host tree on the internal disk, with the worker beside it.
/// Starts the worker the way this host's own supervisor does, and names its package root.
///
/// The daemon passes its own environment on to the process it starts, so a test that wants the
/// worker to look somewhere else has to say so on the child. Everything else is what
/// `DetachedSupervisor` does: the worker's own process group, the working directory the daemon
/// prepared, and no descriptor of this test's.
#[derive(Debug)]
struct WorkerWithPackageRoot {
    packages: PathBuf,
}

impl WorkerSupervisor for WorkerWithPackageRoot {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        let mut command = std::process::Command::new(&launch.program);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;

            command.process_group(0);
        }
        command.args(launch.arguments());
        command.current_dir(&launch.working_directory);
        command.env(
            kr_shell_integration::host::package::PACKAGE_ROOT_VARIABLE,
            &self.packages,
        );
        command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        match command.spawn() {
            Ok(child) => settle(child.id()),
            Err(error) => LaunchOutcome::NotStarted {
                detail: error.to_string(),
            },
        }
    }

    fn describe(&self) -> &'static str {
        "a detached process told where this test's packages are"
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

/// Starts what `DetachedSupervisor` starts, and keeps a list of every request.
///
/// A worker and a separately supervised service, such as the plugin runtime, are both started
/// through the daemon's supervisor, so the list is everything the daemon asked the platform to run
/// for this environment.
#[derive(Debug)]
struct RecordingSupervisor {
    launched: Arc<std::sync::Mutex<Vec<Launch>>>,
    registry: PathBuf,
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
        DetachedSupervisor::new().start(launch)
    }

    fn start_service(&self, launch: &ServiceLaunch) -> LaunchOutcome {
        self.note(Launch {
            what: Requested::Service(launch.label.clone()),
            reserved: None,
        });
        DetachedSupervisor::new().start_service(launch)
    }

    fn describe(&self) -> &'static str {
        "a detached process, with every request remembered"
    }
}

struct Host {
    /// The host tree, which ends every worker its daemon started before it goes.
    temp: teardown::Tree,
    worker: PathBuf,
    environment_id: EnvironmentId,
    /// Where this daemon looks for qualified shell packages, when a test gives it an installation.
    shell_packages: Option<PathBuf>,
    /// Where the worker this daemon starts looks for its own, when a test gives it one.
    worker_packages: Option<PathBuf>,
    /// Everything the daemon asked its supervisor to start, when a test keeps the list.
    launched: Option<Arc<std::sync::Mutex<Vec<Launch>>>>,
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
        Self {
            temp,
            worker,
            environment_id,
            shell_packages: None,
            worker_packages: None,
            launched: None,
        }
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
        let environment_id = self.environment_id;
        let started = std::time::Instant::now();
        let controller = loop {
            let secrets = environment.secrets_dir();
            let outcome = Controller::start(ControllerSetup {
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
                supervisor: self.temp.supervisor(
                    match (self.worker_packages.clone(), self.launched.clone()) {
                        (Some(packages), _) => Box::new(WorkerWithPackageRoot { packages }),
                        (None, Some(launched)) => Box::new(RecordingSupervisor {
                            launched,
                            registry: environment.registry_database(),
                        }),
                        (None, None) => Box::new(DetachedSupervisor::new()),
                    },
                ),
                worker_program: self.worker.clone(),
                build_id: build(),
                release: "0".to_owned(),
                shell_packages: self.shell_packages.clone(),
                terminal: Box::new(kr_controller::supervision::NoTerminal),
            })
            .await;
            match outcome {
                Ok(controller) => break controller,
                // The daemon this one replaces has not let go of the environment yet. Waiting for
                // it is a liveness condition: what a restart test asserts is that the replacement
                // takes the environment over, not how soon the runtime drops the last reference to
                // the one before it. Anything else fails at once.
                Err(kr_controller::ControllerError::AlreadyRunning { .. })
                    if started.elapsed() < ENVIRONMENT_HANDOVER_DEADLINE => {}
                Err(error) => panic!(
                    "the daemon did not start in {:.1?}: {error}",
                    started.elapsed()
                ),
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        };
        let rendezvous = Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
            .expect("binds the rendezvous");
        let clients = Listener::bind(&environment.controller_endpoint().expect("an endpoint"))
            .expect("binds the client endpoint");
        let generation = controller.generation();
        let serving = vec![
            tokio::spawn(Arc::clone(&controller).serve_rendezvous(rendezvous)),
            tokio::spawn(Arc::clone(&controller).serve_clients(clients)),
        ];
        RunningDaemon {
            controller,
            serving,
            generation,
        }
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

/// How long a replacement daemon is given to take the environment over.
///
/// The environment's singleton lock is released when the last reference to the controller goes,
/// which is after the serving tasks have been dropped, so a replacement starting at once can find
/// the environment still held. A bound this generous fails only when the handover never happens.
const ENVIRONMENT_HANDOVER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

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
        presentation: Presentation::Invisible,
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
    let outcome = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &create_params(host.environment_id, host.temp.root()),
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
/// like one that was given the right one until the kernel is asked. `None` means this platform has
/// no way to ask; a platform that has one and refuses to answer is a failure, not a skip.
fn working_directory_of(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Some(
            std::fs::read_link(format!("/proc/{pid}/cwd")).unwrap_or_else(|error| {
                panic!("the working directory of process {pid} could not be read: {error}")
            }),
        )
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("/usr/sbin/lsof")
            .args(["-a", "-d", "cwd", "-p", &pid.to_string(), "-Fn"])
            .output()
            .unwrap_or_else(|error| panic!("the process table could not be read: {error}"));
        Some(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .find_map(|line| line.strip_prefix('n').map(PathBuf::from))
                .unwrap_or_else(|| {
                    panic!("the process table named no working directory for process {pid}")
                }),
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

/// Asserts that the worker this host started runs in the directory the host gave it.
///
/// A worker is deliberately not a child of the process that asked for it, so it inherits nothing
/// worth having: a directory inherited from the daemon belongs to whoever started the daemon, and
/// on this machine that is a build tree on a removable volume. A process holding one open is a
/// volume the person at the machine cannot eject and, on macOS, a permission prompt for every
/// rebuilt binary.
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
    let Some(actual) = working_directory_of(pid) else {
        // Nothing to compare against rather than a comparison that failed. Saying so is better
        // than a pass that checked nothing.
        eprintln!(
            "skipped: this platform does not report another process's working directory here"
        );
        return;
    };
    assert_eq!(
        std::fs::canonicalize(&actual).unwrap_or(actual),
        expected,
        "the worker runs in the directory the host configured"
    );
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
                detail.contains("break away") && detail.contains("per-user service"),
                "the failure names the job that forbids breakaway and the setup: {detail}"
            );
        }
        other => {
            panic!("a start that must break away should be refused inside this job, got {other:?}")
        }
    }
}
