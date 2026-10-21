//! The harness the gateway suites share: one session's gateway backends, a placed copy of the
//! Codex stand-in as the `codex` the shell finds, a signed record that names that copy, and the
//! launcher a test starts as the terminal.
//!
//! Build the stand-in before a package-scoped run (`cargo build -p kr-codex-stand-in`); a run of
//! the workspace builds it.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::session::{LaunchGroup, View, session};
use super::{LIVENESS, Placed};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::EnvironmentId;
use kr_protocol::root::{CommandBackend, CwdRevision, PromptGeneration};
use kr_protocol::scalars::{Digest256, Uuid};
use kr_protocol::session::CommandIntegration;
use kr_worker::broker::Broker;
use kr_worker::broker::commands::{CommandBackends, CommandBackendsConfig, EstablishRequest};
use kr_worker::broker::connectors::{ConnectorSources, QualifiedExecutable, fixture};
use kr_worker::persistence::JournalHealth;
use sha2::{Digest as _, Sha256};

/// A command the server starts for the turn: a shell with a process of its own, so that there is
/// something below the server to end.
pub const COMMAND: &str = r#"["/bin/sh", "-c", "sleep 120 & wait"]"#;

/// The same, for a command that ignores a terminate and passes that on to what it starts.
pub const STUBBORN: &str = r#"["/bin/sh", "-c", "trap '' TERM; sleep 120 & wait"]"#;

/// Where a harness session's broker keeps its ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ledger {
    /// In memory, beside nothing.
    Memory,
    /// In a file of its own under the host's root.
    OnDisk,
    /// In the session's journal, as the broker of a worker service does.
    Service,
}

/// A worker service for the session the view runs, opened over the session's own journal.
fn serve(placed: &Placed, view: &View) -> kr_worker::service::WorkerService {
    use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
    use kr_protocol::ids::{BuildId, ControllerGeneration, SessionEpoch};

    let environment = placed.host.environment();
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session(),
            SessionEpoch::V1,
            boot.clone(),
            kr_ipc::identity::current_process_start_identity().expect("this process"),
            kr_protocol::hello::PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );
    let store = kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a store");
    let controller =
        ControllerIdentity::initialise(store.store.as_ref(), placed.host.environment_id())
            .expect("a controller identity");
    kr_worker::service::WorkerService::new(
        Arc::clone(&view.runtime),
        identity,
        environment
            .worker_endpoint(kr_protocol::session::DisplayNumber::new(1))
            .expect("an endpoint"),
        kr_worker::service::ServiceBinding {
            environment_id: placed.host.environment_id(),
            boot_identity: boot,
            controller_public_key: *controller.public_key(),
            controller_generation: ControllerGeneration::new(1),
            journal_path: Some(environment.journal_database(session())),
            build_id: BuildId::new("kr-hook-test/0").expect("a build identifier"),
        },
    )
    .expect("a worker service")
}

pub fn words(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

/// Waits for a condition, within the liveness bound.
pub fn eventually(what: &str, mut holds: impl FnMut() -> bool) {
    let started = Instant::now();
    while !holds() {
        assert!(started.elapsed() < LIVENESS, "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The stand-in as the build left it, beside the test binaries.
pub fn built_stand_in() -> PathBuf {
    let tests = std::env::current_exe().expect("this test's path");
    let built = tests
        .parent()
        .and_then(Path::parent)
        .expect("the directory the programs are built in")
        .join("codex-stand-in");
    assert!(
        built.is_file(),
        "{} is not built; run `cargo build -p kr-codex-stand-in` first",
        built.display()
    );
    built
}

/// One session's gateway backends, a placed copy of the stand-in as the `codex` the shell finds,
/// and a signed record that names that copy.
pub struct Gateway {
    pub group: LaunchGroup,
    pub placed: Placed,
    pub runtime: tokio::runtime::Runtime,
    pub broker: Arc<Broker>,
    /// The worker service the session runs, where the harness was built with one: its maintenance
    /// is the production storage-recovery pass.
    pub service: Option<Arc<kr_worker::service::WorkerService>>,
    pub backends: Arc<CommandBackends>,
    pub view: View,
    pub executable: PathBuf,
    pub outputs: PathBuf,
    pub generation: std::sync::atomic::AtomicU64,
}

/// What a session's view was told about a resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewTold {
    /// The transition itself.
    Resource,
    /// To discard what it holds and install a fresh state, which covers any transition it missed.
    Resynchronise,
}

/// A launch the test started: the launcher, which becomes the terminal, and what it printed.
pub struct Launched {
    pub child: std::process::Child,
    pub printed: PathBuf,
}

impl Gateway {
    pub fn new() -> Self {
        Self::with(true, "")
    }

    /// A session whose broker keeps its ledger in a file under the host's root, which a test can
    /// search for what must not be kept.
    pub fn with_ledger_on_disk() -> Self {
        Self::build(true, "", Ledger::OnDisk)
    }

    /// A session served by a real worker service, as the worker binary runs one: the broker is the
    /// service's, its ledger lives in the session's journal, the backends are installed through the
    /// service, and the storage-recovery pass a test runs is the service's own maintenance.
    pub fn served() -> Self {
        Self::build(true, "", Ledger::Service)
    }

    /// A session whose signed record names the stand-in's digest, or, with `qualified` false,
    /// names no executable at all, and whose backends live in the directory `runtime_name` names
    /// under the host's root (the root itself when it is empty).
    pub fn with(qualified: bool, runtime_name: &str) -> Self {
        Self::build(qualified, runtime_name, Ledger::Memory)
    }

    pub fn build(qualified: bool, runtime_name: &str, ledger: Ledger) -> Self {
        Self::shaped(
            qualified,
            runtime_name,
            ledger,
            &fixture::Shape::codex_backend(),
        )
    }

    /// The same, for a package of the shape given.
    pub fn shaped(
        qualified: bool,
        runtime_name: &str,
        ledger: Ledger,
        shape: &fixture::Shape,
    ) -> Self {
        let placed = Placed::new();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime");
        let bin = placed.host.root().join("bin");
        let executable = bin.join("codex");
        // Placed and started once where nothing is timed: the first start of a program at a new
        // path is the one the operating system checks.
        let _ =
            kr_ipc::testing::place_and_start_once(&built_stand_in(), &executable, &["--version"]);
        let digest = Digest256::from_bytes(
            Sha256::digest(std::fs::read(&executable).expect("the placed stand-in")).into(),
        );
        let store = placed.host.root().join("store");
        std::fs::create_dir_all(&store).expect("a store");
        let mut source =
            fixture::package(&store, &placed.forwarder, shape).expect("the package is written");
        if qualified {
            source.qualified = vec![QualifiedExecutable {
                digest,
                version: fixture::GATEWAY_QUALIFIED_VERSION.to_owned(),
            }];
        }
        let view = {
            let _entered = runtime.enter();
            View::open(&placed.host)
        };
        let (broker, service) = match ledger {
            Ledger::Service => {
                let service = Arc::new(serve(&placed, &view));
                (Arc::clone(service.broker()), Some(service))
            }
            Ledger::OnDisk => (
                Arc::new(
                    Broker::open(
                        Some(&placed.host.root().join("broker-ledger.sqlite")),
                        session(),
                        JournalHealth::shared(),
                    )
                    .expect("the broker opens"),
                ),
                None,
            ),
            Ledger::Memory => (
                Arc::new(
                    Broker::open(None, session(), JournalHealth::shared())
                        .expect("the broker opens"),
                ),
                None,
            ),
        };
        let sources = Arc::new(ConnectorSources::new());
        let admissions = kr_worker::broker::catalogue::Admissions::new();
        let _ = kr_worker::broker::catalogue::testing::admit(
            &admissions,
            &sources,
            &broker,
            vec![kr_worker::broker::catalogue::testing::admitted(&source)],
            1,
        );
        assert!(sources.for_command("codex").is_some());
        let config = CommandBackendsConfig {
            session_id: session(),
            environment_id: EnvironmentId::new(Uuid::from_bytes([4; 16])),
            os_user: "someone".to_owned(),
            runtime_dir: if runtime_name.is_empty() {
                placed.host.root().to_path_buf()
            } else {
                let directory = placed.host.root().join(runtime_name);
                std::fs::create_dir_all(&directory).expect("a runtime directory");
                directory
            },
            sources,
            launcher: Some(placed.forwarder.clone()),
            registered_forwarder: Some(placed.forwarder.clone()),
        };
        let backends = if let Some(service) = service.as_ref() {
            // The production wiring: the service hands the backends its broker and the session.
            let _entered = runtime.enter();
            service.install_command_backends(config)
        } else {
            let backends = Arc::new(
                CommandBackends::new(Arc::clone(&broker), config, runtime.handle().clone())
                    .with_views(Arc::downgrade(&view.runtime)),
            );
            view.runtime
                .session()
                .set_command_backends(Arc::clone(&backends));
            backends
        };
        let outputs = placed.host.root().join("outputs");
        std::fs::create_dir_all(&outputs).expect("a directory for what the terminal prints");
        Self {
            group: LaunchGroup::new(),
            placed,
            runtime,
            broker,
            service,
            backends,
            view,
            executable,
            outputs,
            generation: std::sync::atomic::AtomicU64::new(1),
        }
    }

    pub fn integration() -> CommandIntegration {
        CommandIntegration {
            plugin_id: kr_protocol::ids::PluginId::new("kalareach/codex")
                .expect("a plugin identifier"),
            command: "codex".to_owned(),
            flags: words(&["--remote", "{gateway}"]),
            enabled: true,
        }
    }

    /// Establishes the backend of a plain launch of `typed`, the way a session does.
    pub fn establish(&self, typed: &[&str]) -> Result<CommandBackend, String> {
        self.establish_in(typed, self.placed.host.root())
    }

    /// Establishes the backend of a plain launch of `typed` the shell reports running in `cwd`.
    pub fn establish_in(&self, typed: &[&str], cwd: &Path) -> Result<CommandBackend, String> {
        let typed = words(typed);
        let added = words(&["--remote", "{gateway}"]);
        let mut answered = vec![typed[0].clone()];
        answered.extend(added.clone());
        answered.extend(typed[1..].iter().cloned());
        let generation = self
            .generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _entered = self.runtime.enter();
        self.backends.establish(&EstablishRequest {
            prompt_generation: PromptGeneration::new(generation),
            typed: &typed,
            arguments: &answered,
            added: &added,
            integration: &Self::integration(),
            executable: self.executable.to_str().expect("a text path"),
            cwd: cwd.to_str().expect("a text path"),
            cwd_revision: CwdRevision::new(1),
            root_shell: kr_ipc::identity::current_process_start_identity().expect("this process"),
        })
    }

    /// Starts the launcher for an answer, the way the shell does: its child, with the answer's
    /// variable and the person's own variables, in the group every launch of this test runs in.
    /// Standard output goes to a file the test reads, for it is what the terminal prints.
    pub fn launch(&self, answer: &CommandBackend, name: &str, own: &[(&str, &str)]) -> Launched {
        let own: Vec<(&std::ffi::OsStr, &std::ffi::OsStr)> = own
            .iter()
            .map(|(variable, value)| (variable.as_ref(), value.as_ref()))
            .collect();
        self.launch_with(answer, name, &own)
    }

    /// The same, with variables that need not be text.
    pub fn launch_with(
        &self,
        answer: &CommandBackend,
        name: &str,
        own: &[(&std::ffi::OsStr, &std::ffi::OsStr)],
    ) -> Launched {
        use std::os::unix::process::CommandExt as _;

        let printed = self.outputs.join(name);
        let mut command = self.placed.command(&[
            "launch",
            "--",
            self.executable.to_str().expect("a text path"),
            "codex",
            "--remote",
            "{gateway}",
        ]);
        for variable in &answer.environment {
            command.env(&variable.name, &variable.value);
        }
        for (name, value) in own {
            command.env(name, value);
        }
        command
            .process_group(self.group.id())
            .stdin(std::process::Stdio::null())
            .stdout(std::fs::File::create(&printed).expect("a file for the terminal's output"))
            .stderr(std::process::Stdio::piped());
        Launched {
            child: command.spawn().expect("the launcher starts"),
            printed,
        }
    }

    /// The servers the session records, which are running.
    pub fn servers(&self) -> Vec<ProcessStartIdentity> {
        self.view
            .runtime
            .session()
            .owned()
            .map(|owned| owned.record().backends)
            .unwrap_or_default()
    }

    /// What the session records of the processes it owns.
    pub fn recorded(&self) -> kr_worker::ownership::OwnedRecord {
        self.view
            .runtime
            .session()
            .owned()
            .expect("the session records its processes")
            .record()
    }

    /// The processes the session records that are neither its root shell nor a server: what the
    /// servers started.
    pub fn started_by_servers(&self) -> Vec<ProcessStartIdentity> {
        let record = self.recorded();
        record
            .processes
            .into_iter()
            .filter(|process| *process != record.root && !record.backends.contains(process))
            .collect()
    }

    /// Waits until the launch the confirmation pause holds is committed, its launcher waiting to
    /// be told.
    pub fn at_the_confirmation(&self, arrived: tokio::sync::oneshot::Receiver<()>) {
        self.runtime
            .block_on(async { tokio::time::timeout(LIVENESS, arrived).await })
            .expect("the launch is committed")
            .expect("and paused before the launcher is told");
    }

    /// Runs the service's storage-recovery pass, as often as it takes, until the gateway reads
    /// `mode`, within the liveness bound. The pass is the one the worker's maintenance runs once a
    /// minute: the journal first, then the broker.
    ///
    /// # Panics
    ///
    /// Panics when this harness has no service, or the gateway does not read `mode` in time.
    pub fn recovers_to(&self, what: &str, mode: kr_protocol::gateway::GatewayMode) {
        let service = self
            .service
            .as_ref()
            .expect("the harness was built with a service");
        let started = Instant::now();
        loop {
            service.recover_storage_now();
            if self.broker.mode() == mode {
                return;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "{what}: the gateway reads {} and not {mode}",
                self.broker.mode()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Reads the session view's stream until it is told that `resource` became `state`, or told to
    /// resynchronise, within the liveness bound.
    ///
    /// # Panics
    ///
    /// Panics when the view is told neither.
    pub fn view_is_told(
        &self,
        resource: kr_protocol::ids::PendingResourceId,
        state: kr_protocol::gateway::PendingState,
    ) -> ViewTold {
        let mut stream = self.view.stream.lock().expect("the view's stream");
        self.runtime.block_on(async {
            loop {
                match tokio::time::timeout(LIVENESS, stream.recv()).await {
                    Ok(Some(kr_worker::output::OutputDelivery::AgentResource { event, bytes })) => {
                        stream.written(bytes);
                        if event.resource_id == resource && event.state == state {
                            return ViewTold::Resource;
                        }
                    }
                    Ok(Some(kr_worker::output::OutputDelivery::Resync(_))) => {
                        return ViewTold::Resynchronise;
                    }
                    Ok(Some(delivery)) => stream.written(delivery.len()),
                    Ok(None) | Err(_) => panic!("the view was told nothing about {resource}"),
                }
            }
        })
    }

    /// Reads the session view's stream until it is told to resynchronise, within the liveness
    /// bound.
    ///
    /// # Panics
    ///
    /// Panics when the view is told nothing of the kind.
    pub fn view_resynchronises(&self) {
        let mut stream = self.view.stream.lock().expect("the view's stream");
        self.runtime.block_on(async {
            loop {
                match tokio::time::timeout(LIVENESS, stream.recv()).await {
                    Ok(Some(kr_worker::output::OutputDelivery::Resync(_))) => return,
                    Ok(Some(delivery)) => stream.written(delivery.len()),
                    Ok(None) | Err(_) => panic!("the view was never told to resynchronise"),
                }
            }
        });
    }

    /// The next announcement about an agent instance the session's view is sent.
    pub fn announcement(&self) -> kr_protocol::projection::AgentInstanceEvent {
        let mut stream = self.view.stream.lock().expect("the view's stream");
        self.runtime.block_on(async {
            loop {
                match tokio::time::timeout(LIVENESS, stream.recv()).await {
                    Ok(Some(kr_worker::output::OutputDelivery::AgentInstance { event, bytes })) => {
                        stream.written(bytes);
                        return *event;
                    }
                    Ok(Some(delivery)) => stream.written(delivery.len()),
                    Ok(None) | Err(_) => panic!("no announcement reached the view"),
                }
            }
        })
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.backends.close();
        // What a session's closure does for the servers its backends ran, so that none is left
        // running, and nothing it started, when the test ends.
        let _entered = self.runtime.enter();
        self.runtime
            .block_on(self.backends.end_servers(tokio::time::Instant::now()));
    }
}

impl Launched {
    /// What the terminal has printed so far.
    pub fn printed(&self) -> String {
        std::fs::read_to_string(&self.printed).unwrap_or_default()
    }

    /// Waits until the terminal has printed `line`.
    pub fn prints(&mut self, line: &str) {
        let started = Instant::now();
        loop {
            if self.printed().lines().any(|printed| printed == line) {
                return;
            }
            if let Ok(Some(status)) = self.child.try_wait() {
                let said = self.said();
                panic!(
                    "the terminal ended with {status} before it printed {line:?}: {}{said}",
                    self.printed()
                );
            }
            assert!(
                started.elapsed() < LIVENESS,
                "the terminal printed {line:?} by now: {}",
                self.printed()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Waits for the terminal to end and returns how.
    pub fn ends(&mut self) -> std::process::ExitStatus {
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().expect("readable") {
                return status;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "the terminal ended by now: {}",
                self.printed()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Launched {
    /// What the launcher's process wrote to its standard error, once it has ended.
    pub fn said(&mut self) -> String {
        let mut said = String::new();
        if let Some(stderr) = self.child.stderr.as_mut() {
            let _ = std::io::Read::read_to_string(stderr, &mut said);
        }
        said
    }
}

/// The directory a backend's answer names.
pub fn directory_of(answer: &CommandBackend) -> PathBuf {
    PathBuf::from(&answer.environment[0].value)
        .parent()
        .expect("the backend's directory")
        .to_path_buf()
}

impl Drop for Launched {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
