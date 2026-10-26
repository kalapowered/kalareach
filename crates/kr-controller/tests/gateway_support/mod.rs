//! A terminal behind a gateway, in a session a worker of this process serves.
//!
//! The application is the Codex stand-in (`tests/support/codex-stand-in`): one program that is the
//! server when it is started with `app-server --listen stdio://` and the terminal when it is
//! started with `--remote unix://PATH`. The worker is the product's own, and so is the launcher
//! (`kr-hook launch`): a test plays the root shell, establishes the backend the way a session does
//! and starts the launcher as its child with the answer's variable. The terminal runs its whole
//! session through the gateway, so the broker reads the turn it starts and ends from the server's
//! own frames, which is how the product learns of one.
//!
//! Build the stand-in and the launcher before a package-scoped run
//! (`cargo build -p kr-codex-stand-in -p kr-hook`); a run of the workspace builds them.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use kr_protocol::ids::{EnvironmentId, SessionId};
use kr_protocol::root::{CommandBackend, CwdRevision, PromptGeneration};
use kr_protocol::scalars::Digest256;
use kr_protocol::session::CommandIntegration;
use kr_worker::broker::commands::{CommandBackendsConfig, EstablishRequest};
use kr_worker::broker::connectors::{ConnectorSources, QualifiedExecutable, fixture};
use kr_worker::service::WorkerService;

/// How long a wait for the terminal is given: the first start of a program that was just copied
/// can take the system most of a minute.
const LIVENESS: Duration = Duration::from_secs(180);

/// The variables the launcher reads from its environment, removed from the one a test starts it
/// in: a test run inside a KalaReach session would otherwise reach for that session's worker.
const LAUNCHER_VARIABLES: &[&str] = &["KR_REGISTRATION", "KR_CREDENTIAL", "KR_SESSION"];

/// A program the build left beside the test binaries.
fn built(name: &str) -> PathBuf {
    let tests = std::env::current_exe().expect("this test's path");
    let built = tests
        .parent()
        .and_then(Path::parent)
        .expect("the directory the programs are built in")
        .join(name);
    assert!(
        built.is_file(),
        "{} is not built; run `cargo build -p kr-codex-stand-in -p kr-hook` first",
        built.display()
    );
    built
}

/// The gateway of one session: the stand-in as the `codex` the shell finds, the launcher, and the
/// package that declares the integration.
pub struct Gateway {
    host: kr_ipc::testing::TempHost,
    launcher: PathBuf,
    executable: PathBuf,
    backends: Arc<kr_worker::broker::commands::CommandBackends>,
    generation: AtomicU64,
}

/// A terminal a test started, and what it printed.
pub struct Launched {
    child: std::process::Child,
    printed: PathBuf,
}

impl Gateway {
    /// Gives the session `service` serves the integration of `codex`, as a session whose worker
    /// the installation handed a connector package has it.
    ///
    /// Must be called from inside the runtime the worker serves on.
    pub fn over(service: &Arc<WorkerService>, session_id: SessionId) -> Self {
        let host = kr_ipc::testing::TempHost::create();
        let bin = host.root().join("bin");
        std::fs::create_dir_all(&bin).expect("a directory for the programs");
        let launcher = bin.join("kr-hook");
        let executable = bin.join("codex");
        // Each placed and started once where nothing is waited for: the first start of a program
        // at a new path is the one the system checks.
        let _ = kr_ipc::testing::place_and_start_once(&built("kr-hook"), &launcher, &["--version"]);
        let _ = kr_ipc::testing::place_and_start_once(
            &built("codex-stand-in"),
            &executable,
            &["--version"],
        );
        let digest = Digest256::from_bytes(kr_cbor::sha256(
            &std::fs::read(&executable).expect("the placed stand-in"),
        ));
        let store = host.root().join("store");
        std::fs::create_dir_all(&store).expect("a store");
        let mut source = fixture::package(
            &store,
            &launcher,
            &fixture::Shape::codex_backend_answering(),
        )
        .expect("the package is written");
        source.qualified = vec![QualifiedExecutable {
            digest,
            version: fixture::GATEWAY_QUALIFIED_VERSION.to_owned(),
        }];
        let sources = Arc::new(ConnectorSources::new());
        let admissions = kr_worker::broker::catalogue::Admissions::new();
        let _ = kr_worker::broker::catalogue::testing::admit(
            &admissions,
            &sources,
            service.broker(),
            vec![kr_worker::broker::catalogue::testing::admitted(&source)],
            1,
        );
        assert!(sources.for_command("codex").is_some());
        let runtime_dir = host.root().join("run");
        std::fs::create_dir_all(&runtime_dir).expect("a runtime directory");
        let backends = service.install_command_backends(CommandBackendsConfig {
            session_id,
            environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
            os_user: "someone".to_owned(),
            runtime_dir,
            sources,
            launcher: Some(launcher.clone()),
            registered_forwarder: Some(launcher.clone()),
        });
        std::fs::create_dir_all(host.root().join("outputs")).expect("a directory for the output");
        Self {
            host,
            launcher,
            executable,
            backends,
            generation: AtomicU64::new(1),
        }
    }

    /// Runs the terminal as a person starts `codex` in the session's shell: the backend is
    /// established for the line, the launcher is started with the answer's variable, and the
    /// terminal runs a turn through the gateway. The stand-in answers its own approval, completes
    /// the turn and ends.
    pub fn run_a_turn(&self, name: &str) -> Launched {
        let generation = self.generation.fetch_add(1, Ordering::SeqCst);
        let typed = ["codex".to_owned()];
        let added = ["--remote".to_owned(), "{gateway}".to_owned()];
        let arguments = ["codex".to_owned(), added[0].clone(), added[1].clone()];
        let integration = CommandIntegration {
            plugin_id: kr_protocol::ids::PluginId::new("kalareach/codex")
                .expect("a plugin identifier"),
            command: "codex".to_owned(),
            flags: added.to_vec(),
            enabled: true,
        };
        let cwd = self.host.root().display().to_string();
        let answer: CommandBackend = self
            .backends
            .establish(&EstablishRequest {
                prompt_generation: PromptGeneration::new(generation),
                typed: &typed,
                arguments: &arguments,
                added: &added,
                integration: &integration,
                executable: self.executable.to_str().expect("a text path"),
                cwd: &cwd,
                cwd_revision: CwdRevision::new(1),
                root_shell: kr_ipc::identity::current_process_start_identity()
                    .expect("this process"),
            })
            .expect("a backend is established");
        let printed = self.host.root().join("outputs").join(name);
        let mut command = std::process::Command::new(&self.launcher);
        command
            .args(["launch", "--"])
            .arg(&self.executable)
            .args(["codex", "--remote", "{gateway}"])
            .current_dir(self.host.root());
        for variable in LAUNCHER_VARIABLES {
            command.env_remove(variable);
        }
        for variable in &answer.environment {
            command.env(&variable.name, &variable.value);
        }
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        command
            .stdin(std::process::Stdio::null())
            .stdout(std::fs::File::create(&printed).expect("a file for the terminal's output"))
            .stderr(std::process::Stdio::null());
        Launched {
            child: command.spawn().expect("the launcher starts"),
            printed,
        }
    }

    /// Ends what the backends started: the servers a closed session leaves to its worker.
    pub async fn finish(&self) {
        let _ = self.backends.close();
        self.backends.end_servers(tokio::time::Instant::now()).await;
    }
}

impl Drop for Gateway {
    /// A case that fails before it reaches [`Self::finish`] leaves no server running: the same
    /// ending is made here, on the runtime the case runs on. Only a multi-thread runtime can wait
    /// for it, so a case on any other runtime ends its servers by [`Self::finish`].
    fn drop(&mut self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
            return;
        }
        let backends = Arc::clone(&self.backends);
        tokio::task::block_in_place(move || {
            let _ = backends.close();
            handle.block_on(backends.end_servers(tokio::time::Instant::now()));
        });
    }
}

impl Launched {
    /// What the terminal has printed so far.
    pub fn printed(&self) -> String {
        std::fs::read_to_string(&self.printed).unwrap_or_default()
    }

    /// Waits until the terminal has printed `line`, or has ended without it.
    pub async fn prints(&mut self, line: &str) {
        let started = Instant::now();
        loop {
            if self.printed().lines().any(|printed| printed == line) {
                return;
            }
            if let Ok(Some(status)) = self.child.try_wait() {
                // It may have printed the line and ended between the read above and the wait.
                if self.printed().lines().any(|printed| printed == line) {
                    return;
                }
                panic!(
                    "the terminal ended with {status} before it printed {line:?}: {}",
                    self.printed()
                );
            }
            assert!(
                started.elapsed() < LIVENESS,
                "the terminal printed {line:?} by now: {}",
                self.printed()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Waits for the terminal to end.
    pub async fn ends(&mut self) {
        let started = Instant::now();
        loop {
            if self.child.try_wait().expect("readable").is_some() {
                return;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "the terminal ended by now: {}",
                self.printed()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for Launched {
    fn drop(&mut self) {
        // The launcher leads a group of its own, with the terminal in it. A launcher that has been
        // collected has given its identifier back, so the group is ended only while it has not.
        if matches!(self.child.try_wait(), Ok(None)) {
            let group = rustix::process::Pid::from_child(&self.child);
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        }
        let _ = self.child.wait();
    }
}
