//! `kr-hook launch` against a backend that runs an application server, with the real worker
//! pieces and a stand-in for the application.
//!
//! This test process plays the root shell, as in the launcher's other suite: it establishes the
//! backend the way a session does, and starts the launcher as its child with the answer's
//! variable. The application is the Codex stand-in (`tests/support/codex-stand-in`), one program
//! that is the server when it is started with `app-server --listen stdio://` and the terminal
//! when it is started with `--remote unix://PATH`, and checks every frame either side writes
//! against the schemas of the release it stands for. The session is a real one, with a journal
//! on disk, so the server is recorded as a root of what it owns. Build the stand-in before a
//! package-scoped run (`cargo build -p kr-codex-stand-in`); a run of the workspace builds it.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-12.07 | a plain launch of an integrated terminal that has a server is served by a gateway: the server is started, recorded and bound before the program runs, the program's whole session runs through it, and the server and the instance end with the program |

#![cfg(unix)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::session::{LaunchGroup, View, session};
use common::{FIRST_START_WITHIN, LIVENESS, Placed};
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
const COMMAND: &str = r#"["/bin/sh", "-c", "sleep 120 & wait"]"#;

/// The same, for a command that ignores a terminate and passes that on to what it starts.
const STUBBORN: &str = r#"["/bin/sh", "-c", "trap '' TERM; sleep 120 & wait"]"#;

fn words(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

/// Waits for a condition, within the liveness bound.
fn eventually(what: &str, mut holds: impl FnMut() -> bool) {
    let started = Instant::now();
    while !holds() {
        assert!(started.elapsed() < LIVENESS, "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The stand-in as the build left it, beside the test binaries.
fn built_stand_in() -> PathBuf {
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
struct Gateway {
    group: LaunchGroup,
    placed: Placed,
    runtime: tokio::runtime::Runtime,
    broker: Arc<Broker>,
    backends: Arc<CommandBackends>,
    view: View,
    executable: PathBuf,
    outputs: PathBuf,
    generation: std::sync::atomic::AtomicU64,
}

/// A launch the test started: the launcher, which becomes the terminal, and what it printed.
struct Launched {
    child: std::process::Child,
    printed: PathBuf,
}

impl Gateway {
    fn new() -> Self {
        Self::with(true)
    }

    /// A session whose signed record names the stand-in's digest, or, with `qualified` false,
    /// names no executable at all.
    fn with(qualified: bool) -> Self {
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
        let started =
            kr_ipc::testing::place_and_start_once(&built_stand_in(), &executable, &["--version"]);
        assert!(started < FIRST_START_WITHIN);
        let digest = Digest256::from_bytes(
            Sha256::digest(std::fs::read(&executable).expect("the placed stand-in")).into(),
        );
        let store = placed.host.root().join("store");
        std::fs::create_dir_all(&store).expect("a store");
        let mut source =
            fixture::package(&store, &placed.forwarder, &fixture::Shape::codex_backend())
                .expect("the package is written");
        if qualified {
            source.qualified = vec![QualifiedExecutable {
                digest,
                version: fixture::GATEWAY_QUALIFIED_VERSION.to_owned(),
            }];
        }
        let broker = Arc::new(
            Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens"),
        );
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
        let view = {
            let _entered = runtime.enter();
            View::open(&placed.host)
        };
        let backends = Arc::new(
            CommandBackends::new(
                Arc::clone(&broker),
                CommandBackendsConfig {
                    session_id: session(),
                    environment_id: EnvironmentId::new(Uuid::from_bytes([4; 16])),
                    os_user: "someone".to_owned(),
                    runtime_dir: placed.host.root().to_path_buf(),
                    sources,
                    launcher: Some(placed.forwarder.clone()),
                    registered_forwarder: Some(placed.forwarder.clone()),
                },
                runtime.handle().clone(),
            )
            .with_views(Arc::downgrade(&view.runtime)),
        );
        view.runtime
            .session()
            .set_command_backends(Arc::clone(&backends));
        let outputs = placed.host.root().join("outputs");
        std::fs::create_dir_all(&outputs).expect("a directory for what the terminal prints");
        Self {
            group: LaunchGroup::new(),
            placed,
            runtime,
            broker,
            backends,
            view,
            executable,
            outputs,
            generation: std::sync::atomic::AtomicU64::new(1),
        }
    }

    fn integration() -> CommandIntegration {
        CommandIntegration {
            plugin_id: kr_protocol::ids::PluginId::new("kalareach/codex")
                .expect("a plugin identifier"),
            command: "codex".to_owned(),
            flags: words(&["--remote", "{gateway}"]),
            enabled: true,
        }
    }

    /// Establishes the backend of a plain launch of `typed`, the way a session does.
    fn establish(&self, typed: &[&str]) -> Result<CommandBackend, String> {
        self.establish_in(typed, self.placed.host.root())
    }

    /// Establishes the backend of a plain launch of `typed` the shell reports running in `cwd`.
    fn establish_in(&self, typed: &[&str], cwd: &Path) -> Result<CommandBackend, String> {
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
    fn launch(&self, answer: &CommandBackend, name: &str, own: &[(&str, &str)]) -> Launched {
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
    fn servers(&self) -> Vec<ProcessStartIdentity> {
        self.view
            .runtime
            .session()
            .owned()
            .map(|owned| owned.record().backends)
            .unwrap_or_default()
    }

    /// What the session records of the processes it owns.
    fn recorded(&self) -> kr_worker::ownership::OwnedRecord {
        self.view
            .runtime
            .session()
            .owned()
            .expect("the session records its processes")
            .record()
    }

    /// The processes the session records that are neither its root shell nor a server: what the
    /// servers started.
    fn started_by_servers(&self) -> Vec<ProcessStartIdentity> {
        let record = self.recorded();
        record
            .processes
            .into_iter()
            .filter(|process| *process != record.root && !record.backends.contains(process))
            .collect()
    }

    /// Waits until the launch the confirmation pause holds is committed, its launcher waiting to
    /// be told.
    fn at_the_confirmation(&self, arrived: tokio::sync::oneshot::Receiver<()>) {
        self.runtime
            .block_on(async { tokio::time::timeout(LIVENESS, arrived).await })
            .expect("the launch is committed")
            .expect("and paused before the launcher is told");
    }

    /// The next announcement about an agent instance the session's view is sent.
    fn announcement(&self) -> kr_protocol::projection::AgentInstanceEvent {
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
    }
}

impl Launched {
    /// What the terminal has printed so far.
    fn printed(&self) -> String {
        std::fs::read_to_string(&self.printed).unwrap_or_default()
    }

    /// Waits until the terminal has printed `line`.
    fn prints(&mut self, line: &str) {
        let started = Instant::now();
        loop {
            if self.printed().lines().any(|printed| printed == line) {
                return;
            }
            if let Ok(Some(status)) = self.child.try_wait() {
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
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Waits for the terminal to end and returns how.
    fn ends(&mut self) -> std::process::ExitStatus {
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
    fn said(&mut self) -> String {
        let mut said = String::new();
        if let Some(stderr) = self.child.stderr.as_mut() {
            let _ = std::io::Read::read_to_string(stderr, &mut said);
        }
        said
    }
}

/// The directory a backend's answer names.
fn directory_of(answer: &CommandBackend) -> PathBuf {
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

/// KR-REQ-12.07: a plain launch of a terminal whose package declares a server is served by a
/// gateway: the server is started in a group of its own and recorded as a root of what the
/// session owns before the program runs, the program connects to the socket the launch named and
/// runs its whole session through it, the instance is a gateway's, and when the program ends the
/// server and the instance end with it.
#[test]
fn kr_req_12_07_a_plain_launch_of_a_terminal_with_a_server_is_served_by_a_gateway() {
    let shell = Gateway::new();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let directory = PathBuf::from(&answer.environment[0].value)
        .parent()
        .expect("the backend's directory")
        .to_path_buf();
    let record = std::fs::read_to_string(directory.join("launch")).expect("the launch record");
    assert!(
        record.contains(&format!("unix://{}", directory.join("gw.sock").display())),
        "the launch record names the gateway's socket: {record}"
    );

    let mut launched = shell.launch(
        &answer,
        "plain",
        &[("KR_STAND_IN", "stay"), ("KR_STAND_IN_COMMAND", COMMAND)],
    );
    // The program's whole session runs through the gateway: it signs in, starts a turn, is asked
    // to approve a command, and the turn completes.
    launched.prints("TUI: the server asks for item/commandExecution/requestApproval");
    launched.prints("TUI: turn/completed");

    // And this is what it ran through: one server, recorded, in a group of its own, running.
    let servers = shell.servers();
    assert_eq!(servers.len(), 1, "{servers:?}");
    let server = servers[0].clone();
    assert_eq!(
        kr_ipc::identity::process_state(&server),
        kr_ipc::identity::ProcessState::Running
    );
    let started = shell.announcement();
    assert_eq!(
        started.instance.mode,
        kr_protocol::broker::IntegrationMode::Gateway
    );

    // The program ends, and the server and the instance end with it.
    let _ = launched.child.kill();
    let _ = launched.ends();
    eventually("the server ended with the program", || {
        kr_ipc::identity::process_state(&server) == kr_ipc::identity::ProcessState::Ended
    });
    let ended = shell.announcement();
    assert!(ended.instance.ended_at.is_present(), "{ended:?}");
}

/// KR-REQ-11.32: only the process the launch registered reaches the gateway, and an upgrade a
/// browser could have sent does not use the admission: another process is closed without a word
/// while the program has not yet connected, and the program whose first upgrade is refused for its
/// `Origin` header connects again and runs its whole session.
#[test]
fn kr_req_11_32_only_the_registered_process_reaches_the_gateway() {
    let shell = Gateway::new();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let socket = directory_of(&answer).join("gw.sock");
    let (arrived, release) = shell.backends.pause_before_confirming();
    let mut launched = shell.launch(
        &answer,
        "second",
        &[
            ("KR_STAND_IN", "origin,retry-plain"),
            ("KR_STAND_IN_COMMAND", COMMAND),
        ],
    );
    // The launch is committed, so the socket is bound, and nothing has connected to it.
    shell.at_the_confirmation(arrived);
    let mut other = std::os::unix::net::UnixStream::connect(&socket).expect("the socket is bound");
    other
        .set_read_timeout(Some(LIVENESS))
        .expect("a read timeout");
    let mut heard = [0_u8; 16];
    assert_eq!(
        std::io::Read::read(&mut other, &mut heard).expect("the connection is closed, not held"),
        0,
        "another process is closed without a word"
    );
    release.send(()).expect("the launch waits");

    launched.prints("TUI: turn/completed");
    assert!(launched.ends().success());
    assert!(
        launched.printed().contains("did not upgrade"),
        "the first upgrade was refused: {}",
        launched.printed()
    );
}

/// KR-REQ-12.07: a launch whose executable no signed record names, or whose server cannot be
/// started, runs the program as typed: it gets no flag, no server is started and nothing of the
/// launch is left published.
#[test]
fn kr_req_12_07_a_launch_that_cannot_have_a_server_runs_the_program_as_typed() {
    for case in ["no record names the executable", "the directory is gone"] {
        let shell = Gateway::with(case != "no record names the executable");
        let work = shell.placed.host.root().join("work");
        std::fs::create_dir_all(&work).expect("a working directory");
        let answer = shell
            .establish_in(&["codex"], &work)
            .expect("a backend is established");
        if case == "the directory is gone" {
            std::fs::remove_dir(&work).expect("the directory is removed");
        }
        let registration = PathBuf::from(&answer.environment[0].value);
        let mut launched = shell.launch(&answer, "typed", &[]);
        // Run as typed, the stand-in is started with no arguments and says what it serves.
        let status = launched.ends();
        assert_eq!(status.code(), Some(2), "{case}: {}", launched.said());
        assert!(
            launched.said().contains("serves `app-server"),
            "{case}: it ran with the arguments it was typed with"
        );
        assert!(shell.servers().is_empty(), "{case}: no server was started");
        assert!(
            !registration.exists(),
            "{case}: the registration was taken back"
        );
        assert!(
            shell.broker.live_bindings().is_empty(),
            "{case}: and so was the binding"
        );
    }
}

/// KR-REQ-07.60: a program that was started and never connects, as one that ran as typed does not,
/// ends the instance and the server at the bound, and the program is left to run.
#[test]
fn kr_req_07_60_a_program_that_never_connects_ends_its_instance_and_server_at_the_bound() {
    let shell = Gateway::new();
    shell.backends.connect_within(Duration::from_millis(500));
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let mut launched = shell.launch(&answer, "idle", &[("KR_STAND_IN", "idle")]);
    let started = shell.announcement();
    assert_eq!(
        started.instance.mode,
        kr_protocol::broker::IntegrationMode::Gateway
    );
    let servers = shell.servers();
    assert_eq!(servers.len(), 1, "the server was started and recorded");
    let ended = shell.announcement();
    assert!(ended.instance.ended_at.is_present(), "{ended:?}");
    eventually("the server ended at the bound", || {
        kr_ipc::identity::process_state(&servers[0]) == kr_ipc::identity::ProcessState::Ended
    });
    assert!(
        launched.child.try_wait().expect("readable").is_none(),
        "and the program that never connected is left running"
    );
}

/// KR-REQ-12.07: a launch lost to a retirement between the server being started and the commit
/// ends the server and runs the program as typed.
#[test]
fn kr_req_12_07_a_launch_lost_to_a_retirement_ends_its_server() {
    let shell = Gateway::new();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let (arrived, release) = shell.backends.pause_before_committing();
    let mut launched = shell.launch(&answer, "lost", &[]);
    shell.at_the_confirmation(arrived);
    let servers = shell.servers();
    assert_eq!(servers.len(), 1, "the server was started before the commit");
    let _ = shell.backends.close();
    release.send(()).expect("the launch waits");
    assert_eq!(launched.ends().code(), Some(2), "the program ran as typed");
    eventually("the server ended", || {
        kr_ipc::identity::process_state(&servers[0]) == kr_ipc::identity::ProcessState::Ended
    });
}

/// KR-REQ-07.60: a server that ignores both the end of its input and a terminate, with a command
/// that ignores a terminate too, is ended by force with the command when the program ends.
#[test]
fn kr_req_07_60_a_stubborn_server_and_its_command_end_by_force_with_the_program() {
    let shell = Gateway::new();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let mut launched = shell.launch(
        &answer,
        "stubborn",
        &[
            ("KR_STAND_IN", "stay,ignore-eof,ignore-term"),
            ("KR_STAND_IN_COMMAND", STUBBORN),
        ],
    );
    launched.prints("TUI: turn/completed");
    // The command is recorded below the server while it runs: the frames the session carried had
    // it look.
    eventually("the session recorded what the server started", || {
        !shell.started_by_servers().is_empty()
    });
    let server = shell.servers().remove(0);
    let started = shell.started_by_servers();
    let _ = launched.child.kill();
    let _ = launched.ends();
    for process in std::iter::once(&server).chain(&started) {
        eventually("everything the server started ended with it", || {
            kr_ipc::identity::process_state(process) == kr_ipc::identity::ProcessState::Ended
        });
    }
}

/// KR-REQ-07.60: a server that dies first, leaving its command running, leaves nothing: the
/// command was recorded while the server ran, and the program's end finds it.
#[test]
fn kr_req_07_60_a_server_that_dies_first_leaves_no_command_behind() {
    let shell = Gateway::new();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let release = shell.placed.host.root().join("release");
    let mut launched = shell.launch(
        &answer,
        "dies",
        &[
            ("KR_STAND_IN", "die-first,answer-when-released"),
            ("KR_STAND_IN_COMMAND", COMMAND),
            (
                "KR_STAND_IN_RELEASE",
                release.to_str().expect("a text path"),
            ),
        ],
    );
    launched.prints("TUI: the server asks for item/commandExecution/requestApproval");
    eventually("the session recorded what the server started", || {
        !shell.started_by_servers().is_empty()
    });
    let started = shell.started_by_servers();
    std::fs::write(&release, b"go").expect("the terminal is released");
    // The server dies as the approval is answered, with its command running; the program loses its
    // connection and leaves with an error.
    assert_eq!(launched.ends().code(), Some(1), "{}", launched.printed());
    for process in &started {
        eventually("what the server started was ended", || {
            kr_ipc::identity::process_state(process) == kr_ipc::identity::ProcessState::Ended
        });
    }
}
