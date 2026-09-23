//! A session's whole local life, driven from the command line the way a person drives it.
//!
//! Every part is a real process the operating system can see: a control daemon, the worker it
//! starts for each session, a shell in that worker's pseudo-terminal, `kr` on terminals of its own,
//! and an agent inside the session that reaches its person through the contact tools. Each step is
//! checked twice: in what the product reports, and in what the operating system shows about the
//! processes involved.
//!
//! The first test is the whole path. `kr new` creates a session and attaches the terminal it runs
//! on. The session's shell runs a scripted agent, a small shell program standing in for a coding
//! agent, that starts `kr agent-tools --stdio` as its own child, asks one question with `ask_user`
//! and waits on it with `wait_for_answer`. A person answers from another window with
//! `kr question`, and the wait returns exactly that answer. The first terminal is detached from
//! another window while a second window watches: the session, its shell and its agent go on
//! running, and the watching window stays attached. The first terminal attaches again and is drawn
//! the screen as it is rather than the history that made it, and the session ends when its shell
//! exits. The other tests are the other ways a session ends: end of input, a crash, and `kr close`
//! with its grace period and drain. Every attachment is sent how its session closed and ends with
//! the status that implies, one attachment or two, and an attachment whose connection is lost
//! without a closure still ends as a lost connection. Nothing that ends is started again.
//!
//! The daemon runs in this test's process, as it does in the host suites, and starts each worker as
//! a detached process of its own, which is how a host without a service manager starts one. The
//! worker is the one this workspace builds. It is copied to the internal disk with the command
//! binaries, and the host's runtime and state directories, every working directory and everything
//! the agent writes are on the internal disk too. The daemon keeps its keys in the file store
//! inside the host's own tree.

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use kr_controller::registry::{LaunchPhase, Registry};
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{DetachedSupervisor, NoTerminal};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::identity::{ProcessState, process_start_identity, process_state};
use kr_ipc::paths::EnvironmentPaths;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{BuildId, EnvironmentId, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::recovery::{EventsSnapshotParams, EventsSnapshotResult};
use kr_protocol::session::{ClosureRecord, SessionReadParams, SessionReadResult};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use serde_json::Value;

mod support;

use support::kr;

/// The scripted agent the session's shell runs.
const SCRIPTED_AGENT: &str = include_str!("support/scripted_agent.sh");

/// A job that ignores the request to stop, says when it is asked, and counts until it is forced.
///
/// When the request reaches it, it says so on the terminal and then creates `asked`, whose time the
/// kernel sets: the request was sent no later than that, and a job that has created it has already
/// said it was asked. Each number goes to the terminal first and is then published whole to
/// `last-tick` by a rename, so every number on record is one the job had already written to the
/// terminal. The request stops the `sleep` the job is waiting in, and it starts another.
const STUBBORN_JOB: &str = r#"#!/bin/sh
trap 'printf "the job was asked to stop\n"; [ -e asked ] || : > asked' HUP TERM
printf '%s\n' "$$" > stubborn.pid
n=0
while :; do
  n=$((n + 1))
  printf 'tick-%s\n' "$n"
  printf '%s\n' "$n" > last-tick.partial && mv last-tick.partial last-tick
  sleep 0.05
done
"#;

/// The prompt every session's shell prints, which is how a test knows the shell is reading.
const PROMPT: &str = "kr-session$ ";

/// What the person answers the agent's question with.
const ANSWER: &str = "call it Kalareach one";

/// How long a wait for something that has to happen is given.
///
/// A liveness bound, not a measurement: it is there to fail when something never happens. These
/// suites run beside others on shared machines, and a host that needs half a minute to publish a
/// closure record is slow rather than broken, which is why the bound is the one the attach suite
/// uses.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// How long a command a failing test runs while it cleans up is given.
///
/// Shorter than a liveness bound, because what follows it is the forced end of whatever the test
/// knows is still running, and a daemon that no longer answers must not keep that from happening.
const CLEANUP_COMMAND_DEADLINE: Duration = Duration::from_secs(20);

/// How long the daemon's runtime is given to finish once it has been told to stop.
const DAEMON_SHUTDOWN: Duration = Duration::from_secs(10);

/// How long a command's output is waited for once the command has exited.
///
/// Its pipes close when it exits, unless something it started holds them open; this is the bound on
/// that.
const OUTPUT_HANDOVER: Duration = Duration::from_secs(5);

/// How long a closed session is watched for anything starting again.
///
/// Longer than the drain, which is the longest anything in a closure waits: a restart would follow
/// the closure, and it would follow it inside this window.
const RESTART_WATCH: Duration = Duration::from_secs(3);

/// The grace period section 7 gives an owned process between the request to stop and force.
const GRACE_PERIOD: Duration = Duration::from_secs(5);

/// How long section 7 lets output drain after the owned processes have stopped.
const DRAIN_PERIOD: Duration = Duration::from_secs(2);

/// How many explicit closes are watched before the machine is judged too busy to watch one.
///
/// Every timing check of a close is a bound read from a watch that samples the process table. A
/// watch that was not scheduled at the moment a check depends on has seen neither a pass nor a
/// failure: that close says so, and another is watched. A bound that what was seen contradicts
/// fails at once.
const CLOSE_ATTEMPTS: usize = 3;

/// How close to a moment a sample has to be to speak for it.
const RESOLUTION: Duration = Duration::from_millis(50);

/// How far past five seconds the force may come and still count as coming when the grace ended.
///
/// The worker looks for survivors every 50 ms, and the earliest the request to stop can be placed
/// is when the close was sent, before the daemon passed it on; this covers both with room to
/// spare. A grace that ran on for seconds exceeds it.
const GRACE_TOLERANCE: Duration = Duration::from_millis(500);

/// What the worker is allowed beyond the drain to be scheduled and write the closure record.
const RECORD_ALLOWANCE: Duration = Duration::from_secs(1);

/// What a terminal that implements both keyboard protocols answers `kr`'s capability queries with,
/// ending with the device attributes that close the exchange.
const PROBE_ANSWER: &[u8] = b"\x1b[?5u\x1b[>4;2m\x1b[?62;22c";

/// The status an attachment ends with when its session closed cleanly: its shell exited with
/// status 0, or somebody closed it.
const CLEAN: i32 = 0;

/// The status an attachment ends with when its session closed any other way: the general failure.
const NOT_CLEAN: i32 = 1;

/// The status an attachment ends with when its connection ended without a closure.
const CONNECTION_LOST: i32 = 3;

/// What an attachment says when its session's shell exited with `status`.
fn exited_with(status: u64) -> Vec<u8> {
    format!("the session closed: its shell exited with status {status}").into_bytes()
}

/// What an attachment says when a signal ended its session's shell, named as the record names it.
fn ended_by(signal: &str) -> Vec<u8> {
    format!("the session closed: a signal ended its shell ({signal})").into_bytes()
}

/// What an attachment says when its session was closed on request.
const CLOSED_ON_REQUEST: &[u8] = b"the session closed: it was closed on request";

/// What an attachment says when its connection ended without a closure.
const CONNECTION_ENDED: &[u8] = b"the connection to the session ended";

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// The worker binary the daemons start: the one this workspace built, copied to the internal disk.
///
/// It is copied once for this whole process, into the directory the command binaries went to, and
/// run once there so the operating system's first look at a new binary happens here rather than
/// inside a create. That directory goes when this process does.
///
/// # Panics
///
/// Panics when the build has no worker. A demonstration that skipped would report a pass for a
/// path it never ran: `scripts/end-to-end.sh` builds the worker before it runs this, and a
/// workspace test run builds it with everything else.
fn worker() -> &'static Path {
    static COPIED: OnceLock<PathBuf> = OnceLock::new();
    COPIED.get_or_init(|| {
        let mut directory = std::env::current_exe().expect("the test binary");
        directory.pop();
        if directory.file_name().is_some_and(|name| name == "deps") {
            directory.pop();
        }
        let built = directory.join("kr-worker");
        assert!(
            built.is_file(),
            "this demonstration starts a real worker process and there is none at {}; build it \
             with `cargo build -p kr-worker` or run `scripts/end-to-end.sh`, which does",
            built.display()
        );
        let copied = support::command_binaries().join("kr-worker");
        std::fs::copy(&built, &copied).expect("copies the worker to the internal disk");
        let _ = std::process::Command::new(&copied)
            .arg("--version")
            .current_dir(support::command_binaries())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        copied
    })
}

/// Quotes a path for the POSIX shell lines this test writes.
fn quoted(path: &Path) -> String {
    let text = path.display().to_string();
    assert!(
        !text.contains('\''),
        "a path this test quotes has no quote in it: {text}"
    );
    format!("'{text}'")
}

/// Makes a named pipe.
fn make_fifo(path: &Path) {
    let mut command = std::process::Command::new("mkfifo");
    command.arg(path).env_clear().env("PATH", "/usr/bin:/bin");
    let output = output_within(command, LIVENESS_DEADLINE)
        .unwrap_or_else(|error| panic!("mkfifo {}: {error}", path.display()));
    assert!(output.status.success(), "mkfifo {}", path.display());
}

/// Runs `command` with nothing on its input, and waits at most `within` for it to exit.
///
/// What it prints is read by threads of its own, so a command that prints more than a pipe holds
/// cannot stall. One still running at `within` is killed and collected. Once it has exited, what it
/// printed is waited for until one further deadline, [`OUTPUT_HANDOVER`] later, for both pipes
/// together; so no command here takes longer than `within` and that hand-over together.
fn output_within(
    mut command: std::process::Command,
    within: Duration,
) -> Result<std::process::Output, String> {
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start: {error}"))?;
    let stdout = read_in_the_background(child.stdout.take());
    let stderr = read_in_the_background(child.stderr.take());
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let handed_over_by = Instant::now() + OUTPUT_HANDOVER;
                let stdout =
                    stdout.recv_timeout(handed_over_by.saturating_duration_since(Instant::now()));
                let stderr =
                    stderr.recv_timeout(handed_over_by.saturating_duration_since(Instant::now()));
                return match (stdout, stderr) {
                    (Ok(stdout), Ok(stderr)) => Ok(std::process::Output {
                        status,
                        stdout,
                        stderr,
                    }),
                    _ => Err(format!(
                        "exited {status}, and something it started still held what it printed \
                         open"
                    )),
                };
            }
            Ok(None) if started.elapsed() < within => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("was still running after {within:?}, and was ended"));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("could not be waited for: {error}"));
            }
        }
    }
}

/// Reads one of a command's output pipes to its end, and hands over what it read.
fn read_in_the_background(
    pipe: Option<impl Read + Send + 'static>,
) -> std::sync::mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut bytes);
        }
        let _ = sender.send(bytes);
    });
    receiver
}

/// A host of this test's own: its tree, the worker it starts, and its control daemon.
struct Host {
    /// The runtime and state directories, held in an option so a failed test can keep them.
    temp: Option<kr_ipc::testing::TempHost>,
    /// The directory every session's shell starts in. The scripted agent and its gates are here.
    work: PathBuf,
    /// The home directory every process this test starts is given, so none of them reads the
    /// person's own.
    home: PathBuf,
    daemon: Option<Daemon>,
    /// Every process this test learned the identity of, so a test that fails part way can end the
    /// ones that are still running.
    started: Mutex<Vec<(ProcessStartIdentity, String)>>,
    /// Reads of the worker and the daemon over their local endpoints.
    runtime: tokio::runtime::Runtime,
}

impl Host {
    fn start() -> Self {
        // Copied and run once before anything starts, so no wait below pays for the first run of a
        // binary the operating system has not seen before.
        let worker = worker();
        let temp = kr_ipc::testing::TempHost::create();
        let root = temp.root().to_path_buf();
        let work = root.join("w");
        let home = root.join("h");
        for directory in [&work, &home] {
            std::fs::create_dir(directory).expect("a directory on the internal disk");
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .expect("makes it the owner's alone");
        }
        let agent = work.join("agent");
        std::fs::write(&agent, SCRIPTED_AGENT).expect("writes the scripted agent");
        std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o755))
            .expect("makes the agent runnable");
        // The agent's tool configuration: which `kr` to start, and the host it belongs to.
        std::fs::write(
            work.join("agent.conf"),
            format!(
                "kr={}\nkr_runtime_dir={}\nkr_state_dir={}\n",
                quoted(&kr()),
                quoted(temp.paths().runtime_root()),
                quoted(temp.paths().state_root()),
            ),
        )
        .expect("writes the agent's configuration");
        let job = work.join("stubborn");
        std::fs::write(&job, STUBBORN_JOB).expect("writes the stubborn job");
        std::fs::set_permissions(&job, std::fs::Permissions::from_mode(0o755))
            .expect("makes the job runnable");
        for gate in ["go-on", "finish"] {
            make_fifo(&work.join(gate));
        }
        let daemon = Daemon::start(
            temp.environment(),
            temp.environment_id(),
            worker.to_path_buf(),
        );
        Self {
            temp: Some(temp),
            work,
            home,
            daemon: Some(daemon),
            started: Mutex::new(Vec::new()),
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime for local reads"),
        }
    }

    fn tree(&self) -> &kr_ipc::testing::TempHost {
        self.temp.as_ref().expect("the host tree is still held")
    }

    fn root(&self) -> &Path {
        self.tree().root()
    }

    fn environment(&self) -> EnvironmentPaths {
        self.tree().environment()
    }

    /// The environment every process this test starts is given, and nothing else.
    fn variables(&self) -> Vec<(&'static str, String)> {
        vec![
            ("PATH", "/usr/bin:/bin".to_owned()),
            ("TERM", "xterm-256color".to_owned()),
            ("HOME", self.home.display().to_string()),
            (
                "KR_RUNTIME_DIR",
                self.tree().paths().runtime_root().display().to_string(),
            ),
            (
                "KR_STATE_DIR",
                self.tree().paths().state_root().display().to_string(),
            ),
        ]
    }

    /// Opens a window, creates a session in it with `kr new`, and waits for the session's shell to
    /// read.
    ///
    /// The window's own shell prints how `kr new` ended and then runs `then`. The prompt is given
    /// to `kr new` itself, whose environment is the one the session's shell starts from: a
    /// window's shell is not interactive, and does not pass a prompt on.
    fn create_in_window(&self, then: &str) -> (Window, Created) {
        let window = Window::open(
            self,
            &format!(
                "env 'PS1={PROMPT}' {} new --attach --headless --shell /bin/sh \
                 --startup interactive --cwd {}; printf '\\nnew-%s-%s\\n' finished \"$?\"; {then}",
                quoted(&kr()),
                quoted(&self.work)
            ),
        );
        answered(window.answer_capability_queries(0));
        window.wait_for(0, PROMPT.as_bytes(), "the new session's shell is reading");
        let listed = self.only_live_session();
        let session_id: SessionId = listed["session_id"]
            .as_str()
            .expect("an identifier")
            .parse()
            .expect("a session identifier");
        let display = listed["display_number"]
            .as_u64()
            .expect("a display number")
            .to_string();
        let worker = self.worker_of(session_id);
        let snapshot = self.snapshot(session_id);
        let root = snapshot
            .session
            .root_process
            .as_ref()
            .cloned()
            .expect("the session names its root shell");
        self.record(&root, "a session's shell");
        (
            window,
            Created {
                session_id,
                display,
                listed,
                snapshot,
                worker,
                root,
            },
        )
    }

    /// Runs `kr` as a command in another window: no terminal, and the host's directories.
    fn kr(&self, arguments: &[&str]) -> std::process::Output {
        self.kr_within(arguments, LIVENESS_DEADLINE)
            .unwrap_or_else(|error| panic!("kr {arguments:?} {error}"))
    }

    /// Runs `kr` the same way, and waits at most `within` for it.
    fn kr_within(
        &self,
        arguments: &[&str],
        within: Duration,
    ) -> Result<std::process::Output, String> {
        let mut command = std::process::Command::new(kr());
        command
            .args(arguments)
            .env_clear()
            .envs(self.variables())
            .current_dir(self.root());
        output_within(command, within)
    }

    /// Runs `kr` with `--json`, requires it to succeed, and returns what it printed.
    fn kr_json(&self, arguments: &[&str]) -> Value {
        let mut arguments = arguments.to_vec();
        arguments.push("--json");
        let output = self.kr(&arguments);
        assert!(
            output.status.success(),
            "kr {arguments:?} exited {:?}: {}{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "kr {arguments:?} printed a document: {error}: {}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
    }

    /// The one live session, as `kr list` reports it.
    fn only_live_session(&self) -> Value {
        let listed = self.kr_json(&["list"]);
        let sessions = listed["sessions"].as_array().expect("a list of sessions");
        assert_eq!(sessions.len(), 1, "one session is live: {listed}");
        sessions[0].clone()
    }

    /// Waits for `kr status` to report the session closed, and returns that report.
    fn wait_until_closed(&self, session: &str) -> Value {
        let started = Instant::now();
        loop {
            let output = self.kr(&["status", session, "--json"]);
            let said = match serde_json::from_slice::<Value>(&output.stdout) {
                Ok(report) if output.status.success() => {
                    if report["state"] == "closed" {
                        return report;
                    }
                    report.to_string()
                }
                _ => format!(
                    "exit {:?}: {}{}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ),
            };
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "waited {:?} for session {session} to close; kr status last said {said}",
                started.elapsed()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Reads the session's own state from its worker: who is attached, and its root shell.
    fn snapshot(&self, session_id: SessionId) -> EventsSnapshotResult {
        let environment = self.environment();
        let descriptor = kr_ipc::descriptor::read_all(&environment)
            .expect("reads the published descriptors")
            .into_iter()
            .filter_map(|entry| entry.descriptor.ok())
            .find(|descriptor| descriptor.session_id == session_id)
            .unwrap_or_else(|| panic!("session {session_id} has a published worker"));
        let read = self.runtime.block_on(async {
            tokio::time::timeout(LIVENESS_DEADLINE, async {
                let endpoint = kr_ipc::paths::Endpoint::from_path(&descriptor.endpoint)
                    .expect("the descriptor names an endpoint");
                let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
                    .await
                    .expect("reaches the worker");
                client
                    .verify_worker(&descriptor)
                    .await
                    .expect("the worker proves it is the one the descriptor names");
                client
                    .request(
                        Method::EventsSnapshot,
                        &EventsSnapshotParams {
                            session_id,
                            agent_resources_from: kr_protocol::scalars::Nullable::null(),
                        },
                    )
                    .await
                    .expect("the request reaches the worker")
                    .unwrap_or_else(|error| panic!("the worker refused the snapshot: {error}"))
                    .to_typed()
                    .expect("decodes the snapshot")
            })
            .await
        });
        read.unwrap_or_else(|_| {
            panic!("the worker did not answer a snapshot within {LIVENESS_DEADLINE:?}")
        })
    }

    /// Reads the whole closure record the daemon keeps for a session.
    fn closure(&self, session_id: SessionId) -> ClosureRecord {
        let endpoint = self
            .environment()
            .controller_endpoint()
            .expect("the daemon's endpoint");
        let read = self.runtime.block_on(async {
            tokio::time::timeout(LIVENESS_DEADLINE, async {
                let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
                    .await
                    .expect("reaches the daemon");
                client
                    .request(Method::SessionRead, &SessionReadParams { session_id })
                    .await
                    .expect("the request reaches the daemon")
                    .unwrap_or_else(|error| panic!("the daemon refused the read: {error}"))
                    .to_typed::<SessionReadResult>()
                    .expect("decodes the read")
            })
            .await
        });
        let read = read.unwrap_or_else(|_| {
            panic!("the daemon did not answer a read within {LIVENESS_DEADLINE:?}")
        });
        read.session
            .closure
            .as_ref()
            .cloned()
            .expect("a closed session has a closure record")
    }

    /// The process identity of the worker the daemon started for a session.
    fn worker_of(&self, session_id: SessionId) -> ProcessStartIdentity {
        let environment = self.environment();
        let registry = Registry::open(
            environment.registry_database(),
            environment.environment_id(),
        )
        .expect("opens the registry");
        let worker = registry
            .workers()
            .expect("reads the worker records")
            .into_iter()
            .find(|worker| worker.session_id == session_id)
            .unwrap_or_else(|| panic!("session {session_id} has a worker record"))
            .process_identity;
        self.record(&worker, "a worker");
        worker
    }

    /// Remembers a process this test started or learned of, for the failing path's cleanup.
    fn record(&self, identity: &ProcessStartIdentity, what: &str) {
        self.started
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((identity.clone(), what.to_owned()));
    }

    /// Reads a process identifier something in the session wrote into the working directory, and
    /// returns the process the kernel says it names.
    fn written_process(&self, file: &str, what: &str) -> ProcessStartIdentity {
        let path = self.work.join(file);
        let pid = until(what, || {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|text| text.trim().parse::<u32>().ok())
        });
        let identity = process_start_identity(pid)
            .unwrap_or_else(|error| panic!("the kernel describes {what}, process {pid}: {error}"));
        self.record(&identity, what);
        identity
    }

    /// Reads one reply the agent kept, once it has written it.
    fn agent_reply(&self, file: &str) -> Value {
        let path = self.work.join(file);
        let text = until(&format!("the agent to keep its {file}"), || {
            std::fs::read_to_string(&path).ok()
        });
        serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("the agent kept a reply in {file}: {error}: {text}"))
    }

    /// Lets the agent past one of its gates.
    fn open_gate(&self, gate: &str) {
        let fifo = self.work.join(gate);
        let started = Instant::now();
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo)
            {
                Ok(mut file) => {
                    file.write_all(b"\n").expect("writes into the gate");
                    return;
                }
                // Nobody is reading it yet: the agent has not reached this gate.
                Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {
                    assert!(
                        started.elapsed() < LIVENESS_DEADLINE,
                        "waited {:?} for the agent to reach its {gate} gate",
                        started.elapsed()
                    );
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("opens the {gate} gate: {error}"),
            }
        }
    }

    /// The questions `kr question list` shows, as a person in another window would ask.
    fn questions(&self) -> Vec<Value> {
        self.kr_json(&["question", "list"])["questions"]
            .as_array()
            .expect("a list of questions")
            .clone()
    }

    /// Every worker process of this host that is running.
    ///
    /// A worker is started with the environment it belongs to among its arguments, and this host's
    /// environment is its own, so the process table names every worker this host started and no
    /// other.
    fn running_workers(&self) -> Vec<u32> {
        let mut command = std::process::Command::new("pgrep");
        command
            .arg("-f")
            .arg("--")
            .arg(format!("--environment {}", self.tree().environment_id()));
        let listing = output_within(command, LIVENESS_DEADLINE)
            .unwrap_or_else(|error| panic!("pgrep {error}"));
        String::from_utf8_lossy(&listing.stdout)
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .collect()
    }

    /// Watches closed sessions for a while and requires that nothing starts again.
    ///
    /// Nothing may: no worker of this host is running, nothing is live, and every session the host
    /// lists is one this test created, closed, with no replacement beside it.
    fn nothing_restarts(&self, closed: &[SessionId]) {
        let watching = Instant::now();
        loop {
            let workers = self.running_workers();
            assert!(
                workers.is_empty(),
                "no worker of this host is running once its sessions have closed: {workers:?}"
            );
            let live = self.kr_json(&["list"]);
            assert!(
                live["sessions"]
                    .as_array()
                    .is_some_and(std::vec::Vec::is_empty),
                "no session is live again: {live}"
            );
            if watching.elapsed() >= RESTART_WATCH {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        let everything = self.kr_json(&["list", "--include-closed"]);
        let listed: Vec<(String, String)> = everything["sessions"]
            .as_array()
            .expect("a list of sessions")
            .iter()
            .map(|session| {
                (
                    session["session_id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    session["state"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        let mut expected: Vec<(String, String)> = closed
            .iter()
            .map(|session_id| (session_id.to_string(), "closed".to_owned()))
            .collect();
        let mut listed_sorted = listed.clone();
        listed_sorted.sort();
        expected.sort();
        assert_eq!(
            listed_sorted, expected,
            "the host lists exactly the sessions this test created, each closed: {everything}"
        );
    }

    /// Ends what a test that failed part way left running.
    ///
    /// The ordinary end has closed every session and seen every process go, so this finds nothing.
    /// A failure leaves sessions open: each is closed through the host first, which stops what it
    /// owns with the grace period and the force a person's close would use, and anything this
    /// test knows of that is still running after that is ended outright, by the identity the
    /// kernel gave it, so a reused identifier is never signalled.
    fn end_what_is_left(&self) -> Vec<String> {
        if let Ok(listed) = self.kr_within(&["list", "--json"], CLEANUP_COMMAND_DEADLINE)
            && let Ok(listed) = serde_json::from_slice::<Value>(&listed.stdout)
            && let Some(sessions) = listed["sessions"].as_array()
        {
            for session in sessions {
                if let Some(session_id) = session["session_id"].as_str() {
                    let _ = self.kr_within(&["close", session_id], CLEANUP_COMMAND_DEADLINE);
                }
            }
        }
        let mut following = self
            .started
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let environment = self.environment();
        if let Ok(registry) = Registry::open(
            environment.registry_database(),
            environment.environment_id(),
        ) {
            if let Ok(workers) = registry.workers() {
                following.extend(
                    workers
                        .into_iter()
                        .map(|worker| (worker.process_identity, "a worker".to_owned())),
                );
            }
            for phase in [
                LaunchPhase::Spawned,
                LaunchPhase::Claimed,
                LaunchPhase::Live,
                LaunchPhase::Fenced,
            ] {
                if let Ok(reservations) = registry.reservations_in(phase) {
                    following.extend(reservations.into_iter().filter_map(|reservation| {
                        reservation
                            .launcher_identity
                            .map(|identity| (identity, "a launched worker".to_owned()))
                    }));
                }
            }
        }
        // A closure takes its grace period and its drain; anything still running after twice that
        // is not going to stop by itself, and is forced.
        let mut patience = Instant::now() + (GRACE_PERIOD + DRAIN_PERIOD) * 2;
        let mut forced = false;
        loop {
            following
                .retain(|(identity, _)| !matches!(process_state(identity), ProcessState::Ended));
            if following.is_empty() {
                return Vec::new();
            }
            if Instant::now() >= patience {
                if forced {
                    return following
                        .iter()
                        .map(|(identity, what)| format!("{what}, process {}", identity.pid.get()))
                        .collect();
                }
                for (identity, what) in &following {
                    eprintln!(
                        "ending {what}, process {}, which this test started and did not see end",
                        identity.pid.get()
                    );
                    if let Ok(pid) = i32::try_from(identity.pid.get())
                        && let Some(pid) = rustix::process::Pid::from_raw(pid)
                        && matches!(process_state(identity), ProcessState::Running)
                    {
                        let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
                    }
                }
                forced = true;
                patience = Instant::now() + GRACE_PERIOD;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let unresolved = self.end_what_is_left();
        drop(self.daemon.take());
        if unresolved.is_empty() {
            return;
        }
        // Not established as ended. The tree stays, because removing the directories a live
        // process is reading is a worse state to leave a machine in than a directory to remove.
        if let Some(temp) = self.temp.take() {
            eprintln!(
                "the host tree has been kept at {} because these did not end: {unresolved:?}",
                temp.root().display()
            );
            std::mem::forget(temp);
        }
    }
}

/// A session `kr new` created, as the host and the kernel describe it.
struct Created {
    session_id: SessionId,
    /// Its display number, as a person types it.
    display: String,
    /// What `kr list` reported for it.
    listed: Value,
    /// What its worker reported once its shell was reading.
    snapshot: EventsSnapshotResult,
    /// The worker the daemon started for it.
    worker: ProcessStartIdentity,
    /// Its root shell.
    root: ProcessStartIdentity,
}

/// The control daemon, serving on a runtime of its own in a thread of its own.
///
/// In an installation the daemon is a process of its own. Here it is a runtime of its own, so
/// nothing this test does while it waits on a terminal or a process can hold the daemon up.
struct Daemon {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Daemon {
    fn start(paths: EnvironmentPaths, environment_id: EnvironmentId, worker: PathBuf) -> Self {
        let (ready, started) = std::sync::mpsc::channel::<Result<(), String>>();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("control daemon".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(4)
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready.send(Err(error.to_string()));
                        return;
                    }
                };
                runtime.block_on(serve(paths, environment_id, worker, ready, stopped));
                // Whatever the daemon still had running is given a bounded moment, so a task that
                // will not stop cannot keep this test from ending.
                runtime.shutdown_timeout(DAEMON_SHUTDOWN);
            })
            .expect("starts the daemon's thread");
        match started.recv_timeout(LIVENESS_DEADLINE) {
            Ok(Ok(())) => {}
            Ok(Err(detail)) => panic!("the control daemon did not start: {detail}"),
            Err(error) => panic!("the control daemon did not say it had started: {error}"),
        }
        Self {
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Starts the control daemon and serves until told to stop.
///
/// It is what `kr-controller` does, with two choices a test has to make: the detached supervisor,
/// so a worker is a process of its own rather than a job left in the person's own service manager,
/// and the file store inside the host's tree for its keys.
async fn serve(
    paths: EnvironmentPaths,
    environment_id: EnvironmentId,
    worker: PathBuf,
    ready: std::sync::mpsc::Sender<Result<(), String>>,
    stopped: tokio::sync::oneshot::Receiver<()>,
) {
    let secrets = paths.secrets_dir();
    let boot_identity = match kr_ipc::identity::boot_identity() {
        Ok(identity) => identity,
        Err(error) => {
            let _ = ready.send(Err(error.to_string()));
            return;
        }
    };
    let started = Controller::start(ControllerSetup {
        paths: paths.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).map_err(|error| {
                kr_controller::ControllerError::NotConfigured(error.to_string())
            })?;
            ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                .map_err(|error| kr_controller::ControllerError::NotConfigured(error.to_string()))
        }),
        secret_store: StoreSelection::File,
        boot_identity,
        supervisor: Box::new(DetachedSupervisor::new()),
        worker_program: worker,
        build_id: build(),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(NoTerminal),
    })
    .await;
    let controller = match started {
        Ok(controller) => controller,
        Err(error) => {
            let _ = ready.send(Err(error.to_string()));
            return;
        }
    };
    let listeners = paths
        .rendezvous_endpoint()
        .and_then(|endpoint| Listener::bind(&endpoint))
        .and_then(|rendezvous| {
            paths
                .controller_endpoint()
                .and_then(|endpoint| Listener::bind(&endpoint))
                .map(|clients| (rendezvous, clients))
        });
    let (rendezvous, clients) = match listeners {
        Ok(listeners) => listeners,
        Err(error) => {
            let _ = ready.send(Err(error.to_string()));
            return;
        }
    };
    let serving = [
        tokio::spawn(Arc::clone(&controller).serve_rendezvous(rendezvous)),
        tokio::spawn(Arc::clone(&controller).serve_clients(clients)),
    ];
    let _ = ready.send(Ok(()));
    let _ = stopped.await;
    for task in &serving {
        task.abort();
    }
    let _ = tokio::time::timeout(DAEMON_SHUTDOWN, async {
        for task in serving {
            let _ = task.await;
        }
    })
    .await;
    drop(controller);
}

/// Everything a terminal has been sent, collected by a thread that never blocks the test.
#[derive(Clone)]
struct Screen {
    seen: Arc<Mutex<Vec<u8>>>,
}

impl Screen {
    fn collect(mut reader: Box<dyn Read + Send>) -> Self {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                collected
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend_from_slice(&buffer[..read]);
            }
        });
        Self { seen }
    }

    /// How much the terminal has been sent so far. A later wait can start from here.
    fn mark(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// What the terminal has been sent since a mark.
    fn since(&self, mark: usize) -> Vec<u8> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(mark..)
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    }

    fn contains_since(&self, mark: usize, marker: &[u8]) -> bool {
        contains(&self.since(mark), marker)
    }

    /// Waits for `marker` to arrive after `mark`, and fails with what did arrive when it never
    /// does.
    ///
    /// It looks every two milliseconds, because one of the things that waits here is the thread
    /// that answers `kr`'s capability queries, and that exchange has one second in all.
    fn wait_for(&self, mark: usize, marker: &[u8], what: &str) {
        let started = Instant::now();
        loop {
            if self.contains_since(mark, marker) {
                return;
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "{what}: waited {:?} for {:?} on the terminal, which was sent: {}",
                started.elapsed(),
                String::from_utf8_lossy(marker),
                String::from_utf8_lossy(&self.since(mark)).escape_debug()
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// A terminal window: a pseudo-terminal with a shell on it, as a person's own terminal has.
///
/// The shell is the session leader and `kr` runs inside it, which is how a person's terminal is
/// arranged: `kr new` and `kr attach` are commands in a window, not the window itself.
struct Window {
    /// The terminal pair, held open for as long as the window is.
    _terminal: portable_pty::PtyPair,
    shell: Box<dyn portable_pty::Child + Send + Sync>,
    screen: Screen,
    keys: Arc<Mutex<Box<dyn Write + Send>>>,
}

impl Window {
    /// Opens a window whose shell runs `script`.
    fn open(host: &Host, script: &str) -> Self {
        let terminal = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("opens a terminal");
        let mut command = CommandBuilder::new("/bin/sh");
        command.arg("-c");
        command.arg(script);
        command.env_clear();
        for (name, value) in host.variables() {
            command.env(name, value);
        }
        command.cwd(host.root());
        let shell = terminal
            .slave
            .spawn_command(command)
            .expect("starts the window's shell");
        let screen = Screen::collect(terminal.master.try_clone_reader().expect("a reader"));
        let keys = Arc::new(Mutex::new(terminal.master.take_writer().expect("a writer")));
        Self {
            _terminal: terminal,
            shell,
            screen,
            keys,
        }
    }

    fn mark(&self) -> usize {
        self.screen.mark()
    }

    fn wait_for(&self, mark: usize, marker: &[u8], what: &str) {
        self.screen.wait_for(mark, marker, what);
    }

    /// Types into the window.
    fn type_text(&self, bytes: &[u8]) {
        let mut keys = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        keys.write_all(bytes).expect("types into the terminal");
        keys.flush().expect("and it reaches the terminal");
    }

    /// Waits for the window's shell to print `marker` and an exit status after `mark`, and returns
    /// the status.
    fn exit_status_after(&self, mark: usize, marker: &str, what: &str) -> i32 {
        until(what, || {
            let text = String::from_utf8_lossy(&self.screen.since(mark)).into_owned();
            let rest = &text[text.find(marker)? + marker.len()..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            // Only once the line is whole: a status is followed by the end of its line.
            rest[digits.len()..]
                .starts_with(['\r', '\n'])
                .then(|| digits.parse().ok())
                .flatten()
        })
    }

    /// Waits for the attachment in this window to end after `mark`, and requires the status it
    /// ended with and the line it said.
    ///
    /// `marker` is what the window's shell prints before the status of the `kr` it ran.
    fn attachment_ended(&self, mark: usize, marker: &str, status: i32, said: &[u8], what: &str) {
        let ended = self.exit_status_after(mark, marker, what);
        let shown = self.screen.since(mark);
        assert_eq!(
            ended,
            status,
            "{what}: the attachment ended with status {ended}, not {status}: {}",
            String::from_utf8_lossy(&shown).escape_debug()
        );
        assert!(
            contains(&shown, said),
            "{what}: the attachment said {:?}: {}",
            String::from_utf8_lossy(said),
            String::from_utf8_lossy(&shown).escape_debug()
        );
    }

    /// Answers the next capability exchange `kr` starts on this terminal after `mark`.
    fn answer_capability_queries(&self, mark: usize) -> std::thread::JoinHandle<()> {
        let screen = self.screen.clone();
        let keys = Arc::clone(&self.keys);
        std::thread::spawn(move || {
            screen.wait_for(
                mark,
                b"\x1b[c",
                "kr asked this terminal what it is before attaching",
            );
            let mut keys = keys.lock().unwrap_or_else(PoisonError::into_inner);
            keys.write_all(PROBE_ANSWER)
                .expect("answers the capability queries");
            keys.flush().expect("and the answer reaches kr");
        })
    }

    /// Waits until the terminal is back in line mode with echo, which is how `kr` found it.
    ///
    /// An attachment puts its terminal into raw mode, and whatever ends the attachment puts it
    /// back. The modes are the kernel's, read from the terminal device itself, which is opened
    /// without becoming anybody's controlling terminal.
    fn wait_until_put_back(&self, what: &str) {
        let device = self
            ._terminal
            .master
            .tty_name()
            .expect("the terminal has a device");
        let terminal = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
            .open(&device)
            .unwrap_or_else(|error| panic!("opens {}: {error}", device.display()));
        until(what, || {
            let modes = rustix::termios::tcgetattr(&terminal).expect("reads the terminal's modes");
            (modes
                .local_modes
                .contains(rustix::termios::LocalModes::ICANON)
                && modes
                    .local_modes
                    .contains(rustix::termios::LocalModes::ECHO))
            .then_some(())
        });
    }

    /// The `kr` process this window's shell is running.
    fn kr_process(&self) -> ProcessStartIdentity {
        let shell = self
            .shell
            .process_id()
            .expect("the shell has an identifier");
        let pid = until("the window's shell to start kr", || {
            children_of(shell)
                .into_iter()
                .find(|pid| command_of(*pid).starts_with(&kr().display().to_string()))
        });
        process_start_identity(pid).expect("the kernel describes the kr process")
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        let _ = self.shell.kill();
        let _ = self.shell.wait();
    }
}

/// Waits for the thread answering a terminal's capability queries, and brings its failure here.
fn answered(queries: std::thread::JoinHandle<()>) {
    if let Err(panic) = queries.join() {
        let detail = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap_or("the thread answering the terminal's queries failed");
        panic!("{detail}");
    }
}

/// Opens a window that watches a session and never types, and waits until it has been drawn the
/// session's screen, which it can only be once it is subscribed.
///
/// Its shell prints `watch-finished-` and the status `kr attach` ended with.
fn watcher(host: &Host, display: &str) -> Window {
    let window = Window::open(
        host,
        &format!(
            "{kr} attach --no-probe {display}; printf '\\nwatch-%s-%s\\n' finished \"$?\"; \
             IFS= read -r _",
            kr = quoted(&kr()),
        ),
    );
    window.wait_for(
        0,
        PROMPT.as_bytes(),
        "the watching window was drawn the session's screen",
    );
    window
}

/// Polls until `found` has an answer, and fails with how long it waited when it never does.
fn until<T>(what: &str, mut found: impl FnMut() -> Option<T>) -> T {
    let started = Instant::now();
    loop {
        if let Some(value) = found() {
            return value;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "waited {:?} for {what}",
            started.elapsed()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn running(identity: &ProcessStartIdentity) -> bool {
    matches!(process_state(identity), ProcessState::Running)
}

/// Waits until the kernel says a process has ended, and returns when it first said so.
fn ended(identity: &ProcessStartIdentity, what: &str) -> Instant {
    until(&format!("{what} to end"), || {
        matches!(process_state(identity), ProcessState::Ended).then(Instant::now)
    })
}

/// The parent the kernel names for a process.
fn parent_of(pid: u32) -> u32 {
    let mut command = std::process::Command::new("ps");
    command.args(["-o", "ppid=", "-p", &pid.to_string()]);
    let output =
        output_within(command, LIVENESS_DEADLINE).unwrap_or_else(|error| panic!("ps {error}"));
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("the process table names a parent for process {pid}"))
}

/// Whether `ancestor` is on the kernel's parent chain of `pid`.
fn descends_from(pid: u32, ancestor: u32) -> bool {
    let mut current = pid;
    for _ in 0..64 {
        if current == ancestor {
            return true;
        }
        if current <= 1 {
            return false;
        }
        current = parent_of(current);
    }
    false
}

fn children_of(pid: u32) -> Vec<u32> {
    let mut command = std::process::Command::new("pgrep");
    command.args(["-P", &pid.to_string()]);
    let listing =
        output_within(command, LIVENESS_DEADLINE).unwrap_or_else(|error| panic!("pgrep {error}"));
    String::from_utf8_lossy(&listing.stdout)
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect()
}

fn command_of(pid: u32) -> String {
    let mut command = std::process::Command::new("ps");
    command.args(["-o", "command=", "-p", &pid.to_string()]);
    let named =
        output_within(command, LIVENESS_DEADLINE).unwrap_or_else(|error| panic!("ps {error}"));
    String::from_utf8_lossy(&named.stdout).trim().to_owned()
}

/// Collects the exit status of a worker this process started, as the kernel reports it.
///
/// The daemon runs in this process, so every worker it started is this process's child, and its
/// status is this process's to collect.
fn worker_exit_status(worker: &ProcessStartIdentity) -> i32 {
    let pid = rustix::process::Pid::from_raw(
        i32::try_from(worker.pid.get()).expect("a process identifier"),
    )
    .expect("a process identifier");
    let status = until("the worker to exit", || {
        rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG)
            .expect("the worker is this process's child")
            .map(|(_, status)| status)
    });
    status.exit_status().unwrap_or_else(|| {
        panic!(
            "the worker exited rather than being ended by a signal: {:?}",
            status.terminating_signal()
        )
    })
}

/// Collects the status of a worker this test killed, and requires that the kill is what ended it.
fn worker_killed(worker: &ProcessStartIdentity) {
    let pid = rustix::process::Pid::from_raw(
        i32::try_from(worker.pid.get()).expect("a process identifier"),
    )
    .expect("a process identifier");
    let status = until("the killed worker to be collected", || {
        rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG)
            .expect("the worker is this process's child")
            .map(|(_, status)| status)
    });
    assert_eq!(
        status.terminating_signal(),
        Some(libc::SIGKILL),
        "the worker was ended by the kill: {status:?}"
    );
}

/// Kills a process this test knows by the identity the kernel gave it.
fn kill(identity: &ProcessStartIdentity, what: &str) {
    assert!(running(identity), "{what} is running before it is killed");
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(i32::try_from(identity.pid.get()).expect("an identifier"))
            .expect("an identifier"),
        rustix::process::Signal::KILL,
    )
    .unwrap_or_else(|error| panic!("kills {what}: {error}"));
}

/// Whether `haystack` shows `prefix` followed by exactly `number`.
fn shows_number(haystack: &[u8], prefix: &[u8], number: u64) -> bool {
    let wanted = [prefix, number.to_string().as_bytes()].concat();
    haystack
        .windows(wanted.len())
        .enumerate()
        .any(|(at, window)| {
            window == wanted.as_slice()
                && !haystack
                    .get(at + wanted.len())
                    .is_some_and(u8::is_ascii_digit)
        })
}

/// The kernel's view of some processes, sampled from before a request until each has ended.
///
/// Every sample bounds when a process ended: one that found it running was taken before it ended,
/// and one that found it gone was taken after. Each is recorded on the side that keeps its bound
/// honest, the start of a sample that found the process running and the end of one that found it
/// gone. [`Watch::start`] returns only once a sample has found every process running, so a watch
/// that is held up afterwards can only leave the interval between the two wider; it cannot narrow
/// it or move it.
struct Watch {
    thread: std::thread::JoinHandle<Vec<Seen>>,
}

/// Between which moments the watch saw one process end, on both clocks.
#[derive(Clone, Copy, Debug)]
struct Seen {
    /// The start of the last sample that found it running.
    running: Instant,
    /// The same moment on the system clock, which the closure record and file times are in.
    running_at: SystemTime,
    /// The end of the first sample that found it gone.
    gone: Instant,
    /// The same moment on the system clock.
    gone_at: SystemTime,
}

impl Watch {
    /// Starts watching, and returns once a sample has found every process running.
    ///
    /// # Panics
    ///
    /// Panics when a process is not running when the watch begins, which everything the watch is
    /// for depends on.
    fn start(processes: Vec<ProcessStartIdentity>) -> Self {
        let (ready, began) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let started = Instant::now();
            let mut running: Vec<Option<(Instant, SystemTime)>> = vec![None; processes.len()];
            let mut gone: Vec<Option<(Instant, SystemTime)>> = vec![None; processes.len()];
            let mut ready = Some(ready);
            while gone.iter().any(Option::is_none) && started.elapsed() < LIVENESS_DEADLINE {
                for (index, identity) in processes.iter().enumerate() {
                    if gone[index].is_some() {
                        continue;
                    }
                    let before = (Instant::now(), SystemTime::now());
                    match process_state(identity) {
                        ProcessState::Running => running[index] = Some(before),
                        ProcessState::Ended => {
                            gone[index] = Some((Instant::now(), SystemTime::now()));
                        }
                        ProcessState::Unknown { .. } => {}
                    }
                }
                // Said after the first round, whatever that round found.
                if let Some(ready) = ready.take() {
                    let _ = ready.send(running.iter().all(Option::is_some));
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            running
                .into_iter()
                .zip(gone)
                .map(|(running, gone)| {
                    let (running, running_at) = running
                        .unwrap_or_else(|| panic!("a watched process was never seen running"));
                    let (gone, gone_at) = gone.unwrap_or_else(|| {
                        panic!("a watched process was still running after {LIVENESS_DEADLINE:?}")
                    });
                    Seen {
                        running,
                        running_at,
                        gone,
                        gone_at,
                    }
                })
                .collect()
        });
        let all_running = began
            .recv_timeout(LIVENESS_DEADLINE)
            .unwrap_or_else(|_| panic!("the watch took no sample within {LIVENESS_DEADLINE:?}"));
        assert!(
            all_running,
            "every watched process was running when the watch began"
        );
        Self { thread }
    }

    /// Waits until every watched process has ended, and says when each was seen to.
    fn finish(self) -> Vec<Seen> {
        self.thread.join().unwrap_or_else(|panic| {
            let detail = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
                .unwrap_or_else(|| "the watch failed".to_owned());
            panic!("{detail}")
        })
    }
}

/// KR-REQ-01.01, the local leg; KR-REQ-07.52: a session created on the command line carries an
/// agent's question to its person, outlives the terminal that made it, is attached again, and ends
/// when its own shell exits.
#[test]
fn a_session_made_by_kr_new_carries_a_question_outlives_its_terminal_and_ends_with_its_shell() {
    let host = Host::start();

    // KR-REQ-01.01: a person creates a session from the command line, in the terminal they are
    // using, and that terminal is attached to it. Once that attachment ends, the same window can
    // attach again.
    let (first, created) = host.create_in_window(&format!(
        "IFS= read -r selector; {kr} attach \"$selector\"; \
         printf '\\nattach-%s-%s\\n' finished \"$?\"; IFS= read -r _",
        kr = quoted(&kr()),
    ));
    let Created {
        session_id,
        display,
        listed: session,
        snapshot: created,
        worker,
        root,
    } = created;
    assert_eq!(session["state"], "live");
    assert_eq!(
        session["attachments"], 1,
        "the creating terminal is attached"
    );
    assert_eq!(session["shell_mode"], "native_compat");
    assert_eq!(session["shell"], "/bin/sh");

    // What the operating system shows: the daemon started a worker, the worker started the shell,
    // and neither belongs to the terminal that asked for them.
    let kr_new = first.kr_process();
    assert!(running(&worker) && running(&root) && running(&kr_new));
    let root_pid = u32::try_from(root.pid.get()).expect("a process identifier");
    let worker_pid = u32::try_from(worker.pid.get()).expect("a process identifier");
    let kr_new_pid = u32::try_from(kr_new.pid.get()).expect("a process identifier");
    assert_eq!(
        parent_of(root_pid),
        worker_pid,
        "the root shell is the worker's own child"
    );
    assert_eq!(
        parent_of(worker_pid),
        std::process::id(),
        "the worker was started by the control daemon"
    );
    assert!(
        !descends_from(worker_pid, kr_new_pid),
        "the worker is not a descendant of the kr new that asked for it"
    );
    assert_eq!(
        host.running_workers(),
        vec![worker_pid],
        "the process table names this host's one worker"
    );
    assert_eq!(created.attachments.len(), 1);
    let first_attachment = created.attachments[0].attachment_id;

    // KR-REQ-01.01: an agent running in the session asks its person a question through the contact
    // tools. It is started the way a person starts one, by typing its name at the prompt.
    let asking = first.mark();
    first.type_text(b"\"$PWD\"/agent; printf 'agent-%s-%s\\n' exited \"$?\"\r");
    let question = until("the agent's question to be waiting", || {
        host.questions().into_iter().next()
    });
    let agent = host.written_process("agent.pid", "the scripted agent");
    let tools = host.written_process("tools.pid", "the agent's tool server");
    let agent_pid = u32::try_from(agent.pid.get()).expect("a process identifier");
    let tools_pid = u32::try_from(tools.pid.get()).expect("a process identifier");
    assert_eq!(
        parent_of(agent_pid),
        root_pid,
        "the agent is a command the session's shell ran"
    );
    assert_eq!(
        parent_of(tools_pid),
        agent_pid,
        "and the tool server is the agent's own child"
    );
    let question_id = question["question_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    assert_eq!(question["state"], "pending");
    assert_eq!(question["session_id"], session_id.to_string());
    assert_eq!(question["question"], "What should the release be called?");
    assert_eq!(question["unverified_agent_label"], "scripted agent");
    assert_eq!(
        question["verified_source"]["pid"],
        u64::from(tools_pid),
        "the host names the process that asked, which is the one the kernel shows: {question}"
    );
    assert_eq!(question["verified_source"]["ancestry"], true);
    assert!(
        question["verified_source"]["executable"]
            .as_str()
            .is_some_and(|executable| executable.ends_with("kr")),
        "and the executable it is running: {question}"
    );

    // KR-REQ-01.01: the person answers from another window, and the agent's wait returns exactly
    // that answer.
    let answered_now = host.kr_json(&["question", "answer", &question_id, "--text", ANSWER]);
    assert_eq!(answered_now["state"], "answered");
    let waited = host.agent_reply("answered.json");
    let result = &waited["result"];
    assert_ne!(result["isError"], true, "the wait succeeded: {waited}");
    let returned = &result["structuredContent"];
    assert_eq!(returned["question_id"], question_id);
    assert_eq!(returned["state"], "answered");
    assert_eq!(returned["answer"]["kind"], "input");
    assert_eq!(
        returned["answer"]["text"], ANSWER,
        "the wait returned exactly the answer the person gave: {waited}"
    );
    first.wait_for(
        asking,
        format!("the agent was answered: {ANSWER}").as_bytes(),
        "the agent said what it was told",
    );
    assert!(
        host.questions().is_empty(),
        "nothing is waiting for an answer any more"
    );

    // A second window attaches to watch the same session.
    let second = Window::open(
        &host,
        &format!(
            "{kr} attach --no-probe {display}; printf '\\nwatch-%s-%s\\n' finished \"$?\"; \
             IFS= read -r _",
            kr = quoted(&kr()),
        ),
    );
    second.wait_for(
        0,
        b"the agent was answered",
        "the second window was drawn the session's screen",
    );
    let watching = host.snapshot(session_id);
    assert_eq!(watching.attachments.len(), 2, "two windows are attached");
    assert_eq!(watching.attachments[0].attachment_id, first_attachment);
    let second_attachment = watching.attachments[1].attachment_id;
    let watcher = second.kr_process();

    // KR-REQ-07.52: detaching the first window from another one removes that attachment and
    // nothing else. The session, its shell, its agent and the other window all carry on.
    let detached = host.kr_json(&[
        "detach",
        &display,
        "--attachment",
        &first_attachment.to_string(),
    ]);
    assert_eq!(detached["detached"], first_attachment.to_string());
    assert_eq!(detached["remaining"], 1, "one attachment remains");
    first.wait_for(
        asking,
        b"new-finished-0",
        "kr new ended when its attachment was detached, and a detach is not a failure",
    );
    first.wait_until_put_back("the first window's terminal came back when it was detached");
    let after_detach = host.snapshot(session_id);
    assert_eq!(
        after_detach.session.state,
        kr_protocol::session::SessionState::Live
    );
    assert_eq!(
        after_detach
            .attachments
            .iter()
            .map(|attachment| attachment.attachment_id)
            .collect::<Vec<_>>(),
        vec![second_attachment],
        "the watching window's attachment is the one left"
    );
    let listed = host.only_live_session();
    assert_eq!(listed["state"], "live");
    assert_eq!(listed["attachments"], 1);
    assert!(
        !running(&kr_new),
        "the kr new process has exited: the detach ended it"
    );
    for (identity, what) in [
        (&worker, "the worker"),
        (&root, "the root shell"),
        (&agent, "the agent"),
        (&tools, "the agent's tool server"),
        (&watcher, "the watching window's kr attach"),
    ] {
        assert!(
            running(identity),
            "{what} is still running after the detach"
        );
    }

    // The agent keeps working with nobody's terminal of its own attached, and the window still
    // attached sees it happen.
    let watched = second.mark();
    host.open_gate("go-on");
    second.wait_for(
        watched,
        b"the screen as it is now",
        "the agent went on running after the detach, and the window still attached saw it",
    );

    // KR-REQ-01.01: the first window attaches again, to the same live session, and is drawn the
    // screen as it is now rather than the history that made it. The clipboard write, the bell and
    // the line that was overwritten are all in that history, and none of them is on the screen.
    let reattaching = first.mark();
    let queries = first.answer_capability_queries(reattaching);
    first.type_text(format!("{display}\r").as_bytes());
    answered(queries);
    first.wait_for(
        reattaching,
        b"the screen as it is now",
        "the reattached window was drawn the session's current screen",
    );
    let drawn = first.screen.since(reattaching);
    assert!(
        contains(&drawn, b"the agent kept running after the detach"),
        "what happened while it was away is on the screen it was drawn: {}",
        String::from_utf8_lossy(&drawn).escape_debug()
    );
    assert!(
        !contains(&drawn, b"\x1b]52;"),
        "the clipboard is not written again for a window that was not there: {}",
        String::from_utf8_lossy(&drawn).escape_debug()
    );
    assert!(
        !drawn.contains(&0x07),
        "the bell does not ring again: {}",
        String::from_utf8_lossy(&drawn).escape_debug()
    );
    assert!(
        !contains(&drawn, b"a line the screen no longer shows"),
        "a line the screen no longer shows is not shown: {}",
        String::from_utf8_lossy(&drawn).escape_debug()
    );
    let reattach = first.kr_process();
    let reattached = host.snapshot(session_id);
    assert_eq!(reattached.session.session_id, session_id);
    assert_eq!(
        reattached.session.root_process.as_ref(),
        Some(&root),
        "the same shell"
    );
    assert_eq!(
        reattached.attachments.len(),
        2,
        "the watching window and the one that came back"
    );
    assert!(running(&worker), "and the same worker");

    // The agent finishes when it is told to, and the shell says how it and its tool server ended.
    host.open_gate("finish");
    first.wait_for(
        reattaching,
        b"the tool server exited with status 0",
        "the agent ended its tool server",
    );
    first.wait_for(reattaching, b"agent-exited-0", "the agent exited");
    ended(&agent, "the agent");
    ended(&tools, "the agent's tool server");

    // KR-REQ-07.52: the shell's own exit closes the session, and its exit status is the one the
    // closure records.
    let ending = first.mark();
    first.type_text(b"exit 7\r");
    let closed = host.wait_until_closed(&session_id.to_string());
    assert_eq!(closed["closure"]["reason"], "root_exit");
    assert_eq!(closed["closure"]["exit_code"], 7);
    ended(&root, "the root shell");
    assert_eq!(
        worker_exit_status(&worker),
        0,
        "the worker ended with its session, and ended cleanly"
    );
    // KR-REQ-07.52: both windows still attached are told how the session closed, and each ends with
    // the status that implies and says so. A shell that exited with status 7 failed, so each ends
    // with the general failure rather than as a lost connection. Each gets its terminal back.
    first.attachment_ended(
        ending,
        "attach-finished-",
        NOT_CLEAN,
        &exited_with(7),
        "the reattached window's attachment ended with the session",
    );
    second.attachment_ended(
        watched,
        "watch-finished-",
        NOT_CLEAN,
        &exited_with(7),
        "the watching window's attachment ended with the session",
    );
    ended(&reattach, "the reattached window's kr attach");
    ended(&watcher, "the watching window's kr attach");
    first.wait_until_put_back("the reattached window's terminal came back");
    second.wait_until_put_back("the watching window's terminal came back");

    // KR-REQ-07.52: and nothing starts it again. Attaching to it by the number it was listed under
    // is refused as a session that does not exist, rather than answered with a new one.
    host.nothing_restarts(&[session_id]);
    let refused = Window::open(
        &host,
        &format!(
            "{kr} attach {display}; printf '\\nrefused-%s-%s\\n' attach \"$?\"; IFS= read -r _",
            kr = quoted(&kr()),
        ),
    );
    refused.wait_for(
        0,
        b"refused-attach-4",
        "an attach to the closed session ended as one to an unknown session",
    );
    assert!(
        refused
            .screen
            .contains_since(0, format!("no session {display}").as_bytes()),
        "and said so: {}",
        String::from_utf8_lossy(&refused.screen.since(0)).escape_debug()
    );
    assert!(
        host.running_workers().is_empty(),
        "no worker was started for it"
    );
    assert_eq!(
        host.kr_json(&["list", "--include-closed"])["sessions"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "and no session was created in its place"
    );
}

/// KR-REQ-07.52: end of input and a crash close a session just as its shell's own exit does, and
/// neither is started again.
#[test]
fn end_of_input_and_a_crash_each_close_their_session_and_neither_is_restarted() {
    let host = Host::start();

    // End of input: in a native_compat session Ctrl-D at the prompt is the shell's own, and the
    // shell ends there.
    let (first, input) = host.create_in_window("IFS= read -r _");
    let Created {
        session_id: ended_by_input,
        worker,
        root,
        ..
    } = input;
    let typing = first.mark();
    first.type_text(b"\x04");
    let closed = host.wait_until_closed(&ended_by_input.to_string());
    assert_eq!(closed["closure"]["reason"], "root_exit");
    assert_eq!(closed["closure"]["exit_code"], 0);
    ended(&root, "the shell that read the end of its input");
    assert_eq!(worker_exit_status(&worker), 0);
    first.attachment_ended(
        typing,
        "new-finished-",
        CLEAN,
        &exited_with(0),
        "the attachment ended with the session its shell ended cleanly",
    );
    first.wait_until_put_back("the terminal came back when the session closed");

    // A crash: the shell is killed outright, and the session closes with the signal that did it.
    let (second, crash) = host.create_in_window("IFS= read -r _");
    assert_eq!(
        crash.listed["display_number"], 2,
        "a display number is never used twice"
    );
    let Created {
        session_id: crashed,
        worker,
        root,
        ..
    } = crash;
    let crashing = second.mark();
    assert!(running(&root), "the shell is running before it is killed");
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(i32::try_from(root.pid.get()).expect("an identifier"))
            .expect("an identifier"),
        rustix::process::Signal::KILL,
    )
    .expect("kills the shell");
    let closed = host.wait_until_closed(&crashed.to_string());
    assert_eq!(closed["closure"]["reason"], "root_signal");
    let signal = closed["closure"]["signal"]
        .as_str()
        .unwrap_or_else(|| panic!("the closure names the signal that ended the shell: {closed}"));
    assert_eq!(worker_exit_status(&worker), 0);
    second.attachment_ended(
        crashing,
        "new-finished-",
        NOT_CLEAN,
        &ended_by(signal),
        "the attachment ended with the session its shell crashed out of",
    );
    second.wait_until_put_back("the terminal came back when the session closed");

    // Neither is started again.
    host.nothing_restarts(&[ended_by_input, crashed]);
}

/// KR-REQ-07.52: however the shell ends, by its own exit, the end of its input or a crash, every
/// attachment is sent how the session closed and ends with the status that implies, whether the
/// session has one attachment or two; and nothing is started again.
#[test]
fn each_way_a_shell_ends_reaches_one_attachment_or_two_with_the_status_it_implies() {
    let host = Host::start();

    // Its own exit, seen by the one terminal that made the session. The shell's status is in what
    // the attachment says, and the attachment ends with the general failure: 3 is the status a lost
    // connection ends with, and a shell's own status never stands in for one of the command's.
    let (alone, exited) = host.create_in_window("IFS= read -r _");
    let exiting = alone.mark();
    alone.type_text(b"exit 3\r");
    let closed = host.wait_until_closed(&exited.session_id.to_string());
    assert_eq!(closed["closure"]["reason"], "root_exit");
    assert_eq!(closed["closure"]["exit_code"], 3);
    alone.attachment_ended(
        exiting,
        "new-finished-",
        NOT_CLEAN,
        &exited_with(3),
        "the only attachment of a session whose shell exited with status 3",
    );
    alone.wait_until_put_back("the terminal came back when the session closed");
    ended(&exited.root, "the shell that exited");
    assert_eq!(worker_exit_status(&exited.worker), 0);

    // The end of its input, seen by two: the terminal that made the session, where Ctrl-D is typed,
    // and one that only watches. A shell that read the end of its input after a command that
    // succeeded exits with status 0, which is a clean end for both.
    let (typing, input) = host.create_in_window("IFS= read -r _");
    let watching = watcher(&host, &input.display);
    let (typed, watched) = (typing.mark(), watching.mark());
    typing.type_text(b"\x04");
    let closed = host.wait_until_closed(&input.session_id.to_string());
    assert_eq!(closed["closure"]["reason"], "root_exit");
    assert_eq!(closed["closure"]["exit_code"], 0);
    for (window, mark, marker, what) in [
        (
            &typing,
            typed,
            "new-finished-",
            "the terminal the end of input was typed into",
        ),
        (
            &watching,
            watched,
            "watch-finished-",
            "the terminal that watched",
        ),
    ] {
        window.attachment_ended(mark, marker, CLEAN, &exited_with(0), what);
        window.wait_until_put_back(what);
    }
    ended(&input.root, "the shell that read the end of its input");
    assert_eq!(worker_exit_status(&input.worker), 0);

    // A crash, seen by two: the shell is killed outright while both terminals are attached.
    let (making, crash) = host.create_in_window("IFS= read -r _");
    let onlooker = watcher(&host, &crash.display);
    let (made, looked) = (making.mark(), onlooker.mark());
    kill(&crash.root, "the shell");
    let closed = host.wait_until_closed(&crash.session_id.to_string());
    assert_eq!(closed["closure"]["reason"], "root_signal");
    let signal = closed["closure"]["signal"]
        .as_str()
        .unwrap_or_else(|| panic!("the closure names the signal that ended the shell: {closed}"));
    for (window, mark, marker, what) in [
        (
            &making,
            made,
            "new-finished-",
            "the terminal that made the crashed session",
        ),
        (
            &onlooker,
            looked,
            "watch-finished-",
            "the terminal that watched it",
        ),
    ] {
        window.attachment_ended(mark, marker, NOT_CLEAN, &ended_by(signal), what);
        window.wait_until_put_back(what);
    }
    assert_eq!(worker_exit_status(&crash.worker), 0);

    host.nothing_restarts(&[exited.session_id, input.session_id, crash.session_id]);
}

/// A connection that ends without a closure is still a lost connection: when a worker is killed
/// outright it tells nobody anything, and each attachment ends with the status that says its
/// connection was lost. The host records the closure the worker could not, and nothing is started
/// again.
#[test]
fn a_connection_lost_without_a_closure_still_ends_each_attachment_as_a_lost_connection() {
    let host = Host::start();
    let (making, created) = host.create_in_window("IFS= read -r _");
    let onlooker = watcher(&host, &created.display);
    let (made, looked) = (making.mark(), onlooker.mark());
    kill(&created.worker, "the worker");
    for (window, mark, marker, what) in [
        (
            &making,
            made,
            "new-finished-",
            "the terminal that made the session",
        ),
        (
            &onlooker,
            looked,
            "watch-finished-",
            "the terminal that watched it",
        ),
    ] {
        window.attachment_ended(mark, marker, CONNECTION_LOST, CONNECTION_ENDED, what);
        window.wait_until_put_back(what);
    }
    worker_killed(&created.worker);
    let closed = host.wait_until_closed(&created.session_id.to_string());
    assert_eq!(
        closed["closure"]["reason"], "worker_crash",
        "the host recorded how the session ended, since its worker could not: {closed}"
    );
    ended(&created.root, "the shell of the worker that was killed");
    host.nothing_restarts(&[created.session_id]);
}

/// One explicit close of a new session, watched from before the request.
///
/// Returns the session, and what the watch missed when it was not scheduled at a moment a check
/// depends on: such a close shows nothing either way, and the caller watches another. A check that
/// what was seen contradicts fails here.
fn close_explicitly(host: &Host) -> (SessionId, Result<(), String>) {
    for left in ["stubborn.pid", "last-tick", "last-tick.partial", "asked"] {
        let _ = std::fs::remove_file(host.work.join(left));
    }
    let (window, created) = host.create_in_window("IFS= read -r _");
    let Created {
        session_id,
        display,
        worker,
        root,
        ..
    } = created;
    let mut missed = Vec::new();

    // A second window watches and never types, so it stays attached for as long as the worker is
    // there to send it anything.
    let watching = Window::open(
        host,
        &format!(
            "{kr} attach --no-probe {display}; printf '\\nwatch-%s-%s\\n' finished \"$?\"; \
             IFS= read -r _",
            kr = quoted(&kr()),
        ),
    );
    watching.wait_for(
        0,
        PROMPT.as_bytes(),
        "the watching window was drawn the session's screen",
    );

    // The shell ignores the request to stop, and so does a job of its, which also says when it is
    // asked and counts until it is forced. The job starts first: a signal a shell ignores is
    // ignored by everything it starts after, and then the job could not say it had been asked.
    let preparing = window.mark();
    window.type_text(b"\"$PWD\"/stubborn & trap '' HUP TERM; printf 'stubborn-%s\\n' ready\r");
    window.wait_for(
        preparing,
        b"stubborn-ready",
        "the shell set itself to ignore the request to stop",
    );
    let job = host.written_process("stubborn.pid", "the job that ignores the request to stop");
    // What the checks below read from the job is on record before the close is asked for, or it is
    // read as optional and its absence leaves the close unobserved: the job's identifier above, the
    // first number it publishes here, which a rename only ever replaces, and `asked` further on.
    until("the job to publish its first number", || {
        std::fs::read_to_string(host.work.join("last-tick"))
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
    });
    let kr_new = window.kr_process();
    assert!(running(&root) && running(&job) && running(&kr_new));

    // KR-REQ-07.53: the answer to the close is the session already closing, with its closure being
    // recorded durably.
    let watch = Watch::start(vec![root.clone(), job.clone()]);
    let before_close = window.mark();
    let requested = Instant::now();
    let accepted = host.kr_json(&["close", &display]);
    assert_eq!(accepted["state"], "closing");
    assert_eq!(accepted["durability"], "durable");

    // KR-REQ-07.53: from then on input is refused. The shell is still running and reading, and this
    // line would create a file if it reached it. The attachment that carries it is refused it, stays
    // until the closure arrives, and ends with the status the closure implies, saying that what was
    // typed went nowhere.
    let typed_while_attached = running(&kr_new);
    window.type_text(b"touch typed-while-closing\r");
    let status = host.kr_json(&["status", &display]);
    let status_read = Instant::now();
    // Looked for from before the close: the attachment cannot end before it.
    let attachment_exit = window.exit_status_after(
        before_close,
        "new-finished-",
        "the attachment the line was typed into to end",
    );
    let seen = watch.finish();
    let (shell_seen, job_seen) = (seen[0], seen[1]);
    assert_ne!(
        status["state"], "live",
        "a session being closed never reads as live again"
    );
    if shell_seen.running >= status_read {
        assert_eq!(
            status["state"], "closing",
            "a client reading the session while its shell still runs reads it closing"
        );
    } else {
        missed.push("the shell was not seen running once the status had been read".to_owned());
    }
    // A close somebody asked for is a clean end, so the attachment ends successfully, and says how
    // the session closed.
    let told = window.screen.since(before_close);
    assert_eq!(
        attachment_exit,
        CLEAN,
        "the attachment the line was typed into ended with the closure's own status: {}",
        String::from_utf8_lossy(&told).escape_debug()
    );
    assert!(
        contains(&told, CLOSED_ON_REQUEST),
        "and said the session was closed on request: {}",
        String::from_utf8_lossy(&told).escape_debug()
    );
    if typed_while_attached && shell_seen.running >= status_read {
        assert!(
            contains(
                &told,
                b"what was typed while it was closing was not delivered"
            ),
            "the attachment was refused the line while the shell still ran, and said so: {}",
            String::from_utf8_lossy(&told).escape_debug()
        );
    } else {
        missed.push(
            "the line was not typed while the attachment was there, or the shell was not seen \
             running after it"
                .to_owned(),
        );
    }

    // KR-REQ-07.53: five seconds are allowed, and then what is left is forced. The request to stop
    // was sent no earlier than the close and no later than the moment the job recorded being asked;
    // each process ended after its last running sample and before its first gone one. So the grace
    // each was given lies between two bounds, and those have to hold it to the five seconds. A job
    // that was held up until the force came never recorded being asked: that leaves the grace
    // bounded from one side only, which can still show an early stop but nothing else.
    let asked_at = std::fs::metadata(host.work.join("asked"))
        .and_then(|about| about.modified())
        .ok();
    if asked_at.is_none() {
        missed.push("the job did not record being asked to stop before it was forced".to_owned());
    }
    for (seen, what) in [(shell_seen, "the shell"), (job_seen, "its job")] {
        let at_most = seen.gone.duration_since(requested);
        assert!(
            at_most + RESOLUTION >= GRACE_PERIOD,
            "{what} was gone at most {at_most:?} after the request to stop, before the five \
             seconds were up"
        );
        let Some(asked_at) = asked_at else {
            continue;
        };
        let at_least = seen.running_at.duration_since(asked_at).unwrap_or_default();
        assert!(
            at_least <= GRACE_PERIOD + GRACE_TOLERANCE,
            "{what} was still running at least {at_least:?} after the request to stop: the force \
             came well after the five seconds"
        );
        if at_least + RESOLUTION < GRACE_PERIOD || at_most > GRACE_PERIOD + GRACE_TOLERANCE {
            missed.push(format!(
                "{what}'s grace lay between {at_least:?} and {at_most:?}, and the watch could not \
                 hold it to the five seconds"
            ));
        }
    }

    // KR-REQ-07.53: the final status: why the session closed, what it ended and how, recorded
    // durably.
    let closed = host.wait_until_closed(&session_id.to_string());
    assert_eq!(closed["closure"]["reason"], "close_requested");
    assert_eq!(closed["closure"]["durability"], "durable");
    let record = host.closure(session_id);
    for (identity, what) in [(&root, "the shell"), (&job, "its job")] {
        let terminated = record
            .terminated
            .iter()
            .find(|process| &process.identity == identity)
            .unwrap_or_else(|| panic!("the closure names {what} among what it ended: {record:?}"));
        assert!(
            terminated.forced,
            "{what} needed force after the grace period, and the record says so"
        );
    }
    assert!(
        record.root_signal.is_present(),
        "the record names the signal that ended the shell: {record:?}"
    );

    // KR-REQ-07.53: output drains for up to two seconds after the owned processes have stopped, and
    // then the final status is recorded. The last of them stopped after the later of their last
    // running samples and before the later of their first gone ones, and the worker took the
    // record's time within the millisecond that time names; the drain lies between the two bounds
    // that makes. That the record was written durably is what its durability says, checked above.
    let recorded_from = UNIX_EPOCH + Duration::from_millis(record.closed_at_ms.get());
    let recorded_until = recorded_from + Duration::from_millis(1);
    let stopped_after = shell_seen.running_at.max(job_seen.running_at);
    let stopped_before = shell_seen.gone_at.max(job_seen.gone_at);
    let longest = recorded_until
        .duration_since(stopped_after)
        .unwrap_or_else(|_| {
            panic!(
                "the final status was recorded before the last owned process stopped: {record:?}"
            )
        });
    let shortest = recorded_from.duration_since(stopped_before).ok();
    assert!(
        shortest.is_none_or(|shortest| shortest <= DRAIN_PERIOD + RECORD_ALLOWANCE),
        "the final status was recorded at least {shortest:?} after the last owned process \
         stopped, beyond the two seconds output may drain for"
    );
    if shortest.is_none() || longest > DRAIN_PERIOD + RECORD_ALLOWANCE {
        missed.push(format!(
            "the drain lay between {shortest:?} and {longest:?}, and the watch could not place it"
        ));
    }

    // What the job wrote while it was being stopped reached the window still attached, and so did
    // the last number it had published, which it had written to the terminal first. Then the
    // closure did, and the window ended with its status.
    watching.attachment_ended(
        0,
        "watch-finished-",
        CLEAN,
        CLOSED_ON_REQUEST,
        "the watching window's attachment ended with the session",
    );
    let last_tick: u64 = std::fs::read_to_string(host.work.join("last-tick"))
        .expect("the job published the numbers it wrote")
        .trim()
        .parse()
        .expect("a number, published whole");
    let shown = watching.screen.since(0);
    // A job that recorded being asked had already said so on the terminal.
    if asked_at.is_some() {
        assert!(
            contains(&shown, b"the job was asked to stop"),
            "what the job wrote when it was asked to stop reached the window still attached: {}",
            String::from_utf8_lossy(&shown).escape_debug()
        );
    }
    assert!(
        shows_number(&shown, b"tick-", last_tick),
        "and so did the last number it published, tick-{last_tick}: {}",
        String::from_utf8_lossy(&shown).escape_debug()
    );
    assert!(
        !host.work.join("typed-while-closing").exists(),
        "the line typed after the close was accepted never reached the shell"
    );

    // The final status is what every later client reads, and asking again changes nothing.
    let again = host.kr_json(&["close", &display]);
    assert_eq!(again["state"], "closed");
    let read_again = host.kr_json(&["status", &session_id.to_string()]);
    assert_eq!(read_again["closure"], closed["closure"]);
    assert_eq!(worker_exit_status(&worker), 0);
    (
        session_id,
        if missed.is_empty() {
            Ok(())
        } else {
            Err(missed.join("; "))
        },
    )
}

/// KR-REQ-07.53: `kr close` answers with the session closing and refuses input from then on, allows
/// what the session owns five seconds, forces what is left, drains its output for up to two more
/// seconds and records the final status every later client reads. KR-REQ-07.52: nothing restarts
/// it.
#[test]
fn kr_close_is_closing_at_once_then_grace_force_drain_and_a_final_status() {
    let host = Host::start();
    let mut closed = Vec::new();
    let mut missed = Vec::new();
    for attempt in 1..=CLOSE_ATTEMPTS {
        let (session_id, observed) = close_explicitly(&host);
        closed.push(session_id);
        match observed {
            Ok(()) => {
                // KR-REQ-07.52: and nothing starts any of them again.
                host.nothing_restarts(&closed);
                return;
            }
            Err(reason) => {
                eprintln!(
                    "close {attempt} shows nothing either way, because the watch missed a moment \
                     it depends on: {reason}"
                );
                missed.push(reason);
            }
        }
    }
    panic!(
        "the watch missed a moment the checks depend on in each of {CLOSE_ATTEMPTS} closes: \
         {missed:?}"
    );
}
