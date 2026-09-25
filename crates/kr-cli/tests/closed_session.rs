//! `kr attach` on a session that has closed.
//!
//! A session's descriptor goes when the session closes, so attaching to one finds nothing on disk.
//! What the command says then comes from the control daemon's registry, which keeps the closure:
//! the session has closed, this is its record, and nothing is started. A session the registry never
//! held is still unknown, and a daemon that cannot be reached is a host that is not running, never
//! a closure it did not report.
//!
//! Everything here is real. The daemon is the control service, started in this process with the
//! detached supervisor, so each session's worker is a process of its own: the one this workspace
//! builds, copied to the internal disk. `kr` is the real binary, and the live control attaches on a
//! real pseudo-terminal. The supervisor counts what it is asked to start, which is how "nothing is
//! started" is read. Every directory a launched process uses is on the internal disk.

#![cfg(unix)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{
    DetachedSupervisor, LaunchOutcome, NoTerminal, WorkerLaunch, WorkerSupervisor,
};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::ids::BuildId;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use serde_json::Value;

mod support;

use support::kr;

/// How long a wait for something to happen is given. It fails when the thing never happens.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// A well-formed session identifier this host never had.
const NEVER_HELD: &str = "0badc0de-0000-4000-8000-00000000c105";

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// The worker binary the daemon starts: the one this workspace built, copied to the internal disk
/// beside the command binaries and run once there before anything is timed.
///
/// # Panics
///
/// Panics when the build has no worker. A check that skipped would report a pass for a path it
/// never ran: a workspace test run builds the worker, and so does `cargo build -p kr-worker`.
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
            "this check starts a real worker process and there is none at {}; build it with \
             `cargo build -p kr-worker`",
            built.display()
        );
        let copied = support::command_binaries().join("kr-worker");
        kr_ipc::testing::place_and_start_once(&built, &copied, &["--version"]);
        copied
    })
}

/// The detached supervisor, counting every worker it is asked to start.
#[derive(Debug)]
struct Counting {
    inner: DetachedSupervisor,
    starts: Arc<AtomicUsize>,
}

impl WorkerSupervisor for Counting {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        self.starts.fetch_add(1, Ordering::SeqCst);
        self.inner.start(launch)
    }

    fn describe(&self) -> &'static str {
        "the detached supervisor, counted"
    }
}

/// A host tree, its daemon, and the sessions this test created in it.
struct Host {
    temp: kr_ipc::testing::TempHost,
    work: PathBuf,
    home: PathBuf,
    controller: Option<Arc<Controller>>,
    serving: Vec<tokio::task::JoinHandle<kr_controller::error::Result<()>>>,
    starts: Arc<AtomicUsize>,
    created: Mutex<Vec<String>>,
}

impl Drop for Host {
    fn drop(&mut self) {
        // A session this test left open would keep its worker and its shell running. Closing it
        // works with or without the daemon: without one, `kr close` asks the worker itself.
        let created =
            std::mem::take(&mut *self.created.lock().unwrap_or_else(PoisonError::into_inner));
        for session in created {
            let _ = self.kr(&["close", &session]);
        }
        for task in &self.serving {
            task.abort();
        }
    }
}

impl Host {
    async fn start() -> Self {
        let worker = worker().to_path_buf();
        let temp = kr_ipc::testing::TempHost::create();
        let work = temp.root().join("w");
        let home = temp.root().join("h");
        for directory in [&work, &home] {
            std::fs::create_dir(directory).expect("a directory on the internal disk");
        }
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        let secrets = environment.secrets_dir();
        let starts = Arc::new(AtomicUsize::new(0));
        let controller = Controller::start(ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                let store = open_store_in(&secrets).expect("a secret store in the test tree");
                Ok(
                    ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                        .expect("an identity"),
                )
            }),
            secret_store: StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(Counting {
                inner: DetachedSupervisor::new(),
                starts: Arc::clone(&starts),
            }),
            worker_program: worker,
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(NoTerminal),
        })
        .await
        .expect("the daemon starts");
        let rendezvous = Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
            .expect("binds the rendezvous endpoint");
        let clients = Listener::bind(&environment.controller_endpoint().expect("an endpoint"))
            .expect("binds the control endpoint");
        let serving = vec![
            tokio::spawn(Arc::clone(&controller).serve_rendezvous(rendezvous)),
            tokio::spawn(Arc::clone(&controller).serve_clients(clients)),
        ];
        Self {
            temp,
            work,
            home,
            controller: Some(controller),
            serving,
            starts,
            created: Mutex::new(Vec::new()),
        }
    }

    /// Ends the daemon the way its process ending would: nothing answers its endpoint afterwards.
    async fn stop_daemon(&mut self) {
        for task in self.serving.drain(..) {
            task.abort();
            let _ = task.await;
        }
        self.controller = None;
    }

    /// How many workers the daemon has asked its supervisor to start.
    fn starts(&self) -> usize {
        self.starts.load(Ordering::SeqCst)
    }

    /// The environment every `kr` this test runs is given: this host's directories, a home of its
    /// own, and nothing of the person running the test.
    fn variables(&self) -> Vec<(&'static str, String)> {
        vec![
            ("PATH", "/usr/bin:/bin".to_owned()),
            ("TERM", "xterm-256color".to_owned()),
            ("HOME", self.home.display().to_string()),
            (
                "KR_RUNTIME_DIR",
                self.temp.paths().runtime_root().display().to_string(),
            ),
            (
                "KR_STATE_DIR",
                self.temp.paths().state_root().display().to_string(),
            ),
        ]
    }

    /// Runs `kr` as a command in another window: no terminal, and this host's directories.
    fn kr(&self, line: &[&str]) -> std::process::Output {
        std::process::Command::new(kr())
            .args(line)
            .env_clear()
            .envs(self.variables())
            .current_dir(&self.work)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("kr runs")
    }

    /// Runs `kr` with `--json` and reads the one document it printed.
    fn json(&self, line: &[&str]) -> (Option<i32>, Value) {
        let mut asked = line.to_vec();
        asked.push("--json");
        let output = self.kr(&asked);
        let document = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "kr {} printed no document ({error}): {}{}",
                asked.join(" "),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output.status.code(), document)
    }

    /// Runs `kr` with `--json`, requires it to succeed, and returns what it printed.
    fn kr_json(&self, line: &[&str]) -> Value {
        let (status, document) = self.json(line);
        assert_eq!(status, Some(0), "kr {}: {document}", line.join(" "));
        document
    }

    /// Creates a session with no terminal of its own, and returns its identifier and number.
    fn create(&self) -> (String, String) {
        let work = self.work.display().to_string();
        let created = self.kr_json(&[
            "new",
            "--invisible",
            "--headless",
            "--shell",
            "/bin/sh",
            "--startup",
            "interactive",
            "--cwd",
            &work,
        ]);
        let session = created["session_id"]
            .as_str()
            .expect("an identifier")
            .to_owned();
        let display = created["display_number"]
            .as_u64()
            .expect("a display number")
            .to_string();
        self.created
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(session.clone());
        (session, display)
    }

    /// Waits until the descriptor `session` was published under has gone, which its worker sees
    /// to as it exits after the closure.
    fn wait_for_no_descriptor(&self, session: &str) {
        let session_id: kr_protocol::ids::SessionId = session.parse().expect("an identifier");
        let descriptor = self.temp.environment().descriptor_file(session_id);
        let started = Instant::now();
        while descriptor.exists() {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "session {session}'s descriptor is still at {}",
                descriptor.display()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The process identifier of `session`'s root shell, as the daemon reads the session.
    async fn root_shell(&self, session: &str) -> u64 {
        let endpoint = self
            .temp
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let mut client = kr_ipc::client::LocalClient::connect(
            &endpoint,
            kr_protocol::local::LocalClientKind::Cli,
            build(),
        )
        .await
        .expect("reaches the daemon");
        let read: kr_protocol::session::SessionReadResult = client
            .request(
                kr_protocol::method::Method::SessionRead,
                &kr_protocol::session::SessionReadParams {
                    session_id: session.parse().expect("an identifier"),
                },
            )
            .await
            .expect("the read reaches the daemon")
            .expect("the daemon reads the session")
            .to_typed()
            .expect("a session read");
        read.session
            .root_process
            .as_ref()
            .map(|process| process.pid.get())
            .expect("the session names its root shell")
    }

    /// Waits until `session` reports `attachments` attachments.
    fn wait_for_attachments(&self, session: &str, attachments: u64) {
        let started = Instant::now();
        loop {
            let (status, document) = self.json(&["status", session]);
            if status == Some(0) && document["attachments"].as_u64() == Some(attachments) {
                return;
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "session {session} never had {attachments} attachments: {document}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// A terminal window with a shell on it, running `kr attach` and saying how it ended.
struct Window {
    _terminal: portable_pty::PtyPair,
    shell: Box<dyn portable_pty::Child + Send + Sync>,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl Drop for Window {
    fn drop(&mut self) {
        let _ = self.shell.kill();
        let _ = self.shell.wait();
    }
}

impl Window {
    /// Opens a window whose shell runs `kr attach` on `session` without probing the terminal, and
    /// then prints the status it ended with.
    fn attach(host: &Host, session: &str) -> Self {
        let terminal = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("opens a terminal");
        let kr = kr().display().to_string();
        assert!(
            !kr.contains('\'') && !session.contains('\''),
            "the words this script quotes hold no quote"
        );
        let mut command = CommandBuilder::new("/bin/sh");
        command.arg("-c");
        command.arg(format!(
            "'{kr}' attach --no-probe '{session}'; echo \"attach ended $?\""
        ));
        command.env_clear();
        for (name, value) in host.variables() {
            command.env(name, value);
        }
        command.cwd(&host.work);
        let shell = terminal
            .slave
            .spawn_command(command)
            .expect("starts the window's shell");
        let mut reader = terminal.master.try_clone_reader().expect("a reader");
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
        Self {
            _terminal: terminal,
            shell,
            seen,
        }
    }

    /// What the window has shown so far.
    fn shown(&self) -> String {
        String::from_utf8_lossy(&self.seen.lock().unwrap_or_else(PoisonError::into_inner))
            .into_owned()
    }

    /// Waits for the window to show `marker`.
    fn wait_for(&self, marker: &str) -> String {
        let started = Instant::now();
        loop {
            let shown = self.shown();
            if shown.contains(marker) {
                return shown;
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "the window never showed {marker:?}: {}",
                shown.escape_debug()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// KR-REQ-05.05: a session whose descriptor went with its closure answers `kr attach` with
/// `SESSION_CLOSED` and the closure record the daemon keeps, by identifier and by display number,
/// exits with a status other than zero, and starts nothing. The controls: the same session attaches
/// while it is live; an identifier or a number the registry never held is still `UNKNOWN_SESSION`;
/// and with no daemon to ask, the command says the host is not running rather than calling the
/// session closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attaching_to_a_closed_session_answers_with_its_closure_and_starts_nothing() {
    let mut host = Host::start().await;
    let (session, display) = host.create();
    assert_eq!(host.starts(), 1, "one session, one worker");

    // The shell the session runs, as its daemon reads it, which its closure has to name.
    let shell = host.root_shell(&session).await;

    // While it is live, it attaches, on a real terminal; a close from another window ends that
    // attachment with the closure.
    let window = Window::attach(&host, &session);
    host.wait_for_attachments(&session, 1);
    let closed = host.kr(&["close", &session]);
    assert!(
        closed.status.success(),
        "kr close: {}",
        String::from_utf8_lossy(&closed.stderr)
    );
    let shown = window.wait_for("attach ended");
    assert!(
        shown.contains("the session closed: it was closed on request"),
        "{}",
        shown.escape_debug()
    );
    assert!(shown.contains("attach ended 0"), "{}", shown.escape_debug());
    host.wait_for_no_descriptor(&session);

    // Closed, its descriptor gone: named either way, it answers with its record.
    for selector in [session.as_str(), display.as_str()] {
        let (status, document) = host.json(&["attach", selector]);
        assert_eq!(status, Some(8), "kr attach {selector}: {document}");
        assert_eq!(document["ok"], Value::Bool(false), "{document}");
        assert_eq!(document["code"], "SESSION_CLOSED", "{document}");
        assert_eq!(document["session_id"], Value::String(session.clone()));
        assert_eq!(
            document["closure"]["reason"], "close_requested",
            "{document}"
        );
        // The whole record: whose it is, and what the closure terminated.
        assert_eq!(
            document["closure"]["session_id"],
            Value::String(session.clone())
        );
        assert!(
            document["closure"]["terminated"]
                .as_array()
                .is_some_and(|terminated| terminated
                    .iter()
                    .any(|process| process["pid"].as_u64() == Some(shell))),
            "the shell it terminated, {shell}, is named: {document}"
        );
        assert!(document["closure"]["surviving"].is_array(), "{document}");
    }
    let said = host.kr(&["attach", &session]);
    assert_eq!(said.status.code(), Some(8));
    let said = String::from_utf8_lossy(&said.stderr);
    assert!(said.contains("SESSION_CLOSED"), "{said}");
    assert!(said.contains("it was closed on request"), "{said}");

    // Nothing was started for any of it.
    assert_eq!(
        host.starts(),
        1,
        "attaching to a closed session starts no worker"
    );
    let listed = host.kr_json(&["list", "--include-closed"]);
    let sessions = listed["sessions"].as_array().expect("a list");
    assert_eq!(sessions.len(), 1, "and creates no session: {listed}");
    assert_eq!(sessions[0]["state"], "closed", "{listed}");

    // What the registry never held is still unknown.
    for selector in [NEVER_HELD, "99"] {
        let (status, document) = host.json(&["attach", selector]);
        assert_eq!(status, Some(4), "kr attach {selector}: {document}");
        assert_eq!(document["code"], "UNKNOWN_SESSION", "{document}");
    }

    // With nothing to ask, the host is not running; that is never taken as a closure.
    host.stop_daemon().await;
    let (status, document) = host.json(&["attach", &session]);
    assert_eq!(status, Some(3), "{document}");
    assert_ne!(document["code"], "SESSION_CLOSED", "{document}");
    assert!(
        document["message"]
            .as_str()
            .is_some_and(|message| message.contains("no KalaReach host is running")),
        "{document}"
    );
    assert_eq!(host.starts(), 1);
}
