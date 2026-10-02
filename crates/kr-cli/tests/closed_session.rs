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
use std::os::unix::process::ExitStatusExt as _;
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
        // Whatever a close did not reach, such as a session whose daemon this test stopped first,
        // has a worker that nothing will close afterwards.
        if let Err(left) = support::leave_no_worker_of(self.temp.root()) {
            if std::thread::panicking() {
                eprintln!("{left}");
            } else {
                panic!("{left}");
            }
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
    assert!(!said.contains("SESSION_CLOSED"), "{said}");
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

/// A stand-in for a host's worker: a program called `kr-worker` that was started with the host's
/// directories and runs until its standard input closes.
struct StandIn {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
}

impl StandIn {
    /// Starts one for the host tree `root`, from a link in `links`.
    fn start(links: &Path, root: &Path) -> Self {
        let program = links.join("kr-worker");
        std::os::unix::fs::symlink("/bin/sh", &program).expect("a link to the shell");
        let mut child = std::process::Command::new(&program)
            .args(["-c", "read line", "kr-worker", "--runtime-dir"])
            .arg(root.join("r"))
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("the stand-in starts");
        let stdin = child.stdin.take();
        Self { child, stdin }
    }

    /// Ends it as a worker ends with its session, and collects it.
    fn end(mut self) -> std::process::ExitStatus {
        drop(self.stdin.take());
        self.child.wait().expect("the stand-in ends")
    }
}

impl Drop for StandIn {
    fn drop(&mut self) {
        // A check that failed first must not leave it running.
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// The workers of a host are the processes whose program is called `kr-worker`, however the system
/// gives the program (a path with spaces in it, or its name alone), that have not ended, and whose
/// arguments name the host's own tree: not another host's, not a program of another name that has a
/// worker's path among its arguments, and not a process that was given a worker's number after the
/// worker ended.
#[test]
fn the_workers_of_a_host_are_read_from_the_process_listing() {
    let start = "Fri Oct  3 07:48:44 2026";
    let listing = format!(
        "\
  101 {start} Ss   /private/var/T/run/kr-worker\n\
  102 {start} Z    /private/var/T/run/kr-worker\n\
  103 {start} S    /private/var/T/run dir/kr-worker\n\
  104 {start} S    kr-worker\n\
  105 {start} S+   /private/var/T/run/kr\n\
  106 {start} S    /usr/bin/tail\n\
  107 {start} S    /private/var/T/kr-worker tools/tail\n\
  108 {start} S    /private/var/T/run/kr-worker-old\n\
  109 Sat Oct  4 00:00:01 2026 R    kr-worker\n"
    );
    let programs = support::worker_programs_in(&listing);
    assert_eq!(
        programs.iter().map(|listed| listed.pid).collect::<Vec<_>>(),
        [101, 103, 104, 109],
        "the programs called kr-worker that run, whatever the path they are given as"
    );
    assert_eq!(
        programs[3].started, "Sat Oct 4 00:00:01 2026",
        "with the time each started"
    );

    let arguments = support::arguments_in(&format!(
        "\
  101 {start} /p/kr-worker --session s --runtime-dir /t/kr-aaaa1111/r/e\n\
  103 {start} /p/run dir/kr-worker --session s --runtime-dir /t/kr-aaaa11112/r/e\n\
  104 {start} kr-worker --session s\n\
  109 Sat Oct  4 00:00:09 2026 /usr/bin/tail -f /t/kr-aaaa1111/r/e/log\n"
    ));
    let found = support::workers_among(&programs, &arguments, "kr-aaaa1111");
    assert_eq!(
        found.iter().map(|worker| worker.pid).collect::<Vec<_>>(),
        [101],
        "this host's workers only: not another host's (103 names kr-aaaa11112), not one that names \
         no host (104), and not a process that was given a worker's number afterwards and started \
         at another time (109)"
    );
    assert!(support::names_host(
        "/p/kr-worker --session s --runtime-dir /t/kr-aaaa1111/r/e",
        "kr-aaaa1111"
    ));
    assert!(!support::names_host("/p/kr-worker", "kr-aaaa1111"));
}

/// A host's check finds a worker that is still running, waits for one that ends by itself, and ends
/// one that does not, saying so, so that none outlives the test that started it. Another host's
/// worker is none of its business.
#[test]
fn a_worker_that_outlives_its_host_is_found_ended_and_reported() {
    let places = tempfile::Builder::new()
        .prefix("kr-")
        .tempdir()
        .expect("a directory");
    let other = tempfile::Builder::new()
        .prefix("kr-")
        .tempdir()
        .expect("a directory");
    let links = tempfile::tempdir().expect("a directory");
    let elsewhere = tempfile::tempdir().expect("a directory");

    // Found while it runs.
    let ending = StandIn::start(links.path(), places.path());
    let found = support::workers_of(places.path()).expect("the processes are listed");
    assert_eq!(
        found.iter().map(|worker| worker.pid).collect::<Vec<_>>(),
        [i32::try_from(ending.child.id()).expect("a process number")],
        "the stand-in is this host's worker"
    );
    assert!(
        support::workers_of(other.path())
            .expect("the processes are listed")
            .is_empty(),
        "and no other host's"
    );

    // One that ends by itself is waited for, and nothing is reported.
    let waiting = std::thread::scope(|scope| {
        let waiting = scope.spawn(|| support::leave_no_worker_of(places.path()));
        // The worker ends with its session; the check is told nothing of it.
        let status = ending.end();
        assert_eq!(
            status.signal(),
            None,
            "the stand-in ends by itself: {status}"
        );
        waiting.join().expect("the check ends")
    });
    assert_eq!(waiting, Ok(()), "a worker that ended is not reported");

    // One that does not end is ended, and reported with its number.
    let stuck = StandIn::start(elsewhere.path(), places.path());
    let pid = stuck.child.id();
    let reported = support::leave_no_worker_of_within(places.path(), Duration::from_millis(500))
        .expect_err("a worker that does not end is reported");
    assert!(
        reported.contains(&pid.to_string()),
        "it names the worker: {reported}"
    );
    let status = stuck.end();
    assert_eq!(
        status.signal(),
        Some(9),
        "and the worker was killed: {status}"
    );
    assert_eq!(
        support::workers_of(places.path()).expect("the processes are listed"),
        [],
        "none is left"
    );
}

/// What a run launched from its directory goes with the run: once the run has ended, the watcher
/// ends a worker that is still running from the directory, and removes the directory. Until then
/// nothing of the run is touched.
#[test]
fn a_worker_left_running_goes_with_the_directory_of_the_run_that_started_it() {
    let sandbox = tempfile::tempdir().expect("a directory");
    let run = sandbox.path().join("run");
    std::fs::create_dir(&run).expect("the run's directory");
    let mut worker = StandIn::start(&run, &sandbox.path().join("kr-0000"));
    let still_going = support::watch(&run).expect("the watcher starts");
    assert!(
        worker
            .child
            .try_wait()
            .expect("the worker is asked after")
            .is_none()
            && run.exists(),
        "a run that is going keeps its worker and its directory"
    );

    // The run ends: every descriptor it held closes, the one the watcher reads among them.
    drop(still_going);
    let started = std::time::Instant::now();
    while run.exists() {
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "the watcher did not remove the directory of the run that ended"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let status = worker.end();
    assert_eq!(
        status.signal(),
        Some(15),
        "the worker was asked to end before its directory went: {status}"
    );
}

/// A run that was ended without its watcher seeing it, which is how a harness that ends the whole
/// group a run is in ends it, leaves a directory and the workers that run from it. The next run
/// that finds the directory, with no process holding the number in its name, ends them and removes
/// it, and leaves the directory of a run that is going, and what runs from it, alone.
#[test]
fn a_worker_an_earlier_run_left_is_ended_when_its_directory_is_swept() {
    const TOKEN: &str = "0123456789abcdef0123";

    let sandbox = tempfile::tempdir().expect("a directory");
    let ours = sandbox.path().join(format!(
        "kalareach-command-tests-sweep-{}-{TOKEN}",
        std::process::id()
    ));
    let mut ended = std::process::Command::new("/usr/bin/true")
        .spawn()
        .expect("a process to end");
    let theirs = sandbox.path().join(format!(
        "kalareach-command-tests-sweep-{}-{TOKEN}",
        ended.id()
    ));
    ended.wait().expect("the process ended");
    for directory in [&ours, &theirs] {
        std::fs::create_dir(directory).expect("a run's directory");
    }
    let mut going = StandIn::start(&ours, &sandbox.path().join("kr-0000"));
    let left = StandIn::start(&theirs, &sandbox.path().join("kr-0000"));

    support::remove_what_earlier_runs_left(sandbox.path(), &ours);

    assert!(
        !theirs.exists(),
        "the directory of the run that ended is gone"
    );
    let status = left.end();
    assert_eq!(
        status.signal(),
        Some(15),
        "and the worker that was running from it was ended: {status}"
    );
    assert!(
        ours.exists() && going.child.try_wait().expect("asked after").is_none(),
        "the run that is going keeps its directory and its worker"
    );
}

/// A directory whose path has a space and backslash escapes in it is no different from any other to
/// the host's check, the watcher and the sweep: what runs from it is found by its whole command and
/// its program, the path is read as it is written, and a directory that has gone changes none of it.
#[test]
fn a_worker_in_a_directory_with_an_odd_path_is_found_and_ended() {
    let sandbox = tempfile::tempdir().expect("a directory");
    let odd = sandbox.path().join(r"run dir\n and \t more");
    let other = sandbox.path().join("run dir");
    for directory in [&odd, &other] {
        std::fs::create_dir(directory).expect("a run's directory");
    }
    // A tree name of its own: the other cases here name theirs `kr-0000`, and run beside this one.
    let tree = sandbox
        .path()
        .join(format!("kr-odd-{}", std::process::id()));
    let worker = StandIn::start(&odd, &tree);
    let mut bystander = StandIn::start(&other, &tree);
    let pids = |tree: &Path| -> Vec<i32> {
        let mut found: Vec<i32> = support::workers_of(tree)
            .expect("the processes are listed")
            .iter()
            .map(|worker| worker.pid)
            .collect();
        found.sort_unstable();
        found
    };
    let mut both = vec![
        i32::try_from(worker.child.id()).expect("a process number"),
        i32::try_from(bystander.child.id()).expect("a process number"),
    ];
    both.sort_unstable();
    assert_eq!(
        pids(&tree),
        both,
        "both are the tree's workers, whatever their paths hold"
    );
    // The directory a worker was started from is gone, as a run's is once it has ended: the worker
    // is still found, and the watcher still ends what runs from it.
    std::fs::remove_dir_all(&odd).expect("the odd directory goes");
    assert_eq!(
        pids(&tree),
        both,
        "and they still are once a directory has gone"
    );

    support::end_what_runs_from(&odd);

    let status = worker.end();
    assert_eq!(
        status.signal(),
        Some(15),
        "the worker running from the odd path was ended: {status}"
    );
    assert!(
        bystander.child.try_wait().expect("asked after").is_none(),
        "a worker running from a directory the path merely starts with, `run dir`, is left alone"
    );
}
