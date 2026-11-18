//! What the control daemon does when it is sent SIGTERM, the signal launchd and systemd send at a
//! stop, and when it is asked to stop on its local socket.
//!
//! The daemon here is the real `kr-controller` program, started as a child of the test with no
//! supervisor between them, so the status the test collects is the daemon's own: an exit code, or
//! the signal that ended it. A session's worker is the real worker program.

#![cfg(unix)]

use std::io::Write as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Stdio};
use std::time::Duration;

use kr_controller::singleton::SingletonLock;
use kr_ipc::client::LocalClient;
use kr_ipc::testing::started_environment::StartedEnvironment;
use kr_protocol::envelope::{ActionTarget, ControlFrame};
use kr_protocol::ids::{ActionId, BuildId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{
    Presentation, SessionCreateParams, SessionCreateResult, SessionListParams, SessionListResult,
    SessionReadParams, SessionReadResult, SessionState, ShellMode,
};
use kr_protocol::update::{HostStopParams, HostStopResult};

mod teardown;

/// How long a wait for something to happen is given. It fails when the thing never happens, and
/// says nothing about how long the daemon needs.
const LIVENESS: Duration = Duration::from_secs(120);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// The worker program beside this test's own.
fn worker_beside_this_test() -> PathBuf {
    let mut directory = std::env::current_exe().expect("the test binary");
    directory.pop();
    if directory.file_name().is_some_and(|name| name == "deps") {
        directory.pop();
    }
    let worker = directory.join("kr-worker");
    assert!(
        worker.is_file(),
        "this test starts a worker process and there is none at {}; build it with \
         `cargo build -p kr-worker`, or run the whole workspace's tests, which build it",
        worker.display()
    );
    worker
}

/// A daemon this test started. Where it started workers, the tree that keeps what they made is held
/// until the daemon has been established as ended.
struct Daemon {
    child: Option<Child>,
    tree: Option<teardown::Holder>,
}

impl Daemon {
    fn id(&self) -> u32 {
        self.child
            .as_ref()
            .expect("a daemon that has not ended")
            .id()
    }

    /// Sends the daemon SIGTERM, as a service manager does at a stop, and collects its status.
    fn terminate(&mut self) -> ExitStatus {
        let pid = rustix::process::Pid::from_raw(i32::try_from(self.id()).expect("a pid in range"))
            .expect("a process identifier");
        rustix::process::kill_process(pid, rustix::process::Signal::TERM)
            .expect("the daemon is signalled");
        self.collect()
    }

    /// Waits until the daemon has ended, and says how.
    fn collect(&mut self) -> ExitStatus {
        let child = self.child.as_mut().expect("a daemon that has not ended");
        let deadline = std::time::Instant::now() + LIVENESS;
        loop {
            if let Some(status) = child.try_wait().expect("the daemon can be waited for") {
                self.child = None;
                return status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the daemon had not ended {LIVENESS:?} after it was signalled"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        // Nothing here may panic: this can run while a test is already failing.
        let ended = child.kill().and_then(|()| child.wait());
        if let (Err(error), Some(tree)) = (ended, &self.tree) {
            tree.hold(format!(
                "the daemon this test started could not be established as ended: {error}"
            ));
        }
    }
}

/// Starts the daemon program on `host`'s directories, its output going to `stdout` and its errors
/// to a log in the host.
fn spawn_daemon(
    program: &Path,
    worker: &Path,
    host: &kr_ipc::testing::TempHost,
    stdout: Stdio,
) -> Child {
    let environment = host.environment();
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(host.root().join("daemon.log"))
        .expect("opens the daemon's log");
    let mut command = std::process::Command::new(program);
    // The daemon's sessions run a login shell: they are given a home inside the tree, not the
    // person's.
    StartedEnvironment::within(host.root()).apply(&mut command);
    command
        .arg("--runtime-dir")
        .arg(environment.runtime_root())
        .arg("--state-dir")
        .arg(environment.state_root())
        .arg("--worker")
        .arg(worker)
        // Its keys belong to this run: they go in this environment's own secrets directory.
        .arg("--secret-store")
        .arg("file")
        // Never this test's own directory: the build tree can be on a removable volume.
        .current_dir(host.root())
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(log)
        .spawn()
        .expect("starts the daemon")
}

/// A host tree of this test's own, with the daemon and worker programs placed in it.
struct Host {
    daemon: Option<Daemon>,
    program: PathBuf,
    worker: PathBuf,
    /// Last, so it goes last: it ends every worker a daemon started.
    tree: teardown::Tree,
}

impl Host {
    fn create() -> Self {
        let tree = teardown::Tree::create();
        let program = tree.root().join("kr-controller");
        let worker = tree.root().join("kr-worker");
        kr_ipc::testing::place_and_start_once(
            Path::new(env!("CARGO_BIN_EXE_kr-controller")),
            &program,
            &["--version"],
        );
        kr_ipc::testing::place_and_start_once(&worker_beside_this_test(), &worker, &["--version"]);
        Self {
            daemon: None,
            program,
            worker,
            tree,
        }
    }

    /// Starts the daemon on this tree, its output going to `stdout`.
    fn spawn(&mut self, stdout: Stdio) {
        self.daemon = Some(Daemon {
            child: Some(spawn_daemon(
                &self.program,
                &self.worker,
                &self.tree,
                stdout,
            )),
            tree: Some(self.tree.holder()),
        });
    }

    /// Starts the daemon and waits until it answers.
    async fn run(&mut self) {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.tree.root().join("daemon.log"))
            .expect("opens the daemon's log");
        self.spawn(Stdio::from(log));
        let endpoint = self
            .tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let started = std::time::Instant::now();
        loop {
            // A daemon that accepts the connection and never answers its hello is held to the
            // same bound as one that does not accept.
            let remaining = LIVENESS.saturating_sub(started.elapsed());
            match tokio::time::timeout(
                remaining,
                LocalClient::connect(&endpoint, LocalClientKind::Cli, build()),
            )
            .await
            {
                Ok(Ok(_)) => return,
                Ok(Err(_)) => {}
                Err(_) => panic!(
                    "the daemon did not answer within {LIVENESS:?}; its log says: {}",
                    std::fs::read_to_string(self.tree.root().join("daemon.log"))
                        .unwrap_or_else(|error| format!("<unreadable: {error}>"))
                ),
            }
            assert!(
                started.elapsed() < LIVENESS,
                "the daemon did not answer within {LIVENESS:?}; its log says: {}",
                std::fs::read_to_string(self.tree.root().join("daemon.log"))
                    .unwrap_or_else(|error| format!("<unreadable: {error}>"))
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn client(&self) -> LocalClient {
        let endpoint = self
            .tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("the daemon answers")
    }

    /// Asks the daemon to stop, or for its launch alone, on a connection of its own.
    async fn stop(&self, launch_only: bool) -> HostStopResult {
        self.client()
            .await
            .mutate(
                Method::HostStop,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(None),
                &HostStopParams { launch_only },
            )
            .await
            .expect("the call reaches the daemon")
            .unwrap_or_else(|error| panic!("the stop was refused: {error}"))
            .to_typed()
            .expect("decodes")
    }

    fn target(&self, session: Option<&SessionCreateResult>) -> ActionTarget {
        ActionTarget {
            environment_id: self.tree.environment_id(),
            session_id: Nullable::from(session.map(|created| created.session.session_id)),
            session_epoch: Nullable::from(session.map(|created| created.session.session_epoch)),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    /// Creates a session with a real worker, and returns it once it is live.
    async fn create_session(&self) -> SessionCreateResult {
        let request = SessionCreateParams {
            environment_id: self.tree.environment_id(),
            presentation: Presentation::Attach,
            shell: Nullable::some("/bin/sh".to_owned()),
            shell_mode: ShellMode::NativeCompat,
            cwd: Nullable::some(self.tree.root().display().to_string()),
            dimensions: Nullable::null(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            environment_snapshot: vec![
                kr_protocol::session::EnvironmentVariable {
                    name: "PATH".to_owned(),
                    value: "/usr/bin:/bin".to_owned(),
                },
                kr_protocol::session::EnvironmentVariable {
                    name: "PS1".to_owned(),
                    value: String::new(),
                },
            ]
            .into_iter()
            .chain(StartedEnvironment::within(self.tree.root()).snapshot_home())
            .collect(),
            palette: Nullable::null(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
            terminal: Nullable::null(),
        };
        self.client()
            .await
            .mutate(
                Method::SessionCreate,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(None),
                &request,
            )
            .await
            .expect("the call reaches the daemon")
            .unwrap_or_else(|error| panic!("the create failed: {error}"))
            .to_typed()
            .expect("decodes")
    }
}

/// A terminal attached on this machine, on the worker's own endpoint, that reads what the session
/// writes and types into it.
struct Terminal {
    client: LocalClient,
    session_id: kr_protocol::ids::SessionId,
    attachment_id: kr_protocol::ids::AttachmentId,
    epoch: Option<kr_protocol::ids::InputLeaseEpoch>,
    sequence: u64,
    seen: String,
}

impl Terminal {
    async fn attach(host: &Host, created: &SessionCreateResult, keys: bool) -> Self {
        use kr_protocol::attachment::{
            AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
        };
        use kr_protocol::scalars::CanonicalSet;

        let session = &created.session;
        let endpoint = host
            .tree
            .environment()
            .worker_endpoint(session.display_number)
            .expect("the worker's endpoint");
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects to the session's worker");
        let target = host.target(Some(created));
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        let attached: SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                target.clone(),
                &SessionAttachParams {
                    session_id: session.session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(session.dimensions),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the attachment is accepted")
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
                        session_id: session.session_id,
                        attachment_id,
                        expected_epoch: Nullable::null(),
                    },
                )
                .await
                .expect("reaches the worker")
                .expect("the lease is acquired")
                .to_typed()
                .expect("decodes");
            Some(lease.lease.epoch)
        } else {
            None
        };
        // Subscribing is the last call: the screen this terminal is drawn is queued the moment it
        // subscribes, and a client drops what arrives while it waits for an answer of its own.
        let mut streams = CanonicalSet::new();
        streams.insert(kr_protocol::recovery::EventStream::Output);
        client
            .request(
                Method::EventsSubscribe,
                &kr_protocol::recovery::EventsSubscribeParams {
                    session_id: session.session_id,
                    attachment_id,
                    streams,
                    from_cursor: Nullable::null(),
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the worker subscribes the terminal");
        Self {
            client,
            session_id: session.session_id,
            attachment_id,
            epoch,
            sequence: 0,
            seen: String::new(),
        }
    }

    /// Types one line into the session, under this terminal's lease.
    async fn type_line(&mut self, line: &str) {
        let epoch = self.epoch.expect("this terminal holds the keys");
        self.client
            .request(
                Method::InputWrite,
                &kr_protocol::input::InputWriteParams {
                    session_id: self.session_id,
                    attachment_id: self.attachment_id,
                    epoch,
                    sequence: kr_protocol::ids::InputSequence::new(self.sequence),
                    input: kr_protocol::input::InputContent::Bytes {
                        bytes: kr_protocol::scalars::Bytes::new(format!("{line}\n").into_bytes()),
                    },
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the worker takes the line");
        self.sequence += 1;
    }

    /// Reads until `marker` has reached this terminal.
    async fn shown(&mut self, marker: &str) {
        let deadline = tokio::time::Instant::now() + LIVENESS;
        while !self.seen.contains(marker) {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, self.client.recv()).await {
                Ok(Ok(ControlFrame::Notification(notification)))
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
                    "waited for {marker:?} and the connection ended ({error}): {:?}",
                    self.seen
                ),
                Err(_) => panic!("waited for {marker:?}: {:?}", self.seen),
            }
        }
    }
}

/// Whether the daemon ended by itself and by the ordinary way out: an exit code of zero, and not
/// a signal.
fn ended_gracefully(status: ExitStatus) -> bool {
    status.code() == Some(0) && status.signal().is_none()
}

/// SIGTERM, which launchd and systemd send at a stop, ends a daemon that serves the way an
/// interrupt does: it exits with status zero rather than dying by the signal, and what it owned is
/// let go of. Its two endpoints and its attachment-chunk endpoint are gone, no client reaches it,
/// and its environment's lock can be taken by the next daemon.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sigterm_ends_a_serving_daemon_with_exit_status_zero_and_lets_go_of_what_it_owned() {
    let mut host = Host::create();
    host.run().await;
    let environment = host.tree.environment();
    let lock = environment.singleton_lock();
    let daemon_id = host.daemon.as_ref().expect("a daemon").id();
    assert_eq!(
        SingletonLock::holder(&lock).expect("the lock file is read"),
        Some(daemon_id),
        "the control: the daemon holds the environment while it serves"
    );

    let status = host.daemon.as_mut().expect("a daemon").terminate();

    assert!(
        ended_gracefully(status),
        "SIGTERM ended the daemon by an exit code of zero, not by the signal: {status:?}"
    );
    for endpoint in [
        environment.controller_endpoint(),
        environment.rendezvous_endpoint(),
        environment.attachment_chunk_endpoint(),
    ] {
        let endpoint = endpoint.expect("an endpoint");
        assert!(
            !endpoint.as_path().exists(),
            "the daemon removed its socket {}",
            endpoint.as_path().display()
        );
    }
    SingletonLock::acquire(&lock, host.tree.environment_id())
        .expect("the environment's lock can be taken once the daemon has ended");
}

/// SIGTERM that arrives while the daemon still starts ends it where it stands, as it always has:
/// the daemon takes no stop signal until its start has completed, so the signal's own action ends
/// it, and a start that was cut is recovered by the next one.
///
/// The daemon's output goes to a pipe that is full and that nobody reads, so its first line (said
/// once it holds its environment and is making its keys) cannot be written, and the start waits
/// there for as long as the test likes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sigterm_during_the_start_ends_the_daemon_by_the_signal_as_it_always_has() {
    let host = kr_ipc::testing::TempHost::create();
    let program = host.root().join("kr-controller");
    kr_ipc::testing::place_and_start_once(
        Path::new(env!("CARGO_BIN_EXE_kr-controller")),
        &program,
        &["--version"],
    );
    let (_unread, mut full) = std::io::pipe().expect("a pipe");
    let blocking = rustix::fs::fcntl_getfl(&full).expect("the pipe's flags");
    rustix::fs::fcntl_setfl(&full, blocking | rustix::fs::OFlags::NONBLOCK)
        .expect("the pipe stops blocking");
    for size in [4096, 1] {
        loop {
            match full.write(&vec![b'.'; size]) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("the pipe could not be filled: {error}"),
            }
        }
    }
    // The flag belongs to the open file description the daemon is given, so it goes back first.
    rustix::fs::fcntl_setfl(&full, blocking).expect("the pipe blocks again");
    let mut daemon = Daemon {
        child: Some(spawn_daemon(
            &program,
            &host.root().join("no-such-worker"),
            &host,
            Stdio::from(full),
        )),
        tree: None,
    };
    let environment = host.environment();
    let lock = environment.singleton_lock();
    let started = std::time::Instant::now();
    while SingletonLock::holder(&lock).expect("the lock file is read") != Some(daemon.id()) {
        assert!(
            started.elapsed() < LIVENESS,
            "the daemon never took its environment; its log says: {}",
            std::fs::read_to_string(host.root().join("daemon.log"))
                .unwrap_or_else(|error| format!("<unreadable: {error}>"))
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    assert!(
        LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .is_err(),
        "the control: the daemon holds its environment and does not serve yet"
    );

    let status = daemon.terminate();

    assert_eq!(
        status.signal(),
        Some(rustix::process::Signal::TERM.as_raw()),
        "the daemon was ended by the signal itself, as before: {status:?}"
    );
    SingletonLock::acquire(&lock, host.environment_id())
        .expect("the environment's lock can be taken once the daemon has ended");
}

/// KR-REQ-02.03, KR-REQ-05.01: a session goes on through a daemon's graceful end. A terminal
/// attached to it keeps reading and typing while no daemon exists, a terminal that attaches then is
/// drawn the screen, and a daemon started again lists the session live, with both terminals still
/// attached.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_goes_on_through_the_stop_sigterm_asks_for_and_the_next_daemon_lists_it() {
    let mut host = Host::create();
    host.run().await;
    let created = host.create_session().await;
    let session_id = created.session.session_id;
    let mut watching = Terminal::attach(&host, &created, true).await;
    watching
        .type_line("printf 'kr-%s\\n' before-the-stop")
        .await;
    watching.shown("kr-before-the-stop").await;

    let status = host.daemon.as_mut().expect("a daemon").terminate();
    assert!(
        ended_gracefully(status),
        "SIGTERM ended the daemon: {status:?}"
    );
    let endpoint = host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    assert!(
        LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .is_err(),
        "no daemon answers"
    );

    // The terminal that was attached reads and writes with no daemon.
    watching
        .type_line("printf 'kr-%s\\n' typed-with-no-daemon")
        .await;
    watching.shown("kr-typed-with-no-daemon").await;
    // And one that attaches now is drawn the screen as it stands, lines from before the stop
    // beside lines from after it.
    let mut late = Terminal::attach(&host, &created, false).await;
    late.shown("kr-before-the-stop").await;
    late.shown("kr-typed-with-no-daemon").await;

    host.run().await;
    let listed: SessionListResult = host
        .client()
        .await
        .request(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::null(),
                include_closed: false,
            },
        )
        .await
        .expect("the call reaches the new daemon")
        .expect("the list succeeds")
        .to_typed()
        .expect("decodes");
    assert!(
        listed
            .sessions
            .iter()
            .any(|summary| summary.session_id == session_id && summary.state == SessionState::Live),
        "the daemon started again found the session: {listed:?}"
    );
    let read: SessionReadResult = host
        .client()
        .await
        .request(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect("the call reaches the new daemon")
        .expect("the read succeeds")
        .to_typed()
        .expect("decodes");
    assert_eq!(
        read.session.attachment_count.get(),
        2,
        "both terminals are still attached"
    );
}

/// KR-REQ-02.03, KR-REQ-05.01: a stop asked on the local socket ends the real daemon after its
/// answer has been written, by the ordinary way out: an exit code of zero, the line that says why, its sockets removed and its
/// environment's lock free, and a session goes on through it as it does through a signal. A request
/// for the launch alone, asked first, stops nothing and says how the daemon was started.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_asked_on_the_local_socket_ends_the_daemon_after_its_answer_and_no_session_stops() {
    let mut host = Host::create();
    host.run().await;
    let environment = host.tree.environment();
    let daemon_id = host.daemon.as_ref().expect("a daemon").id();
    let created = host.create_session().await;
    let session_id = created.session.session_id;

    let launch = host.stop(true).await;
    assert_eq!(launch.pid.get(), u64::from(daemon_id));
    assert_eq!(launch.unsettled.get(), 0);
    let started_as = launch
        .launch
        .0
        .expect("the daemon can say how it was started");
    assert!(
        started_as
            .arguments
            .windows(2)
            .any(|pair| pair == ["--secret-store", "file"]),
        "the arguments it was started with: {:?}",
        started_as.arguments
    );
    assert_eq!(
        std::fs::canonicalize(&started_as.directory).expect("the directory exists"),
        std::fs::canonicalize(host.tree.root()).expect("the tree exists"),
    );
    assert_eq!(
        SingletonLock::holder(&environment.singleton_lock()).expect("the lock file is read"),
        Some(daemon_id),
        "the request for the launch alone stopped nothing"
    );
    host.client().await;

    let answered = host.stop(false).await;
    assert_eq!(answered.pid.get(), u64::from(daemon_id));
    assert_eq!(answered.unsettled.get(), 0);
    let status = host.daemon.as_mut().expect("a daemon").collect();
    assert!(
        ended_gracefully(status),
        "the stop ended the daemon by an exit code of zero: {status:?}"
    );
    let said = std::fs::read_to_string(host.tree.root().join("daemon.log")).unwrap_or_default();
    assert!(
        said.lines()
            .any(|line| line == "kr-controller: stopped: a stop was requested on the local socket"),
        "the daemon said why it stopped: {said}"
    );
    for endpoint in [
        environment.controller_endpoint(),
        environment.rendezvous_endpoint(),
        environment.attachment_chunk_endpoint(),
    ] {
        let endpoint = endpoint.expect("an endpoint");
        assert!(
            !endpoint.as_path().exists(),
            "the daemon removed its socket {}",
            endpoint.as_path().display()
        );
    }
    SingletonLock::acquire(&environment.singleton_lock(), host.tree.environment_id())
        .expect("the environment's lock can be taken once the daemon has ended");

    // The session went on, and the next daemon lists it live.
    host.run().await;
    let listed: SessionListResult = host
        .client()
        .await
        .request(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::null(),
                include_closed: false,
            },
        )
        .await
        .expect("the call reaches the new daemon")
        .expect("the list succeeds")
        .to_typed()
        .expect("decodes");
    assert!(
        listed
            .sessions
            .iter()
            .any(|summary| summary.session_id == session_id && summary.state == SessionState::Live),
        "the daemon started again found the session: {listed:?}"
    );
}
