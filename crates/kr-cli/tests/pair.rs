//! `kr pair` against a real control daemon on the network, and a host's first owner confirmed at a
//! real terminal.
//!
//! The daemon is the `kr-controller` executable the workspace builds beside this test, copied to the
//! internal disk and put on the network on loopback alone, with no relay and no discovery; it keeps
//! its keys in its own temporary host and has no owner when it starts. `kr` runs on a real
//! pseudo-terminal where the first owner's confirmation needs one, and on plain pipes where what is
//! tested is that it refuses. A build of this crate alone that has not built the daemon yet prints
//! why and stops rather than testing something else.
//!
//! Where a test needs a live session, this test hosts one itself, in the daemon's environment: a
//! real session whose real worker answers whether a process is one of its own, published where
//! `kr` finds every session. The daemon did not start it and leaves it alone.

#![cfg(unix)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{BuildId, ControllerGeneration, SessionEpoch, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::scalars::TimestampMs;
use kr_protocol::session::{Dimensions, DisplayNumber, LaunchProfile, ShellMode};
use kr_protocol::worker::WorkerDescriptor;
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use serde_json::Value;

mod support;

use support::kr;

/// How long a wait for something to happen is given. It fails when the thing never happens.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// Returns an executable the workspace builds beside this test, when it has been built.
fn beside_this_test(name: &str) -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let profile = executable.parent()?.parent()?;
    let candidate = profile.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    candidate.is_file().then_some(candidate)
}

/// A host tree with a running daemon on the network, and the `kr` that talks to it.
struct Host {
    daemon: Option<std::process::Child>,
    temp: kr_ipc::testing::TempHost,
}

impl Drop for Host {
    fn drop(&mut self) {
        if let Some(mut daemon) = self.daemon.take() {
            let _ = daemon.kill();
            let _ = daemon.wait();
        }
    }
}

impl Host {
    async fn start() -> Option<Self> {
        let Some(controller) = beside_this_test("kr-controller") else {
            eprintln!(
                "skipped: the kr-controller executable is not built beside this test; a workspace \
                 test run builds it"
            );
            return None;
        };
        let temp = kr_ipc::testing::TempHost::create();
        let bin = temp.root().join("bin");
        std::fs::create_dir_all(&bin).expect("a directory for the executable");
        let controller = copy_into(&controller, &bin);
        let log = std::fs::File::create(temp.root().join("daemon.log")).expect("the daemon's log");
        let child = std::process::Command::new(&controller)
            .current_dir(temp.root())
            .env("KR_NETWORK", "1")
            .env("KR_NETWORK_BIND", "127.0.0.1:0")
            .arg("--runtime-dir")
            .arg(temp.root().join("r"))
            .arg("--state-dir")
            .arg(temp.root().join("s"))
            .arg("--secret-store")
            .arg("file")
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().expect("duplicates the log"))
            .stderr(log)
            .spawn()
            .expect("the daemon starts");
        let host = Self {
            daemon: Some(child),
            temp,
        };
        let endpoint = host
            .temp
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let started = Instant::now();
        while LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .is_err()
        {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "the daemon did not answer; its log says: {}",
                host.log()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Some(host)
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.temp.root().join("daemon.log")).unwrap_or_default()
    }

    /// The environment `kr` runs with: this host's directories, and nothing of this test's own.
    fn environment(&self) -> Vec<(String, String)> {
        vec![
            ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
            (
                "KR_RUNTIME_DIR".to_owned(),
                self.temp.paths().runtime_root().display().to_string(),
            ),
            (
                "KR_STATE_DIR".to_owned(),
                self.temp.paths().state_root().display().to_string(),
            ),
        ]
    }

    /// Runs `kr` on plain pipes.
    fn kr(&self, arguments: &[&str]) -> std::process::Output {
        std::process::Command::new(kr())
            .args(arguments)
            .env_clear()
            .envs(self.environment())
            .current_dir("/")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("runs kr")
    }

    /// Runs `kr` on plain pipes and reads what it printed as JSON.
    fn kr_json(&self, arguments: &[&str]) -> Value {
        let output = self.kr(arguments);
        assert!(
            output.status.success(),
            "kr {}: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("kr printed JSON")
    }

    /// Runs `kr` on a pseudo-terminal of its own, which is its controlling terminal.
    fn on_terminal(&self, arguments: &[&str], extra: &[(&str, &str)]) -> OnTerminal {
        self.program_on_terminal(&kr(), arguments, extra)
    }

    /// Runs `kr` on a pseudo-terminal of its own, below `depth` shells that each wait for the one
    /// below them rather than replacing themselves with it.
    fn nested_on_terminal(&self, depth: usize, arguments: &[&str]) -> OnTerminal {
        let script = self.temp.root().join("nest.sh");
        std::fs::write(
            &script,
            "n=$1\nshift\nif [ \"$n\" -gt 0 ]; then\n  /bin/sh \"$0\" \"$((n - 1))\" \"$@\"\n  \
             status=$?\n  exit \"$status\"\nfi\nexec \"$@\"\n",
        )
        .expect("the nesting script");
        let depth = depth.to_string();
        let kr = kr();
        let mut nested = vec![
            script.to_str().expect("a path"),
            depth.as_str(),
            kr.to_str().expect("a path"),
        ];
        nested.extend_from_slice(arguments);
        self.program_on_terminal(Path::new("/bin/sh"), &nested, &[])
    }

    fn program_on_terminal(
        &self,
        program: &Path,
        arguments: &[&str],
        extra: &[(&str, &str)],
    ) -> OnTerminal {
        let pty = native_pty_system()
            .openpty(PtySize {
                rows: 80,
                cols: 240,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("opens a terminal");
        let mut command = CommandBuilder::new(program);
        command.args(arguments);
        command.env_clear();
        for (name, value) in self.environment() {
            command.env(name, value);
        }
        command.env("TERM", "xterm-256color");
        for (name, value) in extra {
            command.env(name, value);
        }
        command.cwd("/");
        let child = pty.slave.spawn_command(command).expect("starts kr");
        drop(pty.slave);
        let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
        let writer = pty.master.take_writer().expect("a writer");
        OnTerminal {
            child,
            output,
            writer,
            _master: pty.master,
        }
    }

    /// Starts a live session in this host's environment, whose root shell runs `script`, and
    /// publishes it where `kr` finds sessions.
    ///
    /// The session's worker holds a controller key of its own: the daemon's identity is in the
    /// daemon's store, and no controller ever connects to this session anyway.
    fn session(&self, script: &str) -> Hosted {
        let environment = self.temp.environment();
        let environment_id = self.temp.environment_id();
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let display = DisplayNumber::new(1);
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let process =
            kr_ipc::identity::current_process_start_identity().expect("a process identity");
        let identity = Arc::new(
            WorkerIdentity::generate(
                session_id,
                SessionEpoch::V1,
                boot.clone(),
                process.clone(),
                PROTOCOL_VERSION,
            )
            .expect("a session key"),
        );
        let store = kr_crypto::store::MemoryStore::new();
        let controller = kr_ipc::verify::ControllerIdentity::initialise(&store, environment_id)
            .expect("a controller identity");
        let mut variables = self.environment();
        variables.push(("TERM".to_owned(), "xterm-256color".to_owned()));
        let config = SessionConfig {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: display,
            shell: ShellCommand {
                program: "/bin/sh".to_owned(),
                arguments: vec!["-c".to_owned(), script.to_owned()],
                cwd: "/".to_owned(),
                environment: variables,
            },
            shell_mode: ShellMode::NativeCompat,
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: DesktopBinding::none(),
            dimensions: Dimensions::new(240, 40),
            journal_path: Some(environment.journal_database(session_id)),
            spool_directory: Some(environment.session_spool(session_id)),
            worker_endpoint: None,
            send_queue_bytes: 1024 * 1024,
            resident_bytes: 256 * 1024,
            launch_profile: LaunchProfile::default(),
        };
        let mut session = Session::open(config).expect("opens the session");
        session.launch().expect("launches the shell");
        let runtime = Arc::new(
            SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
                .expect("starts the runtime"),
        );
        let endpoint = environment.worker_endpoint(display).expect("an endpoint");
        let listener = Listener::bind(&endpoint).expect("binds the endpoint");
        let service = Arc::new(
            WorkerService::new(
                Arc::clone(&runtime),
                Arc::clone(&identity),
                endpoint.clone(),
                ServiceBinding {
                    environment_id,
                    boot_identity: boot.clone(),
                    controller_public_key: *controller.public_key(),
                    controller_generation: ControllerGeneration::new(1),
                    build_id: build(),
                    journal_path: None,
                },
            )
            .expect("a worker service"),
        );
        tokio::spawn(Arc::clone(&service).serve(listener));
        kr_ipc::descriptor::publish(
            &environment,
            &WorkerDescriptor {
                session_id,
                session_epoch: SessionEpoch::V1,
                environment_id,
                display_number: display,
                boot_identity: boot,
                process_start_identity: process,
                protocol_version: PROTOCOL_VERSION,
                endpoint: endpoint.as_text(),
                worker_public_key: *identity.public_key(),
                worker_profile: WorkerProfile::HeadlessUser,
                published_at_ms: TimestampMs::new(0),
            },
        )
        .expect("publishes the descriptor");
        Hosted {
            session_id,
            runtime,
            _service: service,
        }
    }

    /// Puts a session descriptor nobody can read among the environment's descriptors.
    fn unreadable_descriptor(&self) {
        use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
        let directory = self.temp.environment().descriptors_dir();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)
            .expect("the descriptors directory");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("00000000-0000-4000-8000-000000000002.kr"))
            .and_then(|mut file| file.write_all(b"not a descriptor"))
            .expect("an unreadable descriptor");
    }
}

/// A live session this test hosts, and its worker.
struct Hosted {
    session_id: SessionId,
    runtime: Arc<SessionRuntime>,
    _service: Arc<WorkerService>,
}

impl Hosted {
    /// Waits for the session's own terminal to have shown `marker`, and returns what it showed.
    async fn shown(&self, marker: &str) -> String {
        let started = Instant::now();
        loop {
            let mut seen = Vec::new();
            let mut cursor = 0_u64;
            loop {
                let page = self
                    .runtime
                    .session()
                    .history_page(cursor, 1024 * 1024)
                    .expect("reads what the session retained");
                if page.bytes.as_slice().is_empty() {
                    break;
                }
                seen.extend_from_slice(page.bytes.as_slice());
                cursor = page.next_cursor.get();
            }
            let seen = String::from_utf8_lossy(&seen).into_owned();
            if seen.contains(marker) {
                return seen;
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "waited {:?} for {marker:?} in the session; it shows: {seen}",
                started.elapsed()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// `kr` running on a pseudo-terminal.
struct OnTerminal {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    output: TerminalOutput,
    writer: Box<dyn Write + Send>,
    _master: Box<dyn portable_pty::MasterPty + Send>,
}

impl OnTerminal {
    /// Waits for the command to end, and returns whether it succeeded and what it printed.
    fn finish(mut self) -> (bool, String) {
        let started = Instant::now();
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("the command's state") {
                break status;
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "kr did not finish; it printed: {}",
                self.output.text()
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        // Whatever the command wrote before it ended is read before the reader is judged.
        std::thread::sleep(Duration::from_millis(200));
        (status.success(), self.output.text())
    }
}

/// Everything a pseudo-terminal's command has written, collected as it arrives.
#[derive(Clone)]
struct TerminalOutput {
    seen: Arc<Mutex<Vec<u8>>>,
}

impl TerminalOutput {
    fn collect(mut reader: Box<dyn Read + Send>) -> Self {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                if let Ok(mut seen) = collected.lock() {
                    seen.extend_from_slice(&buffer[..read]);
                }
            }
        });
        Self { seen }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.seen.lock().expect("the output")).into_owned()
    }

    fn expect(&self, marker: &str, what: &str) {
        let started = Instant::now();
        while !self.text().contains(marker) {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "{what}: waited {:?} for {marker:?}; the terminal shows: {}",
                started.elapsed(),
                self.text()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn copy_into(source: &Path, directory: &Path) -> PathBuf {
    let destination = directory.join(source.file_name().expect("the executable has a name"));
    kr_ipc::testing::place_program(source, &destination);
    destination
}

/// KR-REQ-10.04, KR-REQ-10.53: a host with no owner has its first owner invitation confirmed at
/// the controlling terminal of the person who asked for it, and shows the QR code a new device
/// scans; the invitation it issued is then read and withdrawn by the same owner.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_first_owner_invitation_is_confirmed_at_the_terminal() {
    let Some(host) = Host::start().await else {
        return;
    };
    let mut terminal = host.on_terminal(&["pair", "invite", "--owner", "--direct"], &[]);
    terminal
        .output
        .expect("Type pair to issue the invitation", "kr asks the person");
    terminal.writer.write_all(b"pair\r").expect("typed");
    terminal.writer.flush().expect("flushed");
    terminal
        .output
        .expect("kr pair confirm ", "kr issues the invitation");
    let (succeeded, printed) = terminal.finish();
    assert!(succeeded, "kr pair invite: {printed}\n{}", host.log());
    assert!(
        printed.contains("Scan this QR code with the new device"),
        "{printed}"
    );
    assert!(printed.contains("\u{1b}[30;47m"), "the QR code is drawn");
    let invitation = printed
        .split("kr pair confirm ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .expect("the invitation's identity")
        .to_owned();

    let status = host.kr_json(&["pair", "status", &invitation, "--json"]);
    assert!(status["status"]["open"].is_object(), "{status}");
    assert_eq!(status["owner"]["mode"], "direct", "{status}");
    assert_eq!(status["owner"]["grant_kind"], "personal_owner", "{status}");
    let shown = host.kr(&["pair", "status", &invitation]);
    let shown = String::from_utf8_lossy(&shown.stdout);
    assert!(
        shown.contains(&format!("Invitation {invitation}: open")),
        "{shown}"
    );
    assert!(
        !shown.contains("wrong codes"),
        "a direct invitation has no guesses: {shown}"
    );
    let cancelled = host.kr_json(&["pair", "cancel", &invitation, "--json"]);
    assert_eq!(
        cancelled["status"]["consumed"]["reason"], "cancelled",
        "{cancelled}"
    );
}

/// KR-REQ-10.53: the first owner is not confirmed where there is no terminal: with standard input
/// and output on pipes, `kr` refuses before asking anything, and nothing is issued.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_owner_is_not_confirmed_without_a_terminal() {
    let Some(host) = Host::start().await else {
        return;
    };
    let output = host.kr(&["pair", "invite", "--owner", "--direct"]);
    assert_eq!(
        output.status.code(),
        Some(6),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("needs a terminal"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// KR-REQ-10.53: a terminal inside a KalaReach session is not where the first owner is
/// confirmed: with `KR_SESSION` or `KR_ATTACHMENT` set, `kr` refuses on a real terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_owner_is_not_confirmed_inside_a_session() {
    let Some(host) = Host::start().await else {
        return;
    };
    for variable in ["KR_SESSION", "KR_ATTACHMENT"] {
        let terminal = host.on_terminal(
            &["pair", "invite", "--owner", "--direct"],
            &[(variable, "00000000-0000-4000-8000-000000000001")],
        );
        let (succeeded, printed) = terminal.finish();
        assert!(!succeeded, "{printed}");
        assert!(printed.contains(&format!("{variable} is set")), "{printed}");
        assert!(
            !printed.contains("Type pair"),
            "nothing was asked: {printed}"
        );
    }
}

/// KR-REQ-10.53: where it cannot be established whether this process is inside a session (a
/// session descriptor that cannot be read), the first owner is not confirmed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_owner_is_not_confirmed_where_membership_is_unknown() {
    let Some(host) = Host::start().await else {
        return;
    };
    host.unreadable_descriptor();
    let terminal = host.on_terminal(&["pair", "invite", "--owner", "--direct"], &[]);
    let (succeeded, printed) = terminal.finish();
    assert!(!succeeded, "{printed}");
    assert!(printed.contains("cannot be established"), "{printed}");
    assert!(
        !printed.contains("Type pair"),
        "nothing was asked: {printed}"
    );
}

/// KR-REQ-10.53: an environment whose identity cannot be read may hold sessions nobody can ask
/// about, so the first owner is not confirmed while one is there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_owner_is_not_confirmed_where_an_environment_cannot_be_read() {
    use std::os::unix::fs::DirBuilderExt as _;
    let Some(host) = Host::start().await else {
        return;
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(
            host.temp
                .paths()
                .state_root()
                .join("environments")
                .join("unidentified"),
        )
        .expect("an environment directory with no identity");
    let terminal = host.on_terminal(&["pair", "invite", "--owner", "--direct"], &[]);
    let (succeeded, printed) = terminal.finish();
    assert!(!succeeded, "{printed}");
    assert!(printed.contains("cannot be identified"), "{printed}");
    assert!(
        !printed.contains("Type pair"),
        "nothing was asked: {printed}"
    );
}

/// KR-REQ-10.53: with a session live, a terminal outside it is still where the first owner is
/// confirmed: the session's worker establishes that `kr` is not one of its own, and `kr` goes on to
/// ask the person.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_owner_is_confirmed_outside_a_live_session() {
    let Some(host) = Host::start().await else {
        return;
    };
    let _session = host.session("exec cat");
    let mut terminal = host.on_terminal(&["pair", "invite", "--owner", "--direct"], &[]);
    terminal
        .output
        .expect("Type pair to issue the invitation", "kr asks the person");
    terminal.writer.write_all(b"pair\r").expect("typed");
    terminal.writer.flush().expect("flushed");
    let (succeeded, printed) = terminal.finish();
    assert!(succeeded, "kr pair invite: {printed}\n{}", host.log());
    assert!(printed.contains("kr pair confirm "), "{printed}");
}

/// KR-REQ-10.53: a process inside a live session is not where the first owner is confirmed, even
/// with `KR_SESSION` and `KR_ATTACHMENT` unset: the session's worker recognises it as its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_owner_is_not_confirmed_by_a_session_that_hides_its_variables() {
    let Some(host) = Host::start().await else {
        return;
    };
    // The session's shell waits for the session to be published, which is what makes it a
    // session `kr` can find, before it runs `kr` inside it.
    let published = host.temp.root().join("published");
    let session = host.session(&format!(
        "unset KR_SESSION KR_ATTACHMENT; while [ ! -e '{}' ]; do sleep 0.1; done; '{}' pair invite \
         --owner --direct; echo \"kr ended $?\"; exec cat",
        published.display(),
        kr().display()
    ));
    std::fs::write(&published, b"").expect("says the session is published");
    let shown = session.shown("kr ended").await;
    assert!(
        shown.contains(&format!(
            "this process is inside session {}",
            session.session_id
        )),
        "{shown}"
    );
    assert!(!shown.contains("kr ended 0"), "{shown}");
    assert!(!shown.contains("Type pair"), "nothing was asked: {shown}");
}

/// KR-REQ-10.53: where a live session's worker cannot establish whether `kr` is one of its own, the
/// first owner is not confirmed. A process further below the session's start than the worker
/// follows is such a case: the worker can say neither that it is inside nor that it is outside.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_owner_is_not_confirmed_where_a_worker_cannot_establish_membership() {
    let Some(host) = Host::start().await else {
        return;
    };
    let _session = host.session("exec cat");
    let terminal = host.nested_on_terminal(70, &["pair", "invite", "--owner", "--direct"]);
    let (succeeded, printed) = terminal.finish();
    assert!(!succeeded, "{printed}");
    assert!(printed.contains("cannot be established"), "{printed}");
    assert!(printed.contains("could not be established"), "{printed}");
    assert!(
        !printed.contains("Type pair"),
        "nothing was asked: {printed}"
    );
}

/// A host with no owner pairs its first owner before anything else: an invitation for a viewer is
/// refused before anything is asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_with_no_owner_pairs_its_owner_first() {
    let Some(host) = Host::start().await else {
        return;
    };
    let output = host.kr(&["pair", "invite", "--view", "--direct"]);
    assert_eq!(output.status.code(), Some(8));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("kr pair invite --owner"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
