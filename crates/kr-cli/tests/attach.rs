//! `kr attach` against a real session, in a real terminal.
//!
//! These run the command as a process, on a pseudo-terminal, against a worker this test is hosting.
//! That is the only way to check the two things section 8 insists on and no unit test can reach:
//! that the terminal comes back when the attach process is killed outright, and that an attachment
//! ended somewhere else ends the command rather than leaving it waiting.

#![cfg(unix)]

use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_ipc::endpoint::Listener;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{BuildId, ControllerGeneration, SessionEpoch, SessionId};
use kr_protocol::scalars::TimestampMs;
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_protocol::worker::WorkerDescriptor;
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use rustix::termios::SpecialCodeIndex;

/// A session this test hosts, with its descriptor published where `kr` will find it.
struct Hosted {
    temp: kr_ipc::testing::TempHost,
    session_id: SessionId,
    display: DisplayNumber,
    _service: Arc<WorkerService>,
}

async fn hosted(script: &str) -> Hosted {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let display = DisplayNumber::new(1);
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
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
    let store = kr_crypto::store::open_store("KalaReachAttachTest", &environment.secrets_dir())
        .expect("a secret store");
    let controller =
        kr_ipc::verify::ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity");

    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: display,
        shell: ShellCommand {
            program: "/bin/sh".to_owned(),
            arguments: vec!["-c".to_owned(), script.to_owned()],
            cwd: "/".to_owned(),
            environment: vec![
                ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
                ("PS1".to_owned(), String::new()),
            ],
        },
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 256 * 1024,
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime = Arc::new(SessionRuntime::start(session).expect("starts the runtime"));

    let endpoint = environment.worker_endpoint(display).expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let service = Arc::new(WorkerService::new(
        Arc::clone(&runtime),
        Arc::clone(&identity),
        endpoint.clone(),
        ServiceBinding {
            environment_id,
            boot_identity: boot.clone(),
            controller_public_key: *controller.public_key(),
            controller_generation: ControllerGeneration::new(1),
            build_id: BuildId::new("kr-test/0").expect("a build identifier"),
        },
    ));
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
        temp,
        session_id,
        display,
        _service: service,
    }
}

/// Runs a shell on the terminal, with `kr` inside it.
///
/// The shell is the session leader, which is how a person's terminal actually works: `kr attach`
/// is a command *inside* a session, not the session itself. It matters here because killing a
/// session leader makes the operating system revoke the terminal from every process that holds it,
/// and a test that killed one would be testing a condition the command is never in.
fn shell_running(hosted: &Hosted, command_line: &str) -> CommandBuilder {
    let mut builder = CommandBuilder::new("/bin/sh");
    builder.arg("-c");
    builder.arg(command_line);
    builder.env_clear();
    builder.env("PATH", "/usr/bin:/bin");
    builder.env("TERM", "xterm-256color");
    builder.env(
        "KR_RUNTIME_DIR",
        hosted.temp.paths().runtime_root().display().to_string(),
    );
    builder.env(
        "KR_STATE_DIR",
        hosted.temp.paths().state_root().display().to_string(),
    );
    builder.cwd("/");
    builder
}

/// Returns the identifier of the `kr` process the shell started.
///
/// The shell has more than one child while an attachment is running: the command, and the guard
/// the command armed. They are told apart by the executable they are running, because killing the
/// wrong one would prove nothing.
fn attach_process(shell: u32) -> Option<u32> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let listing = std::process::Command::new("pgrep")
            .args(["-P", &shell.to_string()])
            .output()
            .expect("lists child processes");
        for line in String::from_utf8_lossy(&listing.stdout).lines() {
            let Ok(pid) = line.trim().parse::<u32>() else {
                continue;
            };
            let named = std::process::Command::new("ps")
                .args(["-o", "command=", "-p", &pid.to_string()])
                .output()
                .expect("names the process");
            if String::from_utf8_lossy(&named.stdout)
                .trim_start()
                .starts_with(env!("CARGO_BIN_EXE_kr"))
            {
                return Some(pid);
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// Returns the descriptor the terminal's state is read through.
///
/// A pseudo-terminal pair shares one line discipline, so the master answers for the state the
/// attached command set on the slave. It is the end this test holds open.
fn terminal_fd(pty: &portable_pty::PtyPair) -> std::os::fd::BorrowedFd<'_> {
    let raw = pty
        .master
        .as_raw_fd()
        .expect("the terminal has a descriptor");
    // SAFETY-free: the borrow lives no longer than the pair that owns the descriptor.
    unsafe_free_borrow(raw)
}

/// Borrows a descriptor the caller keeps alive.
fn unsafe_free_borrow(raw: std::os::fd::RawFd) -> std::os::fd::BorrowedFd<'static> {
    // The descriptor belongs to the terminal pair, which outlives every use of this borrow in
    // these tests.
    #[expect(
        unsafe_code,
        reason = "borrowing a descriptor the caller owns has no safe form"
    )]
    unsafe {
        std::os::fd::BorrowedFd::borrow_raw(raw)
    }
}

/// Returns how many restoration guards are running.
fn guard_count() -> usize {
    let listing = std::process::Command::new("ps")
        .args(["-o", "command=", "-ax"])
        .output()
        .expect("lists processes");
    String::from_utf8_lossy(&listing.stdout)
        .lines()
        .filter(|line| {
            line.trim_start()
                .starts_with(env!("CARGO_BIN_EXE_kr-attach-guard"))
        })
        .count()
}

/// Everything the terminal has produced, collected by a thread that never blocks the test.
///
/// A blocking read with nothing to read outlasts any deadline the caller sets, so the reading
/// happens somewhere else and the test only ever looks at what has arrived.
#[derive(Clone)]
struct TerminalOutput {
    seen: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl TerminalOutput {
    fn collect(mut reader: Box<dyn Read + Send>) -> Self {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
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

    /// Waits for the marker to appear, or for the deadline to pass.
    fn wait_for(&self, marker: &[u8], within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if self.contains(marker) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        self.contains(marker)
    }

    fn contains(&self, marker: &[u8]) -> bool {
        self.seen
            .lock()
            .is_ok_and(|seen| seen.windows(marker.len()).any(|window| window == marker))
    }

    fn text(&self) -> String {
        self.seen
            .lock()
            .map(|seen| String::from_utf8_lossy(&seen).into_owned())
            .unwrap_or_default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_terminal_comes_back_after_the_attach_process_is_killed() {
    let hosted = hosted("while true; do echo ready; sleep 1; done").await;
    let pty = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("opens a terminal");

    // The state the terminal is in before anything touches it. This is what has to come back.
    let before = rustix::termios::tcgetattr(terminal_fd(&pty)).expect("reads the terminal's modes");

    let display = hosted.display.get().to_string();
    let mut shell = pty
        .slave
        // The trailing command keeps the shell from replacing itself with `kr`: the shell has to
        // stay as the session leader, because killing a session leader revokes the terminal from
        // every process that holds it and `kr attach` is never the session leader in practice.
        .spawn_command(shell_running(
            &hosted,
            &format!(
                "{} attach {display}; printf 'attach-finished-%s\\n' \"$?\"",
                env!("CARGO_BIN_EXE_kr")
            ),
        ))
        .expect("starts the shell");
    let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
    assert!(
        output.wait_for(b"ready", Duration::from_secs(30)),
        "the session's output reached the terminal: {}",
        output.text()
    );

    // Raw mode is on: the terminal no longer waits for a line and no longer echoes.
    let during = rustix::termios::tcgetattr(terminal_fd(&pty)).expect("reads the terminal's modes");
    assert!(
        !during
            .local_modes
            .contains(rustix::termios::LocalModes::ICANON),
        "the attachment put the terminal into raw mode"
    );

    // Killed outright. No handler runs, no destructor runs; only the guard is left.
    assert_eq!(guard_count(), 1, "the attachment armed a restoration guard");
    let attach = attach_process(shell.process_id().expect("the shell has an identifier"))
        .expect("the shell started the attach command");
    // A real `SIGKILL`, not a hang-up. No handler runs, no destructor runs; the only thing left is
    // the guard, which is the whole point of it being a separate process.
    let killed = std::process::Command::new("kill")
        .args(["-KILL", &attach.to_string()])
        .status()
        .expect("sends the signal");
    assert!(killed.success(), "the attach process was killed");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut after = during.clone();
    while Instant::now() < deadline {
        after = rustix::termios::tcgetattr(terminal_fd(&pty)).expect("reads the terminal's modes");
        if after
            .local_modes
            .contains(rustix::termios::LocalModes::ICANON)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        after.local_modes.bits(),
        before.local_modes.bits(),
        "the guard restored the terminal's local modes after the attach process was killed"
    );
    assert_eq!(
        after.input_modes.bits(),
        before.input_modes.bits(),
        "and its input modes"
    );
    // The control characters too. A terminal whose modes look right and whose interrupt key does
    // nothing has not been restored.
    for index in [
        SpecialCodeIndex::VINTR,
        SpecialCodeIndex::VEOF,
        SpecialCodeIndex::VMIN,
        SpecialCodeIndex::VTIME,
    ] {
        assert_eq!(
            after.special_codes[index], before.special_codes[index],
            "a control character survived the restoration"
        );
    }
    let _ = shell.kill();
    let _ = shell.wait();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detaching_from_another_window_ends_the_attachment_and_restores_its_terminal() {
    let hosted = hosted("while true; do echo ready; sleep 1; done").await;
    let pty = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("opens a terminal");
    let before = rustix::termios::tcgetattr(terminal_fd(&pty)).expect("reads the terminal's modes");

    let display = hosted.display.get().to_string();
    let mut shell = pty
        .slave
        .spawn_command(shell_running(
            &hosted,
            &format!(
                "{} attach {display}; printf 'attach-finished-%s\\n' \"$?\"",
                env!("CARGO_BIN_EXE_kr")
            ),
        ))
        .expect("starts the shell");
    let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
    assert!(
        output.wait_for(b"ready", Duration::from_secs(30)),
        "the session's output reached the terminal: {}",
        output.text()
    );

    // A second command, in another window, ends this attachment. It names no attachment, so the
    // session is asked which one it has.
    let session = hosted.session_id.to_string();
    let detach = std::process::Command::new(env!("CARGO_BIN_EXE_kr"))
        .args(["detach", &session])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env(
            "KR_RUNTIME_DIR",
            hosted.temp.paths().runtime_root().display().to_string(),
        )
        .env(
            "KR_STATE_DIR",
            hosted.temp.paths().state_root().display().to_string(),
        )
        .output()
        .expect("runs the detach");
    assert!(
        detach.status.success(),
        "the detach succeeded: {}",
        String::from_utf8_lossy(&detach.stderr)
    );

    // The attached command ends by itself, its exit status says the detach was not a failure, and
    // its terminal comes back with it.
    assert!(
        output.wait_for(b"attach-finished-0", Duration::from_secs(30)),
        "the attachment ended, and an ordinary detach is not a failure: {}",
        output.text()
    );
    let after = rustix::termios::tcgetattr(terminal_fd(&pty)).expect("reads the terminal's modes");
    assert_eq!(
        after.local_modes.bits(),
        before.local_modes.bits(),
        "the terminal came back when the attachment ended"
    );
    let _ = shell.kill();
    let _ = shell.wait();
}
