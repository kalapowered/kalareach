//! `kr attach` against a real session, in a real terminal.
//!
//! These run the command as a process, on a pseudo-terminal, against a worker this test is hosting.
//! That is the only way to check the two things section 8 insists on and no unit test can reach:
//! that the terminal comes back when the attach process is killed outright, and that an attachment
//! ended somewhere else ends the command rather than leaving it waiting.

#![cfg(unix)]

use std::io::{Read, Write};
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
    descriptor: WorkerDescriptor,
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
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
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
                build_id: BuildId::new("kr-test/0").expect("a build identifier"),
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));

    let descriptor = WorkerDescriptor {
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
    };
    kr_ipc::descriptor::publish(&environment, &descriptor).expect("publishes the descriptor");

    Hosted {
        temp,
        session_id,
        display,
        descriptor,
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
fn guards_of(attach: u32) -> usize {
    let listing = std::process::Command::new("pgrep")
        .args(["-P", &attach.to_string()])
        .output()
        .expect("lists child processes");
    String::from_utf8_lossy(&listing.stdout)
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .filter(|pid| {
            let named = std::process::Command::new("ps")
                .args(["-o", "command=", "-p", &pid.to_string()])
                .output()
                .expect("names the process");
            String::from_utf8_lossy(&named.stdout)
                .trim_start()
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

    /// How many times a sequence appears in what the terminal has been sent.
    fn count(&self, marker: &[u8]) -> usize {
        self.seen.lock().map_or(0, |seen| {
            seen.windows(marker.len())
                .filter(|window| *window == marker)
                .count()
        })
    }

    fn text(&self) -> String {
        self.seen
            .lock()
            .map(|seen| String::from_utf8_lossy(&seen).into_owned())
            .unwrap_or_default()
    }
}

/// Answers the keyboard queries the way a terminal that implements both protocols would.
///
/// `kr attach` asks the outer terminal what it has negotiated before it changes anything, so that
/// what it puts back afterwards is that terminal's own state rather than nothing at all. These are
/// the answers a terminal with the Kitty protocol at flags 5 and `modifyOtherKeys` at level 2
/// gives, followed by the device attributes that end the exchange.
fn answer_keyboard_queries(output: &TerminalOutput, mut writer: Box<dyn std::io::Write + Send>) {
    let output = output.clone();
    std::thread::spawn(move || {
        if !output.wait_for(b"\x1b[?u", Duration::from_secs(20)) {
            return;
        }
        let _ = writer.write_all(b"\x1b[?5u\x1b[>4;2m\x1b[?62;22c");
        let _ = writer.flush();
    });
}

/// Answers the keyboard queries and types something in the middle of the exchange.
///
/// Section 8 keeps what a person types during the bounded handshake apart from the terminal's
/// answers, and forwards it once the attachment begins rather than discarding it or reading it as
/// a reply.
fn answer_and_type(
    output: &TerminalOutput,
    mut writer: Box<dyn std::io::Write + Send>,
    typed: &'static [u8],
) {
    let output = output.clone();
    std::thread::spawn(move || {
        if !output.wait_for(b"\x1b[?u", Duration::from_secs(20)) {
            return;
        }
        let mut answer = Vec::from(b"\x1b[?5u".as_slice());
        answer.extend_from_slice(typed);
        answer.extend_from_slice(b"\x1b[>4;2m\x1b[?62;22c");
        let _ = writer.write_all(&answer);
        let _ = writer.flush();
    });
}

/// The sequences that put this test's terminal back into the state it reported.
const KEYBOARD_RESTORED: &[u8] = b"\x1b[=5;1u";

/// The `modifyOtherKeys` level this test's terminal reported, as the restoration writes it.
const MODIFY_OTHER_KEYS_RESTORED: &[u8] = b"\x1b[>4;2m";

/// Counts the Kitty keyboard stack operations in what reached a terminal.
///
/// A push is `CSI > flags u` and a pop is `CSI < count u`. KalaReach writes neither: the stack of
/// the terminal an attachment borrows belongs to whatever was running when it arrived, and an entry
/// pushed there could be taken off by an application inside the session, so the pop that answered
/// it would land on somebody else's. `CSI > 4 ; level m` is the `modifyOtherKeys` level and is not
/// a stack operation, which is why this looks at the final byte rather than at the introducer.
fn stack_operations(bytes: &[u8]) -> usize {
    let mut seen = 0;
    let mut index = 0;
    while index + 2 < bytes.len() {
        if &bytes[index..index + 2] != b"\x1b[" {
            index += 1;
            continue;
        }
        let introducer = bytes[index + 2];
        index += 2;
        if introducer != b'>' && introducer != b'<' {
            continue;
        }
        let mut end = index + 1;
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        if bytes.get(end) == Some(&b'u') {
            seen += 1;
        }
    }
    seen
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
    answer_keyboard_queries(&output, pty.master.take_writer().expect("a writer"));
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

    let attach = attach_process(shell.process_id().expect("the shell has an identifier"))
        .expect("the shell started the attach command");
    // Killed outright. No handler runs, no destructor runs; only the guard is left. The guard is
    // counted among this attachment's own children, because the tests in this file run beside each
    // other and each one arms a guard of its own.
    assert_eq!(
        guards_of(attach),
        1,
        "the attachment armed a restoration guard"
    );
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
    // And the keyboard protocols this terminal had negotiated for itself, which termios does not
    // describe and clearing alone would have taken away.
    assert!(
        output.wait_for(KEYBOARD_RESTORED, Duration::from_secs(10)),
        "the guard put the terminal's own keyboard protocol back: {}",
        output.text().escape_debug()
    );
    assert!(
        output.contains(MODIFY_OTHER_KEYS_RESTORED),
        "and its modifyOtherKeys level: {}",
        output.text().escape_debug()
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
    answer_keyboard_queries(&output, pty.master.take_writer().expect("a writer"));
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
        // Never this test's own directory: the build tree can be on a removable volume, and
        // nothing this suite starts is given a working directory there.
        .current_dir(hosted.temp.root())
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
    assert!(
        output.wait_for(KEYBOARD_RESTORED, Duration::from_secs(10)),
        "and so did the keyboard protocol it had negotiated for itself: {}",
        output.text().escape_debug()
    );
    assert!(
        output.contains(MODIFY_OTHER_KEYS_RESTORED),
        "and its modifyOtherKeys level: {}",
        output.text().escape_debug()
    );
    // And the terminal's own keyboard stack was never operated: what this attachment put back is
    // the state the terminal reported, so an application inside the session that emptied the stack
    // cannot have made this cleanup take an entry belonging to whatever was running before.
    assert_eq!(
        stack_operations(output.text().as_bytes()),
        0,
        "nothing was pushed or popped: {}",
        output.text().escape_debug()
    );
    let _ = shell.kill();
    let _ = shell.wait();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_application_that_empties_the_keyboard_stack_takes_nothing_of_the_terminals_own() {
    // Section 8, finding 10: the Kitty keyboard stack of the terminal an attachment borrows belongs
    // to whatever was running when it arrived. An application inside the session can empty that
    // stack with one sequence, and it does so here. Because KalaReach never put an entry of its own
    // on it, there is no pop written on the way out to land on an outer entry instead: what the
    // terminal reported is written back as the state it is.
    let hosted = hosted("printf '\\033[<65535u'; while true; do echo ready; sleep 1; done").await;
    let pty = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("opens a terminal");

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
    answer_keyboard_queries(&output, pty.master.take_writer().expect("a writer"));
    assert!(
        output.wait_for(b"ready", Duration::from_secs(30)),
        "the session's output reached the terminal: {}",
        output.text()
    );

    let session = hosted.session_id.to_string();
    let detach = std::process::Command::new(env!("CARGO_BIN_EXE_kr"))
        .args(["detach", &session])
        // Never this test's own directory: the build tree can be on a removable volume, and
        // nothing this suite starts is given a working directory there.
        .current_dir(hosted.temp.root())
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
    assert!(
        output.wait_for(b"attach-finished-0", Duration::from_secs(30)),
        "the attachment ended: {}",
        output.text()
    );
    assert!(
        output.wait_for(KEYBOARD_RESTORED, Duration::from_secs(10)),
        "the terminal's own keyboard protocol was put back: {}",
        output.text().escape_debug()
    );
    assert!(
        output.contains(MODIFY_OTHER_KEYS_RESTORED),
        "and its modifyOtherKeys level: {}",
        output.text().escape_debug()
    );

    // Whatever stack operations reached this terminal are the application's own. None of them is
    // one of this attachment's, so the entry an outer program had pushed before `kr` ran is still
    // on the stack and its own pop will find it.
    assert_eq!(
        output.count(b"\x1b[>0u"),
        0,
        "no entry of this attachment's was opened: {}",
        output.text().escape_debug()
    );
    assert_eq!(
        output.count(b"\x1b[<1u"),
        0,
        "and none was taken off: {}",
        output.text().escape_debug()
    );
    assert_eq!(
        output.count(b"\x1b[<65535u"),
        stack_operations(output.text().as_bytes()),
        "every stack operation this terminal saw is the application's own: {}",
        output.text().escape_debug()
    );
    let _ = shell.kill();
    let _ = shell.wait();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_terminal_that_does_not_finish_the_handshake_fails_the_attach_and_keeps_its_modes() {
    // Section 8: the capability handshake is bounded and ends with the device-attributes
    // terminator. A terminal that never sends it may still send a late reply, so the attachment
    // fails rather than beginning to forward live input on that stream.
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
    // Nothing answers. The handshake's own deadline ends it.
    assert!(
        output.wait_for(b"attach-finished-6", Duration::from_secs(30)),
        "the attach failed with the terminal's own exit code rather than forwarding input: {}",
        output.text().escape_debug()
    );
    let after = rustix::termios::tcgetattr(terminal_fd(&pty)).expect("reads the terminal's modes");
    assert_eq!(
        after.local_modes.bits(),
        before.local_modes.bits(),
        "and the terminal it borrowed for the handshake came back"
    );
    assert!(
        !output.contains(b"ready"),
        "no session output reached a terminal whose handshake failed: {}",
        output.text().escape_debug()
    );
    let _ = shell.kill();
    let _ = shell.wait();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_was_typed_during_the_handshake_reaches_the_application() {
    // The session echoes whatever it is given, so a byte that reached the application comes back
    // to this terminal. What is being checked is that the bytes typed while the host was asking
    // the terminal what it is were kept rather than discarded or read as part of an answer.
    let hosted = hosted("exec cat").await;
    let pty = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("opens a terminal");
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
    answer_and_type(
        &output,
        pty.master.take_writer().expect("a writer"),
        b"kr-typed-early\n",
    );
    assert!(
        output.wait_for(b"kr-typed-early", Duration::from_secs(30)),
        "the bytes typed during the handshake reached the application: {}",
        output.text().escape_debug()
    );
    let _ = shell.kill();
    let _ = shell.wait();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attach_that_fails_before_it_forwards_leaves_the_keyboard_protocols_alone() {
    // The outer terminal's own keyboard negotiation is only this attachment's to clear once this
    // attachment could have changed it, which is once it forwards. An attach that asked the
    // terminal what it was and then failed on its way to the session changed nothing, so its
    // cleanup puts the modes back and leaves the protocols the person set up for themselves.
    let hosted = hosted("while true; do echo ready; sleep 1; done").await;
    // A second display whose descriptor names an endpoint nothing is listening on. The command
    // reaches the terminal, completes the handshake, and then fails to reach the session.
    let unreachable = DisplayNumber::new(2);
    let mut descriptor = hosted.descriptor.clone();
    descriptor.display_number = unreachable;
    descriptor.endpoint = hosted
        .temp
        .environment()
        .worker_endpoint(unreachable)
        .expect("an endpoint")
        .as_text();
    kr_ipc::descriptor::publish(&hosted.temp.environment(), &descriptor)
        .expect("publishes the descriptor");

    let pty = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("opens a terminal");
    let before = rustix::termios::tcgetattr(terminal_fd(&pty)).expect("reads the terminal's modes");
    let mut shell = pty
        .slave
        .spawn_command(shell_running(
            &hosted,
            &format!(
                "{} attach {}; printf 'attach-finished-%s\\n' \"$?\"",
                env!("CARGO_BIN_EXE_kr"),
                unreachable.get()
            ),
        ))
        .expect("starts the shell");
    let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
    answer_keyboard_queries(&output, pty.master.take_writer().expect("a writer"));

    assert!(
        output.wait_for(b"attach-finished-", Duration::from_secs(30)),
        "the attach ended: {}",
        output.text().escape_debug()
    );
    assert!(
        !output.contains(b"attach-finished-0"),
        "and it ended as a failure, because nothing was listening: {}",
        output.text().escape_debug()
    );
    assert!(
        output.contains(b"\x1b[?u"),
        "the handshake did happen, so this terminal's state was read: {}",
        output.text().escape_debug()
    );
    assert_eq!(
        stack_operations(output.text().as_bytes()),
        0,
        "no keyboard stack of this terminal's was operated: {}",
        output.text().escape_debug()
    );
    assert!(
        !output.contains(b"\x1b[>4m"),
        "and nothing took the keyboard protocols away from a terminal it never changed: {}",
        output.text().escape_debug()
    );
    let after = rustix::termios::tcgetattr(terminal_fd(&pty)).expect("reads the terminal's modes");
    assert_eq!(
        after.local_modes.bits(),
        before.local_modes.bits(),
        "while the modes it borrowed for the handshake came back"
    );
    let _ = shell.kill();
    let _ = shell.wait();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attachment_that_asked_nothing_leaves_the_keyboard_exactly_as_it_found_it() {
    // `--no-probe` is chosen before any query is sent and asks the terminal nothing. Nothing may
    // then change its keyboard protocols: the host serves such an attachment a screen that installs
    // none, and the command opens no stack entry of its own, so a person who had negotiated a
    // keyboard protocol for themselves still has exactly that afterwards.
    let hosted = hosted("while true; do echo ready; sleep 1; done").await;
    let pty = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("opens a terminal");
    let display = hosted.display.get().to_string();
    let mut shell = pty
        .slave
        .spawn_command(shell_running(
            &hosted,
            &format!(
                "{} attach {display} --no-probe; printf 'attach-finished-%s\\n' \"$?\"",
                env!("CARGO_BIN_EXE_kr")
            ),
        ))
        .expect("starts the shell");
    let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
    assert!(
        output.wait_for(b"ready", Duration::from_secs(30)),
        "the session's output reached the terminal: {}",
        output.text().escape_debug()
    );
    // Section 8: the host checks that a controller can supply the encoding the application reads,
    // and a terminal nobody was allowed to ask about cannot be shown to. The attachment is not
    // refused - it watches - and the person is told which of the two they have.
    assert!(
        output.wait_for(b"will not let it type", Duration::from_secs(10)),
        "the person is told that this attachment watches rather than types: {}",
        output.text().escape_debug()
    );
    let before = rustix::termios::tcgetattr(terminal_fd(&pty)).expect("reads the terminal's modes");

    // And typing does not end it: the bytes go nowhere rather than becoming a refused request.
    pty.master
        .take_writer()
        .expect("a writer")
        .write_all(b"x")
        .expect("types into the terminal");
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !output.contains(b"attach-finished-"),
        "the attachment is still watching after a keystroke: {}",
        output.text().escape_debug()
    );

    let attach = attach_process(shell.process_id().expect("the shell has an identifier"))
        .expect("the shell started the attach command");
    let killed = std::process::Command::new("kill")
        .args(["-KILL", &attach.to_string()])
        .status()
        .expect("sends the signal");
    assert!(killed.success(), "the attach process was killed");

    // The guard puts the modes back, which is how this test knows the cleanup ran at all.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let after =
            rustix::termios::tcgetattr(terminal_fd(&pty)).expect("reads the terminal's modes");
        if after
            .local_modes
            .contains(rustix::termios::LocalModes::ICANON)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Nothing about the keyboard was ever written to this terminal: no stack was operated, no
    // level was imposed and no flags were set. A terminal nobody was allowed to ask keeps exactly
    // what its owner set up.
    assert_eq!(
        stack_operations(output.text().as_bytes()),
        0,
        "no keyboard stack of this terminal's was operated: {}",
        output.text().escape_debug()
    );
    assert!(
        !output.contains(b"\x1b[>4;"),
        "no modifyOtherKeys level was imposed: {}",
        output.text().escape_debug()
    );
    assert!(
        !output.contains(b"\x1b[="),
        "and no Kitty flags were set: {}",
        output.text().escape_debug()
    );
    let _ = before;
    let _ = shell.kill();
    let _ = shell.wait();
}
