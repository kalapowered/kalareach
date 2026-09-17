//! The bounded capability probe, in a real terminal.
//!
//! Section 8 makes the probe a small, bounded, synchronous conversation with the terminal a person
//! is sitting in front of, and it happens once, before the application receives any input. Four
//! properties of it can only be checked with a real terminal on the other end, and they are what
//! these tests are:
//!
//! * the exchange ends with the device-attributes terminator, after every question it asked;
//! * the terminal's replies never enter the application's input, and what the person typed while
//!   the host was asking does;
//! * a terminal that does not finish the exchange fails that attach attempt, with its own modes put
//!   back, rather than timing out into live forwarding on a stream a late reply could still reach;
//! * `--no-probe` asks the terminal nothing at all.

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

/// A session this test hosts, with its descriptor published where `kr` will find it.
struct Hosted {
    temp: kr_ipc::testing::TempHost,
    display: DisplayNumber,
    runtime: Arc<SessionRuntime>,
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

    let _ = descriptor;
    Hosted {
        temp,
        display,
        runtime,
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

/// Returns the descriptor the terminal's state is read through.
///
/// A pseudo-terminal pair shares one line discipline, so the master answers for the state the
/// attached command set on the slave. It is the end this test holds open.
fn terminal_fd(pty: &portable_pty::PtyPair) -> std::os::fd::BorrowedFd<'_> {
    let raw = pty
        .master
        .as_raw_fd()
        .expect("the terminal has a descriptor");
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

    /// Everything the terminal has been sent so far.
    fn snapshot(&self) -> Vec<u8> {
        self.seen
            .lock()
            .map(|seen| seen.clone())
            .unwrap_or_default()
    }

    fn text(&self) -> String {
        self.seen
            .lock()
            .map(|seen| String::from_utf8_lossy(&seen).into_owned())
            .unwrap_or_default()
    }
}

/// The queries this command writes, in the order it writes them.
///
/// Device attributes is last and nothing may come after it: it is the terminator, and its answer is
/// what proves every earlier question has been answered or ignored.
const QUERIES: &[&[u8]] = &[
    b"\x1b[>0q",
    b"\x1b]10;?",
    b"\x1b]11;?",
    b"\x1b[?u",
    b"\x1b[?4m",
    b"\x1b[?2026$p",
    b"\x1b[c",
];

/// Reads everything the session's application actually received.
fn application_saw(runtime: &SessionRuntime) -> Vec<u8> {
    let session = runtime.session();
    let mut seen = Vec::new();
    let mut cursor = 0_u64;
    loop {
        let page = session
            .history_page(cursor, 1024 * 1024)
            .expect("reads the retained output");
        if page.bytes.as_slice().is_empty() {
            break;
        }
        seen.extend_from_slice(page.bytes.as_slice());
        cursor = page.next_cursor.get();
    }
    seen
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Where each query appears in what the terminal was sent, or `None` for one that never arrived.
fn offset_of(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// A shell that echoes its input, so what the application received is visible from outside.
const ECHOES_ITS_INPUT: &str = "stty raw -echo; printf 'kr-ready.'; exec cat";

/// KR-REQ-08.42 and KR-ACC-025: the exchange ends with the terminator, and no reply reaches the
/// application.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_exchange_ends_with_the_terminator_and_no_reply_reaches_the_application() {
    let hosted = hosted(ECHOES_ITS_INPUT).await;
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
                "{} attach {display}; printf 'attach-finished-%s\n' \"$?\"",
                env!("CARGO_BIN_EXE_kr")
            ),
        ))
        .expect("starts the shell");
    let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
    let mut writer = pty.master.take_writer().expect("a writer");

    // The terminal answers every question, and the person types through the middle of it.
    assert!(
        output.wait_for(b"\x1b[c", Duration::from_secs(30)),
        "the command asked the terminal what it is: {}",
        output.text().escape_debug()
    );
    let asked = output.snapshot();
    let mut previous = 0;
    for query in QUERIES {
        let at = offset_of(&asked, query).unwrap_or_else(|| {
            panic!(
                "the command asked {:?}: {}",
                String::from_utf8_lossy(query),
                String::from_utf8_lossy(&asked).escape_debug()
            )
        });
        assert!(
            at >= previous,
            "the questions are written in order, and the terminator last: {:?} came too early",
            String::from_utf8_lossy(query)
        );
        previous = at;
    }
    writer
        .write_all(b"\x1b[?5u\x1b]10;rgb:ff/ff/ff\x1b\\typed-during\x1b[>4;2m\x1b[?62;22c")
        .expect("answers");
    writer.flush().expect("flushes");

    // What the application received. The answers are not in it, and the typing is.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut seen = Vec::new();
    while Instant::now() < deadline {
        seen = application_saw(&hosted.runtime);
        if contains(&seen, b"typed-during") {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        contains(&seen, b"typed-during"),
        "what the person typed while the host was asking reached the application: {}",
        String::from_utf8_lossy(&seen).escape_debug()
    );
    for reply in [
        &b"\x1b[?5u"[..],
        b"\x1b[>4;2m",
        b"\x1b[?62;22c",
        b"rgb:ff/ff/ff",
    ] {
        assert!(
            !contains(&seen, reply),
            "no reply entered the application's input: {:?} is in {}",
            String::from_utf8_lossy(reply),
            String::from_utf8_lossy(&seen).escape_debug()
        );
    }
    let _ = shell.kill();
    let _ = shell.wait();
}

/// KR-REQ-08.42 and KR-ACC-025: a terminal that never finishes fails the attempt, modes intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_terminal_that_never_finishes_the_exchange_fails_the_attempt() {
    let hosted = hosted("while true; do printf 'kr-ready.'; sleep 1; done").await;
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
                "{} attach {display}; printf 'attach-finished-%s\n' \"$?\"",
                env!("CARGO_BIN_EXE_kr")
            ),
        ))
        .expect("starts the shell");
    let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
    // Nothing answers. The exchange has one second, and the attempt fails rather than beginning to
    // forward on a stream that may still receive a late reply.
    let started = Instant::now();
    assert!(
        output.wait_for(b"attach-finished-", Duration::from_secs(40)),
        "the command finished: {}",
        output.text().escape_debug()
    );
    assert!(
        output.contains(b"attach-finished-6"),
        "with the terminal failure's own exit code: {}",
        output.text().escape_debug()
    );
    assert!(
        started.elapsed() < Duration::from_secs(40),
        "and it did not wait indefinitely"
    );
    // The modes it changed to read the answers are the modes it put back.
    let after = rustix::termios::tcgetattr(terminal_fd(&pty)).expect("reads the terminal's modes");
    assert_eq!(
        after.local_modes.bits(),
        before.local_modes.bits(),
        "a failed probe leaves the terminal's own modes"
    );
    assert_eq!(after.input_modes.bits(), before.input_modes.bits());
    // And nothing of the terminal's own keyboard negotiation was cleared: nothing had begun
    // forwarding, so nothing could have changed it.
    assert!(
        !output.contains(b"\x1b[>4m"),
        "an attach that failed before it forwarded leaves the keyboard protocols alone: {}",
        output.text().escape_debug()
    );
    let _ = shell.kill();
    let _ = shell.wait();
}

/// KR-REQ-08.43: `--no-probe` asks the terminal nothing at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_probe_asks_the_terminal_nothing() {
    let hosted = hosted("while true; do printf 'kr-ready.'; sleep 1; done").await;
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
                "{} attach --no-probe {display}; printf 'attach-finished-%s\n' \"$?\"",
                env!("CARGO_BIN_EXE_kr")
            ),
        ))
        .expect("starts the shell");
    let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
    // The screen arrives: the choice is made before anything is written, so there is no handshake
    // to wait for and the attachment simply begins.
    assert!(
        output.wait_for(b"kr-ready.", Duration::from_secs(30)),
        "the session's screen reached the terminal: {}",
        output.text().escape_debug()
    );
    for query in QUERIES {
        assert!(
            !output.contains(query),
            "no question was asked: {:?} reached the terminal in {}",
            String::from_utf8_lossy(query),
            output.text().escape_debug()
        );
    }
    let _ = shell.kill();
    let _ = shell.wait();
}
