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
    runtime: Arc<SessionRuntime>,
    _service: Arc<WorkerService>,
}
/// The command binaries, on the internal disk.
///
/// The build directory is on the external volume this workspace lives on, and a process a test
/// launches is its own privacy identity to the operating system: a binary run from there makes
/// macOS ask whether it may read that volume, and the launch waits on the answer. Nothing a test
/// waits for arrives while that is on screen. So the binaries are copied once per test process to a
/// directory the operating system does not guard, and every test launches them from there. Both are
/// copied together and keep their names, because `kr` looks for its restoration guard beside
/// itself.
fn command_binaries() -> &'static std::path::Path {
    static COPIED: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    COPIED.get_or_init(|| {
        let root = std::env::temp_dir().join(format!(
            "kalareach-command-tests-{}-{}",
            env!("CARGO_CRATE_NAME"),
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("a directory for the command binaries");
        for source in [
            std::path::Path::new(env!("CARGO_BIN_EXE_kr")),
            std::path::Path::new(env!("CARGO_BIN_EXE_kr-attach-guard")),
        ] {
            let name = source.file_name().expect("the binary has a name");
            let destination = root.join(name);
            std::fs::copy(source, &destination).expect("copies a command binary");
            // Run it once, here, where nothing is being timed. The operating system checks a binary
            // it has not seen before on its first run and remembers it afterwards, and that check
            // takes seconds where the run itself takes milliseconds. A test that paid it inside a
            // wait would be measuring the check.
            let _ = std::process::Command::new(&destination)
                .arg("--version")
                .current_dir(&root)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        root
    })
}

/// The `kr` this test launches.
fn kr() -> std::path::PathBuf {
    command_binaries().join("kr")
}

/// The restoration guard this test's `kr` launches, which is beside it.
fn kr_attach_guard() -> std::path::PathBuf {
    command_binaries().join("kr-attach-guard")
}
/// A directory of files a session's application waits on, so this test decides when it acts.
///
/// An application on a clock races the attachment: what it writes before the attachment exists is
/// in the first screen the attachment is given rather than in what the test watched arrive, and a
/// test that watches a window would then be asserting about how fast the machine was. These let the
/// test say when instead. They are on the internal disk, like everything else a launched process
/// touches.
fn gates() -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("kalareach-gates-{}", kr_ipc::new_uuid()));
    std::fs::create_dir_all(&root).expect("a directory for this test's gates");
    root
}

/// The shell that waits for one of those files to appear.
fn waits_for(gates: &std::path::Path, gate: &str) -> String {
    format!(
        "while [ ! -e {} ]; do sleep 0.05; done",
        gates.join(gate).display()
    )
}

/// Lets the application past one.
fn open_gate(gates: &std::path::Path, gate: &str) {
    std::fs::write(gates.join(gate), b"").expect("opens a gate the application is waiting on");
}

async fn hosted(script: &str) -> Hosted {
    // Before the application starts, not between its start and the attachment. Copying the command
    // binaries and running each once happens once per test process, and a test that paid it after
    // its own session had begun would be letting the application run while nothing was attached.
    // What such a test then sees in its first screen is output it expected to watch arrive.
    let _ = command_binaries();
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
            // The host's own directories, so a command run *inside* the session reaches the same
            // host: that is how a person's session behaves, and it is what nesting needs.
            environment: session_environment(&temp),
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
                journal_path: None,
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
        runtime,
        _service: service,
    }
}

/// Waits for the session itself to have produced `marker`, and fails with how long it waited.
///
/// A terminal echoes what a person types, so what the *application* was given can only be read from
/// what its session retained. This is the difference between input that was forwarded and input the
/// outer terminal simply showed back.
async fn session_retained(hosted: &Hosted, marker: &[u8], within: Duration) -> Vec<u8> {
    let started = Instant::now();
    let deadline = started + within;
    loop {
        let mut seen = Vec::new();
        let mut cursor = 0_u64;
        loop {
            let page = hosted
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
        if seen.windows(marker.len()).any(|window| window == marker) {
            return seen;
        }
        assert!(
            Instant::now() < deadline,
            "waited {:?} for {:?} in what the session retained: {}",
            started.elapsed(),
            String::from_utf8_lossy(marker),
            String::from_utf8_lossy(&seen).escape_debug()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The environment a session's own shell runs in.
///
/// It carries the host's directories, because a command run inside a session has to reach the same
/// host: that is what makes a nested attach possible, and it is how a real session is arranged.
fn session_environment(temp: &kr_ipc::testing::TempHost) -> Vec<(String, String)> {
    vec![
        ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        ("PS1".to_owned(), String::new()),
        ("TERM".to_owned(), "xterm-256color".to_owned()),
        (
            "HOME".to_owned(),
            temp.paths().state_root().display().to_string(),
        ),
        (
            "KR_RUNTIME_DIR".to_owned(),
            temp.paths().runtime_root().display().to_string(),
        ),
        (
            "KR_STATE_DIR".to_owned(),
            temp.paths().state_root().display().to_string(),
        ),
    ]
}

/// Hosts a second session in the same environment, on its own display.
///
/// Nesting needs two: a terminal attached to one session, and a `kr attach` to the other running
/// inside it. Both live in one environment, because that is how a person's own host is arranged and
/// because the inner command finds its session through the same published descriptors.
async fn second_session(hosted: &Hosted, script: &str) -> (DisplayNumber, Arc<SessionRuntime>) {
    let environment = hosted.temp.environment();
    let environment_id = hosted.temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let display = DisplayNumber::new(2);
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
    // The environment already has one: this is the second session in it, not a second environment.
    let controller =
        kr_ipc::verify::ControllerIdentity::open(store.store.as_ref(), environment_id, false)
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
            environment: session_environment(&hosted.temp),
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
    // The service is kept alive by the task above for as long as the runtime is.
    std::mem::forget(service);
    (display, runtime)
}

/// Reads everything one session's application received.
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

fn saw(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
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

/// How long a wait for something to appear is given.
///
/// A liveness wait is not a measurement: it is there to fail when something never happens. The ten,
/// twenty and thirty second windows these waits had were inside the range the slowest reference
/// hosts reach when several suites share them, which turned each of them into a coin toss; two
/// minutes is outside it. The poll intervals are unchanged, so a wait that succeeds costs what it
/// always did. The short windows that assert something *never* appears are deliberately left as
/// they are: they are not waiting for anything.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// Returns the identifier of the `kr` process the shell started.
///
/// The shell has more than one child while an attachment is running: the command, and the guard
/// the command armed. They are told apart by the executable they are running, because killing the
/// wrong one would prove nothing.
fn attach_process(shell: u32) -> u32 {
    let started = Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    loop {
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
                .starts_with(&kr().display().to_string())
            {
                return pid;
            }
        }
        assert!(
            Instant::now() < deadline,
            "waited {:?} for the shell to start the attach command",
            started.elapsed()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Waits for the terminal's line discipline to come back, and fails with how long it waited.
///
/// The guard the attached command armed is what puts it back, so this is the wait that says the
/// cleanup ran at all. A terminal the attachment never took out of canonical mode answers at once.
fn canonical_again(pty: &portable_pty::PtyPair, what: &str) -> rustix::termios::Termios {
    let started = Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    loop {
        let modes =
            rustix::termios::tcgetattr(terminal_fd(pty)).expect("reads the terminal's modes");
        if modes
            .local_modes
            .contains(rustix::termios::LocalModes::ICANON)
        {
            return modes;
        }
        assert!(
            Instant::now() < deadline,
            "{what}: waited {:?} for the terminal's line discipline to come back",
            started.elapsed()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
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
                .starts_with(&kr_attach_guard().display().to_string())
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

    /// Waits for the marker, and fails with how long it waited when it never arrives.
    ///
    /// `what` says what the marker means to the caller, so a failure names both the wait and the
    /// thing waited for.
    ///
    /// It looks every two milliseconds, because one of the things that waits here is the thread
    /// that answers the command's handshake, and that handshake has one second in total. A real
    /// terminal answers in microseconds; a test that noticed the question fifty milliseconds later
    /// would be spending the command's own bound on its own polling, and on a busy machine it would
    /// spend all of it.
    fn expect_within(&self, marker: &[u8], within: Duration, what: &str) {
        let started = Instant::now();
        let deadline = started + within;
        loop {
            if self.contains(marker) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{what}: waited {:?} for {:?} in the terminal's output: {}",
                started.elapsed(),
                String::from_utf8_lossy(marker),
                self.text().escape_debug()
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn contains(&self, marker: &[u8]) -> bool {
        self.seen
            .lock()
            .is_ok_and(|seen| seen.windows(marker.len()).any(|window| window == marker))
    }

    /// Every byte the terminal has been sent, as it was sent.
    fn bytes(&self) -> Vec<u8> {
        self.seen
            .lock()
            .map(|seen| seen.clone())
            .unwrap_or_default()
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
fn answer_keyboard_queries(
    output: &TerminalOutput,
    mut writer: Box<dyn std::io::Write + Send>,
) -> std::thread::JoinHandle<()> {
    let output = output.clone();
    std::thread::spawn(move || {
        // The device-attributes request is the one question every profile asks, so it is what this
        // waits for. The two keyboard answers are volunteered: this terminal implements both
        // protocols and says so, and a reply a terminal gives unbidden is still the truth about
        // itself, which is what the restoration puts back.
        output.expect_within(b"\x1b[c", LIVENESS_DEADLINE, QUERY_EXPECTED);
        writer
            .write_all(b"\x1b[?5u\x1b[>4;2m\x1b[?62;22c")
            .expect("answers the queries");
        writer.flush().expect("and the answer reaches the command");
    })
}

/// What a terminal is waiting for when it answers the queries this command asks.
const QUERY_EXPECTED: &str = "the command asked this terminal what it is";

/// Waits for the thread that answers this terminal's queries, and gives the test what it found.
///
/// The query is a required wait: without it nothing is answered, the bounded handshake fails and
/// there is no attachment to test. A thread whose panic nobody joins would leave that as a timeout
/// somewhere else, so the failure is brought back here with its own message.
fn answered(queries: std::thread::JoinHandle<()>) {
    if let Err(panic) = queries.join() {
        let detail = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap_or("the thread answering this terminal's queries failed");
        panic!("{detail}");
    }
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
) -> std::thread::JoinHandle<()> {
    let output = output.clone();
    std::thread::spawn(move || {
        output.expect_within(b"\x1b[c", LIVENESS_DEADLINE, QUERY_EXPECTED);
        let mut answer = Vec::from(b"\x1b[?5u".as_slice());
        answer.extend_from_slice(typed);
        answer.extend_from_slice(b"\x1b[>4;2m\x1b[?62;22c");
        writer
            .write_all(&answer)
            .expect("answers the queries and types in the middle of the exchange");
        writer.flush().expect("and the answer reaches the command");
    })
}

/// Answers the keyboard queries and the mode reports, as a terminal with a state of its own would.
///
/// The three modes whose answer here is the opposite of the documented default are the point:
/// mouse click reporting on, the cursor hidden and bracketed paste on. What the restoration writes
/// afterwards then says which of the two it put back, this terminal's own state or a terminal
/// nobody had touched.
fn answer_keyboard_and_mode_queries(
    output: &TerminalOutput,
    mut writer: Box<dyn std::io::Write + Send>,
) {
    let output = output.clone();
    std::thread::spawn(move || {
        if !output.wait_for(b"\x1b[c", Duration::from_secs(20)) {
            return;
        }
        // DECRPM: one is set, two is reset.
        let _ = writer.write_all(
            b"\x1b[?5u\x1b[>4;2m\x1b[?25;2$y\x1b[?1000;1$y\x1b[?1002;2$y\x1b[?1003;2$y\x1b[?1006;2$y\x1b[?2004;1$y\x1b[?62;22c",
        );
        let _ = writer.flush();
    });
}

/// What the terminal above reported, and therefore what it is owed back.
const REPORTED_MODES: &[(&str, bool)] = &[
    ("?25", false),
    ("?1000", true),
    ("?1002", false),
    ("?1003", false),
    ("?1006", false),
    ("?2004", true),
];

/// The sequences that put this test's terminal back into the state it reported.
const KEYBOARD_RESTORED: &[u8] = b"\x1b[=5;1u";

/// The `modifyOtherKeys` level this test's terminal reported, as the restoration writes it.
///
/// The restoration writes this straight after [`KEYBOARD_RESTORED`], but a terminal delivers what
/// it is given in whatever reads it likes, so this is waited for in its own right rather than
/// checked once the sequence before it has arrived.
const MODIFY_OTHER_KEYS_RESTORED: &[u8] = b"\x1b[>4;2m";

/// The mode state a stream of bytes leaves a terminal in: the last value each mode was given.
///
/// Keyed by the parameter as it was written, so a DEC private mode keeps its `?`. Only the
/// single-parameter forms are read, which is the only form anything here writes.
fn final_modes(stream: &[u8]) -> std::collections::BTreeMap<String, bool> {
    let mut modes = std::collections::BTreeMap::new();
    let mut index = 0;
    while index + 2 < stream.len() {
        if &stream[index..index + 2] != b"\x1b[" {
            index += 1;
            continue;
        }
        let mut at = index + 2;
        let mut key = String::new();
        if stream.get(at) == Some(&b'?') {
            key.push('?');
            at += 1;
        }
        while let Some(byte) = stream.get(at).copied() {
            if byte.is_ascii_digit() {
                key.push(char::from(byte));
                at += 1;
            } else {
                break;
            }
        }
        match stream.get(at) {
            Some(b'h') if !key.is_empty() && key != "?" => {
                modes.insert(key, true);
            }
            Some(b'l') if !key.is_empty() && key != "?" => {
                modes.insert(key, false);
            }
            _ => {}
        }
        index += 2;
    }
    modes
}

/// The mouse tracking a stream leaves a terminal in, as a terminal actually keeps it.
///
/// Not three switches: one state. `CSI ? 1000 h`, `CSI ? 1002 h` and `CSI ? 1003 h` each *replace*
/// whichever tracking was in force, and resetting any of the three turns tracking off whichever of
/// them had turned it on. A restoration that wrote a terminal's own `1000 h` and then the `1002 l`
/// of a mode that was never on would leave it with no mouse reporting at all, and a check that read
/// the three as independent booleans would not notice.
fn mouse_tracking(stream: &[u8]) -> Option<u16> {
    let mut tracking = None;
    let mut index = 0;
    while index + 3 < stream.len() {
        if &stream[index..index + 3] != b"\x1b[?" {
            index += 1;
            continue;
        }
        let mut at = index + 3;
        let mut number = String::new();
        while let Some(byte) = stream.get(at).copied() {
            if byte.is_ascii_digit() {
                number.push(char::from(byte));
                at += 1;
            } else {
                break;
            }
        }
        let Ok(mode) = number.parse::<u16>() else {
            index += 3;
            continue;
        };
        if matches!(mode, 1000 | 1002 | 1003) {
            match stream.get(at) {
                Some(b'h') => tracking = Some(mode),
                Some(b'l') => tracking = None,
                _ => {}
            }
        }
        index += 3;
    }
    tracking
}

/// The last position a sequence appears at in a stream.
fn last_index(stream: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || stream.len() < needle.len() {
        return None;
    }
    (0..=stream.len() - needle.len()).rev().find(|start| {
        stream
            .get(*start..*start + needle.len())
            .is_some_and(|window| window == needle)
    })
}

/// Asserts a terminal was left in its own state rather than in the session's.
///
/// Termios describes the driver. It says nothing about the alternate screen, mouse reporting,
/// bracketed paste, the coordinate system or the cursor, and a person left in any of those has a
/// terminal that behaves like somebody else's: a mouse that prints escape sequences when they
/// select text, or a screen that types over itself. This reads the modes out of what the terminal
/// actually received, checks the state they add up to, and checks the order: the alternate screen
/// is left first, so everything after it lands in the buffer the person is left looking at, and the
/// keyboard protocols the terminal reported are put back last of all.
fn assert_the_terminal_was_left_its_own(stream: &[u8]) {
    let modes = final_modes(stream);
    for (mode, expected, what) in [
        ("?1049", false, "the alternate screen"),
        ("?1000", false, "mouse reporting"),
        ("?1002", false, "button-event mouse reporting"),
        ("?1003", false, "any-event mouse reporting"),
        ("?1004", false, "focus reporting"),
        ("?1006", false, "SGR mouse encoding"),
        ("?1007", false, "alternate scroll"),
        ("?2004", false, "bracketed paste"),
        ("?2026", false, "synchronised output"),
        ("?69", false, "left and right margins"),
        ("?6", false, "origin mode"),
        ("4", false, "insert mode"),
        ("?1", false, "application cursor keys"),
        ("?7", true, "autowrap"),
        ("?25", true, "the cursor"),
    ] {
        assert_eq!(
            modes.get(mode).copied(),
            Some(expected),
            "{what} was left as the terminal's own, not the session's: {:?}",
            modes
        );
    }
    let reset = last_index(stream, kr_cli::terminal::RESET_SEQUENCES)
        .unwrap_or_else(|| panic!("the restoration wrote the whole reset block"));
    assert!(
        kr_cli::terminal::RESET_SEQUENCES.starts_with(b"\x1b[?1049l"),
        "and it begins by leaving the alternate screen"
    );
    if let Some(keyboard) = last_index(stream, KEYBOARD_RESTORED) {
        assert!(
            keyboard > reset,
            "the keyboard state the terminal reported is put back after the modes are cleared"
        );
    }
}

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

/// KR-REQ-08.84: the outer terminal's input, mouse, cursor visibility and keyboard modes come
/// back after the attach process is killed outright, because the guard is holding them.
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
                kr().display()
            ),
        ))
        .expect("starts the shell");
    let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
    let queries = answer_keyboard_queries(&output, pty.master.take_writer().expect("a writer"));
    output.expect_within(
        b"ready",
        LIVENESS_DEADLINE,
        "the session's output reached the terminal",
    );
    answered(queries);

    // Raw mode is on: the terminal no longer waits for a line and no longer echoes.
    let during = rustix::termios::tcgetattr(terminal_fd(&pty)).expect("reads the terminal's modes");
    assert!(
        !during
            .local_modes
            .contains(rustix::termios::LocalModes::ICANON),
        "the attachment put the terminal into raw mode"
    );

    let attach = attach_process(shell.process_id().expect("the shell has an identifier"));
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

    let after = canonical_again(
        &pty,
        "the guard put the terminal back after the attach process was killed",
    );
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
    output.expect_within(
        KEYBOARD_RESTORED,
        LIVENESS_DEADLINE,
        "the guard put the terminal's own keyboard protocol back",
    );
    output.expect_within(
        MODIFY_OTHER_KEYS_RESTORED,
        LIVENESS_DEADLINE,
        "and its modifyOtherKeys level",
    );
    // And everything else the emulator holds and termios does not describe.
    assert_the_terminal_was_left_its_own(&output.bytes());
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

/// KR-REQ-08.84: a terminal that reports its own modes is put back into them, guard included.
///
/// Section 8 asks a detach to restore "the outer terminal's input modes, mouse modes, cursor
/// visibility". Termios carries the first; the other two are read from the terminal before anything
/// changes them, carried to the guard, and written back over the documented defaults. The attach
/// process is killed outright here, so the only thing that can put them back is the guard.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_terminal_that_reported_its_modes_is_put_back_into_them_after_a_kill() {
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
                "{} attach {display}; printf 'attach-finished-%s\\n' \"$?\"",
                kr().display()
            ),
        ))
        .expect("starts the shell");
    let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
    answer_keyboard_and_mode_queries(&output, pty.master.take_writer().expect("a writer"));
    assert!(
        output.wait_for(b"ready", Duration::from_secs(30)),
        "the session's output reached the terminal: {}",
        output.text()
    );

    let attach = attach_process(shell.process_id().expect("the shell has an identifier"))
        .expect("the shell started the attach command");
    assert_eq!(
        guards_of(attach),
        1,
        "the attachment armed a restoration guard"
    );
    let killed = std::process::Command::new("kill")
        .args(["-KILL", &attach.to_string()])
        .status()
        .expect("sends the signal");
    assert!(killed.success(), "the attach process was killed");

    // The guard writes the reset block and then this terminal's own values over it. Waiting for the
    // cursor's own value is waiting for the whole of that, because it is written in one go.
    assert!(
        output.wait_for(b"\x1b[?25l", Duration::from_secs(20)),
        "the guard hid the cursor again, because that is how it found it: {}",
        output.text().escape_debug()
    );
    let modes = final_modes(&output.bytes());
    for (mode, expected) in REPORTED_MODES {
        assert_eq!(
            modes.get(*mode).copied(),
            Some(*expected),
            "mode {mode} was put back to what this terminal reported rather than to the \
             documented default: {modes:?}"
        );
    }
    // And the mouse as a terminal actually keeps it: one tracking state rather than three
    // switches. This terminal reported click reporting on, so that is what it is owed, and a
    // restoration that wrote the reset of a mode it never had after that set would have left it
    // with nothing.
    assert_eq!(
        mouse_tracking(&output.bytes()),
        Some(1000),
        "the terminal's own mouse reporting is what it ends with: {}",
        output.text().escape_debug()
    );
    // The reset block still ran: a mode the terminal said nothing about is still cleared, and the
    // ones it did answer for are written after it rather than instead of it.
    let reset = last_index(&output.bytes(), kr_cli::terminal::RESET_SEQUENCES)
        .expect("the guard wrote the whole reset block");
    let restored = last_index(&output.bytes(), b"\x1b[?1000h")
        .expect("and the terminal's own mouse reporting after it");
    assert!(
        restored > reset,
        "the values the terminal reported are written over the defaults, not before them"
    );
    let _ = shell.kill();
    let _ = shell.wait();
}

/// KR-REQ-08.84: an attach that fails after the handshake still leaves the terminal its own modes.
///
/// The guard writes the reset block on every path out, and that block is the documented default for
/// every one of these modes. So the values the terminal reported reach the guard as soon as they are
/// read, before anything else can fail: a worker that cannot be reached must not cost a person the
/// mouse reporting they had, which nothing in the failed attempt ever touched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attach_that_fails_after_the_handshake_leaves_the_terminal_the_modes_it_reported() {
    let hosted = hosted("while true; do echo ready; sleep 1; done").await;
    // A second session, published and never served: its endpoint has no listener, so the command
    // resolves it, asks the terminal what it is, and then fails to reach the worker.
    let unreachable = DisplayNumber::new(2);
    let descriptor = WorkerDescriptor {
        session_id: SessionId::new(kr_ipc::new_uuid()),
        display_number: unreachable,
        endpoint: hosted
            .temp
            .environment()
            .worker_endpoint(unreachable)
            .expect("an endpoint")
            .as_text(),
        ..hosted.descriptor.clone()
    };
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
    let display = unreachable.get().to_string();
    let mut shell = pty
        .slave
        .spawn_command(shell_running(
            &hosted,
            &format!(
                "{} attach {display}; printf 'attach-finished-%s\\n' \"$?\"",
                kr().display()
            ),
        ))
        .expect("starts the shell");
    let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
    answer_keyboard_and_mode_queries(&output, pty.master.take_writer().expect("a writer"));

    assert!(
        output.wait_for(b"attach-finished-", Duration::from_secs(60)),
        "the attach ended: {}",
        output.text().escape_debug()
    );
    assert!(
        !output.contains(b"attach-finished-0"),
        "and it failed, because nothing is listening on that endpoint: {}",
        output.text().escape_debug()
    );
    // The handshake did happen: this terminal was asked, and it answered.
    assert!(
        output.contains(b"\x1b[?1000$p"),
        "the terminal was asked what its mouse reporting was: {}",
        output.text().escape_debug()
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && mouse_tracking(&output.bytes()) != Some(1000) {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        mouse_tracking(&output.bytes()),
        Some(1000),
        "the mouse reporting this terminal had is what it is left with: {}",
        output.text().escape_debug()
    );
    let modes = final_modes(&output.bytes());
    assert_eq!(
        modes.get("?25").copied(),
        Some(false),
        "and the cursor it had hidden is still hidden: {modes:?}"
    );
    let _ = shell.kill();
    let _ = shell.wait();
}

/// KR-REQ-08.84: the same modes come back on an ordinary detach, which is the path that runs in
/// this process rather than in the guard.
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
                kr().display()
            ),
        ))
        .expect("starts the shell");
    let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
    let queries = answer_keyboard_queries(&output, pty.master.take_writer().expect("a writer"));
    output.expect_within(
        b"ready",
        LIVENESS_DEADLINE,
        "the session's output reached the terminal",
    );
    answered(queries);

    // A second command, in another window, ends this attachment. It names no attachment, so the
    // session is asked which one it has.
    let session = hosted.session_id.to_string();
    let detach = std::process::Command::new(kr())
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
    output.expect_within(
        b"attach-finished-0",
        LIVENESS_DEADLINE,
        "the attachment ended, and an ordinary detach is not a failure",
    );
    let after = rustix::termios::tcgetattr(terminal_fd(&pty)).expect("reads the terminal's modes");
    assert_eq!(
        after.local_modes.bits(),
        before.local_modes.bits(),
        "the terminal came back when the attachment ended"
    );
    output.expect_within(
        KEYBOARD_RESTORED,
        LIVENESS_DEADLINE,
        "and so did the keyboard protocol it had negotiated for itself",
    );
    output.expect_within(
        MODIFY_OTHER_KEYS_RESTORED,
        LIVENESS_DEADLINE,
        "and its modifyOtherKeys level",
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
    // And everything else the emulator holds and termios does not describe.
    assert_the_terminal_was_left_its_own(&output.bytes());
    // This terminal answered the keyboard queries and no mode report at all, so the mouse modes,
    // the cursor and bracketed paste went back to their documented defaults rather than to values
    // anybody read. That is a smaller promise than a terminal that answers gets, and the attachment
    // says which promise it made rather than leaving it to be assumed.
    assert!(
        output.wait_for(
            b"put back to the documented default",
            Duration::from_secs(10)
        ),
        "the attachment reported the modes it had to default: {}",
        output.text().escape_debug()
    );
    for mode in ["25", "1000", "1002", "1003", "1006", "2004"] {
        assert!(
            output.contains(format!("mode {mode}").as_bytes()),
            "and named {mode} among them: {}",
            output.text().escape_debug()
        );
    }
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
    // The application empties the stack when this test says so, not when it starts. On its own
    // clock it could do it before there was an attachment at all, and then a terminal that saw no
    // stack operation would prove nothing: there would have been none to see.
    let gates = gates();
    let hosted = hosted(&format!(
        "printf 'kr-up.\\n'; {}; printf '\\033[<65535u'; printf 'kr-popped.\\n'; \
         while true; do echo ready; sleep 1; done",
        waits_for(&gates, "pop")
    ))
    .await;
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
                kr().display()
            ),
        ))
        .expect("starts the shell");
    let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
    let queries = answer_keyboard_queries(&output, pty.master.take_writer().expect("a writer"));
    output.expect_within(
        b"kr-up.",
        LIVENESS_DEADLINE,
        "the session's output reached the terminal",
    );
    answered(queries);

    // Now, with the attachment live and forwarding, the application empties the stack. The marker
    // after it is what says the sequence was written while there was an attachment to carry it.
    open_gate(&gates, "pop");
    output.expect_within(
        b"kr-popped.",
        LIVENESS_DEADLINE,
        "the application emptied the keyboard stack while this terminal was attached",
    );

    let session = hosted.session_id.to_string();
    let detach = std::process::Command::new(kr())
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
    output.expect_within(
        b"attach-finished-0",
        LIVENESS_DEADLINE,
        "the attachment ended",
    );
    output.expect_within(
        KEYBOARD_RESTORED,
        LIVENESS_DEADLINE,
        "the terminal's own keyboard protocol was put back",
    );
    output.expect_within(
        MODIFY_OTHER_KEYS_RESTORED,
        LIVENESS_DEADLINE,
        "and its modifyOtherKeys level",
    );

    // Not one stack operation reached this terminal, the application's own included. The entry an
    // outer program had pushed before `kr` ran is still on the stack and its own pop will find it,
    // and that is true of the application's `CSI < 65535 u` as much as of anything this attachment
    // might have written: it emptied the session's stack, not this terminal's. A terminal that had
    // been sent it would have lost entries that no restoration of the current flags could bring
    // back, so counting it as "the application's own" would be counting a fault as a pass.
    assert_eq!(
        stack_operations(output.text().as_bytes()),
        0,
        "no stack operation of any kind reached this terminal: {}",
        output.text().escape_debug()
    );
    assert_eq!(
        output.count(b"\x1b[<65535u"),
        0,
        "the application's own emptying of the stack stopped at the session: {}",
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
                kr().display()
            ),
        ))
        .expect("starts the shell");
    let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
    // Nothing answers. The handshake's own deadline ends it.
    output.expect_within(
        b"attach-finished-6",
        LIVENESS_DEADLINE,
        "the attach failed with the terminal's own exit code rather than forwarding input",
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

/// KR-REQ-08.43: what a person typed while the host was asking is theirs, and it is the first
/// input the attachment forwards.
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
                kr().display()
            ),
        ))
        .expect("starts the shell");
    let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
    let queries = answer_and_type(
        &output,
        pty.master.take_writer().expect("a writer"),
        b"kr-typed-early\n",
    );
    // The session is what is asked, because the outer terminal would show these bytes back whether
    // they were forwarded or not: a handshake that failed restores echo, and echo alone would
    // satisfy a terminal-side assertion while the application had never been given anything.
    session_retained(&hosted, b"kr-typed-early", LIVENESS_DEADLINE).await;
    output.expect_within(
        b"kr-typed-early",
        LIVENESS_DEADLINE,
        "the bytes typed during the handshake reached the application and came back",
    );
    answered(queries);
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
                kr().display(),
                unreachable.get()
            ),
        ))
        .expect("starts the shell");
    let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
    let queries = answer_keyboard_queries(&output, pty.master.take_writer().expect("a writer"));

    // The code, not merely "not zero": 3 is a host this command could not reach, and 6 is a
    // terminal that never answered. Accepting any failure would let a handshake that timed out
    // satisfy every assertion below, which is the opposite of what this test is about. The whole
    // marker is waited for rather than checked after a wait for its prefix, because a terminal
    // delivers what it is given in whatever reads it likes and the digit can arrive by itself.
    output.expect_within(
        b"attach-finished-3",
        LIVENESS_DEADLINE,
        "the attach ended because nothing was listening rather than because the handshake failed",
    );
    answered(queries);
    assert!(
        output.contains(b"\x1b[c"),
        "the handshake did happen, so this terminal was asked what it was: {}",
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
                kr().display()
            ),
        ))
        .expect("starts the shell");
    let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
    output.expect_within(
        b"ready",
        LIVENESS_DEADLINE,
        "the session's output reached the terminal",
    );
    // Section 8: the host checks that a controller can supply the encoding the application reads,
    // and a terminal nobody was allowed to ask about cannot be shown to. The attachment is not
    // refused - it watches - and the person is told which of the two they have.
    output.expect_within(
        b"will not let it type",
        LIVENESS_DEADLINE,
        "the person is told that this attachment watches rather than types",
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

    let attach = attach_process(shell.process_id().expect("the shell has an identifier"));
    let killed = std::process::Command::new("kill")
        .args(["-KILL", &attach.to_string()])
        .status()
        .expect("sends the signal");
    assert!(killed.success(), "the attach process was killed");

    // The guard puts the modes back, which is how this test knows the cleanup ran at all.
    canonical_again(
        &pty,
        "the guard put the terminal back after the watching attachment was killed",
    );

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

/// KR-REQ-08.85: a nested attach is an ordinary foreground application to the outer session.
///
/// A terminal is attached to one session, and inside it a second `kr attach` runs against another.
/// Three things follow from the outer worker treating the inner command as an ordinary application,
/// and each is checked here: the inner attachment is established at all, what the person types
/// reaches the *inner* session's application rather than the outer one's, and the end-of-file byte
/// is among what it reaches, so no outer root-only interception is in the way of it.
///
/// SSH loopback is the other half of this row and is not run here: this Mac has Remote Login
/// listening, and public-key authentication for this account is not set up, so an unattended run
/// cannot authenticate and this task does not change the operator's account to make it. The command
/// the matrix run uses is recorded in the handoff.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_nested_attach_is_an_ordinary_application_to_the_outer_session() {
    // The outer session runs a shell that stays as the session leader; the inner one echoes what
    // it reads, so what the person typed is visible from outside the process.
    let outer = hosted("stty raw -echo; printf 'kr-outer.'; exec /bin/sh").await;
    // The inner application turns bracketed paste on, so a paste through both sessions is a real
    // paste rather than a person typing marker bytes.
    let (inner_display, inner) = second_session(
        &outer,
        "stty raw -echo; printf 'kr-inner.'; printf '\\033[?2004h'; exec cat",
    )
    .await;

    let pty = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("opens a terminal");
    let display = outer.display.get().to_string();
    let mut shell = pty
        .slave
        .spawn_command(shell_running(
            &outer,
            &format!(
                "{} attach {display}; printf 'outer-finished-%s\\n' \"$?\"",
                kr().display()
            ),
        ))
        .expect("starts the shell");
    let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
    // A pseudo-terminal hands out its writer once, and two things need it here: the thread that
    // answers the outer command's handshake, and this test typing afterwards.
    let keyboard = Arc::new(std::sync::Mutex::new(
        pty.master.take_writer().expect("a writer"),
    ));
    {
        let output = output.clone();
        let keyboard = Arc::clone(&keyboard);
        std::thread::spawn(move || {
            if !output.wait_for(b"\x1b[c", Duration::from_secs(20)) {
                return;
            }
            if let Ok(mut writer) = keyboard.lock() {
                let _ = writer.write_all(b"\x1b[?5u\x1b[>4;2m\x1b[?62;22c");
                let _ = writer.flush();
            }
        });
    }
    let types = |bytes: &[u8]| {
        let mut writer = keyboard.lock().expect("the writer is not poisoned");
        writer.write_all(bytes).expect("types");
        writer.flush().expect("flushes");
    };
    assert!(
        output.wait_for(b"kr-outer.", Duration::from_secs(30)),
        "the outer session's screen reached the terminal: {}",
        output.text().escape_debug()
    );
    // The outer attachment owns this terminal's driver state. Whatever the inner one does, this is
    // what has to still be true afterwards.
    let outer_raw = rustix::termios::tcgetattr(terminal_fd(&pty)).expect("reads the modes");
    assert!(
        !outer_raw
            .local_modes
            .contains(rustix::termios::LocalModes::ICANON),
        "the outer attachment put the real terminal into raw mode"
    );

    // The inner attach, typed into the outer session's shell. Its own probe asks the outer KR
    // terminal, which answers as the sole responder for that session.
    let inner_command = format!(
        "{} attach {}; printf 'inner-finished-%s\\n' \"$?\"\n",
        kr().display(),
        inner_display.get()
    );
    types(inner_command.as_bytes());
    assert!(
        output.wait_for(b"kr-inner.", Duration::from_secs(40)),
        "the inner session's screen reached the same terminal: {}",
        output.text().escape_debug()
    );

    // Typed with the inner command in the foreground. It reaches the inner session's application,
    // including the end-of-file byte: the outer worker treats the inner command as an ordinary
    // foreground application, so no root-only interception of its own is in the way.
    types(b"kr-nested-typing\x04");
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut seen = Vec::new();
    while Instant::now() < deadline {
        seen = application_saw(&inner);
        if saw(&seen, b"kr-nested-typing") && seen.contains(&0x04) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        saw(&seen, b"kr-nested-typing"),
        "what the person typed reached the inner session's application: {}",
        String::from_utf8_lossy(&seen).escape_debug()
    );
    assert!(
        seen.contains(&0x04),
        "and so did the end-of-file byte, which nothing outer intercepted: {}",
        String::from_utf8_lossy(&seen).escape_debug()
    );
    // The outer session's own shell did not receive it. Its output carries the typed word only
    // because the inner command *drew* it there, which is what a foreground application does with
    // the terminal it is holding; what it must not carry is the outer shell reacting to it as a
    // line of its own, and it must not have ended on the end-of-file byte.
    let outer_saw = application_saw(&outer.runtime);
    assert!(
        !saw(&outer_saw, b"kr-nested-typing: "),
        "the outer session's shell did not read the typed line as a command of its own: {}",
        String::from_utf8_lossy(&outer_saw).escape_debug()
    );
    assert!(
        !saw(&outer_saw, b"not found"),
        "and reported nothing about it: {}",
        String::from_utf8_lossy(&outer_saw).escape_debug()
    );
    assert!(
        !output.contains(b"outer-finished-"),
        "the outer attachment is still running, so nothing outer took the end-of-file byte: {}",
        output.text().escape_debug()
    );
    // Nothing the inner command asked the outer terminal reached the inner application. The
    // replies to its handshake arrive on the same stream as the person's typing and are separated
    // from it: an application that was sent a device report would echo one here, because it echoes
    // everything it reads.
    for reply in [&b"\x1b[?62;22c"[..], &b"\x1b[?5u"[..]] {
        assert!(
            !saw(&seen, reply),
            "no reply to the handshake was forwarded as input: {:?} in {}",
            String::from_utf8_lossy(reply),
            String::from_utf8_lossy(&seen).escape_debug()
        );
    }

    // A paste, through both sessions. The inner application enabled bracketed paste, so each
    // session in the chain has it on and the paste has to arrive framed, whole and once: a marker
    // delivered twice is a paste the application reads as two, and a marker stripped on the way is
    // a paste it cannot tell from typing.
    types(b"\x1b[200~kr-pasted\x1b[201~");
    let framed = &b"\x1b[200~kr-pasted\x1b[201~"[..];
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut pasted = Vec::new();
    while Instant::now() < deadline {
        pasted = application_saw(&inner);
        if saw(&pasted, framed) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        saw(&pasted, framed),
        "the paste reached the inner session's application, framed: {}",
        String::from_utf8_lossy(&pasted).escape_debug()
    );
    let opened = pasted
        .windows(6)
        .filter(|window| *window == b"\x1b[200~")
        .count();
    assert_eq!(
        opened,
        1,
        "once, however many sessions it passed through: {}",
        String::from_utf8_lossy(&pasted).escape_debug()
    );

    // How the inner attachment is being served, said rather than assumed. It claimed the geometry
    // of the terminal it was handed, which is the outer session's own terminal, so the two agree
    // about size and it is forwarded the stream. A projection is what an attachment of another
    // size is served, and that is the same rule inside a nesting as outside it.
    let presentation = inner
        .session()
        .attachments()
        .into_iter()
        .find_map(|summary| summary.presentation.as_ref().copied());
    assert_eq!(
        presentation,
        Some(kr_protocol::attachment::TerminalPresentationMode::Direct),
        "the inner attachment is forwarded the stream, because it claimed the geometry"
    );

    // An orderly inner detach, from outside. The inner command ends, its status says a detach is
    // not a failure, and the outer attachment is untouched by the cleanup of an attachment that
    // was never holding this terminal.
    let detach = std::process::Command::new(kr())
        .args(["detach", &inner_display.get().to_string()])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env(
            "KR_RUNTIME_DIR",
            outer.temp.paths().runtime_root().display().to_string(),
        )
        .env(
            "KR_STATE_DIR",
            outer.temp.paths().state_root().display().to_string(),
        )
        .output()
        .expect("runs the detach");
    assert!(
        detach.status.success(),
        "the detach succeeded: {}",
        String::from_utf8_lossy(&detach.stderr)
    );
    assert!(
        output.wait_for(b"inner-finished-0", Duration::from_secs(30)),
        "the inner command ended, and an ordinary detach is not a failure: {}",
        output.text().escape_debug()
    );
    assert!(
        !output.contains(b"outer-finished-"),
        "while the outer attachment carried on: {}",
        output.text().escape_debug()
    );
    let after_inner = rustix::termios::tcgetattr(terminal_fd(&pty)).expect("reads the modes");
    assert_eq!(
        after_inner.local_modes.bits(),
        outer_raw.local_modes.bits(),
        "and the real terminal is still in the state its own attachment put it in: the inner \
         cleanup restored the terminal it was given, which is the outer session's"
    );

    // And the keys go back to the outer session's shell, which is what was in the foreground
    // before the inner command took it.
    types(b"printf 'kr-back.'\n");
    assert!(
        output.wait_for(b"kr-back.", Duration::from_secs(30)),
        "the outer session's shell is reading again: {}",
        output.text().escape_debug()
    );
    let _ = shell.kill();
    let _ = shell.wait();
}
