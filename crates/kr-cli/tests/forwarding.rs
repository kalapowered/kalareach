//! What the command does to the bytes a person types, which is nothing.
//!
//! Section 8 is a list of things the local command must **not** do: decode ordinary output into
//! text and encode it again, normalise Unicode, change line endings, install a permanent status
//! bar, redraw on every output batch, or translate a wheel event into an arrow key. None of those
//! can be checked by reading the source and none can be checked without a real terminal, so these
//! tests run `kr` on a pseudo-terminal against a session whose root program echoes whatever it
//! reads. What comes back is what the application received.
//!
//! The root program puts the terminal into raw mode with the echo off first, so the echo is the
//! application's and not the line discipline's.

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

mod support;

use support::{command_binaries, kr};

/// A root program that echoes its input and nothing else.
const ECHOES_ITS_INPUT: &str = "stty raw -echo; printf 'kr-ready.'; exec cat";

/// A session this test hosts, with its descriptor published where `kr` will find it.
struct Hosted {
    temp: kr_ipc::testing::TempHost,
    display: DisplayNumber,
    runtime: Arc<SessionRuntime>,
    _service: Arc<WorkerService>,
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
    let store =
        kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
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
        worker_endpoint: None,
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 1024 * 1024,
        launch_profile: kr_protocol::session::LaunchProfile::default(),
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
        display,
        runtime,
        _service: service,
    }
}

/// Runs a shell on the terminal, with `kr` inside it.
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

/// Everything the terminal has produced, collected off the test's own thread.
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

    fn snapshot(&self) -> Vec<u8> {
        self.seen
            .lock()
            .map(|seen| seen.clone())
            .unwrap_or_default()
    }

    /// Waits for the marker to appear, or for the deadline to pass.
    ///
    /// Two milliseconds, because one of the things that waits here is the thread that answers the
    /// command's handshake, and that handshake has one second in total. A real terminal answers in
    /// microseconds; a test that noticed the question fifty milliseconds later would be spending
    /// the command's own bound on its own polling, and on a busy machine it would spend all of it.
    fn wait_for(&self, marker: &[u8], within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if contains(&self.snapshot(), marker) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        contains(&self.snapshot(), marker)
    }

    /// Waits for the marker, and fails with how long it waited when it never arrives.
    ///
    /// `what` says what the marker means to the caller, so a failure names both the wait and the
    /// thing waited for.
    fn expect_within(&self, marker: &[u8], within: Duration, what: &str) {
        let started = Instant::now();
        let deadline = started + within;
        loop {
            if contains(&self.snapshot(), marker) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{what}: waited {:?} for {:?} in the terminal's output: {}",
                started.elapsed(),
                String::from_utf8_lossy(marker),
                self.text().escape_debug()
            );
            // Two milliseconds, because one of the things that waits here is the thread that
            // answers the command's handshake, and that handshake has one second in total. A real
            // terminal answers in microseconds; a test that noticed the question twenty-five
            // milliseconds later would be spending the command's own bound on its own polling.
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.snapshot()).into_owned()
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

/// The one writer the terminal has, shared between the test and the thread that answers the probe.
///
/// A pseudo-terminal hands out its writer once, and two things need it: whatever answers the
/// command's capability handshake, and the test typing afterwards.
#[derive(Clone)]
struct Keyboard {
    writer: Arc<std::sync::Mutex<Box<dyn Write + Send>>>,
}

impl Keyboard {
    fn new(writer: Box<dyn Write + Send>) -> Self {
        Self {
            writer: Arc::new(std::sync::Mutex::new(writer)),
        }
    }

    fn types(&self, bytes: &[u8]) {
        let mut writer = self.writer.lock().expect("the writer is not poisoned");
        writer.write_all(bytes).expect("types");
        writer.flush().expect("flushes");
    }

    /// Answers the keyboard queries the way a terminal with both protocols would.
    ///
    /// The command asks the outer terminal what it has negotiated before it changes anything.
    /// Without an answer the bounded handshake fails and there is no attachment to test.
    fn answers_the_probe(&self, output: &TerminalOutput) -> std::thread::JoinHandle<()> {
        let output = output.clone();
        let keyboard = self.clone();
        std::thread::spawn(move || {
            // The device-attributes request is the question every profile asks, and the last of
            // them, so it is what this waits for: a terminal calling itself `xterm-256color` is
            // asked no keyboard question at all. The keyboard answers are volunteered, and a reply
            // a terminal gives unbidden is still the truth about itself, which is what a cleanup
            // puts back.
            output.expect_within(
                b"\x1b[c",
                LIVENESS_DEADLINE,
                "the command asked this terminal what it is",
            );
            keyboard.types(b"\x1b[?5u\x1b[>4;2m\x1b[?62;22c");
        })
    }
}

/// Waits for the thread that answers this terminal's queries, and gives the test what it found.
///
/// Without an answer the bounded handshake fails and there is no attachment to test, so the query
/// is a required wait. A thread whose panic nobody joins would leave that as a timeout somewhere
/// else, so the failure is brought back here with its own message.
fn answered(probe: std::thread::JoinHandle<()>) {
    if let Err(panic) = probe.join() {
        let detail = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap_or("the thread answering this terminal's queries failed");
        panic!("{detail}");
    }
}

/// Reads everything the session has retained, which is what the application produced.
fn retained(runtime: &SessionRuntime) -> Vec<u8> {
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

/// How long a wait for something to appear is given.
///
/// A liveness wait is not a measurement: it is there to fail when something never happens. The ten,
/// twenty and thirty second windows these waits had were inside the range the slowest reference
/// hosts reach when several suites share them, which turned each of them into a coin toss; two
/// minutes is outside it. The poll intervals are unchanged, so a wait that succeeds costs what it
/// always did. The short windows that assert something *never* appears are deliberately left as
/// they are: they are not waiting for anything.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// Waits for `marker` to appear in the session's retained output.
///
/// A marker that never appears is a failure here rather than partial output a caller has to make
/// sense of, and the failure says how long it waited and what for.
fn retained_within(runtime: &SessionRuntime, marker: &[u8], within: Duration) -> Vec<u8> {
    let started = Instant::now();
    let deadline = started + within;
    loop {
        let seen = retained(runtime);
        if contains(&seen, marker) {
            return seen;
        }
        assert!(
            Instant::now() < deadline,
            "waited {:?} for {:?} in the session's retained output: {:?}",
            started.elapsed(),
            String::from_utf8_lossy(marker),
            String::from_utf8_lossy(&seen)
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The sequences a person's keyboard, mouse and clipboard actually produce.
///
/// Each one is here because a decoder, an encoder or a normaliser in the path would change it, and
/// the change would be invisible until an application misread a key.
struct Sequence {
    what: &'static str,
    bytes: &'static [u8],
}

const SEQUENCES: &[Sequence] = &[
    // Each line ending is framed, because a rewriter turns one into two and a bare scan of the
    // stream could not tell the inserted byte from the next sequence typed.
    Sequence {
        what: "a carriage return on its own, which a line-ending rewriter would change",
        bytes: b"kr-cr\rZ",
    },
    Sequence {
        what: "a line feed on its own",
        bytes: b"kr-lf\nZ",
    },
    Sequence {
        what: "an ordinary cursor key",
        bytes: b"\x1b[A",
    },
    Sequence {
        what: "an application cursor key, which is a different sequence for the same key",
        bytes: b"\x1bOA",
    },
    Sequence {
        what: "a modified cursor key",
        bytes: b"\x1b[1;5A",
    },
    Sequence {
        what: "a modifyOtherKeys report",
        bytes: b"\x1b[27;5;13~",
    },
    Sequence {
        what: "a Kitty key event with its modifiers",
        bytes: b"\x1b[97;5u",
    },
    Sequence {
        what: "a Kitty key release, which a legacy stream cannot express",
        bytes: b"\x1b[97;5:3u",
    },
    Sequence {
        what: "a bracketed paste, delimiters and all",
        bytes: b"\x1b[200~pasted\x1b[201~",
    },
    Sequence {
        what: "a combining sequence a Unicode normaliser would compose",
        bytes: b"e\xcc\x81",
    },
    Sequence {
        what: "a byte that is not valid UTF-8 at all",
        bytes: b"\xff\xfe",
    },
    Sequence {
        what: "the first half of a multi-byte scalar, arriving on its own",
        bytes: b"\xc3",
    },
    Sequence {
        what: "and its second half, arriving later",
        bytes: b"\xa9",
    },
];

/// KR-REQ-08.57: raw mode is forwarded unchanged, with nothing decoded, normalised or drawn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_input_reaches_the_application_byte_for_byte() {
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
                "{} attach {display}; printf 'attach-finished-%s\\n' \"$?\"",
                kr().display()
            ),
        ))
        .expect("starts the shell");
    let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
    let keyboard = Keyboard::new(pty.master.take_writer().expect("a writer"));
    let probe = keyboard.answers_the_probe(&output);
    output.expect_within(
        b"kr-ready.",
        LIVENESS_DEADLINE,
        "the session's screen reached the terminal",
    );
    answered(probe);
    let mut previous = 0_usize;
    for sequence in SEQUENCES {
        keyboard.types(sequence.bytes);
        // One sequence at a time, so an assertion that fails names the sequence that failed rather
        // than a batch, and so the order they arrived in is the order they were typed in.
        let before = retained(&hosted.runtime).len();
        let seen = retained_within(&hosted.runtime, sequence.bytes, LIVENESS_DEADLINE);
        assert!(
            contains(&seen, sequence.bytes),
            "{} reached the application unchanged: {:?}",
            sequence.what,
            String::from_utf8_lossy(&seen[before.min(seen.len())..]).escape_debug()
        );
        // And it arrived after the one before it. A path that reordered or coalesced batches would
        // put one of these in front of its predecessor.
        let at = seen
            .windows(sequence.bytes.len())
            .rposition(|window| window == sequence.bytes)
            .expect("the sequence is in the stream");
        assert!(
            at >= previous,
            "{} arrived out of order: at {at}, after one at {previous}",
            sequence.what
        );
        previous = at;
    }
    // Each framed marker arrived exactly once. A path that retried a batch, or that split one and
    // sent both halves, would have doubled one of them.
    let seen = retained(&hosted.runtime);
    for marker in [&b"kr-cr\rZ"[..], &b"kr-lf\nZ"[..]] {
        assert_eq!(
            count(&seen, marker),
            1,
            "{} arrived more than once",
            String::from_utf8_lossy(marker).escape_debug()
        );
    }
    // Nothing was substituted for what could not be decoded, which is the failure a text decoder
    // in the path produces.
    let seen = retained(&hosted.runtime);
    assert!(
        !contains(&seen, "\u{fffd}".as_bytes()),
        "nothing was replaced with a substitution character"
    );
    // Composition is caught by the sequences above: a normaliser would have turned `e` and the
    // combining acute into one scalar, and the assertion that the two arrived as they were sent
    // would have failed. Nothing here looks for the composed form, because the two halves of the
    // split scalar in this same battery spell it when they meet in the stream.
    assert!(
        !contains(&seen, b"kr-cr\r\n") && !contains(&seen, b"kr-lf\r\n"),
        "and no line ending was rewritten: {}",
        String::from_utf8_lossy(&seen).escape_debug()
    );
    let _ = shell.kill();
    let _ = shell.wait();
}

/// KR-REQ-08.57: the command draws what the host sends it and nothing of its own.
///
/// No status bar, no reserved row, and no repaint per output batch. The application here writes
/// ordinary output in batches and reads nothing, so what reaches the terminal is the command's
/// own behaviour rather than an echo of what this test typed.
///
/// One screen may be installed while the output flows and no more. Forwarding may only begin at a
/// parser-ground boundary, so an attachment that joined while a read had split a sequence is served
/// the canonical grid until a boundary arrives and is then handed the stream, and that single
/// transition installs a screen. What this forbids is a screen per batch, which is what a command
/// that repainted itself would produce: a batch each.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_command_draws_what_the_host_sends_and_nothing_of_its_own() {
    // Each batch waits for this test rather than for a clock. On a clock, a batch written while
    // the attachment was still being made would be in the first screen the attachment is given,
    // and this test is about what the command draws *while output flows*.
    let gates = gates();
    let hosted = hosted(&format!(
        "printf 'kr-ready.'; {}; printf 'kr-batch-1.'; {}; printf 'kr-batch-2.'; {}; \
         printf 'kr-batch-3.'; sleep 120",
        waits_for(&gates, "one"),
        waits_for(&gates, "two"),
        waits_for(&gates, "three"),
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
    let keyboard = Keyboard::new(pty.master.take_writer().expect("a writer"));
    let probe = keyboard.answers_the_probe(&output);
    output.expect_within(
        b"kr-ready.",
        LIVENESS_DEADLINE,
        "the session's screen reached the terminal",
    );
    answered(probe);
    // Everything the terminal was sent while the attachment was being set up. What matters after
    // this point is what the command draws while output flows.
    let settled = output.snapshot();

    // One at a time, each released only once the one before it has arrived, so all three are
    // certainly in the window below and each is certainly a write of its own.
    for (gate, batch) in [
        ("one", b"kr-batch-1.".as_slice()),
        ("two", b"kr-batch-2.".as_slice()),
        ("three", b"kr-batch-3.".as_slice()),
    ] {
        open_gate(&gates, gate);
        output.expect_within(
            batch,
            LIVENESS_DEADLINE,
            "the batch this test released reached the terminal",
        );
    }
    let after = output.snapshot();
    let during = &after[settled.len().min(after.len())..];
    // The batches arrived as the bytes the application wrote. A command that repainted per batch
    // would have cleared the screen or addressed every row between them, once for each of the
    // three; at most one clear is the transition into forwarding, and it is a transition rather
    // than a repaint because it happens once however many batches follow it.
    let cleared = count(during, b"\x1b[2J");
    assert!(
        cleared <= 1,
        "the screen was cleared {cleared} times while two batches flowed: {}",
        String::from_utf8_lossy(during).escape_debug()
    );
    // And counted directly, because a repaint need not clear the screen: a projected frame can
    // draw row by row with a cursor address and an erase to the end of the line, and its text
    // would satisfy every assertion below. Every such frame opens by establishing the coordinate
    // system it addresses in, which is a sequence nothing else writes, so counting that counts the
    // frames. At most one, which is the transition into forwarding.
    let frames = count(during, b"\x1b[?69l\x1b[r\x1b[4l\x1b[?7l");
    assert!(
        frames <= 1,
        "{frames} projected frames were drawn while two batches flowed: {}",
        String::from_utf8_lossy(during).escape_debug()
    );
    assert!(
        contains(during, b"kr-batch-2.") && contains(during, b"kr-batch-3."),
        "each batch reached the terminal as the bytes the application wrote: {}",
        String::from_utf8_lossy(during).escape_debug()
    );
    assert_eq!(
        count(during, b"\x1b[?1049h"),
        0,
        "and no alternate screen was entered for a status line"
    );
    for region in [
        &b"\x1b[1;23r"[..],
        &b"\x1b[2;24r"[..],
        &b"\x1b[1;22r"[..],
        &b"\x1b[24;24r"[..],
    ] {
        assert!(
            !contains(&after, region),
            "no row was reserved by a scrolling region: {}",
            String::from_utf8_lossy(region).escape_debug()
        );
    }

    let _ = shell.kill();
    let _ = shell.wait();
}

/// KR-REQ-08.58: mouse reports pass through, and a wheel event is never an arrow key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mouse_reports_pass_through_and_a_wheel_event_is_never_an_arrow_key() {
    // The application turns mouse reporting on, which is what makes the outer terminal produce
    // these events at all, and echoes what it receives.
    let hosted =
        hosted("stty raw -echo; printf '\\033[?1000h\\033[?1006hkr-ready.'; exec cat").await;
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
    let keyboard = Keyboard::new(pty.master.take_writer().expect("a writer"));
    let probe = keyboard.answers_the_probe(&output);
    output.expect_within(
        b"kr-ready.",
        LIVENESS_DEADLINE,
        "the session's screen reached the terminal",
    );
    answered(probe);

    // Every mouse encoding an advertised protocol produces: the wheel, a press and release in SGR,
    // and the original X10 report whose coordinate bytes are not valid UTF-8.
    let reports: &[(&str, &[u8])] = &[
        ("a wheel scroll upwards", b"\x1b[<64;10;5M"),
        ("a wheel scroll downwards", b"\x1b[<65;10;5M"),
        ("a button press", b"\x1b[<0;3;4M"),
        ("the release that answers it", b"\x1b[<0;3;4m"),
        ("a drag while held", b"\x1b[<32;7;9M"),
        ("an X10 report", b"\x1b[M\x20\x21\x22"),
        (
            "an X10 report beyond the ASCII range",
            b"\x1b[M\x60\xe0\xe1",
        ),
    ];
    for (what, bytes) in reports {
        keyboard.types(bytes);
        let seen = retained_within(&hosted.runtime, bytes, LIVENESS_DEADLINE);
        assert!(
            contains(&seen, bytes),
            "{what} reached the application as the report it is"
        );
    }

    // And nothing was turned into a key. An arrow key is what a wheel event becomes in a client
    // that translates it, and the application never received one.
    let seen = retained(&hosted.runtime);
    let after_ready = seen
        .windows(b"kr-ready.".len())
        .position(|window| window == b"kr-ready.")
        .map_or(0, |at| at + b"kr-ready.".len());
    let typed = &seen[after_ready..];
    for arrow in [
        &b"\x1b[A"[..],
        &b"\x1b[B"[..],
        &b"\x1bOA"[..],
        &b"\x1bOB"[..],
    ] {
        assert_eq!(
            count(typed, arrow),
            0,
            "a wheel event was translated into {}",
            String::from_utf8_lossy(arrow).escape_debug()
        );
    }

    let _ = shell.kill();
    let _ = shell.wait();
}

/// KR-REQ-08.58: focus events come from the input-lease holder and from nobody else.
///
/// The attachment here holds no lease, because `--no-probe` withholds the declaration the host
/// needs before it will let a terminal type. It still watches the session, and what is typed into
/// it reaches nothing: another view cannot change the application's focus state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_view_without_the_lease_cannot_change_the_applications_focus_state() {
    let hosted = hosted("stty raw -echo; printf '\\033[?1004hkr-ready.'; exec cat").await;
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
                "{} attach --no-probe {display}; printf 'attach-finished-%s\\n' \"$?\"",
                kr().display()
            ),
        ))
        .expect("starts the shell");
    let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
    output.expect_within(
        b"kr-ready.",
        LIVENESS_DEADLINE,
        "it watches the session it may not type into",
    );
    assert!(
        !hosted.runtime.session().lease().holder.is_present(),
        "and it was given no lease"
    );

    // A focus event, a focus-out event and an ordinary keystroke behind them.
    let keyboard = Keyboard::new(pty.master.take_writer().expect("a writer"));
    keyboard.types(b"\x1b[I\x1b[Okr-typed-anyway.");
    std::thread::sleep(Duration::from_secs(2));

    let seen = retained(&hosted.runtime);
    assert!(
        !contains(&seen, b"kr-typed-anyway."),
        "nothing it typed reached the application: {}",
        String::from_utf8_lossy(&seen).escape_debug()
    );
    let after_ready = seen
        .windows(b"kr-ready.".len())
        .position(|window| window == b"kr-ready.")
        .map_or(0, |at| at + b"kr-ready.".len());
    assert_eq!(
        count(&seen[after_ready..], b"\x1b[I"),
        0,
        "and neither did its focus events"
    );
    // The attachment is still running, because watching is what it asked for.
    assert!(
        !output.wait_for(b"attach-finished-", Duration::from_secs(2)),
        "the attachment goes on watching rather than ending on a refusal: {}",
        output.text().escape_debug()
    );

    let _ = shell.kill();
    let _ = shell.wait();
}
