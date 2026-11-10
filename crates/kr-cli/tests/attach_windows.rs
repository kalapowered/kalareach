//! `kr attach` against a real worker's session, in a real console, on Windows.
//!
//! The Unix twin of these cases is `crates/kr-cli/tests/attach.rs`, which runs the command on a
//! pseudo-terminal against a worker the test hosts. This one runs it on a pseudo-console against
//! the worker the environment's scheduled task starts, because what it establishes is something
//! this platform does its own way: the console a command writes to. A Windows console has an input
//! handle and an output handle, and only the output handle takes what is drawn on the screen.

#![cfg(windows)]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kr_ipc::identity::{ProcessState, process_state};
use kr_protocol::session::Dimensions;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};

mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;
mod windows_session;

use support::kr;
use windows_session::{
    LIVENESS_DEADLINE, WorkerHost, WorkerTerminal, attachments_until, ended, root_process_of,
    snapshot_of, worker_of,
};

/// The Windows command shell, from the system directory.
fn command_shell() -> String {
    PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
        .join("System32")
        .join("cmd.exe")
        .display()
        .to_string()
}

/// Everything a pseudo-console has shown so far, read on a thread of its own.
struct ConsoleOutput {
    seen: Arc<Mutex<Vec<u8>>>,
    /// Set by the thread once it has read the last of what the console will show.
    complete: Arc<AtomicBool>,
}

impl ConsoleOutput {
    /// Starts the thread that reads the console and answers its cursor query, and returns once that
    /// thread is running.
    ///
    /// It is called before the command that writes to the console is started: the console serves
    /// nothing to that command until its query is answered, so a command started first waits on a
    /// thread that may not have been scheduled yet.
    fn collect(
        mut reader: Box<dyn Read + Send>,
        writer: Arc<Mutex<Box<dyn Write + Send>>>,
    ) -> Self {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&seen);
        let complete = Arc::new(AtomicBool::new(false));
        let finished = Arc::clone(&complete);
        let (running, started) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            // Said before the first read, and `collect` does not return until it is heard.
            let _ = running.send(());
            // The pseudo-console asks this terminal where its cursor is when it starts, and serves
            // nothing to the process attached to it until the terminal answers. This stand-in
            // answers a fixed position, which is all the console host needs.
            const QUERY: &[u8] = b"\x1b[6n";
            const REPLY: &[u8] = b"\x1b[1;1R";
            let mut answered = 0_usize;
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                let asked = match collected.lock() {
                    Ok(mut seen) => {
                        seen.extend_from_slice(&buffer[..read]);
                        seen.windows(QUERY.len())
                            .filter(|window| *window == QUERY)
                            .count()
                    }
                    Err(_) => answered,
                };
                while answered < asked {
                    if let Ok(mut writer) = writer.lock() {
                        let _ = writer.write_all(REPLY);
                        let _ = writer.flush();
                    }
                    answered += 1;
                }
            }
            // After the last byte was added to what is seen, so a reader that finds this set reads
            // all of it.
            finished.store(true, Ordering::SeqCst);
        });
        started
            .recv()
            .expect("the thread that reads the console started");
        Self { seen, complete }
    }

    /// Whether the console has shown everything it will: its thread has read to the end.
    fn complete(&self) -> bool {
        self.complete.load(Ordering::SeqCst)
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(
            &self
                .seen
                .lock()
                .expect("the console output is not poisoned"),
        )
        .into_owned()
    }

    /// Waits until `count` finds at least `times` of what it counts in what the console shows. It
    /// fails when the console's output has ended without it, and when the liveness deadline passes
    /// after `started`; `command` says how the command that writes to the console stands, for the
    /// second failure.
    ///
    /// A command that has ended can still have its last lines on their way to this side of the
    /// console, and how long that takes is not this test's to know. So the end of the command does
    /// not end the wait: the console's thread having read to the end of the output does, and until
    /// it has, the wait goes on to the deadline. The last lines of a command that ends are mostly
    /// the reason it ends, and a failure reported at the moment of the end would not show them. The
    /// output of a pseudo-console usually ends only when the pseudo-console closes, which a test
    /// holds open for as long as the command's console is wanted, so a marker that never comes is
    /// mostly reported by the deadline, which says whether the command had ended.
    fn waits_until(
        &self,
        what: &str,
        count: impl Fn(&str) -> usize,
        times: usize,
        started: Instant,
        mut command: impl FnMut() -> String,
    ) {
        loop {
            // Read before the text is, so that a thread that was done has also added the last bytes.
            let complete = self.complete();
            let text = self.text();
            if count(&text) >= times {
                return;
            }
            assert!(
                !complete,
                "{what}: the console showed all it will, and not {times} time(s) of it; the end of \
                 what it showed: {:?}",
                end_of(&text)
            );
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "{what}: waited {:?} for the console to show it {times} time(s) while {}; the end of \
                 what it showed: {:?}",
                started.elapsed(),
                command(),
                end_of(&text)
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// The last part of what a console showed, for the words of a failure: the latest output is at the
/// end, and a whole screen's drawing before it says nothing.
fn end_of(text: &str) -> &str {
    let mut start = text.len().saturating_sub(700);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
}

/// How a command that writes to a console stands, for the words of a failure.
fn standing_of(name: &str, child: &mut Box<dyn portable_pty::Child + Send + Sync>) -> String {
    match child.try_wait().expect("the command's state") {
        Some(status) => format!("{name} had ended ({status})"),
        None => format!("{name} was running"),
    }
}

/// How many numbered lines the program prints that `text` shows: `tick-` and a digit. The line the
/// shell echoes when it is typed holds `tick-%i`, which is no number.
fn numbered_lines(text: &str) -> usize {
    text.match_indices("tick-")
        .filter(|(at, marker)| {
            text[at + marker.len()..]
                .chars()
                .next()
                .is_some_and(|next| next.is_ascii_digit())
        })
        .count()
}

/// `kr attach` running on a pseudo-console of its own.
struct Attached {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    output: ConsoleOutput,
    /// The console's input, as a terminal emulator writes it.
    keyboard: Arc<Mutex<Box<dyn Write + Send>>>,
    /// Held so the console stays open for as long as the command runs.
    _master: Box<dyn portable_pty::MasterPty + Send>,
}

impl Attached {
    /// Runs `kr attach` for `session` on a pseudo-console of the session's own size, against the
    /// host `host` runs. At that size the worker streams what the session writes as it is written.
    fn start(host: &WorkerHost, session: &str, dimensions: Dimensions) -> Self {
        let pty = native_pty_system()
            .openpty(PtySize {
                rows: u16::try_from(dimensions.rows.get()).expect("a console's rows"),
                cols: u16::try_from(dimensions.columns.get()).expect("a console's columns"),
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("opens a console");
        let mut command = CommandBuilder::new(kr());
        command.args(["attach", session]);
        command.env_clear();
        // The process's own variables as the system holds them, with this host's directories on
        // top, and never a session or attachment identifier of this test's own.
        for (name, value) in std::env::vars_os() {
            if name != "KR_SESSION" && name != "KR_ATTACHMENT" {
                command.env(name, value);
            }
        }
        command.env("KR_RUNTIME_DIR", host.tree.paths().runtime_root());
        command.env("KR_STATE_DIR", host.tree.paths().state_root());
        command.env("TERM", "xterm-256color");
        let writer: Arc<Mutex<Box<dyn Write + Send>>> =
            Arc::new(Mutex::new(pty.master.take_writer().expect("a writer")));
        let output = ConsoleOutput::collect(
            pty.master.try_clone_reader().expect("a reader"),
            Arc::clone(&writer),
        );
        let child = pty.slave.spawn_command(command).expect("starts kr");
        drop(pty.slave);
        Self {
            child,
            output,
            keyboard: writer,
            _master: pty.master,
        }
    }

    /// Writes `bytes` to the console's input the way a terminal emulator hosting it does.
    fn press(&self, bytes: &[u8]) {
        let mut keyboard = self
            .keyboard
            .lock()
            .expect("the console input is not poisoned");
        keyboard
            .write_all(bytes)
            .expect("writes the console's input");
        keyboard.flush().expect("flushes the console's input");
    }

    /// Waits until `count` finds at least `times` of what it counts in the console's output, as
    /// [`ConsoleOutput::waits_until`] says.
    fn shows(&mut self, what: &str, count: impl Fn(&str) -> usize, times: usize) {
        let child = &mut self.child;
        self.output
            .waits_until(what, count, times, Instant::now(), || {
                standing_of("kr attach", child)
            });
    }

    /// Whether the command is still running.
    fn running(&mut self) -> bool {
        self.child
            .try_wait()
            .expect("the command's state")
            .is_none()
    }

    /// Waits for the command to end, and says how it ended. It fails when the command is still
    /// running at the liveness deadline, and says what the console shows then.
    fn ends(&mut self, what: &str) -> portable_pty::ExitStatus {
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().expect("the command's state") {
                return status;
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "{what}: kr attach was still running {:?} later; the console shows: {:?}",
                started.elapsed(),
                self.output.text()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Closes the console the command runs in, as closing its window does, and returns the command,
    /// which the closing of its console ends.
    fn close_the_console(self) -> Box<dyn portable_pty::Child + Send + Sync> {
        let Self {
            child,
            output,
            keyboard,
            _master,
        } = self;
        drop((output, keyboard, _master));
        child
    }
}

/// KR-REQ-01.09: a person's `kr attach` in a console shows what the session writes. The command
/// opens the console's input handle and its output handle, and what the session draws goes to the
/// output handle, which is the only one a console takes drawn bytes on.
///
/// A session whose root shell is the Windows command shell is typed, through the client library, a
/// program that prints a numbered line every moment and, once a file exists, a marker the typed line
/// does not hold. `kr attach` then runs on a pseudo-console of its own, of the session's size. When
/// the console has shown the numbered lines of the session's screen, the file is made, and the
/// console must show the marker: something the session printed after the console had shown what
/// the session had. The command must still be attached. A command that wrote the session's output
/// to the input handle shows the console none of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_console_attached_with_kr_attach_shows_what_the_session_writes() {
    let host = WorkerHost::start().await;
    let (session_id, dimensions) = host
        .kr_new(&["--shell-mode", "native_compat", "--shell", &command_shell()])
        .await
        .session();
    let environment = host.tree.environment();
    let mut typist = WorkerTerminal::attach(&environment, session_id, dimensions).await;
    let gate_directory = tempfile::tempdir().expect("a directory on the internal disk");
    let gate = gate_directory.path().join("gate");
    // The line the shell echoes holds the number as typed, `%i`, and the marker with its caret, so
    // that only what the program prints holds a number or the marker.
    typist
        .type_line(&format!(
            "for /l %i in (1,1,100000) do @(echo tick-%i & (if exist \"{}\" echo K^R-gate-opened) & \
             ping -n 1 127.0.0.1 >nul)",
            gate.display()
        ))
        .await;
    typist
        .shown("tick-1", "the session prints the program's first line")
        .await;

    let mut console = Attached::start(&host, &session_id.to_string(), dimensions);
    console.shows(
        "the numbered lines of the session's screen",
        numbered_lines,
        2,
    );
    std::fs::write(&gate, b"open").expect("the file the session waits for");
    console.shows(
        "what the session prints after",
        |text| text.matches("KR-gate-opened").count(),
        1,
    );
    assert!(
        console.running(),
        "kr attach ended; the console shows: {:?}",
        console.output.text()
    );

    let _ = console.child.kill();
    drop(typist);
    let closed = tokio::task::spawn_blocking({
        let runtime_root = host.tree.paths().runtime_root().to_path_buf();
        let state_root = host.tree.paths().state_root().to_path_buf();
        move || {
            std::process::Command::new(kr())
                .args(["--json", "close", &session_id.to_string()])
                .env("KR_RUNTIME_DIR", runtime_root)
                .env("KR_STATE_DIR", state_root)
                .output()
                .expect("kr close runs")
        }
    })
    .await
    .expect("kr close is waited for");
    assert!(
        closed.status.success(),
        "{}",
        String::from_utf8_lossy(&closed.stdout)
    );
}

/// A session whose application is PowerShell running `script`, with a terminal attached to it that
/// has seen the application say it is ready.
///
/// The line the shell echoes holds the two halves of each marker apart, so that only what the
/// program prints holds a whole one, and `script` prints `kr-ready.` when it waits for keys.
async fn session_waiting_for_keys(
    host: &WorkerHost,
    script: &str,
) -> (WorkerTerminal, kr_protocol::ids::SessionId, Dimensions) {
    let (session_id, dimensions) = host
        .kr_new(&["--shell-mode", "native_compat", "--shell", &command_shell()])
        .await
        .session();
    let environment = host.tree.environment();
    let mut typist = WorkerTerminal::attach(&environment, session_id, dimensions).await;
    typist
        .type_line(&format!("powershell -NoProfile -Command \"{script}\""))
        .await;
    typist
        .shown("kr-ready.", "the application is waiting for a key")
        .await;
    (typist, session_id, dimensions)
}

/// KR-REQ-08.53: a key typed at the console `kr attach` runs in reaches the session's application
/// as the key the console reported, with its modifier state, and not as the bytes the console
/// would have spelled it with.
///
/// The session's root shell starts PowerShell, which reads one key with the console's own call and
/// prints what it was given. The console that `kr attach` runs in is written Shift and Return in the
/// documented record sequence, which its host turns into the console record of that key. Spelled as
/// legacy input the key is a bare carriage return, which the application reads back as Return with
/// nothing held; an application that is told Shift was held was given the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_typed_at_an_attached_console_reaches_the_application_as_the_console_reported_it() {
    let host = WorkerHost::start().await;
    let (mut typist, session_id, dimensions) = session_waiting_for_keys(
        &host,
        "Write-Host ('kr-rea' + 'dy.'); \
         $key = [Console]::ReadKey($true); \
         Write-Host (('kr-key:{0}:{1}:{2}:kr-' -f [int]$key.Key, [int]$key.KeyChar, $key.Modifiers) + 'end'); \
         Start-Sleep -Seconds 300",
    )
    .await;

    let mut console = Attached::start(&host, &session_id.to_string(), dimensions);
    console.shows(
        "the session's screen",
        |text| text.matches("kr-ready.").count(),
        1,
    );
    // Shift and Return: virtual key 13, scan code 0x1c, the carriage return, Shift held.
    console.press(b"\x1b[13;28;13;1;16;1_");
    let seen = typist
        .shown(":kr-end", "the application printed the key it was given")
        .await;
    assert!(
        seen.contains("kr-key:13:13:Shift:kr-end"),
        "the application was given Return with Shift held: {seen:?}"
    );

    let _ = console.child.kill();
    drop(typist);
}

/// KR-REQ-08.53: the records of a key going down and coming up, and of a modifier on its own,
/// reach the application one by one, each in the console's own record, as the console reported them
/// one by one.
///
/// Legacy input has no spelling for a key coming up or for Shift alone, so an application that is
/// told of all four was given records. The application reads four events with the console's own
/// call, key releases included, from the first Shift it is given (the release of the Return that
/// started it is waiting in the console before that), and prints what each was. The console that
/// `kr attach` runs in is written the four in separate writes, which is how a person's key presses
/// reach a console: Shift going down, the letter going down, the letter coming up, Shift coming up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_releases_and_modifiers_of_an_attached_console_reach_the_application_one_by_one() {
    let host = WorkerHost::start().await;
    let (mut typist, session_id, dimensions) = session_waiting_for_keys(
        &host,
        "Write-Host ('kr-rea' + 'dy.'); \
         $seen = @(); \
         while ($seen.Count -lt 4) { \
           $key = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown,IncludeKeyUp'); \
           if ($seen.Count -gt 0 -or $key.VirtualKeyCode -eq 16) { \
             $seen += ('{0}{1}' -f $key.VirtualKeyCode, $(if ($key.KeyDown) { 'd' } else { 'u' })) } }; \
         Write-Host (('kr-events:' + ($seen -join ',') + ':kr-') + 'end'); \
         Start-Sleep -Seconds 300",
    )
    .await;

    let mut console = Attached::start(&host, &session_id.to_string(), dimensions);
    console.shows(
        "the session's screen",
        |text| text.matches("kr-ready.").count(),
        1,
    );
    console.press(b"\x1b[16;42;0;1;16;1_");
    console.press(b"\x1b[65;30;65;1;16;1_");
    console.press(b"\x1b[65;30;65;0;16;1_");
    console.press(b"\x1b[16;42;0;0;0;1_");
    let seen = typist
        .shown(":kr-end", "the application printed the events it was given")
        .await;
    assert!(
        seen.contains("kr-events:16d,65d,65u,16u:kr-end"),
        "the application was given Shift and A going down and coming up: {seen:?}"
    );

    let _ = console.child.kill();
    drop(typist);
}

/// The variable that makes this test binary, started in a console of its own, run the console half
/// of one of the two probes below: the one that has the console spell its keys, or the one that
/// stops a reader in a read of the console's text.
const SPELL_PROBE: &str = "KR_ATTACH_SPELL_PROBE";

/// This test binary, started in a console of its own to run the console half of a probe, with the
/// keys pressed in that console by writing them in the documented record sequence.
struct Probe {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    output: ConsoleOutput,
    started: Instant,
    /// Held open for as long as the console is wanted.
    _master: Box<dyn portable_pty::MasterPty + Send>,
}

impl Probe {
    /// Starts the test `name` of this binary, which runs its console half.
    fn start(name: &str) -> Self {
        Self::start_marked(name, SPELL_PROBE, &[])
    }

    /// Starts the test `name` of this binary with `marker` set, which makes it run its console
    /// half, and `environment` as well.
    fn start_marked(name: &str, marker: &str, environment: &[(&str, String)]) -> Self {
        let pty = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 100,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("opens a console");
        let mut command = CommandBuilder::new(std::env::current_exe().expect("this test binary"));
        command.args(["--exact", name, "--nocapture", "--test-threads=1"]);
        command.env(marker, "1");
        for (name, value) in environment {
            command.env(name, value);
        }
        let writer: Arc<Mutex<Box<dyn Write + Send>>> =
            Arc::new(Mutex::new(pty.master.take_writer().expect("a writer")));
        let output = ConsoleOutput::collect(
            pty.master.try_clone_reader().expect("a reader"),
            Arc::clone(&writer),
        );
        let child = pty.slave.spawn_command(command).expect("starts the probe");
        drop(pty.slave);
        Self {
            child,
            writer,
            output,
            started: Instant::now(),
            _master: pty.master,
        }
    }

    /// Writes `bytes` to the console as the keys of its keyboard.
    fn press(&self, bytes: &[u8]) {
        let mut keyboard = self
            .writer
            .lock()
            .expect("the console input is not poisoned");
        keyboard.write_all(bytes).expect("writes the console input");
        keyboard.flush().expect("flushes the console input");
    }

    /// Waits until the console shows `what`, as [`ConsoleOutput::waits_until`] says.
    fn waits_for(&mut self, what: &str) {
        let child = &mut self.child;
        self.output.waits_until(
            what,
            |text| text.matches(what).count(),
            1,
            self.started,
            || standing_of("the probe", child),
        );
    }

    /// Everything the console has shown.
    fn shown(&self) -> String {
        self.output.text()
    }

    /// Prints the lines the probe showed, which a run with `--nocapture` then keeps in its log.
    fn report(&self) {
        for line in self.output.text().lines() {
            if let Some(at) = line.find("kr-probe:") {
                println!("{}", &line[at..]);
            }
        }
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

/// What a console is read through when its last lines are on their way as the command ends: the read
/// that completes `held`, whether it arrives whole in one read or in pieces over several, is not
/// handed on until `gate` is set, or until the test has let go of it. What came before it is handed
/// on, so that nothing the console asks for is held back, and the whole of `held` is never in what
/// the reader has been given while the gate is shut.
struct HeldBack {
    inner: Box<dyn Read + Send>,
    held: &'static str,
    gate: Arc<AtomicBool>,
    /// The end of what the reads gave, as long as `held` less one byte: the part of it a later read
    /// can complete.
    tail: Vec<u8>,
}

impl Read for HeldBack {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        let mut joined = std::mem::take(&mut self.tail);
        joined.extend_from_slice(&buffer[..read]);
        let held = self.held.as_bytes();
        let carries = joined.windows(held.len()).any(|window| window == held);
        self.tail = joined[joined.len().saturating_sub(held.len() - 1)..].to_vec();
        while carries && !self.gate.load(Ordering::SeqCst) && Arc::strong_count(&self.gate) > 1 {
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(read)
    }
}

/// A command that ends is waited for until the console has shown what it wrote. What a command
/// writes last reaches this side of the console after the command has ended, and a wait that ended
/// with the command failed a command that had done what was asked.
///
/// `cmd.exe` writes a marker, which the console's reader holds back until the wait has looked at the
/// console once after the command has been seen to end. The marker is spelled in the command line
/// so that the line does not hold it. That first look is taken with the marker held back and the
/// command ended, which is where a wait that ended with the command fails, and only after it is the
/// marker let through; the wait must then find it.
#[test]
fn a_command_that_ends_is_waited_for_until_the_console_has_shown_what_it_wrote() {
    const MARKER: &str = "kr-last-words";

    let pty = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("opens a console");
    let writer: Arc<Mutex<Box<dyn Write + Send>>> =
        Arc::new(Mutex::new(pty.master.take_writer().expect("a writer")));
    let gate = Arc::new(AtomicBool::new(false));
    let output = ConsoleOutput::collect(
        Box::new(HeldBack {
            inner: pty.master.try_clone_reader().expect("a reader"),
            held: MARKER,
            gate: Arc::clone(&gate),
            tail: Vec::new(),
        }),
        Arc::clone(&writer),
    );
    let mut command = CommandBuilder::new(command_shell());
    command.args(["/c", "echo kr-last^-words"]);
    let mut child = pty
        .slave
        .spawn_command(command)
        .expect("starts the command");
    drop(pty.slave);

    let started = Instant::now();
    while child.try_wait().expect("the command's state").is_none() {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the command did not end: {:?}",
            output.text()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let first_look = std::cell::Cell::new(true);
    output.waits_until(
        "what the command wrote",
        |text| {
            // The first look is taken with the command ended and the marker held back; the marker is
            // let through once that look has been counted.
            let found = text.matches(MARKER).count();
            if first_look.replace(false) {
                assert_eq!(
                    found, 0,
                    "the command's last words are held back until the wait has looked once: {text:?}"
                );
                gate.store(true, Ordering::SeqCst);
            }
            found
        },
        1,
        started,
        || standing_of("the command", &mut child),
    );
}

/// KR-REQ-08.53: a console the attachment asks to spell its keys itself spells them, and the reader
/// that handed on the console's key records hands on the bytes it spelled from then on, as the
/// console spelled them.
///
/// A session whose application has negotiated a keyboard encoding that its spelling of key records
/// cannot express refuses the records, and the attachment then turns its console to its own
/// virtual-terminal input. This runs the production pieces of that in a console of their own: this
/// test binary is started in a pseudo-console with the variable above set, and there it takes the
/// console the way `kr attach` does, in record mode, starts the input reader over it, and reads a key
/// as the record it is. It then asks the console to spell its keys, and reads an arrow, Ctrl+Space,
/// a letter held down (a record with a repeat count of three), Ctrl+Z, an `é` and another letter,
/// which come back as UTF-8, the NUL of Ctrl+Space and the Ctrl+Z among them. The test, outside,
/// writes the keys in the documented record sequence, and expects the records first and the text
/// after. A switch that changed nothing leaves the arrow a record, a reader that turned the records
/// of the keys going down into bytes loses the NUL, one that reads the console's bytes loses the
/// Ctrl+Z and gives `é` in the console's code page. The test then presses Ctrl+Space again as the
/// only key the console holds, and expects its NUL: a reader that takes the record off the queue
/// with those that make no text loses the key. Last, the test presses Ctrl on its own and the Apps
/// key, one record at a time, which the console keeps as records that make no text. The probe knows
/// each has arrived and been taken by the console's own report of its queue, stops the reader once
/// all four have, and reads one more key itself: a reader left in a read of the console, or
/// cancelled in the middle of one, leaves a pending read behind, and the console gives that read
/// the next key. The stop finds no read to cancel and says so.
#[test]
fn a_console_asked_to_spell_its_keys_hands_the_reader_bytes_where_it_handed_records() {
    if std::env::var_os(SPELL_PROBE).is_some() {
        spell_probe_in_the_console();
        return;
    }

    let mut probe = Probe::start(
        "a_console_asked_to_spell_its_keys_hands_the_reader_bytes_where_it_handed_records",
    );
    probe.waits_for("kr-probe:ready");
    // The letter A, going down and coming up, as a console is written a key.
    probe.press(b"\x1b[65;30;97;1;0;1_");
    probe.press(b"\x1b[65;30;97;0;0;1_");
    probe.waits_for("kr-probe:switched");
    let before = probe.shown();
    assert!(
        before.contains("kr-probe:key:65:97:down"),
        "the letter was read as the record it is before the console spelled anything: {before:?}"
    );
    // The up arrow, Ctrl+Space, the letter A held down (one record that says it repeated three
    // times), Ctrl+Z, an `é` and the letter B, each going down and coming up.
    probe.press(b"\x1b[38;72;0;1;0;1_");
    probe.press(b"\x1b[38;72;0;0;0;1_");
    probe.press(b"\x1b[32;57;32;1;8;1_");
    probe.press(b"\x1b[32;57;32;0;8;1_");
    probe.press(b"\x1b[65;30;97;1;0;3_");
    probe.press(b"\x1b[65;30;97;0;0;1_");
    probe.press(b"\x1b[90;44;26;1;8;1_");
    probe.press(b"\x1b[90;44;26;0;8;1_");
    probe.press(b"\x1b[69;18;233;1;0;1_");
    probe.press(b"\x1b[69;18;233;0;0;1_");
    probe.press(b"\x1b[66;48;98;1;0;1_");
    probe.press(b"\x1b[66;48;98;0;0;1_");
    probe.waits_for("kr-probe:bytes:");
    // Ctrl+Space as the only key the console holds. The console keeps it as a key going down with no
    // character, which a read of the console's text passes over unless the reader has told it apart
    // from a modifier: a reader that took it off the queue with the records that make no text never
    // sends its byte, and the person's key is gone.
    probe.press(b"\x1b[32;57;32;1;8;1_");
    probe.press(b"\x1b[32;57;32;0;8;1_");
    probe.waits_for("kr-probe:alone:");
    // A letter going down and not coming up. The reader hands its text on after every record that
    // came before it, the release of the Ctrl+Space among them, so when the probe has it nothing is
    // on its way and nothing is in the queue; a release after it would be a record of its own.
    probe.press(b"\x1b[69;18;101;1;0;1_");
    probe.waits_for("kr-probe:watching");
    // Ctrl on its own, and the Apps key, each going down and coming up, one record at a time: the
    // console keeps each as a record that makes no text, and a read of the console's text would
    // wait for the next key. The probe has seen each taken before the next is pressed, so the
    // reader has met every one of them with nothing else in the queue.
    let last = [
        &b"\x1b[17;29;0;1;8;1_"[..],
        b"\x1b[17;29;0;0;0;1_",
        b"\x1b[93;93;0;1;256;1_",
        b"\x1b[93;93;0;0;256;1_",
    ];
    for (taken, record) in last.into_iter().enumerate() {
        probe.press(record);
        probe.waits_for(&format!("kr-probe:taken:{}", taken + 1));
    }
    probe.waits_for("kr-probe:stopped");
    // The reader has been stopped, so this key is the process's own to read. A reader left in its
    // read of the console's text would take it.
    probe.press(b"\x1b[67;46;99;1;0;1_");
    probe.press(b"\x1b[67;46;99;0;0;1_");
    probe.waits_for("kr-probe:done");
    let shown = probe.shown();
    let after = &shown[shown
        .find("kr-probe:switched")
        .expect("the switch is shown")..];
    // The arrow, the NUL, the held letter as many times as the console spells it, Ctrl+Z, `é` as
    // UTF-8 and the letter after. How many times the console spells a held key is its own; that it is
    // spelled at all, the NUL, the Ctrl+Z and the encoding are the reader's.
    let spelled = after
        .lines()
        .find_map(|line| line.strip_prefix("kr-probe:bytes:"))
        .expect("the probe shows the bytes it was given");
    let held = spelled
        .strip_prefix("1b5b4100")
        .and_then(|rest| rest.strip_suffix("1ac3a962"))
        .unwrap_or_default();
    assert!(
        !held.is_empty() && held.as_bytes().chunks(2).all(|letter| letter == b"61"),
        "the keys came back as the text the console spells for them, the NUL and the Ctrl+Z among \
         them: {after:?}"
    );
    let alone = after
        .lines()
        .find_map(|line| line.strip_prefix("kr-probe:alone:"))
        .expect("the probe shows the bytes of the lone Ctrl+Space");
    assert_eq!(
        alone.trim_end(),
        "00",
        "Ctrl+Space, as the only key the console held, reached the reader as its NUL: {after:?}"
    );
    assert!(
        !after.contains("kr-probe:key:"),
        "a key was handed on as a record after the console spelled its keys: {after:?}"
    );
    assert!(
        after.contains("kr-probe:stopped:ended:cancel_asked=false"),
        "the stop found the reader ended, in no read of the console, and asked for no cancel: \
         {after:?}"
    );
    assert!(
        after.contains("kr-probe:next:63"),
        "the key typed after the reader was stopped reached the process and not the reader: {after:?}"
    );
    probe.report();
}

/// KR-REQ-08.53: a stop that meets the reader in a read of the console's text ends the read, asks
/// the system to cancel it, and says so.
///
/// A key going down with no character is taken for text when Ctrl is held and the key is not a
/// modifier or a lock, because the console stores a NUL that way. The Apps key with Ctrl held is
/// such a record that makes no text: the read the reader makes for it takes the record, passes over
/// it and waits for the next key with text, so only a cancel ends it. The probe, in a console of
/// its own, starts the reader, has the console spell its keys, and presses Ctrl and then the Apps
/// key with Ctrl held. The console reports its queue empty once the reader has taken each, which
/// for the second is the reader inside its read. The stop then has to cancel that read: it ends the
/// reader and reports that it asked the system to.
#[test]
fn a_stop_that_meets_a_read_of_the_consoles_text_cancels_it_and_says_so() {
    if std::env::var_os(SPELL_PROBE).is_some() {
        stop_probe_in_the_console();
        return;
    }

    let mut probe =
        Probe::start("a_stop_that_meets_a_read_of_the_consoles_text_cancels_it_and_says_so");
    probe.waits_for("kr-probe:watching");
    // Ctrl going down, which the reader takes off the queue without a read, and the Apps key going
    // down with Ctrl held, which it reads the text of.
    probe.press(b"\x1b[17;29;0;1;8;1_");
    probe.waits_for("kr-probe:taken:1");
    probe.press(b"\x1b[93;93;0;1;264;1_");
    probe.waits_for("kr-probe:taken:2");
    probe.waits_for("kr-probe:stopped");
    let shown = probe.shown();
    assert!(
        shown.contains("kr-probe:stopped:ended:cancel_asked=true"),
        "the stop ended the reader's read of the console and said it asked the system to cancel \
         it: {shown:?}"
    );
    probe.report();
}

/// How many times the paste probe writes U+1F600.
const PASTED_CHARACTERS: usize = 100;

/// How many records the console holds for the paste probe's text: a key going down and one coming up
/// for each of the five letters, and twelve for each character outside the basic plane, which a
/// console records as the Alt going down, two keypad digits and the Alt coming up with the half, for
/// each of its two halves.
const PASTED_RECORDS: u32 = 5 * 2 + 12 * PASTED_CHARACTERS as u32;

/// KR-REQ-08.53: a character outside the basic plane that a console is given as text is spelled
/// whole from the pieces the reader hands on, however the console's records are cut into reads.
///
/// A console records U+1F600 as twelve key records, six for each half, and the halves come on the
/// Alt coming up. The reader takes 256 records at a time, so a paste of a hundred of them is read in
/// five pieces that end wherever the count falls, and four letters before the paste put the first
/// end between the two halves of one character, after the Alt has come up with the first. The probe,
/// in a console of its own, waits until the console holds the whole paste, so that the pieces are
/// the reader's and not the timing's, starts the reader as `kr attach` does, spells each piece it
/// hands on as the worker does for a session that did not ask for records, and shows the result.
/// The test, outside, writes the text to the console as UTF-8 and expects every character whole and
/// none replaced.
#[test]
fn a_character_outside_the_basic_plane_pasted_into_a_console_is_spelled_whole_from_the_readers_pieces()
 {
    if std::env::var_os(SPELL_PROBE).is_some() {
        paste_probe_in_the_console();
        return;
    }

    let mut probe = Probe::start(
        "a_character_outside_the_basic_plane_pasted_into_a_console_is_spelled_whole_from_the_readers_pieces",
    );
    probe.waits_for("kr-probe:ready");
    let mut pasted = b"aaaa".to_vec();
    for _ in 0..PASTED_CHARACTERS {
        pasted.extend_from_slice("\u{1F600}".as_bytes());
    }
    pasted.push(b'z');
    probe.press(&pasted);
    probe.waits_for("kr-probe:spelled:");
    let shown = probe.shown();
    assert!(
        shown.contains(&format!(
            "kr-probe:spelled:letters=5:characters={PASTED_CHARACTERS}:replaced=0:"
        )),
        "every character was spelled whole from the reader's pieces and none was replaced: {shown:?}"
    );
    probe.report();
}

/// What the console half of a probe holds: the console taken as `kr attach` takes it, in record
/// mode, and the reader over it.
struct Reading {
    console: kr_cli::platform::ControllingTerminal,
    _saved: kr_cli::platform::SavedModes,
    switch: kr_cli::attach::InputSwitch,
    input: tokio::sync::mpsc::UnboundedReceiver<kr_cli::attach::TerminalInput>,
    stop: kr_cli::attach::InputStop,
    deadline: Instant,
}

impl Reading {
    /// Takes the console and starts the reader over it.
    fn start() -> Self {
        use kr_cli::attach::spawn_input_reader;
        use kr_cli::platform::ControllingTerminal;

        let console = ControllingTerminal::open().expect("this process has a console");
        let saved = console
            .enter_record_mode()
            .expect("the console takes record mode");
        let switch = console.input_switch().expect("a switch over the console");
        let handle = console.handle().try_clone().expect("a handle on the input");
        let (input, stop) = spawn_input_reader(handle, &switch).expect("the reader starts");
        Self {
            console,
            _saved: saved,
            switch,
            input,
            stop,
            deadline: Instant::now() + LIVENESS_DEADLINE,
        }
    }

    /// The next thing the reader hands on.
    fn read(&mut self) -> kr_cli::attach::TerminalInput {
        loop {
            match self.input.try_recv() {
                Ok(read) => return read,
                Err(_) => {
                    assert!(Instant::now() < self.deadline, "the console gave no input");
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    /// Stops the reader, shows what the stop found, and returns the console.
    fn stops(self) -> kr_cli::platform::ControllingTerminal {
        let stopped = self.stop.stop();
        println!(
            "kr-probe:stopped:{}:cancel_asked={}",
            if stopped.still_running {
                "running"
            } else {
                "ended"
            },
            stopped.cancel_asked
        );
        self.console
    }
}

/// Counts the records that arrive in the console's queue and are taken off it, from the console's
/// own report: its input handle is set while the queue holds a record and the queue is empty again
/// once the reader has taken it. A record that makes no text is taken without a trace anywhere
/// else, so this is how a probe knows one has arrived and been taken, and does not judge by the time
/// that has passed that none is coming. Start it when the queue is empty and the next record is
/// not yet pressed, and press one record at a time.
struct Takes(Arc<std::sync::atomic::AtomicUsize>);

impl Takes {
    fn watch(console: &kr_cli::platform::ControllingTerminal) -> Self {
        use std::sync::atomic::Ordering::SeqCst;

        use kr_cli::windows::records::{RecordReader, WakeEvent};

        let taken = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let queue = RecordReader::over(
            console
                .handle()
                .try_clone()
                .expect("a handle to watch the queue with"),
        );
        let (stop, asked) = (
            WakeEvent::new().expect("an event"),
            WakeEvent::new().expect("an event"),
        );
        let (armed, started) = std::sync::mpsc::channel();
        let count = Arc::clone(&taken);
        std::thread::spawn(move || {
            let _ = armed.send(());
            while queue.wait(&stop, &asked, false).is_ok() {
                while queue
                    .waiting()
                    .expect("the console counts its input events")
                    != 0
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                count.fetch_add(1, SeqCst);
            }
        });
        started.recv().expect("the watch started");
        Self(taken)
    }

    /// Waits until `count` records have been taken since the watch began.
    fn until(&self, count: usize) {
        let deadline = Instant::now() + LIVENESS_DEADLINE;
        while self.0.load(std::sync::atomic::Ordering::SeqCst) < count {
            assert!(
                Instant::now() < deadline,
                "the reader took fewer than {count} records off the console"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// The console half of the test that has the console spell its keys, run in a console of its own.
fn spell_probe_in_the_console() {
    use kr_cli::attach::TerminalInput;

    let mut reading = Reading::start();
    println!("kr-probe:ready");
    // Records until the letter comes up.
    loop {
        match reading.read() {
            TerminalInput::Keys(keys) => {
                let mut up = false;
                for key in keys {
                    println!(
                        "kr-probe:key:{}:{}:{}",
                        key.virtual_key,
                        key.unicode,
                        if key.key_down { "down" } else { "up" }
                    );
                    up |= !key.key_down && key.virtual_key == 65;
                }
                if up {
                    break;
                }
            }
            TerminalInput::Bytes(bytes) => println!("kr-probe:early:{}", hex(&bytes)),
            TerminalInput::Mouse(_) => {
                panic!("the reader handed on a mouse record, which no application asked for")
            }
        }
    }
    reading
        .switch
        .engage()
        .expect("the console spells its keys");
    println!("kr-probe:switched");
    // Whatever comes next is read until the last letter has: the arrow's three bytes, a NUL, the
    // letters of the held key, Ctrl+Z, the two bytes of `é` and the letter after.
    let mut spelled = Vec::new();
    while !spelled.ends_with(b"b") {
        match reading.read() {
            TerminalInput::Bytes(bytes) => spelled.extend(bytes),
            TerminalInput::Keys(keys) => {
                for key in keys {
                    println!("kr-probe:key:{}:{}", key.virtual_key, key.unicode);
                }
            }
            TerminalInput::Mouse(_) => {
                panic!("the reader handed on a mouse record, which no application asked for")
            }
        }
    }
    println!("kr-probe:bytes:{}", hex(&spelled));
    // The test now presses Ctrl+Space again, as the only key in the console: its byte is all the
    // reader has to wait for.
    let mut alone = Vec::new();
    while alone.is_empty() {
        match reading.read() {
            TerminalInput::Bytes(bytes) => alone.extend(bytes),
            TerminalInput::Keys(keys) => {
                for key in keys {
                    println!("kr-probe:key:{}:{}", key.virtual_key, key.unicode);
                }
            }
            TerminalInput::Mouse(_) => {
                panic!("the reader handed on a mouse record, which no application asked for")
            }
        }
    }
    println!("kr-probe:alone:{}", hex(&alone));
    // Then a letter going down and not coming up. The reader reads every record before it first, so
    // once the letter has come nothing is left in the queue or on its way.
    let mut barrier = Vec::new();
    while barrier.is_empty() {
        match reading.read() {
            TerminalInput::Bytes(bytes) => barrier.extend(bytes),
            TerminalInput::Keys(keys) => {
                for key in keys {
                    println!("kr-probe:key:{}:{}", key.virtual_key, key.unicode);
                }
            }
            TerminalInput::Mouse(_) => {
                panic!("the reader handed on a mouse record, which no application asked for")
            }
        }
    }
    let takes = Takes::watch(&reading.console);
    println!("kr-probe:watching");
    // Ctrl on its own and the Apps key, going down and coming up, pressed one at a time. The reader
    // is stopped once the console has shown each was taken.
    for taken in 1..=4 {
        takes.until(taken);
        println!("kr-probe:taken:{taken}");
    }
    let console = reading.stops();
    let mut next = [0_u8; 1];
    let mut input_handle = console.handle();
    input_handle
        .read_exact(&mut next)
        .expect("the console hands the process the next key");
    println!("kr-probe:next:{}", hex(&next));
    println!("kr-probe:done");
}

/// The console half of the test of the stop, run in a console of its own.
fn stop_probe_in_the_console() {
    let reading = Reading::start();
    reading
        .switch
        .engage()
        .expect("the console spells its keys");
    let takes = Takes::watch(&reading.console);
    println!("kr-probe:watching");
    // Ctrl, which the reader takes off the queue without a read, and the Apps key with Ctrl held,
    // which it reads the text of: when the console shows that taken the reader is in the read.
    takes.until(1);
    println!("kr-probe:taken:1");
    takes.until(2);
    println!("kr-probe:taken:2");
    let _console = reading.stops();
}

/// The console half of the paste probe, run in a console of its own.
fn paste_probe_in_the_console() {
    use kr_cli::attach::TerminalInput;
    use kr_cli::platform::ControllingTerminal;
    use kr_cli::windows::records::RecordReader;
    use kr_term::modes::KeyboardEncoding;
    use kr_term::win32::{Keyboard, legacy_within};

    // The console is looked at before a reader takes anything from it: it holds the whole paste when
    // the reader starts, so the reader's reads are the same however the paste arrived.
    let console = ControllingTerminal::open().expect("this process has a console");
    let queue = RecordReader::over(console.handle().try_clone().expect("a handle on the input"));
    println!("kr-probe:ready");
    let deadline = Instant::now() + LIVENESS_DEADLINE;
    while queue.waiting().expect("the console counts its input") < PASTED_RECORDS {
        assert!(
            Instant::now() < deadline,
            "the console never held the paste"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(queue);
    drop(console);

    let mut reading = Reading::start();
    let keyboard = Keyboard {
        application_cursor_keys: false,
        negotiated: KeyboardEncoding::Legacy,
    };
    let mut spelled = Vec::new();
    let mut pieces = Vec::new();
    'reading: loop {
        match reading.read() {
            TerminalInput::Keys(keys) => {
                pieces.push(keys.len().to_string());
                spelled.extend(
                    legacy_within(&keys, &keyboard, kr_protocol::limits::MAX_INPUT_FRAME_LEN)
                        .expect("the piece is spelled"),
                );
                if keys
                    .iter()
                    .any(|key| key.key_down && key.unicode == u16::from(b'z'))
                {
                    break 'reading;
                }
            }
            TerminalInput::Bytes(bytes) => println!("kr-probe:early:{}", hex(&bytes)),
            TerminalInput::Mouse(_) => {
                panic!("the reader handed on a mouse record, which no application asked for")
            }
        }
    }
    let text = String::from_utf8_lossy(&spelled);
    println!("kr-probe:pieces:{}", pieces.join(","));
    println!(
        "kr-probe:spelled:letters={}:characters={}:replaced={}:",
        text.chars().filter(char::is_ascii_lowercase).count(),
        text.chars().filter(|&c| c == '\u{1F600}').count(),
        text.chars()
            .filter(|&c| c == char::REPLACEMENT_CHARACTER)
            .count()
    );
    let _console = reading.stops();
}

/// The variable that makes this test binary, started in the session's console, read key records
/// there and print them.
const RECORD_READER: &str = "KR_ATTACH_RECORD_READER";

/// KR-REQ-08.56: a character an input method composed, a dead key and the character it composes,
/// and AltGr reach the session's application as the records the console reported, each with its
/// own virtual key, scan code, character and control-key state.
///
/// The session's root shell starts this test binary, which reads the key records of the session's
/// console with the same reader `kr attach` uses and prints the five numbers of each key that went
/// down. The console that `kr attach` runs in is written, in the documented record sequence, what a
/// keyboard with an input method and a dead key gives it: the hiragana letter A composed by the
/// input method (no virtual key, no scan code), the circumflex as a dead key (a virtual key and a
/// scan code and no character), the `ê` that composes with it, and `@` typed with AltGr (right Alt
/// with left Ctrl held). Spelled as text, the composed letter carries no key, the dead key is not an
/// event at all and AltGr is no modifier; an application that is given all four as written was given
/// the records.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_composed_character_a_dead_key_and_alt_graph_reach_the_application_as_the_console_reported_them()
 {
    if std::env::var_os(RECORD_READER).is_some() {
        record_reader_in_the_session();
        return;
    }

    let host = WorkerHost::start().await;
    let (session_id, dimensions) = host
        .kr_new(&["--shell-mode", "native_compat", "--shell", &command_shell()])
        .await
        .session();
    let environment = host.tree.environment();
    let mut typist = WorkerTerminal::attach(&environment, session_id, dimensions).await;
    let reader = std::env::current_exe().expect("this test binary");
    typist
        .type_line(&format!(
            "set {RECORD_READER}=1&& \"{}\" --exact \
             a_composed_character_a_dead_key_and_alt_graph_reach_the_application_as_the_console_reported_them \
             --nocapture --test-threads=1",
            reader.display()
        ))
        .await;
    typist
        .shown("kr-rec-ready", "the session's console is being read")
        .await;

    let mut console = Attached::start(&host, &session_id.to_string(), dimensions);
    console.shows(
        "the session's screen",
        |text| text.matches("kr-rec-ready").count(),
        1,
    );
    // The hiragana letter A as the input method composed it: no virtual key, no scan code.
    console.press(b"\x1b[0;0;12354;1;0;1_");
    // The circumflex as a dead key: virtual key 0xDD, scan code 0x1a, no character.
    console.press(b"\x1b[221;26;0;1;0;1_");
    // The `ê` it composes with: the letter E's key and the composed character.
    console.press(b"\x1b[69;18;234;1;0;1_");
    // `@` typed with AltGr: the 2 key, right Alt (1) with left Ctrl (8) held.
    console.press(b"\x1b[50;3;64;1;9;1_");
    let seen = typist
        .shown(
            "kr-rec-end",
            "the application printed the records it was given",
        )
        .await;
    // virtual key : scan code : character : control-key state : repeat count
    let mut from = 0;
    for expected in [
        "kr-rec:0:0:12354:0:1;",
        "kr-rec:221:26:0:0:1;",
        "kr-rec:69:18:234:0:1;",
        "kr-rec:50:3:64:9:1;",
    ] {
        match seen[from..].find(expected) {
            Some(at) => from += at + expected.len(),
            None => panic!(
                "the application was not given {expected:?} after the records before it: the \
                 session shows {seen:?}"
            ),
        }
    }

    let _ = console.child.kill();
    drop(typist);
}

/// The session half of the test above: reads the key records of this console and prints the five
/// numbers of each key that went down, each record closed with a semicolon so that a number is read
/// to its end, until it has four.
fn record_reader_in_the_session() {
    use kr_cli::platform::ControllingTerminal;
    use kr_cli::windows::records::{ConsoleEvent, RecordReader};

    let console = ControllingTerminal::open().expect("this process has a console");
    let mut reader =
        RecordReader::over(console.handle().try_clone().expect("a handle on the input"));
    println!("kr-rec-ready");
    let mut printed = 0;
    while printed < 4 {
        for event in reader.read().expect("the console's records") {
            if let ConsoleEvent::Key(key) = event
                && key.key_down
            {
                println!(
                    "kr-rec:{}:{}:{}:{}:{};",
                    key.virtual_key, key.scan_code, key.unicode, key.control_keys, key.repeat
                );
                printed += 1;
            }
        }
    }
    println!("kr-rec-end");
}

/// The variable that makes this test binary, started in a console of its own, run the console half
/// of the test of the console's modes.
const RESTORE_PROBE: &str = "KR_ATTACH_RESTORE_PROBE";

/// KR-REQ-08.56: when an attachment ends, the console it ran in is given back in the modes it had.
///
/// This test binary is started in a pseudo-console of its own, as the outer console of a person's
/// attachment, and there it reads the console's input and output modes, starts the real `kr attach`
/// for a session in that console, and reads the modes again once the command has taken the console
/// over. The test, outside, closes the session, which ends the attachment, and the probe reads the
/// modes a third time once `kr attach` has gone. The modes while the command was attached are not
/// the modes before it (a command that changed nothing would pass the last check without
/// restoring anything), and the modes after it are the ones before.
///
/// KR-REQ-08.55, the part about the outer console after detach: the person's outer console is not
/// left in the wrong mode when an attachment ends. Its input and output modes after `kr attach`
/// has gone are the ones it had before, although the pair was different while the command ran.
/// The attachment here ends because `kr close` closes its session. Not shown here: a detach that
/// leaves the session running, the outer terminal's own modes (mouse, paste, alternate screen),
/// which the case does not read, and a nested `wsl.exe`, `ssh` or ConPTY transition's own mode
/// reset: kr-term's `conpty_sources` and `win32_input` cases show that no request or reset for
/// mode 9001 that reaches the worker goes on to a client. The session runs the command shell and
/// nothing nested in it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_console_an_attachment_ran_in_is_given_back_in_the_modes_it_had() {
    if std::env::var_os(RESTORE_PROBE).is_some() {
        restore_probe_in_the_console();
        return;
    }

    let host = WorkerHost::start().await;
    let (session_id, _) = host
        .kr_new(&["--shell-mode", "native_compat", "--shell", &command_shell()])
        .await
        .session();
    let mut probe = Probe::start_marked(
        "the_console_an_attachment_ran_in_is_given_back_in_the_modes_it_had",
        RESTORE_PROBE,
        &[
            (
                "KR_RUNTIME_DIR",
                host.tree.paths().runtime_root().display().to_string(),
            ),
            (
                "KR_STATE_DIR",
                host.tree.paths().state_root().display().to_string(),
            ),
            ("KR_PROBE_SESSION", session_id.to_string()),
            ("KR_PROBE_KR", kr().display().to_string()),
        ],
    );
    probe.waits_for("kr-probe:inside:");
    let closed = host.kr(&["close", &session_id.to_string()], &[]).await;
    assert!(
        closed.status.success(),
        "kr close: {}{}",
        String::from_utf8_lossy(&closed.stdout),
        String::from_utf8_lossy(&closed.stderr)
    );
    probe.waits_for("kr-probe:end");
    probe.report();
    let shown = probe.shown();
    let modes = |which: &str| -> (u32, u32) {
        let line = shown
            .lines()
            .find_map(|line| line.find(which).map(|at| &line[at..]))
            .unwrap_or_else(|| panic!("the probe said nothing of {which}: {shown:?}"));
        let mut fields = line[which.len()..].trim().split(':');
        // A field is its leading hexadecimal digits; the console may follow the line with a
        // sequence of its own.
        let mut next = || {
            fields
                .next()
                .map(|word| {
                    word.chars()
                        .take_while(char::is_ascii_hexdigit)
                        .collect::<String>()
                })
                .and_then(|digits| u32::from_str_radix(&digits, 16).ok())
                .unwrap_or_else(|| panic!("the modes in {line:?}"))
        };
        (next(), next())
    };
    let before = modes("kr-probe:before:");
    let inside = modes("kr-probe:inside:");
    let after = modes("kr-probe:after:");
    assert_ne!(
        inside, before,
        "the attachment did not change the console's modes, so there was nothing to give back"
    );
    assert_eq!(
        after, before,
        "the console's input and output modes after the attachment are not the ones before it \
         (before {before:x?}, inside {inside:x?}, after {after:x?}): {shown:?}"
    );
}

/// The console half of the test of the console's modes, run in a console of its own.
fn restore_probe_in_the_console() {
    use kr_cli::platform::ControllingTerminal;

    let console = ControllingTerminal::open().expect("this process has a console");
    let before = console.modes().expect("the console's modes");
    println!("kr-probe:before:{:x}:{:x}", before.input, before.output);
    let variable = |name: &str| {
        std::env::var_os(name).unwrap_or_else(|| panic!("{name} is set for the probe"))
    };
    let mut attach = std::process::Command::new(variable("KR_PROBE_KR"))
        .arg("attach")
        .arg(variable("KR_PROBE_SESSION"))
        .spawn()
        .expect("starts kr attach");
    // The command has taken the console over once its modes are not the ones this process saw.
    let deadline = Instant::now() + LIVENESS_DEADLINE;
    let inside = loop {
        let now = console.modes().expect("the console's modes");
        if now != before {
            break now;
        }
        assert!(
            attach.try_wait().expect("the command's state").is_none(),
            "kr attach ended before it changed the console's modes"
        );
        assert!(
            Instant::now() < deadline,
            "kr attach did not change the console's modes"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    println!("kr-probe:inside:{:x}:{:x}", inside.input, inside.output);
    let status = attach.wait().expect("kr attach ends");
    let after = console.modes().expect("the console's modes");
    println!(
        "kr-probe:after:{:x}:{:x}:attach {status}",
        after.input, after.output
    );
    println!("kr-probe:end");
}

/// How an attachment of a session ends in the cases below.
#[derive(Clone, Copy, Debug)]
enum Ending {
    /// `kr detach --attachment`, run from another command.
    Detached,
    /// The console the `kr attach` runs in is closed, as closing its window closes it.
    ConsoleClosed,
    /// The `kr attach` process is ended, as a lost connection ends it.
    ProcessKilled,
}

/// A session with two attachments, a real `kr attach` in a console and a terminal this test holds,
/// of which the first ends as `ending` says; and what that leaves: only that attachment gone, the
/// session live, its worker and its root shell running, and the attachment that is left still
/// typing into the shell and being answered.
async fn only_the_attachment_that_ended_is_removed(ending: Ending) {
    let host = WorkerHost::start().await;
    let (session_id, dimensions) = host
        .kr_new(&["--shell-mode", "native_compat", "--shell", &command_shell()])
        .await
        .session();
    let environment = host.tree.environment();
    let mut holder = WorkerTerminal::attach(&environment, session_id, dimensions).await;
    let worker = worker_of(&environment, session_id);
    let root = root_process_of(&environment, session_id)
        .await
        .expect("the worker is read")
        .expect("the session has a root shell");

    let mut console = Attached::start(&host, &session_id.to_string(), dimensions);
    let joined = attachments_until(
        &environment,
        session_id,
        |listed| listed.len() == 2,
        "kr attach joins the session",
    )
    .await;
    assert_eq!(
        joined[0],
        holder.attachment_id(),
        "the terminal this test holds joined first"
    );
    let leaving = joined[1];

    let mut ended_console = None;
    match ending {
        Ending::Detached => {
            let said = host
                .kr(
                    &[
                        "--json",
                        "detach",
                        &session_id.to_string(),
                        "--attachment",
                        &leaving.to_string(),
                    ],
                    &[],
                )
                .await;
            let printed = format!(
                "{}{}",
                String::from_utf8_lossy(&said.stdout),
                String::from_utf8_lossy(&said.stderr)
            );
            assert!(said.status.success(), "kr detach: {printed}");
            let document: serde_json::Value = serde_json::from_slice(&said.stdout)
                .unwrap_or_else(|error| panic!("kr detach printed no JSON ({error}): {printed}"));
            assert_eq!(
                document["detached"],
                leaving.to_string(),
                "the detach names the attachment it removed: {printed}"
            );
            assert_eq!(
                document["remaining"], 1,
                "and says one attachment remains: {printed}"
            );
            let status = console.ends("a detach ends the attachment it names");
            assert!(
                status.success(),
                "a detach is not a failure of the command it ends ({status}): {:?}",
                console.output.text()
            );
        }
        Ending::ConsoleClosed => ended_console = Some(console.close_the_console()),
        Ending::ProcessKilled => console.child.kill().expect("kr attach is ended"),
    }

    let left = attachments_until(
        &environment,
        session_id,
        |listed| !listed.contains(&leaving),
        "the attachment that ended is removed",
    )
    .await;
    assert_eq!(
        left,
        vec![holder.attachment_id()],
        "only the attachment that ended is gone, and the other is the one left"
    );
    let snapshot = snapshot_of(&environment, session_id)
        .await
        .expect("the worker is read");
    assert_eq!(
        snapshot.session.state,
        kr_protocol::session::SessionState::Live,
        "the session goes on"
    );
    let reported = host
        .kr(&["status", &session_id.to_string(), "--json"], &[])
        .await;
    let status: serde_json::Value =
        serde_json::from_slice(&reported.stdout).unwrap_or_else(|error| {
            panic!(
                "kr status printed no JSON ({error}): {}",
                String::from_utf8_lossy(&reported.stdout)
            )
        });
    assert_eq!(status["state"], "live", "and kr says it is live: {status}");
    for (identity, what) in [(&worker, "the worker"), (&root, "the root shell")] {
        assert!(
            matches!(process_state(identity), ProcessState::Running),
            "{what} is still running after the attachment ended"
        );
    }
    // The attachment that is left still holds the keys, and the shell answers it. The line the shell
    // echoes holds the marker with a caret in it, so that only what the shell prints holds it whole.
    holder.type_line("echo kr-aft^er-the-ending").await;
    holder
        .shown(
            "kr-after-the-ending",
            "the shell answers the attachment that is left",
        )
        .await;

    drop(ended_console);
    drop(holder);
    let closed = host
        .kr(&["--json", "close", &session_id.to_string()], &[])
        .await;
    assert!(
        closed.status.success(),
        "{}",
        String::from_utf8_lossy(&closed.stdout)
    );
    ended(&worker, "the worker").await;
}

/// KR-REQ-07.52, the part about detaching: `kr detach --attachment`, run from another command,
/// removes the attachment it names and nothing else.
///
/// The `kr attach` that holds the attachment ends, and not as a failure; the session, its worker and
/// its root shell go on, and the other attachment is still attached and still typing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_detach_from_another_command_removes_only_the_attachment_it_names() {
    only_the_attachment_that_ended_is_removed(Ending::Detached).await;
}

/// KR-REQ-07.52, the part about closing a terminal window: the attachment of a console that is
/// closed is removed, and nothing else is.
///
/// The console `kr attach` runs in is closed, which ends the command with it; the session, its
/// worker and its root shell go on, and the other attachment is still attached and still typing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_the_console_an_attachment_runs_in_removes_only_that_attachment() {
    only_the_attachment_that_ended_is_removed(Ending::ConsoleClosed).await;
}

/// KR-REQ-07.52, the part about connection loss: an attachment whose connection is lost is removed,
/// and nothing else is.
///
/// The `kr attach` process is ended where it stands, which is what a lost connection looks like to
/// the worker; the session, its worker and its root shell go on, and the other attachment is still
/// attached and still typing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attachment_whose_connection_is_lost_is_removed_and_nothing_else_is() {
    only_the_attachment_that_ended_is_removed(Ending::ProcessKilled).await;
}

/// The variable that makes this test binary, started in the session's console, ask for the mouse and
/// print the reports it is given.
const MOUSE_READER: &str = "KR_ATTACH_MOUSE_READER";

/// The file the application waits for before it asks for the mouse.
const MOUSE_GATE: &str = "KR_ATTACH_MOUSE_GATE";

/// KR-REQ-08.56: a mouse event at the outer console reaches the session's application, which asked
/// for mouse reporting, as the virtual-terminal report it asked for, on the path that hands keys on
/// as records.
///
/// The session's root shell starts this test binary, which reads the console's virtual-terminal
/// input as a terminal application does and, once `kr attach` is attached and a file exists, asks to
/// be told of clicks in the SGR encoding. The console that `kr attach` runs in is then written a
/// press and its release at column 10 and row 5, as a terminal that reports the mouse sends them.
/// The application is told of them as the two reports a terminal would send, at that cell: a
/// command that kept the mouse for the console, or that handed on nothing for a record that is not
/// a key, tells it nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mouse_event_at_an_attached_console_reaches_the_application_that_asked_for_the_mouse() {
    if std::env::var_os(MOUSE_READER).is_some() {
        mouse_reader_in_the_session();
        return;
    }

    let host = WorkerHost::start().await;
    let (session_id, dimensions) = host
        .kr_new(&["--shell-mode", "native_compat", "--shell", &command_shell()])
        .await
        .session();
    let environment = host.tree.environment();
    let mut typist = WorkerTerminal::attach(&environment, session_id, dimensions).await;
    let gate_directory = tempfile::tempdir().expect("a directory on the internal disk");
    let gate = gate_directory.path().join("gate");
    let reader = std::env::current_exe().expect("this test binary");
    typist
        .type_line(&format!(
            "set {MOUSE_READER}=1&& set \"{MOUSE_GATE}={}\"&& \"{}\" --exact \
             a_mouse_event_at_an_attached_console_reaches_the_application_that_asked_for_the_mouse \
             --nocapture --test-threads=1",
            gate.display(),
            reader.display()
        ))
        .await;
    typist
        .shown(
            "kr-mouse-waiting",
            "the application waits to ask for the mouse",
        )
        .await;

    let mut console = Attached::start(&host, &session_id.to_string(), dimensions);
    console.shows(
        "the session's screen",
        |text| text.matches("kr-mouse-waiting").count(),
        1,
    );
    std::fs::write(&gate, b"open").expect("the file the application waits for");
    typist
        .shown(
            "kr-mouse-ready",
            "the application asked for the mouse and said so",
        )
        .await;
    // The command gives the console the mouse before it shows what the application wrote, so a
    // console that shows this has been asked for the mouse.
    console.shows(
        "the application's request for the mouse",
        |text| text.matches("kr-mouse-ready").count(),
        1,
    );
    // A press and its release, as a terminal that reports the mouse sends them.
    console.press(b"\x1b[<0;10;5M");
    console.press(b"\x1b[<0;10;5m");

    let started = Instant::now();
    while !typist.text().contains("kr-mouse-end") {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the mouse event did not reach the application in {:?}: the session shows {:?}; the \
             end of what the outer console shows: {:?}",
            started.elapsed(),
            typist.text(),
            end_of(&console.output.text())
        );
        typist.watch(Duration::from_millis(200)).await;
    }
    // ESC [ < 0 ; 10 ; 5 M and the same ending in m, as hexadecimal.
    let told = typist.text();
    assert!(
        told.contains("kr-mouse:1b5b3c303b31303b354d1b5b3c303b31303b356d;"),
        "the application was told of the press and its release at the cell they were at: {told:?}"
    );

    let _ = console.child.kill();
    drop(typist);
    let closed = host
        .kr(&["--json", "close", &session_id.to_string()], &[])
        .await;
    assert!(
        closed.status.success(),
        "{}",
        String::from_utf8_lossy(&closed.stdout)
    );
}

/// The session half of the test above: gives the console virtual-terminal input as a terminal
/// application does, asks for clicks in the SGR encoding once the gate exists, and prints what it was
/// given as the first two reports, each of which ends in the letter that says whether a button went
/// down or came up.
fn mouse_reader_in_the_session() {
    use kr_cli::platform::ControllingTerminal;

    let gate = PathBuf::from(std::env::var_os(MOUSE_GATE).expect("the file to wait for"));
    let console = ControllingTerminal::open().expect("this process has a console");
    let _modes = console
        .enter_raw_mode()
        .expect("the console is given virtual-terminal input");
    // The console the mode left on does not return the carriage at a line feed, so each line ends
    // with both, and a word is not broken across two rows of the screen.
    print!("kr-mouse-waiting\r\n");
    std::io::stdout().flush().expect("flushes the first word");
    while !gate.exists() {
        std::thread::sleep(Duration::from_millis(20));
    }
    print!("\x1b[?1000h\x1b[?1006hkr-mouse-ready\r\n");
    std::io::stdout().flush().expect("flushes the request");
    let mut input = console.handle();
    let mut seen = Vec::new();
    let mut buffer = [0_u8; 256];
    while seen
        .iter()
        .filter(|byte| matches!(**byte, b'M' | b'm'))
        .count()
        < 2
    {
        let read = input.read(&mut buffer).expect("reads the console's input");
        assert_ne!(read, 0, "the console's input ended");
        seen.extend_from_slice(&buffer[..read]);
    }
    print!("kr-mouse:{};kr-mouse-end\r\n", hex(&seen));
    std::io::stdout().flush().expect("flushes the reports");
}

/// `bytes` as lower-case hexadecimal.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
