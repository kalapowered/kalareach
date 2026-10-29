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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kr_protocol::session::Dimensions;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};

mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;
mod windows_session;

use support::kr;
use windows_session::{LIVENESS_DEADLINE, WorkerHost, WorkerTerminal};

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
}

impl ConsoleOutput {
    fn collect(
        mut reader: Box<dyn Read + Send>,
        writer: Arc<Mutex<Box<dyn Write + Send>>>,
    ) -> Self {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&seen);
        std::thread::spawn(move || {
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
        });
        Self { seen }
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
        let child = pty.slave.spawn_command(command).expect("starts kr");
        drop(pty.slave);
        let writer: Arc<Mutex<Box<dyn Write + Send>>> =
            Arc::new(Mutex::new(pty.master.take_writer().expect("a writer")));
        let output = ConsoleOutput::collect(
            pty.master.try_clone_reader().expect("a reader"),
            Arc::clone(&writer),
        );
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

    /// Waits until `count` finds at least `times` of what it counts in the console's output; it
    /// fails when it does not within the liveness deadline, or when the command ends before it
    /// does.
    fn shows(&mut self, what: &str, count: impl Fn(&str) -> usize, times: usize) {
        let started = Instant::now();
        loop {
            let text = self.output.text();
            if count(&text) >= times {
                return;
            }
            if let Some(status) = self.child.try_wait().expect("the command's state") {
                panic!(
                    "{what}: kr attach ended ({status}) before the console showed it {times} \
                     time(s); the console shows: {text:?}"
                );
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "{what}: waited {:?} for the console to show it {times} time(s); the console \
                 shows: {text:?}",
                started.elapsed(),
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Whether the command is still running.
    fn running(&mut self) -> bool {
        self.child
            .try_wait()
            .expect("the command's state")
            .is_none()
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
/// call, key releases included, and prints what each was. The console that `kr attach` runs in is
/// written the four in separate writes, which is how a person's key presses reach a console: Shift
/// going down, the letter going down, the letter coming up, Shift coming up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_releases_and_modifiers_of_an_attached_console_reach_the_application_one_by_one() {
    let host = WorkerHost::start().await;
    let (mut typist, session_id, dimensions) = session_waiting_for_keys(
        &host,
        "Write-Host ('kr-rea' + 'dy.'); \
         $seen = @(); \
         for ($i = 0; $i -lt 4; $i++) { \
           $key = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown,IncludeKeyUp'); \
           $seen += ('{0}{1}' -f $key.VirtualKeyCode, $(if ($key.KeyDown) { 'd' } else { 'u' })) }; \
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
