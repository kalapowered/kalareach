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

/// The highest number of the numbered lines the session prints that `text` shows.
fn ticks(text: &str) -> u64 {
    text.split("tick-")
        .skip(1)
        .filter_map(|piece| {
            piece
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse::<u64>()
                .ok()
        })
        .max()
        .unwrap_or(0)
}

/// `kr attach` running on a pseudo-console of its own.
struct Attached {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    output: ConsoleOutput,
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
            _master: pty.master,
        }
    }

    /// Waits until the console shows a numbered line higher than `above`, and returns its number;
    /// it fails when the console does not within the liveness deadline, or when the command ends
    /// before it does.
    fn shows_a_line_after(&mut self, above: u64, what: &str) -> u64 {
        let started = Instant::now();
        loop {
            let text = self.output.text();
            let shown = ticks(&text);
            if shown > above {
                return shown;
            }
            if let Some(status) = self.child.try_wait().expect("the command's state") {
                panic!(
                    "{what}: kr attach ended ({status}) before the console showed a line after \
                     {above}; the console shows: {text:?}"
                );
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "{what}: waited {:?} for a line after {above}; the console shows: {text:?}",
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
/// A session whose root shell is the Windows command shell is typed a program that prints a
/// numbered line every moment, through the client library, and `kr attach` runs on a pseudo-console
/// of its own, of the session's size so that the worker streams what the session writes as it is
/// written. The console shows a line the session printed after the console was opened, and then
/// twenty lines more, and the command is still attached after both. A command that wrote to the
/// input handle would show none and would end at the first byte it was sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_console_attached_with_kr_attach_shows_what_the_session_writes() {
    let host = WorkerHost::start().await;
    let (session_id, dimensions) = host
        .kr_new(&["--shell-mode", "native_compat", "--shell", &command_shell()])
        .await
        .session();
    let environment = host.tree.environment();
    let mut typist = WorkerTerminal::attach(&environment, session_id, dimensions).await;
    // The line the shell echoes holds the number as typed, `%i`, and no digits: only what the
    // program prints holds a number.
    typist
        .type_line("for /l %i in (1,1,100000) do @(echo tick-%i & ping -n 1 127.0.0.1 >nul)")
        .await;
    typist
        .shown("tick-1", "the session prints the program's first line")
        .await;
    let printed = ticks(&typist.text());

    let mut console = Attached::start(&host, &session_id.to_string(), dimensions);
    let first = console.shows_a_line_after(printed, "a line the session printed after");
    let later = console.shows_a_line_after(first + 20, "twenty lines more");
    assert!(
        console.running(),
        "kr attach ended after the console showed lines {first} to {later}; the console shows: {:?}",
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
