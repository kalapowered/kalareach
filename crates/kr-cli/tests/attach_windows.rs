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
        command.env(SPELL_PROBE, "1");
        let child = pty.slave.spawn_command(command).expect("starts the probe");
        drop(pty.slave);
        let writer: Arc<Mutex<Box<dyn Write + Send>>> =
            Arc::new(Mutex::new(pty.master.take_writer().expect("a writer")));
        let output = ConsoleOutput::collect(
            pty.master.try_clone_reader().expect("a reader"),
            Arc::clone(&writer),
        );
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

    /// Waits until the console shows `what`.
    fn waits_for(&mut self, what: &str) {
        let mut ended = false;
        while !self.output.text().contains(what) {
            // A probe that has ended can still have its last lines on their way to this side of the
            // console, so the output is read once more before the end counts against the wait.
            assert!(
                !ended,
                "the probe ended before the console showed {what:?}: {:?}",
                self.output.text()
            );
            ended = self.child.try_wait().expect("the probe's state").is_some();
            assert!(
                self.started.elapsed() < LIVENESS_DEADLINE,
                "waited for the console to show {what:?}: {:?}",
                self.output.text()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
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

/// `bytes` as lower-case hexadecimal.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
