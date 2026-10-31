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
/// of [`a_console_asked_to_spell_its_keys_hands_the_reader_bytes_where_it_handed_records`].
const SPELL_PROBE: &str = "KR_ATTACH_SPELL_PROBE";

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
/// key, which the console keeps as records that make no text, and the probe stops the reader and
/// reads one more key itself: a reader left in a read of the console, or cancelled in the middle of
/// one, leaves a pending read behind, and the console gives that read the next key.
#[test]
fn a_console_asked_to_spell_its_keys_hands_the_reader_bytes_where_it_handed_records() {
    if std::env::var_os(SPELL_PROBE).is_some() {
        spell_probe_in_the_console();
        return;
    }

    let pty = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("opens a console");
    let mut command = CommandBuilder::new(std::env::current_exe().expect("this test binary"));
    command.args([
        "--exact",
        "a_console_asked_to_spell_its_keys_hands_the_reader_bytes_where_it_handed_records",
        "--nocapture",
        "--test-threads=1",
    ]);
    command.env(SPELL_PROBE, "1");
    let mut child = pty.slave.spawn_command(command).expect("starts the probe");
    drop(pty.slave);
    let writer: Arc<Mutex<Box<dyn Write + Send>>> =
        Arc::new(Mutex::new(pty.master.take_writer().expect("a writer")));
    let output = ConsoleOutput::collect(
        pty.master.try_clone_reader().expect("a reader"),
        Arc::clone(&writer),
    );
    let press = |bytes: &[u8]| {
        let mut keyboard = writer.lock().expect("the console input is not poisoned");
        keyboard.write_all(bytes).expect("writes the console input");
        keyboard.flush().expect("flushes the console input");
    };
    let started = Instant::now();
    let waits_for = |what: &str, child: &mut Box<dyn portable_pty::Child + Send + Sync>| {
        let mut ended = false;
        while !output.text().contains(what) {
            // A probe that has ended can still have its last lines on their way to this side of the
            // console, so the output is read once more before the end counts against the wait.
            assert!(
                !ended,
                "the probe ended before the console showed {what:?}: {:?}",
                output.text()
            );
            ended = child.try_wait().expect("the probe's state").is_some();
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "waited for the console to show {what:?}: {:?}",
                output.text()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    };

    waits_for("kr-probe:ready", &mut child);
    // The letter A, going down and coming up, as a console is written a key.
    press(b"\x1b[65;30;97;1;0;1_");
    press(b"\x1b[65;30;97;0;0;1_");
    waits_for("kr-probe:switched", &mut child);
    let before = output.text();
    assert!(
        before.contains("kr-probe:key:65:97:down"),
        "the letter was read as the record it is before the console spelled anything: {before:?}"
    );
    // The up arrow, Ctrl+Space, the letter A held down (one record that says it repeated three
    // times), Ctrl+Z, an `é` and the letter B, each going down and coming up.
    press(b"\x1b[38;72;0;1;0;1_");
    press(b"\x1b[38;72;0;0;0;1_");
    press(b"\x1b[32;57;32;1;8;1_");
    press(b"\x1b[32;57;32;0;8;1_");
    press(b"\x1b[65;30;97;1;0;3_");
    press(b"\x1b[65;30;97;0;0;1_");
    press(b"\x1b[90;44;26;1;8;1_");
    press(b"\x1b[90;44;26;0;8;1_");
    press(b"\x1b[69;18;233;1;0;1_");
    press(b"\x1b[69;18;233;0;0;1_");
    press(b"\x1b[66;48;98;1;0;1_");
    press(b"\x1b[66;48;98;0;0;1_");
    waits_for("kr-probe:bytes:", &mut child);
    // Ctrl+Space as the only key the console holds. The console keeps it as a key going down with no
    // character, which a read of the console's text passes over unless the reader has told it apart
    // from a modifier: a reader that took it off the queue with the records that make no text never
    // sends its byte, and the person's key is gone.
    press(b"\x1b[32;57;32;1;8;1_");
    press(b"\x1b[32;57;32;0;8;1_");
    waits_for("kr-probe:alone:", &mut child);
    // Ctrl on its own, and the Apps key, once the reader has the letter: the console keeps each as a
    // key going down and coming up that make no text, and a read of the console's text would wait
    // for the next key. (Behind the letter in the same burst they are taken by the read that
    // returns it.) The probe stops the reader once the console has been quiet for a second and
    // holds nothing more.
    press(b"\x1b[17;29;0;1;8;1_");
    press(b"\x1b[17;29;0;0;0;1_");
    press(b"\x1b[93;93;0;1;256;1_");
    press(b"\x1b[93;93;0;0;256;1_");
    waits_for("kr-probe:stopped", &mut child);
    // The reader has been stopped, so this key is the process's own to read. A reader left in its
    // read of the console's bytes would take it.
    press(b"\x1b[67;46;99;1;0;1_");
    press(b"\x1b[67;46;99;0;0;1_");
    waits_for("kr-probe:done", &mut child);
    let shown = output.text();
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
        after.contains("kr-probe:stopped:ended"),
        "the stop saw the reader end: {after:?}"
    );
    assert!(
        after.contains("kr-probe:next:63"),
        "the key typed after the reader was stopped reached the process and not the reader: {after:?}"
    );
}

/// The console half of the test above, run in a console of its own.
fn spell_probe_in_the_console() {
    use kr_cli::attach::{TerminalInput, spawn_input_reader};
    use kr_cli::platform::ControllingTerminal;

    let console = ControllingTerminal::open().expect("this process has a console");
    let _saved = console
        .enter_record_mode()
        .expect("the console takes record mode");
    let switch = console.input_switch().expect("a switch over the console");
    let handle = console.handle().try_clone().expect("a handle on the input");
    let (mut input, stop) = spawn_input_reader(handle, &switch).expect("the reader starts");
    let deadline = Instant::now() + LIVENESS_DEADLINE;
    let mut next = || loop {
        match input.try_recv() {
            Ok(read) => return read,
            Err(_) => {
                assert!(Instant::now() < deadline, "the console gave no input");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    };
    println!("kr-probe:ready");
    // Records until the letter comes up.
    loop {
        match next() {
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
    switch.engage().expect("the console spells its keys");
    println!("kr-probe:switched");
    // Whatever comes next is read until the last letter has: the arrow's three bytes, a NUL, the
    // letters of the held key, Ctrl+Z, the two bytes of `é` and the letter after.
    let mut spelled = Vec::new();
    while !spelled.ends_with(b"b") {
        match next() {
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
        match next() {
            TerminalInput::Bytes(bytes) => alone.extend(bytes),
            TerminalInput::Keys(keys) => {
                for key in keys {
                    println!("kr-probe:key:{}:{}", key.virtual_key, key.unicode);
                }
            }
        }
    }
    println!("kr-probe:alone:{}", hex(&alone));
    // The test now presses Ctrl on its own and the Apps key. The reader is stopped once the console
    // has been quiet for a second and holds no input, which is when the reader has seen them.
    let waiting = kr_cli::windows::records::RecordReader::over(
        console
            .handle()
            .try_clone()
            .expect("a handle to count with"),
    );
    let quiet_from = Instant::now();
    while quiet_from.elapsed() < Duration::from_millis(1000) || waiting.waiting().unwrap_or(1) != 0
    {
        assert!(
            quiet_from.elapsed() < LIVENESS_DEADLINE,
            "the console never held no input"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let stopped = stop.stop();
    println!(
        "kr-probe:stopped:{}",
        if stopped.still_running {
            "running"
        } else {
            "ended"
        }
    );
    let mut next = [0_u8; 1];
    let mut input_handle = console.handle();
    input_handle
        .read_exact(&mut next)
        .expect("the console hands the process the next key");
    println!("kr-probe:next:{}", hex(&next));
    println!("kr-probe:done");
}

/// `bytes` as lower-case hexadecimal.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
