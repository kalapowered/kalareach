//! The Windows console's binding of the silent read, in a real pseudo-console.
//!
//! The test starts itself as a child inside a pseudo-console and types at it. The child reads the
//! console's input mode, reads a key the way `kr voice credential set` does, and reads the mode
//! again; the parent holds what the child printed against what it typed. The control is a child
//! that reads a line plainly, which the console echoes, so the parent shows it can see an echo.
//! No provider is contacted and no real key is used.

#![cfg(windows)]

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kr_cli::platform::ControllingTerminal;
use kr_cli::secret_input::read_silently;
use kr_cli::secret_input::windows::Console;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};

/// The variable that makes this program the child, and says which read it does.
const CHILD: &str = "KR_SECRET_INPUT_CHILD";

/// This case's own name, which the child is started on.
const CASE: &str = "the_windows_console_binding_clears_echo_and_restores_the_mode";

/// A value no real key has.
const SENTINEL: &str = "kr-test-voice-key-0123456789abcdef";

const DEADLINE: Duration = Duration::from_secs(60);

/// What the child does: prints the console's input mode, reads, prints the mode and the outcome.
fn child(read: &str) {
    let terminal = ControllingTerminal::open().expect("the child has a console");
    let before = terminal.modes().expect("reads the modes").input;
    println!("MODE-BEFORE {before}");
    std::io::stdout().flush().expect("flushes");
    let outcome = if read == "echo" {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map(|_| "ok".to_owned())
            .map_err(|error| error.to_string())
    } else {
        read_silently(&Console::open().expect("opens the console"))
            .map(|key| format!("ok {}", key.expose().len()))
            .map_err(|error| error.to_string())
    };
    let after = terminal.modes().expect("reads the modes").input;
    println!("MODE-AFTER {after}");
    match outcome {
        Ok(said) => println!("RESULT {said}"),
        Err(said) => println!("RESULT err {said}"),
    }
    std::io::stdout().flush().expect("flushes");
}

fn number_after(text: &str, marker: &str) -> u32 {
    text.split(marker)
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|word| word.parse().ok())
        .unwrap_or_else(|| panic!("{marker} is in what the child printed: {text:?}"))
}

/// Runs the child on a new pseudo-console, types `keys` once it has printed its mode, and returns
/// everything it printed.
fn run(read: &str, keys: &str) -> String {
    let pty = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("opens a pseudo-console");
    let seen = Arc::new(Mutex::new(Vec::<u8>::new()));
    let mut reader = pty.master.try_clone_reader().expect("a reader");
    let mut writer = pty.master.take_writer().expect("a writer");
    let into = Arc::clone(&seen);
    std::thread::spawn(move || {
        let mut chunk = [0_u8; 1024];
        while let Ok(taken) = reader.read(&mut chunk) {
            if taken == 0 {
                break;
            }
            into.lock()
                .expect("not poisoned")
                .extend_from_slice(&chunk[..taken]);
        }
    });
    let text = || String::from_utf8_lossy(&seen.lock().expect("not poisoned")).into_owned();
    let mut builder = CommandBuilder::new(std::env::current_exe().expect("this program"));
    builder.args([CASE, "--exact", "--nocapture", "--test-threads=1"]);
    builder.env(CHILD, read);
    let mut process = pty.slave.spawn_command(builder).expect("starts the child");
    let started = Instant::now();
    let mut answered = false;
    while !text().contains("MODE-BEFORE ") {
        // A pseudo-console asks where the cursor is when it starts; it is told once.
        if !answered && text().contains("\x1b[6n") {
            writer.write_all(b"\x1b[1;1R").expect("answers");
            answered = true;
        }
        assert!(
            started.elapsed() < DEADLINE,
            "the child printed its mode: {:?}",
            text()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // The child is waiting for the key by the time its mode has been read twice over.
    std::thread::sleep(Duration::from_millis(500));
    writer.write_all(keys.as_bytes()).expect("types");
    writer.flush().expect("types");
    while !text().contains("RESULT ") {
        assert!(
            started.elapsed() < DEADLINE,
            "the child gave a result: {:?}",
            text()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    process.wait().expect("the child ends");
    text()
}

#[test]
fn the_windows_console_binding_clears_echo_and_restores_the_mode() {
    if let Ok(read) = std::env::var(CHILD) {
        child(&read);
        return;
    }

    // The control: a plain read shows the typed key to the pseudo-console's output.
    let echoed = run("echo", &format!("{SENTINEL}\r"));
    assert!(
        echoed.contains(SENTINEL),
        "the harness sees an echoed key: {echoed:?}"
    );

    // A silent read takes the key, shows none of it, and leaves the mode as it found it.
    let read = run("silent", &format!("{SENTINEL}\r"));
    assert!(!read.contains(SENTINEL), "the key was shown: {read:?}");
    assert!(
        read.contains(&format!("RESULT ok {}", SENTINEL.len())),
        "{read:?}"
    );
    assert_eq!(
        number_after(&read, "MODE-AFTER "),
        number_after(&read, "MODE-BEFORE "),
        "the mode is back after a read: {read:?}"
    );

    // Ctrl+C is a key: it ends the read, shows no key, and the mode is back.
    let cancelled = run("silent", &format!("{SENTINEL}\x03"));
    assert!(
        !cancelled.contains(SENTINEL),
        "the key was shown: {cancelled:?}"
    );
    assert!(
        cancelled.contains("RESULT err key entry was cancelled"),
        "{cancelled:?}"
    );
    assert_eq!(
        number_after(&cancelled, "MODE-AFTER "),
        number_after(&cancelled, "MODE-BEFORE "),
        "the mode is back after Ctrl+C: {cancelled:?}"
    );
}
