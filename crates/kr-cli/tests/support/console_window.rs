//! A Windows console window for a command test: the command runs on a pseudo-console, and the test
//! sees what the window shows and types into it.
//!
//! A Unix test runs the command in a shell on a pseudo-terminal, and the shell prints the status
//! the command ended with. There is no shell here: the command is the process on the console, and
//! the window puts the same trailer, `kr ended <code>`, after what the command showed, once the
//! command has ended and its output has stopped arriving.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use portable_pty::{ChildKiller, CommandBuilder, PtyPair, PtySize};

/// How long the console's output must stay silent after the command ended before the window says
/// that it ended.
const QUIET: Duration = Duration::from_millis(300);

/// How many quiet periods a window waits for before it says that the command ended anyway.
const QUIET_PERIODS: usize = 20;

/// A console the command runs on, and the person's side of it.
pub struct Opened {
    /// Both ends of the pseudo-console, held for as long as the window is.
    pub terminal: PtyPair,
    /// Ends the command when the window goes.
    pub shell: Box<dyn ChildKiller + Send + Sync>,
    /// Where typed bytes go in.
    pub typing: Box<dyn Write + Send>,
    /// Every byte the console has sent, then the trailer.
    pub seen: Arc<Mutex<Vec<u8>>>,
}

/// Starts `command` on a new pseudo-console.
pub fn open(command: CommandBuilder) -> Opened {
    let terminal = portable_pty::native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 200,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("opens a console");
    let typing = terminal.master.take_writer().expect("a writer");
    let mut child = terminal
        .slave
        .spawn_command(command)
        .expect("starts the command on the console");
    let shell = child.clone_killer();
    let mut reader = terminal.master.try_clone_reader().expect("a reader");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let collected = Arc::clone(&seen);
    std::thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        while let Ok(read) = reader.read(&mut buffer) {
            if read == 0 {
                break;
            }
            collected
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(&buffer[..read]);
        }
    });
    let ended = Arc::clone(&seen);
    std::thread::spawn(move || {
        let code = child.wait().map_or(u32::MAX, |status| status.exit_code());
        let length = || ended.lock().unwrap_or_else(PoisonError::into_inner).len();
        for _ in 0..QUIET_PERIODS {
            let before = length();
            std::thread::sleep(QUIET);
            if length() == before {
                break;
            }
        }
        ended
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(format!("\r\nkr ended {code}\r\n").as_bytes());
    });
    Opened {
        terminal,
        shell,
        typing,
        seen,
    }
}

/// What the console showed, as plain text: the console's control sequences are removed, a cursor
/// move to a column of its own line stands for a line end, and the line ends are made plain.
pub fn plain(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut shown = String::new();
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        if character != '\u{1b}' {
            shown.push(character);
            continue;
        }
        match characters.next() {
            Some('[') => {
                let mut parameters = String::new();
                for next in characters.by_ref() {
                    if ('@'..='~').contains(&next) {
                        // A move to a row and column starts a line, as a line end does.
                        if matches!(next, 'H' | 'f') && !shown.ends_with('\n') {
                            shown.push('\n');
                        }
                        break;
                    }
                    parameters.push(next);
                }
            }
            Some(']') => {
                while let Some(next) = characters.next() {
                    if next == '\u{7}' {
                        break;
                    }
                    if next == '\u{1b}' {
                        characters.next();
                        break;
                    }
                }
            }
            Some('(' | ')' | '*' | '+') => {
                characters.next();
            }
            Some(_) | None => {}
        }
    }
    shown.replace("\r\n", "\n").replace('\r', "")
}
