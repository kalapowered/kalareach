//! A terminal window: `kr` on a pseudo-terminal of its own, as it runs in a person's terminal.
//!
//! The command is the session leader of the terminal and the terminal is its controlling one, so
//! whatever `kr` asks of "the terminal" is this one: the owner's ceremony reads what is typed here,
//! an attachment puts it into raw mode and must put it back. Everything the terminal is sent is
//! collected by a thread that never holds the leg up, and the leg waits on what it expects with a
//! bound.

use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use portable_pty::{CommandBuilder, PtySize, native_pty_system};

use crate::LIVENESS;
use crate::run::Run;
use crate::screen::Terminal;

/// What a terminal that implements both keyboard protocols answers `kr`'s capability queries with,
/// ending with the device attributes that close the exchange.
pub const PROBE_ANSWER: &[u8] = b"\x1b[?5u\x1b[>4;2m\x1b[?62;22c";

/// The size every window has.
pub const COLUMNS: u16 = 100;

/// The rows every window has.
pub const ROWS: u16 = 30;

/// The writing end of a window's terminal, shared by whoever types into it.
type Keys = Arc<Mutex<Box<dyn Write + Send>>>;

/// What a window has been sent, and the replies it owes the questions its program asks.
#[derive(Debug, Default)]
struct Transcript {
    bytes: Vec<u8>,
    owed: Vec<Owed>,
    /// Set when the terminal's output has ended, so that nothing more will be sent to it.
    ended: bool,
}

impl Transcript {
    /// Takes the replies whose question has arrived, leaving the rest owed.
    fn take_due(&mut self) -> Vec<Owed> {
        let (due, waiting) = std::mem::take(&mut self.owed)
            .into_iter()
            .partition(|owed| owed.is_due(&self.bytes));
        self.owed = waiting;
        due
    }
}

/// A reply a terminal types the moment the question it answers has arrived.
#[derive(Debug)]
struct Owed {
    mark: usize,
    question: &'static [u8],
    reply: &'static [u8],
    typed: std::sync::mpsc::Sender<bool>,
}

impl Owed {
    /// Whether the question is among the bytes sent since the mark.
    fn is_due(&self, sent: &[u8]) -> bool {
        sent.get(self.mark..)
            .is_some_and(|since| contains(since, self.question))
    }

    /// Types the reply, and says whether the terminal took it.
    fn type_into(self, keys: &Keys) {
        let mut keys = keys.lock().unwrap_or_else(PoisonError::into_inner);
        let typed = keys
            .write_all(self.reply)
            .and_then(|()| keys.flush())
            .is_ok();
        let _ = self.typed.send(typed);
    }
}

/// A reply a window owes, which [`answered`] waits for.
#[derive(Debug)]
pub struct Answering(std::sync::mpsc::Receiver<bool>);

/// Everything a terminal has been sent, collected by a thread of its own.
///
/// The same thread types the replies a window owes. A question with a deadline of its own, as the
/// capability exchange has, is answered by the thread that finds it in the stream rather than by
/// one that looks for it from time to time: a thread that sleeps between looks is woken late on a
/// machine under load, and the question's time runs out while it sleeps.
#[derive(Clone, Debug, Default)]
pub struct Collected {
    seen: Arc<Mutex<Transcript>>,
}

impl Collected {
    fn collect(mut reader: Box<dyn Read + Send>, keys: Keys) -> Self {
        let collected = Self::default();
        let seen = Arc::clone(&collected.seen);
        std::thread::spawn(move || {
            let mut buffer = [0_u8; 8192];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                let due = {
                    let mut transcript = seen.lock().unwrap_or_else(PoisonError::into_inner);
                    transcript.bytes.extend_from_slice(&buffer[..read]);
                    transcript.take_due()
                };
                for owed in due {
                    owed.type_into(&keys);
                }
            }
            // Once the output has ended a question that has not come is not going to: whoever
            // waits for its reply is told so, and so is whoever asks to wait after this.
            let mut transcript = seen.lock().unwrap_or_else(PoisonError::into_inner);
            transcript.ended = true;
            transcript.owed.clear();
        });
        collected
    }

    /// Types `reply` the moment `question` is among the bytes sent since `mark`, or at once when
    /// it already is.
    fn reply_to(
        &self,
        mark: usize,
        question: &'static [u8],
        reply: &'static [u8],
        keys: &Keys,
    ) -> Answering {
        let (typed, outcome) = std::sync::mpsc::channel();
        let owed = Owed {
            mark,
            question,
            reply,
            typed,
        };
        let mut transcript = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        if owed.is_due(&transcript.bytes) {
            drop(transcript);
            owed.type_into(keys);
        } else if !transcript.ended {
            transcript.owed.push(owed);
        }
        Answering(outcome)
    }

    /// How much has been sent so far. A later wait can start from here.
    #[must_use]
    pub fn mark(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .bytes
            .len()
    }

    /// What has been sent since a mark.
    #[must_use]
    pub fn since(&self, mark: usize) -> Vec<u8> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .bytes
            .get(mark..)
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    }
}

/// One window.
pub struct Window {
    what: String,
    /// Whether what the window was sent stays out of failure messages, because it carries an
    /// invitation's secret.
    withheld: bool,
    pair: portable_pty::PtyPair,
    child: Box<dyn portable_pty::Child + Send + Sync>,
    collected: Collected,
    keys: Keys,
}

impl std::fmt::Debug for Window {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Window")
            .field("what", &self.what)
            .finish_non_exhaustive()
    }
}

impl Window {
    /// Opens a window running `program` with `arguments`, in `directory`, with exactly
    /// `variables` in its environment.
    ///
    /// The process is recorded with the run, so the closing check knows it.
    ///
    /// # Panics
    ///
    /// Panics when the terminal cannot be opened or the program cannot start.
    #[must_use]
    pub fn open(
        run: &Run,
        what: &str,
        program: &Path,
        arguments: &[&str],
        directory: &Path,
        variables: &[(String, String)],
    ) -> Self {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: ROWS,
                cols: COLUMNS,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("opens a terminal");
        let mut command = CommandBuilder::new(program);
        command.args(arguments);
        command.env_clear();
        for (name, value) in variables {
            command.env(name, value);
        }
        command.cwd(directory);
        let child = pair
            .slave
            .spawn_command(command)
            .unwrap_or_else(|error| panic!("{what} could not start: {error}"));
        if let Some(pid) = child.process_id() {
            run.record_child(pid, what);
        }
        let keys: Keys = Arc::new(Mutex::new(pair.master.take_writer().expect("a writer")));
        let collected = Collected::collect(
            pair.master.try_clone_reader().expect("a reader"),
            Arc::clone(&keys),
        );
        Self {
            what: what.to_owned(),
            withheld: false,
            pair,
            child,
            collected,
            keys,
        }
    }

    /// Keeps what this window is sent out of every failure message, for a window that shows an
    /// invitation's secret.
    #[must_use]
    pub const fn withholding_output(mut self) -> Self {
        self.withheld = true;
        self
    }

    /// What a failure message may say about what the window was sent since `mark`.
    fn shown(&self, mark: usize) -> String {
        let since = self.collected.since(mark);
        if self.withheld {
            format!(
                "{} bytes, withheld because they carry an invitation",
                since.len()
            )
        } else {
            String::from_utf8_lossy(&since).escape_debug().to_string()
        }
    }

    /// What the terminal has been sent.
    #[must_use]
    pub fn collected(&self) -> &Collected {
        &self.collected
    }

    /// How much has been sent so far.
    #[must_use]
    pub fn mark(&self) -> usize {
        self.collected.mark()
    }

    /// Types into the window.
    ///
    /// # Panics
    ///
    /// Panics when the terminal cannot be written.
    pub fn type_text(&self, bytes: &[u8]) {
        let mut keys = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        keys.write_all(bytes).expect("types into the terminal");
        keys.flush().expect("and it reaches the terminal");
    }

    /// Waits for `needle` to arrive after `mark`, and returns everything sent since `mark`.
    ///
    /// # Panics
    ///
    /// Panics with what did arrive when it does not within [`LIVENESS`].
    #[must_use]
    pub fn wait_for(&self, mark: usize, needle: &[u8], why: &str) -> Vec<u8> {
        let started = Instant::now();
        loop {
            let since = self.collected.since(mark);
            if contains(&since, needle) {
                return since;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "{why}: {} waited {:?} for {:?} and was sent: {}",
                self.what,
                started.elapsed(),
                String::from_utf8_lossy(needle),
                self.shown(mark)
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The screen this window shows now, as text: everything it was sent, read through the
    /// product's own terminal engine at the window's size.
    #[must_use]
    pub fn screen(&self) -> Vec<String> {
        let mut terminal = Terminal::new(COLUMNS, ROWS);
        terminal.feed(&self.collected.since(0));
        terminal.rows()
    }

    /// Waits until the screen this window shows carries `needle`, and returns that screen.
    ///
    /// What `kr` writes to its terminal is a screen it paints, not the session's own bytes: a
    /// blank at the end of a line may arrive as a cursor movement rather than as a space. So what
    /// is waited on is what a person would read.
    ///
    /// # Panics
    ///
    /// Panics with the screen when `needle` has not appeared within [`LIVENESS`].
    #[must_use]
    pub fn wait_for_screen(&self, needle: &str, why: &str) -> Vec<String> {
        let started = Instant::now();
        loop {
            let rows = self.screen();
            if rows.iter().any(|row| row.contains(needle)) {
                return rows;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "{why}: {} waited {:?} for {needle:?}, and its screen is:\n{}",
                self.what,
                started.elapsed(),
                if self.withheld {
                    self.shown(0)
                } else {
                    rows.join("\n")
                }
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Answers the next capability exchange `kr` starts on this terminal after `mark`: the
    /// exchange has one second in all, so the answer is typed by the thread that collects what the
    /// terminal is sent, the moment the question that ends the exchange arrives.
    #[must_use]
    pub fn answer_capability_queries(&self, mark: usize) -> Answering {
        self.collected
            .reply_to(mark, b"\x1b[c", PROBE_ANSWER, &self.keys)
    }

    /// Waits for the program to exit, and returns its status.
    ///
    /// # Panics
    ///
    /// Panics when it has not exited within `within`, with what it was sent.
    #[must_use]
    pub fn exit_code(&mut self, within: Duration) -> u32 {
        let started = Instant::now();
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                return status.exit_code();
            }
            assert!(
                started.elapsed() < within,
                "{} did not exit within {within:?}: {}",
                self.what,
                self.shown(0)
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Whether the terminal is in line mode with echo, which is how `kr` found it and how an
    /// attachment must leave it. The modes are the kernel's, read from the terminal device.
    #[must_use]
    pub fn in_line_mode(&self) -> bool {
        let Some(device) = self.pair.master.tty_name() else {
            return false;
        };
        // Opened without becoming anybody's controlling terminal, and without waiting on it.
        let flags = rustix::fs::OFlags::NOCTTY | rustix::fs::OFlags::NONBLOCK;
        let Ok(terminal) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(i32::try_from(flags.bits()).unwrap_or_default())
            .open(&device)
        else {
            return false;
        };
        rustix::termios::tcgetattr(&terminal).is_ok_and(|modes| {
            modes
                .local_modes
                .contains(rustix::termios::LocalModes::ICANON)
                && modes
                    .local_modes
                    .contains(rustix::termios::LocalModes::ECHO)
        })
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

/// Whether `needle` occurs in `haystack`.
#[must_use]
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Waits for the reply to a window's capability queries to be typed.
///
/// # Panics
///
/// Panics with what the window was sent when `kr` never asked, the answer could not be typed, the
/// window's output ended without the question, or the question did not come within [`LIVENESS`].
pub fn answered(window: &Window, queries: Answering) {
    assert!(
        queries.0.recv_timeout(LIVENESS).unwrap_or(false),
        "{}: kr never asked this terminal what it is, or the answer could not be typed; the \
         terminal was sent: {}",
        window.what,
        window.shown(0)
    );
}
