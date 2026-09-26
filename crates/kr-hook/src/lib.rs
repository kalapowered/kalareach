//! `kr-hook`: the core forwarder a native bridge runs.
//!
//! Section 11 prefers "a small registration file plus the core `kr-hook` forwarder" for an
//! application that needs a bridge beside its unchanged terminal. A plugin package installs the
//! registration into the application's own documented plugin or hook location, or, for an
//! application that reads hooks from the settings its launch is given, the launch passes the
//! registration and nothing is installed. Either way the application then starts this forwarder
//! itself, under its own permissions and outside Wasmtime, and the forwarder carries what the
//! application says to the KalaReach worker that owns the session.
//!
//! The forwarder decides nothing about authority. It finds the registration the worker published
//! for the launch, presents the launch's private exchange and its own process identity, and
//! declares which bridge it is. The worker checks every part of that against the process it
//! launched and the installation it recorded, and refuses the connection otherwise.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`cli`] | The accepted invocations and the exit codes |
//! | [`registration`] | Finding and reading the launch's registration, and the hello |
//! | [`exchange`] | The private exchange with the worker: admission and bounded JSON lines |
//! | [`hook`] | One observing hook, whichever application started it: prompt, neutral, and never a decision |
//! | [`claude_code`] | Claude Code's bridge: its Channels server and what its hooks report |
//! | [`gemini_cli`] | Gemini CLI's bridge: what its hooks report |
//! | [`qoder_cli`] | Qoder CLI's bridge: what its hooks report |
//! | [`launch`] | The launcher an integrated invocation presents itself to its backend through |
//! | [`relay`] | The byte relay a launched agent reaches its worker through |

pub mod claude_code;
pub mod cli;
pub mod exchange;
pub mod gemini_cli;
pub mod hook;
pub mod launch;
pub mod qoder_cli;
pub mod registration;
pub mod relay;

/// Runs one parsed invocation and returns the exit code it ends with.
#[must_use]
pub fn run(command: cli::Command) -> std::process::ExitCode {
    match command {
        cli::Command::ClaudeCode {
            surface: cli::ClaudeCode::Hook,
        } => hook::run(&claude_code::HOOKS),
        cli::Command::ClaudeCode {
            surface: cli::ClaudeCode::Channel,
        } => claude_code::channel::run(),
        cli::Command::GeminiCli {
            surface: cli::Hooks::Hook,
        } => hook::run(&gemini_cli::HOOKS),
        cli::Command::QoderCli {
            surface: cli::Hooks::Hook,
        } => hook::run(&qoder_cli::HOOKS),
        cli::Command::Launch {
            hold_after_admission,
            hold_before_exec,
            invocation,
        } => launch::run(
            &invocation,
            hold_after_admission.map(std::time::Duration::from_millis),
            hold_before_exec.as_deref(),
        ),
        cli::Command::Relay { close_after_hello } => match relay::run(close_after_hello) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(failure) => {
                report(&failure);
                std::process::ExitCode::from(cli::EXIT_FAILURE)
            }
        },
    }
}

/// Writes one diagnostic line to standard error.
///
/// Standard error is where a person debugging reads what happened. For a hook that exits 0,
/// Claude Code and Qoder CLI write it to their logs and show it to nobody, and Gemini CLI reads it
/// only when standard output is empty, which a hook's never is, so it cannot reach the model or
/// change what the application does.
///
/// The write waits for as long as standard error makes it wait. A process that must answer by a
/// deadline answers first and says what went wrong through [`report_by`]. The launcher says what it
/// has to say this way, before it runs the program, which on Unix takes the launcher's place so
/// that nothing of the launcher is left to say it afterwards. No deadline applies to the launcher:
/// the shell waits for the program as it waits for any command.
pub fn report(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr().lock(), "kr-hook: {line}");
}

/// Writes one diagnostic line to standard error, and waits for the write no later than `by`.
///
/// A standard error nobody reads fills up, and a write to a full one waits until somebody reads.
/// A terminal, a file or a pipe another process writes to can make a write wait too, even one
/// that had room a moment before. So the write is made on a thread of its own, and the caller goes
/// on at `by` whether the write has finished or not. A write still waiting when the process ends
/// ends with it, and its line is lost: with nothing left before `by`, the line is written only if
/// that thread gets to it before the process ends.
pub fn report_by(line: &str, by: std::time::Instant) {
    write_by(format!("kr-hook: {line}\n").into_bytes(), by, |bytes| {
        use std::io::Write as _;
        let _ = std::io::stderr().lock().write_all(bytes);
    });
}

/// How many diagnostic lines [`Reports`] holds while its writer waits on standard error.
pub const QUEUED_REPORTS: usize = 64;

/// Diagnostic lines for a process that serves for as long as its session runs.
///
/// [`report`] waits for as long as standard error makes it wait, which a process that answers once
/// and ends can afford. A server cannot: a standard error nobody reads fills up, and the first
/// report after that would stop the thread that serves. So a line here is handed to a queue of
/// [`QUEUED_REPORTS`] lines without waiting, and one writer thread of its own writes them, in
/// order. A line that finds the queue full is dropped and counted, and the writer says how many
/// were dropped once it can write again. Whatever reports never waits on standard error.
pub struct Reports {
    shared: std::sync::Arc<Shared>,
}

/// The writer of one [`Reports`], which its process waits for, for a bounded time, before it ends.
pub struct ReportWriter {
    done: std::sync::mpsc::Receiver<()>,
}

/// What reporters and the writer share.
struct Shared {
    queue: std::sync::Mutex<Queue>,
    /// Signalled when the queue takes a line or the last reporter goes.
    changed: std::sync::Condvar,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// What waits to be written, and how many lines could not wait.
///
/// Both are one value under one lock, so the writer's next step is decided from the two at once:
/// what it says about dropped lines always comes after every line that was queued before them.
#[derive(Default)]
struct Queue {
    entries: std::collections::VecDeque<Entry>,
    /// How many lines are waiting, not counting the counts between them.
    lines: usize,
    /// How many lines were dropped since the last one the queue took.
    dropped: u64,
    /// How many [`Reports`] handles are still there. The writer ends once none is and nothing is
    /// left to write.
    reporters: usize,
}

/// One thing the writer says.
enum Entry {
    Line(String),
    /// How many lines were dropped between the line before this and the line after it.
    Dropped(u64),
}

impl Queue {
    /// Takes a line, or counts it as dropped when [`QUEUED_REPORTS`] lines are already waiting. A
    /// line taken after some were dropped is preceded by their count, which so sits where they
    /// were. Returns whether it was taken.
    fn push(&mut self, line: String) -> bool {
        if self.lines >= QUEUED_REPORTS {
            self.dropped += 1;
            return false;
        }
        if self.dropped > 0 {
            self.entries
                .push_back(Entry::Dropped(std::mem::take(&mut self.dropped)));
        }
        self.entries.push_back(Entry::Line(line));
        self.lines += 1;
        true
    }

    /// The next thing to write: the oldest waiting entry, or, once none is left, how many lines
    /// were dropped since the last one the queue took.
    fn next(&mut self) -> Option<Entry> {
        match self.entries.pop_front() {
            Some(entry) => {
                if matches!(entry, Entry::Line(_)) {
                    self.lines -= 1;
                }
                Some(entry)
            }
            None => (self.dropped > 0).then(|| Entry::Dropped(std::mem::take(&mut self.dropped))),
        }
    }
}

impl Entry {
    fn text(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Self::Line(line) => std::borrow::Cow::Borrowed(line),
            Self::Dropped(count) => std::borrow::Cow::Owned(dropped_notice(*count)),
        }
    }
}

impl Reports {
    /// Starts the writer, on standard error.
    #[must_use]
    pub fn to_standard_error() -> (Self, ReportWriter) {
        Self::start(|bytes| {
            use std::io::Write as _;
            let _ = std::io::stderr().lock().write_all(bytes);
        })
    }

    /// Starts the writer, with `write` in place of standard error.
    ///
    /// A thread that cannot be started writes nothing: a diagnostic never costs the caller its
    /// work.
    fn start(mut write: impl FnMut(&[u8]) + Send + 'static) -> (Self, ReportWriter) {
        let shared = std::sync::Arc::new(Shared {
            queue: std::sync::Mutex::new(Queue {
                reporters: 1,
                ..Queue::default()
            }),
            changed: std::sync::Condvar::new(),
        });
        let (finished, done) = std::sync::mpsc::channel();
        let writing = std::sync::Arc::clone(&shared);
        let _ = std::thread::Builder::new()
            .name("kr-hook reports".to_owned())
            .spawn(move || {
                let mut queue = writing.lock();
                loop {
                    if let Some(entry) = queue.next() {
                        // Written without the lock, so a reporter never waits on standard error.
                        drop(queue);
                        write(entry.text().as_bytes());
                        queue = writing.lock();
                    } else if queue.reporters == 0 {
                        break;
                    } else {
                        queue = writing
                            .changed
                            .wait(queue)
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                    }
                }
                drop(queue);
                let _ = finished.send(());
            });
        (Self { shared }, ReportWriter { done })
    }

    /// Hands one line to the writer without waiting, or drops and counts it when the queue is full.
    pub fn report(&self, line: &str) {
        let taken = self.shared.lock().push(format!("kr-hook: {line}\n"));
        if taken {
            self.shared.changed.notify_one();
        }
    }
}

impl Clone for Reports {
    fn clone(&self) -> Self {
        self.shared.lock().reporters += 1;
        Self {
            shared: std::sync::Arc::clone(&self.shared),
        }
    }
}

impl Drop for Reports {
    fn drop(&mut self) {
        let mut queue = self.shared.lock();
        queue.reporters -= 1;
        if queue.reporters == 0 {
            drop(queue);
            self.shared.changed.notify_one();
        }
    }
}

impl ReportWriter {
    /// Waits, no later than `by`, for the writer to write what was reported and end.
    ///
    /// The writer ends once every [`Reports`] is gone and it has written what they queued. A write
    /// still waiting on standard error at `by` ends with the process, and its lines are lost.
    pub fn finish(self, by: std::time::Instant) {
        let _ = self
            .done
            .recv_timeout(by.saturating_duration_since(std::time::Instant::now()));
    }
}

/// What the writer says about lines it never saw.
fn dropped_notice(count: u64) -> String {
    if count == 1 {
        "kr-hook: 1 report was dropped because standard error was not being read\n".to_owned()
    } else {
        format!("kr-hook: {count} reports were dropped because standard error was not being read\n")
    }
}

/// Hands `bytes` to `write` on a thread of its own, and waits for it no later than `by`.
///
/// A thread that cannot be started writes nothing: a diagnostic never costs the caller its
/// answer.
fn write_by(bytes: Vec<u8>, by: std::time::Instant, write: impl FnOnce(&[u8]) + Send + 'static) {
    let (written, done) = std::sync::mpsc::channel();
    let started = std::thread::Builder::new().spawn(move || {
        write(&bytes);
        let _ = written.send(());
    });
    if started.is_ok() {
        let _ = done.recv_timeout(by.saturating_duration_since(std::time::Instant::now()));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::*;

    /// A write that never finishes, at any point in it, holds its caller no later than the bound.
    #[test]
    fn a_write_that_stalls_holds_its_caller_only_until_the_bound() {
        let (release, stalled) = std::sync::mpsc::channel::<()>();
        let begun = Instant::now();
        write_by(
            b"a line".to_vec(),
            begun + Duration::from_millis(100),
            move |_| {
                // Stalls until the test lets it go, which is after the caller has gone on, or for
                // half a minute, so a caller that waited for it fails rather than hangs.
                let _ = stalled.recv_timeout(Duration::from_secs(30));
            },
        );
        let took = begun.elapsed();
        drop(release);
        assert!(took >= Duration::from_millis(100), "{took:?}");
        assert!(took < Duration::from_secs(10), "{took:?}");
    }

    /// The control: a write that finishes is waited for, and gets the whole line.
    #[test]
    fn a_write_that_finishes_is_waited_for() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let into = Arc::clone(&written);
        write_by(
            b"kr-hook: a line\n".to_vec(),
            Instant::now() + Duration::from_secs(60),
            move |bytes| {
                into.lock().expect("the buffer").extend_from_slice(bytes);
            },
        );
        assert_eq!(
            written.lock().expect("the buffer").as_slice(),
            b"kr-hook: a line\n"
        );
    }

    /// A writer that stalls holds nobody who reports. The queue takes what it holds, the lines
    /// after that are dropped and counted, and once the writer can write again it writes the
    /// queued lines in order and says how many were dropped before the next line.
    #[test]
    fn a_writer_that_stalls_holds_no_report_and_says_what_it_dropped() {
        const DROPPED: usize = 10;
        let written = Arc::new(Mutex::new(Vec::<String>::new()));
        let into = Arc::clone(&written);
        let (stalling, stalled) = std::sync::mpsc::channel::<()>();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let mut first = true;
        let (reports, writer) = Reports::start(move |bytes| {
            if first {
                first = false;
                let _ = stalling.send(());
                // Until the test lets it go, or for half a minute, so a report that waited for it
                // fails rather than hangs.
                let _ = released.recv_timeout(Duration::from_secs(30));
            }
            into.lock()
                .expect("the lines")
                .push(String::from_utf8_lossy(bytes).into_owned());
        });
        reports.report("line 0");
        stalled
            .recv_timeout(Duration::from_secs(30))
            .expect("the writer is writing the first line");
        let begun = Instant::now();
        for index in 1..=QUEUED_REPORTS + DROPPED {
            reports.report(&format!("line {index}"));
        }
        let took = begun.elapsed();
        drop(release);
        assert!(took < Duration::from_secs(10), "a report waited: {took:?}");
        // The writer catches up with the queue, and the next line carries the count.
        let deadline = Instant::now() + Duration::from_secs(60);
        while written.lock().expect("the lines").len() < 1 + QUEUED_REPORTS {
            assert!(Instant::now() < deadline, "the queued lines were written");
            std::thread::sleep(Duration::from_millis(5));
        }
        reports.report("after");
        drop(reports);
        writer.finish(Instant::now() + Duration::from_secs(60));

        let mut expected: Vec<String> = (0..=QUEUED_REPORTS)
            .map(|index| format!("kr-hook: line {index}\n"))
            .collect();
        expected.push(format!(
            "kr-hook: {DROPPED} reports were dropped because standard error was not being read\n"
        ));
        expected.push("kr-hook: after\n".to_owned());
        assert_eq!(*written.lock().expect("the lines"), expected);
    }

    /// The count is said as soon as the writer has caught up with the queue, while whatever
    /// reports is still there and has nothing more to say.
    #[test]
    fn a_writer_that_catches_up_says_what_it_dropped_without_waiting_for_another_line() {
        const DROPPED: usize = 3;
        let written = Arc::new(Mutex::new(Vec::<String>::new()));
        let into = Arc::clone(&written);
        let (stalling, stalled) = std::sync::mpsc::channel::<()>();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let mut first = true;
        let (reports, writer) = Reports::start(move |bytes| {
            if first {
                first = false;
                let _ = stalling.send(());
                let _ = released.recv_timeout(Duration::from_secs(30));
            }
            into.lock()
                .expect("the lines")
                .push(String::from_utf8_lossy(bytes).into_owned());
        });
        reports.report("line 0");
        stalled
            .recv_timeout(Duration::from_secs(30))
            .expect("the writer is writing the first line");
        for index in 1..=QUEUED_REPORTS + DROPPED {
            reports.report(&format!("line {index}"));
        }
        drop(release);
        let notice = format!(
            "kr-hook: {DROPPED} reports were dropped because standard error was not being read\n"
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        while written.lock().expect("the lines").last() != Some(&notice) {
            assert!(
                Instant::now() < deadline,
                "the count was said while nothing more was reported: {:?}",
                written.lock().expect("the lines").last()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(written.lock().expect("the lines").len(), QUEUED_REPORTS + 2);
        drop(reports);
        writer.finish(Instant::now() + Duration::from_secs(60));
        assert_eq!(
            written.lock().expect("the lines").len(),
            QUEUED_REPORTS + 2,
            "and nothing more when the writer ends"
        );
    }

    /// The writer's next step is decided from the queue and the count at once, so whatever the
    /// timing, the count of dropped lines is said after every line queued before them: here after
    /// a burst that fills the queue once the writer has found it empty, and between the lines on
    /// either side of the drops when the queue took a line again.
    #[test]
    fn the_count_of_dropped_lines_is_said_where_they_were_dropped() {
        let text = |entry: Entry| entry.text().into_owned();
        let mut queue = Queue::default();
        assert!(queue.push("line 0".to_owned()));
        assert_eq!(queue.next().map(text), Some("line 0".to_owned()));
        assert!(queue.next().is_none(), "the writer finds the queue empty");
        for index in 1..=QUEUED_REPORTS {
            assert!(queue.push(format!("line {index}")));
        }
        assert!(
            !queue.push("dropped".to_owned()),
            "a full queue drops a line"
        );
        let mut said: Vec<String> = std::iter::from_fn(|| queue.next()).map(text).collect();
        let mut expected: Vec<String> = (1..=QUEUED_REPORTS)
            .map(|index| format!("line {index}"))
            .collect();
        expected.push(dropped_notice(1));
        assert_eq!(said, expected);

        for index in 0..QUEUED_REPORTS {
            assert!(queue.push(format!("line {index}")));
        }
        for _ in 0..3 {
            assert!(!queue.push("dropped".to_owned()));
        }
        assert_eq!(queue.next().map(text), Some("line 0".to_owned()));
        assert!(
            queue.push("after".to_owned()),
            "the queue took a line again"
        );
        said = std::iter::from_fn(|| queue.next()).map(text).collect();
        assert_eq!(said.len(), QUEUED_REPORTS + 1);
        assert_eq!(
            said[QUEUED_REPORTS - 2],
            format!("line {}", QUEUED_REPORTS - 1)
        );
        assert_eq!(said[QUEUED_REPORTS - 1], dropped_notice(3));
        assert_eq!(said[QUEUED_REPORTS], "after");
    }

    /// Lines dropped after the last one queued are counted when the writer ends.
    #[test]
    fn lines_dropped_last_are_counted_when_the_writer_ends() {
        let written = Arc::new(Mutex::new(Vec::<String>::new()));
        let into = Arc::clone(&written);
        let (stalling, stalled) = std::sync::mpsc::channel::<()>();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let mut first = true;
        let (reports, writer) = Reports::start(move |bytes| {
            if first {
                first = false;
                let _ = stalling.send(());
                let _ = released.recv_timeout(Duration::from_secs(30));
            }
            into.lock()
                .expect("the lines")
                .push(String::from_utf8_lossy(bytes).into_owned());
        });
        reports.report("line 0");
        stalled
            .recv_timeout(Duration::from_secs(30))
            .expect("the writer is writing the first line");
        for index in 1..=QUEUED_REPORTS + 1 {
            reports.report(&format!("line {index}"));
        }
        drop(reports);
        drop(release);
        writer.finish(Instant::now() + Duration::from_secs(60));
        let written = written.lock().expect("the lines");
        assert_eq!(written.len(), QUEUED_REPORTS + 2, "{written:?}");
        assert_eq!(
            written.last().map(String::as_str),
            Some("kr-hook: 1 report was dropped because standard error was not being read\n")
        );
    }

    /// The control: a writer that keeps up gets every line, in order, and no notice.
    #[test]
    fn a_writer_that_keeps_up_gets_every_line_in_order() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let into = Arc::clone(&written);
        let (reports, writer) = Reports::start(move |bytes| {
            into.lock().expect("the buffer").extend_from_slice(bytes);
        });
        // No more than the queue holds, so none is dropped however late the writer starts.
        for index in 0..QUEUED_REPORTS {
            reports.report(&format!("line {index}"));
        }
        drop(reports);
        writer.finish(Instant::now() + Duration::from_secs(60));
        let expected: String = (0..QUEUED_REPORTS)
            .map(|index| format!("kr-hook: line {index}\n"))
            .collect();
        assert_eq!(
            String::from_utf8_lossy(&written.lock().expect("the buffer")),
            expected
        );
    }

    /// With nothing left before the bound, the caller does not wait at all.
    #[test]
    fn a_bound_already_passed_is_not_waited_for() {
        let (release, stalled) = std::sync::mpsc::channel::<()>();
        let begun = Instant::now();
        write_by(b"a line".to_vec(), begun, move |_| {
            let _ = stalled.recv_timeout(Duration::from_secs(30));
        });
        let took = begun.elapsed();
        drop(release);
        assert!(took < Duration::from_secs(10), "{took:?}");
    }
}
