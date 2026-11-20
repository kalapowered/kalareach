//! The processes of a step that has a time limit.
//!
//! A step with a `timeout` or a `budget` runs each command it starts (its build, the listing of its
//! tests and its run) as the leader of a process group of its own. When the step's time is spent,
//! the report asks the group to end, waits [`GRACE`], and then ends what is left of the group by
//! force: the command and every process it started that is still in the group. A process that
//! left the group by starting a session or a group of its own is not reached.
//!
//! When the time is spent, the report sends both signals before it reaps the command's leader: a
//! leader that has ended and is not reaped still holds the group's number, so no other process can
//! have it while the signals are sent. A command that ends in its time is reaped as it ends and no
//! signal is sent. The report reads the command's pipes to their end first, and waits for the leader
//! after.
//!
//! A step without a limit is run as it always was, in the report's own group, and this module
//! starts nothing for it. Windows has no such group in the standard library, so a step with a limit
//! does not run there and the plan file refuses one.

use std::io;
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::process::{Child, Stdio};
use std::process::{Command, ExitStatus, Output};
#[cfg(unix)]
use std::time::Duration;
use std::time::Instant;

/// How long the processes of a step have to end after they are asked to, before they are ended by
/// force.
#[cfg(unix)]
pub const GRACE: Duration = Duration::from_secs(2);

/// How often a running command is looked at for its end, and its pipes for what they hold.
#[cfg(unix)]
const POLL: Duration = Duration::from_millis(10);

/// How many bytes of a pipe are read at once, so that the deadline, and the end of the grace, are
/// looked at at least as often as that many bytes arrive.
#[cfg(unix)]
const READ_AT_MOST: usize = 64 * 1024;

/// When a step's time is spent.
#[derive(Clone, Copy, Debug)]
pub struct Deadline {
    /// The instant the time is spent.
    pub at: Instant,
    /// The seconds of the limit that is spent then.
    pub seconds: u64,
    /// Whether that limit is a budget's, and not the step's own `timeout`.
    pub budget: bool,
}

/// What a command wrote to its captured pipes before its time was spent.
#[derive(Debug, Default)]
pub struct Captured {
    /// What it wrote to its standard output, when that was captured.
    pub stdout: Vec<u8>,
    /// What it wrote to its standard error, when that was captured.
    pub stderr: Vec<u8>,
}

/// What became of a command that had a deadline.
#[derive(Debug)]
pub enum Waited<T> {
    /// It ended before its time was spent.
    Done(T),
    /// Its time was spent, and its processes were ended. This is what it had written.
    TimedOut(Captured),
    /// Its time was spent before it was due to start, so it was not started.
    NotStarted,
}

/// Runs `command` to its end with its standard output (and its standard error, when the caller set
/// it to a pipe) captured, as [`Command::output`] does, and, when there is a `deadline`, ends its
/// processes when the time is spent.
///
/// # Errors
///
/// Says why the command could not be started or waited for.
pub fn output(command: &mut Command, deadline: Option<Deadline>) -> io::Result<Waited<Output>> {
    match deadline {
        None => command.output().map(Waited::Done),
        Some(deadline) => supervised(command, deadline, true),
    }
}

/// Runs `command` to its end, as [`Command::status`] does, and, when there is a `deadline`, ends
/// its processes when the time is spent.
///
/// # Errors
///
/// Says why the command could not be started or waited for.
pub fn status(command: &mut Command, deadline: Option<Deadline>) -> io::Result<Waited<ExitStatus>> {
    match deadline {
        None => command.status().map(Waited::Done),
        Some(deadline) => Ok(match supervised(command, deadline, false)? {
            Waited::Done(output) => Waited::Done(output.status),
            Waited::TimedOut(captured) => Waited::TimedOut(captured),
            Waited::NotStarted => Waited::NotStarted,
        }),
    }
}

#[cfg(not(unix))]
fn supervised(_: &mut Command, _: Deadline, _: bool) -> io::Result<Waited<Output>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "this platform cannot end the processes of a step",
    ))
}

#[cfg(unix)]
fn supervised(
    command: &mut Command,
    deadline: Deadline,
    capture: bool,
) -> io::Result<Waited<Output>> {
    // The work between one command of a step and the next can take the time that is left: a command
    // whose time is spent is not started.
    if Instant::now() >= deadline.at {
        return Ok(Waited::NotStarted);
    }
    Group::prepare(command);
    if capture {
        command.stdout(Stdio::piped());
    }
    let mut child = command.spawn()?;
    let mut pipes = match Pipes::of(&mut child) {
        Ok(pipes) => pipes,
        Err(error) => {
            Group::end(&mut child, &mut Pipes::none(), GRACE);
            return Err(error);
        }
    };
    // Every pipe is read to its end before the leader is waited for: a leader that is waited for is
    // reaped, and a reaped leader no longer holds the group's number, which the signals at the
    // deadline need it to. The pipes are read in this loop, a pass at a time and none to its end, so
    // that a process that holds one past the command's end holds this loop no longer than the
    // deadline, and nothing is left reading when it returns.
    while pipes.open() {
        match pipes.pass(deadline.at, Instant::now) {
            Pass::Ended => break,
            Pass::Spent => return Ok(Waited::TimedOut(Group::ended(&mut child, pipes))),
            Pass::Open(true) => {}
            Pass::Open(false) => {
                std::thread::sleep(POLL.min(deadline.at.saturating_duration_since(Instant::now())));
            }
        }
    }
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                let now = Instant::now();
                if now >= deadline.at {
                    return Ok(Waited::TimedOut(Group::ended(&mut child, pipes)));
                }
                std::thread::sleep(POLL.min(deadline.at - now));
            }
            // A wait that fails means that the leader is not this report's unreaped child, so no
            // signal is sent: the number could be another process's.
            Err(error) => return Err(error),
        }
    };
    let captured = pipes.into_captured();
    Ok(Waited::Done(Output {
        status,
        stdout: captured.stdout,
        stderr: captured.stderr,
    }))
}

/// What one pass over a running command's pipes found.
#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
enum Pass {
    /// Every pipe is at its end.
    Ended,
    /// A pipe is open and the time is not spent. Whether the pass read anything.
    Open(bool),
    /// A pipe is still open after the time was spent and the pipes were drained.
    Spent,
}

/// The command's captured pipes, each read without waiting.
#[cfg(unix)]
struct Pipes {
    stdout: Pipe,
    stderr: Pipe,
    buffer: Vec<u8>,
}

/// One captured pipe: its read end while it is open, and what has been read from it.
#[cfg(unix)]
struct Pipe {
    fd: Option<OwnedFd>,
    bytes: Vec<u8>,
}

#[cfg(unix)]
impl Pipe {
    fn new(fd: Option<OwnedFd>) -> io::Result<Self> {
        if let Some(fd) = &fd {
            rustix::io::ioctl_fionbio(fd, true)?;
        }
        Ok(Self {
            fd,
            bytes: Vec::new(),
        })
    }

    /// Reads at most `buffer`'s length of what the pipe holds now, without waiting. A pipe that is
    /// at its end, or that cannot be read, is closed. How many bytes it read.
    fn read(&mut self, buffer: &mut [u8]) -> usize {
        let Some(fd) = &self.fd else {
            return 0;
        };
        match rustix::io::read(fd, &mut *buffer) {
            Ok(0) => {
                self.fd = None;
                0
            }
            Ok(count) => {
                self.bytes.extend_from_slice(&buffer[..count]);
                count
            }
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => 0,
            Err(_) => {
                self.fd = None;
                0
            }
        }
    }

    /// Reads what the pipe holds at this moment, in pieces of at most `buffer`'s length, and then
    /// once more for the end of the pipe. The count of queued bytes is taken once, before the reads,
    /// so a process that goes on writing cannot extend this: it adds at most one piece.
    fn drain(&mut self, buffer: &mut [u8]) {
        let Some(fd) = &self.fd else {
            return;
        };
        let mut queued = rustix::io::ioctl_fionread(fd).unwrap_or(0);
        while queued > 0 {
            let piece =
                usize::try_from(queued).map_or(buffer.len(), |queued| queued.min(buffer.len()));
            let count = self.read(&mut buffer[..piece]);
            if count == 0 {
                break;
            }
            queued = queued.saturating_sub(u64::try_from(count).unwrap_or(u64::MAX));
        }
        self.read(buffer);
    }
}

#[cfg(unix)]
impl Pipes {
    fn of(child: &mut Child) -> io::Result<Self> {
        Ok(Self {
            stdout: Pipe::new(child.stdout.take().map(OwnedFd::from))?,
            stderr: Pipe::new(child.stderr.take().map(OwnedFd::from))?,
            buffer: vec![0; READ_AT_MOST],
        })
    }

    /// No pipe: a command whose pipes could not be read.
    fn none() -> Self {
        Self {
            stdout: Pipe {
                fd: None,
                bytes: Vec::new(),
            },
            stderr: Pipe {
                fd: None,
                bytes: Vec::new(),
            },
            buffer: Vec::new(),
        }
    }

    /// Whether a pipe is still open.
    fn open(&self) -> bool {
        self.stdout.fd.is_some() || self.stderr.fd.is_some()
    }

    /// Reads once from each open pipe, at most [`READ_AT_MOST`] bytes from each, without waiting.
    /// Whether either gave anything.
    fn read(&mut self) -> bool {
        let out = self.stdout.read(&mut self.buffer);
        let err = self.stderr.read(&mut self.buffer);
        out + err > 0
    }

    /// One pass: reads once from each open pipe, and, when that leaves a pipe open, looks at the
    /// clock, which `clock` gives after the read. When the time `deadline` is spent a command may
    /// have written its last bytes and ended in the interval since the last pass, with the end of
    /// its pipes not yet read, so the pipes are drained before the time is read as spent. The read
    /// is of at most [`READ_AT_MOST`] bytes a pipe, and the drain of the bytes queued when it begins
    /// and one piece more, so a process that goes on writing does not extend the pass.
    fn pass(&mut self, deadline: Instant, clock: impl FnOnce() -> Instant) -> Pass {
        let read = self.read();
        if !self.open() {
            return Pass::Ended;
        }
        if clock() < deadline {
            return Pass::Open(read);
        }
        self.drain();
        if self.open() {
            Pass::Spent
        } else {
            Pass::Ended
        }
    }

    /// Reads what each open pipe holds at this moment, and looks for its end.
    fn drain(&mut self) {
        self.stdout.drain(&mut self.buffer);
        self.stderr.drain(&mut self.buffer);
    }

    fn into_captured(self) -> Captured {
        Captured {
            stdout: self.stdout.bytes,
            stderr: self.stderr.bytes,
        }
    }
}

/// The process group a step's command leads: the signals the report sends go to it, and to no other
/// process.
#[cfg(unix)]
struct Group;

#[cfg(unix)]
impl Group {
    /// Makes `command` the leader of a new group when it is started.
    fn prepare(command: &mut Command) {
        std::os::unix::process::CommandExt::process_group(command, 0);
    }

    /// Ends the group `child` leads: asks it to end, waits `grace`, ends what is left by force
    /// whether or not `child` is, and reaps `child`. Until it is reaped `child` holds the group's
    /// number even when it has ended, so the signals go to this group and to no other.
    ///
    /// The pipes are read through the grace, so that a process that writes more than a pipe holds as
    /// it ends is not blocked on its write, and then once they are drained of what the processes
    /// that were ended left in them. A pass reads at most [`READ_AT_MOST`] bytes from a pipe and the
    /// passes end with the grace, whatever a process that goes on writing adds; the drain reads the
    /// bytes queued when it begins.
    fn end(child: &mut Child, pipes: &mut Pipes, grace: Duration) {
        let _ = rustix::process::kill_process_group(
            rustix::process::Pid::from_child(child),
            rustix::process::Signal::TERM,
        );
        let until = Instant::now() + grace;
        loop {
            let now = Instant::now();
            if now >= until {
                break;
            }
            if !pipes.read() {
                std::thread::sleep(POLL.min(until - now));
            }
        }
        let _ = rustix::process::kill_process_group(
            rustix::process::Pid::from_child(child),
            rustix::process::Signal::KILL,
        );
        let _ = child.wait();
        pipes.drain();
    }

    /// [`Group::end`] with the [`GRACE`], and what the pipes held when the processes had ended. The
    /// pipes are closed when this returns, so a process that is outside the group and holds one is
    /// not read from again and cannot grow what the report keeps.
    fn ended(child: &mut Child, mut pipes: Pipes) -> Captured {
        Self::end(child, &mut pipes, GRACE);
        pipes.into_captured()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::Write;

    use super::*;

    /// KR-REQ-29.01, the part about reproducible commands: the bytes queued in a pipe when the
    /// processes that wrote them were ended are all read, however many pieces of the buffer's length
    /// they make: 1 KiB read in pieces of 16 bytes is 64 pieces, more than any fixed number of reads
    /// that the report could make. The writer still holds the pipe, so the pipe stays open.
    #[test]
    fn a_drain_reads_every_queued_byte_whatever_the_length_of_its_pieces() {
        let (reader, mut writer) = std::io::pipe().expect("a pipe");
        writer.write_all(&[7; 1024]).expect("a write");
        let mut pipe = Pipe::new(Some(OwnedFd::from(reader))).expect("a pipe to read");
        pipe.drain(&mut [0; 16]);
        assert_eq!(pipe.bytes.len(), 1024);
        assert!(pipe.fd.is_some(), "the writer holds the pipe open");
    }

    /// KR-REQ-29.01, the part about reproducible commands: what a command had written when the group
    /// was killed, and not yet read, is kept, though the grace is no time at all: the pipes are
    /// drained after the leader is waited for.
    #[test]
    fn what_the_pipes_hold_when_the_group_is_killed_and_reaped_is_kept() {
        let mut command = Command::new("bash");
        command
            .args(["-c", "printf queued; sleep 30"])
            .stdin(Stdio::null());
        Group::prepare(&mut command);
        command.stdout(Stdio::piped());
        let mut leader = Leader(Some(command.spawn().expect("a command")));
        let mut pipes = Pipes::of(leader.child()).expect("pipes");
        // Waits for the bytes for 30 s at most, and ends the group whether or not they came: the
        // case asserts after, and a failed assertion leaves nothing.
        let until = Instant::now() + Duration::from_secs(30);
        let queued = loop {
            let held = pipes
                .stdout
                .fd
                .as_ref()
                .is_some_and(|fd| rustix::io::ioctl_fionread(fd).unwrap_or(0) > 0);
            if held || Instant::now() >= until {
                break held;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        leader.end(&mut pipes);
        assert!(queued, "the command wrote nothing");
        assert_eq!(pipes.into_captured().stdout, b"queued");
    }

    /// The leader of a group a case started: owned until it is ended. [`Leader::end`] ends the group
    /// and reaps the leader, once; a leader that is dropped without that is ended, so that a case
    /// that fails before it ends the group leaves none. The leader is unreaped until its last
    /// signal, so the number is its own.
    struct Leader(Option<Child>);

    impl Leader {
        fn child(&mut self) -> &mut Child {
            self.0.as_mut().expect("the leader is owned")
        }

        fn end(&mut self, pipes: &mut Pipes) {
            if let Some(mut child) = self.0.take() {
                Group::end(&mut child, pipes, Duration::ZERO);
            }
        }
    }

    impl Drop for Leader {
        fn drop(&mut self) {
            self.end(&mut Pipes::none());
        }
    }

    /// The pipes of a pass: standard output is `reader`, standard error is not captured.
    fn pipes_of(reader: std::io::PipeReader) -> Pipes {
        Pipes {
            stdout: Pipe::new(Some(OwnedFd::from(reader))).expect("a pipe to read"),
            stderr: Pipe {
                fd: None,
                bytes: Vec::new(),
            },
            buffer: vec![0; 64],
        }
    }

    /// KR-REQ-29.01, the part about reproducible commands: a command that writes its last byte and
    /// ends in the last interval before the deadline is not read as out of time. The pass that
    /// reads the byte is at the deadline, and the read does not see the end of the pipe, so the
    /// pass drains the pipe before it decides.
    #[test]
    fn a_command_that_wrote_its_last_byte_and_ended_by_the_deadline_is_not_out_of_time() {
        let (reader, mut writer) = std::io::pipe().expect("a pipe");
        writer.write_all(b"x").expect("a write");
        drop(writer);
        let mut pipes = pipes_of(reader);
        let at = Instant::now();
        assert_eq!(pipes.pass(at, || at), Pass::Ended);
        assert_eq!(pipes.stdout.bytes, b"x");
    }

    /// KR-REQ-29.01, the part about reproducible commands: a pipe that a process still holds at the
    /// deadline is out of time, after the pipe is drained of what it holds, and before the deadline
    /// the pass goes on.
    #[test]
    fn a_pipe_that_a_process_holds_at_the_deadline_is_out_of_time_and_before_it_is_open() {
        let (reader, mut writer) = std::io::pipe().expect("a pipe");
        writer.write_all(b"x").expect("a write");
        let mut pipes = pipes_of(reader);
        let at = Instant::now();
        assert_eq!(
            pipes.pass(at + Duration::from_secs(60), Instant::now),
            Pass::Open(true)
        );
        writer.write_all(b"yz").expect("a write");
        assert_eq!(pipes.pass(at, || at), Pass::Spent);
        assert_eq!(pipes.stdout.bytes, b"xyz");
    }
}
