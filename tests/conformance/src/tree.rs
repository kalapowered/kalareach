//! The processes of a step that has a time limit.
//!
//! A step with a `timeout` or a `budget` runs each command it starts (its build, the listing of its
//! tests and its run) as the leader of a process group of its own. When the step's time is spent,
//! the report asks the group to end, waits [`GRACE`], and then ends what is left of the group by
//! force: the command and every process it started that is still in the group. A process that
//! left the group by starting a session or a group of its own is not reached.
//!
//! The command's leader is not reaped before the group is ended: a leader that has ended and is not
//! reaped still holds the group's number, so no other process can have it while the signals are
//! sent. The report reads the command's pipes to their end first, and waits for the leader after.
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

/// How many bytes of a pipe are read at once, so that the deadline is looked at at least as often as
/// that many bytes arrive.
#[cfg(unix)]
const READ_AT_MOST: usize = 64 * 1024;

/// How many times the pipes are read for what is left in them after the processes were ended: what
/// a process of the command wrote as it ended, and no more than a process that is outside the
/// group and still writes can add.
#[cfg(unix)]
const LAST_READS: usize = 16;

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
    /// Its time was spent, and its processes were ended, or it was not started. This is what it
    /// had written.
    TimedOut(Captured),
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
        return Ok(Waited::TimedOut(Captured::default()));
    }
    Group::prepare(command);
    if capture {
        command.stdout(Stdio::piped());
    }
    let mut child = command.spawn()?;
    let mut pipes = match Pipes::of(&mut child) {
        Ok(pipes) => pipes,
        Err(error) => {
            Group::end(&mut child);
            return Err(error);
        }
    };
    // Every pipe is read to its end before the leader is waited for: a leader that is waited for is
    // reaped, and a reaped leader no longer holds the group's number, which the signals at the
    // deadline need it to. The pipes are read in this loop, a pass at a time and none to its end, so
    // that a process that holds one past the command's end holds this loop no longer than the
    // deadline, and nothing is left reading when it returns.
    while pipes.open() {
        let read = pipes.read();
        if !pipes.open() {
            break;
        }
        let now = Instant::now();
        if now >= deadline.at {
            return Ok(Waited::TimedOut(Group::ended(&mut child, pipes)));
        }
        if !read {
            std::thread::sleep(POLL.min(deadline.at - now));
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
            Err(error) => {
                Group::end(&mut child);
                return Err(error);
            }
        }
    };
    let captured = pipes.into_captured();
    Ok(Waited::Done(Output {
        status,
        stdout: captured.stdout,
        stderr: captured.stderr,
    }))
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

    /// Reads at most `buffer`'s length of what the pipe holds now. A pipe that is at its end, or
    /// that cannot be read, is closed. Whether it read anything.
    fn read(&mut self, buffer: &mut [u8]) -> bool {
        let Some(fd) = &self.fd else {
            return false;
        };
        match rustix::io::read(fd, &mut *buffer) {
            Ok(0) => {
                self.fd = None;
                false
            }
            Ok(count) => {
                self.bytes.extend_from_slice(&buffer[..count]);
                true
            }
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => false,
            Err(_) => {
                self.fd = None;
                false
            }
        }
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

    /// Whether a pipe is still open.
    fn open(&self) -> bool {
        self.stdout.fd.is_some() || self.stderr.fd.is_some()
    }

    /// Reads once from each open pipe. Whether either gave anything.
    fn read(&mut self) -> bool {
        let out = self.stdout.read(&mut self.buffer);
        let err = self.stderr.read(&mut self.buffer);
        out || err
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

    /// Ends the group `child` leads: asks it to end, waits [`GRACE`], ends what is left by force
    /// whether or not `child` is, and reaps `child`. Until it is reaped `child` holds the group's
    /// number even when it has ended, so the signals go to this group and to no other.
    fn end(child: &mut Child) {
        let _ = rustix::process::kill_process_group(
            rustix::process::Pid::from_child(child),
            rustix::process::Signal::TERM,
        );
        std::thread::sleep(GRACE);
        let _ = rustix::process::kill_process_group(
            rustix::process::Pid::from_child(child),
            rustix::process::Signal::KILL,
        );
        let _ = child.wait();
    }

    /// [`Group::end`], and what the pipes held when the processes had ended. The pipes are closed
    /// when this returns, so a process that is outside the group and holds one is not read from
    /// again and cannot grow what the report keeps.
    fn ended(child: &mut Child, mut pipes: Pipes) -> Captured {
        Self::end(child);
        for _ in 0..LAST_READS {
            if !pipes.read() {
                break;
            }
        }
        pipes.into_captured()
    }
}
