//! The processes of a step that has a time limit.
//!
//! A step with a `timeout` or a `budget` runs each command it starts (its build, the listing of its
//! tests and its run) as the leader of a process group of its own. When the step's time is spent,
//! the report asks the group to end, waits [`GRACE`], and then ends what is left of the group by
//! force: the command and every process it started that is still in the group. A process that
//! left the group by starting one of its own is not reached.
//!
//! A step without a limit is run as it always was, in the report's own group, and this module
//! starts nothing for it. Windows has no such group in the standard library, so a step with a limit
//! does not run there and the plan file refuses one.

use std::io;
#[cfg(unix)]
use std::process::{Child, Stdio};
use std::process::{Command, ExitStatus, Output};
#[cfg(unix)]
use std::sync::mpsc;
#[cfg(unix)]
use std::time::Duration;
use std::time::Instant;

/// How long the processes of a step have to end after they are asked to, before they are ended by
/// force.
#[cfg(unix)]
pub const GRACE: Duration = Duration::from_secs(2);

/// How often a running command is looked at for its end.
#[cfg(unix)]
const POLL: Duration = Duration::from_millis(10);

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

/// What became of a command that had a deadline.
#[derive(Debug)]
pub enum Waited<T> {
    /// It ended before its time was spent.
    Done(T),
    /// Its time was spent, and its processes were ended.
    TimedOut,
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
            Waited::TimedOut => Waited::TimedOut,
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
        return Ok(Waited::TimedOut);
    }
    Group::prepare(command);
    if capture {
        command.stdout(Stdio::piped());
    }
    let mut child = command.spawn()?;
    let group = Group::of(&child);
    // Each pipe is read on a thread of its own, so a command that writes a great deal does not wait
    // for this one, and a pipe that a process holds open past the command's end cannot hold this
    // one past the deadline.
    let (sender, receiver) = mpsc::channel::<(bool, Vec<u8>)>();
    let mut pipes = 0;
    if let Some(pipe) = child.stdout.take() {
        pipes += 1;
        read_on_a_thread(pipe, true, sender.clone());
    }
    if let Some(pipe) = child.stderr.take() {
        pipes += 1;
        read_on_a_thread(pipe, false, sender.clone());
    }
    drop(sender);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                let now = Instant::now();
                if now >= deadline.at {
                    group.end(Some(&mut child));
                    return Ok(Waited::TimedOut);
                }
                std::thread::sleep(POLL.min(deadline.at - now));
            }
            Err(error) => {
                group.end(Some(&mut child));
                return Err(error);
            }
        }
    };
    let mut collected = Output {
        status,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    for _ in 0..pipes {
        let left = deadline.at.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(left) {
            Ok((true, bytes)) => collected.stdout = bytes,
            Ok((false, bytes)) => collected.stderr = bytes,
            Err(_) => {
                // The command ended, and a process of its group still holds a pipe it wrote to.
                group.end(None);
                return Ok(Waited::TimedOut);
            }
        }
    }
    Ok(Waited::Done(collected))
}

#[cfg(unix)]
fn read_on_a_thread(
    mut pipe: impl io::Read + Send + 'static,
    standard_output: bool,
    sender: mpsc::Sender<(bool, Vec<u8>)>,
) {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = pipe.read_to_end(&mut bytes);
        let _ = sender.send((standard_output, bytes));
    });
}

/// The process group a step's command leads: the one signal the report sends goes to it, and to no
/// other process.
#[cfg(unix)]
struct Group {
    leader: rustix::process::Pid,
}

#[cfg(unix)]
impl Group {
    /// Makes `command` the leader of a new group when it is started.
    fn prepare(command: &mut Command) {
        std::os::unix::process::CommandExt::process_group(command, 0);
    }

    /// The group `child` leads, which [`Group::prepare`] made.
    fn of(child: &Child) -> Self {
        Self {
            leader: rustix::process::Pid::from_child(child),
        }
    }

    /// Ends the group: asks it to end, waits [`GRACE`] without reaping its leader (a leader that
    /// has ended and is not reaped still holds the group's number, so the number is not another
    /// process's), ends what is left by force whether or not the leader is, and reaps `leader`.
    fn end(&self, leader: Option<&mut Child>) {
        let _ = rustix::process::kill_process_group(self.leader, rustix::process::Signal::TERM);
        std::thread::sleep(GRACE);
        let _ = rustix::process::kill_process_group(self.leader, rustix::process::Signal::KILL);
        if let Some(leader) = leader {
            let _ = leader.wait();
        }
    }
}
