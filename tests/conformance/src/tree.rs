//! The processes of a step that has a time limit.
//!
//! A step with a `timeout` or a `budget` runs each command it starts (its build, the listing of its
//! tests and its run) as the leader of a process group of its own. When the step's time is spent,
//! the report asks the group to end, waits `GRACE`, and then ends what is left of the group by
//! force: the command and every process it started that is still in the group. A process that
//! left the group by starting a session or a group of its own is not reached.
//!
//! When the time is spent, the report sends both signals before it reaps the command's leader: a
//! leader that has ended and is not reaped still holds the group's number, so no other process can
//! have it while the signals are sent. A command that ends in its time is reaped as it ends and no
//! signal is sent. The report reads the command's pipes to their end first, and waits for the leader
//! after.
//!
//! An interrupt (INT) or a termination request (TERM) that reaches the report while one of those
//! commands runs is sent on to the command's group, because the terminal sends Ctrl-C to its own
//! foreground group and the command's group is not that. The report then ends the group as it does
//! at the deadline, except that the signal it received is the one it asks with: it waits `GRACE`,
//! ends what is left by force and reaps the leader. The command is `Waited::Interrupted`, and the
//! report starts no later command. The handlers are set the first time a command with a limit is
//! started, and stay: while no such command runs, a signal has its default action, as it has
//! without them.
//!
//! A step without a limit is run as it always was, in the report's own group, and this module
//! starts nothing for it. Windows has no such group in the standard library, so a step with a limit
//! does not run there and the plan file refuses one; a step there is in the console's group, which
//! Ctrl-C reaches.

use std::io;
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::process::{Child, Stdio};
use std::process::{Command, ExitStatus, Output};
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(unix)]
use std::sync::{Arc, OnceLock};
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
    /// The report was sent the signal of this number (INT or TERM) while the command ran or before
    /// it was due to start, and the command's processes were ended. This is what it had written,
    /// which is nothing when it was not started.
    Interrupted(Captured, i32),
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
            Waited::Interrupted(captured, signal) => Waited::Interrupted(captured, signal),
        }),
    }
}

/// Why the trial of the host failed.
#[derive(Debug)]
pub enum Trial {
    /// The command of the trial could not be started.
    Start(io::Error),
    /// The command was started and could not be waited for.
    Wait(io::Error),
}

/// Whether this process can wait for a command it starts, which the time limits rely on. A process
/// that ignores `SIGCHLD` cannot, on Linux: the system reaps its children as they end, so a wait
/// fails, and the signals at a deadline could go to a group whose leader the system has already
/// reaped. The question is asked of `/bin/sh -c :`, a command that does nothing.
///
/// # Errors
///
/// Says whether the command could not be started or could not be waited for, and why.
#[cfg(unix)]
pub fn waits_for_its_commands() -> Result<(), Trial> {
    waited_for("/bin/sh", Child::wait)
}

/// [`waits_for_its_commands`] with `program` as the command's program and `wait` as the wait.
#[cfg(unix)]
fn waited_for(
    program: &str,
    wait: impl FnOnce(&mut Child) -> io::Result<ExitStatus>,
) -> Result<(), Trial> {
    let mut child = Command::new(program)
        .args(["-c", ":"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(Trial::Start)?;
    wait(&mut child).map(drop).map_err(Trial::Wait)
}

/// Where no step with a limit runs, no trial is needed.
///
/// # Errors
///
/// Never.
#[cfg(not(unix))]
pub fn waits_for_its_commands() -> Result<(), Trial> {
    Ok(())
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
    supervise(command, deadline, capture, Group::arm()?, || {})
}

/// [`supervised`] with the `interrupts` it reads and holds, which a unit can give, and `between`,
/// which runs once the command's watch is over and before the supervised phase closes: a signal
/// that a unit records there is one that the watch's last read did not find.
#[cfg(unix)]
fn supervise(
    command: &mut Command,
    deadline: Deadline,
    capture: bool,
    interrupts: &Interrupts,
    between: impl FnOnce(),
) -> io::Result<Waited<Output>> {
    // While this guard is held a signal is recorded and sent on to the command's group, and no
    // longer has its default action.
    let running = Running::begin(interrupts);
    // A signal that reached the report since the last command means that no later command starts.
    if let Some(signal) = interrupts.signal() {
        return Ok(Waited::Interrupted(Captured::default(), signal));
    }
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
    let waited = watch(&mut child, deadline, Child::try_wait, || {
        interrupts.signal()
    })?;
    between();
    // The phase closes before the last read: a signal after this has its default action, and one
    // before it, which the watch's last read did not find, was recorded and is found now. The
    // leader is reaped by then, so no signal goes to the group (its number could be another
    // process's), and a command that ended is stopped all the same.
    drop(running);
    match waited {
        Waited::Done(output) => match interrupts.signal() {
            Some(signal) => Ok(Waited::Interrupted(
                Captured {
                    stdout: output.stdout,
                    stderr: output.stderr,
                },
                signal,
            )),
            None => Ok(Waited::Done(output)),
        },
        waited => Ok(waited),
    }
}

/// What the report keeps of the signals it sends on: INT and TERM. The report runs one command of a
/// step at a time, which is what `outside` assumes.
#[cfg(unix)]
struct Interrupts {
    /// True while no command of a step with a limit runs: a signal has its default action then.
    outside: Arc<AtomicBool>,
    /// For each of the [`Group::FORWARDED`] signals, in that order, its number once it reached the
    /// report, or 0. A signal that reaches the report while no command runs is recorded too, and
    /// then ends it. A flag is not cleared: the report ends the run after the command it ended.
    received: Vec<Arc<AtomicUsize>>,
    /// The number of the signal that stops the run, or 0: the first that a read found. A signal
    /// that comes later does not replace it, so the step that was stopped, the steps that were not
    /// run and the end of the report all name the same signal.
    chosen: AtomicUsize,
}

#[cfg(unix)]
impl Interrupts {
    fn new() -> Self {
        Self {
            outside: Arc::new(AtomicBool::new(true)),
            received: Group::FORWARDED
                .iter()
                .map(|_| Arc::new(AtomicUsize::new(0)))
                .collect(),
            chosen: AtomicUsize::new(0),
        }
    }

    /// The number of the signal that stops the run, when one reached the report while a command
    /// ran. The first read that finds a signal chooses it, and when both were recorded before that
    /// read, the one that comes first in [`Group::FORWARDED`].
    fn signal(&self) -> Option<i32> {
        let number = |number: usize| i32::try_from(number).ok();
        let chosen = self.chosen.load(Ordering::SeqCst);
        if chosen != 0 {
            return number(chosen);
        }
        let found = self
            .received
            .iter()
            .map(|flag| flag.load(Ordering::SeqCst))
            .find(|found| *found != 0)?;
        match self
            .chosen
            .compare_exchange(0, found, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => number(found),
            Err(first) => number(first),
        }
    }
}

/// The handlers, set once, and why they could not be, when they could not.
#[cfg(unix)]
static INTERRUPTS: OnceLock<Result<Interrupts, String>> = OnceLock::new();

/// Holds [`Interrupts::outside`] false while a command of a step with a limit runs.
#[cfg(unix)]
struct Running<'a>(&'a Interrupts);

#[cfg(unix)]
impl<'a> Running<'a> {
    fn begin(interrupts: &'a Interrupts) -> Self {
        interrupts.outside.store(false, Ordering::SeqCst);
        Self(interrupts)
    }
}

#[cfg(unix)]
impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.outside.store(true, Ordering::SeqCst);
    }
}

/// The number of the signal (INT or TERM) that reached the report while a command of a step with a
/// limit ran, when one did. The run ends by that signal after its report is made.
#[cfg(unix)]
#[must_use]
pub fn interrupted() -> Option<i32> {
    INTERRUPTS.get()?.as_ref().ok()?.signal()
}

/// No step with a limit runs where there are no process groups, so no signal is sent on.
#[cfg(not(unix))]
#[must_use]
pub fn interrupted() -> Option<i32> {
    None
}

/// Supervises `child`, which [`supervised`] started, until its time `deadline` is spent or a signal
/// is recorded. `try_wait` is the wait for the leader: it is a seam, so that a unit that holds the
/// unreaped leader can give the failure that another waiter's reap gives, and see that the report
/// signals nothing then. `signalled` is the other seam: it gives the number of the signal that
/// reached the report while the command ran, when one did.
#[cfg(unix)]
fn watch(
    child: &mut Child,
    deadline: Deadline,
    mut try_wait: impl FnMut(&mut Child) -> io::Result<Option<ExitStatus>>,
    signalled: impl Fn() -> Option<i32>,
) -> io::Result<Waited<Output>> {
    let mut pipes = match Pipes::of(child) {
        Ok(pipes) => pipes,
        Err(error) => {
            Group::end(child, &mut Pipes::none(), GRACE);
            return Err(error);
        }
    };
    // Every pipe is read to its end before the leader is waited for: a leader that is waited for is
    // reaped, and a reaped leader no longer holds the group's number, which the signals at the
    // deadline need it to. The pipes are read in this loop, a pass at a time and none to its end, so
    // that a process that holds one past the command's end holds this loop no longer than the
    // deadline, and nothing is left reading when it returns.
    while pipes.open() {
        if let Some(signal) = signalled() {
            return Ok(Waited::Interrupted(
                Group::interrupted(child, pipes, signal),
                signal,
            ));
        }
        match pipes.pass(deadline.at, Instant::now) {
            Pass::Ended => break,
            Pass::Spent => return Ok(Waited::TimedOut(Group::ended(child, pipes))),
            Pass::Open(true) => {}
            Pass::Open(false) => {
                std::thread::sleep(POLL.min(deadline.at.saturating_duration_since(Instant::now())));
            }
        }
    }
    let status = loop {
        // The signal is read before the leader is waited for, and not only when the wait finds the
        // leader still running: a signal that was recorded while the report slept, and a leader
        // that ended in that time, must leave the command stopped. The leader is not reaped yet, so
        // it still holds the group's number and the signal can be sent on to the group.
        if let Some(signal) = signalled() {
            return Ok(Waited::Interrupted(
                Group::interrupted(child, pipes, signal),
                signal,
            ));
        }
        match try_wait(child) {
            Ok(Some(status)) => {
                // A signal that was recorded as the leader ended is read again: the leader is
                // reaped, so no signal goes to the group (its number could be another process's),
                // and the command is stopped all the same.
                if let Some(signal) = signalled() {
                    return Ok(Waited::Interrupted(pipes.into_captured(), signal));
                }
                break status;
            }
            Ok(None) => {
                let now = Instant::now();
                if now >= deadline.at {
                    return Ok(Waited::TimedOut(Group::ended(child, pipes)));
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

    /// The signals that reach the report and are sent on to the group of the command it runs. They
    /// are the ones the terminal and a caller use to stop a program.
    const FORWARDED: &[rustix::process::Signal] =
        &[rustix::process::Signal::INT, rustix::process::Signal::TERM];

    /// Sets the handlers for the [`Group::FORWARDED`] signals, once. For each, the signal's number is
    /// recorded, and then, while no command runs, the default action ends the report as it ends
    /// without the handlers.
    fn arm() -> io::Result<&'static Interrupts> {
        INTERRUPTS
            .get_or_init(|| {
                let interrupts = Interrupts::new();
                for (&signal, received) in Self::FORWARDED.iter().zip(&interrupts.received) {
                    let number = signal.as_raw();
                    let value = usize::try_from(number).map_err(|error| error.to_string())?;
                    Self::handle(number, &interrupts.outside, |number| {
                        signal_hook::flag::register_usize(number, received.clone(), value)
                    })
                    .map_err(|error| error.to_string())?;
                }
                Ok(interrupts)
            })
            .as_ref()
            .map_err(|why| io::Error::other(format!("the signals could not be handled: {why}")))
    }

    /// Sets the two actions that run, in the order they are set, when the signal numbered `number`
    /// reaches the report: `record`, which keeps the signal for the supervisor, and then the default
    /// action, which runs only while `outside` is true. A handler that is on another thread than the
    /// supervisor's therefore records the signal before it reads `outside`, and the supervisor closes
    /// the phase before it reads what was recorded; with every access `SeqCst`, either the handler
    /// finds the phase closed and ends the report by the signal, or the supervisor finds the record.
    /// The two cannot be separated: a signal that is accepted is a signal that is recorded.
    fn handle(
        number: i32,
        outside: &Arc<AtomicBool>,
        record: impl FnOnce(i32) -> io::Result<signal_hook::SigId>,
    ) -> io::Result<()> {
        record(number)?;
        signal_hook::flag::register_conditional_default(number, outside.clone())?;
        Ok(())
    }

    /// Sends the signal numbered `number` to the group `child` leads, when the number is of a
    /// named signal.
    fn forward(child: &Child, number: i32) {
        if let Some(signal) = rustix::process::Signal::from_named_raw(number) {
            let _ = rustix::process::kill_process_group(
                rustix::process::Pid::from_child(child),
                signal,
            );
        }
    }

    /// Asks the group `child` leads to end.
    fn ask(child: &Child) {
        let _ = rustix::process::kill_process_group(
            rustix::process::Pid::from_child(child),
            rustix::process::Signal::TERM,
        );
    }

    /// Ends the group `child` leads: asks it to end, waits `grace`, ends what is left by force
    /// whether or not `child` is, and reaps `child`. Until it is reaped `child` holds the group's
    /// number even when it has ended, so the signals go to this group and to no other.
    fn end(child: &mut Child, pipes: &mut Pipes, grace: Duration) {
        Self::ask(child);
        Self::finish(child, pipes, grace);
    }

    /// Waits `grace` for the group `child` leads to end after it was asked to, ends what is left by
    /// force whether or not `child` is, and reaps `child`.
    ///
    /// The pipes are read through the grace, so that a process that writes more than a pipe holds as
    /// it ends is not blocked on its write, and then once they are drained of what the processes
    /// that were ended left in them. A pass reads at most [`READ_AT_MOST`] bytes from a pipe and the
    /// passes end with the grace, whatever a process that goes on writing adds; the drain reads the
    /// bytes queued when it begins.
    fn finish(child: &mut Child, pipes: &mut Pipes, grace: Duration) {
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

    /// [`Group::ended`] for a report that was sent the signal numbered `number`: that signal is the
    /// one the group is asked to end with, and not `TERM`.
    fn interrupted(child: &mut Child, mut pipes: Pipes, number: i32) -> Captured {
        Self::forward(child, number);
        Self::finish(child, &mut pipes, GRACE);
        pipes.into_captured()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::Write;

    use super::*;

    /// KR-REQ-29.01, the part about reproducible commands: when the wait for the leader fails, as it
    /// does when another waiter has reaped the leader, the report gives that error and signals
    /// nothing: the leader's number may be another process's. The unit holds the leader unreaped,
    /// and the wait is a stand-in that gives ECHILD once the pipes have closed. A process of the
    /// group that writes a line when it is asked to end has its trap set before the call begins; its
    /// file is empty when the call returns. The unit sends no signal after: [`Held`] only waits for
    /// the leader, and the processes of the group end by themselves.
    #[test]
    fn a_wait_that_fails_gives_its_error_and_no_signal_is_sent() {
        let place = tempfile::tempdir().expect("a directory");
        let marker = place.path().join("asked.txt");
        let ready = place.path().join("ready.txt");
        let release = place.path().join("release.txt");
        // The leader ends at once. One process of its group writes `term` to the marker when it is
        // asked to end and `ready` when its trap is set, and holds no pipe, for 20 s at most;
        // another holds the pipe until the release file exists, for 40 s at most.
        let script = "( trap 'printf \"%s\\n\" term >> \"$1\"; exit 0' TERM; printf '%s\\n' ready >> \"$2\"; sleep 20 & wait ) >/dev/null 2>&1 &\n( i=0; while [ ! -e \"$3\" ] && [ $i -lt 200 ]; do sleep 0.2; i=$((i+1)); done ) &\nexit 0";
        let mut command = Command::new("bash");
        command
            .arg("-c")
            .arg(script)
            .arg("bash")
            .args([&marker, &ready, &release])
            .stdin(Stdio::null());
        Group::prepare(&mut command);
        command.stdout(Stdio::piped());
        let mut leader = Held(command.spawn().expect("a command"));
        let until = Instant::now() + Duration::from_secs(30);
        while !ready.exists() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        let set = ready.exists();
        // The barrier is let go whatever came of the wait, so that a failed case leaves nothing: the
        // processes of the group end by themselves, the holder when the file exists and the other
        // one in 20 s.
        std::fs::write(&release, "").expect("the release file");
        let deadline = Deadline {
            at: Instant::now() + Duration::from_secs(600),
            seconds: 600,
            budget: false,
        };
        let waited = watch(
            &mut leader.0,
            deadline,
            |_| Err(io::Error::from(rustix::io::Errno::CHILD)),
            || None,
        );
        let asked = std::fs::read_to_string(&marker).unwrap_or_default();
        assert!(set, "the trap was not set in 30 s");
        let error = waited.expect_err("a wait that failed gave a result");
        assert_eq!(
            error.raw_os_error(),
            Some(rustix::io::Errno::CHILD.raw_os_error())
        );
        assert_eq!(asked, "", "a signal was sent to the group");
    }

    /// KR-REQ-29.01, the part about reproducible commands: the signal that stops the run is the first
    /// one a read finds, and a later, different signal does not replace it, so the step that was
    /// stopped, the steps that were not run and the end of the report name one signal. When both
    /// were recorded before the first read, the one that comes first in the list is chosen.
    #[test]
    fn a_later_signal_does_not_replace_the_one_that_stops_the_run() {
        let int = signal_hook::consts::SIGINT;
        // The number of TERM on every platform the report runs on.
        let term = 15;
        let number = |number: i32| usize::try_from(number).expect("a number");
        let first_is_int = Interrupts::new();
        assert_eq!(first_is_int.signal(), None);
        first_is_int.received[0].store(number(int), Ordering::SeqCst);
        assert_eq!(first_is_int.signal(), Some(int));
        first_is_int.received[1].store(number(term), Ordering::SeqCst);
        assert_eq!(first_is_int.signal(), Some(int), "TERM replaced INT");
        let first_is_term = Interrupts::new();
        first_is_term.received[1].store(number(term), Ordering::SeqCst);
        assert_eq!(first_is_term.signal(), Some(term));
        first_is_term.received[0].store(number(int), Ordering::SeqCst);
        assert_eq!(first_is_term.signal(), Some(term), "INT replaced TERM");
        let both = Interrupts::new();
        both.received[1].store(number(term), Ordering::SeqCst);
        both.received[0].store(number(int), Ordering::SeqCst);
        assert_eq!(both.signal(), Some(int));
    }

    /// KR-REQ-29.01, the part about reproducible commands: a signal that was recorded while the
    /// report slept, and a leader that has ended in that time and is not reaped, leave the command
    /// stopped and not done. The wait is a stand-in that reports the leader as ended, so the case
    /// does not depend on when it ends; the signal is read before the wait, and the call says which
    /// signal it was.
    #[test]
    fn a_signal_recorded_while_the_leader_ended_leaves_the_command_stopped() {
        let mut command = Command::new("bash");
        command.arg("-c").arg("exit 0").stdin(Stdio::null());
        Group::prepare(&mut command);
        let mut leader = command.spawn().expect("a command");
        let deadline = Deadline {
            at: Instant::now() + Duration::from_secs(600),
            seconds: 600,
            budget: false,
        };
        let waited = watch(
            &mut leader,
            deadline,
            |_| Ok(Some(std::os::unix::process::ExitStatusExt::from_raw(0))),
            || Some(2),
        );
        match waited.expect("a watched command") {
            Waited::Interrupted(_, 2) => {}
            other => panic!("the command was not stopped by the signal: {other:?}"),
        }
    }

    /// KR-REQ-29.01, the part about reproducible commands: a signal that is recorded as the wait finds
    /// the leader ended leaves the command stopped too, and, because the leader is reaped by then,
    /// the report sends no signal to the group: a process of the group that writes a line when it is
    /// asked to end has its trap set before the call begins, and its file is empty after it. The
    /// signal is not there when the wait begins and is there after it, and the wait is a stand-in
    /// that reports the leader as ended and reaps nothing, so the case holds the leader unreaped. It
    /// ends by itself when the case writes the release file, or in 20 s. The signal is `TERM`, which a
    /// shell can trap whatever the test process does with `INT`: a shell that is started with `INT`
    /// ignored cannot trap it, and a signal sent in error would not show.
    #[test]
    fn a_signal_recorded_after_the_leader_is_reaped_stops_the_command_and_signals_nothing() {
        let place = tempfile::tempdir().expect("a directory");
        let marker = place.path().join("asked.txt");
        let ready = place.path().join("ready.txt");
        let release = place.path().join("release.txt");
        let script = "trap 'printf \"%s\\n\" asked >> \"$1\"' TERM; printf '%s\\n' ready >> \"$2\"; i=0; while [ ! -e \"$3\" ] && [ $i -lt 200 ]; do sleep 0.1 & wait $!; i=$((i+1)); done";
        let mut command = Command::new("bash");
        command
            .arg("-c")
            .arg(script)
            .arg("bash")
            .args([&marker, &ready, &release])
            .stdin(Stdio::null());
        Group::prepare(&mut command);
        let mut leader = command.spawn().expect("a command");
        let until = Instant::now() + Duration::from_secs(30);
        while !ready.exists() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        let set = ready.exists();
        let deadline = Deadline {
            at: Instant::now() + Duration::from_secs(600),
            seconds: 600,
            budget: false,
        };
        let reads = std::cell::Cell::new(0);
        let waited = watch(
            &mut leader,
            deadline,
            |_| Ok(Some(std::os::unix::process::ExitStatusExt::from_raw(0))),
            || {
                reads.set(reads.get() + 1);
                (reads.get() > 1).then_some(15)
            },
        );
        // A signal that had been sent would have run the trap by now.
        std::thread::sleep(Duration::from_millis(500));
        let asked = std::fs::read_to_string(&marker).unwrap_or_default();
        std::fs::write(&release, "").expect("the release file");
        let _ = leader.wait();
        assert!(set, "the trap was not set in 30 s");
        match waited.expect("a watched command") {
            Waited::Interrupted(_, 15) => {}
            other => panic!("the command was not stopped by the signal: {other:?}"),
        }
        assert_eq!(asked, "", "a signal was sent to the group");
    }

    /// KR-REQ-29.01, the part about reproducible commands: a signal that is recorded after the last
    /// read of the watch and before the supervised phase closes leaves the command stopped, and not
    /// done, and, because the leader is reaped by then, the report sends no signal to the group. The
    /// command is a leader that ends at once and leaves a process in its group that writes a line
    /// when it is asked to end, with its trap set before the leader ends. The seam records the
    /// signal in that interval, as the handler does, so the case does not depend on a timing; the
    /// process's file is empty after the call, and the phase is closed.
    #[test]
    fn a_signal_recorded_as_the_supervised_phase_closes_leaves_the_command_stopped() {
        let place = tempfile::tempdir().expect("a directory");
        let marker = place.path().join("asked.txt");
        let ready = place.path().join("ready.txt");
        // The straggler ends by itself in 20 s at most, and holds no pipe.
        let script = "( trap 'printf \"%s\\n\" asked >> \"$1\"; exit 0' TERM; printf '%s\\n' ready >> \"$2\"; sleep 20 & wait ) >/dev/null 2>&1 &\ni=0; while [ ! -e \"$2\" ] && [ $i -lt 600 ]; do sleep 0.05; i=$((i+1)); done\nexit 0";
        let mut command = Command::new("bash");
        command
            .arg("-c")
            .arg(script)
            .arg("bash")
            .args([&marker, &ready])
            .stdin(Stdio::null());
        let interrupts = Interrupts::new();
        let deadline = Deadline {
            at: Instant::now() + Duration::from_secs(600),
            seconds: 600,
            budget: false,
        };
        let waited = supervise(&mut command, deadline, false, &interrupts, || {
            interrupts.received[1].store(15, Ordering::SeqCst);
        });
        // A signal that had been sent would have run the trap by now.
        std::thread::sleep(Duration::from_millis(500));
        let asked = std::fs::read_to_string(&marker).unwrap_or_default();
        assert!(
            ready.exists(),
            "the trap was not set before the leader ended"
        );
        match waited.expect("a supervised command") {
            Waited::Interrupted(_, 15) => {}
            other => panic!("the command was not stopped by the signal: {other:?}"),
        }
        assert_eq!(asked, "", "a signal was sent to the group");
        assert!(
            interrupts.outside.load(Ordering::SeqCst),
            "the phase was not closed"
        );
    }

    /// The variable that makes the test program run the child's part of
    /// `a_signal_that_finds_the_phase_closed_is_recorded_before_it_ends_the_process`.
    const CHILD: &str = "KR_CONFORMANCE_UNIT_CHILD";

    /// KR-REQ-29.01, the part about reproducible commands: a signal that reaches the report while no
    /// command runs is recorded before the default action ends the report, so a handler that runs
    /// on another thread than the supervisor cannot accept a signal and leave it unrecorded: it
    /// either records it before the supervisor closes the phase and reads, or finds the phase closed
    /// and ends the report by the signal. The case sets the two actions of `Group::handle` for a
    /// signal with a record that writes a byte to its standard error, closes the phase, and raises
    /// the signal in a child that is this test program. The byte is there, and the child ended by
    /// the signal, only when the record ran first and the default action after it.
    #[test]
    fn a_signal_that_finds_the_phase_closed_is_recorded_before_it_ends_the_process() {
        use std::io::Read;
        use std::os::fd::AsFd;
        use std::os::unix::process::ExitStatusExt;
        let number = signal_hook::consts::SIGUSR1;
        if std::env::var_os(CHILD).is_some() {
            let outside = Arc::new(AtomicBool::new(true));
            let witness = std::io::stderr()
                .as_fd()
                .try_clone_to_owned()
                .expect("a descriptor");
            Group::handle(number, &outside, |number| {
                signal_hook::low_level::pipe::register(number, witness)
            })
            .expect("the actions");
            signal_hook::low_level::raise(number).expect("a signal");
            // Not reached when the default action ends the process.
            std::process::exit(3);
        }
        let (mut reader, writer) = std::io::pipe().expect("a pipe");
        let mut command = Command::new(std::env::current_exe().expect("the test program"));
        command
            .args([
                "--exact",
                "tree::tests::a_signal_that_finds_the_phase_closed_is_recorded_before_it_ends_the_process",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(writer);
        let mut child = command.spawn().expect("the child");
        // The writer is held by the command until it is dropped, and the read below ends with it.
        drop(command);
        let status = child.wait().expect("a wait");
        let mut written = Vec::new();
        reader.read_to_end(&mut written).expect("a read");
        assert!(
            written.contains(&b'X'),
            "the default action ended the child before the record ran: {status:?}, {written:?}"
        );
        assert_eq!(
            status.signal(),
            Some(number),
            "the child was not ended by the signal: {status:?}"
        );
    }

    /// The leader of the group of `group_signalled`: it writes the name of each signal it is sent to
    /// the file of its first argument, records its pid and its child's in the file of its second,
    /// and goes on for 30 s at most, so that it ends by itself when nothing ends it.
    const GROUP_LEADER: &str = "import os, signal, subprocess, sys, time
names = {signal.SIGINT: 'INT', signal.SIGTERM: 'TERM'}
def note(number, frame):
    with open(sys.argv[1], 'a') as out:
        out.write(names[number] + '\\n')
signal.signal(signal.SIGINT, note)
signal.signal(signal.SIGTERM, note)
child = subprocess.Popen(['sleep', '61'])
with open(sys.argv[2], 'a') as out:
    out.write(str(os.getpid()) + '\\n' + str(child.pid) + '\\n')
end = time.monotonic() + 30
while time.monotonic() < end:
    time.sleep(0.05)
";

    /// Runs a group whose processes record the signal they are sent, with the signal that the flag
    /// `flag` of the interrupts holds recorded once the group has started, and gives what the
    /// group recorded. The group's leader is a Python program that handles `INT` and `TERM`, and not a shell: a
    /// shell that is started with `INT` ignored, as it is under a parent that runs in the background
    /// of a non-interactive shell, cannot trap it. Its child waits with `sleep`, and ends at the end
    /// of the grace, by the force. It is not the leader's to reap, so the case looks for it for up
    /// to 10 s after the call, as the cases of `tests/execution.rs` do: on Linux a process that has
    /// ended answers a look until its parent reaps it. The flag is stored by a thread of the case
    /// once the processes have started, which stands for the handler that sets it. The case allows
    /// 30 s for the processes to start, and 30 s from the signal for the call to return.
    fn group_signalled(flag: usize, number: i32) -> String {
        let place = tempfile::tempdir().expect("a directory");
        let pids = place.path().join("pids.txt");
        let signals = place.path().join("signals.txt");
        let script = GROUP_LEADER;
        let mut command = Command::new("python3");
        command
            .arg("-c")
            .arg(script)
            .args([&signals, &pids])
            .stdin(Stdio::null());
        Group::prepare(&mut command);
        command.stdout(Stdio::piped());
        let mut child = command.spawn().expect("a command");
        let interrupts = Interrupts::new();
        let deadline = Deadline {
            at: Instant::now() + Duration::from_secs(600),
            seconds: 600,
            budget: false,
        };
        let stored = usize::try_from(number).expect("a number");
        let signalled = std::sync::OnceLock::new();
        let waited = std::thread::scope(|scope| {
            scope.spawn(|| {
                let until = Instant::now() + Duration::from_secs(30);
                while std::fs::read_to_string(&pids)
                    .unwrap_or_default()
                    .lines()
                    .count()
                    < 2
                    && Instant::now() < until
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                interrupts.received[flag].store(stored, Ordering::SeqCst);
                let _ = signalled.set(Instant::now());
            });
            watch(&mut child, deadline, Child::try_wait, || {
                interrupts.signal()
            })
        });
        let took = signalled.get().map(Instant::elapsed);
        let recorded = std::fs::read_to_string(&pids).unwrap_or_default();
        assert_eq!(
            recorded.lines().count(),
            2,
            "the processes did not start: {recorded:?}"
        );
        match waited.expect("a watched command") {
            Waited::Interrupted(_, signal) => assert_eq!(signal, number),
            other => panic!("the command was not interrupted: {other:?}"),
        }
        assert!(
            took.is_some_and(|took| took < Duration::from_secs(30)),
            "the call took {took:?} from the signal"
        );
        let until = Instant::now() + Duration::from_secs(10);
        let left = loop {
            let left: Vec<&str> = recorded
                .lines()
                .filter(|pid| {
                    let number = pid.parse::<i32>().expect("a pid");
                    rustix::process::Pid::from_raw(number)
                        .is_some_and(|pid| rustix::process::test_kill_process(pid).is_ok())
                })
                .collect();
            if left.is_empty() || Instant::now() >= until {
                break left;
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        assert!(
            left.is_empty(),
            "processes of the group were left: {left:?}"
        );
        std::fs::read_to_string(&signals).unwrap_or_default()
    }

    /// KR-REQ-29.01, the part about reproducible commands: an interrupt that reached the report while
    /// a command ran is sent on to the command's group, before the force: a process of the group
    /// writes the name of the signal it was sent, and the file holds `INT` and nothing else.
    #[test]
    fn an_interrupt_that_reached_the_report_is_sent_on_to_the_group() {
        assert_eq!(
            group_signalled(0, signal_hook::consts::SIGINT),
            "INT\n",
            "the group was not sent INT"
        );
    }

    /// KR-REQ-29.01, the part about reproducible commands: the same for the termination request.
    #[test]
    fn a_termination_request_that_reached_the_report_is_sent_on_to_the_group() {
        assert_eq!(
            group_signalled(1, 15),
            "TERM\n",
            "the group was not sent TERM"
        );
    }

    /// KR-REQ-29.01, the part about reproducible commands: a signal that reached the report before a
    /// command is due starts nothing: the call says which signal it was. The command is a program that
    /// does not exist, so a start would be an error from the call. That makes the start of the command
    /// visible whatever the test process does with `INT`, and however long a started shell takes to
    /// reach its first command.
    #[test]
    fn a_signal_received_before_a_command_is_due_starts_nothing() {
        let place = tempfile::tempdir().expect("a directory");
        let mut command = Command::new(place.path().join("no-such-program"));
        command.stdin(Stdio::null());
        let interrupts = Interrupts::new();
        interrupts.received[0].store(2, Ordering::SeqCst);
        let deadline = Deadline {
            at: Instant::now() + Duration::from_secs(600),
            seconds: 600,
            budget: false,
        };
        let waited = supervise(&mut command, deadline, false, &interrupts, || {});
        assert!(
            matches!(waited, Ok(Waited::Interrupted(_, 2))),
            "the command was started, or the signal was not found: {waited:?}"
        );
    }

    /// KR-REQ-29.01, the part about reproducible commands: the report finds a host that cannot wait
    /// for a command it started before it runs a step with a limit. A wait that fails, as it does
    /// under a parent that ignores `SIGCHLD`, is the trial's wait error; a command that cannot be
    /// started is its start error, and not a wait failure; a wait that works passes. The stand-in
    /// waits for the command first, so that it leaves none.
    #[test]
    fn a_host_that_cannot_wait_for_a_command_it_started_is_found_by_the_trial() {
        let failed = waited_for("/bin/sh", |child| {
            child.wait()?;
            Err(io::Error::from(rustix::io::Errno::CHILD))
        });
        let missing = waited_for("/nonexistent/program", Child::wait);
        let mut wrong = Vec::new();
        match failed {
            Err(Trial::Wait(error))
                if error.raw_os_error() == Some(rustix::io::Errno::CHILD.raw_os_error()) => {}
            other => wrong.push(format!("a wait that fails gave {other:?}")),
        }
        match missing {
            Err(Trial::Start(error)) if error.kind() == io::ErrorKind::NotFound => {}
            other => wrong.push(format!("a program that is not there gave {other:?}")),
        }
        if let Err(error) = waited_for("/bin/sh", Child::wait) {
            wrong.push(format!("the trial failed here: {error:?}"));
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

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

    /// The leader of a group that a unit holds unreaped and only waits for: when it is dropped, at
    /// the end of the unit or in a panic, [`Child::wait`] is the whole of its cleanup. It sends no
    /// signal, so no path of the unit signals a group whose leader a call has reaped; a leader that
    /// a call has reaped is not waited for again.
    struct Held(Child);

    impl Drop for Held {
        fn drop(&mut self) {
            let _ = self.0.wait();
        }
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
