//! The pseudo-terminal and the root shell that runs inside it.
//!
//! Section 7 is explicit about the order: KalaReach creates the pseudo-terminal **before** the
//! root shell starts. A shell that is launched into an existing terminal of the right size prints
//! its first prompt at the real geometry; one that is resized afterwards has already drawn.
//!
//! The worker owns the terminal for the session's whole life. It owns the shell's process group
//! too, which is what makes closure mean something: signalling the group reaches the shell and the
//! children it started, and the recorded process identity keeps a recycled identifier from being
//! mistaken for one of them.

use std::io::{Read, Write};

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::session::Dimensions;
#[cfg(windows)]
use portable_pty::CommandBuilder;
#[cfg(unix)]
use portable_pty::native_pty_system;
use portable_pty::{MasterPty, PtySize};

use crate::error::{Result, WorkerError};

#[cfg(unix)]
mod spawn;

/// What to launch as the session's root shell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellCommand {
    /// The executable to run. `SHELL` is set to exactly this path.
    pub program: String,
    /// Its arguments.
    pub arguments: Vec<String>,
    /// The working directory to start in.
    pub cwd: String,
    /// The complete environment, already filtered by [`crate::environment`].
    pub environment: Vec<(String, String)>,
}

/// How a root shell ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellExit {
    /// The exit code the shell returned.
    pub code: u32,
    /// The signal that ended it, named as the platform names it.
    ///
    /// A signalled exit has no meaningful numeric code on every platform, so the name is what is
    /// recorded. Inventing a number here would put a wrong one in the closure record.
    pub signal: Option<String>,
}

impl ShellExit {
    /// Returns true when a signal ended the shell rather than a normal return.
    #[must_use]
    pub const fn signalled(&self) -> bool {
        self.signal.is_some()
    }
}

/// The session's pseudo-terminal, created before any shell runs.
pub struct Pty {
    master: Box<dyn MasterPty + Send>,
    /// The end the root shell is given, until it is.
    #[cfg(unix)]
    slave: Option<std::os::fd::OwnedFd>,
    /// The end the root shell is given, until it is.
    #[cfg(windows)]
    slave: Option<Box<dyn portable_pty::SlavePty + Send>>,
    /// The event a started read of this terminal's output is signalled on.
    ///
    /// Windows has no readiness to ask a pipe about: what says there is output is the read the
    /// reader already started, and this is how the waiter beside it waits for that read.
    #[cfg(windows)]
    output_event: std::os::windows::io::OwnedHandle,
    /// The console's own input, which the interrupt is written into.
    ///
    /// Separate from the writer the session takes, because an interrupt that queued behind input
    /// an application had stopped reading would be no interrupt at all.
    #[cfg(windows)]
    console_input: std::sync::Arc<crate::windows::conpty::Input>,
    dimensions: Dimensions,
}

impl std::fmt::Debug for Pty {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Pty")
            .field("dimensions", &self.dimensions)
            .field("used", &self.slave.is_none())
            .finish()
    }
}

impl Pty {
    /// Creates the pseudo-terminal at a validated geometry.
    ///
    /// # Errors
    ///
    /// Returns a dimension failure when the geometry violates a constraint, and
    /// [`WorkerError::Pty`] when the terminal cannot be created.
    #[cfg(unix)]
    pub fn open(dimensions: Dimensions) -> Result<Self> {
        dimensions.validate()?;
        let pair = native_pty_system()
            .openpty(pty_size(dimensions))
            .map_err(|error| WorkerError::pty("create the pseudo-terminal", error))?;
        // The terminal answers rather than waits. A read with nothing to read and a write the
        // terminal has no room for both come straight back, which is what lets the loops on either
        // side of it decide what to do next instead of being held inside a system call: the writer
        // can be told the lease it is writing for has ended, and the reader can be stopped. Both
        // wait on the descriptor itself when there is nothing to do.
        answer_rather_than_wait(pair.master.as_ref())?;
        // The shell is started by this host rather than by the terminal library, so that nothing
        // is read from the file system between the last admission of the start and the process
        // ([`spawn`]). The slave end it needs is taken from the master, or opened by the name the
        // master reports where it cannot be taken ([`open_slave`]), while the library's own is
        // still open.
        let slave = open_slave(pair.master.as_ref())?;
        Ok(Self {
            master: pair.master,
            slave: Some(slave),
            dimensions,
        })
    }

    /// Creates the pseudo-console at a validated geometry.
    ///
    /// The pipes are this host's own rather than the terminal library's, because the modes they
    /// need are the ones the boundaries need and a pipe cannot be changed into them afterwards:
    /// what this host writes into answers rather than waits, and what it reads from is overlapped,
    /// so the reader waits on its own read rather than asking again on a timer.
    ///
    /// # Errors
    ///
    /// Returns a dimension failure when the geometry violates a constraint, and
    /// [`WorkerError::Pty`] when the console cannot be created.
    #[cfg(windows)]
    pub fn open(dimensions: Dimensions) -> Result<Self> {
        dimensions.validate()?;
        let (master, slave) = crate::windows::conpty::open(pty_size(dimensions))
            .map_err(|error| WorkerError::pty("create the pseudo-terminal", error))?;
        let output_event = master
            .output_event()
            .map_err(|error| WorkerError::pty("create the pseudo-terminal", error))?;
        let console_input = master.input();
        Ok(Self {
            master: Box::new(master),
            slave: Some(Box::new(slave)),
            output_event,
            console_input,
            dimensions,
        })
    }

    /// Returns the geometry the terminal is currently set to.
    #[must_use]
    pub const fn dimensions(&self) -> Dimensions {
        self.dimensions
    }

    /// Starts the root shell inside the terminal, if `admit` allows it.
    ///
    /// On Unix everything the start reads from the file system is read before `admit` is asked,
    /// and nothing is read between its answer and the process: it is the last look at whether the
    /// start may go ahead, such as a look at the clock for a start that is held to a moment. On
    /// Windows the terminal library still looks at the directory and for the program as it starts
    /// the process. `admit` is given whether the directory the command names was there. A start it
    /// refuses leaves the terminal unused, and the shell can be started in it later.
    ///
    /// The environment is replaced outright rather than inherited: the worker's own environment is
    /// not the session's, and section 7 decides what the session gets.
    ///
    /// # Errors
    ///
    /// Returns what `admit` returns when it refuses, and [`WorkerError::Pty`] when the shell
    /// cannot be started, or when a shell has already been started in this terminal.
    pub fn launch(
        &mut self,
        command: &ShellCommand,
        admit: impl FnOnce(bool) -> Result<()>,
    ) -> Result<RootShell> {
        let running = || WorkerError::pty("start the root shell", "a shell is already running");
        if self.slave.is_none() {
            return Err(running());
        }
        #[cfg(unix)]
        let reads = spawn::Reads::read(command);
        #[cfg(unix)]
        let named_is_there = reads.named_is_there();
        #[cfg(windows)]
        let named_is_there = std::path::Path::new(&command.cwd).is_dir();
        admit(named_is_there)?;
        let slave = self.slave.take().ok_or_else(running)?;
        #[cfg(unix)]
        let child: Box<dyn portable_pty::Child + Send + Sync> = Box::new(
            spawn::start(&slave, reads, command)
                .map_err(|error| WorkerError::pty("start the root shell", error))?,
        );
        #[cfg(windows)]
        let child = {
            let mut builder = CommandBuilder::new(&command.program);
            for argument in &command.arguments {
                builder.arg(argument);
            }
            builder.env_clear();
            for (name, value) in &command.environment {
                builder.env(name, value);
            }
            builder.cwd(&command.cwd);
            slave
                .spawn_command(builder)
                .map_err(|error| WorkerError::pty("start the root shell", error))?
        };
        // The slave descriptor is dropped here. Holding it open would keep the terminal alive
        // after the shell exits, so the read loop would never see end of file and the session
        // would look busy for ever.
        drop(slave);
        let pid = child
            .process_id()
            .ok_or_else(|| WorkerError::pty("start the root shell", "no process identifier"))?;
        // A shell can be gone before this reads it. `exit 0` in a startup file, a shell that cannot
        // open something it needs, a program that is not the shell it was declared to be: all of
        // them run and leave inside the moment between the spawn above and the reading here, and on
        // macOS the kernel then refuses to describe the process at all. That is not a launch
        // failure. The shell ran, and the session it belongs to closes on the root shell's exit
        // through the ordinary sequence, with its status read from the child itself; what this
        // needs is an identity that says so rather than an error that loses it.
        let identity = kr_ipc::identity::started_process_identity(pid)?;
        Ok(RootShell {
            child,
            identity,
            process_group: foreground_group(self.master.as_ref()),
            #[cfg(windows)]
            console_input: std::sync::Arc::clone(&self.console_input),
        })
    }

    /// Returns whether the terminal has been handed to a start of the root shell, whether or not
    /// the start went on to create a process, for this host's own tests.
    #[cfg(feature = "testing")]
    #[must_use]
    pub const fn was_used(&self) -> bool {
        self.slave.is_none()
    }

    /// Returns a reader for everything the terminal produces.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::Pty`] when the reader cannot be cloned.
    pub fn reader(&self) -> Result<Box<dyn Read + Send>> {
        self.master
            .try_clone_reader()
            .map_err(|error| WorkerError::pty("read the pseudo-terminal", error))
    }

    /// Takes the writer for input.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::Pty`] when the writer has already been taken.
    pub fn writer(&self) -> Result<Box<dyn Write + Send>> {
        self.master
            .take_writer()
            .map_err(|error| WorkerError::pty("write to the pseudo-terminal", error))
    }

    /// Returns a handle that can be waited on until the terminal will take more input.
    ///
    /// `None` on a platform where the terminal cannot be waited on, and a writer there waits inside
    /// its own write instead.
    #[must_use]
    pub fn input_waiter(&self) -> Option<InputWaiter> {
        InputWaiter::of(self.master.as_ref())
    }

    /// Returns a handle that can be waited on until the application has written something.
    ///
    /// The terminal answers a read with nothing to read rather than waiting inside it, so the read
    /// loop waits here instead.
    #[must_use]
    #[cfg(unix)]
    pub fn output_waiter(&self) -> Option<OutputWaiter> {
        OutputWaiter::of(self.master.as_ref())
    }

    /// Returns a handle that can be waited on until the application has written something.
    ///
    /// It waits on the read the reader has already started, because a pipe has no readiness of its
    /// own to ask about.
    #[cfg(windows)]
    #[must_use]
    pub fn output_waiter(&self) -> Option<OutputWaiter> {
        self.output_event.try_clone().ok().map(OutputWaiter::over)
    }

    /// Returns the process group the terminal currently has in the foreground.
    ///
    /// This changes with every command an interactive shell runs, so it is read now rather than
    /// remembered from when the shell started.
    #[must_use]
    pub fn foreground_group(&self) -> Option<i32> {
        foreground_group(self.master.as_ref())
    }

    /// Sends the terminal's interrupt to the group it has in the foreground.
    ///
    /// The foreground group is the one the terminal itself would signal when the interrupt key is
    /// pressed, and for an interactive shell running a command that is the command's group, not
    /// the shell's. Signalling the shell's group instead would interrupt the shell and leave the
    /// command running, which is the opposite of what the key does.
    ///
    /// # Errors
    ///
    /// Returns an error when the terminal will not name a foreground group, so the caller can fall
    /// back to the group it does know.
    #[cfg(unix)]
    pub fn interrupt_foreground(&self) -> Result<()> {
        let group = self.foreground_group().ok_or_else(|| {
            WorkerError::pty(
                "interrupt the foreground application",
                "the terminal did not name a foreground process group",
            )
        })?;
        let pid = rustix::process::Pid::from_raw(group).ok_or_else(|| {
            WorkerError::pty(
                "interrupt the foreground application",
                "the foreground group is not a valid identifier",
            )
        })?;
        match rustix::process::kill_process_group(pid, rustix::process::Signal::INT) {
            Ok(()) => Ok(()),
            // The group is already gone, which is the outcome the caller wanted.
            Err(error) if error == rustix::io::Errno::SRCH => Ok(()),
            Err(error) => Err(WorkerError::pty(
                "interrupt the foreground application",
                error,
            )),
        }
    }

    /// Delivers the console's interrupt to the application attached to it.
    ///
    /// This platform has no foreground process group and no signal to send one. What it has is the
    /// console's own input: the byte a console turns into a control event for whatever is attached
    /// to it. It is written through the console rather than through the session's input, so an
    /// application that has stopped reading cannot hold it.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::Pty`] when the console will not take it.
    #[cfg(windows)]
    pub fn interrupt_foreground(&self) -> Result<()> {
        match self
            .console_input
            .write(&[crate::windows::conpty::INTERRUPT_BYTE])
        {
            Ok(1) => Ok(()),
            Ok(_) => Err(WorkerError::pty(
                "interrupt the foreground application",
                "the console is full, so it took none of the interrupt",
            )),
            Err(error) => Err(WorkerError::pty(
                "interrupt the foreground application",
                error,
            )),
        }
    }

    /// Sends the terminal's interrupt to the group it has in the foreground.
    ///
    /// # Errors
    ///
    /// Always returns an error: this platform names no foreground process group.
    #[cfg(not(any(unix, windows)))]
    pub fn interrupt_foreground(&self) -> Result<()> {
        Err(WorkerError::pty(
            "interrupt the foreground application",
            "this platform names no foreground process group",
        ))
    }

    /// Changes the terminal's geometry and notifies the foreground application.
    ///
    /// # Errors
    ///
    /// Returns a dimension failure when the geometry violates a constraint, and
    /// [`WorkerError::Pty`] when the kernel refuses the change.
    pub fn resize(&mut self, dimensions: Dimensions) -> Result<()> {
        dimensions.validate()?;
        self.master
            .resize(pty_size(dimensions))
            .map_err(|error| WorkerError::pty("resize the pseudo-terminal", error))?;
        self.dimensions = dimensions;
        Ok(())
    }
}

/// The root shell running in a session's terminal.
pub struct RootShell {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    identity: ProcessStartIdentity,
    process_group: Option<i32>,
    /// The console this shell runs in, which is where a request to stop is delivered.
    ///
    /// This platform has no signal that means "please stop". What it has is the console's own
    /// control byte, which is what the closure sequence's grace period is for: the shell is asked
    /// through the console, and force is the separate step that follows if it does not go.
    #[cfg(windows)]
    console_input: std::sync::Arc<crate::windows::conpty::Input>,
}

impl std::fmt::Debug for RootShell {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RootShell")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl RootShell {
    /// Returns the shell's process and the kernel's record of when it started.
    #[must_use]
    pub const fn identity(&self) -> &ProcessStartIdentity {
        &self.identity
    }

    /// Returns the foreground process group of the terminal, where the platform reports one.
    #[must_use]
    pub const fn foreground_group(&self) -> Option<i32> {
        self.process_group
    }

    /// Returns the exit status if the shell has already ended.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::Pty`] when the status cannot be read.
    pub fn try_wait(&mut self) -> Result<Option<ShellExit>> {
        self.child
            .try_wait()
            .map(|status| status.map(exit_from))
            .map_err(|error| WorkerError::pty("read the root shell's status", error))
    }

    /// Waits for the shell to end.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::Pty`] when the status cannot be read.
    pub fn wait(&mut self) -> Result<ShellExit> {
        self.child
            .wait()
            .map(exit_from)
            .map_err(|error| WorkerError::pty("wait for the root shell", error))
    }

    /// Asks the shell and everything in its process group to stop.
    ///
    /// Signalling the group rather than the process is what reaches the children the shell
    /// started. The recorded start identity is checked first, so a recycled identifier belonging
    /// to an unrelated program is never signalled.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::Pty`] when the signal cannot be sent.
    pub fn request_stop(&mut self) -> Result<()> {
        self.signal_group(Signal::Terminate)
    }

    /// Ends the shell and its process group without waiting.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::Pty`] when the signal cannot be sent.
    pub fn force_stop(&mut self) -> Result<()> {
        self.signal_group(Signal::Kill)
    }

    /// Sends the terminal's interrupt to the root shell's own process group.
    ///
    /// This is the fallback. The interrupt normally goes to the terminal's *foreground* group,
    /// which [`Pty::interrupt_foreground`] reads from the terminal itself.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::Pty`] when the signal cannot be sent.
    pub fn interrupt(&mut self) -> Result<()> {
        self.signal_group(Signal::Interrupt)
    }

    #[cfg(unix)]
    fn signal_group(&mut self, signal: Signal) -> Result<()> {
        use kr_ipc::identity::{ProcessState, process_state};

        // A process identifier alone is never enough to justify a signal.
        match process_state(&self.identity) {
            ProcessState::Running => {}
            ProcessState::Ended => return Ok(()),
            ProcessState::Unknown { detail } => {
                return Err(WorkerError::pty("signal the root shell", detail));
            }
        }
        let raw = i32::try_from(self.identity.pid.get()).map_err(|_| {
            WorkerError::pty("signal the root shell", "the identifier is out of range")
        })?;
        let pid = rustix::process::Pid::from_raw(raw).ok_or_else(|| {
            WorkerError::pty("signal the root shell", "the identifier is not valid")
        })?;
        let result = match signal {
            Signal::Terminate => {
                rustix::process::kill_process_group(pid, rustix::process::Signal::TERM)
            }
            Signal::Kill => rustix::process::kill_process_group(pid, rustix::process::Signal::KILL),
            Signal::Interrupt => {
                rustix::process::kill_process_group(pid, rustix::process::Signal::INT)
            }
        };
        match result {
            Ok(()) => Ok(()),
            // The group is already gone, which is the outcome the caller wanted.
            Err(error) if error == rustix::io::Errno::SRCH => Ok(()),
            Err(error) => Err(WorkerError::pty("signal the root shell", error)),
        }
    }

    #[cfg(windows)]
    fn signal_group(&mut self, signal: Signal) -> Result<()> {
        match signal {
            // Asked, not ended. This platform has no signal that means "please stop", and the
            // closure sequence allows five seconds for one: turning the request into a forced
            // termination would spend that allowance before it began and would leave a shell
            // recorded as having stopped when it was asked. So the request is the console's own
            // control byte, delivered the same way an interrupt is, and force is the step after.
            Signal::Terminate | Signal::Interrupt => self.interrupt_through_console(),
            // Force. The session's job object is what reaches the descendants; this is the shell.
            Signal::Kill => self
                .child
                .kill()
                .map_err(|error| WorkerError::pty("signal the root shell", error)),
        }
    }

    /// Writes the console's control byte into the console this shell runs in.
    #[cfg(windows)]
    fn interrupt_through_console(&self) -> Result<()> {
        match self
            .console_input
            .write(&[crate::windows::conpty::INTERRUPT_BYTE])
        {
            Ok(1) => Ok(()),
            Ok(_) => Err(WorkerError::pty(
                "ask the root shell to stop",
                "the console took none of the request",
            )),
            Err(error) => Err(WorkerError::pty("ask the root shell to stop", error)),
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn signal_group(&mut self, signal: Signal) -> Result<()> {
        match signal {
            Signal::Terminate | Signal::Kill => self
                .child
                .kill()
                .map_err(|error| WorkerError::pty("signal the root shell", error)),
            Signal::Interrupt => Err(WorkerError::pty(
                "interrupt the foreground application",
                "this platform names no foreground process group",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Signal {
    Terminate,
    Kill,
    Interrupt,
}

fn exit_from(status: portable_pty::ExitStatus) -> ShellExit {
    ShellExit {
        code: status.exit_code(),
        signal: status.signal().map(ToOwned::to_owned),
    }
}

#[cfg(unix)]
fn foreground_group(master: &dyn MasterPty) -> Option<i32> {
    master.process_group_leader()
}

#[cfg(not(unix))]
const fn foreground_group(_master: &dyn MasterPty) -> Option<i32> {
    // Windows has no process groups on a console pseudo-terminal. Ownership there is the
    // per-session Job Object, which the Windows qualification pass installs.
    None
}

fn pty_size(dimensions: Dimensions) -> PtySize {
    PtySize {
        // Validation bounds columns at 2,048 and rows at 1,024, so both fit.
        rows: u16::try_from(dimensions.rows()).unwrap_or(u16::MAX),
        cols: u16::try_from(dimensions.columns()).unwrap_or(u16::MAX),
        pixel_width: 0,
        pixel_height: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KR-REQ-07.01: a terminal is created, at its size and with a reader, before any shell is
    /// launched into it; a shell can only be started inside a terminal that already exists.
    #[test]
    fn the_terminal_exists_before_any_shell_runs() {
        let pty = Pty::open(Dimensions::new(120, 40)).expect("opens");
        assert_eq!(pty.dimensions(), Dimensions::new(120, 40));
        // A reader exists before anything has been launched into it.
        pty.reader().expect("a reader");
    }

    /// A read of a terminal with nothing to read answers at once rather than waiting.
    ///
    /// The read loop counts each read under the lock a closing session measures what was read
    /// with, so a read that waited would hold that measure for as long as nothing arrived. The
    /// read runs on a thread of its own here, so a terminal that did wait fails this test rather
    /// than hanging it.
    #[cfg(unix)]
    #[test]
    fn a_read_with_nothing_to_read_answers_rather_than_waits() {
        let pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
        let mut reader = pty.reader().expect("a reader");
        let (answered, answer) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buffer = [0_u8; 64];
            let _ = answered.send(reader.read(&mut buffer).map_err(|error| error.kind()));
        });
        let result = answer
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the read answered rather than waited");
        assert_eq!(result, Err(std::io::ErrorKind::WouldBlock));
    }

    /// The copies of the terminal's master side that the waiters hold are not handed to a program
    /// started beside them: a program that held one would keep the terminal's other side open, and
    /// the session's end would not reach the writer waiting on it.
    #[cfg(unix)]
    #[test]
    fn a_program_started_beside_the_terminals_waiters_is_not_handed_their_descriptors() {
        let pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
        let input = pty.input_waiter().expect("a waiter for input");
        let output = pty.output_waiter().expect("a waiter for output");
        let held = kr_ipc::testing::descriptors_a_started_program_holds();
        for (what, handle) in [("input", &input.handle), ("output", &output.handle)] {
            let number = u32::try_from(std::os::fd::AsRawFd::as_raw_fd(handle)).expect("a number");
            assert!(
                !held.contains(&number),
                "a program started beside the {what} waiter holds its descriptor"
            );
        }
    }

    #[test]
    fn an_invalid_geometry_never_allocates_a_terminal() {
        assert!(matches!(
            Pty::open(Dimensions::new(2_048, 1_024)),
            Err(WorkerError::Dimensions(_))
        ));
    }

    /// Reads until `marker` appears, waiting on the terminal rather than inside the read.
    ///
    /// The terminal answers a read with nothing to read rather than waiting, which is what lets
    /// the worker steer its own loops; a test that reads from one waits the same way.
    fn read_until(pty: &Pty, reader: &mut Box<dyn Read + Send>, marker: &[u8]) -> Vec<u8> {
        let waiter = pty.output_waiter();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let mut seen = Vec::new();
        let mut buffer = [0_u8; 256];
        while std::time::Instant::now() < deadline {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    seen.extend_from_slice(&buffer[..read]);
                    if seen.windows(marker.len()).any(|window| window == marker) {
                        break;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    match waiter
                        .as_ref()
                        .map(|waiter| waiter.wait(std::time::Duration::from_millis(50)))
                    {
                        Some(Room::Gone) => break,
                        Some(_) => {}
                        None => std::thread::sleep(std::time::Duration::from_millis(50)),
                    }
                }
                Err(_) => break,
            }
        }
        seen
    }

    #[test]
    fn a_windows_command_line_can_be_taken_apart_again() {
        use std::ffi::OsString;

        // A path is mostly backslashes. The shell this host starts is named by one, so a line that
        // dropped them would start the wrong program or none at all.
        let plain = command_line(&[OsString::from(r"C:\Windows\System32\cmd.exe")]);
        assert_eq!(plain, r"C:\Windows\System32\cmd.exe");

        // A space makes it quoted, and the backslashes inside stay exactly as they are: they are
        // only special in front of a quotation mark.
        let spaced = command_line(&[OsString::from(r"C:\Program Files\PowerShell\pwsh.exe")]);
        assert_eq!(spaced, "\"C:\\Program Files\\PowerShell\\pwsh.exe\"");

        // A run of backslashes before a quotation mark is doubled, and one more is added for the
        // quotation mark itself.
        let embedded = command_line(&[OsString::from("say \\\\\"this\"")]);
        assert_eq!(embedded, "\"say \\\\\\\\\\\"this\\\"\"");

        // A run at the end is doubled, so the closing quote is not the one that was escaped.
        let trailing = command_line(&[OsString::from(r"c:\a b\")]);
        assert_eq!(trailing, "\"c:\\a b\\\\\"");

        // An empty argument is a pair of quotes rather than nothing at all.
        assert_eq!(command_line(&[OsString::from("")]), "\"\"");

        // And the arguments are separated by one space, in the order they were given.
        let several = command_line(&[
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from("echo hello"),
        ]);
        assert_eq!(several, "/bin/sh -c \"echo hello\"");
    }

    #[cfg(unix)]
    #[test]
    fn a_whole_second_is_expressed_as_a_wait_rather_than_a_refusal() {
        // A nanosecond field of a second or more is not a duration `poll` accepts: it is refused,
        // and a refusal reads as a terminal that has gone, which would stop a session's output for
        // good the first time its application paused.
        let whole = deadline(std::time::Duration::from_secs(1));
        assert_eq!((whole.tv_sec, whole.tv_nsec), (1, 0));
        let mixed = deadline(std::time::Duration::from_millis(1_020));
        assert_eq!((mixed.tv_sec, mixed.tv_nsec), (1, 20_000_000));
        let small = deadline(std::time::Duration::from_millis(20));
        assert_eq!((small.tv_sec, small.tv_nsec), (0, 20_000_000));
    }

    #[test]
    fn a_wait_of_a_whole_second_is_a_wait_rather_than_a_refusal() {
        // A terminal with nothing to read has nothing to read, and has not gone.
        let pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
        let waiter = pty.output_waiter().expect("a waiter");
        let started = std::time::Instant::now();
        assert_eq!(waiter.wait(std::time::Duration::from_secs(1)), Room::NotYet);
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(500),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_shell_runs_in_the_terminal_and_its_output_is_read_back() {
        let mut pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
        let mut reader = pty.reader().expect("a reader");
        let mut shell = pty
            .launch(&crate::testing::posix_script("printf hello"), |_| Ok(()))
            .expect("launches");
        assert!(shell.identity().pid.get() > 0);
        let seen = read_until(&pty, &mut reader, b"hello");
        assert!(
            seen.windows(5).any(|window| window == b"hello"),
            "the shell's output reached the reader"
        );
        let exit = shell.wait().expect("waits");
        assert_eq!(exit.code, 0);
    }

    #[test]
    fn the_environment_is_replaced_rather_than_inherited() {
        // The worker's own process has this set and the launch environment does not carry it, so
        // a shell that sees it would be inheriting rather than being given its environment.
        // Not one of the variables the test shell is deliberately given: those are what a program
        // on this platform needs to start at all, and seeing one would prove nothing.
        let inherited = if cfg!(windows) {
            "COMPUTERNAME"
        } else {
            "HOME"
        };
        assert!(
            std::env::var_os(inherited).is_some(),
            "the test process has {inherited}"
        );
        let mut pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
        let mut reader = pty.reader().expect("a reader");
        let mut shell = pty
            .launch(
                &crate::testing::posix_script(&format!("printf %s \"[${{{inherited}:-absent}}]\"")),
                |_| Ok(()),
            )
            .expect("launches");
        let seen = read_until(&pty, &mut reader, b"[absent]");
        shell.wait().expect("waits");
        assert!(
            seen.windows(8).any(|window| window == b"[absent]"),
            "the worker's own environment did not reach the shell"
        );
    }

    #[test]
    fn a_second_shell_cannot_be_started_in_the_same_terminal() {
        let mut pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
        let mut first = pty
            .launch(&crate::testing::posix_script("exit 0"), |_| Ok(()))
            .expect("launches");
        first.wait().expect("waits");
        assert!(matches!(
            pty.launch(&crate::testing::posix_script("exit 0"), |_| Ok(())),
            Err(WorkerError::Pty { .. })
        ));
    }

    /// KR-REQ-19.04 and KR-REQ-25.14: a start the admission refuses has created no process and
    /// has not used the terminal: the shell is started in it afterwards.
    #[test]
    fn a_start_the_admission_refuses_leaves_the_terminal_unused() {
        let mut pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
        let refused = pty.launch(&crate::testing::posix_script("exit 0"), |_| {
            Err(WorkerError::PermissionDenied {
                detail: "the moment has passed".to_owned(),
            })
        });
        assert!(matches!(refused, Err(WorkerError::PermissionDenied { .. })));
        let mut shell = pty
            .launch(&crate::testing::posix_script("exit 0"), |_| Ok(()))
            .expect("the terminal was not used by the refused start");
        assert_eq!(shell.wait().expect("waits").code, 0);
    }

    /// KR-REQ-19.04 and KR-REQ-25.14: on Windows the system reads the directory and looks for the
    /// program as it creates the process, after the admission has allowed the start, and a read
    /// that waits can carry the start past its moment. So the admission is asked again once the
    /// process exists, before it runs: a start whose moment has passed by then ends the process
    /// unstarted and fails with the admission's own refusal.
    ///
    /// The moment passes here as the process is created: the admission allows the start while no
    /// process exists and refuses it once one does, which is only so if it is asked after the
    /// creation. The process is ended without having run, and nothing it would have done is done.
    #[cfg(windows)]
    #[test]
    fn a_start_whose_moment_passes_as_the_process_is_created_runs_nothing() {
        use crate::windows::conpty::CREATED;

        let host = kr_ipc::testing::TempHost::create();
        let work = host.root().join("work");
        std::fs::create_dir(&work).expect("the directory the shell is to start in");
        let mut command = crate::testing::posix_script(": > ran-here");
        command.cwd = work.display().to_string();
        let mut pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
        CREATED.with(|created| created.set(None));
        let created = std::cell::RefCell::new(None);
        let refused = pty.launch(&command, |_| match CREATED.with(std::cell::Cell::get) {
            None => Ok(()),
            Some(process) => {
                *created.borrow_mut() = kr_ipc::identity::process_start_identity(process).ok();
                Err(WorkerError::PermissionDenied {
                    detail: "the moment has passed".to_owned(),
                })
            }
        });
        let outcome = match &refused {
            Ok(_) => "a shell was started".to_owned(),
            Err(error) => error.to_string(),
        };
        assert!(
            matches!(refused, Err(WorkerError::PermissionDenied { .. })),
            "the start is refused with the admission's refusal: {outcome}"
        );
        let process = created
            .into_inner()
            .expect("the process existed when the start was refused");
        // The process goes: ended by the refused start, which waits for no run of its own.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while kr_ipc::identity::process_state(&process) != kr_ipc::identity::ProcessState::Ended {
            assert!(
                std::time::Instant::now() < deadline,
                "the process a refused start created is still there"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            !work.join("ran-here").exists(),
            "the shell ran, though its start was refused"
        );
        assert!(pty.was_used(), "the terminal was handed to the start");
    }

    /// KR-REQ-19.04 and KR-REQ-25.14: once the admission has allowed the start, the directory is
    /// not read again. The directory is moved away inside the admission, as a mount or an owner
    /// could take it, and the shell still starts in the directory that was opened before: reading
    /// the name again would find nothing there and start the shell in the home directory instead.
    #[cfg(unix)]
    #[test]
    fn the_directory_is_not_read_again_once_the_start_is_admitted() {
        let host = kr_ipc::testing::TempHost::create();
        let (work, moved, home) = (
            host.root().join("work"),
            host.root().join("moved"),
            host.root().join("home"),
        );
        std::fs::create_dir(&work).expect("the directory the shell is to start in");
        std::fs::create_dir(&home).expect("the home directory");
        let mut command = crate::testing::posix_script(": > ran-here");
        command.cwd = work.display().to_string();
        command
            .environment
            .push(("HOME".to_owned(), home.display().to_string()));
        let mut pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
        let mut shell = pty
            .launch(&command, |named_is_there| {
                assert!(named_is_there, "the directory is there when it is asked");
                std::fs::rename(&work, &moved).expect("the directory goes");
                Ok(())
            })
            .expect("launches");
        shell.wait().expect("the shell ends");
        assert!(
            moved.join("ran-here").exists(),
            "the shell started in the directory that was opened; the home directory holds {:?}",
            std::fs::read_dir(&home).map(|entries| entries
                .flatten()
                .map(|entry| entry.file_name())
                .collect::<Vec<_>>())
        );
    }

    /// A directory that is not there is told to the admission, and the start goes ahead in the
    /// account's home directory when the admission allows it.
    #[cfg(unix)]
    #[test]
    fn a_directory_that_is_not_there_is_told_to_the_admission_and_the_home_directory_is_used() {
        let host = kr_ipc::testing::TempHost::create();
        let home = host.root().join("home");
        std::fs::create_dir(&home).expect("the home directory");
        let mut command = crate::testing::posix_script(": > ran-here");
        command.cwd = host.root().join("not-there").display().to_string();
        command
            .environment
            .push(("HOME".to_owned(), home.display().to_string()));
        let mut pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
        let told = std::cell::Cell::new(None);
        let mut shell = pty
            .launch(&command, |named_is_there| {
                told.set(Some(named_is_there));
                Ok(())
            })
            .expect("launches");
        shell.wait().expect("the shell ends");
        assert_eq!(told.get(), Some(false));
        assert!(
            home.join("ran-here").exists(),
            "the shell ran in the home directory"
        );
    }

    /// A program that cannot be run is a start that failed: it is reported when the start is
    /// asked for, and not as a shell that began and ended. One that is not there and one that is
    /// there and may not be run are both refused.
    #[cfg(unix)]
    #[test]
    fn a_program_that_cannot_be_run_fails_the_start() {
        use std::os::unix::fs::PermissionsExt as _;

        let host = kr_ipc::testing::TempHost::create();
        let not_executable = host.root().join("not-executable");
        std::fs::write(&not_executable, b"#!/bin/sh\nexit 0\n").expect("a file");
        std::fs::set_permissions(&not_executable, std::fs::Permissions::from_mode(0o600))
            .expect("that may not be run");
        for program in [host.root().join("not-there"), not_executable] {
            let mut command = crate::testing::posix_script("exit 0");
            command.program = program.display().to_string();
            let mut pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
            let outcome = pty.launch(&command, |_| Ok(()));
            assert!(
                matches!(outcome, Err(WorkerError::Pty { .. })),
                "{program:?} was started: {outcome:?}"
            );
        }
    }

    /// A directory that can be entered and not listed is one a shell starts in: entering it needs
    /// the right to search it and not the right to read it.
    #[cfg(unix)]
    #[test]
    fn a_directory_that_can_be_entered_and_not_listed_is_where_the_shell_starts() {
        use std::os::unix::fs::PermissionsExt as _;

        let host = kr_ipc::testing::TempHost::create();
        let (work, home) = (host.root().join("work"), host.root().join("home"));
        std::fs::create_dir(&work).expect("the directory the shell is to start in");
        std::fs::create_dir(&home).expect("the home directory");
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o300))
            .expect("that can be entered and not listed");
        let mut command = crate::testing::posix_script(": > ran-here");
        command.cwd = work.display().to_string();
        command
            .environment
            .push(("HOME".to_owned(), home.display().to_string()));
        let mut pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
        let told = std::cell::Cell::new(None);
        let started = pty.launch(&command, |named_is_there| {
            told.set(Some(named_is_there));
            Ok(())
        });
        let mut shell = started.expect("launches");
        shell.wait().expect("the shell ends");
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700))
            .expect("it can be read again");
        assert_eq!(told.get(), Some(true), "the directory is there");
        assert!(work.join("ran-here").exists(), "the shell started in it");
    }

    /// A directory that is there and cannot be entered is a start that fails, and the shell is not
    /// started in the home directory instead. Run as the superuser, a mode stops nothing, and the
    /// case then has nothing to show.
    #[cfg(unix)]
    #[test]
    fn a_directory_that_is_there_and_cannot_be_entered_is_a_start_that_fails() {
        use std::os::unix::fs::PermissionsExt as _;

        let host = kr_ipc::testing::TempHost::create();
        let (work, home) = (host.root().join("work"), host.root().join("home"));
        std::fs::create_dir(&work).expect("the directory the shell is to start in");
        std::fs::create_dir(&home).expect("the home directory");
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o000))
            .expect("that cannot be entered");
        let enforced = std::fs::read_dir(&work).is_err();
        let mut command = crate::testing::posix_script(": > ran-here");
        command.cwd = work.display().to_string();
        command
            .environment
            .push(("HOME".to_owned(), home.display().to_string()));
        let mut pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
        let told = std::cell::Cell::new(None);
        let outcome = pty.launch(&command, |named_is_there| {
            told.set(Some(named_is_there));
            Ok(())
        });
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700))
            .expect("it can be entered again");
        if !enforced {
            return;
        }
        assert_eq!(told.get(), Some(true), "the directory is there");
        assert!(
            matches!(outcome, Err(WorkerError::Pty { .. })),
            "the start fails: {outcome:?}"
        );
        assert!(!home.join("ran-here").exists(), "and nothing ran at home");
    }

    /// The shell has the terminal and nothing else of the worker's descriptors: one the worker
    /// holds open, with nothing to close it on exec, is not open in the shell, whether it was open
    /// low in the table, far up it, or is opened while the start is being admitted, above all the
    /// others. The shell lists what it has open, and the control is the terminal itself, which is.
    #[cfg(unix)]
    #[test]
    fn the_shell_inherits_no_descriptor_of_the_workers() {
        use std::os::fd::AsRawFd as _;

        let held = std::fs::File::open("/").expect("a descriptor of the worker's");
        // Numbers the shell and the program it lists with have none of their own at.
        let low =
            rustix::io::fcntl_dupfd_cloexec(&held, 100).expect("a descriptor low in the table");
        rustix::io::fcntl_setfd(&low, rustix::io::FdFlags::empty()).expect("left open on exec");
        let far = spawn::tests::descriptor_far_up(&held);
        let mut pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
        let mut reader = pty.reader().expect("a reader");
        let command = crate::testing::posix_script(
            "printf '[terminal:'; [ -e /dev/fd/1 ] && printf yes; printf ']'; \
             printf '[open:'; ls /dev/fd | tr '\\n' ' '; printf '][done]'",
        );
        // Opened by the admission, which is after the descriptors were read, and above them all.
        let late = std::cell::RefCell::new(None);
        let mut shell = pty
            .launch(&command, |_| {
                // A good way above the others, which no fixed margin above the highest of them
                // would reach, or just above them where the table ends soon after.
                let opened = rustix::io::fcntl_dupfd_cloexec(&held, far.as_raw_fd() + 100)
                    .or_else(|_| rustix::io::fcntl_dupfd_cloexec(&held, far.as_raw_fd() + 1))
                    .expect("a descriptor above the others");
                rustix::io::fcntl_setfd(&opened, rustix::io::FdFlags::empty())
                    .expect("left open on exec");
                *late.borrow_mut() = Some(opened);
                Ok(())
            })
            .expect("launches");
        let seen = read_until(&pty, &mut reader, b"[done]");
        shell.wait().expect("waits");
        let seen = String::from_utf8_lossy(&seen);
        assert!(
            seen.contains("[terminal:yes]"),
            "the shell has the terminal: {seen:?}"
        );
        let open: Vec<i32> = seen
            .split("[open:")
            .nth(1)
            .and_then(|rest| rest.split(']').next())
            .expect("the shell listed what it has open")
            .split_whitespace()
            .filter_map(|number| number.parse().ok())
            .collect();
        assert!(
            !open.is_empty(),
            "the shell listed its descriptors: {seen:?}"
        );
        let late = late.borrow();
        let workers = [
            ("low", low.as_raw_fd()),
            ("far", far.as_raw_fd()),
            (
                "opened by the admission",
                late.as_ref().expect("opened").as_raw_fd(),
            ),
        ];
        for (which, number) in workers {
            assert!(
                !open.contains(&number),
                "the descriptor of the worker's that was {which}, {number}, is open in the shell: {open:?}"
            );
        }
    }

    #[test]
    fn resizing_is_validated_before_the_kernel_is_asked() {
        let mut pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
        assert!(matches!(
            pty.resize(Dimensions::new(0, 24)),
            Err(WorkerError::Dimensions(_))
        ));
        assert_eq!(pty.dimensions(), Dimensions::new(80, 24));
        pty.resize(Dimensions::new(100, 30)).expect("resizes");
        assert_eq!(pty.dimensions(), Dimensions::new(100, 30));
    }

    #[cfg(unix)]
    #[test]
    fn a_stop_request_reaches_the_shell_and_its_group() {
        let mut pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
        let mut shell = pty
            .launch(&crate::testing::posix_script("sleep 30"), |_| Ok(()))
            .expect("launches");
        shell.request_stop().expect("asks");
        let exit = shell.wait().expect("waits");
        assert!(exit.signalled(), "the shell ended on a signal");
    }

    #[cfg(unix)]
    #[test]
    fn a_shell_that_ignores_the_request_is_ended_by_force() {
        let mut pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
        let mut shell = pty
            .launch(
                &crate::testing::posix_script("trap '' TERM; while :; do sleep 1; done"),
                |_| Ok(()),
            )
            .expect("launches");
        shell.force_stop().expect("forces");
        let exit = shell.wait().expect("waits");
        assert!(exit.signalled());
    }

    #[cfg(unix)]
    #[test]
    fn signalling_a_shell_that_has_already_ended_succeeds() {
        let mut pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
        let mut shell = pty
            .launch(&crate::testing::posix_script("exit 3"), |_| Ok(()))
            .expect("launches");
        let exit = shell.wait().expect("waits");
        assert_eq!(exit.code, 3);
        shell.request_stop().expect("asking again succeeds");
        shell.force_stop().expect("forcing again succeeds");
    }
}

/// What waiting on the terminal established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Room {
    /// The terminal will take more input now.
    Ready,
    /// It will not yet. Nothing is wrong; the caller may look at its own state and wait again.
    NotYet,
    /// The terminal has gone, and nothing more will reach it.
    Gone,
}

/// A handle on the terminal that can be waited on until it will take more input.
///
/// The writer needs to know *when* the terminal will take more without being inside a write while
/// it finds out: a write that waits holds the bytes it was given in a system call, where nothing
/// can decide that the lease they belong to has ended. This waits instead, so a takeover reaches a
/// waiting writer at once and the bytes it was holding are abandoned rather than delivered.
#[cfg(unix)]
#[derive(Debug)]
pub struct InputWaiter {
    handle: std::os::fd::OwnedFd,
}

#[cfg(unix)]
impl InputWaiter {
    /// Builds a waiter for a terminal, or `None` when it has no descriptor to wait on.
    fn of(master: &dyn MasterPty) -> Option<Self> {
        let raw = master.as_raw_fd()?;
        Some(Self {
            handle: descriptor::duplicate(raw)?,
        })
    }

    /// Waits until the terminal will take more input, or until `timeout` passes.
    #[must_use]
    pub fn wait(&self, timeout: std::time::Duration) -> Room {
        wait_for(&self.handle, rustix::event::PollFlags::OUT, timeout)
    }
}

/// A handle on the terminal that can be waited on until the application has written something.
#[cfg(unix)]
#[derive(Debug)]
pub struct OutputWaiter {
    handle: std::os::fd::OwnedFd,
}

#[cfg(unix)]
impl OutputWaiter {
    /// Builds a waiter for a terminal, or `None` when it has no descriptor to wait on.
    fn of(master: &dyn MasterPty) -> Option<Self> {
        let raw = master.as_raw_fd()?;
        Some(Self {
            handle: descriptor::duplicate(raw)?,
        })
    }

    /// Waits until the terminal has output to read, or until `timeout` passes.
    #[must_use]
    pub fn wait(&self, timeout: std::time::Duration) -> Room {
        wait_for(&self.handle, rustix::event::PollFlags::IN, timeout)
    }
}

/// Waits for one direction of a terminal to be usable.
#[cfg(unix)]
fn wait_for(
    handle: &std::os::fd::OwnedFd,
    interest: rustix::event::PollFlags,
    timeout: std::time::Duration,
) -> Room {
    use std::os::fd::AsFd as _;

    let handle = handle.as_fd();
    let mut fds = [rustix::event::PollFd::new(&handle, interest)];
    let timeout = deadline(timeout);
    match rustix::event::poll(&mut fds, Some(&timeout)) {
        // Interrupted, or nothing happened before the deadline. Neither says the terminal is ready,
        // and neither says it never will be; the caller looks at its own state and asks again.
        Ok(0) | Err(rustix::io::Errno::INTR) => Room::NotYet,
        Ok(_) => {
            let ready = fds[0].revents();
            if ready.intersects(
                rustix::event::PollFlags::HUP
                    | rustix::event::PollFlags::ERR
                    | rustix::event::PollFlags::NVAL,
            ) {
                // A terminal whose other side has gone still has what it was written: output that
                // is there to be read is read before this is called an ending.
                if interest.contains(rustix::event::PollFlags::IN)
                    && ready.contains(rustix::event::PollFlags::IN)
                {
                    Room::Ready
                } else {
                    Room::Gone
                }
            } else if ready.contains(interest) {
                Room::Ready
            } else {
                Room::NotYet
            }
        }
        Err(_) => Room::Gone,
    }
}

/// Expresses a wait the way the system call wants it.
///
/// Whole seconds and the nanoseconds left over. A nanosecond field of a second or more is not a
/// duration this call accepts: it is refused, and a refusal reads as a terminal that has gone, which
/// would stop a session's output for good the first time its application paused.
#[cfg(unix)]
fn deadline(timeout: std::time::Duration) -> rustix::event::Timespec {
    rustix::event::Timespec {
        tv_sec: i64::try_from(timeout.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: i64::from(timeout.subsec_nanos()),
    }
}

/// Opens the slave end of a terminal for the shell.
///
/// The terminal library keeps the end it opened to itself, and a shell started by this host needs
/// one of its own. Linux hands it over from the master, which does not depend on the terminal's
/// name being visible where this runs; where the master will not, and on the other systems, it is
/// opened by the name the master reports. It is not made the opening process's controlling
/// terminal, which is the shell's to be.
///
/// # Errors
///
/// Returns [`WorkerError::Pty`] when the terminal gives no end and reports no name that opens.
#[cfg(unix)]
fn open_slave(master: &dyn MasterPty) -> Result<std::os::fd::OwnedFd> {
    const OPERATION: &str = "open the slave end of the pseudo-terminal";
    #[cfg(target_os = "linux")]
    if let Some(master) = master.as_raw_fd().and_then(descriptor::duplicate)
        && let Ok(slave) = rustix::pty::ioctl_tiocgptpeer(
            &master,
            rustix::pty::OpenptFlags::RDWR
                | rustix::pty::OpenptFlags::NOCTTY
                | rustix::pty::OpenptFlags::CLOEXEC,
        )
    {
        return Ok(slave);
    }
    let name = master
        .tty_name()
        .ok_or_else(|| WorkerError::pty(OPERATION, "the terminal reports no name"))?;
    rustix::fs::open(
        &name,
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| WorkerError::pty(OPERATION, error))
}

/// Puts a terminal into the mode where it answers rather than waits.
///
/// # Errors
///
/// Returns [`WorkerError::Pty`] when the terminal's descriptor cannot be found, duplicated or
/// changed. A terminal left in the mode where a read waits would hold the read loop inside a read
/// for as long as nothing arrived, and a closing session's measure of what has been read with it,
/// so such a terminal is refused rather than used.
#[cfg(unix)]
fn answer_rather_than_wait(master: &dyn MasterPty) -> Result<()> {
    const OPERATION: &str = "make the pseudo-terminal answer rather than wait";
    let raw = master
        .as_raw_fd()
        .ok_or_else(|| WorkerError::pty(OPERATION, "the terminal has no descriptor"))?;
    let handle = descriptor::duplicate(raw)
        .ok_or_else(|| WorkerError::pty(OPERATION, "its descriptor could not be duplicated"))?;
    let flags =
        rustix::fs::fcntl_getfl(&handle).map_err(|error| WorkerError::pty(OPERATION, error))?;
    rustix::fs::fcntl_setfl(&handle, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(|error| WorkerError::pty(OPERATION, error))
}

/// Waiting for the terminal's output, which on Windows is waiting for the read that was started.
#[cfg(windows)]
pub use crate::windows::conpty::OutputWaiter;

/// Builds a Windows command line the way the operating system takes one apart again.
///
/// An argument is quoted when it is empty or contains a space, a tab or a quotation mark. Inside
/// the quotes the rule is the documented inverse of how a program's own argument parser reads it
/// back: a run of `n` backslashes before a quotation mark is written as `2n + 1` of them, a run
/// before the closing quote as `2n`, and a run anywhere else exactly as it is. A path is mostly
/// backslashes, so a version of this that dropped them would start the wrong program or none.
///
/// That is the reading of the Microsoft C runtime, which almost every Windows program uses, and a
/// program that takes its command line apart itself can read it otherwise. A program built on
/// MSYS2, such as the `sh.exe` Git for Windows installs, reads a pair of backslashes inside quotes
/// as one backslash unless a quotation mark follows, so an argument that is quoted and holds `\\`
/// reaches it with one where two were given. The backslashes of an argument that is not quoted, and
/// those that come before a quotation mark or before the closing quote, are read the same by both.
/// A script for such a shell therefore writes a backslash it needs as the octal escape `\134`.
///
/// It lives here rather than beside the console it is for, so that it can be tested on a machine
/// that cannot run Windows: the rule is a string rule and has nothing of the platform in it. The
/// control daemon's Windows supervisor quotes the command its scheduled task runs with it too, so
/// there is one rule for every command line this host writes.
#[must_use]
pub fn command_line(argv: &[std::ffi::OsString]) -> String {
    let mut line = String::new();
    for argument in argv {
        if !line.is_empty() {
            line.push(' ');
        }
        let argument = argument.to_string_lossy();
        if !argument.is_empty() && !argument.contains([' ', '\t', '"']) {
            line.push_str(&argument);
            continue;
        }
        line.push('"');
        let mut backslashes = 0_usize;
        for character in argument.chars() {
            match character {
                '\\' => backslashes += 1,
                '"' => {
                    for _ in 0..=backslashes.saturating_mul(2) {
                        line.push('\\');
                    }
                    backslashes = 0;
                    line.push('"');
                }
                _ => {
                    for _ in 0..backslashes {
                        line.push('\\');
                    }
                    backslashes = 0;
                    line.push(character);
                }
            }
        }
        for _ in 0..backslashes.saturating_mul(2) {
            line.push('\\');
        }
        line.push('"');
    }
    line
}

/// A waiter for room in a terminal whose writes answer rather than wait.
///
/// A pipe has nothing to wait on for room: what knows whether there is any is the write itself, and
/// in this mode it answers. So this waits a little and says to ask again, which is what turns a
/// writer that would spin into one that comes back shortly. A terminal that has gone is reported by
/// the write rather than here, because the write is the thing that finds out.
#[cfg(windows)]
#[derive(Debug)]
pub struct InputWaiter {}

#[cfg(windows)]
impl InputWaiter {
    /// Builds the waiter. Every terminal on this platform has one.
    const fn of(_master: &dyn MasterPty) -> Option<Self> {
        Some(Self {})
    }

    /// Waits `timeout` and says the writer may ask the terminal again.
    #[must_use]
    pub fn wait(&self, timeout: std::time::Duration) -> Room {
        std::thread::sleep(timeout);
        Room::Ready
    }
}

/// The place in this crate that borrows a descriptor the terminal library owns.
///
/// The workspace forbids unsafe code; this crate denies it and relaxes the rule here, because
/// duplicating a descriptor the terminal owns has no safe form: the terminal library hands out a
/// raw number and nothing else.
#[cfg(unix)]
mod descriptor {
    #![expect(
        unsafe_code,
        reason = "duplicating a descriptor the terminal owns has no safe form"
    )]

    /// Duplicates a descriptor the caller keeps open for at least the length of this call.
    ///
    /// The duplicate is closed when a program is run, so that no program this worker starts holds
    /// the terminal's master.
    pub fn duplicate(raw: std::os::fd::RawFd) -> Option<std::os::fd::OwnedFd> {
        // SAFETY: `raw` is the terminal's own master descriptor, which the `Pty` that produced it
        // holds open, and this borrow lives no longer than this call. The duplicate it makes is a
        // descriptor of its own, closed when it is dropped.
        let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(raw) };
        rustix::io::fcntl_dupfd_cloexec(borrowed, 0).ok()
    }
}
