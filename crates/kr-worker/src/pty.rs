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
#[cfg(unix)]
use portable_pty::native_pty_system;
use portable_pty::{CommandBuilder, MasterPty, PtySize};

use crate::error::{Result, WorkerError};

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
    slave: Option<Box<dyn portable_pty::SlavePty + Send>>,
    /// The event a started read of this terminal's output is signalled on.
    ///
    /// Windows has no readiness to ask a pipe about: what says there is output is the read the
    /// reader already started, and this is how the waiter beside it waits for that read.
    #[cfg(windows)]
    output_event: std::os::windows::io::OwnedHandle,
    dimensions: Dimensions,
}

impl std::fmt::Debug for Pty {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Pty")
            .field("dimensions", &self.dimensions)
            .field("shell_started", &self.slave.is_none())
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
        answer_rather_than_wait(pair.master.as_ref());
        Ok(Self {
            master: pair.master,
            slave: Some(pair.slave),
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
        let (master, slave) = crate::conpty::open(pty_size(dimensions))
            .map_err(|error| WorkerError::pty("create the pseudo-terminal", error))?;
        let output_event = master
            .output_event()
            .map_err(|error| WorkerError::pty("create the pseudo-terminal", error))?;
        Ok(Self {
            master: Box::new(master),
            slave: Some(Box::new(slave)),
            output_event,
            dimensions,
        })
    }

    /// Returns the geometry the terminal is currently set to.
    #[must_use]
    pub const fn dimensions(&self) -> Dimensions {
        self.dimensions
    }

    /// Starts the root shell inside the terminal.
    ///
    /// The environment is replaced outright rather than inherited: the worker's own environment is
    /// not the session's, and section 7 decides what the session gets.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::Pty`] when the shell cannot be started, or when a shell has already
    /// been started in this terminal.
    pub fn launch(&mut self, command: &ShellCommand) -> Result<RootShell> {
        let slave = self.slave.take().ok_or_else(|| {
            WorkerError::pty("start the root shell", "a shell is already running")
        })?;
        let mut builder = CommandBuilder::new(&command.program);
        for argument in &command.arguments {
            builder.arg(argument);
        }
        builder.env_clear();
        for (name, value) in &command.environment {
            builder.env(name, value);
        }
        builder.cwd(&command.cwd);
        let child = slave
            .spawn_command(builder)
            .map_err(|error| WorkerError::pty("start the root shell", error))?;
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
        })
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

    /// Sends the terminal's interrupt to the group it has in the foreground.
    ///
    /// # Errors
    ///
    /// Always returns an error: a Windows console pseudo-terminal has no foreground process group.
    #[cfg(not(unix))]
    pub fn interrupt_foreground(&self) -> Result<()> {
        Err(WorkerError::pty(
            "interrupt the foreground application",
            "a console pseudo-terminal has no foreground process group",
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

    #[cfg(not(unix))]
    fn signal_group(&mut self, signal: Signal) -> Result<()> {
        match signal {
            // The per-session Job Object carries group termination on Windows; the child killer
            // ends the shell itself.
            Signal::Terminate | Signal::Kill => self
                .child
                .kill()
                .map_err(|error| WorkerError::pty("signal the root shell", error)),
            // There is no Unix signal to send. The configured console interrupt belongs to the
            // Windows qualification pass, and reporting success for an action that did not happen
            // would be worse than saying so.
            Signal::Interrupt => Err(WorkerError::pty(
                "interrupt the foreground application",
                "the Windows console interrupt is not yet qualified",
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

    fn shell(program: &str, arguments: &[&str]) -> ShellCommand {
        ShellCommand {
            program: program.to_owned(),
            arguments: arguments
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
            cwd: "/".to_owned(),
            environment: vec![
                ("TERM".to_owned(), "xterm-256color".to_owned()),
                ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
            ],
        }
    }

    #[test]
    fn the_terminal_exists_before_any_shell_runs() {
        let pty = Pty::open(Dimensions::new(120, 40)).expect("opens");
        assert_eq!(pty.dimensions(), Dimensions::new(120, 40));
        // A reader exists before anything has been launched into it.
        pty.reader().expect("a reader");
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
            .launch(&shell("/bin/sh", &["-c", "printf hello"]))
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
        // The worker's own process has HOME set and the launch environment does not carry it,
        // so a shell that sees it would be inheriting rather than being given its environment.
        assert!(
            std::env::var_os("HOME").is_some(),
            "the test process has HOME"
        );
        let mut pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
        let mut reader = pty.reader().expect("a reader");
        let mut shell = pty
            .launch(&shell(
                "/bin/sh",
                &["-c", "printf %s \"[${HOME:-absent}]\""],
            ))
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
            .launch(&shell("/bin/sh", &["-c", "exit 0"]))
            .expect("launches");
        first.wait().expect("waits");
        assert!(matches!(
            pty.launch(&shell("/bin/sh", &["-c", "exit 0"])),
            Err(WorkerError::Pty { .. })
        ));
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
            .launch(&shell("/bin/sh", &["-c", "sleep 30"]))
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
            .launch(&shell(
                "/bin/sh",
                &["-c", "trap '' TERM; while :; do sleep 1; done"],
            ))
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
            .launch(&shell("/bin/sh", &["-c", "exit 3"]))
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

/// Puts a terminal into the mode where it answers rather than waits.
#[cfg(unix)]
fn answer_rather_than_wait(master: &dyn MasterPty) {
    let Some(raw) = master.as_raw_fd() else {
        return;
    };
    let Some(handle) = descriptor::duplicate(raw) else {
        return;
    };
    if let Ok(flags) = rustix::fs::fcntl_getfl(&handle) {
        let _ = rustix::fs::fcntl_setfl(&handle, flags | rustix::fs::OFlags::NONBLOCK);
    }
}

/// Waiting for the terminal's output, which on Windows is waiting for the read that was started.
#[cfg(windows)]
pub use crate::conpty::OutputWaiter;

/// Builds a Windows command line the way the operating system takes one apart again.
///
/// An argument is quoted when it is empty or contains a space, a tab or a quotation mark. Inside
/// the quotes the rule is the documented inverse of how a program's own argument parser reads it
/// back: a run of `n` backslashes before a quotation mark is written as `2n + 1` of them, a run
/// before the closing quote as `2n`, and a run anywhere else exactly as it is. A path is mostly
/// backslashes, so a version of this that dropped them would start the wrong program or none.
///
/// It lives here rather than beside the console it is for, so that it can be tested on a machine
/// that cannot run Windows: the rule is a string rule and has nothing of the platform in it.
#[cfg(any(windows, test))]
pub(crate) fn command_line(argv: &[std::ffi::OsString]) -> String {
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

/// The one place in this crate that borrows a descriptor the operating system owns.
///
/// The workspace forbids unsafe code; this crate denies it and relaxes the rule here alone, because
/// duplicating a descriptor the terminal owns has no safe form: the terminal library hands out a
/// raw number and nothing else.
#[cfg(unix)]
mod descriptor {
    #![expect(
        unsafe_code,
        reason = "duplicating a descriptor the terminal owns has no safe form"
    )]

    /// Duplicates a descriptor the caller keeps open for at least the length of this call.
    pub fn duplicate(raw: std::os::fd::RawFd) -> Option<std::os::fd::OwnedFd> {
        // SAFETY: `raw` is the terminal's own master descriptor, which the `Pty` that produced it
        // holds open, and this borrow lives no longer than this call. The duplicate it makes is a
        // descriptor of its own, closed when it is dropped.
        let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(raw) };
        rustix::io::dup(borrowed).ok()
    }
}
