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
use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShellExit {
    /// The exit code the shell returned.
    pub code: u32,
    /// True when a signal ended it rather than a normal return.
    pub signalled: bool,
}

/// The session's pseudo-terminal, created before any shell runs.
pub struct Pty {
    master: Box<dyn MasterPty + Send>,
    slave: Option<Box<dyn portable_pty::SlavePty + Send>>,
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
    pub fn open(dimensions: Dimensions) -> Result<Self> {
        dimensions.validate()?;
        let pair = native_pty_system()
            .openpty(pty_size(dimensions))
            .map_err(|error| WorkerError::pty("create the pseudo-terminal", error))?;
        Ok(Self {
            master: pair.master,
            slave: Some(pair.slave),
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
        let identity = kr_ipc::identity::process_start_identity(pid)?;
        Ok(RootShell {
            child,
            identity,
            process_group: self.master.process_group_leader(),
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

    /// Sends the terminal's interrupt to the foreground process group.
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
        use portable_pty::ChildKiller as _;

        match signal {
            // The per-session Job Object carries group termination on Windows; the child killer
            // ends the shell itself.
            Signal::Terminate | Signal::Kill => self
                .child
                .kill()
                .map_err(|error| WorkerError::pty("signal the root shell", error)),
            Signal::Interrupt => Ok(()),
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
        signalled: status.signal().is_some(),
    }
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

    #[test]
    fn a_shell_runs_in_the_terminal_and_its_output_is_read_back() {
        let mut pty = Pty::open(Dimensions::new(80, 24)).expect("opens");
        let mut reader = pty.reader().expect("a reader");
        let mut shell = pty
            .launch(&shell("/bin/sh", &["-c", "printf hello"]))
            .expect("launches");
        assert!(shell.identity().pid.get() > 0);
        let mut seen = Vec::new();
        let mut buffer = [0_u8; 256];
        while let Ok(read) = reader.read(&mut buffer) {
            if read == 0 {
                break;
            }
            seen.extend_from_slice(&buffer[..read]);
            if seen.windows(5).any(|window| window == b"hello") {
                break;
            }
        }
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
        let mut seen = Vec::new();
        let mut buffer = [0_u8; 256];
        while let Ok(read) = reader.read(&mut buffer) {
            if read == 0 {
                break;
            }
            seen.extend_from_slice(&buffer[..read]);
            if seen.windows(8).any(|window| window == b"[absent]") {
                break;
            }
        }
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
        assert!(exit.signalled, "the shell ended on a signal");
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
        assert!(exit.signalled);
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
