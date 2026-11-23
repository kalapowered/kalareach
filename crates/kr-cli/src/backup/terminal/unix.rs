//! The setup dialogue's terminal calls on Unix: `setrlimit`, `prctl` and `termios`.

use std::fs::File;
use std::os::fd::AsFd as _;

use kr_client::shown;
use kr_client::shown::Shown;
use rustix::termios::{OptionalActions, Termios};

use crate::error::{CliError, Result};

/// Keeps this process out of a core dump, before the seed exists.
///
/// The core size limit is zero. On Linux the process is also made non-dumpable, because a core
/// pattern that pipes to a handler ignores the limit. A failure of either refuses the setup.
///
/// # Errors
///
/// Returns the refusal when either call fails.
pub fn keep_out_of_a_dump() -> Result<()> {
    let refused = |error: rustix::io::Errno| {
        CliError::Other(shown!(
            "the recovery kit is not made because this process could not be kept out of a core \
             dump: {}",
            crate::shown::errno(error)
        ))
    };
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(refused)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(refused)?;
    Ok(())
}

/// Opens the controlling terminal as itself, for writing, with no buffer of ours in between. The
/// command runs only where standard output is that terminal.
///
/// # Errors
///
/// Returns the error that opening it gave.
pub fn open_output() -> std::io::Result<File> {
    File::options().write(true).open("/dev/tty")
}

/// The terminal's modes as they were found. They are put back when this is dropped, and the input
/// still waiting is discarded with them: what was pasted past a line the dialogue read is not for
/// the shell.
pub struct Terminal {
    input: File,
    saved: Termios,
}

impl Terminal {
    /// Reads the modes of the terminal on standard input.
    ///
    /// # Errors
    ///
    /// Returns a terminal failure when the terminal cannot be reached or its modes cannot be read.
    pub fn hold() -> Result<Self> {
        let input = std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .map(File::from)
            .map_err(|error| {
                CliError::Terminal(shown!(
                    "the terminal could not be reached: {}",
                    Shown::io(&error)
                ))
            })?;
        let saved = rustix::termios::tcgetattr(&input).map_err(|error| {
            CliError::Terminal(shown!(
                "the terminal's modes could not be read: {}",
                crate::shown::errno(error)
            ))
        })?;
        Ok(Self { input, saved })
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        // The call waits for output to drain, so a signal can end it early; it is asked again.
        while let Err(rustix::io::Errno::INTR) =
            rustix::termios::tcsetattr(&self.input, OptionalActions::Flush, &self.saved)
        {}
    }
}
