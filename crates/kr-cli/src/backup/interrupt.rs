//! What ends a command that holds a secret or has written files before it is done.
//!
//! Once a handler for the interrupt is installed, Ctrl-C no longer ends the process by itself: the
//! command has to notice it, put the terminal back, remove what it wrote and say so. A termination
//! request, a hang-up (the terminal went away) and Ctrl-\ mean the same; the last would otherwise
//! end the process with a core dump that holds whatever it was holding. A command that waits on
//! this makes the wait cancellable, because a blocking read is not ended by a signal that
//! restarts it.
//!
//! Windows catches Ctrl-C and Ctrl-Break once [`Interrupt::arm`] has installed the handler. A
//! command arms it before it reads a console, which it reads in short turns that look at a flag:
//! the kit, and each answer on its thread of its own, which the command waits for so that the
//! console's modes are back before it says that it stopped. It does not arm it before it reads a
//! pipe, which a handler cannot end: there Ctrl-C ends the process, which has written and changed
//! nothing.

use kr_client::shown;
use kr_client::shown::Shown;

use crate::error::{CliError, Result};

/// The signals that mean stop, and clean up first.
pub struct Interrupt {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(unix)]
    hangup: tokio::signal::unix::Signal,
    #[cfg(unix)]
    quit: tokio::signal::unix::Signal,
    #[cfg(windows)]
    handlers: Option<(
        tokio::signal::windows::CtrlC,
        tokio::signal::windows::CtrlBreak,
    )>,
}

kr_client::debug_as_name!(Interrupt);

impl Interrupt {
    /// Installs the handlers a platform allows before a secret is read.
    ///
    /// # Errors
    ///
    /// Returns a failure when the handlers cannot be installed.
    pub fn install() -> Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};

            let failed = |error: std::io::Error| {
                CliError::Other(shown!(
                    "the interrupt could not be handled: {}",
                    Shown::io(&error)
                ))
            };
            Ok(Self {
                interrupt: signal(SignalKind::interrupt()).map_err(failed)?,
                terminate: signal(SignalKind::terminate()).map_err(failed)?,
                hangup: signal(SignalKind::hangup()).map_err(failed)?,
                quit: signal(SignalKind::quit()).map_err(failed)?,
            })
        }
        #[cfg(windows)]
        {
            Ok(Self { handlers: None })
        }
    }

    /// Installs what [`Self::install`] could not, before anything is read that a handler can end,
    /// and not before a read that it cannot.
    ///
    /// # Errors
    ///
    /// Returns a failure when the handler cannot be installed.
    pub fn arm(&mut self) -> Result<()> {
        #[cfg(windows)]
        if self.handlers.is_none() {
            let failed = |error: std::io::Error| {
                CliError::Other(shown!(
                    "the interrupt could not be handled: {}",
                    Shown::io(&error)
                ))
            };
            self.handlers = Some((
                tokio::signal::windows::ctrl_c().map_err(failed)?,
                tokio::signal::windows::ctrl_break().map_err(failed)?,
            ));
        }
        Ok(())
    }

    /// Completes when the person interrupts, or never when nothing is installed to say so.
    pub async fn arrived(&mut self) {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = self.interrupt.recv() => {}
                _ = self.terminate.recv() => {}
                _ = self.hangup.recv() => {}
                _ = self.quit.recv() => {}
            }
        }
        #[cfg(windows)]
        {
            match self.handlers.as_mut() {
                Some((ctrl_c, ctrl_break)) => {
                    tokio::select! {
                        _ = ctrl_c.recv() => {}
                        _ = ctrl_break.recv() => {}
                    }
                }
                None => std::future::pending::<()>().await,
            }
        }
    }
}

/// The failure of a command that was interrupted.
#[must_use]
pub fn stopped() -> CliError {
    CliError::Other(Shown::said("stopped before it finished"))
}
