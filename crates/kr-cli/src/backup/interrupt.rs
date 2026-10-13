//! What ends a command that holds a secret or has written files before it is done.
//!
//! Once a handler for the interrupt is installed, Ctrl-C no longer ends the process by itself: the
//! command has to notice it, put the terminal back, remove what it wrote and say so. A termination
//! request means the same. A command that waits on this makes the wait cancellable, because a
//! blocking read is not ended by a signal that restarts it.
//!
//! Windows polls sockets only, so a command there reads its secret without a handler and installs
//! one afterwards ([`Interrupt::arm`]): before that, Ctrl-C ends the process, which has written and
//! changed nothing.

use kr_client::shown;
use kr_client::shown::Shown;

use crate::error::{CliError, Result};

/// The signals that mean stop, and clean up first.
pub struct Interrupt {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(windows)]
    ctrl_c: Option<tokio::signal::windows::CtrlC>,
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
            })
        }
        #[cfg(windows)]
        {
            Ok(Self { ctrl_c: None })
        }
    }

    /// Installs what [`Self::install`] could not, once nothing is being read that a handler cannot
    /// end.
    ///
    /// # Errors
    ///
    /// Returns a failure when the handler cannot be installed.
    pub fn arm(&mut self) -> Result<()> {
        #[cfg(windows)]
        if self.ctrl_c.is_none() {
            self.ctrl_c = Some(tokio::signal::windows::ctrl_c().map_err(|error| {
                CliError::Other(shown!(
                    "the interrupt could not be handled: {}",
                    Shown::io(&error)
                ))
            })?);
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
            }
        }
        #[cfg(windows)]
        {
            match self.ctrl_c.as_mut() {
                Some(ctrl_c) => {
                    ctrl_c.recv().await;
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
