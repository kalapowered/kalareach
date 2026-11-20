//! What ends a command that holds a secret or has written files before it is done.
//!
//! Once a handler for the interrupt is installed, Ctrl-C no longer ends the process by itself: the
//! command has to notice it, put the terminal back, remove what it wrote and say so. A termination
//! request, a hang-up (the terminal went away) and Ctrl-\ mean the same; the last would otherwise
//! end the process with a core dump that holds whatever it was holding. A command that waits on
//! this makes the wait cancellable, because a blocking read is not ended by a signal that
//! restarts it.
//!
//! Windows polls sockets only, so a command there reads its secret without a handler and installs
//! one afterwards ([`Interrupt::arm`]): before that, Ctrl-C ends the process, which has written and
//! changed nothing. A command that asks questions arms it before the first one, and the handler
//! takes Ctrl-Break as it takes Ctrl-C, and keeps taking both until the process ends. Closing the
//! window, signing out and shutting down end the process after a few seconds whatever a handler
//! says.

use kr_client::shown;
use kr_client::shown::Shown;

use crate::error::{CliError, Result};

/// The receivers that keep Ctrl-C and Ctrl-Break taken from the moment a command arms its interrupt
/// to the end of the process, though the command's own are dropped sooner. The handler that tokio
/// installs gives an event to the system's default handler, which ends the process, as soon as no
/// receiver is left to take it, and a command's receivers are dropped before `kr` has said that it
/// stopped.
#[cfg(windows)]
static KEPT: std::sync::Mutex<
    Option<(
        tokio::signal::windows::CtrlC,
        tokio::signal::windows::CtrlBreak,
    )>,
> = std::sync::Mutex::new(None);

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
    ctrl_c: Option<tokio::signal::windows::CtrlC>,
    #[cfg(windows)]
    ctrl_break: Option<tokio::signal::windows::CtrlBreak>,
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
            Ok(Self {
                ctrl_c: None,
                ctrl_break: None,
            })
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
        {
            let failed = |error: std::io::Error| {
                CliError::Other(shown!(
                    "the interrupt could not be handled: {}",
                    Shown::io(&error)
                ))
            };
            if self.ctrl_c.is_none() {
                self.ctrl_c = Some(tokio::signal::windows::ctrl_c().map_err(failed)?);
            }
            if self.ctrl_break.is_none() {
                self.ctrl_break = Some(tokio::signal::windows::ctrl_break().map_err(failed)?);
            }
            let mut kept = KEPT
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if kept.is_none() {
                *kept = Some((
                    tokio::signal::windows::ctrl_c().map_err(failed)?,
                    tokio::signal::windows::ctrl_break().map_err(failed)?,
                ));
            }
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
            match (self.ctrl_c.as_mut(), self.ctrl_break.as_mut()) {
                (Some(ctrl_c), Some(ctrl_break)) => {
                    tokio::select! {
                        _ = ctrl_c.recv() => {}
                        _ = ctrl_break.recv() => {}
                    }
                }
                _ => std::future::pending::<()>().await,
            }
        }
    }
}

/// The failure of a command that was interrupted.
#[must_use]
pub fn stopped() -> CliError {
    CliError::Other(Shown::said("stopped before it finished"))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// The process still holds a receiver for Ctrl-C and for Ctrl-Break after the interrupt that
    /// armed them is dropped, which is what keeps the system's default handler from ending the
    /// command in the moment between the command's last receiver and its report that it stopped.
    #[tokio::test]
    async fn ctrl_c_and_ctrl_break_stay_taken_after_the_command_that_armed_them_lets_go() {
        let mut interrupt = Interrupt::install().expect("the interrupt is installed");
        interrupt.arm().expect("the interrupt is armed");
        drop(interrupt);
        let kept = KEPT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            kept.is_some(),
            "a receiver for each of Ctrl-C and Ctrl-Break is held after the command's own are dropped"
        );
    }
}
