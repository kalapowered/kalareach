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
    use std::os::windows::process::CommandExt as _;
    use std::process::Stdio;
    use std::time::Duration;

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

    /// The variable that makes the helper below run: `armed` arms an interrupt and drops it,
    /// `plain` does neither.
    const CHILD: &str = "KR_TEST_INTERRUPT_CHILD";
    /// How the system's default handler ends a process that has no handler of its own for the event.
    const STATUS_CONTROL_C_EXIT: i32 = i32::from_ne_bytes(0xC000_013A_u32.to_ne_bytes());
    /// The code the helper ends with when the system would not send the event.
    const NOT_SENT: i32 = 42;

    /// A Ctrl-Break that comes after the command let go of its interrupt does not end the process:
    /// the helper arms an interrupt, drops it, and sends Ctrl-Break to its own console. It runs as
    /// a program of its own with a console of its own, since the event ends the process that has
    /// no handler for it. The case needs only the exit code: 0 when the event was taken.
    #[test]
    fn a_ctrl_break_after_the_command_let_go_of_its_interrupt_does_not_end_the_process() {
        assert_the_event_ends_a_process_that_has_no_handler(run_the_helper("plain"));
        assert_eq!(
            run_the_helper("armed"),
            Some(0),
            "a Ctrl-Break after the interrupt was dropped ended the process by the default handler"
        );
    }

    /// The case's condition, asserted in a helper so that a run that cannot make it reads as a
    /// set-up fault and never as the kill of the mutation the case is named for: the event reaches
    /// a program that has no handler, and ends it as the default handler does.
    fn assert_the_event_ends_a_process_that_has_no_handler(code: Option<i32>) {
        assert_eq!(
            code,
            Some(STATUS_CONTROL_C_EXIT),
            "this case could not make its condition: a program with no handler for Ctrl-Break was \
             not ended by it, so the event does not reach a program on a console of its own here"
        );
    }

    /// Runs the helper below in `mode` as a program with its own console, and gives its exit code.
    /// A helper that could not send the event fails here, in words.
    fn run_the_helper(mode: &str) -> Option<i32> {
        let me = std::env::current_exe().expect("this test program has a path");
        let status = std::process::Command::new(me)
            .args([
                "--exact",
                "backup::interrupt::tests::the_program_that_is_sent_ctrl_break_after_it_lets_go",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, mode)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(windows_sys::Win32::System::Threading::CREATE_NEW_CONSOLE)
            .status()
            .expect("starts the helper");
        assert_ne!(
            status.code(),
            Some(NOT_SENT),
            "this case could not make its condition: the system would not send Ctrl-Break to the \
             helper's console"
        );
        status.code()
    }

    /// The helper of the case above. It does nothing in an ordinary run.
    #[test]
    fn the_program_that_is_sent_ctrl_break_after_it_lets_go() {
        let Some(mode) = std::env::var_os(CHILD) else {
            return;
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let _entered = runtime.enter();
        if mode == "armed" {
            let mut interrupt = Interrupt::install().expect("the interrupt is installed");
            interrupt.arm().expect("the interrupt is armed");
            drop(interrupt);
        }
        if !send_ctrl_break_to_this_console() {
            std::process::exit(NOT_SENT);
        }
        // A process that has no handler is ended within this time, and one that took the event
        // goes on and ends with the code of an ordinary run.
        std::thread::sleep(Duration::from_secs(1));
    }

    /// Sends Ctrl-Break to every program on this process's console, which is its own.
    #[expect(
        unsafe_code,
        reason = "a console event has no safe interface in the standard library"
    )]
    fn send_ctrl_break_to_this_console() -> bool {
        use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent};

        // SAFETY: the call takes the event and a process group, zero meaning every process on this
        // console, and touches no memory of this program.
        unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0) != 0 }
    }
}
