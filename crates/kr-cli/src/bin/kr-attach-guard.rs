//! The out-of-process terminal restoration guard.
//!
//! This process exists to outlive `kr attach` by a few milliseconds. It holds two things: a handle
//! on the user's terminal, and the complete state that terminal had before the attach began. Then
//! it waits on a pipe whose other end only the attach process holds.
//!
//! * End of file means the attach process is gone, however it went. The terminal is restored.
//! * A release byte means the attach process restored the terminal itself and this one should
//!   leave without touching anything.
//!
//! It confirms that it is holding the state before the attach process changes anything, so there is
//! no window in which the terminal is raw and nothing is holding its previous state.
//!
//! It runs in its own process group, so a signal aimed at the attach process's group does not reach
//! it. By the time it acts that group is in the background, and a background process that changes
//! the terminal is stopped by `SIGTTOU`. Catching that signal is not enough: the call still fails.
//! The guard **ignores** it instead, which is what lets the change through.
//!
//! It never promises to survive the terminal emulator itself: if that is gone there is nothing to
//! restore.

use std::io::{Read as _, Write as _};
use std::process::ExitCode;

use clap::Parser;
use kr_cli::attach::{GUARD_READY, GUARD_RELEASE};
#[cfg(unix)]
use kr_cli::terminal::RESET_SEQUENCES;
use kr_cli::terminal::SavedModes;

#[derive(Debug, Parser)]
#[command(
    name = "kr-attach-guard",
    version,
    about = "Restores a terminal when the attach process that owned it is gone."
)]
struct Arguments {
    /// The terminal state to restore.
    #[arg(long)]
    modes: String,
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    let Ok(saved) = SavedModes::decode(&arguments.modes) else {
        return ExitCode::FAILURE;
    };

    // Ignored, not caught. A background process that changes the terminal is stopped by `SIGTTOU`
    // unless the signal is ignored; a handler that merely records the signal leaves the call
    // failing. This is set before anything is written back, and before readiness is reported, so
    // there is no moment at which the guard is holding state it could not restore.
    if kr_cli::platform::ignore_background_write_signal().is_err() {
        return ExitCode::FAILURE;
    }

    // Standard error is the readiness pipe, standard input is the release pipe, and standard
    // output is the terminal. Reporting readiness here rather than at startup means the attach
    // process learns that the guard is armed, not merely that it was spawned.
    let mut ready = std::io::stderr();
    if ready.write_all(&[GUARD_READY]).is_err() || ready.flush().is_err() {
        return ExitCode::FAILURE;
    }

    let mut signal = [0_u8; 1];
    let released =
        matches!(std::io::stdin().read(&mut signal), Ok(1) if signal[0] == GUARD_RELEASE);
    if released {
        // The attach process restored the terminal itself.
        return ExitCode::SUCCESS;
    }

    if restore(&saved) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(unix)]
fn restore(saved: &SavedModes) -> bool {
    use rustix::termios::OptionalActions;

    let terminal = std::io::stdout();
    let Ok(mut modes) = rustix::termios::tcgetattr(&terminal) else {
        return false;
    };
    saved.apply(&mut modes);
    for _ in 0..8 {
        match rustix::termios::tcsetattr(&terminal, OptionalActions::Flush, &modes) {
            Ok(()) => {
                let mut handle = terminal.lock();
                let _ = handle.write_all(RESET_SEQUENCES);
                let _ = handle.flush();
                return true;
            }
            // An interrupted call is retried. Anything else is a terminal this guard cannot reach:
            // the emulator has gone, and there is nothing left to restore.
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return false,
        }
    }
    false
}

#[cfg(not(unix))]
fn restore(saved: &SavedModes) -> bool {
    let Ok(terminal) = kr_cli::terminal::ControllingTerminal::open() else {
        return false;
    };
    terminal.restore(saved).is_ok()
}
