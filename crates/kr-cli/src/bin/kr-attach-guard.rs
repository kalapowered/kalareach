//! The out-of-process terminal restoration guard.
//!
//! This process exists to outlive `kr attach` by a few milliseconds. It holds two things: a handle
//! on the user's terminal, and the modes that terminal had before the attach began. Then it waits
//! on a pipe whose other end only the attach process holds.
//!
//! * End of file means the attach process is gone, however it went. The terminal is restored.
//! * A release byte means the attach process restored the terminal itself and this one should
//!   leave without touching anything.
//!
//! It runs in its own process group, so a signal aimed at the attach process's group does not
//! reach it. By the time it acts that group is in the background, and a background process that
//! changes the terminal is normally stopped with `SIGTTOU`; the guard catches that signal instead,
//! so the change goes through. It never promises to survive the terminal emulator itself: if that
//! is gone there is nothing to restore.

use std::io::{Read as _, Write as _};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use clap::Parser;
use kr_cli::attach::GUARD_RELEASE;
use kr_cli::terminal::{RESET_SEQUENCES, SavedModes};
use rustix::termios::OptionalActions;

#[derive(Debug, Parser)]
#[command(
    name = "kr-attach-guard",
    version,
    about = "Restores a terminal when the attach process that owned it is gone."
)]
struct Arguments {
    /// The terminal modes to restore, as four hexadecimal words.
    #[arg(long)]
    modes: String,
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    let Ok(saved) = SavedModes::decode(&arguments.modes) else {
        return ExitCode::FAILURE;
    };

    // Standard input is the pipe; standard output is the terminal.
    let mut signal = [0_u8; 1];
    let released =
        matches!(std::io::stdin().read(&mut signal), Ok(1) if signal[0] == GUARD_RELEASE);
    if released {
        // The attach process restored the terminal itself.
        return ExitCode::SUCCESS;
    }

    // A background process that changes the terminal is stopped by `SIGTTOU` unless it handles the
    // signal. Registering a handler is what lets the restoration actually happen.
    let interrupted = Arc::new(AtomicBool::new(false));
    if signal_hook::flag::register(signal_hook::consts::SIGTTOU, Arc::clone(&interrupted)).is_err()
    {
        return ExitCode::FAILURE;
    }

    let terminal = std::io::stdout();
    let Ok(mut modes) = rustix::termios::tcgetattr(&terminal) else {
        return ExitCode::FAILURE;
    };
    saved.apply(&mut modes);
    if !set_modes(&terminal, &modes) {
        return ExitCode::FAILURE;
    }
    let mut handle = terminal.lock();
    let _ = handle.write_all(RESET_SEQUENCES);
    let _ = handle.flush();
    ExitCode::SUCCESS
}

/// Applies the modes, retrying the interruption a caught signal causes.
fn set_modes(terminal: &std::io::Stdout, modes: &rustix::termios::Termios) -> bool {
    for _ in 0..8 {
        match rustix::termios::tcsetattr(terminal, OptionalActions::Flush, modes) {
            Ok(()) => return true,
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return false,
        }
    }
    false
}
