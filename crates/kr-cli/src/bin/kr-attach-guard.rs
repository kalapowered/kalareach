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
//! It is started with its own session, so it has no controlling terminal and changing the
//! inherited one cannot stop it with `SIGTTOU`. It never promises to survive the terminal
//! emulator itself: if that is gone there is nothing to restore.

use std::io::{Read as _, Write as _};
use std::process::ExitCode;

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

    let terminal = std::io::stdout();
    let Ok(mut modes) = rustix::termios::tcgetattr(&terminal) else {
        return ExitCode::FAILURE;
    };
    saved.apply(&mut modes);
    if rustix::termios::tcsetattr(&terminal, OptionalActions::Flush, &modes).is_err() {
        return ExitCode::FAILURE;
    }
    let mut handle = terminal.lock();
    let _ = handle.write_all(RESET_SEQUENCES);
    let _ = handle.flush();
    ExitCode::SUCCESS
}
