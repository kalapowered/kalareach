//! The setup program's entry point.

use std::process::ExitCode;

/// Runs the setup program.
pub fn main() -> ExitCode {
    eprintln!("kr-boundary-setup: no command is built yet");
    ExitCode::from(2)
}
