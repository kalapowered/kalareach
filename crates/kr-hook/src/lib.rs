//! `kr-hook`: the core forwarder a native bridge runs.
//!
//! Section 11 prefers "a small registration file plus the core `kr-hook` forwarder" for an
//! application that needs a bridge beside its unchanged terminal. A plugin package installs the
//! registration into the application's own documented plugin or hook location; the application then
//! starts this forwarder itself, under its own permissions and outside Wasmtime, and the forwarder
//! carries what the application says to the KalaReach worker that owns the session.
//!
//! The forwarder decides nothing about authority. It finds the registration the worker published
//! for the launch, presents the launch's private exchange and its own process identity, and
//! declares which bridge it is. The worker checks every part of that against the process it
//! launched and the installation it recorded, and refuses the connection otherwise.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`cli`] | The accepted invocations and the exit codes |
//! | [`registration`] | Finding and reading the launch's registration, and the hello |
//! | [`exchange`] | The private exchange with the worker: admission and bounded JSON lines |
//! | [`claude_code`] | Claude Code's bridge: its Channels server and its hooks |
//! | [`relay`] | The byte relay a launched agent reaches its worker through |

pub mod claude_code;
pub mod cli;
pub mod exchange;
pub mod registration;
pub mod relay;

/// Runs one parsed invocation and returns the exit code it ends with.
#[must_use]
pub fn run(command: cli::Command) -> std::process::ExitCode {
    match command {
        cli::Command::ClaudeCode {
            surface: cli::ClaudeCode::Hook,
        } => claude_code::hook::run(),
        cli::Command::ClaudeCode {
            surface: cli::ClaudeCode::Channel,
        } => claude_code::channel::run(),
        cli::Command::Relay { close_after_hello } => match relay::run(close_after_hello) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(failure) => {
                report(&failure);
                std::process::ExitCode::from(cli::EXIT_FAILURE)
            }
        },
    }
}

/// Writes one diagnostic line to standard error.
///
/// Standard error is where a person debugging reads what happened. For a hook that exits 0,
/// Claude Code writes it to its debug log and shows it to nobody, so it cannot reach the model or
/// change what the application does.
pub fn report(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr().lock(), "kr-hook: {line}");
}
