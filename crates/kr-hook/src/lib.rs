//! `kr-hook`: the core forwarder a native bridge runs.
//!
//! Section 11 prefers "a small registration file plus the core `kr-hook` forwarder" for an
//! application that needs a bridge beside its unchanged terminal. A plugin package installs the
//! registration into the application's own documented plugin or hook location, or, for an
//! application that reads hooks from the settings its launch is given, the launch passes the
//! registration and nothing is installed. Either way the application then starts this forwarder
//! itself, under its own permissions and outside Wasmtime, and the forwarder carries what the
//! application says to the KalaReach worker that owns the session.
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
//! | [`hook`] | One observing hook, whichever application started it: prompt, neutral, and never a decision |
//! | [`claude_code`] | Claude Code's bridge: its Channels server and what its hooks report |
//! | [`gemini_cli`] | Gemini CLI's bridge: what its hooks report |
//! | [`qoder_cli`] | Qoder CLI's bridge: what its hooks report |
//! | [`launch`] | The launcher an integrated invocation presents itself to its backend through |
//! | [`relay`] | The byte relay a launched agent reaches its worker through |

pub mod claude_code;
pub mod cli;
pub mod exchange;
pub mod gemini_cli;
pub mod hook;
pub mod launch;
pub mod qoder_cli;
pub mod registration;
pub mod relay;

/// Runs one parsed invocation and returns the exit code it ends with.
#[must_use]
pub fn run(command: cli::Command) -> std::process::ExitCode {
    match command {
        cli::Command::ClaudeCode {
            surface: cli::ClaudeCode::Hook,
        } => hook::run(&claude_code::HOOKS),
        cli::Command::ClaudeCode {
            surface: cli::ClaudeCode::Channel,
        } => claude_code::channel::run(),
        cli::Command::GeminiCli {
            surface: cli::Hooks::Hook,
        } => hook::run(&gemini_cli::HOOKS),
        cli::Command::QoderCli {
            surface: cli::Hooks::Hook,
        } => hook::run(&qoder_cli::HOOKS),
        cli::Command::Launch {
            hold_after_admission,
            hold_before_exec,
            invocation,
        } => launch::run(
            &invocation,
            hold_after_admission.map(std::time::Duration::from_millis),
            hold_before_exec.as_deref(),
        ),
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
/// Claude Code and Qoder CLI write it to their logs and show it to nobody, and Gemini CLI reads it
/// only when standard output is empty, which a hook's never is, so it cannot reach the model or
/// change what the application does.
pub fn report(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr().lock(), "kr-hook: {line}");
}
