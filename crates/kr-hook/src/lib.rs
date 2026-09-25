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
///
/// The write waits for as long as standard error makes it wait. A process that must answer by a
/// deadline answers first and says what went wrong through [`report_by`]. The launcher says what it
/// has to say this way, before it runs the program, which on Unix takes the launcher's place so
/// that nothing of the launcher is left to say it afterwards. No deadline applies to the launcher:
/// the shell waits for the program as it waits for any command.
pub fn report(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr().lock(), "kr-hook: {line}");
}

/// Writes one diagnostic line to standard error, and waits for the write no later than `by`.
///
/// A standard error nobody reads fills up, and a write to a full one waits until somebody reads.
/// A terminal, a file or a pipe another process writes to can make a write wait too, even one
/// that had room a moment before. So the write is made on a thread of its own, and the caller goes
/// on at `by` whether the write has finished or not. A write still waiting when the process ends
/// ends with it, and its line is lost: with nothing left before `by`, the line is written only if
/// that thread gets to it before the process ends.
pub fn report_by(line: &str, by: std::time::Instant) {
    write_by(format!("kr-hook: {line}\n").into_bytes(), by, |bytes| {
        use std::io::Write as _;
        let _ = std::io::stderr().lock().write_all(bytes);
    });
}

/// Hands `bytes` to `write` on a thread of its own, and waits for it no later than `by`.
///
/// A thread that cannot be started writes nothing: a diagnostic never costs the caller its
/// answer.
fn write_by(bytes: Vec<u8>, by: std::time::Instant, write: impl FnOnce(&[u8]) + Send + 'static) {
    let (written, done) = std::sync::mpsc::channel();
    let started = std::thread::Builder::new().spawn(move || {
        write(&bytes);
        let _ = written.send(());
    });
    if started.is_ok() {
        let _ = done.recv_timeout(by.saturating_duration_since(std::time::Instant::now()));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::*;

    /// A write that never finishes, at any point in it, holds its caller no later than the bound.
    #[test]
    fn a_write_that_stalls_holds_its_caller_only_until_the_bound() {
        let (release, stalled) = std::sync::mpsc::channel::<()>();
        let begun = Instant::now();
        write_by(
            b"a line".to_vec(),
            begun + Duration::from_millis(100),
            move |_| {
                // Stalls until the test lets it go, which is after the caller has gone on, or for
                // half a minute, so a caller that waited for it fails rather than hangs.
                let _ = stalled.recv_timeout(Duration::from_secs(30));
            },
        );
        let took = begun.elapsed();
        drop(release);
        assert!(took >= Duration::from_millis(100), "{took:?}");
        assert!(took < Duration::from_secs(10), "{took:?}");
    }

    /// The control: a write that finishes is waited for, and gets the whole line.
    #[test]
    fn a_write_that_finishes_is_waited_for() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let into = Arc::clone(&written);
        write_by(
            b"kr-hook: a line\n".to_vec(),
            Instant::now() + Duration::from_secs(60),
            move |bytes| {
                into.lock().expect("the buffer").extend_from_slice(bytes);
            },
        );
        assert_eq!(
            written.lock().expect("the buffer").as_slice(),
            b"kr-hook: a line\n"
        );
    }

    /// With nothing left before the bound, the caller does not wait at all.
    #[test]
    fn a_bound_already_passed_is_not_waited_for() {
        let (release, stalled) = std::sync::mpsc::channel::<()>();
        let begun = Instant::now();
        write_by(b"a line".to_vec(), begun, move |_| {
            let _ = stalled.recv_timeout(Duration::from_secs(30));
        });
        let took = begun.elapsed();
        drop(release);
        assert!(took < Duration::from_secs(10), "{took:?}");
    }
}
