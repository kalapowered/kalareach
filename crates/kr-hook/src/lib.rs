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

/// The most one diagnostic line [`report_within`] writes takes, in bytes, with its newline: the
/// most a pipe with room for it takes in one write on every system this forwarder runs on.
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;

/// Writes one diagnostic line to standard error.
///
/// Standard error is where a person debugging reads what happened. For a hook that exits 0,
/// Claude Code and Qoder CLI write it to their logs and show it to nobody, and Gemini CLI reads it
/// only when standard output is empty, which a hook's never is, so it cannot reach the model or
/// change what the application does.
///
/// The write waits for as long as standard error makes it wait. A process that must answer by a
/// deadline answers first and says what went wrong through [`report_within`]. The launcher says
/// what it has to say this way, before it runs the program: once the program runs, nothing of the
/// launcher is left to say it, and its standard error is the terminal the program writes to next,
/// which holds the program's own first line wherever it would hold this one.
pub fn report(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr().lock(), "kr-hook: {line}");
}

/// Writes one diagnostic line to standard error if standard error takes it within `within`.
///
/// A standard error nobody reads fills up, and a write to a full one waits until somebody reads.
/// So the line goes only once standard error has room for all of it, which is waited for no longer
/// than `within`, and is dropped otherwise: whatever standard error is, the caller goes on in time.
/// With nothing left of `within`, the line still goes if standard error has room at once. It is
/// one write of at most [`MAX_DIAGNOSTIC_BYTES`], cut to fit.
pub fn report_within(line: &str, within: std::time::Duration) {
    write_within(diagnostic(line).as_bytes(), within);
}

/// `line` as the one line a diagnostic is written as, cut at a character boundary to fit
/// [`MAX_DIAGNOSTIC_BYTES`] with its newline.
fn diagnostic(line: &str) -> String {
    let mut said = format!("kr-hook: {line}");
    let mut end = said.len().min(MAX_DIAGNOSTIC_BYTES - 1);
    while !said.is_char_boundary(end) {
        end -= 1;
    }
    said.truncate(end);
    said.push('\n');
    said
}

/// Writes `bytes` to standard error once it has room for them, waiting no longer than `within`.
#[cfg(unix)]
fn write_within(bytes: &[u8], within: std::time::Duration) {
    use std::io::Write as _;
    let stderr = std::io::stderr();
    let deadline = std::time::Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let timeout = rustix::event::Timespec {
            tv_sec: i64::try_from(left.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(left.subsec_nanos()),
        };
        let mut waiting = [rustix::event::PollFd::new(
            &stderr,
            rustix::event::PollFlags::OUT,
        )];
        match rustix::event::poll(&mut waiting, Some(&timeout)) {
            // Room for a write of this size, so the write does not wait. Closed or failed is said
            // by the same flags, and then nothing is written.
            Ok(1..) => {
                if waiting[0].revents().contains(rustix::event::PollFlags::OUT) {
                    let _ = stderr.lock().write_all(bytes);
                }
                return;
            }
            Err(rustix::io::Errno::INTR) => {}
            Ok(0) | Err(_) => return,
        }
    }
}

/// Writes `bytes` to standard error on a thread of its own, waiting for it no longer than
/// `within`, where standard error cannot be asked whether it has room.
#[cfg(not(unix))]
fn write_within(bytes: &[u8], within: std::time::Duration) {
    use std::io::Write as _;
    let bytes = bytes.to_vec();
    let (written, done) = std::sync::mpsc::channel();
    // A write that is still waiting when the process ends goes with it.
    std::thread::spawn(move || {
        let _ = std::io::stderr().lock().write_all(&bytes);
        let _ = written.send(());
    });
    let _ = done.recv_timeout(within);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_diagnostic_is_one_line_that_fits_one_write() {
        assert_eq!(
            diagnostic("the worker did not answer"),
            "kr-hook: the worker did not answer\n"
        );
        // A long line is cut at a character boundary, with its newline inside the bound.
        let long = "\u{e9}".repeat(MAX_DIAGNOSTIC_BYTES);
        let said = diagnostic(&long);
        assert!(said.len() <= MAX_DIAGNOSTIC_BYTES, "{}", said.len());
        assert!(said.len() >= MAX_DIAGNOSTIC_BYTES - 2, "{}", said.len());
        assert!(said.ends_with('\n'));
        assert_eq!(said.lines().count(), 1);
    }
}
