//! What `kr-hook` accepts on its command line, and the exit codes it answers with.
//!
//! The command line is fixed by the registrations that start the forwarder and by the shell that
//! runs an integrated invocation. Each registration names exactly one invocation: `kr-hook
//! claude-code channel` for Claude Code's Channels server, and `kr-hook claude-code hook`,
//! `kr-hook gemini-cli hook` and `kr-hook qoder-cli hook` for every hook of Claude Code, Gemini
//! CLI and Qoder CLI. The shell runs `kr-hook launch -- <executable> <arguments...>` for an
//! invocation the worker gave a backend. Nothing else is accepted. An unknown application, an
//! unknown surface, an extra argument or a flag this forwarder does not declare is refused with a
//! usage error on standard error, before anything is read or connected.
//!
//! The usage error's exit code is [`EXIT_USAGE`], 64, and not the 2 an argument parser uses by
//! default. Claude Code and Qoder CLI read a hook's exit code: 2 is the one code that blocks an
//! action on the events that can be blocked, and Claude Code hands the hook's standard error to
//! the model on some of the events its bridge registers. Both treat 64 as an ordinary failure.
//! Gemini CLI reads a hook's standard error as its output when standard output is empty, and turns
//! plain text with any exit code other than 0 and 1 into a refusal, so there a usage error is
//! read as a refusal of the event it ran for; the Gemini CLI registration names only events whose
//! refusals Gemini CLI ignores.

use clap::{Parser, Subcommand};

/// The exit code of a command line this forwarder does not accept.
///
/// `EX_USAGE` from the BSD `sysexits` convention. It is deliberately not 2, which Claude Code and
/// Qoder CLI read as a hook's request to block the action it observed.
pub const EXIT_USAGE: u8 = 64;

/// The exit code of a forwarder that was invoked correctly and could not do its work.
pub const EXIT_FAILURE: u8 = 1;

/// The forwarder an application's native bridge starts to reach the KalaReach worker that owns its
/// session.
#[derive(Debug, Parser)]
#[command(
    name = "kr-hook",
    version,
    about = "Carries an application's native bridge traffic to the KalaReach worker that owns its \
             session",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// What this invocation is.
    #[command(subcommand)]
    pub command: Command,
}

/// The invocations this forwarder accepts.
#[derive(Clone, Debug, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Claude Code's native bridge: its Channels server and its lifecycle and tool hooks.
    #[command(name = "claude-code")]
    ClaudeCode {
        /// Which of the bridge's two registrations started this process.
        #[command(subcommand)]
        surface: ClaudeCode,
    },
    /// Gemini CLI's native bridge: its session and notification hooks.
    #[command(name = "gemini-cli")]
    GeminiCli {
        /// The registration that started this process.
        #[command(subcommand)]
        surface: Hooks,
    },
    /// Qoder CLI's native bridge: its session, tool and notification hooks.
    #[command(name = "qoder-cli")]
    QoderCli {
        /// The registration that started this process.
        #[command(subcommand)]
        surface: Hooks,
    },
    /// Runs an integrated invocation's program, after presenting it to the backend the worker gave
    /// it: the executable, then its argument vector, command name first, after `--`.
    Launch {
        /// Holds after the admission for this many milliseconds before the program runs.
        ///
        /// It exists for the host's own tests, which change the executable in that interval, and
        /// it is named by nothing a shell runs.
        #[arg(long, hide = true, value_name = "MILLISECONDS")]
        hold_after_admission: Option<u64>,
        /// Waits, before the program is executed on any route, until this file exists.
        ///
        /// It exists for the host's own tests, which change the executable while a launch waits
        /// to be told it is committed, and must not have the program executed before the change
        /// is complete; it is named by nothing a shell runs.
        #[arg(long, hide = true, value_name = "PATH")]
        hold_before_exec: Option<std::path::PathBuf>,
        /// The executable and its argument vector.
        #[arg(last = true, required = true, num_args = 2.., value_name = "INVOCATION")]
        invocation: Vec<std::ffi::OsString>,
    },
    /// Carries bytes between this process's standard streams and the endpoint of the launch that
    /// started it, after saying who it is.
    Relay {
        /// Says who this is, closes the connection and stays alive.
        ///
        /// It exists for the host's own endpoint tests, which need a process that was admitted and
        /// then went quiet, and it is not part of any registration.
        #[arg(long, hide = true)]
        close_after_hello: bool,
    },
}

/// The two registrations Claude Code's bridge installs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Subcommand)]
pub enum ClaudeCode {
    /// The Channels server Claude Code starts over this process's standard input and output.
    Channel,
    /// One lifecycle or tool hook: reads the event on standard input and answers `{}`.
    Hook,
}

/// The one registration of a bridge that has hooks and nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Subcommand)]
pub enum Hooks {
    /// One hook: reads the event on standard input and answers `{}`.
    Hook,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    fn parse(arguments: &[&str]) -> Result<Command, clap::Error> {
        Cli::try_parse_from(std::iter::once("kr-hook").chain(arguments.iter().copied()))
            .map(|cli| cli.command)
    }

    #[test]
    fn the_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn each_registered_invocation_parses_to_its_surface() {
        assert_eq!(
            parse(&["claude-code", "channel"]).expect("the channel registration"),
            Command::ClaudeCode {
                surface: ClaudeCode::Channel
            }
        );
        assert_eq!(
            parse(&["claude-code", "hook"]).expect("the hook registration"),
            Command::ClaudeCode {
                surface: ClaudeCode::Hook
            }
        );
        assert_eq!(
            parse(&["gemini-cli", "hook"]).expect("Gemini CLI's hook registration"),
            Command::GeminiCli {
                surface: Hooks::Hook
            }
        );
        assert_eq!(
            parse(&["qoder-cli", "hook"]).expect("Qoder CLI's hook registration"),
            Command::QoderCli {
                surface: Hooks::Hook
            }
        );
        assert_eq!(
            parse(&["relay"]).expect("the relay"),
            Command::Relay {
                close_after_hello: false
            }
        );
        assert_eq!(
            parse(&[
                "launch",
                "--",
                "/usr/local/bin/claude",
                "claude",
                "--resume"
            ])
            .expect("the launcher"),
            Command::Launch {
                hold_after_admission: None,
                hold_before_exec: None,
                invocation: ["/usr/local/bin/claude", "claude", "--resume"]
                    .into_iter()
                    .map(std::ffi::OsString::from)
                    .collect(),
            }
        );
        assert_eq!(
            parse(&[
                "launch",
                "--",
                "/usr/local/bin/claude",
                "claude",
                "--",
                "--help"
            ])
            .expect("a separator in the invocation is the invocation's"),
            Command::Launch {
                hold_after_admission: None,
                hold_before_exec: None,
                invocation: ["/usr/local/bin/claude", "claude", "--", "--help"]
                    .into_iter()
                    .map(std::ffi::OsString::from)
                    .collect(),
            }
        );
    }

    #[test]
    fn anything_else_is_a_usage_error() {
        for arguments in [
            &[][..],
            &["claude-code"][..],
            &["claude"][..],
            &["Claude-Code", "hook"][..],
            &["claude-code", "hooks"][..],
            &["claude-code", "Hook"][..],
            &["claude-code", "hook", "extra"][..],
            &["claude-code", "channel", "--session", "abc"][..],
            &["claude-code", "--close-after-hello", "hook"][..],
            &["codex", "hook"][..],
            &["gemini-cli"][..],
            &["gemini-cli", "channel"][..],
            &["gemini-cli", "hook", "extra"][..],
            &["gemini", "hook"][..],
            &["qoder-cli"][..],
            &["qoder-cli", "channel"][..],
            &["qoder-cli", "Hook"][..],
            &["qoder-cli", "hook", "--close-after-hello"][..],
            &["qoder", "hook"][..],
            &["relay", "extra"][..],
            &["--session=abc", "claude-code", "hook"][..],
            &["launch"][..],
            &["launch", "/usr/bin/true"][..],
            &["launch", "--", "/usr/bin/true"][..],
            &["launch", "--hold", "--", "/usr/bin/true", "true"][..],
        ] {
            let refused = parse(arguments).expect_err("refused");
            assert!(
                refused.use_stderr(),
                "{arguments:?} is refused on standard error, not answered as help"
            );
        }
    }
}
