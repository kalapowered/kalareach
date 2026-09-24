//! What `kr-hook` accepts on its command line, and the exit codes it answers with.
//!
//! The command line is fixed by the files that register the forwarder. A plugin package installs
//! them into an application's own configuration, and they name exactly one invocation each:
//! `kr-hook claude-code channel` for the Channels server and `kr-hook claude-code hook` for every
//! lifecycle and tool hook. Nothing else is accepted. An unknown application, an unknown surface, an
//! extra argument or a flag this forwarder does not declare is refused with a usage error on
//! standard error, before anything is read or connected.
//!
//! The usage error's exit code is [`EXIT_USAGE`], 64, and not the 2 an argument parser uses by
//! default. Claude Code reads a hook's exit code: 2 is the one code that blocks an action on the
//! events that can be blocked, and on the events this bridge registers it hands the hook's standard
//! error to the model. A forwarder invoked wrongly must not be able to do either, so its usage error
//! is a code every application treats as an ordinary failure.

use clap::{Parser, Subcommand};

/// The exit code of a command line this forwarder does not accept.
///
/// `EX_USAGE` from the BSD `sysexits` convention. It is deliberately not 2, which Claude Code reads
/// as a hook's request to block the action it observed.
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Claude Code's native bridge: its Channels server and its lifecycle and tool hooks.
    #[command(name = "claude-code")]
    ClaudeCode {
        /// Which of the bridge's two registrations started this process.
        #[command(subcommand)]
        surface: ClaudeCode,
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
            parse(&["relay"]).expect("the relay"),
            Command::Relay {
                close_after_hello: false
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
            &["relay", "extra"][..],
            &["--session=abc", "claude-code", "hook"][..],
        ] {
            let refused = parse(arguments).expect_err("refused");
            assert!(
                refused.use_stderr(),
                "{arguments:?} is refused on standard error, not answered as help"
            );
        }
    }
}
