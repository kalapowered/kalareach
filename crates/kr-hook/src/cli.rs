//! What `kr-hook` accepts on its command line, and the exit codes it answers with.
//!
//! The command line is fixed by the registrations that start the forwarder and by the shell that
//! runs an integrated invocation. A registration names exactly one invocation: `kr-hook
//! claude-code channel` for Claude Code's Channels server, and `kr-hook <application> hook` for each
//! hook of an application, the application being the word its registration names (`claude-code`,
//! `gemini-cli` and `qoder-cli` are the words of the packages published today). The shell runs
//! `kr-hook launch -- <executable> <arguments...>` for an invocation the worker gave a backend.
//! Nothing else is accepted. A word that is not an application word, an unknown surface, an extra
//! argument or a flag this forwarder does not declare is refused with a usage error on standard
//! error, before anything is read or connected.
//!
//! The usage error's exit code is [`EXIT_USAGE`], 64, and not the 2 an argument parser uses by
//! default. Claude Code and Qoder CLI read a hook's exit code: 2 is the one code that blocks an
//! action on the events that can be blocked, and Claude Code hands the hook's standard error to
//! the model on some of the events its bridge registers. Both treat 64 as an ordinary failure.
//! Gemini CLI reads a hook's standard error as its output when standard output is empty, and turns
//! plain text with any exit code other than 0 and 1 into a refusal, so there a usage error is
//! read as a refusal of the event it ran for; the Gemini CLI registration names only events whose
//! refusals Gemini CLI ignores.

use clap::{CommandFactory as _, Parser, Subcommand};

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
    /// One hook of an application the registration names: `<application> hook`.
    #[command(external_subcommand)]
    Hook(Vec<String>),
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

/// What a usage error says of an invocation that is not `<application> hook`.
const NOT_AN_INVOCATION: &str = "an invocation is `kr-hook <application> hook`, where the application is a word of lower-case letters, digits and hyphens that does not begin with a hyphen";

/// Returns whether `word` is an application word: lower-case letters, digits and hyphens, and not
/// beginning with a hyphen, which no command line reads as an option.
#[must_use]
pub fn is_application_word(word: &str) -> bool {
    !word.is_empty()
        && !word.starts_with('-')
        && word
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// The application word of an invocation clap did not name, when it is exactly `<application> hook`
/// and the application is an application word; `None` for anything else.
#[must_use]
pub fn hooked_application(words: &[String]) -> Option<&str> {
    match words {
        [application, surface] if surface == "hook" && is_application_word(application) => {
            Some(application)
        }
        _ => None,
    }
}

fn not_an_invocation() -> clap::Error {
    Cli::command().error(clap::error::ErrorKind::InvalidSubcommand, NOT_AN_INVOCATION)
}

/// Parses a command line, the program's name first, and refuses an invocation this forwarder does
/// not accept: this is the one place that decides what a command line is, for the program and for
/// every case that holds what it accepts.
///
/// # Errors
///
/// Returns the usage error clap gives, or the one for an invocation that is not `<application>
/// hook`: a word that is not an application word, another surface, an extra argument or a `--`.
pub fn parse_from<I, T>(arguments: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let arguments: Vec<std::ffi::OsString> = arguments.into_iter().map(Into::into).collect();
    // `--` makes the next word an external command's, which no registration starts.
    if arguments.get(1).is_some_and(|word| word == "--") {
        return Err(not_an_invocation());
    }
    let cli = Cli::try_parse_from(&arguments)?;
    match &cli.command {
        Command::Hook(words) if hooked_application(words).is_none() => Err(not_an_invocation()),
        _ => Ok(cli),
    }
}

/// Parses this process's command line with [`parse_from`].
///
/// # Errors
///
/// Returns what [`parse_from`] returns.
pub fn parse() -> Result<Cli, clap::Error> {
    parse_from(std::env::args_os())
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    fn parse(arguments: &[&str]) -> Result<Command, clap::Error> {
        parse_from(std::iter::once("kr-hook").chain(arguments.iter().copied()))
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
            Command::Hook(vec!["gemini-cli".to_owned(), "hook".to_owned()])
        );
        assert_eq!(
            parse(&["qoder-cli", "hook"]).expect("Qoder CLI's hook registration"),
            Command::Hook(vec!["qoder-cli".to_owned(), "hook".to_owned()])
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
            &["a_b", "hook"][..],
            &["Amp", "hook"][..],
            &["amp", "channel"][..],
            &["amp", "hook", "extra"][..],
            &["-amp", "hook"][..],
            &["gemini-cli"][..],
            &["gemini-cli", "channel"][..],
            &["gemini-cli", "hook", "extra"][..],
            &["qoder-cli"][..],
            &["qoder-cli", "channel"][..],
            &["qoder-cli", "Hook"][..],
            &["qoder-cli", "hook", "--close-after-hello"][..],
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

    /// KR-REQ-11.44: a hook is accepted for any application word, whichever application it is.
    #[test]
    fn kr_req_11_44_a_hook_for_any_application_word_is_accepted() {
        for word in ["amp", "codex", "gemini", "qoder", "a1-b", "7zip"] {
            match parse_from(["kr-hook", word, "hook"]) {
                Ok(Cli {
                    command: Command::Hook(words),
                }) => assert_eq!(hooked_application(&words), Some(word), "{word}"),
                Ok(other) => panic!("{word} parsed as {other:?}"),
                Err(error) => panic!("{word} is refused: {error}"),
            }
        }
    }

    /// KR-REQ-11.44: a word that starts with a hyphen is never an application: a flag is refused as
    /// a usage error, help and the version are answers, and `-` and `--` reach no hook.
    #[test]
    fn kr_req_11_44_a_word_that_starts_with_a_hyphen_is_never_an_application() {
        for arguments in [
            &["-amp", "hook"][..],
            &["-x", "hook"][..],
            &["-"][..],
            &["-", "hook"][..],
            &["--", "hook"][..],
            &["--", "amp", "hook"][..],
        ] {
            match parse_from(std::iter::once("kr-hook").chain(arguments.iter().copied())) {
                Ok(cli) => panic!("{arguments:?} parsed as {cli:?}"),
                Err(error) => assert!(
                    error.use_stderr(),
                    "{arguments:?} is a usage error on standard error: {error}"
                ),
            }
        }
        for arguments in [&["--help", "hook"][..], &["--version", "hook"][..]] {
            match parse_from(std::iter::once("kr-hook").chain(arguments.iter().copied())) {
                Ok(cli) => panic!("{arguments:?} parsed as {cli:?}"),
                Err(error) => assert!(
                    !error.use_stderr(),
                    "{arguments:?} is an answer, never a hook: {error}"
                ),
            }
        }
    }
}
