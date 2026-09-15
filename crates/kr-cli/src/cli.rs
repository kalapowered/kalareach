//! The command surface.
//!
//! Section 7 fixes the commands, their one-letter forms and the standard options. Two rules shape
//! the definitions here: a literal `--` ends KalaReach option parsing, and no shell command or path
//! is ever assembled by interpolating text.

use clap::{Args, Parser, Subcommand};

/// The KalaReach command line.
#[derive(Debug, Parser)]
#[command(
    name = "kr",
    version,
    about = "KalaReach: persistent terminal sessions",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Print machine-readable output instead of text for people.
    #[arg(long, global = true)]
    pub json: bool,

    /// The command.
    #[command(subcommand)]
    pub command: Command,
}

/// One KalaReach command.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a session.
    #[command(visible_alias = "n")]
    New(NewArguments),
    /// Attach to an existing session. Never resumes or creates a replacement.
    #[command(visible_alias = "a")]
    Attach(AttachArguments),
    /// Detach this attachment.
    #[command(visible_alias = "d")]
    Detach(DetachArguments),
    /// Close a session and terminate the processes it owns.
    #[command(visible_alias = "c")]
    Close(CloseArguments),
    /// List sessions.
    #[command(visible_alias = "l")]
    List(ListArguments),
    /// Show a session's connection, process and adapter state.
    #[command(visible_alias = "s")]
    Status(StatusArguments),
    /// Run read-only diagnostics.
    Doctor(DoctorArguments),
}

/// How a new session is presented.
#[derive(Debug, Args)]
#[group(multiple = false)]
pub struct Presentation {
    /// Create and attach in this terminal. The default when input and output are terminals.
    #[arg(long)]
    pub attach: bool,
    /// Create a session and open an installed terminal application on it.
    #[arg(long)]
    pub terminal: bool,
    /// Create a session with no local terminal attachment.
    #[arg(long)]
    pub invisible: bool,
}

/// `kr new`.
#[derive(Debug, Args)]
pub struct NewArguments {
    /// How the session is presented. These are mutually exclusive.
    #[command(flatten)]
    pub presentation: Presentation,
    /// The environment to create in.
    #[arg(long)]
    pub environment: Option<String>,
    /// The working directory the root shell starts in.
    #[arg(long)]
    pub cwd: Option<String>,
    /// The shell to launch. The environment's configured default is used when this is absent.
    #[arg(long)]
    pub shell: Option<String>,
    /// The shell integration mode. This build implements `native_compat`.
    #[arg(long, default_value = "native_compat")]
    pub shell_mode: String,
}

/// `kr attach`.
#[derive(Debug, Args)]
pub struct AttachArguments {
    /// The session, by display number or identifier.
    pub session: String,
    /// Do not probe the outer terminal's capabilities.
    #[arg(long)]
    pub no_probe: bool,
    /// Take size ownership for this terminal. Ordinary attach never moves it.
    #[arg(long)]
    pub take_geometry: bool,
    /// The environment, when a display number is ambiguous.
    #[arg(long)]
    pub environment: Option<String>,
}

/// `kr detach`.
#[derive(Debug, Args)]
pub struct DetachArguments {
    /// The attachment to remove. Required outside the attachment's own context.
    #[arg(long)]
    pub attachment: Option<String>,
    /// The session, by display number or identifier.
    pub session: Option<String>,
}

/// `kr close`.
#[derive(Debug, Args)]
pub struct CloseArguments {
    /// The session, by display number or identifier. Defaults to the current session.
    pub session: Option<String>,
    /// The environment, when a display number is ambiguous.
    #[arg(long)]
    pub environment: Option<String>,
}

/// `kr list`.
#[derive(Debug, Args)]
pub struct ListArguments {
    /// Include sessions that have already closed.
    #[arg(long)]
    pub include_closed: bool,
    /// Restrict the listing to one environment.
    #[arg(long)]
    pub environment: Option<String>,
}

/// `kr status`.
#[derive(Debug, Args)]
pub struct StatusArguments {
    /// The session, by display number or identifier. Defaults to the current session.
    pub session: Option<String>,
    /// The environment, when a display number is ambiguous.
    #[arg(long)]
    pub environment: Option<String>,
}

/// `kr doctor`.
#[derive(Debug, Args)]
pub struct DoctorArguments {
    /// Reserved for a future individual repair. Diagnostics are read-only by default.
    #[arg(long)]
    pub verbose: bool,
}

impl Presentation {
    /// Resolves the presentation, defaulting to attaching when this is a terminal.
    ///
    /// The three flags are mutually exclusive, and a command whose input and output are not
    /// terminals has to say which presentation it wants rather than being given one.
    ///
    /// # Errors
    ///
    /// Returns a usage failure when no presentation was given and none can be inferred.
    pub fn resolve(
        &self,
        stdio_is_terminal: bool,
    ) -> crate::error::Result<kr_protocol::session::Presentation> {
        if self.terminal {
            return Ok(kr_protocol::session::Presentation::Terminal);
        }
        if self.invisible {
            return Ok(kr_protocol::session::Presentation::Invisible);
        }
        if self.attach {
            return Ok(kr_protocol::session::Presentation::Attach);
        }
        if stdio_is_terminal {
            Ok(kr_protocol::session::Presentation::Attach)
        } else {
            Err(crate::error::CliError::Usage(
                "choose --attach, --terminal or --invisible: standard input and output are not terminals".to_owned(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    #[test]
    fn the_definitions_are_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn every_command_has_its_documented_short_form() {
        for (long, short) in [
            ("new", "n"),
            ("attach", "a"),
            ("detach", "d"),
            ("close", "c"),
            ("list", "l"),
            ("status", "s"),
        ] {
            let parsed = Cli::try_parse_from(["kr", short, "1"])
                .or_else(|_| Cli::try_parse_from(["kr", short]))
                .unwrap_or_else(|error| panic!("{short} parses: {error}"));
            let full = Cli::try_parse_from(["kr", long, "1"])
                .or_else(|_| Cli::try_parse_from(["kr", long]))
                .unwrap_or_else(|error| panic!("{long} parses: {error}"));
            assert_eq!(
                std::mem::discriminant(&parsed.command),
                std::mem::discriminant(&full.command),
                "{short} is {long}"
            );
        }
    }

    #[test]
    fn the_presentation_flags_are_mutually_exclusive() {
        assert!(Cli::try_parse_from(["kr", "new", "--attach", "--invisible"]).is_err());
        assert!(Cli::try_parse_from(["kr", "new", "--terminal", "--invisible"]).is_err());
        assert!(Cli::try_parse_from(["kr", "new", "--invisible"]).is_ok());
    }

    #[test]
    fn a_terminator_ends_option_parsing() {
        let parsed =
            Cli::try_parse_from(["kr", "attach", "--", "--not-an-option"]).expect("parses");
        let Command::Attach(arguments) = parsed.command else {
            panic!("attach");
        };
        assert_eq!(arguments.session, "--not-an-option");
    }

    #[test]
    fn a_presentation_is_required_without_a_terminal() {
        let parsed = Cli::try_parse_from(["kr", "new"]).expect("parses");
        let Command::New(arguments) = parsed.command else {
            panic!("new");
        };
        assert!(arguments.presentation.resolve(false).is_err());
        assert_eq!(
            arguments.presentation.resolve(true).expect("defaults"),
            kr_protocol::session::Presentation::Attach
        );
    }

    #[test]
    fn json_is_available_on_every_command() {
        let parsed = Cli::try_parse_from(["kr", "list", "--json"]).expect("parses");
        assert!(parsed.json);
        let parsed = Cli::try_parse_from(["kr", "--json", "doctor"]).expect("parses");
        assert!(parsed.json);
    }
}
