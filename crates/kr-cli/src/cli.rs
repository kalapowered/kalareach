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
    /// Read and answer the questions agents in this host's sessions are waiting on.
    #[command(subcommand)]
    Question(QuestionCommand),
    /// Install the contact skill and its tool configuration for an agent.
    #[command(subcommand)]
    Skill(SkillCommand),
    /// Run the contact tools for the agent that launched this process.
    AgentTools(AgentToolsArguments),
    /// Run read-only diagnostics.
    Doctor(DoctorArguments),
    /// Inspect or change this host's own settings.
    Host(HostArguments),
}

/// `kr host`.
#[derive(Debug, Args)]
pub struct HostArguments {
    /// What to inspect or change.
    #[command(subcommand)]
    pub command: HostCommand,
}

/// One `kr host` operation.
#[derive(Debug, Subcommand)]
pub enum HostCommand {
    /// Show or change whether this host keeps itself awake for work it has admitted.
    Power(PowerArguments),
}

/// `kr host power`.
#[derive(Debug, Args)]
pub struct PowerArguments {
    /// The choice to make: `off`, `mains_only` or `battery_too`. Without it, the current setting
    /// and what it is doing are shown and nothing changes.
    #[arg(long)]
    pub set: Option<String>,
}

/// Which execution context a new session runs in.
#[derive(Debug, Args)]
#[group(multiple = false)]
pub struct Execution {
    /// Run in this host's current desktop. The session closes when that desktop's login ends.
    #[arg(long)]
    pub desktop: bool,
    /// Run in this host's headless user context, with no inherited graphical access.
    #[arg(long)]
    pub headless: bool,
}

/// `kr question`.
#[derive(Debug, Subcommand)]
pub enum QuestionCommand {
    /// List the questions waiting for an answer.
    List(QuestionListArguments),
    /// Show one question in full, including the application identity the host verified.
    Show(QuestionShowArguments),
    /// Answer one question.
    Answer(QuestionAnswerArguments),
    /// Withdraw one question without answering it.
    Cancel(QuestionShowArguments),
}

/// `kr question list`.
#[derive(Debug, Args)]
pub struct QuestionListArguments {
    /// One session, by display number or identifier. Every session by default.
    #[arg(long)]
    pub session: Option<String>,
    /// Include questions that have already been answered, cancelled or expired.
    #[arg(long)]
    pub include_resolved: bool,
}

/// `kr question show` and `kr question cancel`.
#[derive(Debug, Args)]
pub struct QuestionShowArguments {
    /// The question identifier.
    pub question: String,
}

/// How one question is answered. Exactly one of these is required.
#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct AnswerForm {
    /// Free text, for an `input` question.
    #[arg(long)]
    pub text: Option<String>,
    /// One of the listed choices, for a `select` question.
    #[arg(long)]
    pub choice: Option<String>,
    /// Yes, for a `confirm` question.
    #[arg(long)]
    pub yes: bool,
    /// No, for a `confirm` question.
    #[arg(long)]
    pub no: bool,
    /// Free text instead of the listed choices. Every select and confirm offers it, and it is
    /// never folded into a choice or into yes.
    #[arg(long)]
    pub other: Option<String>,
}

/// `kr question answer`.
#[derive(Debug, Args)]
pub struct QuestionAnswerArguments {
    /// The question identifier.
    pub question: String,
    /// The answer.
    #[command(flatten)]
    pub form: AnswerForm,
}

/// `kr skill`.
#[derive(Debug, Subcommand)]
pub enum SkillCommand {
    /// Install the skill and register the tool server.
    Install(SkillArguments),
    /// Report what is installed, and what no longer matches what was written.
    Status(SkillArguments),
    /// Undo exactly what an installation recorded.
    Remove(SkillArguments),
}

/// `kr skill install`, `kr skill status` and `kr skill remove`.
#[derive(Debug, Args)]
pub struct SkillArguments {
    /// The agent: codex, claude-code, opencode, gemini-cli, kimi-code-cli or qoder-cli.
    #[arg(long)]
    pub agent: String,
    /// user or project.
    #[arg(long)]
    pub scope: String,
    /// The project directory, for project scope. The working directory by default.
    #[arg(long)]
    pub project_dir: Option<String>,
}

/// `kr agent-tools`.
#[derive(Debug, Args)]
pub struct AgentToolsArguments {
    /// Speak the Model Context Protocol over this process's standard input and output.
    #[arg(long)]
    pub stdio: bool,
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
    /// Which execution context the session runs in. These are mutually exclusive, and this host's
    /// own default is used when neither is given.
    #[command(flatten)]
    pub execution: Execution,
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
    /// The palette the session starts with: `light`, `dark`, or `probe` to adopt this terminal's
    /// own foreground and background. The profile default is used when this is absent, and an
    /// invisible session cannot probe because it has no terminal.
    #[arg(long)]
    pub palette: Option<String>,
}

/// `kr attach`.
#[derive(Debug, Args)]
pub struct AttachArguments {
    /// The session, by display number or identifier.
    pub session: String,
    /// Do not probe the outer terminal's capabilities. The attachment then watches: the host
    /// changes nothing about this terminal's keyboard and will not let it type, because what its
    /// keys mean was never established.
    #[arg(long)]
    pub no_probe: bool,
    /// Take size ownership for this terminal. Ordinary attach never moves it.
    #[arg(long)]
    pub take_geometry: bool,
    /// Come back to the live screen as soon as the session writes something. Without this a window
    /// scrolled back with Shift and Page Up stays where it was put.
    #[arg(long)]
    pub follow_live: bool,
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

impl Execution {
    /// Returns the execution context this command asked for, or none for the host's own default.
    ///
    /// The presentation is not an input. Where a session is shown and where its processes run are
    /// different questions, and `--invisible` answers only the first.
    #[must_use]
    pub const fn chosen(&self) -> Option<kr_protocol::identity::WorkerProfile> {
        if self.desktop {
            return Some(kr_protocol::identity::WorkerProfile::DesktopBound);
        }
        if self.headless {
            return Some(kr_protocol::identity::WorkerProfile::HeadlessUser);
        }
        None
    }
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
    fn the_execution_context_is_chosen_separately_from_the_presentation() {
        let parsed = Cli::try_parse_from(["kr", "new", "--invisible"]).expect("parses");
        let Command::New(arguments) = parsed.command else {
            panic!("new");
        };
        assert!(
            arguments.execution.chosen().is_none(),
            "an invisible session takes this host's own execution context, not a headless one"
        );

        let parsed =
            Cli::try_parse_from(["kr", "new", "--invisible", "--desktop"]).expect("parses");
        let Command::New(arguments) = parsed.command else {
            panic!("new");
        };
        assert_eq!(
            arguments.execution.chosen(),
            Some(kr_protocol::identity::WorkerProfile::DesktopBound),
            "the two flags are about different things and combine"
        );
        assert_eq!(
            arguments
                .presentation
                .resolve(false)
                .expect("a presentation was given"),
            kr_protocol::session::Presentation::Invisible
        );

        assert!(
            Cli::try_parse_from(["kr", "new", "--desktop", "--headless"]).is_err(),
            "a session runs in one execution context"
        );
    }

    #[test]
    fn the_power_setting_is_shown_without_an_argument_and_changed_with_one() {
        let parsed = Cli::try_parse_from(["kr", "host", "power"]).expect("parses");
        let Command::Host(arguments) = parsed.command else {
            panic!("host");
        };
        let HostCommand::Power(power) = arguments.command;
        assert!(power.set.is_none(), "showing the setting changes nothing");

        let parsed =
            Cli::try_parse_from(["kr", "host", "power", "--set", "mains_only"]).expect("parses");
        let Command::Host(arguments) = parsed.command else {
            panic!("host");
        };
        let HostCommand::Power(power) = arguments.command;
        assert_eq!(power.set.as_deref(), Some("mains_only"));
    }

    #[test]
    fn json_is_available_on_every_command() {
        let parsed = Cli::try_parse_from(["kr", "list", "--json"]).expect("parses");
        assert!(parsed.json);
        let parsed = Cli::try_parse_from(["kr", "--json", "doctor"]).expect("parses");
        assert!(parsed.json);
    }
}
