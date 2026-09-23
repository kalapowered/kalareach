//! The command surface.
//!
//! Section 7 fixes the commands, their one-letter forms and the standard options. Two rules shape
//! the definitions here: a literal `--` ends KalaReach option parsing, and no shell command or path
//! is ever assembled by interpolating text.

use std::path::PathBuf;

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
    /// Set up the managed shell integration, or report what it is.
    Shell(ShellArguments),
    /// Manage this host's managed-service account credentials.
    Account(AccountArguments),
    /// Serve this environment to a local process bridge, or manage the environments this host has
    /// enrolled.
    Bridge(BridgeArguments),
}

/// `kr bridge`.
///
/// Section 3 names the invocation this command has to answer to exactly: a Windows host runs
/// `wsl.exe --distribution <name> --user <user> --exec <absolute-kr-path> bridge --stdio`, and a
/// container host runs the equivalent against an enrolled container identifier. So `--stdio` is a
/// flag on this command rather than a word of its own, and the other operations are subcommands
/// beside it.
#[derive(Debug, Args)]
pub struct BridgeArguments {
    /// Serve this environment on standard input and output.
    #[arg(long)]
    pub stdio: bool,

    /// The environment to serve. Without it, this installation's own.
    #[arg(long)]
    pub environment: Option<String>,

    /// What to do instead of serving a bridge.
    #[command(subcommand)]
    pub command: Option<BridgeCommand>,
}

/// One `kr bridge` operation on this host's enrolled environments.
#[derive(Debug, Subcommand)]
pub enum BridgeCommand {
    /// List the enrolled environments from this host's cached inventory.
    ///
    /// The listing reports what was last observed and starts nothing.
    List(BridgeListArguments),
    /// Record an environment this host may reach.
    Enrol(BridgeEnrolArguments),
    /// Remove one enrolled environment and its cached inventory row.
    Forget(BridgeForgetArguments),
    /// Observe one enrolled environment now, optionally starting it.
    Refresh(BridgeRefreshArguments),
}

/// `kr bridge list`.
#[derive(Debug, Args)]
pub struct BridgeListArguments {
    /// Report only this access class: `wsl`, `container`, `ssh` or `paired`.
    #[arg(long)]
    pub access: Option<String>,
}

/// `kr bridge enrol`.
#[derive(Debug, Args)]
pub struct BridgeEnrolArguments {
    /// How this host reaches it: `wsl`, `container`, `ssh` or `paired`.
    #[arg(long)]
    pub access: String,
    /// The name a person selects this record by. A label, never an identity.
    #[arg(long)]
    pub label: String,
    /// The identity the platform issued: the distribution name, the container identifier, or the
    /// SSH destination. A container's human name is not its identity.
    #[arg(long)]
    pub target: String,
    /// The operating-system user the helper runs as inside the target.
    #[arg(long)]
    pub user: String,
    /// The absolute path of the helper installed in the target.
    #[arg(long)]
    pub helper: String,
    /// Where this environment's clipboard writes go.
    #[arg(long)]
    pub clipboard: Option<String>,
    /// The environment identity this record names, when it is already known.
    #[arg(long)]
    pub environment_id: Option<String>,
    /// Ask the destination which environment it is, instead of naming it. The destination has to
    /// be running: asking runs the helper inside it, and enrolment starts nothing.
    #[arg(long)]
    pub probe: bool,
}

/// `kr bridge forget`.
#[derive(Debug, Args)]
pub struct BridgeForgetArguments {
    /// The label of the record to remove.
    pub label: String,
}

/// `kr bridge refresh`.
#[derive(Debug, Args)]
pub struct BridgeRefreshArguments {
    /// The label of the record to observe.
    pub label: String,
    /// Start the environment when it is stopped. A listing never does; a refresh may.
    #[arg(long)]
    pub start: bool,
}

/// `kr account`.
#[derive(Debug, Args)]
pub struct AccountArguments {
    /// What to do.
    #[command(subcommand)]
    pub command: AccountCommand,
}

/// One `kr account` operation.
#[derive(Debug, Subcommand)]
pub enum AccountCommand {
    /// Manage the account token this host presents to managed services.
    #[command(subcommand)]
    Token(AccountTokenCommand),
}

/// One `kr account token` operation.
#[derive(Debug, Subcommand)]
pub enum AccountTokenCommand {
    /// Read an account token from a file and write it where this host reads it.
    ///
    /// The token's value is never printed. What is reported is where it was written, the origin it
    /// belongs to, the scopes it carries and when it stops.
    Import(AccountTokenImportArguments),
    /// Report where this host reads its account token, and what the stored one carries.
    Show,
}

/// `kr account token import`.
#[derive(Debug, Args)]
pub struct AccountTokenImportArguments {
    /// The file to read the token from.
    pub path: std::path::PathBuf,
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
    /// Show the terminal applications this host has, and which one a new window opens in.
    Terminal(TerminalArguments),
}

/// `kr host terminal`.
#[derive(Debug, Args)]
pub struct TerminalArguments {
    /// The application to prefer, by its identifier. Without it, what this host has and what it
    /// prefers are shown and nothing changes.
    #[arg(long)]
    pub set: Option<String>,
    /// Go back to letting this host choose for itself.
    #[arg(long, conflicts_with = "set")]
    pub clear: bool,
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
    /// Run in this host's headless user context, which is bound to no desktop and is given none
    /// of a desktop's handles.
    #[arg(long)]
    pub headless: bool,
}

/// `kr shell`.
#[derive(Debug, Args)]
pub struct ShellArguments {
    /// What to do.
    #[command(subcommand)]
    pub command: ShellCommand,
}

/// One `kr shell` operation.
#[derive(Debug, Subcommand)]
pub enum ShellCommand {
    /// Report the resolved executable, flags, version and integration mode.
    Status(ShellStatusArguments),
    /// Add the marked, guarded entry to this user's own startup configuration.
    Install(ShellInstallArguments),
    /// Delete the marked entry, and nothing else.
    Remove(ShellRemoveArguments),
}

/// `kr shell status`.
#[derive(Debug, Args)]
pub struct ShellStatusArguments {
    /// Report one shell rather than every installed package.
    #[arg(long)]
    pub shell: Option<String>,
}

/// `kr shell install`.
#[derive(Debug, Args)]
pub struct ShellInstallArguments {
    /// Install the entry for one shell rather than every installed package.
    #[arg(long)]
    pub shell: Option<String>,
    /// Offer the documented session-local bypass for a known auto-wrapper.
    ///
    /// It sets `NSH_NO_WRAP=1` inside KalaReach-created shells only, and changes no other setting.
    #[arg(long)]
    pub nsh_bypass: bool,
    /// Report what would change without writing anything.
    #[arg(long)]
    pub dry_run: bool,
}

/// `kr shell remove`.
#[derive(Debug, Args)]
pub struct ShellRemoveArguments {
    /// Remove the entry for one shell rather than every shell KalaReach qualifies.
    #[arg(long)]
    pub shell: Option<String>,
    /// Report what would change without writing anything.
    #[arg(long)]
    pub dry_run: bool,
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
    /// The shell integration mode: `managed` or `native_compat`.
    ///
    /// `managed` launches a KalaReach-qualified shell package, with empty-prompt Ctrl-D and the
    /// fenced launch. `native_compat` launches the selected stock shell and claims neither.
    #[arg(long, default_value = "native_compat")]
    pub shell_mode: String,
    /// The palette the session starts with: `light`, `dark`, or `probe` to adopt this terminal's
    /// own foreground and background. The profile default is used when this is absent, and an
    /// invisible session cannot probe because it has no terminal.
    #[arg(long)]
    pub palette: Option<String>,
    /// Which startup files the root shell reads: `host-default`, `interactive` or `login`.
    ///
    /// The host default is login startup on macOS and the interactive startup alone elsewhere,
    /// which is what section 7 states.
    #[arg(long, default_value = "host-default")]
    pub startup: String,
    /// The terminal application `--terminal` opens in, by its identifier.
    ///
    /// The host detects what is installed when this is absent. A named application this host does
    /// not have is `TERMINAL_UNAVAILABLE`, never a different one.
    #[arg(long)]
    pub terminal_app: Option<String>,
    /// Refuse `shell.launch` in this session.
    ///
    /// Everything else a managed session has stays: the editor fence, the empty-prompt end-of-file
    /// gesture and the attributed acceptance. What goes is the one operation that puts text the
    /// person did not type into their editor.
    #[arg(long)]
    pub no_fenced_launch: bool,
}

impl NewArguments {
    /// Returns the launch profile this invocation asks for.
    ///
    /// # Errors
    ///
    /// Returns a usage failure when `--startup` names none of the three.
    pub fn launch_profile(&self) -> Result<kr_protocol::session::LaunchProfile, crate::CliError> {
        let startup = match self.startup.as_str() {
            "host-default" | "host_default" => kr_protocol::session::ShellStartup::HostDefault,
            "interactive" => kr_protocol::session::ShellStartup::Interactive,
            "login" => kr_protocol::session::ShellStartup::Login,
            other => {
                return Err(crate::CliError::Usage(format!(
                    "{other} is not a startup selection; use host-default, interactive or login"
                )));
            }
        };
        Ok(kr_protocol::session::LaunchProfile {
            startup,
            fenced_launch: !self.no_fenced_launch,
            // Command integrations are configured for the environment rather than per invocation,
            // and a session inherits what that configuration enables.
            command_integrations: Vec::new(),
        })
    }
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
    /// Print every check's evidence, including the checks that passed. Without it, only a check
    /// that did not pass shows its evidence.
    #[arg(long)]
    pub verbose: bool,
    /// Write a support bundle to this path: software versions, capabilities, the diagnostics and
    /// redacted errors, as one archive.
    #[arg(long, value_name = "PATH")]
    pub bundle: Option<PathBuf>,
    /// Add the content-bearing diagnostic export to the bundle. The command prints what it will
    /// contain before it writes anything.
    #[arg(long, requires = "bundle")]
    pub include_content: bool,
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

    /// KR-REQ-07.50: the standard `--help` is answered by the command and by every subcommand at
    /// every depth, and `--version` by the command; each answer is a report that exits with zero,
    /// while a command line that is wrong exits with something else.
    #[test]
    fn help_and_version_are_answered_everywhere() {
        // Every command path the parser knows, from the command itself down.
        let mut paths: Vec<Vec<String>> = Vec::new();
        let mut waiting = vec![(vec!["kr".to_owned()], Cli::command())];
        while let Some((path, command)) = waiting.pop() {
            for subcommand in command.get_subcommands() {
                let mut deeper = path.clone();
                deeper.push(subcommand.get_name().to_owned());
                waiting.push((deeper, subcommand.clone()));
            }
            paths.push(path);
        }
        assert!(
            paths.len() > 8,
            "the walk reached the subcommands: {paths:?}"
        );
        for path in &paths {
            let mut asked = path.clone();
            asked.push("--help".to_owned());
            let answer = Cli::try_parse_from(&asked).expect_err("help is a report, not a command");
            assert_eq!(
                answer.kind(),
                clap::error::ErrorKind::DisplayHelp,
                "{asked:?}"
            );
            assert_eq!(answer.exit_code(), 0, "{asked:?}");
        }
        let answer = Cli::try_parse_from(["kr", "--version"]).expect_err("a report");
        assert_eq!(answer.kind(), clap::error::ErrorKind::DisplayVersion);
        assert_eq!(answer.exit_code(), 0);
        // A command line that is wrong is a failure, and exits with something other than zero.
        let wrong = Cli::try_parse_from(["kr", "new", "--no-such-option"]).expect_err("refused");
        assert_ne!(wrong.exit_code(), 0);
    }

    /// KR-REQ-07.50: `--json` is one option of the whole command line, so every subcommand has it.
    #[test]
    fn json_is_an_option_of_every_subcommand() {
        let command = Cli::command();
        let json = command
            .get_arguments()
            .find(|argument| argument.get_id() == "json")
            .expect("the command line has --json");
        assert!(json.is_global_set(), "and it is global");
        let names: Vec<&str> = command
            .get_subcommands()
            .map(clap::Command::get_name)
            .collect();
        assert!(
            [
                "new", "attach", "detach", "close", "list", "status", "doctor"
            ]
            .iter()
            .all(|name| names.contains(name)),
            "{names:?}"
        );
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

    /// KR-REQ-07.05: `--attach`, `--terminal` and `--invisible` exclude one another.
    #[test]
    fn the_presentation_flags_are_mutually_exclusive() {
        assert!(Cli::try_parse_from(["kr", "new", "--attach", "--terminal"]).is_err());
        assert!(Cli::try_parse_from(["kr", "new", "--attach", "--invisible"]).is_err());
        assert!(Cli::try_parse_from(["kr", "new", "--terminal", "--invisible"]).is_err());
        assert!(Cli::try_parse_from(["kr", "new", "--invisible"]).is_ok());
    }

    /// KR-REQ-07.50: a literal `--` ends option parsing, so what follows it is an argument even
    /// when it looks like an option.
    #[test]
    fn a_terminator_ends_option_parsing() {
        let parsed =
            Cli::try_parse_from(["kr", "attach", "--", "--not-an-option"]).expect("parses");
        let Command::Attach(arguments) = parsed.command else {
            panic!("attach");
        };
        assert_eq!(arguments.session, "--not-an-option");
    }

    /// KR-REQ-07.05: with standard input and output on a terminal the default is `--attach`, and
    /// without one a presentation has to be named.
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

    /// KR-REQ-07.06: `--desktop` or `--headless` chooses where a session runs, apart from how it
    /// is presented, and a session runs in one of them.
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
        let HostCommand::Power(power) = arguments.command else {
            panic!("power");
        };
        assert!(power.set.is_none(), "showing the setting changes nothing");

        let parsed =
            Cli::try_parse_from(["kr", "host", "power", "--set", "mains_only"]).expect("parses");
        let Command::Host(arguments) = parsed.command else {
            panic!("host");
        };
        let HostCommand::Power(power) = arguments.command else {
            panic!("power");
        };
        assert_eq!(power.set.as_deref(), Some("mains_only"));
    }

    /// KR-REQ-07.31: the saved preference is the middle step of the selection order.
    #[test]
    fn the_terminal_preference_is_shown_set_and_cleared() {
        let parsed = Cli::try_parse_from(["kr", "host", "terminal"]).expect("parses");
        let Command::Host(arguments) = parsed.command else {
            panic!("host");
        };
        let HostCommand::Terminal(terminal) = arguments.command else {
            panic!("terminal");
        };
        assert!(terminal.set.is_none() && !terminal.clear);

        let parsed =
            Cli::try_parse_from(["kr", "host", "terminal", "--set", "iterm2"]).expect("parses");
        let Command::Host(arguments) = parsed.command else {
            panic!("host");
        };
        let HostCommand::Terminal(terminal) = arguments.command else {
            panic!("terminal");
        };
        assert_eq!(terminal.set.as_deref(), Some("iterm2"));

        assert!(
            Cli::try_parse_from(["kr", "host", "terminal", "--set", "iterm2", "--clear"]).is_err(),
            "naming one and clearing it are not one request"
        );
    }

    /// KR-REQ-07.06: `--environment`, `--cwd` and `--shell` select the environment, the working
    /// directory and the shell of the session, each taken as given, alongside the execution
    /// context and the presentation.
    #[test]
    fn the_environment_directory_and_shell_are_selected_on_the_command_line() {
        let environment = "01234567-89ab-4def-8123-456789abcdef";
        let parsed = Cli::try_parse_from([
            "kr",
            "new",
            "--invisible",
            "--headless",
            "--environment",
            environment,
            "--cwd",
            "/srv/a directory; with $(punctuation)",
            "--shell",
            "zsh",
        ])
        .expect("parses");
        let Command::New(arguments) = parsed.command else {
            panic!("new");
        };
        assert_eq!(arguments.environment.as_deref(), Some(environment));
        assert_eq!(
            arguments.cwd.as_deref(),
            Some("/srv/a directory; with $(punctuation)"),
            "a path is one argument, never text to be interpreted"
        );
        assert_eq!(arguments.shell.as_deref(), Some("zsh"));
        assert_eq!(
            arguments.execution.chosen(),
            Some(kr_protocol::identity::WorkerProfile::HeadlessUser)
        );
        assert_eq!(
            arguments
                .presentation
                .resolve(false)
                .expect("a presentation was given"),
            kr_protocol::session::Presentation::Invisible
        );
    }

    /// KR-REQ-07.50: `--json` is accepted before and after the subcommand.
    #[test]
    fn json_is_available_on_every_command() {
        let parsed = Cli::try_parse_from(["kr", "list", "--json"]).expect("parses");
        assert!(parsed.json);
        let parsed = Cli::try_parse_from(["kr", "--json", "doctor"]).expect("parses");
        assert!(parsed.json);
    }
}
