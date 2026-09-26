//! What the command line adds to the text a diagnostic may show.
//!
//! The rule is the client library's own ([`kr_client::shown`]): a failure, a line on stderr and a
//! `--json` failure document say only a [`Shown`], built from this program's words, `Plain` values,
//! a reducer or a door. This file is where the command line adds to it, and the only file in this
//! crate that may claim a type is `Plain`:
//!
//! * [`Named`], a path the person named on this command line, returned to them;
//! * [`Usage`], a usage failure as the command's own declarations and clap's classification say it,
//!   with every value the person typed taken out;
//! * [`tool_server`], a failure of the tool server by its kind;
//! * [`VerificationValue`], a pairing's verification value as both devices show it.
//!
//! Each type here is made only by the function beside it, so a value of it is always what that
//! function decided may be said.

use std::fmt;
use std::path::{Path, PathBuf};

use kr_client::shown;
use kr_client::shown::{Plain, Said, Shown};

/// A path the person named on this command line.
///
/// It is shown back to them because saying which of their files could not be used is the answer
/// to their own request, and it is theirs: nothing here names a path a listing found.
pub struct Named(PathBuf);

/// Returns a path the person named, as a failure may show it back to them.
#[must_use]
pub fn named(path: &Path) -> Named {
    Named(path.to_path_buf())
}

impl fmt::Display for Named {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0.display(), formatter)
    }
}

impl Plain for Named {}

/// A usage failure, as a person reading it can act on it.
///
/// The words are this program's own for the kind of mistake, then what the command declares:
/// the argument the mistake is about, the values it takes, a suggestion and the usage line. What the
/// person typed is not in it: an argument this command does not take, a value it cannot read or a
/// subcommand it does not have is named by its kind, never repeated.
pub struct Usage(String);

/// Returns what a usage failure says.
#[must_use]
pub fn usage(error: &clap::Error) -> Usage {
    use clap::error::{ContextKind, ContextValue, ErrorKind};

    let (words, argument_is_declared) = match error.kind() {
        ErrorKind::InvalidValue => ("a value this argument does not take was given", true),
        ErrorKind::UnknownArgument => ("an argument this command does not take was given", false),
        ErrorKind::InvalidSubcommand => {
            ("a subcommand this command does not have was given", false)
        }
        ErrorKind::NoEquals => ("the argument takes its value after an equals sign", true),
        ErrorKind::ValueValidation => ("a value was given that this argument cannot read", true),
        ErrorKind::TooManyValues => ("more values were given than the argument takes", true),
        ErrorKind::TooFewValues => ("fewer values were given than the argument needs", true),
        ErrorKind::WrongNumberOfValues => ("the wrong number of values was given", true),
        ErrorKind::ArgumentConflict => (
            "two arguments were given that cannot be used together",
            true,
        ),
        ErrorKind::MissingRequiredArgument => ("a required argument was not given", true),
        ErrorKind::MissingSubcommand => ("this command needs a subcommand", false),
        ErrorKind::InvalidUtf8 => ("an argument is not valid UTF-8", false),
        _ => ("the command line is not one this command takes", false),
    };
    let text = |value: &ContextValue| match value {
        ContextValue::String(one) => Some(one.clone()),
        ContextValue::Strings(many) => Some(many.join(", ")),
        ContextValue::StyledStr(one) => Some(one.to_string()),
        ContextValue::StyledStrs(many) => Some(
            many.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        ),
        _ => None,
    };
    let mut said = format!("error: {words}");
    for (kind, value) in error.context() {
        // The declared argument, the values it takes and a suggestion are the command's own text.
        // An invalid value, an unknown argument and an invalid subcommand are what was typed, and
        // are never read here.
        let what = match kind {
            ContextKind::InvalidArg if argument_is_declared => "the argument",
            ContextKind::PriorArg => "given with",
            ContextKind::ValidValue => "it takes",
            ContextKind::ValidSubcommand => "the subcommands are",
            ContextKind::SuggestedArg
            | ContextKind::SuggestedSubcommand
            | ContextKind::SuggestedValue => "did you mean",
            _ => continue,
        };
        if let Some(value) = text(value) {
            said.push_str(&format!("; {what} {value}"));
        }
    }
    if let Some(usage) = error.get(ContextKind::Usage).and_then(text) {
        said.push_str("\n\n");
        said.push_str(usage.trim());
    }
    said.push_str("\n\nFor more information, try '--help'.");
    Usage(said)
}

impl fmt::Display for Usage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Plain for Usage {}

/// What an identifier someone typed or sent says: the identifier when the text is one, and that it
/// is not one otherwise. The text itself is never repeated.
#[must_use]
pub fn parsed_identifier<T: std::str::FromStr + Plain>(text: &str) -> Shown {
    text.parse::<T>().map_or_else(
        |_| Shown::said("[not an identifier]"),
        |identifier| shown!("{}", identifier),
    )
}

/// What a failure to start the tool server says: its kind, never what a client sent.
#[must_use]
pub fn tool_server(error: &rmcp::service::ServerInitializeError) -> Shown {
    use rmcp::service::ServerInitializeError as Failure;

    Shown::said(match error {
        Failure::ExpectedInitializeRequest(_) => {
            "the client did not open with an initialize request"
        }
        Failure::ConnectionClosed(_) => "the connection closed before the server started",
        Failure::UnexpectedInitializeResponse(_) => {
            "the client answered initialisation unexpectedly"
        }
        Failure::InitializeFailed(_) => "initialisation failed",
        Failure::TransportError { .. } => "the transport failed while the server started",
        Failure::Cancelled => "starting the server was cancelled",
        _ => "the server could not start",
    })
}

/// A pairing's verification value, as both devices show it.
pub struct VerificationValue(String);

/// Returns what a pairing's verification value says: its eight hexadecimal digits in the
/// protocol's own grouping, the one both devices show. Any other text is replaced: the value
/// arrived from the host, and one of another shape is not a value this build can say.
#[must_use]
pub fn verification_value(text: &str) -> VerificationValue {
    let read = text.len() == kr_protocol::pairing::VERIFICATION_VALUE_LEN
        && text.bytes().all(|byte| byte.is_ascii_hexdigit());
    VerificationValue(if read {
        kr_protocol::pairing::group_verification_value(text)
    } else {
        "[a verification value this build does not read]".to_owned()
    })
}

impl fmt::Display for VerificationValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Plain for VerificationValue {}

/// What a device's platform says: the protocol's own name for it.
#[must_use]
pub fn platform(platform: kr_protocol::pairing::DevicePlatform) -> Shown {
    use kr_protocol::pairing::DevicePlatform;

    Shown::said(match platform {
        DevicePlatform::Macos => "macos",
        DevicePlatform::Windows => "windows",
        DevicePlatform::Linux => "linux",
        DevicePlatform::Ios => "ios",
        DevicePlatform::Android => "android",
    })
}

impl Said for crate::resolve::SessionSelector {
    fn said(&self) -> Shown {
        match self {
            Self::Display(number) => shown!("{}", *number),
            Self::Identifier(session_id) => shown!("{}", *session_id),
        }
    }
}

kr_client::display_as_said!(crate::resolve::SessionSelector);

// A selector is a display number or a session identifier, both parsed before one is made.
impl Plain for crate::resolve::SessionSelector {}

/// What a terminal library failure says: its numbers and its fixed words, never a colour
/// specification or an encoding name the terminal or an application supplied.
#[must_use]
pub fn term(error: &kr_term::TermError) -> Shown {
    use kr_term::TermError as Failure;

    match error {
        Failure::Geometry {
            cols,
            rows,
            violated,
            max_cols,
            max_rows,
            max_cells,
        } => shown!(
            "geometry {}x{} violates {}: columns 1..={}, rows 1..={}, cells 1..={}",
            *cols,
            *rows,
            *violated,
            *max_cols,
            *max_rows,
            *max_cells
        ),
        Failure::Admission {
            cols,
            rows,
            cells,
            footprint,
            budget,
        } => shown!(
            "geometry {}x{} is {} cells, which needs {} bytes of the {}-byte session budget",
            *cols,
            *rows,
            *cells,
            *footprint,
            *budget
        ),
        Failure::ColourSpec { .. } => {
            Shown::said("a colour specification is not a form kr-vt/1 accepts")
        }
        Failure::ProbeFailed { reason } => shown!("TERMINAL_PROBE_FAILED: {}", *reason),
        Failure::CursorGap {
            requested,
            available,
        } => shown!(
            "delta bases on cursor {} but the engine holds {}",
            *requested,
            *available
        ),
        Failure::HistoryEvicted {
            from,
            to,
            oldest,
            newest,
        } => shown!(
            "history rows {}..{} are outside the retained range {}..{}",
            *from,
            *to,
            *oldest,
            *newest
        ),
        Failure::InputIncompatible { .. } => Shown::said(
            "INPUT_INCOMPATIBLE: the application negotiated an input encoding the attachment \
             does not offer",
        ),
        _ => Shown::said("the terminal library failed"),
    }
}

/// What a shell package failure says: its kind and the package root it was found under, never a
/// manifest's text, a name the root's listing or a pointer file gave, or what a request asked for.
#[must_use]
pub fn package_fault(
    fault: &kr_shell_integration::host::package::PackageFault,
    root: &Path,
) -> Shown {
    use kr_shell_integration::host::package::{PACKAGE_ROOT_VARIABLE, PackageFault as Fault};

    match fault {
        Fault::NoPackages => shown!(
            "no qualified shell packages are installed; {} names none either",
            PACKAGE_ROOT_VARIABLE
        ),
        Fault::Unqualified { .. } => Shown::said(
            "the shell asked for has no qualified KalaReach package, so it cannot claim the \
             managed contract",
        ),
        Fault::Unreadable { .. } => shown!("a package under {} cannot be read", Shown::root(root)),
        Fault::MissingExecutable { .. } => shown!(
            "a package under {} names an executable that is not installed",
            Shown::root(root)
        ),
        Fault::NotInteractive { .. } => {
            Shown::said("a script invocation is not an interactive root shell")
        }
    }
}

/// The terminal applications the terminal catalogue names, which a failure may repeat.
const TERMINAL_APPLICATIONS: &[&str] = &[
    "alacritty",
    "apple-terminal",
    "gnome-terminal",
    "iterm2",
    "kitty",
    "konsole",
    "windows-console",
    "windows-terminal",
    "xfce4-terminal",
    "xterm",
];

/// What a terminal application's identifier says: the identifier when it is one the terminal
/// catalogue gives, and a placeholder otherwise.
#[must_use]
pub fn terminal_application(id: &str) -> Shown {
    TERMINAL_APPLICATIONS
        .iter()
        .find(|known| **known == id)
        .map_or_else(
            || Shown::said("[a terminal this build does not list]"),
            |known| Shown::said(known),
        )
}

/// What an operating system error number says: its kind and its number, as [`Shown::io`] says any
/// input or output failure.
#[must_use]
pub fn errno(error: rustix::io::Errno) -> Shown {
    Shown::io(&std::io::Error::from(error))
}

// The command line's own failures, each held to saying only `Shown` and `Plain` values.
impl Plain for crate::error::CliError {}
impl Plain for crate::bridge::pipe::PipeError {}

#[cfg(test)]
pub(crate) mod marker;

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::error::CliError;
    use marker::{MARKER, assert_unmarked, failure_renderings};

    /// What the command line makes of a line it refuses.
    fn refused(line: &[&str]) -> clap::Error {
        match crate::cli::Cli::try_parse_from(line) {
            Ok(_) => panic!("the command line refuses {line:?}"),
            Err(error) => error,
        }
    }

    /// A usage failure never repeats what was typed. An argument this command does not take, a
    /// value where none goes, a subcommand it does not have, a value outside a declared set and a
    /// value that cannot be read are each said by their kind and the command's own declarations.
    #[test]
    fn a_usage_failure_never_repeats_what_was_typed() {
        let cases: [(&str, &[&str]); 6] = [
            ("an unknown argument", &["kr", "attach", "--kr-marker-7c1e"]),
            (
                "an unexpected value",
                &["kr", "attach", "one", "kr-marker-7c1e"],
            ),
            ("an unknown subcommand", &["kr", "kr-marker-7c1e"]),
            (
                "a value outside a declared set",
                &[
                    "kr",
                    "workspace",
                    "create",
                    "project",
                    "--kind",
                    "kr-marker-7c1e",
                ],
            ),
            (
                "a value that cannot be read",
                &["kr", "pair", "invite", "--view", "kr-marker-7c1e"],
            ),
            (
                "an unknown argument with a value, under --json",
                &["kr", "--json", "attach", "--kr-marker-7c1e=kr-marker-7c1e"],
            ),
        ];
        for (class, line) in cases {
            let error = refused(line);
            // The negative control: clap's own rendering, which the command wrote on standard
            // error and into its failure document, repeats what was typed.
            assert!(
                error.render().to_string().contains(MARKER),
                "{class}: {}",
                error.render()
            );
            let said = usage(&error).to_string();
            assert!(
                said.starts_with("error: ")
                    && said.ends_with("For more information, try '--help'."),
                "{class}: {said}"
            );
            assert_unmarked(class, std::slice::from_ref(&said));
            assert_unmarked(
                class,
                &failure_renderings(CliError::Usage(shown!("{}", usage(&error)))),
            );
        }
    }

    /// What the command declares is said: the argument, the values it takes and the usage line.
    #[test]
    fn a_usage_failure_says_what_the_command_declares() {
        let error = refused(&["kr", "workspace", "create", "project", "--kind", "neither"]);
        let said = usage(&error).to_string();
        assert!(said.contains("--kind <KIND>"), "{said}");
        assert!(said.contains("it takes shared, isolated"), "{said}");
        assert!(!said.contains("neither"), "{said}");

        let error = refused(&["kr", "attach"]);
        let said = usage(&error).to_string();
        assert!(said.contains("Usage: kr attach"), "{said}");
    }

    /// A value typed where an identifier, a selector or a choice goes is not repeated when it is
    /// none of them. Each of these failures began with the value as it was typed.
    #[test]
    fn a_typed_value_that_is_not_read_is_not_repeated() {
        let startup = match crate::cli::Cli::try_parse_from(["kr", "new", "--startup", MARKER])
            .expect("the line parses")
            .command
        {
            crate::cli::Command::New(arguments) => arguments
                .launch_profile()
                .expect_err("not a startup selection"),
            _ => unreachable!("the line is kr new"),
        };
        let failures: [(&str, CliError); 7] = [
            (
                "a session selector",
                crate::resolve::SessionSelector::parse(MARKER).expect_err("not a selector"),
            ),
            (
                "an identifier",
                crate::daemon::identifier::<kr_protocol::ids::EnvironmentId>(
                    MARKER,
                    "an environment",
                )
                .expect_err("not an identifier"),
            ),
            (
                "a palette",
                crate::create::PaletteChoice::parse(MARKER).expect_err("not a palette"),
            ),
            (
                "an agent",
                crate::skill::parse(MARKER, "user", None).expect_err("not an agent"),
            ),
            (
                "a scope",
                crate::skill::parse("codex", MARKER, None).expect_err("not a scope"),
            ),
            (
                "a shell",
                crate::shell::shells(Some(MARKER)).expect_err("not a shell"),
            ),
            ("a startup selection", startup),
        ];
        for (class, error) in failures {
            assert_unmarked(class, &failure_renderings(error));
        }
    }

    /// A shell package failure says its kind and the package root it was found under, never a
    /// manifest's text, a name a listing gave, or what a request asked for.
    #[test]
    fn a_package_failure_says_its_kind_and_not_what_it_read() {
        use kr_shell_integration::host::package::PackageFault;

        let root = Path::new("/opt/kalareach/shells");
        // The root is said with the platform's own separator throughout.
        let said = ["", "opt", "kalareach", "shells"].join(std::path::MAIN_SEPARATOR_STR);
        for (fault, expected) in [
            (
                PackageFault::Unreadable {
                    path: format!("/opt/kalareach/shells/{MARKER}"),
                    detail: MARKER.to_owned(),
                },
                format!("a package under {said} cannot be read"),
            ),
            (
                PackageFault::MissingExecutable {
                    path: format!("/opt/kalareach/shells/{MARKER}/current"),
                },
                format!("a package under {said} names an executable that is not installed"),
            ),
            (
                PackageFault::Unqualified {
                    requested: MARKER.to_owned(),
                },
                "the shell asked for has no qualified KalaReach package, so it cannot claim the \
                 managed contract"
                    .to_owned(),
            ),
            (
                PackageFault::NotInteractive {
                    detail: MARKER.to_owned(),
                },
                "a script invocation is not an interactive root shell".to_owned(),
            ),
        ] {
            // The negative control: the fault's own text carries what it read.
            assert!(fault.to_string().contains(MARKER), "{fault}");
            // The neutral control: what is said is the kind and the root, and nothing else.
            assert_eq!(package_fault(&fault, root).as_str(), expected);
            assert_unmarked(
                "a package failure",
                &failure_renderings(CliError::ShellIntegrationUnsupported(package_fault(
                    &fault, root,
                ))),
            );
        }
    }

    /// A terminal application is named when the terminal catalogue names it, and replaced
    /// otherwise.
    #[test]
    fn a_terminal_application_is_named_only_as_the_catalogue_names_it() {
        assert_eq!(terminal_application("iterm2").as_str(), "iterm2");
        assert_eq!(
            terminal_application(MARKER).as_str(),
            "[a terminal this build does not list]"
        );
    }

    /// The usage a failure prints names the command as it declares itself, never as the caller
    /// invoked it.
    #[test]
    fn a_usage_failure_names_the_command_as_it_declares_itself() {
        let error = refused(&[MARKER, "attach"]);
        let said = usage(&error).to_string();
        assert!(said.contains("Usage: kr attach"), "{said}");
        assert_unmarked("the usage line", &[said]);
    }

    /// A terminal library failure never repeats a colour specification the terminal sent.
    #[test]
    fn a_terminal_failure_does_not_repeat_what_the_terminal_sent() {
        let error = kr_term::TermError::ColourSpec {
            spec: MARKER.to_owned(),
        };
        assert!(error.to_string().contains(MARKER), "{error}");
        // The neutral control: the kind of failure is said.
        assert_eq!(
            term(&error).as_str(),
            "a colour specification is not a form kr-vt/1 accepts"
        );
        assert_unmarked(
            "a colour specification",
            &failure_renderings(CliError::Terminal(term(&error))),
        );
    }

    /// A pairing failure never repeats what a rendezvous service, a store or a refusal said.
    #[test]
    fn a_pairing_failure_does_not_repeat_what_a_service_said() {
        use kr_pairing::PairingError;

        for (error, expected) in [
            (
                PairingError::RendezvousUnavailable {
                    reason: MARKER.to_owned(),
                },
                "the rendezvous service is unavailable",
            ),
            (
                PairingError::RendezvousConfiguration {
                    reason: MARKER.to_owned(),
                },
                "the rendezvous origin is not configured correctly",
            ),
            (
                PairingError::Store {
                    reason: MARKER.to_owned(),
                },
                "the pairing store failed",
            ),
            (
                PairingError::Refused {
                    code: kr_protocol::error::ErrorCode::PermissionDenied,
                    reason: MARKER.to_owned(),
                },
                "the pairing was refused: PERMISSION_DENIED",
            ),
        ] {
            assert!(error.to_string().contains(MARKER), "{error}");
            // The neutral control: the kind of failure, and a refusal's code, are said.
            assert_eq!(Shown::pairing(&error).as_str(), expected);
            assert_unmarked(
                "a pairing failure",
                &failure_renderings(CliError::Other(Shown::pairing(&error))),
            );
        }
    }

    /// The tool server's failures say their kind: what a client sent, and what a task's panic
    /// said, are not repeated.
    #[test]
    fn a_tool_server_failure_says_its_kind() {
        let closed = rmcp::service::ServerInitializeError::ConnectionClosed(MARKER.to_owned());
        assert!(closed.to_string().contains(MARKER), "{closed}");
        assert_unmarked(
            "a tool server that could not start",
            &failure_renderings(CliError::Other(tool_server(&closed))),
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime");
        let panicked = runtime
            .block_on(async {
                tokio::spawn(async {
                    std::panic::panic_any(MARKER.to_owned());
                })
                .await
            })
            .expect_err("the task panics");
        assert!(panicked.is_panic());
        // The negative control: the join failure's own text quotes what the panic said.
        assert!(panicked.to_string().contains(MARKER), "{panicked}");
        assert_unmarked(
            "a task that panicked",
            &failure_renderings(CliError::Other(Shown::task(&panicked))),
        );
    }

    /// An operating system error number is said as any input or output failure is: its kind and its
    /// number.
    #[cfg(unix)]
    #[test]
    fn an_error_number_is_its_kind_and_number() {
        let said = errno(rustix::io::Errno::NOENT).to_string();
        assert!(said.contains("(os error 2)"), "{said}");
    }

    /// A verification value is said grouped in fours, as both devices show it, and only when it is
    /// eight hexadecimal digits; anything else a host sent is replaced. A platform is said by the
    /// protocol's own name for it.
    #[test]
    fn a_verification_value_is_said_only_as_eight_hexadecimal_digits() {
        assert_eq!(verification_value("f3c146fd").to_string(), "f3c1 46fd");
        for sent in [MARKER, "f3c146fd0", "f3c1 46fd", "", "g3c146fd"] {
            let said = verification_value(sent).to_string();
            assert_eq!(
                said, "[a verification value this build does not read]",
                "{sent}"
            );
        }
        assert_unmarked(
            "a verification value",
            &failure_renderings(CliError::Other(shown!("{}", verification_value(MARKER)))),
        );
        assert_eq!(
            platform(kr_protocol::pairing::DevicePlatform::Ios).as_str(),
            "ios"
        );
    }
}
