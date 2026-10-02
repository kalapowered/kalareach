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
//! * [`VerificationValue`], a pairing's verification value as both devices show it;
//! * [`BuildName`], a build identifier that is a program's name and its release;
//! * [`host_text`], the door for the host's own export text as it arrived on the owner's local
//!   connection;
//! * [`withheld`], a value the host wrote said by its class and its length, in the host's own words;
//! * [`git_revision`], [`git_mode`] and [`hex_digest`], identifiers that arrived as text, said only
//!   when they match their grammar, and [`socket_address`] and [`host_name`], the two network forms
//!   a configuration value can take besides a URL;
//! * [`startup_refusal`], why a shell's startup file was left as it was, in the host's own words;
//! * [`help`], this program's own help and version, as clap renders its declarations.
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

/// Spelled as every path this program says: the platform's own separator throughout.
impl fmt::Display for Named {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&kr_client::shown::spelled(&self.0))
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

/// Returns what a pairing's verification value says in a document: its eight hexadecimal digits as
/// they arrived, when that is what they are. Any other text is replaced, as
/// [`verification_value`] replaces it.
#[must_use]
pub fn verification_digits(text: &str) -> Shown {
    if text.len() == kr_protocol::pairing::VERIFICATION_VALUE_LEN
        && text.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        shown!("{}", Checked(text.to_owned()))
    } else {
        Shown::said("[a verification value this build does not read]")
    }
}

impl fmt::Display for VerificationValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Plain for VerificationValue {}

/// A build identifier, as a refusal names it.
pub struct BuildName(String);

/// The longest build identifier a refusal names.
const BUILD_NAME_LIMIT: usize = 64;

/// Returns what a build identifier says: the identifier when it is a program's name and a release,
/// such as `kr-worker/0.1.0` or, for a program of an installed release, `kr-worker/0.1.0+4254aa6e62e5`,
/// and that it is not one otherwise. A worker states its own, so any other text is replaced rather
/// than repeated.
///
/// The name is lower-case letters, digits and dashes, starting with a letter; the release is
/// numbers separated by dots, and after a `+` the twelve lower-case hexadecimal digits of a
/// commit where there is one; the whole is at most [`BUILD_NAME_LIMIT`] bytes.
#[must_use]
pub fn build_name(build_id: &kr_protocol::ids::BuildId) -> BuildName {
    let text = build_id.as_str();
    let named = text.len() <= BUILD_NAME_LIMIT
        && text.split_once('/').is_some_and(|(name, release)| {
            let (numbers, commit) = match release.split_once('+') {
                Some((numbers, commit)) => (numbers, Some(commit)),
                None => (release, None),
            };
            name.starts_with(|first: char| first.is_ascii_lowercase())
                && name.chars().all(|character| {
                    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
                })
                && numbers.split('.').all(|number| {
                    !number.is_empty() && number.chars().all(|digit| digit.is_ascii_digit())
                })
                && commit.is_none_or(|commit| lower_hex(commit, 12..=12))
        });
    BuildName(if named {
        text.to_owned()
    } else {
        "[a build this kr does not name]".to_owned()
    })
}

impl fmt::Display for BuildName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

// A program's name and its release, from the fixed alphabet above, or this program's own words.
impl Plain for BuildName {}

/// What a release's name says: itself. A [`kr_protocol::update::ReleaseName`] is checked to three
/// numbers and twelve lower-case hexadecimal digits when it is made, so nothing else is in one.
#[must_use]
pub fn release(release: &kr_protocol::update::ReleaseName) -> Shown {
    shown!("{}", Checked(release.as_str().to_owned()))
}

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

/// The names the terminal catalogue gives the applications it names.
const TERMINAL_APPLICATION_NAMES: &[(&str, &str)] = &[
    ("alacritty", "alacritty"),
    ("apple-terminal", "Terminal"),
    ("gnome-terminal", "gnome-terminal"),
    ("iterm2", "iTerm2"),
    ("kitty", "kitty"),
    ("konsole", "konsole"),
    ("windows-console", "Console window"),
    ("windows-terminal", "Windows Terminal"),
    ("xfce4-terminal", "xfce4-terminal"),
    ("xterm", "xterm"),
];

/// What a terminal application's name says: the name the terminal catalogue gives the identifier,
/// and a placeholder for an identifier it does not name.
#[must_use]
pub fn terminal_application_name(id: &str) -> Shown {
    TERMINAL_APPLICATION_NAMES
        .iter()
        .find(|(known, _)| *known == id)
        .map_or_else(
            || Shown::said("[a terminal this build does not list]"),
            |(_, name)| Shown::said(name),
        )
}

/// What an operating system error number says: its kind and its number, as [`Shown::io`] says any
/// input or output failure.
#[must_use]
pub fn errno(error: rustix::io::Errno) -> Shown {
    Shown::io(&std::io::Error::from(error))
}

/// The host's own export text, as it arrived.
pub struct HostText(String);

/// Returns what a host's export text says: its words, as the host wrote them.
///
/// A host composes an export [`Stated`](kr_protocol::hostinfo::export::Stated) or
/// [`Sentence`](kr_protocol::hostinfo::export::Sentence) only from its own source's words, numbers,
/// the terms its build defines, the identifiers it generated, and the class and length of anything
/// else, so the text carries nothing that arrived at the host. Once it has crossed the wire it is
/// text that arrived here, which [`Shown::sentence`] measures. This door says it as the host wrote
/// it instead, as [`Shown::protocol`] says the host's messages: it is for the replies this command
/// line reads from its own host on the owner's local connection, which are every reply it reads.
/// It takes only those two types, and a plain string is not one of them:
///
/// ```compile_fail
/// let arrived = String::from("kr-marker-7c1e");
/// let _ = kr_cli::shown::host_text(&arrived);
/// ```
#[must_use]
pub fn host_text(text: &impl kr_protocol::hostinfo::export::Provenance) -> Shown {
    shown!("{}", HostText(text.as_str().to_owned()))
}

impl fmt::Display for HostText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Plain for HostText {}

/// A value the host wrote, said as its class and its length.
pub struct Withheld(String);

/// Returns what a value the host wrote says when nothing asks to show it: its class and its length,
/// in the host's own words for a value it does not export (`[message withheld, 23 bytes]`).
#[must_use]
pub fn withheld(class: kr_protocol::hostinfo::export::ContentClass, value: &str) -> Shown {
    shown!(
        "{}",
        Withheld(kr_protocol::hostinfo::export::withheld(class, value))
    )
}

/// Returns what a value of `class` says on the host's own export terms: a term this build defines
/// and a number as themselves, anything else as its class and its length.
#[must_use]
pub fn carried(class: kr_protocol::hostinfo::export::ContentClass, value: &str) -> Shown {
    shown!(
        "{}",
        Withheld(kr_protocol::hostinfo::export::carry(class, value))
    )
}

/// Returns what a text field of the host's `type_name` says on the host's own export terms: the
/// class its allowlist gives the field decides, and a field it does not list is a message.
#[must_use]
pub fn exported(type_name: &str, field: &str, value: &str) -> Shown {
    use kr_protocol::hostinfo::export::{ContentClass, class_of};

    carried(
        class_of(type_name, field).unwrap_or(ContentClass::Message),
        value,
    )
}

impl fmt::Display for Withheld {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Plain for Withheld {}

/// Returns the word a value of a closed set goes by on the wire: the name this build's own source
/// gives the variant.
///
/// The value is one the writer claims [`Closed`](crate::output::Closed), a claim a test holds to
/// every leaf of the type, so what it serialises to is a word of that set. A value that does not
/// serialise to one word is named as such. Text is never one, however it is held:
///
/// ```compile_fail
/// let arrived = "kr-marker-7c1e";
/// let _ = kr_cli::shown::wire_word(arrived.chars().next().unwrap_or(' '));
/// ```
#[must_use]
pub fn wire_word<T: crate::output::Closed>(value: T) -> Shown {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(word)) => shown!("{}", Withheld(word)),
        _ => Shown::said("[a value this build does not name]"),
    }
}

/// Why a shell's startup file was left as it was.
///
/// The sentence is one of a closed set the shell integration owns, and nothing of the person's file
/// is in it: the one thing that came from outside, a name PowerShell gave a parse error, was kept
/// only because it is a name.
pub struct StartupRefusal(String);

impl fmt::Display for StartupRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Plain for StartupRefusal {}

/// What a refusal to write into, or take out of, a startup file says: the host's own sentence for
/// it, which says what stopped the change and that the file is as it was.
#[must_use]
pub fn startup_refusal(refusal: &kr_shell_integration::host::refusal::Refusal) -> Shown {
    shown!("{}", StartupRefusal(refusal.to_string()))
}

/// An identifier that arrived as text and matched its grammar.
pub struct Checked(String);

impl fmt::Display for Checked {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Plain for Checked {}

/// What an identifier that is not one says.
const NOT_AN_IDENTIFIER: &str = "[not an identifier]";

/// Says `text` when `matches` holds of it, and that it is not an identifier otherwise.
fn checked(text: &str, matches: bool) -> Shown {
    if matches {
        shown!("{}", Checked(text.to_owned()))
    } else {
        Shown::said(NOT_AN_IDENTIFIER)
    }
}

/// Whether `text` is hexadecimal digits, lower case, within `lengths`.
fn lower_hex(text: &str, lengths: std::ops::RangeInclusive<usize>) -> bool {
    lengths.contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether `text` is a Git reference name as `git check-ref-format` accepts one: no control
/// character, space or `~ ^ : ? * [ \`, no `..`, `@{` or `//`, no part that begins with a dot or
/// ends with `.lock`, and neither `/` nor `.` at either end.
fn git_reference_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 255
        && text != "@"
        && !text.bytes().any(|byte| {
            byte.is_ascii_control()
                || matches!(byte, b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
        && !text.contains("..")
        && !text.contains("@{")
        && !text.contains("//")
        && !text.starts_with('/')
        && !text.ends_with('/')
        && !text.ends_with('.')
        && text
            .split('/')
            .all(|part| !part.starts_with('.') && !part.ends_with(".lock"))
}

/// What a Git revision that arrived as text says: an object identifier (hexadecimal, 4 to 64
/// digits) or a reference name, as itself; anything else is not an identifier.
#[must_use]
pub fn git_revision(text: &str) -> Shown {
    checked(text, lower_hex(text, 4..=64) || git_reference_name(text))
}

/// What a Git file mode that arrived as text says: six octal digits as themselves.
#[must_use]
pub fn git_mode(text: &str) -> Shown {
    checked(
        text,
        text.len() == 6 && text.bytes().all(|byte| (b'0'..=b'7').contains(&byte)),
    )
}

/// What a digest that arrived as text says: 64 lower-case hexadecimal digits as themselves.
#[must_use]
pub fn hex_digest(text: &str) -> Shown {
    checked(text, lower_hex(text, 64..=64))
}

/// What a build identifier that arrived as text says: itself, when it is one this build reads
/// (`kr/0.46.0`), and that it is not an identifier otherwise.
#[must_use]
pub fn build_identity(text: &str) -> Shown {
    checked(
        text,
        kr_protocol::hostinfo::export::BuildIdentity::parse(text).is_some(),
    )
}

/// A 32-bit number in eight hexadecimal digits, as a result code is written.
#[must_use]
pub fn hexadecimal_word(value: u32) -> Shown {
    shown!("{}", Checked(format!("{value:08x}")))
}

/// What a socket address says, in the form it parses to, when the text is one.
#[must_use]
pub fn socket_address(text: &str) -> Option<Shown> {
    text.parse::<std::net::SocketAddr>()
        .ok()
        .map(|address| shown!("{}", Checked(address.to_string())))
}

/// What a host name says, when the text is one: labels of letters, digits and hyphens, each 1 to 63
/// bytes and neither beginning nor ending with a hyphen, joined by dots, 253 bytes at most, with a
/// final dot allowed.
#[must_use]
pub fn host_name(text: &str) -> Option<Shown> {
    let labels = text.strip_suffix('.').unwrap_or(text);
    let named = !labels.is_empty()
        && text.len() <= 253
        && labels.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    named.then(|| shown!("{}", Checked(text.to_owned())))
}

/// Returns the text of a value the writer holds closed ([`crate::output::Closed`]): a protocol value
/// whose every leaf is a closed word, an identifier, a digest or a number by its type, said as the
/// protocol encodes it: its one string, or its JSON text when it is not one string.
#[must_use]
pub fn closed_text(value: &impl crate::output::Closed) -> Shown {
    let text = match serde_json::to_value(value).unwrap_or(serde_json::Value::Null) {
        serde_json::Value::String(text) => text,
        other => other.to_string(),
    };
    shown!("{}", Withheld(text))
}

/// Returns the name a value of a closed set has in this build's source, as its derived `Debug`
/// writes it.
///
/// The value is one the writer claims [`Closed`](crate::output::Closed), so what its `Debug`
/// writes is a variant's name or a number.
#[must_use]
pub fn variant_name<T: crate::output::Closed + fmt::Debug>(value: T) -> Shown {
    shown!("{}", Withheld(format!("{value:?}")))
}

/// This program's help or version, as clap renders what the command declares.
pub struct Help(String);

/// Returns this program's help or version, when that is what clap answered: the command's own
/// declarations, which hold nothing that was typed. Any other answer is a usage failure, which
/// [`usage`] says.
#[must_use]
pub fn help(answer: &clap::Error) -> Option<Shown> {
    use clap::error::ErrorKind;

    matches!(
        answer.kind(),
        ErrorKind::DisplayHelp
            | ErrorKind::DisplayVersion
            | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    )
    .then(|| {
        let rendered = answer.render().to_string();
        let text = rendered.strip_suffix('\n').unwrap_or(&rendered);
        shown!("{}", Help(text.to_owned()))
    })
}

impl fmt::Display for Help {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Plain for Help {}

/// Composes one line of standard output from a template of this program's own and parts that are
/// each [`Plain`] or content the person asked to read ([`crate::output::Asked`]).
///
/// `stdout_line!("{} is {}", question_id, state)`. As with [`kr_client::shown!`], every hole is a
/// bare `{}` filled by the next part in order, and a template with more or fewer holes than parts
/// does not build.
#[macro_export]
macro_rules! stdout_line {
    ($template:literal $(,)?) => {{
        const _: () = ::core::assert!(
            ::core::matches!(
                ::kr_client::shown::holes($template),
                ::core::option::Option::Some(0)
            ),
            "a stdout_line! template has one bare {{}} for each part and no other braces"
        );
        $crate::output::Line::compose($template, &[])
    }};
    ($template:literal, $($part:expr),+ $(,)?) => {{
        const _: () = ::core::assert!(
            ::core::matches!(
                ::kr_client::shown::holes($template),
                ::core::option::Option::Some(holes)
                    if holes == 0 $(+ ::kr_client::shown::one(::core::stringify!($part)))+
            ),
            "a stdout_line! template has one bare {{}} for each part and no other braces"
        );
        $crate::output::Line::compose(
            $template,
            &[$($crate::output::Part::piece(&$part)),+],
        )
    }};
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

    /// A build is named with its release's commit, and a suffix that is anything else is not
    /// repeated.
    #[test]
    fn a_build_is_named_with_its_release_s_commit_and_nothing_else() {
        let named = |text: &str| {
            build_name(&kr_protocol::ids::BuildId::new(text).expect("an identifier")).to_string()
        };
        for text in [
            "kr-worker/0.1.0",
            "kr-worker/0.2.0+4254aa6e62e5",
            "kr-controller/12.0.3+000000000000",
        ] {
            assert_eq!(named(text), text);
        }
        for text in [
            "kr-worker/0.2.0+4254AA6E62E5",
            "kr-worker/0.2.0+4254aa6e62e",
            "kr-worker/0.2.0+sk-live-4254aa",
            "kr-worker/0.2.0+4254aa6e62e5+4254aa6e62e5",
        ] {
            assert_eq!(named(text), "[a build this kr does not name]", "{text}");
        }
        let release =
            kr_protocol::update::ReleaseName::new("0.2.0+4254aa6e62e5").expect("a release");
        assert_eq!(super::release(&release).as_str(), "0.2.0+4254aa6e62e5");
    }
}
