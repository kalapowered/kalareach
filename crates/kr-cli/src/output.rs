//! What this program writes on standard output, and the only way anything is written there.
//!
//! Standard output is read by a person at a terminal somebody may be sharing and by scripts that
//! keep what they read, so it follows the rule a diagnostic follows
//! ([`kr_client::shown`](mod@kr_client::shown)), with one addition: content the person asked this
//! command for is shown to them, marked as such.
//!
//! * [`say`] writes one [`Shown`]: this program's words, `Plain` values, and what a reducer or a
//!   door decided may be said.
//! * [`line`](fn@line) writes one [`Line`], composed ([`stdout_line!`](crate::stdout_line)) from a
//!   template of this program's own and parts that are each `Plain` or [`Asked`].
//! * [`document`] writes one `--json` [`Document`], built from `Shown`, numbers, switches, `Asked`,
//!   `Line`s, documents and lists of them. There is no conversion into one from a string or a JSON
//!   value.
//!
//! [`Asked`] is content the person asked to read: a question's text, a repository's path, the name
//! a paired device gave itself. Each names the [`Request`] that asked for it. It never becomes a
//! `Shown` or a `Plain` value, so it cannot reach a failure or a `Debug`, and standard error shows
//! it only through the one reporter function that prints a content export's preview.
//!
//! Three commands own standard output for a protocol or a terminal rather than for lines: the tool
//! server, `kr bridge --stdio` and the attach guard. [`protocol_stream`] and [`attached_terminal`]
//! are their handles, under names nothing else goes by. The source test holds every other use of
//! standard output to this module.

use std::fmt::Write as _;
use std::path::Path;

use kr_client::shown::{Plain, Shown};

/// Why a person is shown content that arrived: what their command asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    /// A session's shell, directory, desktop and processes: `kr new`, `list`, `status`, `close`.
    Sessions,
    /// An agent's question and the answers to it: `kr question`.
    Question,
    /// An invitation's code and QR text: `kr pair invite`.
    Invitation,
    /// The name a paired device gave itself: `kr pair`, `kr device`.
    Devices,
    /// An environment's source repositories: `kr project`.
    Repositories,
    /// A repository's working copies: `kr workspace`.
    Workspaces,
    /// A workspace's captured versions: `kr changeset`.
    Changesets,
    /// A change and the paths it touches: `kr diff`.
    Diff,
    /// Plugin packages and the repositories they come from: `kr plugin`.
    Plugins,
    /// The contact skill's files and tool configuration for an agent: `kr skill`.
    AgentFiles,
    /// A shell's startup files and its package: `kr shell`.
    ShellFiles,
    /// The environments this host reaches through a bridge: `kr bridge`.
    Bridges,
    /// What a contact tool returns to the agent that called it.
    ToolAnswer,
    /// The token an agent presented to the contact tools.
    ToolCaller,
    /// What `kr doctor` was asked to diagnose: a capability's resolved executable, this host's
    /// configuration and state locations, and each effective configuration value.
    Diagnostics,
    /// What the service manager applies to the control daemon's definition besides it: the
    /// drop-ins `kr host startup --set service` names.
    Startup,
    /// Privacy mode's report: what is still owed and why, what is kept and what had already left:
    /// `kr privacy`.
    Privacy,
    /// The content a support bundle's export would hold, shown to the person who asked for it
    /// before it is written: `kr doctor --include-content`.
    Export,
    /// What session descriptions offer on this host: the model's name, where its files come from
    /// and why a fetch failed: `kr host descriptions`.
    Descriptions,
}

/// Content the person asked to read.
///
/// It has no `Display` and no `Debug`, and nothing turns it into a [`Shown`]: this module writes
/// it, into a line or a document on standard output, and nothing else reads it.
pub struct Asked {
    request: Request,
    text: String,
}

impl Asked {
    /// Text as it arrived. A path the host sent is such text, said as the host wrote it: its own
    /// separators, and a repository's paths with the `/` they always have.
    #[must_use]
    pub fn text(request: Request, text: &str) -> Self {
        Self {
            request,
            text: text.to_owned(),
        }
    }

    /// A path this program holds, one it composed or read on this host, spelled as this program
    /// spells every path of its own: the platform's own separator throughout.
    #[must_use]
    pub fn path(request: Request, path: impl AsRef<Path>) -> Self {
        Self {
            request,
            text: kr_client::shown::spelled(path.as_ref()),
        }
    }

    /// A location: a URL as its scheme, host, port and path, a file URL as its path
    /// ([`kr_client::shown::located`]); an SCP-style location (`user@host:path`) as its host and its
    /// path; anything else as a local path, as it was written.
    ///
    /// Nothing is said of a location but those parts, so user information, a query and a fragment
    /// are never kept. Every reading but the parser's says only text that holds none of the
    /// characters that bring them into a URL: an SCP host must be a host name or an IPv6 address in
    /// brackets and its path, like a local path, hold no `@`, `?` or `#`, and a local path no colon
    /// but a drive's. Text written as a URL that the parser does not read, and text none of the
    /// readings takes, is said as its class and its length.
    #[must_use]
    pub fn location(request: Request, location: &str) -> Self {
        use kr_protocol::hostinfo::export::{ContentClass, withheld};

        let text = if let Some(located) =
            kr_client::shown::located(location).or_else(|| kr_client::shown::file_located(location))
        {
            located
        } else if kr_client::shown::written_as_url(location) {
            withheld(ContentClass::Location, location)
        } else if let Some((host, path)) = scp(location) {
            if names_a_host(host) && !path.contains(['@', '?', '#']) {
                format!("{host}:{path}")
            } else {
                withheld(ContentClass::Location, location)
            }
        } else if local_path(location) {
            location.to_owned()
        } else {
            withheld(ContentClass::Location, location)
        };
        Self { request, text }
    }

    /// Why it is shown.
    #[must_use]
    pub const fn request(&self) -> Request {
        self.request
    }
}

/// The host and the path of an SCP-style location, `[user@]host:path`: a user, when there is one,
/// before any colon or slash; a host that is a name or an IPv6 address in brackets, whose own
/// colons are not the one before the path; and a colon after it. A single letter with no user in
/// front of it is a drive, not a host.
fn scp(location: &str) -> Option<(&str, &str)> {
    let (user, rest) = match location.split_once('@') {
        Some((user, rest)) if !user.contains([':', '/', '\\']) => (Some(user), rest),
        _ => (None, location),
    };
    let (host, path) = if rest.starts_with('[') {
        let close = rest.find(']')?;
        let (host, after) = rest.split_at(close + 1);
        (host, after.strip_prefix(':')?)
    } else {
        let (host, path) = rest.split_once(':')?;
        if host.contains(['/', '\\']) {
            return None;
        }
        (host, path)
    };
    let drive =
        user.is_none() && host.len() == 1 && host.bytes().all(|byte| byte.is_ascii_alphabetic());
    (!drive).then_some((host, path))
}

/// Whether text reads as a local path and nothing else: no `@`, `?` or `#`, and no colon but a
/// drive's (`C:`).
fn local_path(location: &str) -> bool {
    let drive = location.len() >= 2
        && location.as_bytes()[0].is_ascii_alphabetic()
        && location.as_bytes()[1] == b':';
    let rest = if drive { &location[2..] } else { location };
    !rest.contains([':', '@', '?', '#'])
}

/// Whether an SCP-style location's host is one: a host name, or an IPv6 address in brackets.
fn names_a_host(host: &str) -> bool {
    crate::shown::host_name(host).is_some()
        || host
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .is_some_and(|inner| inner.parse::<std::net::Ipv6Addr>().is_ok())
}

/// A value of this host's configuration as `kr doctor` shows it, by the class it is made of: a term
/// this build defines and a number as themselves; a path through
/// [`Shown::host_path`](kr_client::shown::Shown::host_path); a location by its shape, a URL as its
/// scheme, host, port and path, a socket address and a host name as themselves; anything else, and
/// a location of no shape this reads, as its class and its length. A list, which the host joins
/// with `, `, is said piece by piece.
///
/// Section 26 asks the report to show each effective value, so the value is content the person
/// asked `kr doctor` for.
#[must_use]
pub fn configured(class: kr_protocol::hostinfo::export::ContentClass, value: &str) -> Asked {
    use kr_protocol::hostinfo::export::ContentClass;

    let each =
        |say: &dyn Fn(&str) -> String| value.split(", ").map(say).collect::<Vec<_>>().join(", ");
    let text = match class {
        ContentClass::Path => each(&|piece| Shown::host_path(Path::new(piece)).into_string()),
        ContentClass::Location => each(&|piece| {
            kr_client::shown::located(piece)
                .or_else(|| crate::shown::socket_address(piece).map(Shown::into_string))
                .or_else(|| crate::shown::host_name(piece).map(Shown::into_string))
                .unwrap_or_else(|| {
                    crate::shown::withheld(ContentClass::Location, piece).into_string()
                })
        }),
        other => crate::shown::carried(other, value).into_string(),
    };
    Asked {
        request: Request::Diagnostics,
        text,
    }
}

/// A text field of the host's configuration report, by the class the host's own export allowlist
/// gives it, as [`configured`] says a value of that class. A field the allowlist does not list is a
/// message.
#[must_use]
pub fn configured_field(type_name: &str, field: &str, value: &str) -> Asked {
    use kr_protocol::hostinfo::export::{ContentClass, class_of};

    configured(
        class_of(type_name, field).unwrap_or(ContentClass::Message),
        value,
    )
}

/// One line of standard output, or one string of a document: a template of this program's own,
/// filled with `Plain` values and content the person asked to read. It never becomes a [`Shown`]
/// or a `Plain` value.
pub struct Line {
    text: String,
    /// The asked content the line holds, which a test compares its text against.
    #[cfg(test)]
    asked: Vec<String>,
}

/// One part of a line, as [`Line::compose`] takes it.
pub enum Piece<'a> {
    /// A value whose text cannot carry input.
    Plain(&'a dyn Plain),
    /// Content the person asked to read.
    Asked(&'a Asked),
    /// A line composed before, whole.
    Line(&'a Line),
    /// Another part, padded with spaces to a width in characters.
    Padded {
        /// The part.
        part: &'a dyn Part,
        /// The width.
        width: usize,
        /// Whether the spaces go before the part rather than after it.
        right: bool,
    },
}

/// What can fill a hole of a line: a `Plain` value, [`Asked`] content, or one of those padded.
pub trait Part {
    /// This part, as a line takes it.
    fn piece(&self) -> Piece<'_>;
}

impl<T: Plain> Part for T {
    fn piece(&self) -> Piece<'_> {
        Piece::Plain(self)
    }
}

impl Part for Asked {
    fn piece(&self) -> Piece<'_> {
        Piece::Asked(self)
    }
}

impl Part for Line {
    fn piece(&self) -> Piece<'_> {
        Piece::Line(self)
    }
}

/// A part padded with spaces to a width.
pub struct Padded<'a> {
    part: &'a dyn Part,
    width: usize,
    right: bool,
}

impl Part for Padded<'_> {
    fn piece(&self) -> Piece<'_> {
        Piece::Padded {
            part: self.part,
            width: self.width,
            right: self.right,
        }
    }
}

/// `part`, followed by spaces to `width` characters, as `{:<width}` pads.
#[must_use]
pub fn left(width: usize, part: &dyn Part) -> Padded<'_> {
    Padded {
        part,
        width,
        right: false,
    }
}

/// `part`, after spaces to `width` characters, as `{:>width}` pads.
#[must_use]
pub fn right(width: usize, part: &dyn Part) -> Padded<'_> {
    Padded {
        part,
        width,
        right: true,
    }
}

impl Line {
    /// A template of this program's own with each bare `{}` filled by the next part.
    ///
    /// [`stdout_line!`](crate::stdout_line) checks at compile time that every hole is a bare `{}`
    /// and that there is one part for each. `{{` and `}}` are a brace.
    #[must_use]
    pub fn compose(template: &'static str, parts: &[Piece<'_>]) -> Self {
        let mut text = String::with_capacity(template.len() + 16 * parts.len());
        #[cfg(test)]
        let mut asked = Vec::new();
        let mut parts = parts.iter();
        let mut characters = template.chars().peekable();
        while let Some(character) = characters.next() {
            match (character, characters.peek()) {
                ('{', Some('{')) | ('}', Some('}')) => {
                    text.push(character);
                    characters.next();
                }
                ('{', Some('}')) => {
                    characters.next();
                    if let Some(part) = parts.next() {
                        written(&mut text, part);
                        #[cfg(test)]
                        asked_in(&mut asked, part);
                    }
                }
                _ => text.push(character),
            }
        }
        Self {
            text,
            #[cfg(test)]
            asked,
        }
    }

    /// The line's text, for a test in this crate to compare.
    #[cfg(test)]
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// How many times `planted` appears in the line beyond the asked content it holds.
    #[cfg(test)]
    pub(crate) fn unasked(&self, planted: &str) -> usize {
        let asked: usize = self
            .asked
            .iter()
            .map(|text| text.matches(planted).count())
            .sum();
        self.text.matches(planted).count().saturating_sub(asked)
    }
}

/// Appends one part of a line.
fn written(text: &mut String, piece: &Piece<'_>) {
    match piece {
        Piece::Plain(value) => {
            let _ = write!(text, "{value}");
        }
        Piece::Asked(asked) => text.push_str(&asked.text),
        Piece::Line(line) => text.push_str(&line.text),
        Piece::Padded { part, width, right } => {
            let mut inner = String::new();
            written(&mut inner, &part.piece());
            let spaces = " ".repeat(width.saturating_sub(inner.chars().count()));
            if *right {
                text.push_str(&spaces);
                text.push_str(&inner);
            } else {
                text.push_str(&inner);
                text.push_str(&spaces);
            }
        }
    }
}

/// Records the asked text a part holds, for a test.
#[cfg(test)]
fn asked_in(asked: &mut Vec<String>, piece: &Piece<'_>) {
    match piece {
        Piece::Plain(_) => {}
        Piece::Asked(content) => asked.push(content.text.clone()),
        Piece::Line(line) => asked.extend(line.asked.iter().cloned()),
        Piece::Padded { part, .. } => asked_in(asked, &part.piece()),
    }
}

/// A value a document holds. Anything in this crate can make one; only this module reads it.
pub struct Held {
    value: serde_json::Value,
    /// Where in the value asked content is, for a test: `""` for the value itself, a key, or `[n]`
    /// for the element of a list at `n`, joined with dots.
    #[cfg(test)]
    asked: std::collections::BTreeSet<String>,
}

impl Held {
    /// A value that holds no asked content.
    const fn plain(value: serde_json::Value) -> Self {
        Self {
            value,
            #[cfg(test)]
            asked: std::collections::BTreeSet::new(),
        }
    }
}

impl From<Shown> for Held {
    fn from(said: Shown) -> Self {
        Self::plain(serde_json::Value::String(said.into_string()))
    }
}

impl From<&'static str> for Held {
    fn from(words: &'static str) -> Self {
        Self::plain(serde_json::Value::String(words.to_owned()))
    }
}

impl From<Asked> for Held {
    fn from(asked: Asked) -> Self {
        Self {
            value: serde_json::Value::String(asked.text),
            #[cfg(test)]
            asked: std::iter::once(String::new()).collect(),
        }
    }
}

impl From<Line> for Held {
    fn from(line: Line) -> Self {
        // A line in a document is asked content where it stands when it holds some and the text a
        // test plants shows nowhere else in it, the check a line on its own is held to; a line
        // that shows it elsewhere is not, so the document's check names the place.
        #[cfg(test)]
        let asked = if !line.asked.is_empty() && line.unasked(crate::shown::marker::MARKER) == 0 {
            std::iter::once(String::new()).collect()
        } else {
            std::collections::BTreeSet::new()
        };
        Self {
            value: serde_json::Value::String(line.text),
            #[cfg(test)]
            asked,
        }
    }
}

impl From<Document> for Held {
    fn from(document: Document) -> Self {
        Self {
            value: serde_json::Value::Object(document.values),
            #[cfg(test)]
            asked: document.asked,
        }
    }
}

impl From<bool> for Held {
    fn from(switch: bool) -> Self {
        Self::plain(serde_json::Value::Bool(switch))
    }
}

impl From<u8> for Held {
    fn from(number: u8) -> Self {
        Self::plain(serde_json::Value::from(number))
    }
}

impl From<u16> for Held {
    fn from(number: u16) -> Self {
        Self::plain(serde_json::Value::from(number))
    }
}

impl From<u32> for Held {
    fn from(number: u32) -> Self {
        Self::plain(serde_json::Value::from(number))
    }
}

impl From<u64> for Held {
    fn from(number: u64) -> Self {
        Self::plain(serde_json::Value::from(number))
    }
}

impl From<usize> for Held {
    fn from(number: usize) -> Self {
        Self::plain(serde_json::Value::from(number))
    }
}

impl From<i32> for Held {
    fn from(number: i32) -> Self {
        Self::plain(serde_json::Value::from(number))
    }
}

impl From<i64> for Held {
    fn from(number: i64) -> Self {
        Self::plain(serde_json::Value::from(number))
    }
}

impl<T: Into<Held>> From<Option<T>> for Held {
    fn from(value: Option<T>) -> Self {
        value.map_or(Self::plain(serde_json::Value::Null), Into::into)
    }
}

impl<T: Into<Held>> From<Vec<T>> for Held {
    fn from(values: Vec<T>) -> Self {
        let held: Vec<Self> = values.into_iter().map(Into::into).collect();
        Self {
            #[cfg(test)]
            asked: held
                .iter()
                .enumerate()
                .flat_map(|(index, element)| {
                    element
                        .asked
                        .iter()
                        .map(move |path| joined(&format!("[{index}]"), path))
                })
                .collect(),
            value: serde_json::Value::Array(
                held.into_iter().map(|element| element.value).collect(),
            ),
        }
    }
}

/// A protocol value that holds no text that arrived: every text leaf in it is a word of a closed
/// set, an identifier or a digest by its type, and every other leaf a number or a switch.
///
/// Such a value is written as the protocol encodes it, which keeps a document's shape what a
/// script reading the protocol expects. A type is claimed closed only in this file, because the
/// claim is `claim::Claimed`, which nothing outside it can name; a test plants text in every leaf
/// of each claimed type's schema that could hold it and finds none, and another holds that test to
/// every claim written here. A type that holds text cannot be written as one:
///
/// ```compile_fail
/// let arrived = String::from("kr-marker-7c1e");
/// let _ = kr_cli::output::closed(&arrived);
/// ```
pub trait Closed: serde::Serialize + claim::Claimed {}

impl<T: serde::Serialize + claim::Claimed> Closed for T {}

/// The claim a type is [`Closed`], which only this file can make.
mod claim {
    /// A type this file claims closed.
    pub trait Claimed {}
}

/// A closed value, as the protocol encodes it.
#[must_use]
pub fn closed(value: &impl Closed) -> Held {
    Held::plain(serde_json::to_value(value).unwrap_or(serde_json::Value::Null))
}

/// A closed value as a line says it: the text the protocol encodes it as.
#[must_use]
pub fn closed_word(value: &impl Closed) -> Shown {
    crate::shown::closed_text(value)
}

impl<T: claim::Claimed> claim::Claimed for kr_protocol::scalars::Nullable<T> {}
impl<T: claim::Claimed> claim::Claimed for Vec<T> {}
impl<T: claim::Claimed + Ord> claim::Claimed for kr_protocol::scalars::CanonicalSet<T> {}
impl claim::Claimed for kr_protocol::scalars::U64 {}
impl claim::Claimed for kr_protocol::scalars::TimestampMs {}
impl claim::Claimed for kr_protocol::scalars::Digest256 {}
impl claim::Claimed for kr_protocol::ids::ActionId {}
impl claim::Claimed for kr_protocol::ids::AuthorityRevision {}
impl claim::Claimed for kr_protocol::ids::DeviceId {}
impl claim::Claimed for kr_protocol::ids::GrantId {}
impl claim::Claimed for kr_protocol::ids::SessionId {}
impl claim::Claimed for kr_protocol::privacy::PrivacyDisabled {}
impl claim::Claimed for kr_protocol::describe::DescriptionDownload {}
impl claim::Claimed for kr_protocol::describe::DescriptionPause {}
impl claim::Claimed for kr_protocol::describe::DescriptionState {}
impl claim::Claimed for kr_protocol::action::BarrierState {}
impl claim::Claimed for kr_protocol::receipt::ReceiptState {}
impl claim::Claimed for kr_protocol::pairing::DevicePublicKeys {}
impl claim::Claimed for kr_protocol::pairing::ProposedGrant {}
impl claim::Claimed for kr_protocol::invitation::PairingApproval {}
impl claim::Claimed for kr_protocol::ids::AttemptId {}
impl claim::Claimed for kr_protocol::ids::ConfirmationId {}
impl claim::Claimed for kr_protocol::ids::InvitationId {}
impl claim::Claimed for kr_protocol::scalars::KeyId {}
impl claim::Claimed for kr_protocol::ids::PairingEventSequence {}
impl claim::Claimed for kr_protocol::invitation::InviteGrantKind {}
impl claim::Claimed for kr_protocol::invitation::InviteModeKind {}
impl claim::Claimed for kr_protocol::pairing::ConfirmationChannel {}
impl claim::Claimed for kr_protocol::pairing::DevicePlatform {}
impl claim::Claimed for kr_protocol::pairing::PairingConsumedReason {}
impl claim::Claimed for kr_protocol::identity::EnvironmentAccess {}
impl claim::Claimed for kr_protocol::identity::EnvironmentPresence {}
impl claim::Claimed for kr_protocol::identity::ObservationSource {}
impl claim::Claimed for kr_protocol::local::LocalRole {}
impl claim::Claimed for kr_protocol::hello::ProtocolVersion {}
impl claim::Claimed for kr_protocol::catalogue::CatalogueBudgets {}
impl claim::Claimed for kr_protocol::catalogue::CatalogueKind {}
impl claim::Claimed for kr_protocol::catalogue::PluginGrantRequirement {}
impl claim::Claimed for kr_protocol::catalogue::PluginLeftOutReason {}
impl claim::Claimed for kr_protocol::changeset::ApplyOutcomeClass {}
impl claim::Claimed for kr_protocol::changeset::CaptureCount {}
impl claim::Claimed for kr_protocol::changeset::ContentOrigin {}
impl claim::Claimed for kr_protocol::changeset::DestinationClass {}
impl claim::Claimed for kr_protocol::changeset::EvidenceKind {}
impl claim::Claimed for kr_protocol::changeset::ExclusionReason {}
impl claim::Claimed for kr_protocol::changeset::MaterialisationPurpose {}
impl claim::Claimed for kr_protocol::changeset::PathClass {}
impl claim::Claimed for kr_protocol::changeset::PathProgressState {}
impl claim::Claimed for kr_protocol::changeset::SourceConsistency {}
impl claim::Claimed for kr_protocol::changeset::TestedSource {}
impl claim::Claimed for kr_protocol::changeset::TreeSummary {}
impl claim::Claimed for kr_protocol::changeset::VersionRef {}
impl claim::Claimed for kr_protocol::project::ContentClass {}
impl claim::Claimed for kr_protocol::ids::ChangeSetId {}
impl claim::Claimed for kr_protocol::ids::ChangeSetVersion {}
impl claim::Claimed for kr_protocol::ids::EnvironmentId {}
impl claim::Claimed for kr_protocol::ids::MaterialisationId {}
impl claim::Claimed for kr_protocol::ids::ProjectRepositoryId {}
impl claim::Claimed for kr_protocol::ids::RepositoryGeneration {}
impl claim::Claimed for kr_protocol::ids::WorkflowRunId {}
impl claim::Claimed for kr_protocol::ids::WorkspaceId {}
impl claim::Claimed for kr_protocol::project::ChangeKind {}
impl claim::Claimed for kr_protocol::project::DestinationState {}
impl claim::Claimed for kr_protocol::project::FilesystemIdentity {}
impl claim::Claimed for kr_protocol::project::InclusionClass {}
impl claim::Claimed for kr_protocol::project::InclusionPolicy {}
impl claim::Claimed for kr_protocol::project::IsolationMechanism {}
impl claim::Claimed for kr_protocol::project::OperationState {}
impl claim::Claimed for kr_protocol::project::PreviewCount {}
impl claim::Claimed for kr_protocol::project::ProjectOrigin {}
impl claim::Claimed for kr_protocol::project::ProjectState {}
impl claim::Claimed for kr_protocol::project::RemoteTransport {}
impl claim::Claimed for kr_protocol::project::RetainedKind {}
impl claim::Claimed for kr_protocol::project::WorkspaceKind {}
impl claim::Claimed for kr_protocol::project::WorkspaceState {}
impl claim::Claimed for kr_protocol::error::RetryCategory {}
impl claim::Claimed for kr_protocol::identity::ProcessStartSource {}

/// One `--json` document: keys of this program's own, each holding a [`Held`] value.
#[derive(Default)]
pub struct Document {
    values: serde_json::Map<String, serde_json::Value>,
    /// Where in the document asked content is, for a test.
    #[cfg(test)]
    asked: std::collections::BTreeSet<String>,
}

/// A path inside a document, `inner` below `outer`.
#[cfg(test)]
fn joined(outer: &str, inner: &str) -> String {
    match (outer.is_empty(), inner.is_empty()) {
        (_, true) => outer.to_owned(),
        (true, false) => inner.to_owned(),
        (false, false) if inner.starts_with('[') => format!("{outer}{inner}"),
        (false, false) => format!("{outer}.{inner}"),
    }
}

impl Document {
    /// An empty document.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// This document with `key` holding `value`.
    #[must_use]
    pub fn with(mut self, key: &'static str, value: impl Into<Held>) -> Self {
        self.set(key, value);
        self
    }

    /// Makes `key` hold `value`, replacing what it held.
    pub fn set(&mut self, key: &'static str, value: impl Into<Held>) {
        let held = value.into();
        #[cfg(test)]
        {
            self.asked.retain(|path| {
                path != key
                    && !path.starts_with(&format!("{key}."))
                    && !path.starts_with(&format!("{key}["))
            });
            self.asked
                .extend(held.asked.iter().map(|path| joined(key, path)));
        }
        self.values.insert(key.to_owned(), held.value);
    }

    /// Adds every key of `other`, replacing a key both hold.
    pub fn merge(&mut self, other: Self) {
        #[cfg(test)]
        {
            let keys = other.values.keys().cloned().collect::<Vec<_>>();
            self.asked.retain(|path| {
                !keys.iter().any(|key| {
                    path == key
                        || path.starts_with(&format!("{key}."))
                        || path.starts_with(&format!("{key}["))
                })
            });
            self.asked.extend(other.asked);
        }
        self.values.extend(other.values);
    }

    /// The document as JSON, for a test in this crate to read.
    #[cfg(test)]
    pub(crate) fn json(&self) -> serde_json::Value {
        serde_json::Value::Object(self.values.clone())
    }

    /// Where in the document asked content is, for a test.
    #[cfg(test)]
    pub(crate) fn asked(&self) -> &std::collections::BTreeSet<String> {
        &self.asked
    }
}

/// A `Plain` value as it says itself.
#[must_use]
pub fn said(value: &dyn Plain) -> Shown {
    Shown::compose("{}", &[value])
}

/// Writes one line on standard output.
pub fn say(line: &Shown) {
    println!("{line}");
}

/// Writes one composed line on standard output.
pub fn line(line: &Line) {
    println!("{}", line.text);
}

/// Writes composed lines on standard output, one after another.
pub fn lines(lines: &[Line]) {
    for each in lines {
        line(each);
    }
}

/// Writes one composed line on `writer`: the controlling terminal a command asks its person at,
/// opened as itself rather than as standard output, or the error stream a content export's preview
/// is printed on (`report::show_preview`, the one place that does).
///
/// # Errors
///
/// Returns the failure to write.
pub fn write_line(writer: &mut impl std::io::Write, line: &Line) -> std::io::Result<()> {
    writeln!(writer, "{}", line.text)
}

/// Writes a composed prompt on `writer`, with no end of line, for the answer to follow it.
///
/// # Errors
///
/// Returns the failure to write.
pub fn write_prompt(writer: &mut impl std::io::Write, prompt: &Line) -> std::io::Result<()> {
    write!(writer, "{}", prompt.text)
}

/// Writes one machine-readable document on standard output.
pub fn document(document: &Document) {
    println!(
        "{}",
        serde_json::to_string_pretty(&document.values).unwrap_or_else(|_| "{}".to_owned())
    );
}

/// The document a contact tool returns to the agent that called it, as the tool's structured
/// result.
#[must_use]
pub fn tool_result(document: Document) -> rmcp::model::CallToolResult {
    rmcp::model::CallToolResult::structured(serde_json::Value::Object(document.values))
}

/// The document a contact tool returns to the agent that called it when the call failed, as the
/// tool's structured error.
#[must_use]
pub fn tool_error(document: Document) -> rmcp::model::CallToolResult {
    rmcp::model::CallToolResult::structured_error(serde_json::Value::Object(document.values))
}

/// Whether standard output is a terminal.
#[must_use]
pub fn is_terminal() -> bool {
    use std::io::IsTerminal as _;

    std::io::stdout().is_terminal()
}

/// Standard output as a protocol's own stream: the tool server's and `kr bridge --stdio`'s. Nothing
/// else writes there while one of them runs.
#[must_use]
pub const fn protocol_stream() -> ProtocolStream {
    ProtocolStream(())
}

/// Standard output, held for a protocol that owns it.
pub struct ProtocolStream(());

impl ProtocolStream {
    /// The stream for a blocking writer.
    #[must_use]
    pub fn blocking(self) -> std::io::Stdout {
        std::io::stdout()
    }

    /// The stream for an asynchronous writer.
    #[must_use]
    pub fn asynchronous(self) -> tokio::io::Stdout {
        tokio::io::stdout()
    }
}

/// Standard output as the terminal the attach guard gives its modes and sequences back to.
#[must_use]
pub fn attached_terminal() -> std::io::Stdout {
    std::io::stdout()
}

#[cfg(test)]
pub(crate) mod planted;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shown::marker::MARKER;
    use kr_client::shown;

    /// A location keeps its scheme, host, port and path; an SCP-style one its host and path; a
    /// drive or a local path is a path. User information, a query and a fragment never show.
    #[test]
    fn a_location_is_said_without_user_information_query_or_fragment() {
        for (location, expected) in [
            (
                format!("https://{MARKER}:{MARKER}@proxy.example:8080/relay/?{MARKER}#{MARKER}"),
                "https://proxy.example:8080/relay/".to_owned(),
            ),
            (
                format!("ssh://{MARKER}@git.example/team/repository.git"),
                "ssh://git.example/team/repository.git".to_owned(),
            ),
            (
                format!("{MARKER}@git.example:team/repository.git"),
                "git.example:team/repository.git".to_owned(),
            ),
            (
                "git.example:team/repository.git".to_owned(),
                "git.example:team/repository.git".to_owned(),
            ),
            (
                "/srv/repositories/one".to_owned(),
                "/srv/repositories/one".to_owned(),
            ),
        ] {
            let asked = Asked::location(Request::Repositories, &location);
            assert_eq!(asked.text, expected, "{location}");
            assert_eq!(asked.request(), Request::Repositories);
        }
        // A drive is a local path, not a host.
        let drive = Asked::location(Request::Repositories, "C:/work/repository");
        assert!(drive.text.starts_with("C:"), "{}", drive.text);
        assert!(!drive.text.contains("C:work"), "{}", drive.text);
        // A file URL keeps its path and loses its query and fragment; a URL the parser reads
        // another way than it was written is said from its reading; text written as a URL that
        // does not parse, and SCP-style text that holds what a URL would carry or no host name,
        // keep nothing but their class and length.
        let withheld = |text: &str| format!("[location withheld, {} bytes]", text.len());
        for (location, expected) in [
            (
                format!("file:///tmp/catalogue?token={MARKER}#{MARKER}"),
                "file:///tmp/catalogue".to_owned(),
            ),
            (
                format!("https://someone:{MARKER}@relay.example:port/x"),
                withheld(&format!("https://someone:{MARKER}@relay.example:port/x")),
            ),
            (
                format!("https:someone:{MARKER}@relay.example:port/x?token={MARKER}#{MARKER}"),
                withheld(&format!(
                    "https:someone:{MARKER}@relay.example:port/x?token={MARKER}#{MARKER}"
                )),
            ),
            (
                format!("https:someone:{MARKER}@relay.example/x"),
                "https://relay.example/x".to_owned(),
            ),
            (
                "https:/example.com/repo.git".to_owned(),
                "https://example.com/repo.git".to_owned(),
            ),
            (
                format!("git.example:team/repository.git?token={MARKER}"),
                withheld(&format!("git.example:team/repository.git?token={MARKER}")),
            ),
            (
                format!("someone:{MARKER}@git.example:team"),
                withheld(&format!("someone:{MARKER}@git.example:team")),
            ),
            (
                format!("{MARKER} x:team/repository.git"),
                withheld(&format!("{MARKER} x:team/repository.git")),
            ),
            // Nothing to leave out: the text as it was written, or its host and its path.
            (
                "https://example.com:443/repo.git".to_owned(),
                "https://example.com:443/repo.git".to_owned(),
            ),
            (
                "[2001:db8::1]:team/repository.git".to_owned(),
                "[2001:db8::1]:team/repository.git".to_owned(),
            ),
            (
                format!("{MARKER}@[2001:db8::1]:team/repository.git"),
                "[2001:db8::1]:team/repository.git".to_owned(),
            ),
            (
                format!("{MARKER}@x:repository.git"),
                "x:repository.git".to_owned(),
            ),
            // Text no reading takes, which is how a location written the wrong way would look.
            (
                format!("{MARKER}@git.example/team:repository?token={MARKER}#{MARKER}"),
                withheld(&format!(
                    "{MARKER}@git.example/team:repository?token={MARKER}#{MARKER}"
                )),
            ),
            (
                format!("/srv/{MARKER}@repository"),
                withheld(&format!("/srv/{MARKER}@repository")),
            ),
            (
                format!("repository#{MARKER}"),
                withheld(&format!("repository#{MARKER}")),
            ),
        ] {
            let asked = Asked::location(Request::Plugins, &location);
            assert_eq!(asked.text, expected, "{location}");
            assert!(!asked.text.contains(MARKER), "{location}");
        }
    }

    /// A path this program holds is spelled with the platform's own separator throughout, however
    /// it was joined; a path the host sent is said as it arrived, a repository's `/` and a Windows
    /// host's `\` alike, on every platform.
    #[test]
    fn a_path_is_spelled_with_one_separator_unless_the_host_sent_it() {
        let separator = std::path::MAIN_SEPARATOR;
        let asked = Asked::path(
            Request::ShellFiles,
            Path::new("/home").join("person/.zshrc"),
        );
        assert_eq!(
            asked.text,
            format!("{separator}home{separator}person{separator}.zshrc")
        );
        assert_eq!(Asked::text(Request::Question, MARKER).text, MARKER);
        for sent in [
            "src/output/lines.rs",
            r"C:\Users\someone\repository",
            "/usr/bin/zsh",
        ] {
            assert_eq!(Asked::text(Request::Diff, sent).text, sent);
        }
    }

    /// A configured location is said piece by piece, at the host's own `, ` join, each by its
    /// shape: a URL as its scheme, host, port and path, never the user information, the query or
    /// the fragment written with it; a socket address in its parsed form and a host name as
    /// itself; anything else as its class and its length.
    #[test]
    fn a_configured_location_says_each_piece_by_its_shape_and_never_its_credentials() {
        use kr_protocol::hostinfo::export::ContentClass;

        let proxy = configured(
            ContentClass::Location,
            &format!("http://someone:{MARKER}@proxy.example:3128/tunnel?token={MARKER}#{MARKER}"),
        );
        assert_eq!(proxy.text, "http://proxy.example:3128/tunnel");
        assert!(!proxy.text.contains(MARKER), "{}", proxy.text);
        assert!(!proxy.text.contains("someone"), "{}", proxy.text);
        assert!(!proxy.text.contains("token"), "{}", proxy.text);
        assert_eq!(proxy.request(), Request::Diagnostics);

        let relays = configured(
            ContentClass::Location,
            "https://relay-one.example/, https://relay-two.example:8443",
        );
        assert_eq!(
            relays.text,
            "https://relay-one.example/, https://relay-two.example:8443"
        );

        let unreadable = format!("{MARKER} is not a location");
        let shapes = configured(
            ContentClass::Location,
            &format!("127.0.0.1:4433, [::1]:4433, relay.example, {unreadable}"),
        );
        assert_eq!(
            shapes.text,
            format!(
                "127.0.0.1:4433, [::1]:4433, relay.example, [location withheld, {} bytes]",
                unreadable.len()
            )
        );
    }

    /// A configured path is said piece by piece through the host-path rule, and a term, a number
    /// and anything else by the host's own export terms.
    #[test]
    fn a_configured_value_of_any_other_class_is_said_on_the_host_s_terms() {
        use kr_protocol::hostinfo::export::ContentClass;

        let pieces = ["/Users/someone/kalareach", &format!("/opt/{MARKER}/state")];
        let paths = configured(ContentClass::Path, &pieces.join(", "));
        assert_eq!(
            paths.text,
            pieces
                .iter()
                .map(|piece| shown::Shown::host_path(Path::new(piece)).into_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        assert!(!paths.text.contains(MARKER), "{}", paths.text);

        assert_eq!(configured(ContentClass::Number, "42").text, "42");
        assert_eq!(
            configured(ContentClass::Term, "session_limit").text,
            "session_limit"
        );
        assert_eq!(
            configured(ContentClass::Term, MARKER).text,
            format!("[name withheld, {} bytes]", MARKER.len())
        );
        assert_eq!(
            configured(ContentClass::Message, MARKER).text,
            format!("[message withheld, {} bytes]", MARKER.len())
        );
    }

    /// A line fills its holes in order, pads a part to its width and keeps a doubled brace; content
    /// the person asked for is written as it arrived.
    #[test]
    fn a_line_fills_its_holes_in_order_and_pads() {
        let asked = Asked::text(Request::Question, MARKER);
        let line = crate::stdout_line!(
            "{}|{}|{} {{kept}} {}",
            left(6, &3_u64),
            right(6, &shown!("{}", 7_u64)),
            asked,
            "words"
        );
        assert_eq!(
            line.text(),
            format!("3     |     7|{MARKER} {{kept}} words")
        );
        assert_eq!(
            crate::stdout_line!("nothing to fill").text(),
            "nothing to fill"
        );
    }

    /// A document holds numbers as numbers, switches as switches, an absent value as null, and
    /// words, `Shown` values and asked content as strings, nested as they were built.
    #[test]
    fn a_document_holds_each_value_in_its_own_json_form() {
        let mut document = Document::new()
            .with("count", 3_u64)
            .with("signed", -2_i64)
            .with("ok", true)
            .with("state", "live")
            .with("said", shown!("{} of {}", 1_u64, 2_u64))
            .with("asked", Asked::text(Request::Question, MARKER))
            .with("absent", None::<Shown>)
            .with("present", Some(4_u32))
            .with(
                "inner",
                Document::new().with("list", vec![Shown::said("a"), Shown::said("b")]),
            );
        document.merge(Document::new().with("ok", false).with("more", 1_u8));
        assert_eq!(
            document.json(),
            serde_json::json!({
                "count": 3,
                "signed": -2,
                "ok": false,
                "state": "live",
                "said": "1 of 2",
                "asked": MARKER,
                "absent": null,
                "present": 4,
                "inner": { "list": ["a", "b"] },
                "more": 1,
            })
        );
    }

    /// The harness plants the marker in every leaf of free text, and its checks pass the marker
    /// where asked content holds it and name it anywhere else.
    #[test]
    fn the_checks_pass_asked_content_and_find_the_marker_elsewhere() {
        use kr_protocol::hostinfo::export::ContentClass;

        let resources = planted::planted::<kr_protocol::session::SurvivingResource>();
        assert!(!resources.is_empty());
        for resource in &resources {
            assert!(resource.kind.contains(MARKER), "{}", resource.kind);
            assert!(resource.detail.contains(MARKER), "{}", resource.detail);
            let detail = crate::shown::withheld(ContentClass::Message, &resource.detail);
            let document = Document::new()
                .with("kind", Asked::text(Request::Sessions, &resource.kind))
                .with("detail", detail.clone())
                .with(
                    "inner",
                    Document::new()
                        .with("list", vec![Asked::text(Request::Sessions, &resource.kind)]),
                );
            assert_eq!(
                planted::only_asked("a planted resource", &document),
                ["inner.list[]", "kind"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            );
            planted::only_asked_lines(
                "a planted resource",
                &[crate::stdout_line!(
                    "{} {}",
                    Asked::text(Request::Sessions, &resource.kind),
                    detail
                )],
            );
        }
    }

    /// The negative control: the marker in a field that holds no asked content fails the check.
    #[test]
    #[should_panic(expected = "holds no asked content")]
    fn the_marker_outside_asked_content_fails_the_document_check() {
        let document = Document::new()
            .with("asked", Asked::text(Request::Sessions, MARKER))
            .with("leaked", Shown::said(MARKER));
        let _ = planted::only_asked("a planted leak", &document);
    }

    /// The negative control for lines: the marker outside asked content fails the check.
    #[test]
    #[should_panic(expected = "outside asked content")]
    fn the_marker_outside_asked_content_fails_the_line_check() {
        planted::only_asked_lines(
            "a planted leak",
            &[crate::stdout_line!(
                "{} {}",
                Asked::text(Request::Sessions, MARKER),
                Shown::said(MARKER)
            )],
        );
    }

    /// A composed line in a document is its text, and asked content where it stands when it holds
    /// some; a line of this program's words alone asks for nothing.
    #[test]
    fn a_line_in_a_document_is_asked_content_only_where_it_holds_some() {
        let document = Document::new().with(
            "notes",
            vec![
                crate::stdout_line!("applies {}", Asked::text(Request::Startup, MARKER)),
                crate::stdout_line!("process {} keeps serving", 7_u32),
            ],
        );
        assert_eq!(
            document.json(),
            serde_json::json!({
                "notes": [format!("applies {MARKER}"), "process 7 keeps serving"],
            })
        );
        assert_eq!(
            planted::only_asked("a line in a document", &document),
            std::iter::once("notes[]".to_owned()).collect()
        );
        assert_eq!(document.asked().iter().collect::<Vec<_>>(), ["notes[0]"]);
    }

    /// The negative control for a line in a document: asked content in the line does not let the
    /// marker show in its other parts.
    #[test]
    #[should_panic(expected = "holds no asked content")]
    fn the_marker_outside_a_lines_asked_content_fails_the_document_check() {
        let document = Document::new().with(
            "notes",
            vec![crate::stdout_line!(
                "{} {}",
                Asked::text(Request::Startup, MARKER),
                Shown::said(MARKER)
            )],
        );
        let _ = planted::only_asked("a planted leak in a line", &document);
    }

    /// The negative control for lists: asked content in one element does not let the marker show
    /// in the same field of another.
    #[test]
    #[should_panic(expected = "holds no asked content")]
    fn the_marker_in_an_element_that_asked_for_nothing_fails_the_document_check() {
        let document = Document::new().with(
            "items",
            vec![
                Document::new().with("detail", Asked::text(Request::Sessions, MARKER)),
                Document::new().with("detail", Shown::said(MARKER)),
            ],
        );
        let _ = planted::only_asked("a planted leak in a list", &document);
    }

    /// The negative control for the encoding: a reducer's words stand only in place of a string, so
    /// a value replaced whole by a bracketed string fails the check.
    #[test]
    #[should_panic(expected = "neither asked content")]
    fn a_value_replaced_whole_fails_the_encoding_check() {
        let encoded = serde_json::json!({ "nested": { "text": MARKER } });
        let document = Document::new().with("nested", Shown::said("[withheld]"));
        planted::differs_only_where_said("a value replaced whole", &document, &encoded, &[]);
    }

    /// A choice inside one alternative of another is built in each of its own alternatives, not
    /// only in the one its parent's position would give it.
    #[test]
    fn a_choice_inside_an_alternative_is_built_in_each_of_its_own() {
        #[derive(
            Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, schemars::JsonSchema,
        )]
        #[serde(rename_all = "snake_case")]
        enum Reason {
            First,
            Second,
            Third,
            Fourth,
        }
        #[derive(serde::Deserialize, schemars::JsonSchema)]
        #[serde(tag = "state", rename_all = "snake_case")]
        enum Status {
            Open { count: u64 },
            Waiting { since: u64 },
            Consumed { reason: Reason },
        }
        let mut reasons = std::collections::BTreeSet::new();
        let mut states = 0_usize;
        for status in planted::planted::<Status>() {
            match status {
                Status::Open { count } | Status::Waiting { since: count } => {
                    states += usize::from(count > 0);
                }
                Status::Consumed { reason } => {
                    reasons.insert(reason);
                }
            }
        }
        assert!(states >= 2, "each other state is built too");
        assert_eq!(
            reasons.len(),
            4,
            "every reason is built inside the one state that has one"
        );
    }

    /// Each type claimed closed holds no text that arrived: the marker cannot be planted in it.
    #[test]
    fn every_type_claimed_closed_holds_no_text() {
        use planted::assert_closed;

        assert_closed::<kr_protocol::scalars::U64>();
        assert_closed::<kr_protocol::scalars::TimestampMs>();
        assert_closed::<kr_protocol::scalars::Digest256>();
        assert_closed::<kr_protocol::ids::ActionId>();
        assert_closed::<kr_protocol::ids::AuthorityRevision>();
        assert_closed::<kr_protocol::ids::DeviceId>();
        assert_closed::<kr_protocol::ids::GrantId>();
        assert_closed::<kr_protocol::ids::SessionId>();
        assert_closed::<kr_protocol::action::BarrierState>();
        assert_closed::<kr_protocol::receipt::ReceiptState>();
        assert_closed::<kr_protocol::pairing::DevicePublicKeys>();
        assert_closed::<kr_protocol::pairing::ProposedGrant>();
        assert_closed::<kr_protocol::invitation::PairingApproval>();
        assert_closed::<kr_protocol::ids::AttemptId>();
        assert_closed::<kr_protocol::ids::ConfirmationId>();
        assert_closed::<kr_protocol::ids::InvitationId>();
        assert_closed::<kr_protocol::scalars::KeyId>();
        assert_closed::<kr_protocol::ids::PairingEventSequence>();
        assert_closed::<kr_protocol::invitation::InviteGrantKind>();
        assert_closed::<kr_protocol::invitation::InviteModeKind>();
        assert_closed::<kr_protocol::pairing::ConfirmationChannel>();
        assert_closed::<kr_protocol::pairing::DevicePlatform>();
        assert_closed::<kr_protocol::pairing::PairingConsumedReason>();
        assert_closed::<kr_protocol::identity::EnvironmentAccess>();
        assert_closed::<kr_protocol::identity::EnvironmentPresence>();
        assert_closed::<kr_protocol::identity::ObservationSource>();
        assert_closed::<kr_protocol::local::LocalRole>();
        assert_closed::<kr_protocol::hello::ProtocolVersion>();
        assert_closed::<kr_protocol::catalogue::CatalogueBudgets>();
        assert_closed::<kr_protocol::catalogue::CatalogueKind>();
        assert_closed::<kr_protocol::catalogue::PluginGrantRequirement>();
        assert_closed::<kr_protocol::catalogue::PluginLeftOutReason>();
        assert_closed::<kr_protocol::changeset::ApplyOutcomeClass>();
        assert_closed::<kr_protocol::changeset::CaptureCount>();
        assert_closed::<kr_protocol::changeset::ContentOrigin>();
        assert_closed::<kr_protocol::changeset::DestinationClass>();
        assert_closed::<kr_protocol::changeset::EvidenceKind>();
        assert_closed::<kr_protocol::changeset::ExclusionReason>();
        assert_closed::<kr_protocol::changeset::MaterialisationPurpose>();
        assert_closed::<kr_protocol::changeset::PathClass>();
        assert_closed::<kr_protocol::changeset::PathProgressState>();
        assert_closed::<kr_protocol::changeset::SourceConsistency>();
        assert_closed::<kr_protocol::changeset::TestedSource>();
        assert_closed::<kr_protocol::changeset::TreeSummary>();
        assert_closed::<kr_protocol::changeset::VersionRef>();
        assert_closed::<kr_protocol::project::ContentClass>();
        assert_closed::<kr_protocol::ids::ChangeSetId>();
        assert_closed::<kr_protocol::ids::ChangeSetVersion>();
        assert_closed::<kr_protocol::ids::EnvironmentId>();
        assert_closed::<kr_protocol::ids::MaterialisationId>();
        assert_closed::<kr_protocol::ids::ProjectRepositoryId>();
        assert_closed::<kr_protocol::ids::RepositoryGeneration>();
        assert_closed::<kr_protocol::ids::WorkflowRunId>();
        assert_closed::<kr_protocol::ids::WorkspaceId>();
        assert_closed::<kr_protocol::project::ChangeKind>();
        assert_closed::<kr_protocol::project::DestinationState>();
        assert_closed::<kr_protocol::project::FilesystemIdentity>();
        assert_closed::<kr_protocol::project::InclusionClass>();
        assert_closed::<kr_protocol::project::InclusionPolicy>();
        assert_closed::<kr_protocol::project::IsolationMechanism>();
        assert_closed::<kr_protocol::project::OperationState>();
        assert_closed::<kr_protocol::project::PreviewCount>();
        assert_closed::<kr_protocol::project::ProjectOrigin>();
        assert_closed::<kr_protocol::project::ProjectState>();
        assert_closed::<kr_protocol::project::RemoteTransport>();
        assert_closed::<kr_protocol::project::RetainedKind>();
        assert_closed::<kr_protocol::project::WorkspaceKind>();
        assert_closed::<kr_protocol::project::WorkspaceState>();
        assert_closed::<kr_protocol::error::RetryCategory>();
        assert_closed::<kr_protocol::identity::ProcessStartSource>();
        assert_closed::<kr_protocol::privacy::PrivacyDisabled>();
        assert_closed::<kr_protocol::describe::DescriptionDownload>();
        assert_closed::<kr_protocol::describe::DescriptionPause>();
        assert_closed::<kr_protocol::describe::DescriptionState>();
    }

    /// Every type this file claims closed is one the planted test above checks: the claims and the
    /// checks are read out of this file's own text and must name the same types.
    #[test]
    fn every_claim_is_checked() {
        let source = include_str!("output.rs");
        let named = |prefix: &str, suffix: &str| {
            source
                .lines()
                .filter_map(|line| line.trim().strip_prefix(prefix)?.strip_suffix(suffix))
                .map(str::to_owned)
                .collect::<std::collections::BTreeSet<_>>()
        };
        let claimed = named("impl claim::Claimed for ", " {}");
        let checked = named("assert_closed::<", ">();");
        assert!(claimed.len() > 60, "{claimed:?}");
        assert_eq!(
            claimed, checked,
            "a claim with no check, or a check with no claim"
        );
    }

    /// The negative control: a type with a leaf of free text fails the claim's check.
    #[test]
    #[should_panic(expected = "is claimed closed and holds text")]
    fn a_type_with_free_text_fails_the_closed_check() {
        planted::assert_closed::<kr_protocol::session::SurvivingResource>();
    }

    /// A tool's structured result is the document, and nothing else.
    #[test]
    fn a_tool_result_carries_the_document() {
        let result = tool_result(Document::new().with("state", "answered"));
        assert_eq!(
            result.structured_content,
            Some(serde_json::json!({ "state": "answered" }))
        );
    }
}
