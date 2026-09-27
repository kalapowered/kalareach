//! What this program writes on standard output, and the only way anything is written there.
//!
//! Standard output is read by a person at a terminal somebody may be sharing and by scripts that
//! keep what they read, so it follows the rule a diagnostic follows ([`kr_client::shown`]), with one
//! addition: content the person asked this command for is shown to them, marked as such.
//!
//! * [`say`] writes one [`Shown`]: this program's words, `Plain` values, and what a reducer or a
//!   door decided may be said.
//! * [`line`] writes one [`Line`], composed ([`stdout_line!`](crate::stdout_line)) from a template
//!   of this program's own and parts that are each `Plain` or [`Asked`].
//! * [`document`] writes one `--json` [`Document`], built from `Shown`, numbers, switches, `Asked`,
//!   documents and lists of them. There is no conversion into one from a string or a JSON value.
//!
//! [`Asked`] is content the person asked to read: a question's text, a repository's path, the name
//! a paired device gave itself. Each names the [`Request`] that asked for it. It never becomes a
//! `Shown` or a `Plain` value, so it cannot reach standard error, a failure or a `Debug`.
//!
//! Three commands own standard output for a protocol or a terminal rather than for lines: the tool
//! server, `kr bridge --stdio` and the attach guard. [`protocol_stream`] and [`terminal`] are their
//! handles. The source test holds every other use of standard output to this module.

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
    /// What `kr doctor` was asked to diagnose: a capability's resolved executable and each
    /// effective configuration value.
    Diagnostics,
}

/// Content the person asked to read.
///
/// It has no `Display` and no `Debug`, and nothing turns it into a [`Shown`]: this module writes it,
/// into a line or a document on standard output, and nothing else reads it.
pub struct Asked {
    request: Request,
    text: String,
}

impl Asked {
    /// Text as it arrived.
    #[must_use]
    pub fn text(request: Request, text: &str) -> Self {
        Self {
            request,
            text: text.to_owned(),
        }
    }

    /// A path, spelled as this program spells every path: the platform's own separator throughout.
    #[must_use]
    pub fn path(request: Request, path: impl AsRef<Path>) -> Self {
        Self {
            request,
            text: kr_client::shown::spelled(path.as_ref()),
        }
    }

    /// A location: a URL as its scheme, host, port and path; an SCP-style location
    /// (`user@host:path`) as its host and path; anything else as a local path. User information, a
    /// query and a fragment are never kept.
    #[must_use]
    pub fn location(request: Request, location: &str) -> Self {
        if let Some(located) = kr_client::shown::located(location) {
            return Self {
                request,
                text: located,
            };
        }
        match scp(location) {
            Some((host, path)) => Self {
                request,
                text: format!("{host}:{path}"),
            },
            None => Self::path(request, location),
        }
    }

    /// Why it is shown.
    #[must_use]
    pub const fn request(&self) -> Request {
        self.request
    }
}

/// The host and the path of an SCP-style location, `[user@]host:path`: a colon before any slash,
/// and a host longer than one letter, which would be a drive.
fn scp(location: &str) -> Option<(&str, &str)> {
    let (front, path) = location.split_once(':')?;
    if front.contains(['/', '\\']) {
        return None;
    }
    let host = front.rsplit_once('@').map_or(front, |(_, host)| host);
    (host.chars().count() > 1).then_some((host, path))
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

/// One line of standard output: a template of this program's own, filled with `Plain` values and
/// content the person asked to read. It never becomes a [`Shown`] or a `Plain` value.
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
        Piece::Padded { part, .. } => asked_in(asked, &part.piece()),
    }
}

/// A value a document holds. Anything in this crate can make one; only this module reads it.
pub struct Held {
    value: serde_json::Value,
    /// Where in the value asked content is, for a test: `""` for the value itself, a key, or `[]`
    /// for every element of a list, joined with dots.
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
        #[cfg(test)]
        let mut asked = std::collections::BTreeSet::new();
        let values = values
            .into_iter()
            .map(|value| {
                let held = value.into();
                #[cfg(test)]
                asked.extend(held.asked.iter().map(|path| joined("[]", path)));
                held.value
            })
            .collect();
        Self {
            value: serde_json::Value::Array(values),
            #[cfg(test)]
            asked,
        }
    }
}

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
pub fn terminal() -> std::io::Stdout {
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
        let separator = std::path::MAIN_SEPARATOR;
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
                format!("{separator}srv{separator}repositories{separator}one"),
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
    }

    /// A path is spelled with the platform's own separator throughout, however it was written.
    #[test]
    fn a_path_is_spelled_with_one_separator() {
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
