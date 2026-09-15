//! The private, pinned `xterm-256color` database and the XTGETTCAP responder.
//!
//! Section 8 requires the managed environment to supply its own `xterm-256color` database,
//! consistent with the virtual profile and with the responder that answers capability queries. One
//! database serves both here, so an application that reads a capability and an application that
//! asks for it over the wire get the same answer.
//!
//! The database is also the input to the class-coverage check: every capability it advertises is
//! lexed and must land in a supported class. A capability whose sequence would be consumed with a
//! diagnostic is not advertised, which is why this database is not the stock entry.

mod data;
mod expand;

pub use expand::{Param, expand};

use crate::class::SequenceClass;
use crate::event::Event;
use crate::lexer::Lexer;

/// Whether a string capability is something the terminal reads, something the keyboard sends, or
/// plain data.
///
/// Only the capabilities the terminal reads can be classified, because only those appear in the
/// application's output stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// A sequence the application writes to the terminal.
    Output,
    /// A sequence the keyboard sends to the application.
    Input,
    /// The documented shape of a reply, not a sequence anything emits verbatim.
    Report,
    /// A data table rather than a sequence.
    Data,
}

/// One string capability of the pinned database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringCapability {
    /// The terminfo capability name.
    pub name: &'static str,
    /// The capability value, with padding directives removed and escapes decoded.
    pub value: &'static str,
    /// One representative parameter set, which the coverage check expands `value` with.
    pub arguments: &'static [Param],
    /// What kind of capability this is.
    pub direction: Direction,
}

/// The terminal name the database describes.
pub const TERMINAL_NAME: &str = "xterm-256color";

/// Every boolean capability the database advertises.
#[must_use]
pub fn booleans() -> &'static [&'static str] {
    data::BOOLEANS
}

/// Every numeric capability the database advertises.
#[must_use]
pub fn numbers() -> &'static [(&'static str, i32)] {
    data::NUMBERS
}

/// Every string capability the database advertises.
#[must_use]
pub fn strings() -> &'static [StringCapability] {
    data::STRINGS
}

/// A capability value in the form an XTGETTCAP reply carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityValue {
    /// A boolean capability, reported as `1`.
    Boolean,
    /// A numeric capability, reported as its decimal text.
    Number(i32),
    /// A string capability, reported as its bytes.
    Text(&'static str),
    /// The terminal name, which `TN` asks for.
    Name,
}

impl CapabilityValue {
    /// The bytes the reply hex-encodes.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            Self::Boolean => b"1".to_vec(),
            Self::Number(value) => value.to_string().into_bytes(),
            Self::Text(text) => text.as_bytes().to_vec(),
            Self::Name => TERMINAL_NAME.as_bytes().to_vec(),
        }
    }
}

/// Looks a capability up by name.
///
/// `TN` is the one special case: it is not a terminfo capability but the terminal's name, and
/// applications ask for it first to find out what they are talking to.
#[must_use]
pub fn lookup(name: &str) -> Option<CapabilityValue> {
    if name == "TN" {
        return Some(CapabilityValue::Name);
    }
    if data::BOOLEANS.contains(&name) {
        return Some(CapabilityValue::Boolean);
    }
    if let Some((_, value)) = data::NUMBERS.iter().find(|(n, _)| *n == name) {
        return Some(CapabilityValue::Number(*value));
    }
    data::STRINGS
        .iter()
        .find(|cap| cap.name == name)
        .map(|cap| CapabilityValue::Text(cap.value))
}

/// Encodes bytes as the uppercase hex an XTGETTCAP reply uses.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(
            char::from_digit(u32::from(byte >> 4), 16)
                .unwrap_or('0')
                .to_ascii_uppercase(),
        );
        out.push(
            char::from_digit(u32::from(byte & 0x0f), 16)
                .unwrap_or('0')
                .to_ascii_uppercase(),
        );
    }
    out
}

/// Decodes the hex-encoded capability names an XTGETTCAP request carries.
///
/// Returns `None` when the request is not valid hex, which the caller reports as a failed query
/// rather than guessing at a name.
#[must_use]
pub fn from_hex(text: &[u8]) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.chunks_exact(2) {
        let hi = char::from(pair[0]).to_digit(16)?;
        let lo = char::from(pair[1]).to_digit(16)?;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "two hex digits are at most 0xff"
        )]
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// The maximum number of capability names one request may ask about.
///
/// The reply for each name is a separate bounded record, and the lane bounds the total, but the
/// request itself is bounded here so a single query cannot make the broker build hundreds of
/// replies.
pub const MAX_REQUEST_NAMES: usize = 32;

/// The longest capability name the responder will name back.
///
/// Terminfo names are short. A longer one cannot match anything, and echoing it would let an
/// application choose how many bytes the trusted lane carries.
pub const MAX_REQUEST_NAME_BYTES: usize = 32;

/// One reply to one requested capability name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityReply {
    /// The name the reply is about, as the database or the request spells it.
    pub name: String,
    /// The exact reply bytes.
    pub bytes: Vec<u8>,
}

/// Builds the replies to one XTGETTCAP request.
///
/// Each name gets its own reply: `DCS 1 + r name=value ST` when the database has it, and
/// `DCS 0 + r name ST` when it does not.
///
/// A request names capabilities in hex, and the responder repeats the name. A name that is not
/// valid hex, or is longer than a capability name can be, is answered with the bare failure reply
/// rather than repeated: an application must not be able to choose the bytes that travel on the
/// trusted lane.
#[must_use]
pub fn xtgettcap_replies(payload: &[u8]) -> Vec<CapabilityReply> {
    payload
        .split(|byte| *byte == b';')
        .take(MAX_REQUEST_NAMES)
        .map(|encoded| {
            let Some(name) = validated_name(encoded) else {
                return CapabilityReply {
                    name: String::new(),
                    bytes: bare_failure_reply(),
                };
            };
            match lookup(&name) {
                Some(value) => CapabilityReply {
                    bytes: success_reply(&name, &value.bytes()),
                    name,
                },
                None => CapabilityReply {
                    bytes: failure_reply(&name),
                    name,
                },
            }
        })
        .collect()
}

/// Decodes a requested name, refusing anything a capability name could not be.
fn validated_name(encoded: &[u8]) -> Option<String> {
    if encoded.len() > MAX_REQUEST_NAME_BYTES * 2 {
        return None;
    }
    let decoded = from_hex(encoded)?;
    let name = String::from_utf8(decoded).ok()?;
    let printable = !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b';' && byte != b'=');
    printable.then_some(name)
}

fn success_reply(name: &str, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"\x1bP1+r");
    out.extend_from_slice(to_hex(name.as_bytes()).as_bytes());
    out.push(b'=');
    out.extend_from_slice(to_hex(value).as_bytes());
    out.extend_from_slice(b"\x1b\\");
    out
}

fn failure_reply(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"\x1bP0+r");
    out.extend_from_slice(to_hex(name.as_bytes()).as_bytes());
    out.extend_from_slice(b"\x1b\\");
    out
}

fn bare_failure_reply() -> Vec<u8> {
    b"\x1bP0+r\x1b\\".to_vec()
}

/// What the class-coverage check found for one capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    /// The capability name.
    pub name: &'static str,
    /// What kind of capability it is.
    pub direction: Direction,
    /// The bytes its own value produced for the representative arguments.
    pub expansion: Vec<u8>,
    /// The classes its expansion produced, in order.
    pub classes: Vec<SequenceClass>,
    /// Whether this check examined the capability at all.
    pub checked: bool,
    /// Whether the policy layer refused what the expansion asked for.
    pub refused: bool,
    /// Whether the capability lexes into supported classes and actions the canonical grid knows.
    pub supported: bool,
}

/// Lexes every advertised output capability and reports what the engine does with it.
///
/// A capability is covered when its expansion produces at least one event, no event is `X`, and the
/// canonical grid recognises every action the approved events adapt to. The second half is what
/// makes this a check rather than a formality: a capability can lex into a perfectly ordinary
/// control sequence that the grid then does not understand, and advertising that is the same
/// inconsistency as advertising an `X`.
///
/// A capability the terminal never reads is not classified here. An input capability is a key
/// encoding and a report capability is the documented shape of a reply, and neither appears in the
/// application's output stream; `checked` says which entries this check actually examined.
#[must_use]
pub fn coverage() -> Vec<Coverage> {
    data::STRINGS
        .iter()
        .map(|cap| {
            if cap.direction != Direction::Output {
                return Coverage {
                    name: cap.name,
                    direction: cap.direction,
                    expansion: Vec::new(),
                    classes: Vec::new(),
                    checked: false,
                    refused: false,
                    supported: true,
                };
            }
            let expansion = expand::expand(cap.value, cap.arguments);
            let mut lexer = Lexer::new();
            let mut events: Vec<Event> = Vec::new();
            lexer.feed(&expansion, &mut events);
            lexer.close(&mut events);
            let classes: Vec<SequenceClass> = events.iter().map(|event| event.class).collect();
            let context = crate::adapter::AdaptContext { rows: 24, cols: 80 };
            let recognised = events
                .iter()
                .all(|event| !crate::adapter::adapt(event, context).unrecognised);
            // Recognising a sequence is not the same as acting on it. A capability whose own
            // representative arguments the policy layer refuses is advertising something this
            // profile will not do, which is the same inconsistency as advertising an `X`.
            let policy = crate::policy::Policy::DEFAULT;
            let refused = events
                .iter()
                .any(|event| policy.decide(event).refusal.is_some());
            let supported = !classes.is_empty()
                && !classes.contains(&SequenceClass::Extension)
                && recognised
                && !refused;
            Coverage {
                name: cap.name,
                direction: cap.direction,
                expansion,
                classes,
                checked: true,
                refused,
                supported,
            }
        })
        .collect()
}
