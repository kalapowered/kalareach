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
    /// The value expanded for one representative parameter set. Empty for a non-output capability.
    pub expansion: &'static str,
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

/// Builds the replies to one XTGETTCAP request.
///
/// Each name gets its own reply: `DCS 1 + r name=value ST` when the database has it, and
/// `DCS 0 + r name ST` when it does not. A name that is not valid hex gets the failure reply for
/// the bytes as they arrived.
#[must_use]
pub fn xtgettcap_replies(payload: &[u8]) -> Vec<Vec<u8>> {
    payload
        .split(|byte| *byte == b';')
        .take(MAX_REQUEST_NAMES)
        .map(|encoded| {
            let Some(decoded) = from_hex(encoded) else {
                return failure_reply(encoded);
            };
            let Ok(name) = core::str::from_utf8(&decoded) else {
                return failure_reply(encoded);
            };
            match lookup(name) {
                Some(value) => success_reply(name, &value.bytes()),
                None => failure_reply(encoded),
            }
        })
        .collect()
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

fn failure_reply(encoded_name: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"\x1bP0+r");
    out.extend_from_slice(encoded_name);
    out.extend_from_slice(b"\x1b\\");
    out
}

/// What the class-coverage check found for one capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    /// The capability name.
    pub name: &'static str,
    /// What kind of capability it is.
    pub direction: Direction,
    /// The classes its expansion produced, in order.
    pub classes: Vec<SequenceClass>,
    /// Whether every class is one the profile supports.
    pub supported: bool,
}

/// Lexes every advertised output capability and reports the classes it produces.
///
/// A capability is covered when its expansion produces at least one event and no event is `X`. An
/// `X` here means the database advertises something the profile would consume with a diagnostic,
/// which is exactly the inconsistency section 8 forbids.
#[must_use]
pub fn coverage() -> Vec<Coverage> {
    data::STRINGS
        .iter()
        .map(|cap| {
            if cap.direction != Direction::Output {
                return Coverage {
                    name: cap.name,
                    direction: cap.direction,
                    classes: Vec::new(),
                    supported: true,
                };
            }
            let mut lexer = Lexer::new();
            let mut events: Vec<Event> = Vec::new();
            lexer.feed(cap.expansion.as_bytes(), &mut events);
            lexer.close(&mut events);
            let classes: Vec<SequenceClass> = events.iter().map(|event| event.class).collect();
            let supported = !classes.is_empty() && !classes.contains(&SequenceClass::Extension);
            Coverage {
                name: cap.name,
                direction: cap.direction,
                classes,
                supported,
            }
        })
        .collect()
}
