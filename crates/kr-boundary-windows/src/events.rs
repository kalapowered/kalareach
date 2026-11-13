//! What the platform's application-control log says about a program it refused.
//!
//! The proof that the policy is in force does not rest on a launch failing: another control, a
//! missing file or a permission could fail it the same way. It rests on the log naming the rule
//! that refused: the event for a blocked program carries the identifier of the rule, the account
//! it was refused to and the path of the program, and the proof requires the account's own deny
//! rule by its identifier. This module reads the log's XML into those fields.

use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};

/// The event the platform writes when it refuses a program an enforced rule denies.
pub const BLOCKED: u32 = 8004;

/// The event the platform writes when it has applied a policy.
pub const APPLIED: u32 = 8001;

/// One event of the application-control log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogEvent {
    /// The event's number.
    pub id: u32,
    /// The log's own number for the record, which only grows.
    pub record: u64,
    /// The identifier of the rule that decided, lower case, without braces. Empty when the event
    /// names none.
    pub rule_id: String,
    /// The name of that rule.
    pub rule_name: String,
    /// The identifier of the account the program was refused to.
    pub user: String,
    /// The full path of the program.
    pub path: String,
}

/// A log that could not be read.
#[derive(Debug, thiserror::Error)]
pub enum EventError {
    /// The text is not the log's XML.
    // text: events-1
    #[error("the application-control log could not be read: {0}")]
    Unreadable(String),
    /// The text holds a reference that is none of the five named ones and not a character reference.
    // text: events-2
    #[error(
        "the application-control log holds the reference &{0}; which this program does not read"
    )]
    UnknownReference(String),
    /// The text holds a character reference that is not a character.
    // text: events-3
    #[error(
        "the application-control log holds the reference &{name}; which is not a character: {why}"
    )]
    NotACharacter {
        /// What stands between the ampersand and the semicolon.
        name: String,
        /// Why it is not a character.
        why: String,
    },
    /// The text of an event's number is not a number.
    // text: events-4
    #[error("the application-control log gave the {name} {text:?}, which is not a number")]
    NotANumber {
        /// The element: the event's number or the record's.
        name: String,
        /// What the element held.
        text: String,
    },
}

/// Reads the XML `wevtutil qe` writes: a sequence of `Event` elements with no root, or the same
/// inside a root element.
///
/// # Errors
///
/// Returns [`EventError::Unreadable`] for text that is not well-formed.
pub fn parse(xml: &str) -> Result<Vec<LogEvent>, EventError> {
    let wrapped = format!("<Events>{xml}</Events>");
    let mut reader = Reader::from_str(&wrapped);
    let mut events = Vec::new();
    let mut current: Option<LogEvent> = None;
    let mut numbers = Numbers::default();
    let mut field: Option<String> = None;
    loop {
        let event = reader
            .read_event()
            .map_err(|error| EventError::Unreadable(error.to_string()))?;
        match event {
            Event::Start(element) => {
                let name = element.local_name().as_ref().to_owned();
                if name == "Event" {
                    current = Some(LogEvent::default());
                    numbers = Numbers::default();
                } else if current.is_some() {
                    // An element of a number that is there is read, whatever it holds.
                    match name.as_str() {
                        "EventID" => numbers.id = Some(String::new()),
                        "EventRecordID" => numbers.record = Some(String::new()),
                        _ => {}
                    }
                    field = Some(name);
                }
            }
            Event::Text(text) => {
                if let (Some(event), Some(field)) = (current.as_mut(), field.as_deref()) {
                    let content = text.xml_content(XmlVersion::Implicit1_0);
                    append(event, &mut numbers, field, &content);
                }
            }
            Event::GeneralRef(reference) => {
                if let (Some(event), Some(field)) = (current.as_mut(), field.as_deref()) {
                    let name = reference.xml10_content();
                    let character = match name.as_ref() {
                        "amp" => '&',
                        "lt" => '<',
                        "gt" => '>',
                        "quot" => '"',
                        "apos" => '\'',
                        other => match reference.resolve_char_ref() {
                            Ok(Some(character)) => character,
                            Ok(None) => {
                                return Err(EventError::UnknownReference(other.to_owned()));
                            }
                            Err(error) => {
                                return Err(EventError::NotACharacter {
                                    name: other.to_owned(),
                                    why: error.to_string(),
                                });
                            }
                        },
                    };
                    append(event, &mut numbers, field, &character.to_string());
                }
            }
            Event::End(element) => {
                if element.local_name().as_ref() == "Event" {
                    if let Some(mut done) = current.take() {
                        if let Some(text) = numbers.id.take() {
                            done.id = number(&text, "EventID")?;
                        }
                        if let Some(text) = numbers.record.take() {
                            done.record = number(&text, "EventRecordID")?;
                        }
                        done.rule_id = done.rule_id.trim().trim_matches(['{', '}']).to_lowercase();
                        events.push(done);
                    }
                    field = None;
                } else {
                    field = None;
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(events)
}

/// The text of the two numbers of an event as the log wrote it: a number is read once its element
/// has ended, since a reference in it splits the text, and a text that is not a number is an error
/// and not a number that was not given.
#[derive(Default)]
struct Numbers {
    id: Option<String>,
    record: Option<String>,
}

/// Reads one of the event's numbers.
fn number<T: std::str::FromStr>(text: &str, name: &str) -> Result<T, EventError> {
    text.trim().parse().map_err(|_| EventError::NotANumber {
        name: name.to_owned(),
        text: text.to_owned(),
    })
}

fn append(event: &mut LogEvent, numbers: &mut Numbers, field: &str, text: &str) {
    match field {
        "EventID" => numbers.id.get_or_insert_with(String::new).push_str(text),
        "EventRecordID" => numbers
            .record
            .get_or_insert_with(String::new)
            .push_str(text),
        "RuleId" => event.rule_id.push_str(text),
        "RuleName" => event.rule_name.push_str(text),
        "TargetUser" => event.user.push_str(text.trim()),
        "FullFilePath" => event.path.push_str(text),
        _ => {}
    }
}
