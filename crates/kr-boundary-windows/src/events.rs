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
    /// An event holds the element of a number twice, so which text is its number is not known.
    // text: events-5
    #[error("the application-control log gave an event with the {name} twice")]
    Repeated {
        /// The element: the event's number or the record's.
        name: String,
    },
    /// The element of a number holds something beside its text: a comment, a CDATA section, an
    /// element or another item.
    // text: events-7
    #[error(
        "the application-control log gave the {name} with something beside its text (a comment, a CDATA section, an element or another item), so which text is its number is not known"
    )]
    NotOneText {
        /// The element: the event's number or the record's.
        name: String,
    },
    /// An event holds no element of one of its numbers.
    // text: events-6
    #[error("the application-control log gave an event with no {name}")]
    Missing {
        /// The element: the event's number or the record's.
        name: String,
    },
}

/// Reads the XML `wevtutil qe` writes: a sequence of `Event` elements with no root, or the same
/// inside a root element.
///
/// # Errors
///
/// Returns [`EventError::Unreadable`] for text that is not well-formed, and an error for an event
/// whose number or record number is missing, empty, not a number or given twice: a number that the
/// log did not give is never taken for zero.
pub fn parse(xml: &str) -> Result<Vec<LogEvent>, EventError> {
    let wrapped = format!("<Events>{xml}</Events>");
    let mut reader = Reader::from_str(&wrapped);
    let mut events = Vec::new();
    let mut current: Option<LogEvent> = None;
    let mut numbers = Numbers::default();
    let mut field: Option<String> = None;
    // The element of a number that is open: it holds one text, and a reference that stands for a
    // character, and nothing else.
    let mut number_open: Option<String> = None;
    loop {
        let event = reader
            .read_event()
            .map_err(|error| EventError::Unreadable(error.to_string()))?;
        if let Some(name) = &number_open
            && !matches!(event, Event::Text(_) | Event::GeneralRef(_) | Event::End(_))
        {
            return Err(EventError::NotOneText { name: name.clone() });
        }
        match event {
            Event::Start(element) => {
                let name = element.local_name().as_ref().to_owned();
                if name == "Event" {
                    current = Some(LogEvent::default());
                    numbers = Numbers::default();
                } else if current.is_some() {
                    // An element of a number that is there is read, whatever it holds.
                    numbers.begin(&name)?;
                    if matches!(name.as_str(), "EventID" | "EventRecordID") {
                        number_open = Some(name.clone());
                    }
                    field = Some(name);
                }
            }
            Event::Empty(element) => {
                let name = element.local_name().as_ref().to_owned();
                if name == "Event" {
                    // An event with nothing in it holds no number.
                    events.push(finished(LogEvent::default(), Numbers::default())?);
                } else if current.is_some() {
                    // An element of a number with no content is a number that is not there.
                    numbers.begin(&name)?;
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
                    if let Some(done) = current.take() {
                        events.push(finished(done, std::mem::take(&mut numbers))?);
                    }
                    field = None;
                } else {
                    field = None;
                }
                number_open = None;
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

impl Numbers {
    /// Starts the text of a number at the element of that name, and refuses a second element of the
    /// same name in the event: it would replace the first one's text before either is read.
    fn begin(&mut self, name: &str) -> Result<(), EventError> {
        let slot = match name {
            "EventID" => &mut self.id,
            "EventRecordID" => &mut self.record,
            _ => return Ok(()),
        };
        if slot.is_some() {
            return Err(EventError::Repeated {
                name: name.to_owned(),
            });
        }
        *slot = Some(String::new());
        Ok(())
    }
}

/// An event at its end: its two numbers are read from their text, and an event that holds no
/// element of one of them is refused, since the number would stand as zero.
fn finished(mut event: LogEvent, numbers: Numbers) -> Result<LogEvent, EventError> {
    let missing = |name: &str| EventError::Missing {
        name: name.to_owned(),
    };
    let id = numbers.id.ok_or_else(|| missing("EventID"))?;
    event.id = number(&id, "EventID")?;
    let record = numbers.record.ok_or_else(|| missing("EventRecordID"))?;
    event.record = number(&record, "EventRecordID")?;
    event.rule_id = event.rule_id.trim().trim_matches(['{', '}']).to_lowercase();
    Ok(event)
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
