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
    #[error("the application-control log could not be read: {0}")]
    Unreadable(String),
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
                } else if current.is_some() {
                    field = Some(name);
                }
            }
            Event::Text(text) => {
                if let (Some(event), Some(field)) = (current.as_mut(), field.as_deref()) {
                    let content = text.xml_content(XmlVersion::Implicit1_0);
                    append(event, field, &content);
                }
            }
            Event::GeneralRef(reference) => {
                if let (Some(event), Some(field)) = (current.as_mut(), field.as_deref()) {
                    let name = reference.xml10_content();
                    let character = match name.as_ref() {
                        "amp" => Some('&'),
                        "lt" => Some('<'),
                        "gt" => Some('>'),
                        "quot" => Some('"'),
                        "apos" => Some('\''),
                        _ => reference.resolve_char_ref().ok().flatten(),
                    };
                    if let Some(character) = character {
                        append(event, field, &character.to_string());
                    }
                }
            }
            Event::End(element) => {
                if element.local_name().as_ref() == "Event" {
                    if let Some(mut done) = current.take() {
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

fn append(event: &mut LogEvent, field: &str, text: &str) {
    match field {
        "EventID" => {
            event.id = text.trim().parse().unwrap_or(event.id);
        }
        "EventRecordID" => {
            event.record = text.trim().parse().unwrap_or(event.record);
        }
        "RuleId" => event.rule_id.push_str(text),
        "RuleName" => event.rule_name.push_str(text),
        "TargetUser" => event.user.push_str(text.trim()),
        "FullFilePath" => event.path.push_str(text),
        _ => {}
    }
}
