//! What the provider's data channel says, read as far as the delegation gate needs it.
//!
//! The channel is read-only and carries what the provider chose to send, so every message is data
//! and none is authority. Two event types are **required**: a transcript fragment
//! (`session.input_transcript.delta`) and a delegation (`session.delegation.created`). A message of
//! either that cannot be read exactly as the profile's closed schema states it is not skipped: it
//! is [`Malformed`], and the gate refuses every request from then on, since what it failed to read
//! may have been what a person said. The provider's acknowledgement of a mute is read too, because
//! a provider that hears nothing leaves the device's own record of the microphone clean. Every
//! other type is [`Provider::Other`] and says nothing the gate acts on.
//!
//! The text of a fragment is what a person said: nothing here prints it, and a malformed message
//! is told by its kind and never by its content.

use serde_json::Value;

/// The longest moment on a call's timeline: a call's longest length, in milliseconds.
pub(super) const TIMELINE_MAX_MS: u64 = 86_400_000;

/// The most bytes a fragment's text may hold.
const TEXT_MAX_BYTES: usize = kr_protocol::voice::VOICE_FRAGMENT_BYTES_MAX;

/// What one message of the provider's data channel is, to the gate.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Provider {
    /// A transcript fragment of what the caller said.
    Fragment(Fragment),
    /// The model delegated work at `offset_ms` on the call's timeline.
    Delegation { id: String, offset_ms: u64 },
    /// The provider says it muted what it hears of the caller.
    InputMuted,
    /// Anything else the provider may send: it never reaches the gate, and is known by its type
    /// alone.
    Other { kind: String },
    /// A message of a required kind that cannot be read as it must be, or one that is no event.
    Malformed(Malformed),
}

/// One transcript fragment, with the moments on the provider's timeline it covers.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Fragment {
    /// Where it starts, in whole milliseconds.
    pub start_ms: u64,
    /// Where it ends, excluded, in whole milliseconds.
    pub end_ms: u64,
    /// What was said. Never printed.
    pub text: String,
}

impl std::fmt::Debug for Fragment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Fragment")
            .field("start_ms", &self.start_ms)
            .field("end_ms", &self.end_ms)
            .field("text", &format_args!("{} bytes", self.text.len()))
            .finish()
    }
}

/// Why a message of a required kind could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Malformed {
    /// The bytes are not a JSON object with a string `type`.
    NotAnEvent,
    /// A required event that fails its closed schema: a member missing, of another kind or not
    /// listed.
    Schema,
    /// A type that begins as a required one does and is neither of the two.
    UnknownRequired,
    /// A fragment whose text is empty, over the bound or holds a control character.
    Text,
    /// A moment that is not a whole number of milliseconds from 0 to a call's longest length.
    Time,
    /// A fragment that ends before it starts.
    Ends,
}

/// Reads the bytes of one message of the provider's data channel.
pub(super) fn read(bytes: &[u8]) -> Provider {
    let Ok(Value::Object(message)) = serde_json::from_slice::<Value>(bytes) else {
        return Provider::Malformed(Malformed::NotAnEvent);
    };
    let Some(Value::String(kind)) = message.get("type") else {
        return Provider::Malformed(Malformed::NotAnEvent);
    };
    match kind.as_str() {
        "session.input_transcript.delta" => fragment(&message),
        "session.delegation.created" => delegation(&message),
        // Whatever it says, a mute the provider reports is read as one.
        "session.input_audio.muted" => Provider::InputMuted,
        other
            if other.starts_with("session.input_transcript")
                || other.starts_with("session.delegation") =>
        {
            Provider::Malformed(Malformed::UnknownRequired)
        }
        other => Provider::Other {
            kind: other.to_owned(),
        },
    }
}

type Members = serde_json::Map<String, Value>;

/// Whether `message` has every member of `required`, no member outside `allowed`, and a non-empty
/// string for each of `strings` it holds.
fn closed(message: &Members, required: &[&str], allowed: &[&str], strings: &[&str]) -> bool {
    required.iter().all(|name| message.contains_key(*name))
        && message.keys().all(|name| allowed.contains(&name.as_str()))
        && strings.iter().all(|name| {
            message
                .get(*name)
                .is_none_or(|value| value.as_str().is_some_and(|text| !text.is_empty()))
        })
}

fn fragment(message: &Members) -> Provider {
    const ALLOWED: &[&str] = &[
        "type",
        "event_id",
        "client_event_id",
        "delta",
        "start_ms",
        "end_ms",
    ];
    if !closed(
        message,
        &["type", "event_id", "delta", "start_ms", "end_ms"],
        ALLOWED,
        &["event_id", "client_event_id"],
    ) {
        return Provider::Malformed(Malformed::Schema);
    }
    let (Some(Value::String(text)), Some(start), Some(end)) = (
        message.get("delta"),
        message.get("start_ms"),
        message.get("end_ms"),
    ) else {
        return Provider::Malformed(Malformed::Schema);
    };
    let (Value::Number(start), Value::Number(end)) = (start, end) else {
        return Provider::Malformed(Malformed::Schema);
    };
    if text.is_empty() || text.len() > TEXT_MAX_BYTES || text.chars().any(char::is_control) {
        return Provider::Malformed(Malformed::Text);
    }
    let (Some(start_ms), Some(end_ms)) = (moment(start), moment(end)) else {
        return Provider::Malformed(Malformed::Time);
    };
    if end_ms < start_ms {
        return Provider::Malformed(Malformed::Ends);
    }
    Provider::Fragment(Fragment {
        start_ms,
        end_ms,
        text: text.clone(),
    })
}

fn delegation(message: &Members) -> Provider {
    const ALLOWED: &[&str] = &[
        "type",
        "event_id",
        "client_event_id",
        "offset_ms",
        "delegation",
    ];
    if !closed(
        message,
        &["type", "event_id", "offset_ms", "delegation"],
        ALLOWED,
        &["event_id", "client_event_id"],
    ) {
        return Provider::Malformed(Malformed::Schema);
    }
    let (Some(Value::Number(offset)), Some(Value::Object(inner))) =
        (message.get("offset_ms"), message.get("delegation"))
    else {
        return Provider::Malformed(Malformed::Schema);
    };
    if !closed(
        inner,
        &["id", "type", "target"],
        &["id", "type", "target"],
        &["id"],
    ) || inner.get("type") != Some(&Value::String("delegation".to_owned()))
        || inner.get("target") != Some(&Value::String("client".to_owned()))
    {
        return Provider::Malformed(Malformed::Schema);
    }
    let Some(Value::String(id)) = inner.get("id") else {
        return Provider::Malformed(Malformed::Schema);
    };
    let Some(offset_ms) = moment(offset) else {
        return Provider::Malformed(Malformed::Time);
    };
    Provider::Delegation {
        id: id.clone(),
        offset_ms,
    }
}

/// A moment as the profile's bare JSON number gives it, when it is a whole number of milliseconds
/// from 0 to a call's longest length: a fraction, a negative and a huge value pass the profile's
/// schema and are not moments of a call.
fn moment(number: &serde_json::Number) -> Option<u64> {
    let value = number.as_f64()?;
    // A negative zero is a negative: nothing is accepted that is signed below zero.
    if !value.is_finite() || value.is_sign_negative() || value.fract() != 0.0 {
        return None;
    }
    if value > 86_400_000.0 {
        return None;
    }
    // Whole, finite, from 0 to a bound that fits: the conversion loses nothing.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let moment = value as u64;
    (moment <= TIMELINE_MAX_MS).then_some(moment)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Messages the provider's closed schemas accept, from a recorded session (profile
    /// `gpt-live-1`): each is read as the fixture says, and the text of a fragment is kept as it
    /// came, leading space included.
    #[test]
    fn the_recorded_events_are_read_as_the_fixture_says() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../../fixtures/voice/provider-events.json"
        ))
        .expect("the fixture is JSON");
        let recorded = fixture["recorded"].as_array().expect("recorded events");
        assert!(!recorded.is_empty());
        for entry in recorded {
            let bytes = serde_json::to_vec(&entry["event"]).expect("an event encodes");
            let read = read(&bytes);
            match entry["reads_as"].as_str().expect("what it reads as") {
                "fragment" => assert_eq!(
                    read,
                    Provider::Fragment(Fragment {
                        start_ms: entry["start_ms"].as_u64().expect("start"),
                        end_ms: entry["end_ms"].as_u64().expect("end"),
                        text: entry["event"]["delta"].as_str().expect("text").to_owned(),
                    })
                ),
                "delegation" => assert_eq!(
                    read,
                    Provider::Delegation {
                        id: entry["event"]["delegation"]["id"]
                            .as_str()
                            .expect("id")
                            .to_owned(),
                        offset_ms: entry["offset_ms"].as_u64().expect("offset"),
                    }
                ),
                "muted" => assert_eq!(read, Provider::InputMuted),
                "other" => assert_eq!(
                    read,
                    Provider::Other {
                        kind: entry["event"]["type"].as_str().expect("a type").to_owned()
                    }
                ),
                unknown => panic!("an entry the test does not know: {unknown}"),
            }
        }
    }

    /// What the gate must refuse to read, each as a kind: every one is a message the profile's
    /// schema lets through or a message of a required kind that breaks it.
    #[test]
    fn what_the_gate_cannot_read_is_malformed_by_its_kind() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../../fixtures/voice/provider-events.json"
        ))
        .expect("the fixture is JSON");
        let unreadable = fixture["unreadable"].as_array().expect("unreadable events");
        assert!(!unreadable.is_empty());
        for entry in unreadable {
            let bytes = match entry["event"].as_str() {
                Some(text) => text.as_bytes().to_vec(),
                None => serde_json::to_vec(&entry["event"]).expect("an event encodes"),
            };
            let wanted = match entry["malformed"].as_str().expect("its kind") {
                "not_an_event" => Malformed::NotAnEvent,
                "schema" => Malformed::Schema,
                "unknown_required" => Malformed::UnknownRequired,
                "text" => Malformed::Text,
                "time" => Malformed::Time,
                "ends" => Malformed::Ends,
                unknown => panic!("a kind the test does not know: {unknown}"),
            };
            assert_eq!(
                read(&bytes),
                Provider::Malformed(wanted),
                "{}",
                entry["why"].as_str().unwrap_or_default()
            );
        }
    }

    /// A fragment never prints what was said.
    #[test]
    fn a_fragment_never_prints_its_text() {
        let printed = format!(
            "{:?}",
            Fragment {
                start_ms: 1,
                end_ms: 2,
                text: "do not close session three".to_owned(),
            }
        );
        assert!(!printed.contains("close"), "{printed}");
    }
}
