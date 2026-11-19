//! How a package says what its application's hook payload means.
//!
//! An application that starts a hook runs the forwarder with the event as one JSON document on
//! standard input. A package whose table carries [`HookEvents`] names, in that document, where the
//! event's name and the session are, which of its event names reports which of the five things the
//! forwarder can report, and where the few members a report carries are. It cannot name a new kind
//! of report, a wire member or anything the worker does. Like [`crate::connector::Observation`],
//! nothing here lets a package say what happened: it says where to read and which of five words a
//! name stands for.
//!
//! The same value is checked in three places, by the one function [`HookEvents::refusals`]: the
//! package check, the worker when it assembles an installed connector, and the forwarder when it
//! reads the value the worker published for its launch.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::connector::{FieldPath, FieldSegment};

/// Most events a package may map.
pub const MAX_EVENTS: usize = 32;

/// Most member segments in a place.
pub const MAX_PLACE_SEGMENTS: usize = 3;

/// Most bytes in an event name, a member name or a contact tool template.
pub const MAX_NAME_BYTES: usize = 64;

/// Most bytes the value may take when it is written as JSON: what a package states and what the
/// worker publishes for a launch.
pub const MAX_SERIALISED_BYTES: usize = 8 * 1024;

/// The member of the contact tool's input that holds the request's identifier.
///
/// It is the contact skill's own member, so a package declares only where the input object is.
pub const CONTACT_REQUEST_MEMBER: &str = "request_id";

/// What a hook's payload means, for one application.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct HookEvents {
    /// Where the payload names the event.
    pub event: FieldPath,
    /// Where the payload names the session, which KalaReach binds as the thread.
    pub thread: FieldPath,
    /// The event names the forwarder reports, one to thirty-two, each with what it reports. An
    /// event not named here is answered and reports nothing.
    pub events: Vec<HookEvent>,
    /// The members a report carries.
    #[serde(default)]
    pub details: HookDetails,
    /// How the application names the contact skill's tool, for a package that reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<HookContact>,
}

/// One event name and what it reports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct HookEvent {
    /// The name the application gives the event.
    pub name: String,
    /// What the forwarder reports for it.
    pub report: HookReport,
    /// The start source that makes this a continuation of the thread already selected, for a
    /// session start.
    ///
    /// A start whose source reads as this one goes on in the same thread; every other start is a
    /// new selection. It needs the `start_source` place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continued_by: Option<String>,
}

/// The five things the forwarder reports. The worker reads these and no others.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HookReport {
    /// A session started: a thread is selected, or continued.
    SessionStarted,
    /// A session ended: the thread is ended.
    SessionEnded,
    /// A tool finished.
    ToolFinished,
    /// A tool failed.
    ToolFailed,
    /// The application raised a notification.
    Notification,
}

/// The places of the members a report carries, each optional.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct HookDetails {
    /// How a session started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_source: Option<FieldPath>,
    /// Why a session ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_reason: Option<FieldPath>,
    /// The tool that ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<FieldPath>,
    /// Which notification this is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_kind: Option<FieldPath>,
    /// The notification's text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_text: Option<FieldPath>,
}

/// How the application names the contact skill's tool and the request it asked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct HookContact {
    /// How the application spells the tool's name at the `tool_name` place: plain characters and
    /// the words `{server}` and `{tool}`, which the host expands to the contact skill's server
    /// name and tool name before it compares for equality.
    pub tool_name: String,
    /// Where the tool's input object is. The request identifier is its member `request_id`.
    pub tool_input: FieldPath,
    /// The other members the application names the server or the tool by. When the payload holds
    /// one of them, it has to agree with the contact skill's own name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agreeing: Vec<HookAgreement>,
}

/// A member that names the contact skill's server or tool, and which one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct HookAgreement {
    /// Where the payload names it.
    pub place: FieldPath,
    /// Which of the two it names.
    pub names: HookAgreed,
}

/// Which name an agreeing member holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HookAgreed {
    /// The MCP server's name.
    Server,
    /// The tool's own name on that server.
    Tool,
}

/// What a refusal of a [`HookEvents`] value is about. [`Self::name`] is the name a report carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookEventsRefusal {
    /// A place has no segment.
    PlaceEmpty,
    /// A place has more than three segments.
    PlaceTooDeep,
    /// A place has an index segment.
    PlaceHasIndex,
    /// A member name is empty, over 64 bytes or holds a control character.
    PlaceMemberBad,
    /// A place read as a value is the start of another place, so one member would be read as a
    /// value and as an object.
    PlacesOverlap,
    /// The value maps no event.
    NoEvents,
    /// The value maps more than thirty-two events.
    TooManyEvents,
    /// An event name, or the start source of a continuation, is empty, over 64 bytes or holds a
    /// control character.
    EventNameBad,
    /// Two events have one name.
    EventDuplicate,
    /// `continued_by` is on a report other than a session start, or there is no `start_source`.
    ContinuedByMisplaced,
    /// The contact's template names a word other than `{server}` and `{tool}`, lacks one of them,
    /// holds a character outside `a-z 0-9 _ . -`, or is over 64 bytes.
    ContactTemplateBad,
    /// A contact is declared and no event reports a finished tool.
    ContactWithoutToolFinished,
    /// A contact is declared and `details.tool_name` has no place.
    ContactWithoutToolNamePlace,
    /// The value is over 8 KiB written as JSON.
    TooLarge,
    /// The package declares the value and starts no forwarder: it has neither a native bridge nor a
    /// command integration, so the value would never be read.
    NoForwarder,
}

impl HookEventsRefusal {
    /// The name the report carries.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PlaceEmpty => "hook_events.place_empty",
            Self::PlaceTooDeep => "hook_events.place_too_deep",
            Self::PlaceHasIndex => "hook_events.place_has_index",
            Self::PlaceMemberBad => "hook_events.place_member_bad",
            Self::PlacesOverlap => "hook_events.places_overlap",
            Self::NoEvents => "hook_events.no_events",
            Self::TooManyEvents => "hook_events.too_many_events",
            Self::EventNameBad => "hook_events.event_name_bad",
            Self::EventDuplicate => "hook_events.event_duplicate",
            Self::ContinuedByMisplaced => "hook_events.continued_by_misplaced",
            Self::ContactTemplateBad => "hook_events.contact_template_bad",
            Self::ContactWithoutToolFinished => "hook_events.contact_without_tool_finished",
            Self::ContactWithoutToolNamePlace => "hook_events.contact_without_tool_name_place",
            Self::TooLarge => "hook_events.too_large",
            Self::NoForwarder => "hook_events.no_forwarder",
        }
    }
}

/// Why a [`HookEvents`] value is refused: which refusal, and what it found.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{}: {detail}", .refusal.name())]
pub struct HookEventsError {
    /// Which refusal.
    pub refusal: HookEventsRefusal,
    /// What it found, in words.
    pub detail: String,
}

impl HookEventsError {
    fn new(refusal: HookEventsRefusal, detail: impl Into<String>) -> Self {
        Self {
            refusal,
            detail: detail.into(),
        }
    }
}

impl HookEvents {
    /// The value a package gets when it declares none: what Claude Code's hooks carry, which
    /// Gemini CLI and Qoder CLI name the same way.
    ///
    /// It is data, the same value as `tests/fixtures/hook_events_claude_code.json`, which a package
    /// may copy. It stays because the packages already installed declare no value and the seed
    /// never replaces an installation. Removal condition: when a compatibility level stops reading
    /// packages whose connector table declares no hook events, the default goes and every table
    /// declares its own.
    #[must_use]
    pub fn claude_code() -> Self {
        let place = |names: &[&str]| FieldPath {
            segments: names
                .iter()
                .map(|name| FieldSegment::Member {
                    name: (*name).to_owned(),
                })
                .collect(),
        };
        let event = |name: &str, report, continued_by: Option<&str>| HookEvent {
            name: name.to_owned(),
            report,
            continued_by: continued_by.map(str::to_owned),
        };
        Self {
            event: place(&["hook_event_name"]),
            thread: place(&["session_id"]),
            events: vec![
                event("SessionStart", HookReport::SessionStarted, Some("compact")),
                event("SessionEnd", HookReport::SessionEnded, None),
                event("PostToolUse", HookReport::ToolFinished, None),
                event("PostToolUseFailure", HookReport::ToolFailed, None),
                event("Notification", HookReport::Notification, None),
            ],
            details: HookDetails {
                start_source: Some(place(&["source"])),
                end_reason: Some(place(&["reason"])),
                tool_name: Some(place(&["tool_name"])),
                notification_kind: Some(place(&["notification_type"])),
                notification_text: Some(place(&["message"])),
            },
            contact: Some(HookContact {
                tool_name: "mcp__{server}__{tool}".to_owned(),
                tool_input: place(&["tool_input"]),
                agreeing: vec![
                    HookAgreement {
                        place: place(&["mcp_server", "name"]),
                        names: HookAgreed::Server,
                    },
                    HookAgreement {
                        place: place(&["mcp_context", "server_name"]),
                        names: HookAgreed::Server,
                    },
                    HookAgreement {
                        place: place(&["mcp_context", "tool_name"]),
                        names: HookAgreed::Tool,
                    },
                ],
            }),
        }
    }

    /// The first refusal, for a reader that stops at one.
    ///
    /// # Errors
    ///
    /// Returns the first of [`Self::refusals`].
    pub fn check(&self) -> Result<(), HookEventsError> {
        self.refusals().into_iter().next().map_or(Ok(()), Err)
    }

    /// Every refusal of the value, in the order the checks run. An empty list is a value every
    /// reader accepts.
    #[must_use]
    pub fn refusals(&self) -> Vec<HookEventsError> {
        let mut found = Vec::new();
        let mut places: Vec<(&str, &FieldPath)> =
            vec![("event", &self.event), ("thread", &self.thread)];
        let details = [
            ("details.start_source", &self.details.start_source),
            ("details.end_reason", &self.details.end_reason),
            ("details.tool_name", &self.details.tool_name),
            ("details.notification_kind", &self.details.notification_kind),
            ("details.notification_text", &self.details.notification_text),
        ];
        for (what, declared) in details {
            if let Some(declared) = declared {
                places.push((what, declared));
            }
        }
        if let Some(contact) = &self.contact {
            for agreement in &contact.agreeing {
                places.push(("contact.agreeing", &agreement.place));
            }
        }
        let mut leaves: Vec<Vec<&str>> = Vec::new();
        for (what, place) in places {
            leaves.extend(check_place(what, place, &mut found));
        }
        // The contact's input is an object: the request identifier is a member of it, so the value
        // read there is one place deeper.
        if let Some(contact) = &self.contact {
            let input = check_place("contact.tool_input", &contact.tool_input, &mut found);
            leaves.extend(input.map(|mut names| {
                names.push(CONTACT_REQUEST_MEMBER);
                names
            }));
        }
        found.extend(overlap(&leaves));
        self.check_events(&mut found);
        if let Some(contact) = &self.contact {
            self.check_contact(contact, &mut found);
        }
        if serde_json::to_vec(self).map_or(true, |bytes| bytes.len() > MAX_SERIALISED_BYTES) {
            found.push(HookEventsError::new(
                HookEventsRefusal::TooLarge,
                format!("the value is over {MAX_SERIALISED_BYTES} bytes written as JSON"),
            ));
        }
        found
    }

    fn check_events(&self, found: &mut Vec<HookEventsError>) {
        if self.events.is_empty() {
            found.push(HookEventsError::new(
                HookEventsRefusal::NoEvents,
                "the value maps no event",
            ));
        }
        if self.events.len() > MAX_EVENTS {
            found.push(HookEventsError::new(
                HookEventsRefusal::TooManyEvents,
                format!(
                    "the value maps {} events, and {MAX_EVENTS} is the most",
                    self.events.len()
                ),
            ));
        }
        let mut names = BTreeSet::new();
        for event in &self.events {
            if !is_a_name(&event.name) {
                found.push(HookEventsError::new(
                    HookEventsRefusal::EventNameBad,
                    format!(
                        "an event name is empty, over {MAX_NAME_BYTES} bytes or holds a control \
                         character"
                    ),
                ));
            } else if !names.insert(event.name.as_str()) {
                found.push(HookEventsError::new(
                    HookEventsRefusal::EventDuplicate,
                    format!("the event {} is mapped more than once", event.name),
                ));
            }
            if let Some(source) = &event.continued_by {
                if event.report != HookReport::SessionStarted || self.details.start_source.is_none()
                {
                    found.push(HookEventsError::new(
                        HookEventsRefusal::ContinuedByMisplaced,
                        format!(
                            "the event {} states continued_by, which belongs to a session start \
                             and needs the start_source place",
                            event.name
                        ),
                    ));
                }
                if !is_a_name(source) {
                    found.push(HookEventsError::new(
                        HookEventsRefusal::EventNameBad,
                        format!(
                            "the continued_by of {} is empty, over {MAX_NAME_BYTES} bytes or \
                             holds a control character",
                            event.name
                        ),
                    ));
                }
            }
        }
    }

    fn check_contact(&self, contact: &HookContact, found: &mut Vec<HookEventsError>) {
        if !template_is_good(&contact.tool_name) {
            found.push(HookEventsError::new(
                HookEventsRefusal::ContactTemplateBad,
                format!(
                    "the contact's tool name template has to hold {{server}} and {{tool}}, no \
                     other word in braces, only a-z 0-9 _ . - besides, and at most \
                     {MAX_NAME_BYTES} bytes"
                ),
            ));
        }
        if !self
            .events
            .iter()
            .any(|event| event.report == HookReport::ToolFinished)
        {
            found.push(HookEventsError::new(
                HookEventsRefusal::ContactWithoutToolFinished,
                "a contact is declared and no event reports a finished tool",
            ));
        }
        if self.details.tool_name.is_none() {
            found.push(HookEventsError::new(
                HookEventsRefusal::ContactWithoutToolNamePlace,
                "a contact is declared and details.tool_name has no place",
            ));
        }
    }
}

/// The member names of a place that is good, or `None` after pushing what is wrong with it.
fn check_place<'a>(
    what: &str,
    place: &'a FieldPath,
    found: &mut Vec<HookEventsError>,
) -> Option<Vec<&'a str>> {
    let mut names = Vec::new();
    let mut good = true;
    if place.segments.is_empty() {
        found.push(HookEventsError::new(
            HookEventsRefusal::PlaceEmpty,
            format!("the place {what} has no segment"),
        ));
        return None;
    }
    if place.segments.len() > MAX_PLACE_SEGMENTS {
        found.push(HookEventsError::new(
            HookEventsRefusal::PlaceTooDeep,
            format!(
                "the place {what} has {} segments, and {MAX_PLACE_SEGMENTS} is the most",
                place.segments.len()
            ),
        ));
        good = false;
    }
    for segment in &place.segments {
        match segment {
            FieldSegment::Index { .. } => {
                found.push(HookEventsError::new(
                    HookEventsRefusal::PlaceHasIndex,
                    format!("the place {what} has an index segment, and a hook reads members only"),
                ));
                good = false;
            }
            FieldSegment::Member { name } => {
                if is_a_name(name) {
                    names.push(name.as_str());
                } else {
                    found.push(HookEventsError::new(
                        HookEventsRefusal::PlaceMemberBad,
                        format!(
                            "a member of the place {what} is empty, over {MAX_NAME_BYTES} bytes \
                             or holds a control character"
                        ),
                    ));
                    good = false;
                }
            }
        }
    }
    good.then_some(names)
}

/// A refusal when a place read as a value is the start of another place.
fn overlap(leaves: &[Vec<&str>]) -> Option<HookEventsError> {
    for (index, shorter) in leaves.iter().enumerate() {
        for (other_index, longer) in leaves.iter().enumerate() {
            if index != other_index
                && shorter.len() < longer.len()
                && longer.starts_with(shorter.as_slice())
            {
                return Some(HookEventsError::new(
                    HookEventsRefusal::PlacesOverlap,
                    format!(
                        "the place {} is read as a value and is also the start of the place {}",
                        shorter.join("."),
                        longer.join(".")
                    ),
                ));
            }
        }
    }
    None
}

fn is_a_name(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_NAME_BYTES && !text.chars().any(char::is_control)
}

/// Whether a template holds `{server}` and `{tool}`, no other word in braces, and only plain
/// characters besides.
fn template_is_good(template: &str) -> bool {
    if template.is_empty() || template.len() > MAX_NAME_BYTES {
        return false;
    }
    let (mut server, mut tool) = (false, false);
    let mut rest = template;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix("{server}") {
            server = true;
            rest = after;
        } else if let Some(after) = rest.strip_prefix("{tool}") {
            tool = true;
            rest = after;
        } else {
            let mut characters = rest.chars();
            let Some(next) = characters.next() else {
                break;
            };
            if !(next.is_ascii_lowercase()
                || next.is_ascii_digit()
                || matches!(next, '_' | '.' | '-'))
            {
                return false;
            }
            rest = characters.as_str();
        }
    }
    server && tool
}

impl FieldPath {
    /// The member names of a place that holds members only, in order, or `None` when it holds an
    /// index.
    #[must_use]
    pub fn member_names(&self) -> Option<Vec<&str>> {
        self.segments
            .iter()
            .map(|segment| match segment {
                FieldSegment::Member { name } => Some(name.as_str()),
                FieldSegment::Index { .. } => None,
            })
            .collect()
    }
}
