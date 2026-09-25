//! The records a call to the plugin host carries, and the bounds both ends of it share.
//!
//! Plain data, with no engine behind it. A worker builds these and the host reads them: it turns
//! them into the types a component sees and hands them to the component. The protocol carries them
//! as wire records of its own, and the conversions between the two are here, so both ends convert
//! the same way.

use std::sync::Arc;

use kr_plugin_sdk::limits::OUTPUT_BYTES_PER_CALL;
use kr_protocol::ids::SourceEventHandle;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Uuid;

use crate::protocol::{WireFacts, WireSourceEvent};

/// The largest single document node the host will carry.
///
/// One call may emit 1 MiB in total, and the service protocol carries one node per frame on a
/// control stream whose frames are 1 MiB including their envelope. Reserving the envelope here is
/// what keeps a node that fits the call budget from being a node that cannot be delivered. A
/// component that has more than this to say emits more nodes, which is what the node union is for.
pub const MAX_NODE_BYTES: u64 = OUTPUT_BYTES_PER_CALL - FRAME_ENVELOPE_BYTES;

/// How much of a frame a node's envelope may take.
///
/// The frame's length prefix, the request correlation, the binding identifier, the export name and
/// the node's own field names and CBOR headers. Eight kibibytes is far more than any of that, and
/// being far more is the point: a node that fits the call budget must be one the protocol can
/// deliver, and a bound that were merely exact would depend on the encoding staying the same.
pub const FRAME_ENVELOPE_BYTES: u64 = 8 * 1024;

/// What one emitted node costs of the call's output budget before its contents are counted.
///
/// A node is a record with two identifiers and a body, and it occupies host memory, a frame and a
/// place in a document whatever its strings say. Without a fixed cost a component could emit
/// millions of empty nodes for nothing, and "1 MiB of output per call" would bound only the text.
pub const NODE_OVERHEAD_BYTES: u64 = 64;

/// How long a compile may take before its result is discarded.
///
/// The host's compiler holds to it, and the registration deadlines on both ends of the protocol are
/// made from it, which is why it is here rather than beside the compiler.
pub const COMPILE_DEADLINE_MS: u64 = 30_000;

/// The identifier of one binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BindingId(Uuid);

impl BindingId {
    /// Wraps a raw identifier.
    #[must_use]
    pub const fn new(value: Uuid) -> Self {
        Self(value)
    }

    /// Returns the raw identifier.
    #[must_use]
    pub const fn get(self) -> Uuid {
        self.0
    }
}

impl core::fmt::Display for BindingId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, formatter)
    }
}

/// What happened to an event offered to the queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// The event is queued, and nothing was lost.
    Queued,
    /// The event is queued, and older observations were evicted to make room.
    QueuedWithGap {
        /// How many observations were evicted.
        events: u32,
        /// How many bytes they held.
        bytes: u64,
    },
    /// The event was not queued.
    ///
    /// Only an authoritative request reaches this, and only when the queue is full of other
    /// authoritative requests. The broker keeps the request; what is unavailable is the rich
    /// interpretation of it, not the request.
    Refused {
        /// How many bytes the queue holds.
        held_bytes: u64,
    },
}

/// One immutable source event, as the host holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedSourceEvent {
    /// The private broker handle the component refers to it by.
    pub handle: SourceEventHandle,
    /// What produced the bytes.
    pub provenance: SourceProvenance,
    /// When the host observed them, in milliseconds since the Unix epoch.
    pub observed_at_ms: u64,
    /// The native request identifier, where the event is a native request.
    pub request_id: Option<String>,
    /// The bytes. Shared, never lent mutably.
    pub bytes: Arc<[u8]>,
}

impl ScopedSourceEvent {
    /// Builds an event from bytes the host already owns.
    #[must_use]
    pub fn new(
        handle: SourceEventHandle,
        provenance: SourceProvenance,
        observed_at_ms: u64,
        request_id: Option<String>,
        bytes: impl Into<Arc<[u8]>>,
    ) -> Self {
        Self {
            handle,
            provenance,
            observed_at_ms,
            request_id,
            bytes: bytes.into(),
        }
    }

    /// Returns true when this event is an authoritative native request.
    ///
    /// An authoritative event carries a request the upstream is waiting on. The observation queue
    /// never evicts one to make room, because a dropped request is a decision nobody made.
    #[must_use]
    pub const fn is_authoritative(&self) -> bool {
        self.request_id.is_some()
    }

    /// Returns the size this event occupies in the observation queue.
    #[must_use]
    pub fn queue_bytes(&self) -> u64 {
        // The bytes plus the handle and the request identifier, because a queue that counted only
        // payloads could be filled with empty events.
        let handle = self.handle.as_str().len() as u64;
        let request = self.request_id.as_ref().map_or(0, |id| id.len() as u64);
        self.bytes.len() as u64 + handle + request
    }
}

/// What produced a source event.
///
/// The three are not interchangeable. Terminal bytes may carry useful content and support inferred
/// attention; they never establish native approval authority, which is why provenance travels with
/// every event rather than being inferred from its shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceProvenance {
    /// A framed message on the connector's own upstream connection.
    NativeProtocol,
    /// A documented machine-readable output stream.
    MachineOutput,
    /// Terminal bytes.
    TerminalScrape,
}

impl SourceProvenance {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeProtocol => "native_protocol",
            Self::MachineOutput => "machine_output",
            Self::TerminalScrape => "terminal_scrape",
        }
    }

    /// Returns the provenance for a wire string.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "native_protocol" => Some(Self::NativeProtocol),
            "machine_output" => Some(Self::MachineOutput),
            "terminal_scrape" => Some(Self::TerminalScrape),
            _ => None,
        }
    }

    /// Returns true when this provenance can establish native approval authority.
    ///
    /// Only a framed message on the connector's own authenticated upstream connection can. A
    /// scrape cannot, however convincing it looks.
    #[must_use]
    pub const fn establishes_native_authority(self) -> bool {
        matches!(self, Self::NativeProtocol)
    }
}

/// The facts a component may read about its binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingFacts {
    /// The plugin this instance serves.
    pub plugin_id: String,
    /// The binding revision.
    pub binding_revision: u64,
    /// What the bound execution is doing.
    pub activity: BindingActivity,
    /// The upstream thread, where the application exposes one.
    pub thread_id: Option<String>,
    /// The upstream turn, where the application exposes one.
    pub turn_id: Option<String>,
    /// When these facts were last true, in milliseconds since the Unix epoch.
    pub updated_at_ms: u64,
    /// The rights the current actor holds.
    ///
    /// A courtesy, so a component can present controls that will work. The broker rechecks every
    /// right at dispatch, so a component that ignores this only produces controls that then fail.
    pub held_rights: Vec<ActionRight>,
}

/// What a bound execution is doing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BindingActivity {
    /// Nothing is running.
    #[default]
    Idle,
    /// A turn is running.
    Running,
    /// The upstream is waiting for a person.
    AwaitingPerson,
    /// The execution has ended.
    Ended,
}

impl BindingActivity {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Running => "running",
            Self::AwaitingPerson => "awaiting_person",
            Self::Ended => "ended",
        }
    }
}

/// One completed attachment, as the host holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentFact {
    /// The attachment identifier.
    pub attachment_id: String,
    /// The name a person gave it.
    pub name: String,
    /// The declared media type.
    pub media_type: String,
    /// The transferred size.
    pub size_bytes: u64,
    /// When the transfer completed, in milliseconds since the Unix epoch.
    pub completed_at_ms: u64,
}

/// Turns the facts a worker sent into the facts a component reads.
#[must_use]
pub fn facts_of(facts: &WireFacts) -> BindingFacts {
    BindingFacts {
        plugin_id: facts.plugin_id.clone(),
        binding_revision: facts.binding_revision,
        activity: activity_of(&facts.activity),
        thread_id: facts.thread_id.clone(),
        turn_id: facts.turn_id.clone(),
        updated_at_ms: facts.updated_at_ms,
        held_rights: facts.held_rights.clone(),
    }
}

/// Turns the facts a component reads into the facts that travel.
#[must_use]
pub fn wire_facts(facts: &BindingFacts) -> WireFacts {
    WireFacts {
        plugin_id: facts.plugin_id.clone(),
        binding_revision: facts.binding_revision,
        activity: facts.activity.as_str().to_owned(),
        thread_id: facts.thread_id.clone(),
        turn_id: facts.turn_id.clone(),
        updated_at_ms: facts.updated_at_ms,
        held_rights: facts.held_rights.clone(),
    }
}

/// Reads an activity name, treating anything unrecognised as idle.
///
/// An activity is presentation, not authority: a name this host does not know means the component
/// is told the execution is idle rather than being told something invented.
fn activity_of(name: &str) -> BindingActivity {
    match name {
        "running" => BindingActivity::Running,
        "awaiting_person" => BindingActivity::AwaitingPerson,
        "ended" => BindingActivity::Ended,
        _ => BindingActivity::Idle,
    }
}

/// Turns an event that travelled into one a component can be given.
///
/// # Errors
///
/// Returns the reason the event was refused: an unrecognised provenance. Provenance decides whether
/// an event can establish native approval authority, so a name this host does not know is a refusal
/// rather than a default.
pub fn event_of(event: &WireSourceEvent) -> Result<ScopedSourceEvent, String> {
    let provenance = SourceProvenance::from_wire(&event.provenance).ok_or_else(|| {
        format!(
            "{} is not a provenance this host knows, and provenance decides what an event can establish",
            event.provenance
        )
    })?;
    Ok(ScopedSourceEvent::new(
        event.handle.clone(),
        provenance,
        event.observed_at_ms,
        event.request_id.clone(),
        event.bytes.clone(),
    ))
}

/// Turns an event a host holds into one that travels.
#[must_use]
pub fn wire_event(event: &ScopedSourceEvent) -> WireSourceEvent {
    WireSourceEvent {
        handle: event.handle.clone(),
        provenance: event.provenance.as_str().to_owned(),
        observed_at_ms: event.observed_at_ms,
        request_id: event.request_id.clone(),
        bytes: event.bytes.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle(text: &str) -> SourceEventHandle {
        SourceEventHandle::new(text).expect("a handle within the identifier bound")
    }

    fn wire() -> WireFacts {
        WireFacts {
            plugin_id: "kalareach/example".to_owned(),
            binding_revision: 5,
            activity: "running".to_owned(),
            thread_id: Some("t".to_owned()),
            turn_id: None,
            updated_at_ms: 9,
            held_rights: vec![ActionRight::SessionView],
        }
    }

    #[test]
    fn only_a_native_protocol_event_can_establish_native_authority() {
        assert!(SourceProvenance::NativeProtocol.establishes_native_authority());
        assert!(!SourceProvenance::MachineOutput.establishes_native_authority());
        assert!(!SourceProvenance::TerminalScrape.establishes_native_authority());
    }

    #[test]
    fn a_native_request_is_authoritative_and_a_scrape_is_not() {
        let request = ScopedSourceEvent::new(
            handle("se-1"),
            SourceProvenance::NativeProtocol,
            7,
            Some("req-1".to_owned()),
            b"{}".to_vec(),
        );
        let scrape = ScopedSourceEvent::new(
            handle("se-2"),
            SourceProvenance::TerminalScrape,
            7,
            None,
            b"$ ls".to_vec(),
        );
        assert!(request.is_authoritative());
        assert!(!scrape.is_authoritative());
    }

    #[test]
    fn queue_bytes_counts_the_handle_so_empty_events_are_not_free() {
        let event = ScopedSourceEvent::new(
            handle("se-1"),
            SourceProvenance::MachineOutput,
            7,
            None,
            Vec::new(),
        );
        assert_eq!(event.queue_bytes(), 4);
    }

    #[test]
    fn provenance_round_trips_through_its_wire_string() {
        for provenance in [
            SourceProvenance::NativeProtocol,
            SourceProvenance::MachineOutput,
            SourceProvenance::TerminalScrape,
        ] {
            assert_eq!(
                SourceProvenance::from_wire(provenance.as_str()),
                Some(provenance)
            );
        }
        assert!(SourceProvenance::from_wire("guessed").is_none());
    }

    #[test]
    fn the_facts_round_trip_through_the_wire() {
        let facts = facts_of(&wire());
        assert_eq!(facts.activity, BindingActivity::Running);
        assert_eq!(wire_facts(&facts), wire());
    }

    #[test]
    fn an_activity_this_host_does_not_know_reads_as_idle() {
        let mut wire = wire();
        wire.activity = "thinking-hard".to_owned();
        assert_eq!(facts_of(&wire).activity, BindingActivity::Idle);
    }

    #[test]
    fn a_provenance_this_host_does_not_know_is_refused() {
        let event = WireSourceEvent {
            handle: handle("se-1"),
            provenance: "trustworthy".to_owned(),
            observed_at_ms: 1,
            request_id: None,
            bytes: b"{}".to_vec(),
        };
        let error = event_of(&event).expect_err("an unknown provenance is refused");
        assert!(error.contains("trustworthy"));
        assert!(error.contains("provenance decides"));
    }

    #[test]
    fn an_event_round_trips_through_the_wire() {
        let event = WireSourceEvent {
            handle: handle("se-1"),
            provenance: "native_protocol".to_owned(),
            observed_at_ms: 1,
            request_id: Some("req-1".to_owned()),
            bytes: b"{}".to_vec(),
        };
        let scoped = event_of(&event).expect("the event is admitted");
        assert!(scoped.is_authoritative());
        assert_eq!(wire_event(&scoped), event);
    }
}
