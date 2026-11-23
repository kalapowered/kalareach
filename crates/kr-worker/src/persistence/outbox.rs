//! A state transition and its event, committed together.
//!
//! Section 24 makes an authoritative producer commit the state transition and a small event
//! record **in the same local transaction**. That is what stops the two disagreeing: a crash
//! between a receipt and the event announcing it would leave a consumer that never hears about a
//! state the host is already serving.
//!
//! What comes out of that transaction is an outbox. This worker only produces it: no consumer
//! reads it here, so a journal with no registered consumer owes nothing and collects its outbox by
//! age. A cursor an earlier build recorded for a consumer still holds back the rows it has not
//! passed.
//!
//! **No global cross-database total order is invented.** The row's cursor orders this journal's
//! own events and nothing else. An event from the transfer journal and an event from this one are
//! not comparable, and nothing in this module pretends they are.

#[cfg(any(test, feature = "testing"))]
use kr_protocol::ids::{ActionId, ActorId};
#[cfg(any(test, feature = "testing"))]
use kr_protocol::recovery::EventStream;
#[cfg(any(test, feature = "testing"))]
use kr_protocol::scalars::{TimestampMs, Uuid};

#[cfg(any(test, feature = "testing"))]
use crate::persistence::stores::ContentClass;

/// Which part of the worker produced an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Subsystem {
    /// The session's own lifecycle.
    Session,
    /// The receipt journal.
    Receipts,
    /// The question ledger.
    Questions,
    /// Attachments and the input lease.
    Attachments,
    /// Retained output.
    History,
}

impl Subsystem {
    /// Returns the stable name this subsystem is recorded under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Receipts => "receipts",
            Self::Questions => "questions",
            Self::Attachments => "attachments",
            Self::History => "history",
        }
    }

    /// Returns the subsystem a stored name refers to.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn from_stored(value: &str) -> Option<Self> {
        match value {
            "session" => Some(Self::Session),
            "receipts" => Some(Self::Receipts),
            "questions" => Some(Self::Questions),
            "attachments" => Some(Self::Attachments),
            "history" => Some(Self::History),
            _ => None,
        }
    }
}

/// What a producer commits beside its state transition, as a test reads it back.
///
/// It is written inside the transaction that made the transition true, so a crash between them is
/// not a state this host can reach. The write can still fail on its own account - the store can be
/// full, and the identifier has a uniqueness constraint - and when it does the transition goes
/// back with it.
#[cfg(any(test, feature = "testing"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxEvent {
    /// The event's immutable identity. A redelivery carries the same one.
    pub event_id: Uuid,
    /// Which stream a subscriber reads it from.
    pub stream: EventStream,
    /// The subsystem that produced it.
    pub source: Subsystem,
    /// The actor whose action it was, when there is one.
    pub actor_id: Option<ActorId>,
    /// The action it belongs to, when there is one.
    pub action_id: Option<ActionId>,
    /// The revision of the subject or binding the event describes.
    pub subject_revision: u64,
    /// The root of the causal chain this event belongs to.
    pub causal_root: Option<Uuid>,
    /// The event this one followed from.
    pub causal_parent: Option<Uuid>,
    /// What class of content it carries.
    pub content: ContentClass,
    /// The event body, as metadata rather than as content.
    pub detail: String,
    /// When the producer recorded it.
    pub recorded_at_ms: TimestampMs,
}

/// One outbox row, as the store holds it.
#[cfg(any(test, feature = "testing"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxRecord {
    /// This journal's own ordering of its events. It is not a global order.
    pub cursor: u64,
    /// The event.
    pub event: OutboxEvent,
}
