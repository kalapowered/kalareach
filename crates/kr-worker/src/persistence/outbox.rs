//! A state transition and its event, committed together, and the fan-out that follows.
//!
//! Section 24 makes an authoritative producer commit the state transition and a small event
//! record **in the same local transaction**. That is what stops the two disagreeing: a crash
//! between a receipt and the event announcing it would leave a consumer that never hears about a
//! state the host is already serving.
//!
//! What comes out of that transaction is an outbox, and what reads the outbox is a consumer with
//! a cursor of its own. Delivery is at-least-once: a consumer that takes a page and dies before
//! recording its cursor takes the same page again. Idempotency is the consumer's side of the same
//! bargain, and the immutable event identifier is what makes it possible.
//!
//! **No global cross-database total order is invented.** The cursor here orders this journal's own
//! events and nothing else. An event from the transfer journal and an event from this one are not
//! comparable, and nothing in this module pretends they are.

use kr_protocol::ids::{ActionId, ActorId};
use kr_protocol::recovery::EventStream;
use kr_protocol::scalars::{TimestampMs, Uuid};

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

/// What a producer commits beside its state transition.
///
/// Everything here is decided before the transaction opens, so committing it cannot fail for a
/// reason the transition would not have failed for.
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxRecord {
    /// This journal's own ordering of its events. It is not a global order.
    pub cursor: u64,
    /// The event.
    pub event: OutboxEvent,
}

/// Where one consumer has got to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutboxCursor {
    /// The consumer's stable name.
    pub consumer: String,
    /// The cursor after the last record this consumer recorded as taken.
    pub cursor: u64,
    /// How many records it has recorded as taken, over the life of this journal.
    pub delivered: u64,
}

/// How many event identifiers a consumer remembers for de-duplication.
///
/// At-least-once delivery means a consumer can be handed a record it has already applied. The
/// cursor alone does not settle it, because the failure that causes a redelivery is exactly the
/// one that lost the cursor write. Remembering the identifiers of the last page is what closes
/// that window, and the page is what a redelivery is bounded by.
pub const REMEMBERED_EVENT_IDS: usize = 256;

/// A consumer that applies each event once, however many times it is handed one.
///
/// This is the consumer's half of at-least-once delivery, and it is deliberately here rather than
/// in each consumer: a consumer that wrote its own would be a consumer that could get it wrong.
#[derive(Clone, Debug, Default)]
pub struct Fanout {
    seen: std::collections::VecDeque<Uuid>,
    applied: u64,
    suppressed: u64,
}

impl Fanout {
    /// Builds a fan-out that has seen nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuilds a fan-out from the identifiers a consumer last recorded.
    #[must_use]
    pub fn resumed(seen: impl IntoIterator<Item = Uuid>) -> Self {
        let mut fanout = Self::default();
        for id in seen {
            fanout.remember(id);
        }
        fanout
    }

    /// Returns the records this consumer has not already applied, and counts the rest.
    pub fn accept<'a>(&mut self, page: &'a [OutboxRecord]) -> Vec<&'a OutboxRecord> {
        let mut fresh = Vec::new();
        for record in page {
            if self.seen.contains(&record.event.event_id) {
                self.suppressed += 1;
                continue;
            }
            self.remember(record.event.event_id);
            self.applied += 1;
            fresh.push(record);
        }
        fresh
    }

    /// Returns the identifiers this consumer remembers, oldest first.
    #[must_use]
    pub fn remembered(&self) -> Vec<Uuid> {
        self.seen.iter().copied().collect()
    }

    /// Returns how many records this consumer applied.
    #[must_use]
    pub const fn applied(&self) -> u64 {
        self.applied
    }

    /// Returns how many redeliveries this consumer suppressed.
    #[must_use]
    pub const fn suppressed(&self) -> u64 {
        self.suppressed
    }

    fn remember(&mut self, id: Uuid) {
        self.seen.push_back(id);
        while self.seen.len() > REMEMBERED_EVENT_IDS {
            self.seen.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(byte: u8) -> OutboxEvent {
        OutboxEvent {
            event_id: Uuid::from_bytes([byte; 16]),
            stream: EventStream::Receipts,
            source: Subsystem::Receipts,
            actor_id: None,
            action_id: None,
            subject_revision: u64::from(byte),
            causal_root: None,
            causal_parent: None,
            content: ContentClass::Metadata,
            detail: "accepted".to_owned(),
            recorded_at_ms: TimestampMs::new(u64::from(byte)),
        }
    }

    fn page(bytes: &[u8]) -> Vec<OutboxRecord> {
        bytes
            .iter()
            .enumerate()
            .map(|(index, byte)| OutboxRecord {
                cursor: index as u64 + 1,
                event: event(*byte),
            })
            .collect()
    }

    #[test]
    fn a_redelivered_page_is_applied_once() {
        let mut fanout = Fanout::new();
        let first = page(&[1, 2, 3]);
        assert_eq!(fanout.accept(&first).len(), 3);
        // The consumer died before it recorded its cursor, so it is handed the same page again.
        assert!(fanout.accept(&first).is_empty());
        assert_eq!(fanout.applied(), 3);
        assert_eq!(fanout.suppressed(), 3);
    }

    #[test]
    fn a_page_that_overlaps_the_previous_one_applies_only_what_is_new() {
        let mut fanout = Fanout::new();
        fanout.accept(&page(&[1, 2, 3]));
        let overlapping = page(&[2, 3, 4, 5]);
        let fresh: Vec<u8> = fanout
            .accept(&overlapping)
            .into_iter()
            .map(|record| record.event.event_id.as_bytes()[0])
            .collect();
        assert_eq!(fresh, vec![4, 5]);
    }

    #[test]
    fn a_consumer_resumes_from_the_identifiers_it_recorded() {
        let mut fanout = Fanout::new();
        let first = page(&[1, 2, 3]);
        fanout.accept(&first);
        let resumed = Fanout::resumed(fanout.remembered());
        let mut resumed = resumed;
        assert!(resumed.accept(&first).is_empty());
    }

    #[test]
    fn what_a_consumer_remembers_is_bounded() {
        let mut fanout = Fanout::new();
        for byte in 0..=255u8 {
            fanout.accept(&page(&[byte]));
        }
        assert_eq!(fanout.remembered().len(), REMEMBERED_EVENT_IDS);
        for byte in 0..=255u8 {
            fanout.accept(&page(&[byte]));
        }
        // Everything still fits inside what is remembered, so nothing was applied twice.
        assert_eq!(fanout.applied(), 256);
    }

    #[test]
    fn a_cursor_orders_this_journals_events_and_says_nothing_about_another_store() {
        let records = page(&[1, 2, 3]);
        let cursors: Vec<u64> = records.iter().map(|record| record.cursor).collect();
        assert_eq!(cursors, vec![1, 2, 3]);
        // The record carries no field that would let it be ordered against another store's, which
        // is the point: section 24 forbids inventing a global cross-database total order.
        let record = &records[0];
        assert_eq!(record.event.source, Subsystem::Receipts);
        assert_eq!(record.event.content, ContentClass::Metadata);
    }
}
