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
/// It is written inside the transaction that made the transition true, so a crash between them is
/// not a state this host can reach. The write can still fail on its own account - the store can be
/// full, and the identifier has a uniqueness constraint - and when it does the transition goes
/// back with it.
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
/// At-least-once delivery means a consumer can be handed a record it has already applied. Two
/// things close that window, and both are needed.
///
/// * **The cursor is durable.** A redelivery starts at the cursor the consumer last recorded, so
///   the replayable range is bounded by what it has not yet recorded as taken.
/// * **The remembered identifiers cover a whole page.** They are process memory, so a consumer
///   that restarts remembers nothing and is handed its page again; what they close is the window
///   *within* one process, between applying a record and recording the cursor past it. Because
///   [`MAX_OUTBOX_PAGE`] is no larger than this figure, a replayed page can never displace an
///   identifier the same page still needs.
///
/// Neither makes an effect outside this host idempotent. That is the destination's own property,
/// and a consumer whose effect leaves the host has to establish it there.
pub const REMEMBERED_EVENT_IDS: usize = 256;

/// The most records one page of the outbox carries.
///
/// It is bounded by what a consumer can remember, so a page cannot outrun the de-duplication
/// window that covers it.
pub const MAX_OUTBOX_PAGE: u64 = REMEMBERED_EVENT_IDS as u64;

/// A consumer's de-duplication of the page it is handed, within one process.
///
/// The order is the contract. [`Self::fresh`] says what has not been applied and remembers
/// nothing; [`Self::note_applied`] is called *after* the effect, and is what makes the next
/// answer different. A helper that remembered a record before its effect ran would suppress it
/// after the effect failed, which is the one thing at-least-once delivery exists to prevent.
///
/// **What this does not do**, stated because the difference decides whether a consumer is
/// correct. It is process memory, so a consumer that applies a record and then dies before
/// recording its cursor is handed that record again and applies it again. Closing *that* window
/// needs the de-duplication record committed in the same transaction as the effect, which only
/// the consumer can do because only the consumer's store holds the effect. A consumer whose
/// effect leaves this host cannot do even that, and needs the destination to be idempotent.
///
/// So this helper covers one thing exactly: the page in hand. A consumer records its cursor
/// before it asks for the next page, and what this stops is the same page being applied twice
/// inside one process.
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

    /// Rebuilds a fan-out from the identifiers a consumer last held.
    #[must_use]
    pub fn resumed(seen: impl IntoIterator<Item = Uuid>) -> Self {
        let mut fanout = Self::default();
        for id in seen {
            fanout.remember(id);
        }
        fanout
    }

    /// Returns the records this consumer has not recorded as applied, and counts the rest.
    ///
    /// Nothing is remembered here. A record this returns is one the consumer still has to apply,
    /// and it stays that way until [`Self::note_applied`] says otherwise.
    pub fn fresh<'a>(&mut self, page: &'a [OutboxRecord]) -> Vec<&'a OutboxRecord> {
        let mut fresh = Vec::new();
        for record in page {
            if self.seen.contains(&record.event.event_id) {
                self.suppressed += 1;
                continue;
            }
            fresh.push(record);
        }
        fresh
    }

    /// Records that one record's effect has been applied.
    pub fn note_applied(&mut self, record: &OutboxRecord) {
        if self.seen.contains(&record.event.event_id) {
            return;
        }
        self.remember(record.event.event_id);
        self.applied += 1;
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

    /// Applies a page the way a consumer does: take what is fresh, do the work, then say so.
    fn apply(fanout: &mut Fanout, page: &[OutboxRecord]) -> Vec<u8> {
        let fresh: Vec<OutboxRecord> = fanout.fresh(page).into_iter().cloned().collect();
        let mut applied = Vec::new();
        for record in &fresh {
            applied.push(record.event.event_id.as_bytes()[0]);
            fanout.note_applied(record);
        }
        applied
    }

    #[test]
    fn a_redelivered_page_is_applied_once() {
        let mut fanout = Fanout::new();
        let first = page(&[1, 2, 3]);
        assert_eq!(apply(&mut fanout, &first), vec![1, 2, 3]);
        // The cursor write is what failed, so the consumer is handed the same page again.
        assert!(apply(&mut fanout, &first).is_empty());
        assert_eq!(fanout.applied(), 3);
        assert_eq!(fanout.suppressed(), 3);
    }

    #[test]
    fn a_record_whose_effect_failed_is_offered_again_rather_than_suppressed() {
        let mut fanout = Fanout::new();
        let first = page(&[1, 2, 3]);
        // The consumer applies the first two and fails on the third.
        let fresh: Vec<OutboxRecord> = fanout.fresh(&first).into_iter().cloned().collect();
        for record in fresh.iter().take(2) {
            fanout.note_applied(record);
        }
        let again: Vec<u8> = fanout
            .fresh(&first)
            .into_iter()
            .map(|record| record.event.event_id.as_bytes()[0])
            .collect();
        assert_eq!(again, vec![3], "the failed effect is still owed");
    }

    #[test]
    fn a_page_that_overlaps_the_previous_one_applies_only_what_is_new() {
        let mut fanout = Fanout::new();
        apply(&mut fanout, &page(&[1, 2, 3]));
        assert_eq!(apply(&mut fanout, &page(&[2, 3, 4, 5])), vec![4, 5]);
    }

    #[test]
    fn a_consumer_resumes_from_the_identifiers_it_held() {
        let mut fanout = Fanout::new();
        let first = page(&[1, 2, 3]);
        apply(&mut fanout, &first);
        let mut resumed = Fanout::resumed(fanout.remembered());
        assert!(apply(&mut resumed, &first).is_empty());
    }

    #[test]
    fn a_whole_page_of_redeliveries_never_displaces_a_name_that_page_still_needs() {
        // The window is what covers one page, so a page at the bound that is replayed entire
        // suppresses every record in it rather than letting the newest evict the oldest.
        let bytes: Vec<u8> = (0..REMEMBERED_EVENT_IDS as u16).map(|v| v as u8).collect();
        let full: Vec<OutboxRecord> = bytes
            .iter()
            .enumerate()
            .map(|(index, byte)| OutboxRecord {
                cursor: index as u64 + 1,
                event: event(*byte),
            })
            .collect();
        assert_eq!(full.len() as u64, MAX_OUTBOX_PAGE);
        let mut fanout = Fanout::new();
        assert_eq!(apply(&mut fanout, &full).len(), full.len());
        assert_eq!(fanout.remembered().len(), REMEMBERED_EVENT_IDS);
        assert!(apply(&mut fanout, &full).is_empty());
        assert_eq!(fanout.applied() as usize, full.len());
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
