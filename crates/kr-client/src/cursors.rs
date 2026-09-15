//! Cursors, receipts, and the order a client restores state in.
//!
//! Section 8: a client subscribes from a cursor *before* it installs the snapshot. The worker
//! returns state at cursor N and queues subsequent updates after N; if the bounded replay window
//! has a gap, the client discards its partial state and installs a new snapshot. Section 23 adds
//! the other half: reconnect creates a new connection identity and input stream, old raw input is
//! never replayed, and the client restores state through cursors and receipts.
//!
//! [`StreamCursors`] is the bookkeeping; [`Restoration`] is the order. Keeping the order in a type
//! rather than in a comment is the point: subscribing after installing a snapshot loses every event
//! in between, and the mistake is invisible until a user sees a stale screen.

use std::collections::BTreeMap;

use kr_protocol::envelope::Notification;
use kr_protocol::ids::{ActionId, EventSequence, StreamId};
use kr_protocol::receipt::{Receipt, ReceiptState};

/// The position a client has consumed on each subscribed stream.
#[derive(Clone, Debug, Default)]
pub struct StreamCursors {
    positions: BTreeMap<StreamId, EventSequence>,
}

impl StreamCursors {
    /// Creates an empty set of cursors.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the cursor this client has reached on `stream_id`.
    #[must_use]
    pub fn position(&self, stream_id: &StreamId) -> Option<EventSequence> {
        self.positions.get(stream_id).copied()
    }

    /// Records one delivered event, returning whether it was the next one.
    ///
    /// An event that is not the next one is a gap. The caller discards its partial state and
    /// installs a fresh snapshot rather than applying an update whose base it never saw.
    pub fn accept(&mut self, notification: &Notification) -> Delivery {
        let next = self
            .positions
            .get(&notification.stream_id)
            .map_or(0, |position| position.get().saturating_add(1));
        let sequence = notification.sequence.get();
        if sequence < next {
            // Already applied. A duplicate is not a gap and is not an error.
            return Delivery::Duplicate;
        }
        if self.positions.contains_key(&notification.stream_id) && sequence > next {
            return Delivery::Gap {
                expected: EventSequence::new(next),
                received: notification.sequence,
            };
        }
        self.positions
            .insert(notification.stream_id.clone(), notification.sequence);
        Delivery::Applied
    }

    /// Forgets a stream, which is what a resynchronisation requirement means.
    pub fn discard(&mut self, stream_id: &StreamId) {
        self.positions.remove(stream_id);
    }

    /// Forgets every stream.
    pub fn discard_all(&mut self) {
        self.positions.clear();
    }

    /// Returns how many streams are tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.positions.len()
    }

    /// Returns true when nothing is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.positions.is_empty()
    }
}

/// What happened to one delivered event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// The event was the next one and has been applied.
    Applied,
    /// The event had already been applied.
    Duplicate,
    /// An event is missing. The client's state for this stream is no longer usable.
    Gap {
        /// The sequence that was expected next.
        expected: EventSequence,
        /// The sequence that arrived.
        received: EventSequence,
    },
}

/// The steps of restoring one stream, in the only order that is correct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestorationStep {
    /// Subscribe from this cursor. Nothing has been installed yet.
    SubscribeFrom(EventSequence),
    /// Subscribe from the beginning, because this client has no position on the stream.
    SubscribeFromStart,
    /// Install the snapshot the subscription returned, then apply the queued updates.
    InstallSnapshot,
    /// Done: the stream is live.
    Live,
}

/// Drives one stream through the restoration order.
#[derive(Clone, Debug)]
pub struct Restoration {
    stream_id: StreamId,
    step: RestorationStep,
}

impl Restoration {
    /// Starts a restoration from whatever this client already has.
    #[must_use]
    pub fn start(stream_id: StreamId, cursors: &StreamCursors) -> Self {
        let step = match cursors.position(&stream_id) {
            Some(position) => RestorationStep::SubscribeFrom(position),
            None => RestorationStep::SubscribeFromStart,
        };
        Self { stream_id, step }
    }

    /// Returns the stream being restored.
    #[must_use]
    pub const fn stream_id(&self) -> &StreamId {
        &self.stream_id
    }

    /// Returns the step to perform now.
    #[must_use]
    pub const fn step(&self) -> RestorationStep {
        self.step
    }

    /// Records that the subscription succeeded.
    pub fn subscribed(&mut self) {
        self.step = RestorationStep::InstallSnapshot;
    }

    /// Records that the snapshot was installed.
    pub fn installed(&mut self) {
        self.step = RestorationStep::Live;
    }

    /// Records that the host required a resynchronisation.
    ///
    /// The partial state is discarded and the restoration starts again from the beginning, which
    /// is what section 8 requires when the bounded replay window has a gap.
    pub fn resynchronise(&mut self, cursors: &mut StreamCursors) {
        cursors.discard(&self.stream_id);
        self.step = RestorationStep::SubscribeFromStart;
    }

    /// Returns true once the stream is live.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.step == RestorationStep::Live
    }
}

/// The receipts this client is waiting on or has seen.
///
/// A receipt has a monotonically increasing revision, and a duplicate request returns the latest
/// authorised revision while it evolves. The tracker keeps the latest revision of each action, so
/// a client that reconnects can tell which of its actions are still unresolved, and never
/// redispatches one whose receipt is incomplete.
#[derive(Clone, Debug, Default)]
pub struct ReceiptTracker {
    receipts: BTreeMap<ActionId, Receipt>,
}

impl ReceiptTracker {
    /// Creates an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a receipt, keeping the higher revision.
    ///
    /// An older revision is ignored: a receipt only moves forward, and a late frame from a
    /// previous connection must not undo what a newer one said.
    pub fn record(&mut self, receipt: Receipt) {
        match self.receipts.get(&receipt.action_id) {
            Some(current) if current.revision >= receipt.revision => {}
            _ => {
                self.receipts.insert(receipt.action_id, receipt);
            }
        }
    }

    /// Returns the latest receipt of one action.
    #[must_use]
    pub fn get(&self, action_id: &ActionId) -> Option<&Receipt> {
        self.receipts.get(action_id)
    }

    /// Returns the actions whose outcome is not yet terminal.
    ///
    /// These are what a reconnecting client asks about. It never redispatches them: section 9 says
    /// an action identifier is never dispatched again simply because its receipt is incomplete.
    #[must_use]
    pub fn unresolved(&self) -> Vec<ActionId> {
        self.receipts
            .values()
            .filter(|receipt| !receipt.state.is_terminal())
            .map(|receipt| receipt.action_id)
            .collect()
    }

    /// Returns the actions whose dispatch may have happened but whose outcome is unknown.
    ///
    /// A client shows these as uncertain rather than as failed, because section 9 forbids implying
    /// that an uncertain side effect did not happen.
    #[must_use]
    pub fn unknown(&self) -> Vec<ActionId> {
        self.receipts
            .values()
            .filter(|receipt| receipt.state == ReceiptState::Unknown)
            .map(|receipt| receipt.action_id)
            .collect()
    }

    /// Returns how many actions are tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    /// Returns true when nothing is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::envelope::ParamsValue;
    use kr_protocol::ids::{ActionId, EventType};
    use kr_protocol::method::{Method, MethodVersion};
    use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};

    fn stream(name: &str) -> StreamId {
        StreamId::new(name).expect("a stream identifier")
    }

    fn event(stream_id: &StreamId, sequence: u64) -> Notification {
        Notification {
            stream_id: stream_id.clone(),
            sequence: EventSequence::new(sequence),
            event_type: EventType::new("terminal.output").expect("an event type"),
            payload: ParamsValue::empty(),
        }
    }

    #[test]
    fn events_apply_in_order_and_a_gap_is_visible() {
        let mut cursors = StreamCursors::new();
        let stream_id = stream("session:1");
        assert_eq!(cursors.accept(&event(&stream_id, 4)), Delivery::Applied);
        assert_eq!(cursors.accept(&event(&stream_id, 5)), Delivery::Applied);
        assert_eq!(cursors.accept(&event(&stream_id, 5)), Delivery::Duplicate);
        assert_eq!(
            cursors.accept(&event(&stream_id, 9)),
            Delivery::Gap {
                expected: EventSequence::new(6),
                received: EventSequence::new(9),
            }
        );
        assert_eq!(cursors.position(&stream_id), Some(EventSequence::new(5)));
    }

    #[test]
    fn a_restoration_subscribes_before_it_installs_a_snapshot() {
        let mut cursors = StreamCursors::new();
        let stream_id = stream("session:1");
        cursors.accept(&event(&stream_id, 7));

        let mut restoration = Restoration::start(stream_id.clone(), &cursors);
        assert_eq!(
            restoration.step(),
            RestorationStep::SubscribeFrom(EventSequence::new(7))
        );
        restoration.subscribed();
        assert_eq!(restoration.step(), RestorationStep::InstallSnapshot);
        restoration.installed();
        assert!(restoration.is_live());
    }

    #[test]
    fn a_first_restoration_subscribes_from_the_start() {
        let cursors = StreamCursors::new();
        let restoration = Restoration::start(stream("session:1"), &cursors);
        assert_eq!(restoration.step(), RestorationStep::SubscribeFromStart);
    }

    #[test]
    fn a_resynchronisation_discards_the_partial_state_and_starts_again() {
        let mut cursors = StreamCursors::new();
        let stream_id = stream("session:1");
        cursors.accept(&event(&stream_id, 7));
        let mut restoration = Restoration::start(stream_id.clone(), &cursors);
        restoration.subscribed();

        restoration.resynchronise(&mut cursors);
        assert_eq!(restoration.step(), RestorationStep::SubscribeFromStart);
        assert_eq!(cursors.position(&stream_id), None);
        assert!(cursors.is_empty());
    }

    fn receipt(action: u8, revision: u64, state: ReceiptState) -> Receipt {
        Receipt {
            action_id: ActionId::new(Uuid::from_bytes([action; 16])),
            actor_id: kr_protocol::ids::ActorId::new("device:test").expect("a principal"),
            method: Method::SessionCreate.into(),
            method_version: MethodVersion::V1,
            revision: U64::new(revision),
            state,
            reason: Nullable::null(),
            payload_digest: Digest256::from_bytes([0; 32]),
            accepted_deadline_ms: Nullable::null(),
            error: Nullable::null(),
            updated_at_ms: TimestampMs::new(0),
        }
    }

    #[test]
    fn a_receipt_only_moves_forward() {
        let mut tracker = ReceiptTracker::new();
        tracker.record(receipt(1, 2, ReceiptState::Dispatching));
        tracker.record(receipt(1, 1, ReceiptState::Accepted));
        assert_eq!(
            tracker
                .get(&ActionId::new(Uuid::from_bytes([1; 16])))
                .map(|receipt| receipt.state),
            Some(ReceiptState::Dispatching)
        );
        tracker.record(receipt(1, 3, ReceiptState::Applied));
        assert_eq!(
            tracker
                .get(&ActionId::new(Uuid::from_bytes([1; 16])))
                .map(|receipt| receipt.state),
            Some(ReceiptState::Applied)
        );
    }

    #[test]
    fn a_reconnecting_client_can_see_what_is_unresolved_and_what_is_uncertain() {
        let mut tracker = ReceiptTracker::new();
        tracker.record(receipt(1, 1, ReceiptState::Applied));
        tracker.record(receipt(2, 1, ReceiptState::Dispatching));
        tracker.record(receipt(3, 1, ReceiptState::Unknown));
        assert_eq!(tracker.len(), 3);
        // An unknown outcome is unresolved: section 9 forbids treating it as settled.
        assert_eq!(
            tracker.unresolved(),
            vec![
                ActionId::new(Uuid::from_bytes([2; 16])),
                ActionId::new(Uuid::from_bytes([3; 16])),
            ]
        );
        assert_eq!(
            tracker.unknown(),
            vec![ActionId::new(Uuid::from_bytes([3; 16]))]
        );
    }
}
