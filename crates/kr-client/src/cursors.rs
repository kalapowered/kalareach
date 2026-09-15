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

/// What a client has received and what it has actually applied, per subscribed stream.
///
/// The two are not the same, and a restoration that confuses them loses events. A notification is
/// *received* when it arrives on the connection; it is *applied* when whatever consumes the stream
/// has folded it into its state. A reconnect subscribes from the applied position, because an event
/// that was received and never applied has to arrive again.
#[derive(Clone, Debug, Default)]
pub struct StreamCursors {
    received: BTreeMap<StreamId, EventSequence>,
    applied: BTreeMap<StreamId, EventSequence>,
    /// Streams whose partial state is no longer usable. They need a snapshot before anything else.
    needs_snapshot: std::collections::BTreeSet<StreamId>,
}

impl StreamCursors {
    /// Creates an empty set of cursors.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the position a consumer has applied on `stream_id`.
    ///
    /// This is the position a restoration subscribes from. `None` means nothing usable is held.
    #[must_use]
    pub fn position(&self, stream_id: &StreamId) -> Option<EventSequence> {
        if self.needs_snapshot.contains(stream_id) {
            return None;
        }
        self.applied.get(stream_id).copied()
    }

    /// Returns the last position received on `stream_id`, applied or not.
    #[must_use]
    pub fn received(&self, stream_id: &StreamId) -> Option<EventSequence> {
        self.received.get(stream_id).copied()
    }

    /// Returns true when this stream needs a fresh snapshot before it is usable.
    #[must_use]
    pub fn needs_snapshot(&self, stream_id: &StreamId) -> bool {
        self.needs_snapshot.contains(stream_id)
    }

    /// Records one delivered event, returning whether it was the next one.
    ///
    /// An event that is not the next one is a gap: the stream is marked as needing a snapshot, so
    /// no later event can quietly establish a new position on top of state that has a hole in it.
    pub fn accept(&mut self, notification: &Notification) -> Delivery {
        let stream_id = &notification.stream_id;
        let sequence = notification.sequence.get();
        if self.needs_snapshot.contains(stream_id) {
            // Nothing is tracked while a snapshot is owed; the events are still delivered, because
            // a consumer that is rebuilding wants to see them, but they establish no position.
            return Delivery::NeedsSnapshot;
        }
        let next = self
            .received
            .get(stream_id)
            .map_or(0, |position| position.get().saturating_add(1));
        if self.received.contains_key(stream_id) && sequence < next {
            return Delivery::Duplicate;
        }
        if self.received.contains_key(stream_id) && sequence > next {
            self.needs_snapshot.insert(stream_id.clone());
            self.received.remove(stream_id);
            self.applied.remove(stream_id);
            return Delivery::Gap {
                expected: EventSequence::new(next),
                received: notification.sequence,
            };
        }
        self.received
            .insert(stream_id.clone(), notification.sequence);
        Delivery::Received
    }

    /// Records that a consumer applied everything up to `sequence` on `stream_id`.
    ///
    /// Only this moves the position a reconnect subscribes from.
    pub fn applied(&mut self, stream_id: &StreamId, sequence: EventSequence) {
        if self.needs_snapshot.contains(stream_id) {
            return;
        }
        let current = self
            .applied
            .get(stream_id)
            .map_or(0, |position| position.get());
        if sequence.get() > current {
            self.applied.insert(stream_id.clone(), sequence);
        }
    }

    /// Records that a snapshot at `sequence` was installed, which makes the stream usable again.
    pub fn installed_snapshot(&mut self, stream_id: &StreamId, sequence: EventSequence) {
        self.needs_snapshot.remove(stream_id);
        self.received.insert(stream_id.clone(), sequence);
        self.applied.insert(stream_id.clone(), sequence);
    }

    /// Discards a stream's state and marks it as needing a snapshot.
    ///
    /// This is what a resynchronisation requirement means, and what a gap does.
    pub fn discard(&mut self, stream_id: &StreamId) {
        self.received.remove(stream_id);
        self.applied.remove(stream_id);
        self.needs_snapshot.insert(stream_id.clone());
    }

    /// Forgets every stream, holding none of them to a snapshot.
    pub fn discard_all(&mut self) {
        self.received.clear();
        self.applied.clear();
        self.needs_snapshot.clear();
    }

    /// Returns how many streams hold a usable position.
    #[must_use]
    pub fn len(&self) -> usize {
        self.applied.len()
    }

    /// Returns true when no stream holds a usable position.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.applied.is_empty()
    }
}

/// What happened to one delivered event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// The event was the next one on the stream and has been recorded as received.
    Received,
    /// The event had already been received.
    Duplicate,
    /// The stream is waiting for a snapshot, so the event establishes no position.
    NeedsSnapshot,
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

/// A restoration step taken out of order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the stream is at {step:?} and cannot take that step")]
pub struct OutOfOrder {
    /// The step the stream is actually at.
    pub step: RestorationStep,
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
    ///
    /// # Errors
    ///
    /// Returns [`OutOfOrder`] when the stream is not waiting to subscribe.
    pub fn subscribed(&mut self) -> std::result::Result<(), OutOfOrder> {
        match self.step {
            RestorationStep::SubscribeFrom(_) | RestorationStep::SubscribeFromStart => {
                self.step = RestorationStep::InstallSnapshot;
                Ok(())
            }
            step => Err(OutOfOrder { step }),
        }
    }

    /// Records that the snapshot was installed.
    ///
    /// # Errors
    ///
    /// Returns [`OutOfOrder`] when the stream has not subscribed yet. Section 8 requires the
    /// subscription first: installing a snapshot before subscribing loses every event in between,
    /// and the mistake is invisible until a user sees a stale screen.
    pub fn installed(&mut self) -> std::result::Result<(), OutOfOrder> {
        if self.step == RestorationStep::InstallSnapshot {
            self.step = RestorationStep::Live;
            Ok(())
        } else {
            Err(OutOfOrder { step: self.step })
        }
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
    fn events_arrive_in_order_and_a_gap_stops_the_stream() {
        let mut cursors = StreamCursors::new();
        let stream_id = stream("session:1");
        assert_eq!(cursors.accept(&event(&stream_id, 4)), Delivery::Received);
        assert_eq!(cursors.accept(&event(&stream_id, 5)), Delivery::Received);
        assert_eq!(cursors.accept(&event(&stream_id, 5)), Delivery::Duplicate);
        assert_eq!(cursors.received(&stream_id), Some(EventSequence::new(5)));

        // Receiving is not applying: nothing is subscribed from until a consumer says so.
        assert_eq!(cursors.position(&stream_id), None);
        cursors.applied(&stream_id, EventSequence::new(5));
        assert_eq!(cursors.position(&stream_id), Some(EventSequence::new(5)));

        assert_eq!(
            cursors.accept(&event(&stream_id, 9)),
            Delivery::Gap {
                expected: EventSequence::new(6),
                received: EventSequence::new(9),
            }
        );
        // A gap leaves the stream owing a snapshot, and nothing after it establishes a position.
        assert!(cursors.needs_snapshot(&stream_id));
        assert_eq!(cursors.position(&stream_id), None);
        assert_eq!(
            cursors.accept(&event(&stream_id, 10)),
            Delivery::NeedsSnapshot
        );
        assert_eq!(cursors.position(&stream_id), None);

        cursors.installed_snapshot(&stream_id, EventSequence::new(12));
        assert_eq!(cursors.position(&stream_id), Some(EventSequence::new(12)));
        assert_eq!(cursors.accept(&event(&stream_id, 13)), Delivery::Received);
    }

    #[test]
    fn a_restoration_subscribes_before_it_installs_a_snapshot() {
        let mut cursors = StreamCursors::new();
        let stream_id = stream("session:1");
        cursors.accept(&event(&stream_id, 7));
        cursors.applied(&stream_id, EventSequence::new(7));

        let mut restoration = Restoration::start(stream_id.clone(), &cursors);
        assert_eq!(
            restoration.step(),
            RestorationStep::SubscribeFrom(EventSequence::new(7))
        );
        // A snapshot cannot be installed before the subscription: that order loses every event in
        // between, so the type refuses it rather than leaving it to a comment.
        assert!(restoration.installed().is_err());
        restoration
            .subscribed()
            .expect("the subscription succeeded");
        assert_eq!(restoration.step(), RestorationStep::InstallSnapshot);
        assert!(restoration.subscribed().is_err(), "and it subscribes once");
        restoration.installed().expect("the snapshot was installed");
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
        cursors.applied(&stream_id, EventSequence::new(7));
        let mut restoration = Restoration::start(stream_id.clone(), &cursors);
        restoration
            .subscribed()
            .expect("the subscription succeeded");

        restoration.resynchronise(&mut cursors);
        assert_eq!(restoration.step(), RestorationStep::SubscribeFromStart);
        assert_eq!(cursors.position(&stream_id), None);
        assert!(cursors.needs_snapshot(&stream_id));
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
