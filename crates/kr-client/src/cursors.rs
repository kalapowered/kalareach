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
use kr_protocol::ids::{ActionId, AttachmentId, EventSequence, SessionId, StreamId};
use kr_protocol::receipt::{Receipt, ReceiptState};
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::scalars::{CanonicalSet, Nullable, U64};

/// What a client has received and what it has actually applied, per subscribed stream.
///
/// The two are not the same, and a restoration that confuses them loses events. A notification is
/// *received* when it arrives on the connection; it is *applied* when whatever consumes the stream
/// has folded it into its state. A reconnect subscribes from the applied position, because an event
/// that was received and never applied has to arrive again.
///
/// There are two positions here, and keeping them apart is the whole point. An event *sequence*
/// orders one stream on one connection: the host starts a fresh subscription at its first event, so
/// a sequence means nothing on the next connection and is what gap detection works from here. A
/// *content cursor* is the host's own durable position in what the session produced, so it is what
/// survives a disconnect and what [`EventsSubscribeParams::from_cursor`] names. A reconnect
/// therefore resumes from the content cursor and starts its sequences again from nothing.
#[derive(Clone, Default)]
pub struct StreamCursors {
    received: BTreeMap<StreamId, EventSequence>,
    applied: BTreeMap<StreamId, EventSequence>,
    /// The host's durable position in each stream's content, as far as a consumer has applied it.
    applied_cursor: BTreeMap<StreamId, U64>,
    /// Streams whose partial state is no longer usable. They need a snapshot before anything else.
    needs_snapshot: std::collections::BTreeSet<StreamId>,
    /// The contiguous run of events that arrived on a stream while it was waiting for a snapshot.
    ///
    /// Events keep arriving while a snapshot is being prepared, and they are the history that
    /// follows it. Keeping their first and last sequence is what lets an installed snapshot tell
    /// whether they continue it, instead of discarding them and treating the next one as a gap.
    since_discard: BTreeMap<StreamId, (EventSequence, EventSequence)>,
}

impl std::fmt::Debug for StreamCursors {
    /// How many streams it follows in each way. Never a stream's identifier, which is the
    /// host's text.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StreamCursors")
            .field("received", &self.received.len())
            .field("applied", &self.applied.len())
            .field("applied_cursor", &self.applied_cursor.len())
            .field("needs_snapshot", &self.needs_snapshot.len())
            .field("since_discard", &self.since_discard.len())
            .finish()
    }
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

    /// Returns the host's content position a consumer has applied on `stream_id`.
    ///
    /// This is what a subscription resumes from, and it is the only position that means anything
    /// after a disconnect. `None` means nothing usable is held and the subscription starts wherever
    /// the host is now.
    #[must_use]
    pub fn applied_cursor(&self, stream_id: &StreamId) -> Option<U64> {
        if self.needs_snapshot.contains(stream_id) {
            return None;
        }
        self.applied_cursor.get(stream_id).copied()
    }

    /// Records that a consumer applied this stream's content up to `cursor`.
    ///
    /// The cursor only moves forwards. An event that was delivered and never folded into a
    /// consumer's state leaves the cursor where it was, so the next subscription asks for it again.
    pub fn applied_content(&mut self, stream_id: &StreamId, cursor: U64) {
        if self.needs_snapshot.contains(stream_id) {
            return;
        }
        // A stream held at zero is not the same as a stream held nowhere: the first says resume
        // from the beginning, the second says start wherever the host is. So an explicit zero is
        // recorded rather than read as an absent entry's default.
        match self.applied_cursor.get(stream_id) {
            Some(current) if current.get() >= cursor.get() => {}
            Some(_) | None => {
                self.applied_cursor.insert(stream_id.clone(), cursor);
            }
        }
    }

    /// Forgets every per-connection sequence and keeps every content position.
    ///
    /// A reconnect is exactly this transition. The host numbers a fresh subscription's events from
    /// its own beginning, so carrying the old connection's sequences across would make the first
    /// event of the new subscription read as a duplicate and the client would drop it. What does
    /// carry across is where each stream's content had been applied to, which is what the new
    /// subscription asks to resume from.
    pub fn reconnected(&mut self) {
        self.received.clear();
        self.applied.clear();
        self.since_discard.clear();
    }

    /// Records one delivered event, returning whether it was the next one.
    ///
    /// An event that is not the next one is a gap: the stream is marked as needing a snapshot, so
    /// no later event can quietly establish a new position on top of state that has a hole in it.
    pub fn accept(&mut self, notification: &Notification) -> Delivery {
        let stream_id = &notification.stream_id;
        let sequence = notification.sequence.get();
        if self.needs_snapshot.contains(stream_id) {
            // The events are still delivered, because a consumer that is rebuilding wants to see
            // them, and they establish no position until a snapshot says where they belong. Their
            // contiguous run is remembered so that snapshot can place them.
            match self.since_discard.get(stream_id).copied() {
                Some((first, last)) if sequence >= first.get() && sequence <= last.get() => {
                    // Already inside the run. A repeat is not a hole, and treating it as one would
                    // throw away a perfectly good run because the host sent something twice.
                    let _ = (first, last);
                }
                Some((first, last)) if sequence == last.get().saturating_add(1) => {
                    self.since_discard
                        .insert(stream_id.clone(), (first, notification.sequence));
                }
                Some(_) => {
                    // A hole inside the run makes the whole run unusable: nothing after it can be
                    // placed, so the snapshot will stand on its own.
                    self.since_discard.remove(stream_id);
                }
                None => {
                    self.since_discard.insert(
                        stream_id.clone(),
                        (notification.sequence, notification.sequence),
                    );
                }
            }
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
            self.since_discard.insert(
                stream_id.clone(),
                (notification.sequence, notification.sequence),
            );
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
    ///
    /// Events that arrived while the snapshot was being prepared are ahead of its base, and they
    /// are still this stream's contiguous history: the received position therefore never moves
    /// backwards here. Moving it back would make the next event look like a gap.
    pub fn installed_snapshot(&mut self, stream_id: &StreamId, sequence: EventSequence) {
        self.needs_snapshot.remove(stream_id);
        // Events that arrived while the snapshot was being prepared continue it when their run
        // starts at the sequence after its base. Then the received position is the end of that run,
        // and the next event is contiguous rather than a gap. A run that starts anywhere else says
        // nothing about this snapshot, and the snapshot stands alone.
        // The run continues the snapshot when it covers everything after the base and reaches at
        // least as far: it may start before the base, because a snapshot can repeat events the run
        // already carried, and it may start exactly one past it. Anything that leaves a hole
        // between the base and the run's start says nothing about this snapshot.
        let queued = self
            .since_discard
            .remove(stream_id)
            .filter(|(first, last)| {
                first.get() <= sequence.get().saturating_add(1) && last.get() >= sequence.get()
            })
            .map(|(_, last)| last);
        let received = queued.unwrap_or(sequence);
        let received = self
            .received
            .get(stream_id)
            .map_or(received, |held| held.max(&received).to_owned());
        self.received.insert(stream_id.clone(), received);
        let applied = self
            .applied
            .get(stream_id)
            .map_or(sequence, |held| held.max(&sequence).to_owned());
        self.applied.insert(stream_id.clone(), applied);
    }

    /// Discards a stream's state and marks it as needing a snapshot.
    ///
    /// This is what a resynchronisation requirement means, and what a gap does. The content
    /// position goes with the rest: a stream that owes a snapshot has no position to resume from,
    /// and asking to resume from one would ask for history the host has already said it cannot
    /// replay.
    pub fn discard(&mut self, stream_id: &StreamId) {
        self.received.remove(stream_id);
        self.applied.remove(stream_id);
        self.applied_cursor.remove(stream_id);
        self.since_discard.remove(stream_id);
        self.needs_snapshot.insert(stream_id.clone());
    }

    /// Forgets every stream, holding none of them to a snapshot.
    pub fn discard_all(&mut self) {
        self.received.clear();
        self.applied.clear();
        self.applied_cursor.clear();
        self.since_discard.clear();
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
    /// Subscribe from this content cursor. Nothing has been installed yet.
    SubscribeFrom(U64),
    /// Subscribe from wherever the host is now, because this client holds no position on the
    /// stream.
    SubscribeFromStart,
    /// Install the snapshot the subscription returned, then apply the queued updates.
    InstallSnapshot,
    /// Done: the stream is live.
    Live,
}

/// A restoration step taken out of order.
#[derive(Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the stream is {step} and cannot take that step")]
pub struct OutOfOrder {
    /// The step the stream is actually at.
    pub step: RestorationStep,
}

crate::debug_as_display!(OutOfOrder);

impl crate::shown::Said for RestorationStep {
    fn said(&self) -> crate::shown::Shown {
        match self {
            Self::SubscribeFrom(cursor) => {
                crate::shown!("waiting to subscribe from cursor {}", *cursor)
            }
            Self::SubscribeFromStart => {
                crate::shown::Shown::said("waiting to subscribe from the start")
            }
            Self::InstallSnapshot => crate::shown::Shown::said("installing a snapshot"),
            Self::Live => crate::shown::Shown::said("live"),
        }
    }
}

crate::display_as_said!(RestorationStep);

/// Drives one stream through the restoration order.
#[derive(Clone)]
pub struct Restoration {
    stream_id: StreamId,
    step: RestorationStep,
}

impl Restoration {
    /// Starts a restoration from whatever this client already has.
    #[must_use]
    pub fn start(stream_id: StreamId, cursors: &StreamCursors) -> Self {
        let step = match cursors.applied_cursor(&stream_id) {
            Some(cursor) => RestorationStep::SubscribeFrom(cursor),
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

    /// Returns the parameters of the `events.subscribe` this restoration is waiting to send.
    ///
    /// The cursor is this restoration's own, so the request cannot be built from a position the
    /// client no longer holds: a stream that owes a snapshot subscribes from wherever the host is
    /// now, and one that holds a position asks the host to resume from exactly it.
    ///
    /// # Errors
    ///
    /// Returns [`OutOfOrder`] when the stream is not waiting to subscribe. Subscribing again after
    /// the subscription succeeded would restart the stream and lose whatever came in between.
    pub fn subscribe_params(
        &self,
        session_id: SessionId,
        attachment_id: AttachmentId,
        streams: &[EventStream],
    ) -> std::result::Result<EventsSubscribeParams, OutOfOrder> {
        let from_cursor = match self.step {
            RestorationStep::SubscribeFrom(cursor) => Nullable::some(cursor),
            RestorationStep::SubscribeFromStart => Nullable::null(),
            step => return Err(OutOfOrder { step }),
        };
        Ok(EventsSubscribeParams {
            session_id,
            attachment_id,
            streams: streams.iter().copied().collect::<CanonicalSet<_>>(),
            from_cursor,
        })
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
#[derive(Clone, Default)]
pub struct ReceiptTracker {
    receipts: BTreeMap<ActionId, Receipt>,
}

impl std::fmt::Debug for ReceiptTracker {
    /// How many receipts it holds. Never a receipt, whose result is whatever the action returned.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReceiptTracker")
            .field("receipts", &self.receipts.len())
            .finish()
    }
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

        cursors.applied_content(&stream_id, U64::new(2_048));

        let mut restoration = Restoration::start(stream_id.clone(), &cursors);
        assert_eq!(
            restoration.step(),
            RestorationStep::SubscribeFrom(U64::new(2_048))
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
    fn events_that_arrive_during_a_resynchronisation_continue_its_snapshot() {
        let mut cursors = StreamCursors::new();
        let stream_id = stream("session:1");
        cursors.discard(&stream_id);

        // Two events arrive while the snapshot is being prepared.
        assert_eq!(
            cursors.accept(&event(&stream_id, 11)),
            Delivery::NeedsSnapshot
        );
        assert_eq!(
            cursors.accept(&event(&stream_id, 12)),
            Delivery::NeedsSnapshot
        );

        // The snapshot's base is 10, so those two continue it and 13 is the next event, not a gap.
        cursors.installed_snapshot(&stream_id, EventSequence::new(10));
        cursors.applied(&stream_id, EventSequence::new(12));
        assert_eq!(cursors.accept(&event(&stream_id, 13)), Delivery::Received);
        assert_eq!(cursors.position(&stream_id), Some(EventSequence::new(12)));
    }

    #[test]
    fn a_snapshot_that_overlaps_the_queued_events_still_continues_them() {
        let mut cursors = StreamCursors::new();
        let stream_id = stream("session:1");
        cursors.discard(&stream_id);
        // A repeat at the end of the run, which is where a duplicate would do the most damage.
        cursors.accept(&event(&stream_id, 11));
        cursors.accept(&event(&stream_id, 12));
        cursors.accept(&event(&stream_id, 12));

        // The snapshot's base is 11, which the run already carried. Event 12 still continues it.
        cursors.installed_snapshot(&stream_id, EventSequence::new(11));
        cursors.applied(&stream_id, EventSequence::new(12));
        assert_eq!(cursors.accept(&event(&stream_id, 13)), Delivery::Received);
        assert_eq!(cursors.position(&stream_id), Some(EventSequence::new(12)));
    }

    #[test]
    fn a_snapshot_that_the_queued_events_do_not_continue_stands_alone() {
        let mut cursors = StreamCursors::new();
        let stream_id = stream("session:1");
        cursors.discard(&stream_id);
        cursors.accept(&event(&stream_id, 11));
        cursors.accept(&event(&stream_id, 12));

        // A base of 8 leaves a hole at 9 and 10, so the queued events say nothing about it.
        cursors.installed_snapshot(&stream_id, EventSequence::new(8));
        assert_eq!(cursors.position(&stream_id), Some(EventSequence::new(8)));
        assert!(matches!(
            cursors.accept(&event(&stream_id, 12)),
            Delivery::Gap { .. }
        ));
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

    #[test]
    fn a_reconnect_keeps_the_content_position_and_starts_the_sequences_again() {
        let mut cursors = StreamCursors::new();
        let stream_id = stream("session.output");
        cursors.accept(&event(&stream_id, 1));
        cursors.accept(&event(&stream_id, 2));
        cursors.applied(&stream_id, EventSequence::new(2));
        cursors.applied_content(&stream_id, U64::new(4_096));

        cursors.reconnected();

        // The host numbers the next subscription's events from its own beginning, and that first
        // event is not a duplicate of anything.
        assert_eq!(cursors.received(&stream_id), None);
        assert_eq!(cursors.accept(&event(&stream_id, 1)), Delivery::Received);
        // What the content had reached is what the new subscription resumes from.
        assert_eq!(cursors.applied_cursor(&stream_id), Some(U64::new(4_096)));
        assert_eq!(
            Restoration::start(stream_id.clone(), &cursors).step(),
            RestorationStep::SubscribeFrom(U64::new(4_096))
        );
    }

    /// KR-REQ-06.05: a stream position belongs to the stream it was taken on. Two streams held
    /// side by side keep their own sequences and content cursors: a gap on one leaves the other's
    /// position alone, and a restoration of each resumes from that stream's own cursor.
    #[test]
    fn a_position_belongs_to_the_stream_it_was_taken_on() {
        let mut cursors = StreamCursors::new();
        let output = stream("session:1.output");
        let other = stream("session:2.output");
        for sequence in 1..=3 {
            assert_eq!(
                cursors.accept(&event(&output, sequence)),
                Delivery::Received
            );
        }
        cursors.applied(&output, EventSequence::new(3));
        cursors.applied_content(&output, U64::new(900));

        // The first event on the other stream is not judged against this one's sequence.
        assert_eq!(cursors.accept(&event(&other, 1)), Delivery::Received);
        assert_eq!(cursors.position(&other), None);
        assert_eq!(cursors.applied_cursor(&other), None);
        cursors.applied(&other, EventSequence::new(1));
        cursors.applied_content(&other, U64::new(40));

        // A gap on the other stream costs that stream its position and nothing else.
        assert!(matches!(
            cursors.accept(&event(&other, 5)),
            Delivery::Gap { .. }
        ));
        assert!(cursors.needs_snapshot(&other));
        assert_eq!(cursors.applied_cursor(&other), None);
        assert!(!cursors.needs_snapshot(&output));
        assert_eq!(cursors.position(&output), Some(EventSequence::new(3)));
        assert_eq!(cursors.applied_cursor(&output), Some(U64::new(900)));
        assert_eq!(
            Restoration::start(output.clone(), &cursors).step(),
            RestorationStep::SubscribeFrom(U64::new(900))
        );
        assert_eq!(
            Restoration::start(other, &cursors).step(),
            RestorationStep::SubscribeFromStart
        );
    }

    #[test]
    fn a_stream_held_at_the_beginning_is_not_a_stream_held_nowhere() {
        let mut cursors = StreamCursors::new();
        let stream_id = stream("session.output");
        assert_eq!(cursors.applied_cursor(&stream_id), None);
        cursors.applied_content(&stream_id, U64::ZERO);
        assert_eq!(
            cursors.applied_cursor(&stream_id),
            Some(U64::ZERO),
            "resuming from the beginning is a position; holding none is not"
        );
        assert_eq!(
            Restoration::start(stream_id, &cursors).step(),
            RestorationStep::SubscribeFrom(U64::ZERO)
        );
    }

    #[test]
    fn a_content_position_only_moves_forwards_and_never_over_a_hole() {
        let mut cursors = StreamCursors::new();
        let stream_id = stream("session.output");
        cursors.applied_content(&stream_id, U64::new(100));
        cursors.applied_content(&stream_id, U64::new(40));
        assert_eq!(cursors.applied_cursor(&stream_id), Some(U64::new(100)));

        // A stream that owes a snapshot holds no position, and nothing can give it one until the
        // snapshot says where it is.
        cursors.discard(&stream_id);
        cursors.applied_content(&stream_id, U64::new(200));
        assert_eq!(cursors.applied_cursor(&stream_id), None);
        cursors.installed_snapshot(&stream_id, EventSequence::new(0));
        cursors.applied_content(&stream_id, U64::new(200));
        assert_eq!(cursors.applied_cursor(&stream_id), Some(U64::new(200)));
    }

    #[test]
    fn a_subscription_asks_for_the_position_the_restoration_holds() {
        let mut cursors = StreamCursors::new();
        let stream_id = stream("session.output");
        cursors.applied_content(&stream_id, U64::new(512));
        let session_id = SessionId::new(Uuid::from_bytes([3; 16]));
        let attachment_id = AttachmentId::new(Uuid::from_bytes([4; 16]));

        let mut restoration = Restoration::start(stream_id.clone(), &cursors);
        let params = restoration
            .subscribe_params(session_id, attachment_id, &[EventStream::Output])
            .expect("the stream is waiting to subscribe");
        assert_eq!(params.from_cursor, Nullable::some(U64::new(512)));
        assert_eq!(params.session_id, session_id);
        assert_eq!(params.attachment_id, attachment_id);

        // And once it has subscribed it cannot build another subscription: that would restart the
        // stream and lose whatever arrived in between.
        restoration
            .subscribed()
            .expect("the subscription succeeded");
        assert!(
            restoration
                .subscribe_params(session_id, attachment_id, &[EventStream::Output])
                .is_err()
        );
    }

    #[test]
    fn a_client_with_no_position_subscribes_from_wherever_the_host_is() {
        let cursors = StreamCursors::new();
        let params = Restoration::start(stream("session.output"), &cursors)
            .subscribe_params(
                SessionId::new(Uuid::from_bytes([3; 16])),
                AttachmentId::new(Uuid::from_bytes([4; 16])),
                &[EventStream::Output],
            )
            .expect("the stream is waiting to subscribe");
        assert_eq!(params.from_cursor, Nullable::null());
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

    /// Cursors and receipts say how many streams and receipts they hold, and never a stream's
    /// identifier or a receipt's result.
    #[test]
    fn cursors_and_receipts_say_how_many_and_never_what() {
        assert_eq!(
            format!("{:?}", StreamCursors::default()),
            "StreamCursors { received: 0, applied: 0, applied_cursor: 0, needs_snapshot: 0, since_discard: 0 }"
        );
        assert_eq!(
            format!("{:?}", ReceiptTracker::default()),
            "ReceiptTracker { receipts: 0 }"
        );
    }
}
