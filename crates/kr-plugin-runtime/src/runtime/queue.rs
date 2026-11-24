//! The bounded observation queue, and what its overflow means.
//!
//! The broker supplies one 4 MiB queue per binding. Pushing onto it never waits and never runs a
//! component, which is what keeps PTY draining, terminal-query responses and the presentation
//! queues independent of a component that is slow or stuck: the producer hands over an event and
//! carries on, whatever the component is doing.
//!
//! # Overflow
//!
//! Overflow is explicit. Rather than quietly losing events, the queue evicts the oldest
//! observations, records a gap naming how many events and bytes went, and asks for a fresh
//! snapshot. A component that receives a gap knows its view is incomplete and rebuilds it from
//! `snapshot`, which is exactly what that export is for.
//!
//! # What overflow never does
//!
//! It never drops an authoritative native request, because a dropped request is a decision nobody
//! made. An authoritative event is never evicted to make room for anything. If one cannot be
//! admitted even after every ordinary observation has been evicted, the queue refuses the
//! admission instead: the broker still holds the request and its proven native path, and only the
//! rich interpretation of it is unavailable.
//!
//! An *ordinary* observation that cannot be admitted is a different matter: nobody else is holding
//! it, so losing it silently would be a hole in the stream nothing recorded. It goes into the gap
//! like any evicted observation, and the refusal says so.
//!
//! # The snapshot obligation
//!
//! A gap obliges the component to take a fresh snapshot. The obligation is a number rather than a
//! flag, because a snapshot that was asked for by one gap must not discharge an obligation a later
//! gap created while that snapshot was running: the component's view would then be missing events
//! nobody would ever ask it to rebuild. [`ObservationQueue::snapshot_owed`] says which obligation
//! is outstanding, and [`ObservationQueue::snapshot_taken`] clears only the one it names.

use std::collections::VecDeque;

use kr_plugin_sdk::limits::OBSERVATION_QUEUE_BYTES;
use kr_plugin_service::notices::Bound;
use kr_plugin_service::vocabulary::{Admission, ScopedSourceEvent};
use kr_protocol::ids::SourceEventHandle;

/// A gap in the observation stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObservationGap {
    /// How many observations were lost.
    pub events: u32,
    /// How many bytes they held.
    pub bytes: u64,
    /// The first lost event in the order the queue was offered events, where one was lost.
    ///
    /// Not every event between the first and the last was lost: a request is never evicted, so one
    /// can stand between two that were. The two bound the loss.
    pub first: Option<SourceEventHandle>,
    /// The last lost event in that order.
    pub last: Option<SourceEventHandle>,
    first_order: u64,
    last_order: u64,
}

impl ObservationGap {
    /// Returns true when anything was lost.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events == 0
    }

    fn absorb(&mut self, events: u32, bytes: u64) {
        self.events = self.events.saturating_add(events);
        self.bytes = self.bytes.saturating_add(bytes);
    }

    /// Returns the first lost event with the place it was offered at.
    #[must_use]
    pub fn first_bound(&self) -> Option<Bound> {
        self.first.clone().map(|handle| Bound {
            handle,
            place: self.first_order,
        })
    }

    /// Returns the last lost event with the place it was offered at.
    #[must_use]
    pub fn last_bound(&self) -> Option<Bound> {
        self.last.clone().map(|handle| Bound {
            handle,
            place: self.last_order,
        })
    }

    /// Widens `first` and `last` to take in the events this gap lost.
    ///
    /// By the place each event was offered at and not by the order the gaps were reported in: a
    /// request is never evicted, so a gap reported later can name an event that was offered earlier.
    pub fn widen(&self, first: &mut Option<Bound>, last: &mut Option<Bound>) {
        *first = Bound::earlier(first.take(), self.first_bound());
        *last = Bound::later(last.take(), self.last_bound());
    }

    /// Records that the event offered `order`th was lost, which moves the bounds of the gap.
    fn note(&mut self, order: u64, handle: &SourceEventHandle) {
        if self.first.is_none() || order < self.first_order {
            self.first = Some(handle.clone());
            self.first_order = order;
        }
        if self.last.is_none() || order > self.last_order {
            self.last = Some(handle.clone());
            self.last_order = order;
        }
    }
}

/// What a drain produced.
#[cfg(any(test, feature = "testing"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Drained {
    /// The gap that preceded these events, where there was one.
    ///
    /// A gap arrives before the events that follow it, because the component has to know its view
    /// is stale before it interprets what came next.
    pub gap: Option<ObservationGap>,
    /// The events, oldest first.
    pub events: Vec<ScopedSourceEvent>,
}

/// An event in the queue, with the place it was offered in.
#[derive(Debug)]
struct Held {
    order: u64,
    event: ScopedSourceEvent,
}

/// One binding's bounded observation queue.
#[derive(Debug)]
pub struct ObservationQueue {
    events: VecDeque<Held>,
    held_bytes: u64,
    capacity_bytes: u64,
    gap: ObservationGap,
    /// The place the next offered event takes, counted from one.
    offered: u64,
    /// The place of the event `take_one` took last.
    taken: u64,
    /// The place of the first request that was offered and refused, which no gap accounts for,
    /// until `take_loss_before_taken` reports it. Zero means none.
    refused: u64,
    /// The place of the last one. Zero means none.
    refused_last: u64,
    /// Which snapshot obligation is outstanding, counted from one. Zero means none.
    snapshot_owed: u64,
    /// How many obligations have ever been raised, so a new one is always a new number.
    obligations: u64,
}

impl ObservationQueue {
    /// Builds a queue with the section 11 capacity of 4 MiB.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_capacity(OBSERVATION_QUEUE_BYTES)
    }

    /// Builds a queue with a different capacity.
    #[must_use]
    pub const fn with_capacity(capacity_bytes: u64) -> Self {
        Self {
            events: VecDeque::new(),
            held_bytes: 0,
            capacity_bytes,
            gap: ObservationGap {
                events: 0,
                bytes: 0,
                first: None,
                last: None,
                first_order: 0,
                last_order: 0,
            },
            offered: 0,
            taken: 0,
            refused: 0,
            refused_last: 0,
            snapshot_owed: 0,
            obligations: 0,
        }
    }

    /// Returns how many bytes the queue holds.
    #[must_use]
    #[cfg(any(test, feature = "testing"))]
    pub const fn held_bytes(&self) -> u64 {
        self.held_bytes
    }

    /// Returns how many bytes the queue can still take.
    #[must_use]
    pub const fn free_bytes(&self) -> u64 {
        self.capacity_bytes.saturating_sub(self.held_bytes)
    }

    /// Returns how many events the queue holds.
    #[must_use]
    #[cfg(any(test, feature = "testing"))]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns true when the queue holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Returns true when the component must take a fresh snapshot before its document is trusted.
    #[must_use]
    #[cfg(any(test, feature = "testing"))]
    pub const fn snapshot_required(&self) -> bool {
        self.snapshot_owed != 0
    }

    /// Returns the outstanding snapshot obligation, or zero when there is none.
    ///
    /// A caller that takes a snapshot passes this back to [`Self::snapshot_taken`], so a snapshot
    /// that was already running when a new gap appeared does not discharge the new obligation.
    #[must_use]
    pub const fn snapshot_owed(&self) -> u64 {
        self.snapshot_owed
    }

    /// Records that the component has taken the snapshot obligation `owed` asked for.
    ///
    /// An obligation raised after `owed` stays outstanding. That is the whole point: a snapshot
    /// that started before the latest gap cannot have seen what the gap lost.
    pub const fn snapshot_taken(&mut self, owed: u64) {
        if self.snapshot_owed == owed {
            self.snapshot_owed = 0;
        }
    }

    /// Asks for a fresh snapshot without recording a gap.
    ///
    /// A replaced instance has lost its presentation state without any event having been lost. The
    /// component still needs to rebuild its document, and this is how the binding says so.
    pub const fn require_snapshot(&mut self) {
        self.raise_obligation();
    }

    const fn raise_obligation(&mut self) {
        self.obligations = self.obligations.saturating_add(1);
        self.snapshot_owed = self.obligations;
    }

    /// Returns how many events have been offered to the queue.
    #[must_use]
    pub const fn offered(&self) -> u64 {
        self.offered
    }

    /// Offers one event to the queue. Never waits, and never runs a component.
    pub fn push(&mut self, event: ScopedSourceEvent) -> Admission {
        self.offered = self.offered.saturating_add(1);
        let order = self.offered;
        let bytes = event.queue_bytes();
        if bytes > self.capacity_bytes {
            // One event larger than the whole queue cannot be admitted by evicting anything. An
            // ordinary observation of that size is a gap of one; an authoritative request of that
            // size is refused so the broker keeps it rather than losing it here.
            if event.is_authoritative() {
                self.note_refusal(order);
                return Admission::Refused {
                    held_bytes: self.held_bytes,
                };
            }
            self.gap.absorb(1, bytes);
            self.gap.note(order, &event.handle);
            self.raise_obligation();
            return Admission::QueuedWithGap { events: 1, bytes };
        }

        let mut evicted_events = 0_u32;
        let mut evicted_bytes = 0_u64;
        while self.held_bytes + bytes > self.capacity_bytes {
            let Some(position) = self
                .events
                .iter()
                .position(|held| !held.event.is_authoritative())
            else {
                // Nothing left to evict but requests, and a request is never evicted. What was
                // evicted on the way here is a gap, and so is this event if it is an ordinary
                // observation: nobody else is holding one of those, so losing it without recording
                // it would be a hole in the stream that nothing ever accounts for.
                if event.is_authoritative() {
                    self.note_refusal(order);
                } else {
                    evicted_events = evicted_events.saturating_add(1);
                    evicted_bytes = evicted_bytes.saturating_add(bytes);
                    self.gap.note(order, &event.handle);
                }
                if evicted_events > 0 {
                    self.gap.absorb(evicted_events, evicted_bytes);
                    self.raise_obligation();
                }
                return Admission::Refused {
                    held_bytes: self.held_bytes,
                };
            };
            let removed = self
                .events
                .remove(position)
                .expect("the position came from this queue");
            let removed_bytes = removed.event.queue_bytes();
            self.held_bytes = self.held_bytes.saturating_sub(removed_bytes);
            self.gap.note(removed.order, &removed.event.handle);
            evicted_events = evicted_events.saturating_add(1);
            evicted_bytes = evicted_bytes.saturating_add(removed_bytes);
        }

        self.held_bytes += bytes;
        self.events.push_back(Held { order, event });
        if evicted_events == 0 {
            Admission::Queued
        } else {
            self.gap.absorb(evicted_events, evicted_bytes);
            self.raise_obligation();
            Admission::QueuedWithGap {
                events: evicted_events,
                bytes: evicted_bytes,
            }
        }
    }

    /// Records that the request offered `order`th was refused, which is a loss no gap reports.
    ///
    /// A refused request stays with the broker, so the gap and the snapshot of `/3` do not change; the
    /// binding is told through [`Self::take_loss_before_taken`] so that what it consumed after the
    /// request is not claimed to follow it. Every refusal counts, not the first alone.
    const fn note_refusal(&mut self, order: u64) {
        if self.refused == 0 {
            self.refused = order;
        }
        self.refused_last = order;
    }

    /// Records that an event was offered and refused before it reached the queue.
    ///
    /// The refusal takes a place among the events offered, so what is taken after it is told it
    /// came after a loss, as for a request the queue refused.
    pub const fn refuse(&mut self) {
        self.offered = self.offered.saturating_add(1);
        self.note_refusal(self.offered);
    }

    /// Returns true when the gap holds a lost event, or a request was refused, that was offered
    /// before the event `take_one` took last, and forgets the refusal.
    ///
    /// Called with the queue still held after `take_one`, so that what is reported is what stood
    /// before that event. A loss offered after it, which the queue records while the component
    /// works on it, comes before no event this pass has taken.
    pub const fn take_loss_before_taken(&mut self) -> bool {
        let gap = self.gap.first.is_some() && self.gap.first_order < self.taken;
        let refused = self.refused != 0 && self.refused < self.taken;
        if refused {
            if self.refused_last < self.taken {
                self.refused = 0;
                self.refused_last = 0;
            } else {
                // A later refusal is still to come before an event not yet taken. The queue keeps
                // the place of the first and of the last only, so the next event taken is told of
                // a loss as well: a loss said where there was none, and never one left unsaid.
                self.refused = self.taken;
            }
        }
        gap || refused
    }

    /// Returns true when a gap is waiting to be taken.
    #[must_use]
    pub const fn gap_pending(&self) -> bool {
        !self.gap.is_empty()
    }

    /// Takes the gap, if there is one.
    ///
    /// Separate from taking events, because a gap has to be reported and its snapshot taken before
    /// any event after it is interpreted, and taking events at the same time would mean holding
    /// them somewhere the queue no longer accounts for.
    pub fn take_gap(&mut self) -> Option<ObservationGap> {
        (!self.gap.is_empty()).then(|| core::mem::take(&mut self.gap))
    }

    /// Takes the oldest event, if there is one.
    ///
    /// One at a time is what lets a caller stop after a fault without having removed events it is
    /// not going to deliver.
    pub fn take_one(&mut self) -> Option<ScopedSourceEvent> {
        let held = self.events.pop_front()?;
        self.held_bytes = self.held_bytes.saturating_sub(held.event.queue_bytes());
        self.taken = held.order;
        Some(held.event)
    }

    /// Records that the event `take_one` took last was taken and then not delivered.
    ///
    /// A fault costs the event that caused it. Saying so is what keeps the stream's account
    /// complete: the component's view is missing that event, and a gap is how it learns to rebuild.
    pub fn taken_event_was_lost(&mut self, event: &ScopedSourceEvent) {
        self.gap.absorb(1, event.queue_bytes());
        self.gap.note(self.taken, &event.handle);
        self.raise_obligation();
    }

    /// Takes up to `limit` events, with the gap that precedes them.
    #[cfg(any(test, feature = "testing"))]
    pub fn drain(&mut self, limit: usize) -> Drained {
        let gap = (!self.gap.is_empty()).then(|| core::mem::take(&mut self.gap));
        let mut events = Vec::new();
        while events.len() < limit {
            let Some(held) = self.events.pop_front() else {
                break;
            };
            self.held_bytes = self.held_bytes.saturating_sub(held.event.queue_bytes());
            events.push(held.event);
        }
        Drained { gap, events }
    }

    /// Discards everything, recording what was discarded as a gap.
    ///
    /// Used when a binding is rebound or its instance is replaced: the events belong to the
    /// previous instance's view, and the new one starts from a snapshot.
    pub fn clear(&mut self) {
        let events = u32::try_from(self.events.len()).unwrap_or(u32::MAX);
        if events > 0 {
            self.gap.absorb(events, self.held_bytes);
            for held in &self.events {
                self.gap.note(held.order, &held.event.handle);
            }
            self.raise_obligation();
        }
        self.events.clear();
        self.held_bytes = 0;
    }
}

impl Default for ObservationQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_plugin_service::vocabulary::SourceProvenance;
    use kr_protocol::ids::SourceEventHandle;

    fn scrape(name: &str, bytes: usize) -> ScopedSourceEvent {
        ScopedSourceEvent::new(
            SourceEventHandle::new(name).expect("a handle within the identifier bound"),
            SourceProvenance::TerminalScrape,
            0,
            None,
            vec![0_u8; bytes],
        )
    }

    fn request(name: &str, id: &str, bytes: usize) -> ScopedSourceEvent {
        ScopedSourceEvent::new(
            SourceEventHandle::new(name).expect("a handle within the identifier bound"),
            SourceProvenance::NativeProtocol,
            0,
            Some(id.to_owned()),
            vec![0_u8; bytes],
        )
    }

    #[test]
    fn the_capacity_is_the_specified_four_mebibytes() {
        assert_eq!(ObservationQueue::new().capacity_bytes, 4_194_304);
    }

    #[test]
    fn events_within_the_bound_queue_without_a_gap() {
        let mut queue = ObservationQueue::new();
        for index in 0..4 {
            assert_eq!(
                queue.push(scrape(&format!("se-{index}"), 512 * 1024)),
                Admission::Queued
            );
        }
        assert!(!queue.snapshot_required());
        let drained = queue.drain(16);
        assert!(drained.gap.is_none());
        assert_eq!(drained.events.len(), 4);
        assert!(queue.is_empty());
        assert_eq!(queue.held_bytes(), 0);
    }

    #[test]
    fn overflow_produces_an_explicit_gap_and_asks_for_a_fresh_snapshot() {
        let mut queue = ObservationQueue::with_capacity(1024);
        for index in 0..4 {
            queue.push(scrape(&format!("se-{index}"), 240));
        }
        assert!(!queue.snapshot_required());

        let admission = queue.push(scrape("se-4", 240));
        let Admission::QueuedWithGap { events, bytes } = admission else {
            panic!("overflow did not report a gap: {admission:?}");
        };
        assert_eq!(events, 1);
        assert!(bytes >= 240);
        assert!(queue.snapshot_required());
        let gap_owed = queue.snapshot_owed();
        assert_ne!(gap_owed, 0);

        let drained = queue.drain(16);
        let gap = drained.gap.expect("the gap arrives before the events");
        assert_eq!(gap.events, 1);
        // The oldest observation is the one that went, so what remains is the newest four.
        assert_eq!(drained.events.len(), 4);
        assert_eq!(drained.events[0].handle.as_str(), "se-1");
        assert_eq!(drained.events[3].handle.as_str(), "se-4");

        queue.snapshot_taken(gap_owed);
        assert!(!queue.snapshot_required());
    }

    #[test]
    fn a_snapshot_does_not_discharge_an_obligation_raised_after_it_started() {
        let mut queue = ObservationQueue::with_capacity(1024);
        for index in 0..5 {
            queue.push(scrape(&format!("se-{index}"), 240));
        }
        let first = queue.snapshot_owed();
        assert_ne!(first, 0);

        // A second overflow while that snapshot is still running raises a new obligation.
        for index in 5..10 {
            queue.push(scrape(&format!("se-{index}"), 240));
        }
        let second = queue.snapshot_owed();
        assert_ne!(second, first);

        // The snapshot the first gap asked for finishes. It cannot have seen what the second gap
        // lost, so the obligation stays.
        queue.snapshot_taken(first);
        assert!(
            queue.snapshot_required(),
            "a snapshot that started before the latest gap discharged its obligation"
        );
        assert_eq!(queue.snapshot_owed(), second);

        queue.snapshot_taken(second);
        assert!(!queue.snapshot_required());
    }

    #[test]
    fn an_ordinary_observation_that_cannot_be_admitted_is_recorded_as_lost() {
        // A queue full of requests, and then an ordinary observation with nowhere to go. Nobody
        // else is holding that observation, so its loss has to appear in the gap.
        let mut queue = ObservationQueue::with_capacity(1024);
        queue.push(request("se-0", "req-0", 480));
        queue.push(request("se-1", "req-1", 480));

        let admission = queue.push(scrape("se-2", 480));
        assert!(matches!(admission, Admission::Refused { .. }));
        assert!(
            queue.snapshot_required(),
            "a lost observation did not ask for a fresh snapshot"
        );
        let drained = queue.drain(16);
        let gap = drained.gap.expect("the lost observation is a gap");
        assert_eq!(gap.events, 1);
        assert!(gap.bytes >= 480);
        // Both requests are still there.
        assert_eq!(drained.events.len(), 2);
    }

    #[test]
    fn an_authoritative_request_is_never_evicted_to_make_room() {
        let mut queue = ObservationQueue::with_capacity(1024);
        queue.push(request("se-0", "req-0", 400));
        queue.push(scrape("se-1", 400));

        // The new observation needs room, and the only old entry that may go is the scrape.
        let admission = queue.push(scrape("se-2", 400));
        assert!(matches!(
            admission,
            Admission::QueuedWithGap { events: 1, .. }
        ));

        let drained = queue.drain(16);
        assert!(drained.gap.is_some());
        let handles: Vec<&str> = drained
            .events
            .iter()
            .map(|event| event.handle.as_str())
            .collect();
        assert_eq!(handles, vec!["se-0", "se-2"]);
    }

    #[test]
    fn a_request_that_cannot_be_admitted_is_refused_rather_than_losing_another_request() {
        let mut queue = ObservationQueue::with_capacity(1024);
        queue.push(request("se-0", "req-0", 480));
        queue.push(request("se-1", "req-1", 480));

        let admission = queue.push(request("se-2", "req-2", 480));
        assert!(matches!(admission, Admission::Refused { .. }));
        // Nothing was lost: the broker is holding the refused request, so there is no gap and no
        // snapshot to take.
        assert!(!queue.snapshot_required());

        // Both earlier requests are still there. Nothing authoritative was dropped.
        let drained = queue.drain(16);
        assert!(drained.gap.is_none());
        assert_eq!(drained.events.len(), 2);
        assert!(
            drained
                .events
                .iter()
                .all(ScopedSourceEvent::is_authoritative)
        );
    }

    #[test]
    fn an_event_larger_than_the_whole_queue_becomes_a_gap_and_a_request_is_refused() {
        let mut queue = ObservationQueue::with_capacity(1024);
        assert!(matches!(
            queue.push(scrape("se-0", 4096)),
            Admission::QueuedWithGap { events: 1, .. }
        ));
        assert!(queue.snapshot_required());
        assert!(queue.is_empty());

        let mut other = ObservationQueue::with_capacity(1024);
        assert!(matches!(
            other.push(request("se-0", "req-0", 4096)),
            Admission::Refused { .. }
        ));
        assert!(other.is_empty());
    }

    #[test]
    fn one_event_at_a_time_leaves_the_rest_where_they_were() {
        let mut queue = ObservationQueue::new();
        for index in 0..3 {
            queue.push(scrape(&format!("se-{index}"), 32));
        }
        let first = queue.take_one().expect("an event");
        assert_eq!(first.handle.as_str(), "se-0");
        assert_eq!(queue.len(), 2);

        // A fault on that event is the event's loss, and the account says so.
        queue.taken_event_was_lost(&first);
        assert!(queue.snapshot_required());
        let gap = queue.take_gap().expect("the lost event is a gap");
        assert_eq!(gap.events, 1);

        // And the two that were never taken are still there, in order.
        assert_eq!(queue.take_one().expect("an event").handle.as_str(), "se-1");
        assert_eq!(queue.take_one().expect("an event").handle.as_str(), "se-2");
        assert!(queue.take_one().is_none());
        assert_eq!(queue.held_bytes(), 0);
    }

    #[test]
    fn a_partial_drain_leaves_the_rest_in_order() {
        let mut queue = ObservationQueue::new();
        for index in 0..5 {
            queue.push(scrape(&format!("se-{index}"), 16));
        }
        let first = queue.drain(2);
        assert_eq!(first.events.len(), 2);
        assert_eq!(first.events[0].handle.as_str(), "se-0");
        let rest = queue.drain(16);
        assert_eq!(rest.events.len(), 3);
        assert_eq!(rest.events[0].handle.as_str(), "se-2");
        assert!(rest.gap.is_none());
    }

    #[test]
    fn a_snapshot_can_be_asked_for_without_anything_having_been_lost() {
        let mut queue = ObservationQueue::new();
        queue.require_snapshot();
        assert!(queue.snapshot_required());
        let owed = queue.snapshot_owed();
        let drained = queue.drain(16);
        assert!(
            drained.gap.is_none(),
            "nothing was lost, so there is no gap"
        );
        queue.snapshot_taken(owed);
        assert!(!queue.snapshot_required());
    }

    #[test]
    fn clearing_the_queue_records_what_it_discarded() {
        let mut queue = ObservationQueue::new();
        queue.push(scrape("se-0", 32));
        queue.push(scrape("se-1", 32));
        queue.clear();
        assert!(queue.snapshot_required());
        let drained = queue.drain(16);
        assert_eq!(drained.gap.expect("a gap").events, 2);
        assert!(drained.events.is_empty());
    }

    #[test]
    fn successive_gaps_accumulate_until_they_are_drained() {
        let mut queue = ObservationQueue::with_capacity(512);
        for index in 0..8 {
            queue.push(scrape(&format!("se-{index}"), 240));
        }
        let drained = queue.drain(16);
        let gap = drained.gap.expect("a gap");
        assert!(gap.events >= 5, "only {} events reported lost", gap.events);
        assert!(gap.bytes >= gap.u64_events() * 240);
    }

    /// A loss is reported against the events offered after it, and not against those before it.
    #[test]
    fn a_loss_is_reported_before_the_events_offered_after_it() {
        let mut queue = ObservationQueue::with_capacity(500);
        queue.push(scrape("se-0", 100));
        queue.push(scrape("se-1", 100));
        assert_eq!(
            queue.take_one().map(|event| event.handle),
            SourceEventHandle::new("se-0").ok()
        );
        assert!(!queue.take_loss_before_taken(), "nothing was lost yet");
        // Three more fill the queue, and the one after them takes the place of the oldest.
        for index in 2..=5 {
            queue.push(scrape(&format!("se-{index}"), 100));
        }
        assert_eq!(queue.take_gap().map(|gap| gap.events), Some(1));
        queue.push(scrape("se-6", 100));
        queue.push(scrape("se-7", 100));
        queue.push(scrape("se-8", 100));
        // What was lost was offered before the event taken now.
        assert!(queue.take_one().is_some());
        assert!(
            queue.take_loss_before_taken(),
            "a loss stands before this event"
        );
    }

    /// A loss offered after the event taken is not one that stands before it.
    #[test]
    fn a_loss_offered_after_the_event_taken_is_not_reported_against_it() {
        let mut queue = ObservationQueue::with_capacity(500);
        for index in 0..4 {
            queue.push(request(&format!("se-{index}"), &format!("rq-{index}"), 100));
        }
        // Nothing but requests to evict: this scrape is the loss, and it is the newest.
        assert!(matches!(
            queue.push(scrape("se-lost", 100)),
            Admission::Refused { .. }
        ));
        assert!(queue.take_one().is_some());
        assert!(!queue.take_loss_before_taken());
    }

    /// A request the queue refuses is a loss that no gap reports, and the events offered after it
    /// are told of it once.
    #[test]
    fn a_refused_request_is_reported_before_the_events_offered_after_it() {
        let mut queue = ObservationQueue::with_capacity(500);
        for index in 0..4 {
            queue.push(request(&format!("se-{index}"), &format!("rq-{index}"), 100));
        }
        assert!(matches!(
            queue.push(request("se-refused", "rq-refused", 100)),
            Admission::Refused { .. }
        ));
        assert!(queue.take_gap().is_none(), "the gap of /3 does not change");
        for _ in 0..4 {
            assert!(queue.take_one().is_some());
            assert!(!queue.take_loss_before_taken(), "these came before it");
        }
        queue.push(request("se-after", "rq-after", 100));
        assert!(queue.take_one().is_some());
        assert!(queue.take_loss_before_taken(), "this one came after it");
        queue.push(request("se-last", "rq-last", 100));
        assert!(queue.take_one().is_some());
        assert!(!queue.take_loss_before_taken(), "it is reported once");
    }

    /// A gap names the first and the last event it lost in the order they were offered, and a request
    /// the queue kept can stand between them.
    #[test]
    fn a_gap_names_the_first_and_last_lost_event_in_the_order_they_were_offered() {
        let mut queue = ObservationQueue::with_capacity(500);
        queue.push(scrape("se-0", 100));
        queue.push(request("se-1", "rq-1", 100));
        queue.push(scrape("se-2", 100));
        queue.push(scrape("se-3", 100));
        for index in 4..=6 {
            queue.push(scrape(&format!("se-{index}"), 100));
        }
        let gap = queue.take_gap().expect("a gap");
        assert_eq!(gap.events, 3);
        assert_eq!(gap.first, SourceEventHandle::new("se-0").ok());
        assert_eq!(gap.last, SourceEventHandle::new("se-3").ok());
        let kept: Vec<_> = queue
            .drain(16)
            .events
            .into_iter()
            .map(|e| e.handle)
            .collect();
        assert!(kept.contains(&SourceEventHandle::new("se-1").expect("a handle")));
    }

    /// A gap reported later can name an event that was offered earlier, and the bounds of what was
    /// lost are the earliest and the latest event by when they were offered.
    #[test]
    fn gaps_widen_the_bounds_by_the_place_events_were_offered_at_and_not_the_order_they_are_told_in()
     {
        let mut queue = ObservationQueue::with_capacity(500);
        queue.push(request("se-0", "rq-0", 100));
        for index in 1..=5 {
            queue.push(scrape(&format!("se-{index}"), 100));
        }
        // Two observations were evicted for room, and are reported first.
        let later = queue.take_gap().expect("a gap");
        // The request that stood before them is observed next, and is lost.
        let taken = queue.take_one().expect("the request");
        queue.taken_event_was_lost(&taken);
        let earlier = queue.take_gap().expect("a second gap");

        let (mut first, mut last) = (None, None);
        later.widen(&mut first, &mut last);
        earlier.widen(&mut first, &mut last);
        assert_eq!(
            (
                first.map(|bound| bound.handle),
                last.map(|bound| bound.handle)
            ),
            (
                SourceEventHandle::new("se-0").ok(),
                SourceEventHandle::new("se-2").ok()
            ),
            "the request that was offered first bounds the loss from the front"
        );
    }

    /// A second refusal is not forgotten because an event taken between the two was told of the
    /// first.
    #[test]
    fn a_refusal_that_follows_one_already_told_is_told_as_well() {
        let mut queue = ObservationQueue::with_capacity(500);
        for index in 0..4 {
            queue.push(request(&format!("se-{index}"), &format!("rq-{index}"), 100));
        }
        assert!(matches!(
            queue.push(request("se-refused-1", "rq-refused-1", 100)),
            Admission::Refused { .. }
        ));
        // Room for one more, which a second refusal then takes away again.
        assert!(queue.take_one().is_some());
        assert!(!queue.take_loss_before_taken(), "this came before both");
        assert!(matches!(
            queue.push(request("se-between", "rq-between", 100)),
            Admission::Queued
        ));
        assert!(matches!(
            queue.push(request("se-refused-2", "rq-refused-2", 100)),
            Admission::Refused { .. }
        ));
        for _ in 0..3 {
            assert!(queue.take_one().is_some());
            assert!(
                !queue.take_loss_before_taken(),
                "these came before the first"
            );
        }
        // The event offered between the two refusals is told of the first.
        assert!(queue.take_one().is_some());
        assert!(
            queue.take_loss_before_taken(),
            "this one came after the first"
        );
        queue.push(request("se-after", "rq-after", 100));
        assert!(queue.take_one().is_some());
        assert!(
            queue.take_loss_before_taken(),
            "this one came after the second, which the first one's report did not account for"
        );
        queue.push(request("se-last", "rq-last", 100));
        assert!(queue.take_one().is_some());
        assert!(!queue.take_loss_before_taken(), "both are told once");
    }

    #[test]
    fn an_event_refused_before_it_reached_the_queue_is_a_loss_the_events_after_it_are_told_of() {
        let mut queue = ObservationQueue::with_capacity(500);
        queue.push(request("se-0", "rq-0", 100));
        queue.refuse();
        queue.push(request("se-1", "rq-1", 100));
        assert!(queue.take_one().is_some());
        assert!(!queue.take_loss_before_taken(), "this came before it");
        assert!(queue.take_one().is_some());
        assert!(queue.take_loss_before_taken(), "this one came after it");
    }

    impl ObservationGap {
        fn u64_events(&self) -> u64 {
            u64::from(self.events)
        }
    }
}
