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

use crate::runtime::host::ScopedSourceEvent;

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

/// A gap in the observation stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObservationGap {
    /// How many observations were lost.
    pub events: u32,
    /// How many bytes they held.
    pub bytes: u64,
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
}

/// What a drain produced.
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

/// One binding's bounded observation queue.
#[derive(Debug)]
pub struct ObservationQueue {
    events: VecDeque<ScopedSourceEvent>,
    held_bytes: u64,
    capacity_bytes: u64,
    gap: ObservationGap,
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
            },
            snapshot_owed: 0,
            obligations: 0,
        }
    }

    /// Returns the capacity in bytes.
    #[must_use]
    pub const fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }

    /// Returns how many bytes the queue holds.
    #[must_use]
    pub const fn held_bytes(&self) -> u64 {
        self.held_bytes
    }

    /// Returns how many events the queue holds.
    #[must_use]
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

    /// Offers one event to the queue. Never waits, and never runs a component.
    pub fn push(&mut self, event: ScopedSourceEvent) -> Admission {
        let bytes = event.queue_bytes();
        if bytes > self.capacity_bytes {
            // One event larger than the whole queue cannot be admitted by evicting anything. An
            // ordinary observation of that size is a gap of one; an authoritative request of that
            // size is refused so the broker keeps it rather than losing it here.
            if event.is_authoritative() {
                return Admission::Refused {
                    held_bytes: self.held_bytes,
                };
            }
            self.gap.absorb(1, bytes);
            self.raise_obligation();
            return Admission::QueuedWithGap { events: 1, bytes };
        }

        let mut evicted_events = 0_u32;
        let mut evicted_bytes = 0_u64;
        while self.held_bytes + bytes > self.capacity_bytes {
            let Some(position) = self.events.iter().position(|held| !held.is_authoritative())
            else {
                // Nothing left to evict but requests, and a request is never evicted. What was
                // evicted on the way here is a gap, and so is this event if it is an ordinary
                // observation: nobody else is holding one of those, so losing it without recording
                // it would be a hole in the stream that nothing ever accounts for.
                if !event.is_authoritative() {
                    evicted_events = evicted_events.saturating_add(1);
                    evicted_bytes = evicted_bytes.saturating_add(bytes);
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
            self.held_bytes = self.held_bytes.saturating_sub(removed.queue_bytes());
            evicted_events = evicted_events.saturating_add(1);
            evicted_bytes = evicted_bytes.saturating_add(removed.queue_bytes());
        }

        self.held_bytes += bytes;
        self.events.push_back(event);
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
        let event = self.events.pop_front()?;
        self.held_bytes = self.held_bytes.saturating_sub(event.queue_bytes());
        Some(event)
    }

    /// Records that one event was taken and then not delivered.
    ///
    /// A fault costs the event that caused it. Saying so is what keeps the stream's account
    /// complete: the component's view is missing that event, and a gap is how it learns to rebuild.
    pub fn taken_event_was_lost(&mut self, event: &ScopedSourceEvent) {
        self.gap.absorb(1, event.queue_bytes());
        self.raise_obligation();
    }

    /// Takes up to `limit` events, with the gap that precedes them.
    pub fn drain(&mut self, limit: usize) -> Drained {
        let gap = (!self.gap.is_empty()).then(|| core::mem::take(&mut self.gap));
        let mut events = Vec::new();
        while events.len() < limit {
            let Some(event) = self.events.pop_front() else {
                break;
            };
            self.held_bytes = self.held_bytes.saturating_sub(event.queue_bytes());
            events.push(event);
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
    use crate::runtime::host::SourceProvenance;
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
        assert_eq!(ObservationQueue::new().capacity_bytes(), 4_194_304);
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

    impl ObservationGap {
        fn u64_events(&self) -> u64 {
            u64::from(self.events)
        }
    }
}
