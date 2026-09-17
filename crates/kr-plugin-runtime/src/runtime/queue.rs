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
    snapshot_required: bool,
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
            snapshot_required: false,
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
        self.snapshot_required
    }

    /// Records that the component has taken the fresh snapshot the gap asked for.
    pub fn snapshot_taken(&mut self) {
        self.snapshot_required = false;
    }

    /// Asks for a fresh snapshot without recording a gap.
    ///
    /// A replaced instance has lost its presentation state without any event having been lost. The
    /// component still needs to rebuild its document, and this is how the binding says so.
    pub fn require_snapshot(&mut self) {
        self.snapshot_required = true;
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
            self.snapshot_required = true;
            return Admission::QueuedWithGap { events: 1, bytes };
        }

        let mut evicted_events = 0_u32;
        let mut evicted_bytes = 0_u64;
        while self.held_bytes + bytes > self.capacity_bytes {
            let Some(position) = self.events.iter().position(|held| !held.is_authoritative())
            else {
                // Nothing left to evict but requests, and a request is never evicted.
                if evicted_events > 0 {
                    self.gap.absorb(evicted_events, evicted_bytes);
                    self.snapshot_required = true;
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
            self.snapshot_required = true;
            Admission::QueuedWithGap {
                events: evicted_events,
                bytes: evicted_bytes,
            }
        }
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
            self.snapshot_required = true;
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

        let drained = queue.drain(16);
        let gap = drained.gap.expect("the gap arrives before the events");
        assert_eq!(gap.events, 1);
        // The oldest observation is the one that went, so what remains is the newest four.
        assert_eq!(drained.events.len(), 4);
        assert_eq!(drained.events[0].handle.as_str(), "se-1");
        assert_eq!(drained.events[3].handle.as_str(), "se-4");

        queue.snapshot_taken();
        assert!(!queue.snapshot_required());
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

        // Both earlier requests are still there. Nothing authoritative was dropped.
        let drained = queue.drain(16);
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
        let drained = queue.drain(16);
        assert!(
            drained.gap.is_none(),
            "nothing was lost, so there is no gap"
        );
        queue.snapshot_taken();
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
