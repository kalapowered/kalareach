//! The bounded queue a connection's notices wait in.
//!
//! A notice is something a binding produced without being asked: document nodes, a gap, a fault or
//! a disabling. Between the binding's thread and whoever reads the connection there has to be
//! somewhere for them to wait, and that somewhere has to be bounded: a component can emit a
//! mebibyte per call, and a reader that has stopped reading must not be able to make either process
//! grow without limit.
//!
//! # One bound, and nothing outside it
//!
//! [`MAX_NOTICE_BYTES`] covers everything this queue holds, the record of what it has already
//! dropped included. Three things follow from that.
//!
//! Presentation gives way first. A document a reader never collected is a document the component
//! can draw again, so an overflow drops the oldest documents and counts them.
//!
//! Losses coalesce rather than accumulate. Every loss against one binding -- observations the
//! runtime's queue dropped, documents this queue dropped -- folds into one record per binding and
//! travels as one gap, so a reader that has stopped reading cannot be given a backlog of gaps
//! either.
//!
//! A fault and a disabling are never dropped: nothing else tells a reader that a binding stopped
//! working. If even those will not fit once every document has gone, the queue says so and the
//! connection is over. A connection whose reliable news cannot be delivered is not one worth
//! keeping open, and pretending otherwise would be the unbounded growth this bound exists to
//! prevent.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use kr_protocol::scalars::Uuid;

use crate::service::protocol::{Notice, WireNode};

/// How many bytes of notices one connection may hold.
///
/// The observation queue's figure, because it bounds the same thing from the other side: what one
/// binding's traffic may cost a process that is not reading it as fast as it arrives.
pub const MAX_NOTICE_BYTES: u64 = 4 * 1024 * 1024;

/// What one notice costs of the queue before its contents are counted.
///
/// A notice is a record with a binding identifier and a discriminant, and it occupies a place in
/// this queue and a frame on the wire whatever its strings say. A loss record costs the same: it is
/// a binding identifier and three counts, and it becomes a notice.
const NOTICE_OVERHEAD_BYTES: u64 = 64;

/// What one document node costs.
///
/// The runtime charges the same fixed cost per node against a call's output budget, so a document
/// that fitted that budget fits this queue's accounting too.
const NODE_OVERHEAD_BYTES: u64 = crate::runtime::host::NODE_OVERHEAD_BYTES;

/// What became of a notice this queue was offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Offered {
    /// It is in the queue, or folded into a loss the reader will be told about.
    Kept,
    /// It was presentation and there was no room. The loss is recorded, and the binding it came
    /// from should be asked to rebuild its document.
    Dropped,
    /// What must arrive will not fit, even with every document gone. The connection is over.
    Overflowed,
    /// The reader is gone.
    Closed,
}

/// Returns what one notice costs of the queue.
#[must_use]
pub fn notice_bytes(notice: &Notice) -> u64 {
    let contents = match notice {
        Notice::Document { call, nodes, .. } => {
            call.len() as u64 + nodes.iter().map(node_bytes).sum::<u64>()
        }
        Notice::Gap { .. } => 0,
        Notice::Fault { call, detail, .. } => (call.len() + detail.len()) as u64,
        Notice::Disabled { reason, .. } => reason.len() as u64,
    };
    NOTICE_OVERHEAD_BYTES + contents
}

/// Returns what one document node costs, in the queue and in a frame.
#[must_use]
pub fn node_bytes(node: &WireNode) -> u64 {
    NODE_OVERHEAD_BYTES + (node.node_id.len() + node.body_json.len()) as u64
}

/// What one binding has lost, waiting to be told.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Loss {
    events: u32,
    bytes: u64,
    documents: u64,
}

/// The shared state behind a sink and its stream.
#[derive(Debug)]
struct Shared {
    queue: Mutex<Queued>,
    wake: tokio::sync::Notify,
}

#[derive(Debug, Default)]
struct Queued {
    waiting: VecDeque<Notice>,
    held: u64,
    /// What each binding has lost, waiting to be reported as one gap.
    lost: HashMap<Uuid, Loss>,
    /// The order the losses are reported in, so the oldest loss is the first a reader hears about.
    lost_order: VecDeque<Uuid>,
    closed: bool,
    /// Set when what must arrive would not fit. The connection is over.
    overflowed: bool,
    /// How many documents this queue has dropped in its life, for the health report.
    dropped: u64,
}

/// Where notices are put. Cloneable: one per binding forwarder, and one for the reader.
#[derive(Clone, Debug)]
pub struct NoticeSink {
    shared: Arc<Shared>,
}

/// Where notices are taken from. One consumer.
#[derive(Debug)]
pub struct NoticeStream {
    shared: Arc<Shared>,
}

/// Builds a bounded notice queue.
#[must_use]
pub fn channel() -> (NoticeSink, NoticeStream) {
    let shared = Arc::new(Shared {
        queue: Mutex::new(Queued::default()),
        wake: tokio::sync::Notify::new(),
    });
    (
        NoticeSink {
            shared: Arc::clone(&shared),
        },
        NoticeStream { shared },
    )
}

impl NoticeSink {
    /// Offers one notice, dropping presentation rather than growing or waiting.
    pub fn send(&self, notice: Notice) -> Offered {
        let Ok(mut queue) = self.shared.queue.lock() else {
            return Offered::Closed;
        };
        if queue.closed {
            return Offered::Closed;
        }
        let offered = queue.admit(notice);
        drop(queue);
        // One waiter, so one wake-up, and it leaves a permit behind when nobody is waiting yet. A
        // wake-up that woke nobody would otherwise be lost between the reader looking at an empty
        // queue and the reader waiting on it.
        self.shared.wake.notify_one();
        offered
    }

    /// Closes the queue, so a reader waiting on it stops waiting.
    pub fn close(&self) {
        if let Ok(mut queue) = self.shared.queue.lock() {
            queue.closed = true;
        }
        self.shared.wake.notify_one();
    }

    /// Returns true once the queue is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.shared.queue.lock().is_ok_and(|queue| queue.closed)
    }

    /// Returns how many bytes the queue holds, for a health report.
    #[must_use]
    pub fn held_bytes(&self) -> u64 {
        self.shared.queue.lock().map_or(0, |queue| queue.held)
    }

    /// Returns how many documents this queue has dropped for want of room.
    #[must_use]
    pub fn dropped_documents(&self) -> u64 {
        self.shared.queue.lock().map_or(0, |queue| queue.dropped)
    }
}

impl NoticeStream {
    /// Waits for the next notice, or returns nothing once the queue is closed and empty.
    pub async fn recv(&mut self) -> Option<Notice> {
        let shared = Arc::clone(&self.shared);
        loop {
            // Registered before the queue is looked at, so a notice that arrives between the look
            // and the wait is not one this waits for ever on.
            let waiting = shared.wake.notified();
            if let Some(notice) = self.try_recv() {
                return Some(notice);
            }
            if self.is_closed() {
                return None;
            }
            waiting.await;
        }
    }

    /// Takes the next notice if one is waiting.
    pub fn try_recv(&mut self) -> Option<Notice> {
        self.shared
            .queue
            .lock()
            .ok()
            .and_then(|mut queue| queue.take())
    }

    /// Returns how many bytes the queue holds.
    #[must_use]
    pub fn held_bytes(&self) -> u64 {
        self.shared.queue.lock().map_or(0, |queue| queue.held)
    }

    /// Returns how many documents this queue has dropped for want of room.
    #[must_use]
    pub fn dropped_documents(&self) -> u64 {
        self.shared.queue.lock().map_or(0, |queue| queue.dropped)
    }

    /// Returns true once the queue is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.shared.queue.lock().is_ok_and(|queue| queue.closed)
    }

    /// Returns true when the queue closed because what had to arrive would not fit.
    #[must_use]
    pub fn overflowed(&self) -> bool {
        self.shared.queue.lock().is_ok_and(|queue| queue.overflowed)
    }
}

impl Drop for NoticeStream {
    /// A reader that is gone is a reader nothing should keep producing for.
    fn drop(&mut self) {
        if let Ok(mut queue) = self.shared.queue.lock() {
            queue.closed = true;
            queue.waiting.clear();
            queue.lost.clear();
            queue.lost_order.clear();
            queue.held = 0;
        }
    }
}

impl Queued {
    /// Admits one notice, making room by dropping presentation.
    fn admit(&mut self, notice: Notice) -> Offered {
        // A gap is not queued: it folds into what its binding has already lost, so a reader that
        // has stopped reading cannot be given a backlog of them either.
        if let Notice::Gap {
            binding_id,
            events,
            bytes,
            documents,
        } = notice
        {
            return self.absorb(
                binding_id,
                Loss {
                    events,
                    bytes,
                    documents,
                },
            );
        }

        let cost = notice_bytes(&notice);
        let droppable = matches!(notice, Notice::Document { .. });
        while self.held + cost > MAX_NOTICE_BYTES && self.evict_oldest_document() {}
        if self.held + cost > MAX_NOTICE_BYTES {
            if droppable {
                // Nothing left to make room with, and this is presentation. It goes, and the
                // reader is told so it expects a fresh document.
                return self.absorb(
                    notice.binding_id(),
                    Loss {
                        documents: 1,
                        ..Loss::default()
                    },
                );
            }
            // What must arrive will not fit even with every document gone. Nothing this connection
            // could say next would be answerable, so it is over.
            self.closed = true;
            self.overflowed = true;
            return Offered::Overflowed;
        }
        self.held += cost;
        self.waiting.push_back(notice);
        Offered::Kept
    }

    /// Folds one loss into what its binding has already lost.
    fn absorb(&mut self, binding_id: Uuid, loss: Loss) -> Offered {
        let dropped_document = loss.documents > 0;
        let answer = if dropped_document {
            Offered::Dropped
        } else {
            Offered::Kept
        };
        if self.merge(binding_id, loss) {
            return answer;
        }
        // A binding this queue has no loss record for yet. The record is one more thing the queue
        // holds, so it is charged like anything else.
        while self.held + NOTICE_OVERHEAD_BYTES > MAX_NOTICE_BYTES && self.evict_oldest_document() {
        }
        // Making room may have created this binding's record, if what it evicted was this
        // binding's document. Merging again is what keeps one binding to one record and one charge.
        if self.merge(binding_id, loss) {
            return answer;
        }
        if self.held + NOTICE_OVERHEAD_BYTES > MAX_NOTICE_BYTES {
            self.closed = true;
            self.overflowed = true;
            return Offered::Overflowed;
        }
        self.charge_loss(binding_id, loss);
        answer
    }

    /// Adds one loss to a record this queue already holds, and says whether it did.
    fn merge(&mut self, binding_id: Uuid, loss: Loss) -> bool {
        let Some(held) = self.lost.get_mut(&binding_id) else {
            return false;
        };
        held.events = held.events.saturating_add(loss.events);
        held.bytes = held.bytes.saturating_add(loss.bytes);
        held.documents = held.documents.saturating_add(loss.documents);
        self.dropped = self.dropped.saturating_add(loss.documents);
        true
    }

    /// Starts one binding's loss record, and charges the queue for holding it.
    fn charge_loss(&mut self, binding_id: Uuid, loss: Loss) {
        self.held += NOTICE_OVERHEAD_BYTES;
        self.lost.insert(binding_id, loss);
        self.lost_order.push_back(binding_id);
        self.dropped = self.dropped.saturating_add(loss.documents);
    }

    /// Drops the oldest document, whole, and says whether it dropped anything.
    ///
    /// Whole, because half a document is worse than none: a reader that received some of a
    /// document's frames and not others could not tell which it was missing, and the last frame
    /// surviving would tell it the document was complete. Every frame of the oldest one goes
    /// together, and the loss is counted once.
    fn evict_oldest_document(&mut self) -> bool {
        let Some((binding_id, document)) = self.waiting.iter().find_map(|notice| match notice {
            Notice::Document {
                binding_id,
                document,
                ..
            } => Some((*binding_id, *document)),
            _ => None,
        }) else {
            return false;
        };
        let mut freed = 0;
        self.waiting.retain(|notice| {
            let theirs = matches!(
                notice,
                Notice::Document {
                    binding_id: held,
                    document: number,
                    ..
                } if *held == binding_id && *number == document
            );
            if theirs {
                freed += notice_bytes(notice);
            }
            !theirs
        });
        self.held = self.held.saturating_sub(freed);
        // Counted here rather than through `absorb`, which would try to make room again while it
        // is making room.
        let one = Loss {
            documents: 1,
            ..Loss::default()
        };
        if !self.merge(binding_id, one) {
            self.charge_loss(binding_id, one);
        }
        true
    }

    /// Takes the next notice: a loss first, because a reader has to know before it reads on.
    fn take(&mut self) -> Option<Notice> {
        if let Some(binding_id) = self.lost_order.pop_front()
            && let Some(loss) = self.lost.remove(&binding_id)
        {
            self.held = self.held.saturating_sub(NOTICE_OVERHEAD_BYTES);
            return Some(Notice::Gap {
                binding_id,
                events: loss.events,
                bytes: loss.bytes,
                documents: loss.documents,
            });
        }
        let notice = self.waiting.pop_front()?;
        self.held = self.held.saturating_sub(notice_bytes(&notice));
        Some(notice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(binding_id: Uuid, bytes: usize) -> Notice {
        Notice::Document {
            binding_id,
            call: "observe".to_owned(),
            document: 1,
            last: true,
            nodes: vec![WireNode {
                node_id: "n0".to_owned(),
                node_revision: 1,
                body_json: "x".repeat(bytes),
            }],
        }
    }

    fn binding(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    #[test]
    fn a_reader_that_keeps_up_gets_what_was_sent() {
        let (sink, mut stream) = channel();
        assert_eq!(sink.send(document(binding(1), 16)), Offered::Kept);
        assert!(matches!(stream.try_recv(), Some(Notice::Document { .. })));
        assert_eq!(stream.held_bytes(), 0);
        assert!(stream.try_recv().is_none());
    }

    #[test]
    fn a_reader_that_stops_reading_costs_a_bounded_amount_of_memory() {
        let (sink, mut stream) = channel();
        // Far more than the queue holds, from a component that keeps drawing.
        for _ in 0..64 {
            sink.send(document(binding(1), 256 * 1024));
        }
        assert!(
            stream.held_bytes() <= MAX_NOTICE_BYTES,
            "the queue held {} bytes",
            stream.held_bytes()
        );
        assert!(stream.dropped_documents() > 0);
        assert!(!stream.overflowed());

        // And the first thing the reader is told is that it missed documents, so it expects a
        // fresh one rather than a continuation.
        let first = stream.try_recv().expect("a notice");
        assert!(
            matches!(first, Notice::Gap { documents, .. } if documents > 0),
            "the reader was told {first:?}"
        );
    }

    #[test]
    fn gaps_coalesce_rather_than_accumulate() {
        let (sink, mut stream) = channel();
        for _ in 0..100_000 {
            sink.send(Notice::Gap {
                binding_id: binding(1),
                events: 1,
                bytes: 16,
                documents: 0,
            });
        }
        // One record, whatever the number of gaps: a reader that has stopped reading cannot be
        // given a backlog of them.
        assert!(stream.held_bytes() <= NOTICE_OVERHEAD_BYTES);
        let Some(Notice::Gap { events, bytes, .. }) = stream.try_recv() else {
            panic!("the losses were not reported");
        };
        assert_eq!(events, 100_000);
        assert_eq!(bytes, 1_600_000);
        assert!(stream.try_recv().is_none());
    }

    #[test]
    fn a_fault_is_never_dropped_to_make_room() {
        let (sink, mut stream) = channel();
        for _ in 0..64 {
            sink.send(document(binding(1), 256 * 1024));
        }
        assert_eq!(
            sink.send(Notice::Fault {
                binding_id: binding(1),
                call: "observe".to_owned(),
                detail: "the component trapped".to_owned(),
                faults_in_window: 1,
            }),
            Offered::Kept
        );
        assert_eq!(
            sink.send(Notice::Disabled {
                binding_id: binding(1),
                reason: "three faults in a minute".to_owned(),
            }),
            Offered::Kept
        );

        let mut faults = 0;
        let mut disabled = 0;
        while let Some(notice) = stream.try_recv() {
            match notice {
                Notice::Fault { .. } => faults += 1,
                Notice::Disabled { .. } => disabled += 1,
                Notice::Document { .. } | Notice::Gap { .. } => {}
            }
        }
        assert_eq!(faults, 1);
        assert_eq!(disabled, 1);
    }

    #[test]
    fn a_queue_that_cannot_hold_what_must_arrive_ends_the_connection() {
        let (sink, stream) = channel();
        // Faults alone, with nothing droppable to make room with. The queue says what it cannot do
        // rather than growing past its bound.
        let mut overflowed = false;
        for index in 0..200_000 {
            let offered = sink.send(Notice::Fault {
                binding_id: binding(1),
                call: "observe".to_owned(),
                detail: format!("fault {index} {}", "x".repeat(1024)),
                faults_in_window: 1,
            });
            if offered == Offered::Overflowed {
                overflowed = true;
                break;
            }
        }
        assert!(overflowed, "the queue grew past its bound");
        assert!(stream.overflowed());
        assert!(stream.is_closed());
        assert!(
            stream.held_bytes() <= MAX_NOTICE_BYTES,
            "the queue held {} bytes",
            stream.held_bytes()
        );
    }

    #[test]
    fn a_document_is_dropped_whole_or_not_at_all() {
        let (sink, mut stream) = channel();
        // One document in three pieces, then enough others to make room be needed. Half a document
        // would be worse than none: a reader that received the last piece would be told the
        // document was complete when it was not.
        let big = 512 * 1024;
        for piece in 0..3 {
            sink.send(Notice::Document {
                binding_id: binding(1),
                call: "snapshot".to_owned(),
                document: 1,
                last: piece == 2,
                nodes: vec![WireNode {
                    node_id: format!("n{piece}"),
                    node_revision: 1,
                    body_json: "x".repeat(big),
                }],
            });
        }
        for number in 2..12 {
            sink.send(Notice::Document {
                binding_id: binding(1),
                call: "observe".to_owned(),
                document: number,
                last: true,
                nodes: vec![WireNode {
                    node_id: "n0".to_owned(),
                    node_revision: 1,
                    body_json: "y".repeat(big),
                }],
            });
        }

        let mut pieces: std::collections::BTreeMap<u64, usize> = std::collections::BTreeMap::new();
        let mut lost = 0;
        while let Some(notice) = stream.try_recv() {
            match notice {
                Notice::Document { document, .. } => *pieces.entry(document).or_insert(0) += 1,
                Notice::Gap { documents, .. } => lost += documents,
                Notice::Fault { .. } | Notice::Disabled { .. } => {}
            }
        }
        assert!(lost > 0, "nothing was dropped, so nothing is under test");
        assert!(
            !pieces.contains_key(&1) || pieces[&1] == 3,
            "the three-piece document survived in pieces: {pieces:?}"
        );
    }

    #[test]
    fn a_gap_that_arrives_while_room_is_made_is_counted_once() {
        let (sink, mut stream) = channel();
        // Fill the queue, then offer that binding a gap. Making room creates the binding's loss
        // record; the gap has to find that record rather than replace it.
        for number in 0..16 {
            sink.send(Notice::Document {
                binding_id: binding(1),
                call: "observe".to_owned(),
                document: number,
                last: true,
                nodes: vec![WireNode {
                    node_id: "n0".to_owned(),
                    node_revision: 1,
                    body_json: "x".repeat(512 * 1024),
                }],
            });
        }
        sink.send(Notice::Gap {
            binding_id: binding(1),
            events: 7,
            bytes: 99,
            documents: 0,
        });

        let mut gaps = 0;
        let mut events = 0;
        let mut documents = 0;
        while let Some(notice) = stream.try_recv() {
            if let Notice::Gap {
                events: lost,
                documents: drawn,
                ..
            } = notice
            {
                gaps += 1;
                events += lost;
                documents += drawn;
            }
        }
        assert_eq!(gaps, 1, "one binding's losses became {gaps} gaps");
        assert_eq!(events, 7, "the observations the gap named were lost");
        assert!(
            documents > 0,
            "the documents that made room were not counted"
        );
        assert_eq!(
            stream.held_bytes(),
            0,
            "the queue kept a charge for nothing"
        );
    }

    #[test]
    fn a_loss_is_reported_against_the_binding_it_belonged_to() {
        let (sink, mut stream) = channel();
        for _ in 0..32 {
            sink.send(document(binding(1), 256 * 1024));
        }
        for _ in 0..32 {
            sink.send(document(binding(2), 256 * 1024));
        }
        let mut lost = Vec::new();
        while let Some(notice) = stream.try_recv() {
            if let Notice::Gap {
                binding_id,
                documents,
                ..
            } = notice
            {
                lost.push((binding_id, documents));
            }
        }
        assert!(lost.iter().any(|(id, _)| *id == binding(1)));
        assert!(lost.iter().all(|(_, documents)| *documents > 0));
    }

    #[tokio::test]
    async fn a_closed_queue_stops_a_reader_waiting_on_it() {
        let (sink, mut stream) = channel();
        sink.close();
        assert!(stream.recv().await.is_none());
        // And a sink whose reader is gone says so, which is what stops a forwarder.
        let (sink, stream) = channel();
        drop(stream);
        assert_eq!(sink.send(document(binding(1), 8)), Offered::Closed);
        assert!(sink.is_closed());
    }

    #[tokio::test]
    async fn a_reader_waiting_is_woken_by_what_arrives() {
        let (sink, mut stream) = channel();
        let sending = tokio::spawn(async move {
            tokio::time::sleep(core::time::Duration::from_millis(20)).await;
            sink.send(document(binding(3), 8));
        });
        let notice = tokio::time::timeout(core::time::Duration::from_secs(5), stream.recv())
            .await
            .expect("the reader was woken")
            .expect("a notice");
        assert_eq!(notice.binding_id(), binding(3));
        sending.await.expect("the sender finished");
    }

    #[tokio::test]
    async fn a_notice_that_arrives_before_the_reader_waits_still_wakes_it() {
        // The order that loses a wake-up if the queue only wakes whoever is already waiting: the
        // reader looks, finds nothing, and something arrives before it settles down to wait.
        let (sink, mut stream) = channel();
        assert!(stream.try_recv().is_none());
        sink.send(document(binding(4), 8));
        let notice = tokio::time::timeout(core::time::Duration::from_secs(5), stream.recv())
            .await
            .expect("the reader was not left waiting")
            .expect("a notice");
        assert_eq!(notice.binding_id(), binding(4));

        // And a queue closed the same way ends a reader rather than leaving it waiting.
        sink.close();
        assert!(
            tokio::time::timeout(core::time::Duration::from_secs(5), stream.recv())
                .await
                .expect("the reader was not left waiting")
                .is_none()
        );
    }
}
