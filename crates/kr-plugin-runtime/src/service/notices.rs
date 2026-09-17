//! The bounded queue a connection's notices wait in.
//!
//! A notice is something a binding produced without being asked: document nodes, a gap, a fault or
//! a disabling. Between the binding's thread and whoever reads the connection there has to be
//! somewhere for them to wait, and that somewhere has to be bounded: a component can emit a
//! mebibyte per call, and a reader that has stopped reading must not be able to make either process
//! grow without limit.
//!
//! # What gives way
//!
//! Presentation. A document a reader never collected is a document the component can draw again, so
//! an overflow drops the oldest documents, counts them, and reports the loss as a gap with no events
//! named. The reader knows to expect a fresh document rather than a continuation, which is the same
//! answer a lost observation gets and for the same reason.
//!
//! A fault and a disabling are not presentation. Nothing else tells a reader that a binding stopped
//! working, so they are admitted whatever the queue holds; what keeps that from being a hole in the
//! bound is that their text is clipped where it is built and a connection holds a bounded number of
//! bindings, each of which faults a bounded number of times before it is disabled.

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
/// this queue and a frame on the wire whatever its strings say.
const NOTICE_OVERHEAD_BYTES: u64 = 64;

/// What one document node costs.
///
/// The runtime charges the same fixed cost per node against a call's output budget, so a document
/// that fitted that budget fits this queue's accounting too.
const NODE_OVERHEAD_BYTES: u64 = crate::runtime::host::NODE_OVERHEAD_BYTES;

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
    /// Documents dropped for want of room, by the binding they belonged to, waiting to be reported.
    lost: HashMap<Uuid, u64>,
    /// The order the losses are reported in, so the oldest loss is the first a reader hears about.
    lost_order: VecDeque<Uuid>,
    closed: bool,
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
    ///
    /// Returns false once the stream is closed, which is what tells a forwarder to stop.
    pub fn send(&self, notice: Notice) -> bool {
        let Ok(mut queue) = self.shared.queue.lock() else {
            return false;
        };
        if queue.closed {
            return false;
        }
        queue.admit(notice);
        drop(queue);
        self.shared.wake.notify_waiters();
        true
    }

    /// Closes the queue, so a reader waiting on it stops waiting.
    pub fn close(&self) {
        if let Ok(mut queue) = self.shared.queue.lock() {
            queue.closed = true;
        }
        self.shared.wake.notify_waiters();
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
}

impl Drop for NoticeStream {
    /// A reader that is gone is a reader nothing should keep producing for.
    fn drop(&mut self) {
        if let Ok(mut queue) = self.shared.queue.lock() {
            queue.closed = true;
            queue.waiting.clear();
            queue.held = 0;
        }
    }
}

impl Queued {
    /// Admits one notice, making room by dropping presentation.
    fn admit(&mut self, notice: Notice) {
        let cost = notice_bytes(&notice);
        let droppable = matches!(notice, Notice::Document { .. });
        while self.held + cost > MAX_NOTICE_BYTES && self.evict_oldest_document() {}
        if self.held + cost > MAX_NOTICE_BYTES && droppable {
            // Nothing left to make room with, and this is presentation. It goes, and the reader is
            // told so it expects a fresh document.
            self.record_loss(notice.binding_id());
            return;
        }
        self.held += cost;
        self.waiting.push_back(notice);
    }

    /// Drops the oldest document, if there is one, and says whether it dropped anything.
    fn evict_oldest_document(&mut self) -> bool {
        let Some(position) = self
            .waiting
            .iter()
            .position(|notice| matches!(notice, Notice::Document { .. }))
        else {
            return false;
        };
        let Some(dropped) = self.waiting.remove(position) else {
            return false;
        };
        self.held = self.held.saturating_sub(notice_bytes(&dropped));
        self.record_loss(dropped.binding_id());
        true
    }

    /// Counts one lost document against the binding it belonged to.
    fn record_loss(&mut self, binding_id: Uuid) {
        self.dropped = self.dropped.saturating_add(1);
        let counted = self.lost.entry(binding_id).or_insert_with(|| {
            self.lost_order.push_back(binding_id);
            0
        });
        *counted = counted.saturating_add(1);
    }

    /// Takes the next notice: a loss first, because a reader has to know before it reads on.
    fn take(&mut self) -> Option<Notice> {
        if let Some(binding_id) = self.lost_order.pop_front()
            && let Some(documents) = self.lost.remove(&binding_id)
        {
            return Some(Notice::Gap {
                binding_id,
                events: 0,
                bytes: documents,
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
        assert!(sink.send(document(binding(1), 16)));
        assert!(matches!(stream.try_recv(), Some(Notice::Document { .. })));
        assert_eq!(stream.held_bytes(), 0);
        assert!(stream.try_recv().is_none());
    }

    #[test]
    fn a_reader_that_stops_reading_costs_a_bounded_amount_of_memory() {
        let (sink, mut stream) = channel();
        // Far more than the queue holds, from a component that keeps drawing.
        for _ in 0..64 {
            assert!(sink.send(document(binding(1), 256 * 1024)));
        }
        assert!(
            stream.held_bytes() <= MAX_NOTICE_BYTES,
            "the queue held {} bytes",
            stream.held_bytes()
        );
        assert!(stream.dropped_documents() > 0);

        // And the first thing the reader is told is that it missed documents, so it expects a
        // fresh one rather than a continuation.
        let first = stream.try_recv().expect("a notice");
        assert!(
            matches!(first, Notice::Gap { events: 0, bytes, .. } if bytes > 0),
            "the reader was told {first:?}"
        );
    }

    #[test]
    fn a_fault_is_never_dropped_to_make_room() {
        let (sink, mut stream) = channel();
        for _ in 0..64 {
            sink.send(document(binding(1), 256 * 1024));
        }
        assert!(sink.send(Notice::Fault {
            binding_id: binding(1),
            call: "observe".to_owned(),
            detail: "the component trapped".to_owned(),
            faults_in_window: 1,
        }));
        assert!(sink.send(Notice::Disabled {
            binding_id: binding(1),
            reason: "three faults in a minute".to_owned(),
        }));

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
                events: 0,
                bytes,
            } = notice
            {
                lost.push((binding_id, bytes));
            }
        }
        assert!(lost.iter().any(|(id, _)| *id == binding(1)));
        assert!(lost.iter().all(|(_, bytes)| *bytes > 0));
    }

    #[tokio::test]
    async fn a_closed_queue_stops_a_reader_waiting_on_it() {
        let (sink, mut stream) = channel();
        sink.close();
        assert!(stream.recv().await.is_none());
        // And a sink whose reader is gone says so, which is what stops a forwarder.
        let (sink, stream) = channel();
        drop(stream);
        assert!(!sink.send(document(binding(1), 8)));
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
}
