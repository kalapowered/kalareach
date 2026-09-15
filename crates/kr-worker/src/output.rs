//! Fan-out of terminal output to every attachment.
//!
//! The rule that shapes this module is in section 9: a slow client cannot hold the pseudo-terminal
//! read loop. So publishing never waits. Each subscriber has its own queue with its own byte
//! bound, and a subscriber that reaches its bound is not slowed down, not blocked and not silently
//! trimmed — it is told to resynchronise, its queue is dropped, and the read loop carries on for
//! everyone else.
//!
//! The worker still honours the operating system's own backpressure if terminal parsing itself
//! cannot keep up. What it must never do is discard parser input and claim its screen is correct,
//! which is why the bound lives on the delivery queues and not on the read.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use kr_protocol::ids::AttachmentId;
use kr_protocol::recovery::{ResyncReason, ResyncRequired};
use kr_protocol::scalars::U64;
use tokio::sync::mpsc;

/// The bound on one subscriber's queued bytes.
pub const DEFAULT_SEND_QUEUE_BYTES: usize = 8 * 1024 * 1024;

/// One thing delivered to a subscriber.
#[derive(Clone, Debug)]
pub enum OutputDelivery {
    /// Output bytes and the cursor they start at.
    Bytes {
        /// The cursor these bytes start at.
        cursor: u64,
        /// The bytes. Shared, because every subscriber receives the same ones.
        bytes: Arc<Vec<u8>>,
    },
    /// The subscriber must discard its partial state and install a fresh snapshot.
    Resync(ResyncRequired),
    /// The attachment was detached. Nothing more will arrive on this stream.
    Detached,
}

impl OutputDelivery {
    /// Returns how many bytes this delivery accounts for against a subscriber's bound.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Bytes { bytes, .. } => bytes.len(),
            Self::Resync(_) | Self::Detached => 0,
        }
    }

    /// Returns whether this delivery carries no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The receiving end of one subscription.
#[derive(Debug)]
pub struct OutputStream {
    receiver: mpsc::UnboundedReceiver<OutputDelivery>,
    queued: Arc<AtomicUsize>,
}

impl OutputStream {
    /// Takes the next delivery.
    ///
    /// Taking a delivery does **not** release the bytes it accounted for. The bound section 9 puts
    /// on a subscriber is on what is queued *for that peer*, and a delivery that has been taken
    /// off this channel and is waiting on a socket the peer is not reading is still queued for it.
    /// Releasing here would mean a client that never reads is never found to be behind: the
    /// backlog would sit in the sender instead, unaccounted for and unbounded.
    ///
    /// The consumer calls [`OutputStream::written`] once the bytes have reached the peer.
    pub async fn recv(&mut self) -> Option<OutputDelivery> {
        self.receiver.recv().await
    }

    /// Releases the bytes of a delivery that has reached the peer.
    pub fn written(&self, delivery_len: usize) {
        // Saturating, because a resynchronisation can discard deliveries this subscriber will
        // never report as written.
        let _ = self
            .queued
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                Some(queued.saturating_sub(delivery_len))
            });
    }

    /// Returns the bytes currently waiting for this subscriber.
    #[must_use]
    pub fn queued_bytes(&self) -> usize {
        self.queued.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
struct Subscriber {
    sender: mpsc::UnboundedSender<OutputDelivery>,
    queued: Arc<AtomicUsize>,
    limit: usize,
    resynchronising: bool,
}

/// Every attachment currently receiving output.
#[derive(Debug, Default)]
pub struct OutputHub {
    subscribers: BTreeMap<AttachmentId, Subscriber>,
}

impl OutputHub {
    /// Builds an empty hub.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces a subscription.
    ///
    /// Resubscribing clears a previous resynchronisation: the client has just installed a fresh
    /// snapshot, which is exactly what the marker asked it to do.
    pub fn subscribe(&mut self, attachment_id: AttachmentId, limit: usize) -> OutputStream {
        let (sender, receiver) = mpsc::unbounded_channel();
        let queued = Arc::new(AtomicUsize::new(0));
        self.subscribers.insert(
            attachment_id,
            Subscriber {
                sender,
                queued: Arc::clone(&queued),
                limit,
                resynchronising: false,
            },
        );
        OutputStream { receiver, queued }
    }

    /// Tells a subscriber its attachment has been detached, then removes it.
    ///
    /// A terminal whose attachment was ended somewhere else has to learn that it was, or it sits
    /// waiting for output that is never coming and only finds out when its next keystroke is
    /// refused.
    pub fn detached(&mut self, attachment_id: AttachmentId) {
        if let Some(subscriber) = self.subscribers.get(&attachment_id) {
            let _ = subscriber.sender.send(OutputDelivery::Detached);
        }
        self.unsubscribe(attachment_id);
    }

    /// Removes a subscription.
    pub fn unsubscribe(&mut self, attachment_id: AttachmentId) {
        self.subscribers.remove(&attachment_id);
    }

    /// Returns how many subscribers the hub has.
    #[must_use]
    pub fn len(&self) -> usize {
        self.subscribers.len()
    }

    /// Returns true when nothing is subscribed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.subscribers.is_empty()
    }

    /// Returns true when this subscriber is waiting for a fresh snapshot.
    #[must_use]
    pub fn is_resynchronising(&self, attachment_id: AttachmentId) -> bool {
        self.subscribers
            .get(&attachment_id)
            .is_some_and(|subscriber| subscriber.resynchronising)
    }

    /// Delivers output to every subscriber that is keeping up.
    ///
    /// Returns the subscribers that were told to resynchronise. This call never awaits and never
    /// fails: the read loop that produced these bytes continues whatever any client is doing.
    pub fn publish(
        &mut self,
        cursor: u64,
        bytes: &Arc<Vec<u8>>,
        oldest_retained_cursor: u64,
    ) -> Vec<AttachmentId> {
        let mut resynchronised = Vec::new();
        let mut gone = Vec::new();
        for (id, subscriber) in &mut self.subscribers {
            if subscriber.resynchronising {
                continue;
            }
            let queued = subscriber.queued.load(Ordering::Acquire);
            if queued.saturating_add(bytes.len()) > subscriber.limit {
                subscriber.resynchronising = true;
                // Nothing is trimmed and nothing is zeroed here. The subscriber still owns what is
                // already queued and releases it as it reads; stopping new output is what bounds
                // the queue. Zeroing the counter would make those later releases underflow it.
                let marker = ResyncRequired {
                    reason: ResyncReason::SendQueueFull,
                    cursor: U64::new(cursor),
                    oldest_retained_cursor: U64::new(oldest_retained_cursor),
                };
                if subscriber
                    .sender
                    .send(OutputDelivery::Resync(marker))
                    .is_err()
                {
                    gone.push(*id);
                }
                resynchronised.push(*id);
                continue;
            }
            subscriber.queued.fetch_add(bytes.len(), Ordering::AcqRel);
            if subscriber
                .sender
                .send(OutputDelivery::Bytes {
                    cursor,
                    bytes: Arc::clone(bytes),
                })
                .is_err()
            {
                gone.push(*id);
            }
        }
        for id in gone {
            self.subscribers.remove(&id);
        }
        resynchronised
    }

    /// Tells one subscriber to resynchronise for a reason other than its queue.
    pub fn require_resync(
        &mut self,
        attachment_id: AttachmentId,
        reason: ResyncReason,
        cursor: u64,
        oldest_retained_cursor: u64,
    ) {
        if let Some(subscriber) = self.subscribers.get_mut(&attachment_id) {
            // The same accounting rule as an overflow. Bytes already queued still belong to the
            // subscriber and it releases them as it reads; zeroing the counter here would make
            // every one of those releases subtract from nothing.
            subscriber.resynchronising = true;
            let _ = subscriber
                .sender
                .send(OutputDelivery::Resync(ResyncRequired {
                    reason,
                    cursor: U64::new(cursor),
                    oldest_retained_cursor: U64::new(oldest_retained_cursor),
                }));
        }
    }
}

#[cfg(test)]
mod tests {
    use kr_protocol::scalars::Uuid;

    use super::*;

    fn identifier(byte: u8) -> AttachmentId {
        AttachmentId::new(Uuid::from_bytes([byte; 16]))
    }

    #[tokio::test]
    async fn every_subscriber_receives_the_same_bytes() {
        let mut hub = OutputHub::new();
        let mut first = hub.subscribe(identifier(1), 1024);
        let mut second = hub.subscribe(identifier(2), 1024);
        assert!(hub.publish(0, &Arc::new(b"hello".to_vec()), 0).is_empty());
        for stream in [&mut first, &mut second] {
            match stream.recv().await.expect("a delivery") {
                OutputDelivery::Bytes { cursor, bytes } => {
                    assert_eq!(cursor, 0);
                    assert_eq!(bytes.as_slice(), b"hello");
                }
                other => panic!("an unexpected delivery: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn a_slow_subscriber_is_resynchronised_and_the_others_are_not_held_up() {
        let mut hub = OutputHub::new();
        let mut slow = hub.subscribe(identifier(1), 8);
        let mut quick = hub.subscribe(identifier(2), 1024);
        // The quick subscriber drains; the slow one does not.
        hub.publish(0, &Arc::new(vec![b'a'; 8]), 0);
        let _ = quick.recv().await.expect("a delivery");
        let resynchronised = hub.publish(8, &Arc::new(vec![b'b'; 8]), 0);
        assert_eq!(resynchronised, vec![identifier(1)]);
        assert!(hub.is_resynchronising(identifier(1)));

        // The quick subscriber still receives everything, in order.
        match quick.recv().await.expect("a delivery") {
            OutputDelivery::Bytes { cursor, bytes } => {
                assert_eq!(cursor, 8);
                assert_eq!(bytes.len(), 8);
            }
            other => panic!("the quick subscriber kept up: {other:?}"),
        }

        // The slow one receives what it had, then the marker, and nothing after it.
        let first = slow.recv().await.expect("a delivery");
        assert!(matches!(first, OutputDelivery::Bytes { .. }));
        match slow.recv().await.expect("a delivery") {
            OutputDelivery::Resync(marker) => {
                assert_eq!(marker.reason, ResyncReason::SendQueueFull);
                assert_eq!(marker.cursor.get(), 8);
            }
            other => panic!("the slow subscriber was resynchronised: {other:?}"),
        }
        hub.publish(16, &Arc::new(vec![b'c'; 8]), 0);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), slow.recv())
                .await
                .is_err(),
            "nothing more is queued until the client resubscribes"
        );
    }

    #[tokio::test]
    async fn resubscribing_clears_the_resynchronisation() {
        let mut hub = OutputHub::new();
        let _slow = hub.subscribe(identifier(1), 4);
        hub.publish(0, &Arc::new(vec![b'a'; 4]), 0);
        hub.publish(4, &Arc::new(vec![b'b'; 4]), 0);
        assert!(hub.is_resynchronising(identifier(1)));
        let mut fresh = hub.subscribe(identifier(1), 4);
        assert!(!hub.is_resynchronising(identifier(1)));
        hub.publish(8, &Arc::new(b"ok".to_vec()), 8);
        assert!(matches!(
            fresh.recv().await.expect("a delivery"),
            OutputDelivery::Bytes { cursor: 8, .. }
        ));
    }

    #[tokio::test]
    async fn a_departed_subscriber_is_dropped_without_affecting_the_others() {
        let mut hub = OutputHub::new();
        let departed = hub.subscribe(identifier(1), 1024);
        let mut staying = hub.subscribe(identifier(2), 1024);
        drop(departed);
        hub.publish(0, &Arc::new(b"x".to_vec()), 0);
        assert_eq!(hub.len(), 1);
        assert!(matches!(
            staying.recv().await.expect("a delivery"),
            OutputDelivery::Bytes { .. }
        ));
    }
}
