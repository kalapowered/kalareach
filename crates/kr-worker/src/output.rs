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
    /// A rendering of the canonical screen as it stands at one cursor.
    ///
    /// It is not a span of the output stream: it is what that stream *produced*, drawn for one
    /// subscriber's own window. Its cursor is the state it describes rather than an offset, so it
    /// is delivered whole, at one cursor, however many frames that takes.
    Screen {
        /// The cursor the screen describes.
        cursor: u64,
        /// The bytes that draw it.
        bytes: Arc<Vec<u8>>,
    },
    /// One projection event: a reset, a snapshot, one of its row pages, or a bounded update.
    ///
    /// A projected attachment receives these instead of a rendering of the whole screen. Its cost
    /// against the subscriber's bound is measured when it is built, because the queue is bounded in
    /// bytes and an event is not bytes until something encodes it.
    Projection {
        /// The cursor the event describes.
        cursor: u64,
        /// The event.
        event: Box<kr_protocol::projection::ProjectionEvent>,
        /// What it costs this subscriber's queue.
        bytes: usize,
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
            Self::Bytes { bytes, .. } | Self::Screen { bytes, .. } => bytes.len(),
            Self::Projection { bytes, .. } => *bytes,
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
    /// Whether this subscriber takes the raw stream or a rendering of the canonical screen.
    ///
    /// A broadcast reaches only the subscribers that take the raw stream. A terminal of another
    /// size is looking at its own window of the grid, so what it is sent is computed for it and
    /// delivered to it alone.
    presentation: Presentation,
}

/// How one subscriber is being served.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Presentation {
    /// The spans of the raw stream a terminal may take unchanged.
    #[default]
    Direct,
    /// A rendering of the canonical screen, clipped to this subscriber's own size.
    Projected,
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
    pub fn subscribe(
        &mut self,
        attachment_id: AttachmentId,
        limit: usize,
        presentation: Presentation,
    ) -> OutputStream {
        let (sender, receiver) = mpsc::unbounded_channel();
        let queued = Arc::new(AtomicUsize::new(0));
        self.subscribers.insert(
            attachment_id,
            Subscriber {
                sender,
                queued: Arc::clone(&queued),
                limit,
                resynchronising: false,
                presentation,
            },
        );
        OutputStream { receiver, queued }
    }

    /// Records how one subscriber is being served.
    ///
    /// A terminal moves between the two when the stream stops being something it can take
    /// unchanged, or when it becomes one again. The caller resynchronises it around the change, so
    /// nothing it holds is continued into a form it does not match.
    /// Returns whether this changed how the subscriber is being served.
    pub fn set_presentation(
        &mut self,
        attachment_id: AttachmentId,
        presentation: Presentation,
    ) -> bool {
        let Some(subscriber) = self.subscribers.get_mut(&attachment_id) else {
            return false;
        };
        let changed = subscriber.presentation != presentation;
        subscriber.presentation = presentation;
        changed
    }

    /// Returns how one subscriber is currently being served.
    ///
    /// `None` for an attachment with no subscription, which is one that has not joined yet and is
    /// therefore not forwarding anything.
    #[must_use]
    pub fn presentation_of(&self, attachment_id: AttachmentId) -> Option<Presentation> {
        self.subscribers
            .get(&attachment_id)
            .map(|subscriber| subscriber.presentation)
    }

    /// Returns every attachment currently subscribed.
    #[must_use]
    pub fn subscribers(&self) -> Vec<AttachmentId> {
        self.subscribers.keys().copied().collect()
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
    pub fn publish_direct(
        &mut self,
        cursor: u64,
        bytes: &Arc<Vec<u8>>,
        oldest_retained_cursor: u64,
    ) -> Vec<AttachmentId> {
        let mut resynchronised = Vec::new();
        let mut gone = Vec::new();
        for (id, subscriber) in &mut self.subscribers {
            if subscriber.resynchronising || subscriber.presentation != Presentation::Direct {
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

    /// Delivers bytes to one subscriber.
    ///
    /// This is how anything computed for a single attachment reaches it: the rendering of the
    /// canonical screen a terminal of another size is shown, and the side effects that belong to
    /// the one attachment holding the input lease. Returns whether the subscriber was told to
    /// resynchronise.
    pub fn publish_to(
        &mut self,
        attachment_id: AttachmentId,
        cursor: u64,
        bytes: &Arc<Vec<u8>>,
        oldest_retained_cursor: u64,
    ) -> bool {
        self.deliver_one(attachment_id, cursor, bytes, oldest_retained_cursor, false)
    }

    /// Delivers a rendering of the canonical screen to one subscriber.
    ///
    /// Returns whether the subscriber was told to resynchronise.
    pub fn publish_screen(
        &mut self,
        attachment_id: AttachmentId,
        cursor: u64,
        bytes: &Arc<Vec<u8>>,
        oldest_retained_cursor: u64,
    ) -> bool {
        self.deliver_one(attachment_id, cursor, bytes, oldest_retained_cursor, true)
    }

    /// Delivers one projection event to one subscriber.
    ///
    /// A projected attachment is served state rather than bytes, and the state is computed for its
    /// own window, so it is delivered to it alone. Returns whether the subscriber was told to
    /// resynchronise, which happens for the same reason as any other delivery: its queue is full,
    /// and the read loop does not wait for it.
    pub fn publish_projection(
        &mut self,
        attachment_id: AttachmentId,
        cursor: u64,
        event: kr_protocol::projection::ProjectionEvent,
        cost: usize,
        oldest_retained_cursor: u64,
    ) -> bool {
        let Some(subscriber) = self.subscribers.get_mut(&attachment_id) else {
            return false;
        };
        if subscriber.resynchronising {
            return false;
        }
        let queued = subscriber.queued.load(Ordering::Acquire);
        if queued.saturating_add(cost) > subscriber.limit {
            subscriber.resynchronising = true;
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
                self.subscribers.remove(&attachment_id);
            }
            return true;
        }
        subscriber.queued.fetch_add(cost, Ordering::AcqRel);
        if subscriber
            .sender
            .send(OutputDelivery::Projection {
                cursor,
                event: Box::new(event),
                bytes: cost,
            })
            .is_err()
        {
            self.subscribers.remove(&attachment_id);
        }
        false
    }

    fn deliver_one(
        &mut self,
        attachment_id: AttachmentId,
        cursor: u64,
        bytes: &Arc<Vec<u8>>,
        oldest_retained_cursor: u64,
        screen: bool,
    ) -> bool {
        let Some(subscriber) = self.subscribers.get_mut(&attachment_id) else {
            return false;
        };
        if subscriber.resynchronising {
            return false;
        }
        let queued = subscriber.queued.load(Ordering::Acquire);
        if queued.saturating_add(bytes.len()) > subscriber.limit {
            subscriber.resynchronising = true;
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
                self.subscribers.remove(&attachment_id);
            }
            return true;
        }
        subscriber.queued.fetch_add(bytes.len(), Ordering::AcqRel);
        let delivery = if screen {
            OutputDelivery::Screen {
                cursor,
                bytes: Arc::clone(bytes),
            }
        } else {
            OutputDelivery::Bytes {
                cursor,
                bytes: Arc::clone(bytes),
            }
        };
        if subscriber.sender.send(delivery).is_err() {
            self.subscribers.remove(&attachment_id);
        }
        false
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
        let mut first = hub.subscribe(identifier(1), 1024, Presentation::Direct);
        let mut second = hub.subscribe(identifier(2), 1024, Presentation::Direct);
        assert!(
            hub.publish_direct(0, &Arc::new(b"hello".to_vec()), 0)
                .is_empty()
        );
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
        let mut slow = hub.subscribe(identifier(1), 8, Presentation::Direct);
        let mut quick = hub.subscribe(identifier(2), 1024, Presentation::Direct);
        // The quick subscriber drains; the slow one does not.
        hub.publish_direct(0, &Arc::new(vec![b'a'; 8]), 0);
        let _ = quick.recv().await.expect("a delivery");
        let resynchronised = hub.publish_direct(8, &Arc::new(vec![b'b'; 8]), 0);
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
        hub.publish_direct(16, &Arc::new(vec![b'c'; 8]), 0);
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
        let _slow = hub.subscribe(identifier(1), 4, Presentation::Direct);
        hub.publish_direct(0, &Arc::new(vec![b'a'; 4]), 0);
        hub.publish_direct(4, &Arc::new(vec![b'b'; 4]), 0);
        assert!(hub.is_resynchronising(identifier(1)));
        let mut fresh = hub.subscribe(identifier(1), 4, Presentation::Direct);
        assert!(!hub.is_resynchronising(identifier(1)));
        hub.publish_direct(8, &Arc::new(b"ok".to_vec()), 8);
        assert!(matches!(
            fresh.recv().await.expect("a delivery"),
            OutputDelivery::Bytes { cursor: 8, .. }
        ));
    }

    #[tokio::test]
    async fn a_departed_subscriber_is_dropped_without_affecting_the_others() {
        let mut hub = OutputHub::new();
        let departed = hub.subscribe(identifier(1), 1024, Presentation::Direct);
        let mut staying = hub.subscribe(identifier(2), 1024, Presentation::Direct);
        drop(departed);
        hub.publish_direct(0, &Arc::new(b"x".to_vec()), 0);
        assert_eq!(hub.len(), 1);
        assert!(matches!(
            staying.recv().await.expect("a delivery"),
            OutputDelivery::Bytes { .. }
        ));
    }
}
