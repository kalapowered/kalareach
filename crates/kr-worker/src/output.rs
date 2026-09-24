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
use kr_protocol::session::ClosureRecord;
use tokio::sync::mpsc;

/// The bound on one subscriber's queued bytes.
pub const DEFAULT_SEND_QUEUE_BYTES: usize = 8 * 1024 * 1024;

/// What one resynchronisation marker costs a subscriber's queue.
///
/// A marker is small, and it is still something queued for a peer, so it is charged like
/// everything else. It is at least what any marker encodes to, whatever its reason and cursors.
pub const RESYNC_MARKER_BYTES: usize = 96;

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
    /// The editor could not be fenced, and this subscriber's input waited for it.
    ///
    /// It carries no output, so it costs the subscriber's queue nothing: what it reports is the
    /// lease change that stands and the bytes that were released in their original order.
    EditorBusy(Box<kr_protocol::root::EditorBusyEvent>),
    /// One committed broker transition, for a view that observes this session's agent.
    ///
    /// It is charged against the subscriber's queue bound so that a stalled view cannot
    /// accumulate unlimited events.
    AgentResource {
        /// The event that announces what changed about the resource.
        event: Box<kr_protocol::projection::AgentResourceEvent>,
        /// How many bytes this event counts against the subscriber's queue limit.
        bytes: usize,
    },
    /// The subscriber must discard its partial state and install a fresh snapshot.
    ///
    /// A subscriber is told this once for each time it has to resynchronise, whatever number of
    /// reasons arise before it has: the fresh snapshot it installs covers every one of them. The
    /// marker is charged [`RESYNC_MARKER_BYTES`] against the subscriber's queue.
    Resync(ResyncRequired),
    /// The attachment was detached. Nothing more will arrive on this stream.
    Detached,
    /// The session has closed, and this is how. Nothing more will arrive on this stream.
    Closed(ClosureNotice),
}

impl OutputDelivery {
    /// Returns how many bytes this delivery accounts for against a subscriber's bound.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Bytes { bytes, .. } | Self::Screen { bytes, .. } => bytes.len(),
            Self::Projection { bytes, .. } | Self::AgentResource { bytes, .. } => *bytes,
            Self::Resync(_) => RESYNC_MARKER_BYTES,
            Self::EditorBusy(_) | Self::Detached | Self::Closed(_) => 0,
        }
    }

    /// Returns whether this delivery carries no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One attachment's copy of how its session closed.
///
/// A notice is owed until it is dropped. Whoever delivers it drops it once it has been written or
/// once there is nowhere left to write it, and a notice that could not be queued at all, because
/// its subscriber had already gone, is dropped at once. [`ClosureDeliveries`] counts the ones still
/// owed, which is what a worker waits on before it exits.
#[derive(Debug)]
pub struct ClosureNotice {
    record: Arc<ClosureRecord>,
    owed: Owed,
}

impl ClosureNotice {
    fn new(record: &Arc<ClosureRecord>, deliveries: &Arc<ClosureDeliveries>) -> Self {
        Self {
            record: Arc::clone(record),
            owed: Owed::new(deliveries),
        }
    }

    /// The session's closure record.
    #[must_use]
    pub fn record(&self) -> &ClosureRecord {
        &self.record
    }
}

impl Clone for ClosureNotice {
    /// A second copy is a second notice to deliver, and it is owed on its own.
    fn clone(&self) -> Self {
        Self {
            record: Arc::clone(&self.record),
            owed: self.owed.clone(),
        }
    }
}

/// One notice's share of what a hub still owes.
#[derive(Debug)]
struct Owed(Arc<ClosureDeliveries>);

impl Owed {
    fn new(deliveries: &Arc<ClosureDeliveries>) -> Self {
        deliveries.outstanding.fetch_add(1, Ordering::AcqRel);
        Self(Arc::clone(deliveries))
    }
}

impl Clone for Owed {
    fn clone(&self) -> Self {
        Self::new(&self.0)
    }
}

impl Drop for Owed {
    fn drop(&mut self) {
        if self.0.outstanding.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.settled.notify_waiters();
        }
    }
}

/// The closure notices a hub has handed out and that have not been delivered yet.
#[derive(Debug, Default)]
pub struct ClosureDeliveries {
    outstanding: AtomicUsize,
    settled: tokio::sync::Notify,
}

impl ClosureDeliveries {
    /// Returns how many notices are still owed.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.outstanding.load(Ordering::Acquire)
    }

    /// Waits until no notice is owed, returning at once when none is.
    ///
    /// A notice handed to an attachment that subscribes while this waits is waited for as well.
    pub async fn settled(&self) {
        loop {
            let notified = self.settled.notified();
            tokio::pin!(notified);
            // Registered before the count is read, so a last notice dropped between the two still
            // wakes this.
            notified.as_mut().enable();
            if self.outstanding() == 0 {
                return;
            }
            notified.await;
        }
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

    /// Takes the next delivery already queued, without waiting for one.
    ///
    /// It is what a reader that knows everything producing for it has finished uses to take the
    /// whole of what it was sent, rather than waiting for a quiet moment and calling that the end.
    /// The same accounting rule applies as for [`OutputStream::recv`].
    pub fn try_recv(&mut self) -> Option<OutputDelivery> {
        self.receiver.try_recv().ok()
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

impl Subscriber {
    /// Tells this subscriber to resynchronise, once, and charges the marker to its queue.
    ///
    /// One marker waits per subscription until the subscriber resubscribes. A subscriber that is
    /// already resynchronising is sent nothing more, whatever the new reason: its resubscription
    /// takes a fresh screen and presentation under the session's lock, so what it installs covers
    /// every reason that arose in between. A second marker would tell it nothing, and repeating
    /// markers is the one thing that could still grow a queue that has stopped taking output.
    ///
    /// Everything already queued stays the subscriber's, and it releases those bytes as it reads;
    /// the marker is added to them rather than replacing them.
    ///
    /// Returns false when the subscriber's end has gone, which its caller removes it for.
    fn resynchronise(&mut self, reason: ResyncReason, cursor: u64, oldest_retained: u64) -> bool {
        if self.resynchronising {
            return !self.sender.is_closed();
        }
        self.resynchronising = true;
        self.queued.fetch_add(RESYNC_MARKER_BYTES, Ordering::AcqRel);
        self.sender
            .send(OutputDelivery::Resync(ResyncRequired {
                reason,
                cursor: U64::new(cursor),
                oldest_retained_cursor: U64::new(oldest_retained),
            }))
            .is_ok()
    }
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
    /// How the session closed, once it has. A hub that holds it has told every subscriber, and
    /// keeps none: all there is left to say to an attachment is this.
    closure: Option<Arc<ClosureRecord>>,
    /// The attachments that had no subscription when the session closed.
    ///
    /// Each is owed the closure all the same: it was admitted, its client may be about to
    /// subscribe, and a worker that stopped counting it would exit under it. It is owed until it
    /// subscribes, which puts the notice on its stream, or until it leaves.
    awaiting: BTreeMap<AttachmentId, Owed>,
    /// The closure notices handed out and not yet delivered.
    deliveries: Arc<ClosureDeliveries>,
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
    ///
    /// On a hub whose session has closed the stream carries the closure and then ends. An
    /// attachment that subscribes between the closure and the worker's exit still learns how the
    /// session ended, rather than finding a connection that stopped.
    pub fn subscribe(
        &mut self,
        attachment_id: AttachmentId,
        limit: usize,
        presentation: Presentation,
    ) -> OutputStream {
        let (sender, receiver) = mpsc::unbounded_channel();
        let queued = Arc::new(AtomicUsize::new(0));
        if let Some(record) = self.closure.as_ref() {
            let _ = sender.send(OutputDelivery::Closed(ClosureNotice::new(
                record,
                &self.deliveries,
            )));
            // What it was owed from the moment the session closed is on its stream now, and the
            // notice there is what is owed from here.
            self.awaiting.remove(&attachment_id);
            return OutputStream { receiver, queued };
        }
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
    ///
    /// An attachment that leaves after its session closed is owed nothing more.
    pub fn unsubscribe(&mut self, attachment_id: AttachmentId) {
        self.subscribers.remove(&attachment_id);
        self.awaiting.remove(&attachment_id);
    }

    /// Tells every attachment how the session closed, and removes every subscription.
    ///
    /// `attachments` is every attachment the session holds. One with a subscription is sent the
    /// record through its own queue, so it arrives after everything that subscriber was sent
    /// before it. It is not charged against the queue's bound, and a subscriber that is
    /// resynchronising is told as well: falling behind loses output, not the news of how the
    /// session ended. One without a subscription is owed the record until it subscribes or leaves,
    /// because it may be about to subscribe. A subscriber that has already gone is owed nothing.
    /// The session has one closure, so a second call changes nothing.
    pub fn close(
        &mut self,
        record: &ClosureRecord,
        attachments: impl IntoIterator<Item = AttachmentId>,
    ) {
        if self.closure.is_some() {
            return;
        }
        let record = Arc::new(record.clone());
        let subscribers = std::mem::take(&mut self.subscribers);
        for attachment_id in attachments {
            if !subscribers.contains_key(&attachment_id) {
                self.awaiting
                    .insert(attachment_id, Owed::new(&self.deliveries));
            }
        }
        for subscriber in subscribers.into_values() {
            let _ = subscriber
                .sender
                .send(OutputDelivery::Closed(ClosureNotice::new(
                    &record,
                    &self.deliveries,
                )));
        }
        self.closure = Some(record);
    }

    /// Returns the closure notices this hub still owes, which a caller can wait on.
    #[must_use]
    pub fn closure_deliveries(&self) -> Arc<ClosureDeliveries> {
        Arc::clone(&self.deliveries)
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

    /// What one subscriber's send queue holds, in bytes.
    ///
    /// Zero for an attachment that has no subscription, because nothing can be queued for one.
    /// This is the bound a whole screen has to fit: a client that holds some of a snapshot's pages
    /// holds no screen at all, so the screen is cut to this and marked degraded rather than being
    /// refused every time it is asked for.
    #[must_use]
    pub fn limit_of(&self, attachment_id: AttachmentId) -> usize {
        self.subscribers
            .get(&attachment_id)
            .map_or(0, |subscriber| subscriber.limit)
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
                // Nothing is trimmed and nothing is zeroed here. The subscriber still owns what is
                // already queued and releases it as it reads; stopping new output is what bounds
                // the queue. Zeroing the counter would make those later releases underflow it.
                if !subscriber.resynchronise(
                    ResyncReason::SendQueueFull,
                    cursor,
                    oldest_retained_cursor,
                ) {
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

    /// Delivers one attachment event to the subscriber it is about.
    ///
    /// It carries no bytes, so it is not charged against that subscriber's queue and never makes
    /// one resynchronise. A subscriber that has gone is not an error: the event was about input it
    /// sent, and there is nobody left to tell.
    pub fn publish_event(&mut self, attachment_id: AttachmentId, delivery: OutputDelivery) {
        let Some(subscriber) = self.subscribers.get_mut(&attachment_id) else {
            return;
        };
        let _ = subscriber.sender.send(delivery);
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
            if !subscriber.resynchronise(
                ResyncReason::SendQueueFull,
                cursor,
                oldest_retained_cursor,
            ) {
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

    /// Delivers one agent resource event to one subscriber.
    ///
    /// The event is charged against the subscriber's send queue limit. Returns whether the
    /// subscriber was told to resynchronise because its queue exceeded the limit.
    pub fn publish_agent_resource(
        &mut self,
        attachment_id: AttachmentId,
        cursor: u64,
        event: kr_protocol::projection::AgentResourceEvent,
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
            if !subscriber.resynchronise(
                ResyncReason::SendQueueFull,
                cursor,
                oldest_retained_cursor,
            ) {
                self.subscribers.remove(&attachment_id);
            }
            return true;
        }
        subscriber.queued.fetch_add(cost, Ordering::AcqRel);
        if subscriber
            .sender
            .send(OutputDelivery::AgentResource {
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
            if !subscriber.resynchronise(
                ResyncReason::SendQueueFull,
                cursor,
                oldest_retained_cursor,
            ) {
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
        // The same accounting rule as an overflow. Bytes already queued still belong to the
        // subscriber and it releases them as it reads; zeroing the counter here would make every
        // one of those releases subtract from nothing.
        let gone = self
            .subscribers
            .get_mut(&attachment_id)
            .is_some_and(|subscriber| {
                !subscriber.resynchronise(reason, cursor, oldest_retained_cursor)
            });
        if gone {
            self.subscribers.remove(&attachment_id);
        }
    }

    /// Tells every subscriber to resynchronise.
    pub fn require_resync_all(
        &mut self,
        reason: ResyncReason,
        cursor: u64,
        oldest_retained_cursor: u64,
    ) {
        let mut gone = Vec::new();
        for (id, subscriber) in &mut self.subscribers {
            if !subscriber.resynchronise(reason, cursor, oldest_retained_cursor) {
                gone.push(*id);
            }
        }
        for id in gone {
            self.subscribers.remove(&id);
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

    fn closure(code: u64) -> ClosureRecord {
        ClosureRecord {
            session_id: kr_protocol::ids::SessionId::new(Uuid::from_bytes([9; 16])),
            session_epoch: kr_protocol::ids::SessionEpoch::V1,
            reason: kr_protocol::session::ClosureReason::RootExit,
            root_exit_code: kr_protocol::scalars::Nullable::some(U64::new(code)),
            root_signal: kr_protocol::scalars::Nullable::null(),
            terminated: Vec::new(),
            surviving: Vec::new(),
            ownership_coverage: kr_protocol::session::OwnershipCoverage::Complete,
            durability: kr_protocol::session::Durability::Durable,
            closed_at_ms: kr_protocol::scalars::TimestampMs::new(1),
        }
    }

    /// Settles a count of notices within a bound a test can afford, or says it did not.
    async fn settles(deliveries: &ClosureDeliveries) -> bool {
        tokio::time::timeout(std::time::Duration::from_secs(5), deliveries.settled())
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn a_closure_reaches_every_subscriber_after_what_it_was_already_sent() {
        let mut hub = OutputHub::new();
        let mut first = hub.subscribe(identifier(1), 1024, Presentation::Direct);
        let mut second = hub.subscribe(identifier(2), 1024, Presentation::Direct);
        hub.publish_direct(0, &Arc::new(b"last words".to_vec()), 0);
        hub.close(&closure(7), [identifier(1), identifier(2)]);
        assert!(hub.is_empty(), "a closed hub keeps no subscriber");
        let deliveries = hub.closure_deliveries();
        assert_eq!(deliveries.outstanding(), 2, "each subscriber is owed one");
        for stream in [&mut first, &mut second] {
            assert!(matches!(
                stream.recv().await,
                Some(OutputDelivery::Bytes { cursor: 0, .. })
            ));
            match stream.recv().await {
                Some(OutputDelivery::Closed(notice)) => {
                    assert_eq!(notice.record(), &closure(7));
                }
                other => panic!("the closure follows the output: {other:?}"),
            }
            assert!(stream.recv().await.is_none(), "and nothing follows it");
        }
        assert!(
            settles(&deliveries).await,
            "nothing is owed once both have taken theirs"
        );
    }

    #[tokio::test]
    async fn a_subscriber_that_fell_behind_is_told_and_one_that_has_gone_owes_nothing() {
        let mut hub = OutputHub::new();
        let mut behind = hub.subscribe(identifier(1), 4, Presentation::Direct);
        hub.publish_direct(0, &Arc::new(vec![b'a'; 4]), 0);
        hub.publish_direct(4, &Arc::new(vec![b'b'; 4]), 0);
        assert!(hub.is_resynchronising(identifier(1)));
        let gone = hub.subscribe(identifier(2), 1024, Presentation::Direct);
        drop(gone);
        hub.close(&closure(0), [identifier(1), identifier(2)]);
        let deliveries = hub.closure_deliveries();
        assert_eq!(
            deliveries.outstanding(),
            1,
            "the subscriber that had gone is owed nothing"
        );
        assert!(matches!(
            behind.recv().await,
            Some(OutputDelivery::Bytes { .. })
        ));
        assert!(matches!(
            behind.recv().await,
            Some(OutputDelivery::Resync(_))
        ));
        assert!(
            matches!(behind.recv().await, Some(OutputDelivery::Closed(_))),
            "falling behind loses output, not the closure"
        );
        assert!(settles(&deliveries).await);
    }

    #[tokio::test]
    async fn a_notice_still_queued_is_owed_until_its_attachment_takes_it_or_goes() {
        let mut hub = OutputHub::new();
        let stream = hub.subscribe(identifier(1), 1024, Presentation::Direct);
        hub.close(&closure(0), [identifier(1)]);
        let deliveries = hub.closure_deliveries();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), deliveries.settled())
                .await
                .is_err(),
            "a notice nobody has taken is still owed"
        );
        drop(stream);
        assert!(
            settles(&deliveries).await,
            "an attachment that has gone takes its notice with it"
        );
    }

    #[tokio::test]
    async fn an_attachment_that_subscribes_after_the_closure_is_told_at_once() {
        let mut hub = OutputHub::new();
        hub.close(&closure(3), [identifier(1)]);
        hub.close(&closure(4), [identifier(1)]);
        let mut late = hub.subscribe(identifier(1), 1024, Presentation::Direct);
        assert!(hub.is_empty(), "it is not kept as a subscriber");
        let deliveries = hub.closure_deliveries();
        assert_eq!(deliveries.outstanding(), 1);
        match late.recv().await {
            Some(OutputDelivery::Closed(notice)) => {
                assert_eq!(
                    notice.record(),
                    &closure(3),
                    "the session has one closure, the first"
                );
            }
            other => panic!("the stream carries the closure: {other:?}"),
        }
        assert!(late.recv().await.is_none(), "and then ends");
        assert!(settles(&deliveries).await);
    }

    #[tokio::test]
    async fn an_attachment_without_a_subscription_is_owed_until_it_subscribes_or_leaves() {
        let mut hub = OutputHub::new();
        let watching = hub.subscribe(identifier(1), 1024, Presentation::Direct);
        drop(watching);
        // Two attachments were admitted and had not subscribed when the session closed.
        hub.close(&closure(0), [identifier(1), identifier(2), identifier(3)]);
        let deliveries = hub.closure_deliveries();
        assert_eq!(
            deliveries.outstanding(),
            2,
            "each admitted attachment without a live subscription is owed the closure"
        );
        // One subscribes: its notice goes on its stream, and that is what is owed now.
        let mut subscribing = hub.subscribe(identifier(2), 1024, Presentation::Direct);
        assert_eq!(deliveries.outstanding(), 2);
        assert!(matches!(
            subscribing.recv().await,
            Some(OutputDelivery::Closed(_))
        ));
        assert_eq!(deliveries.outstanding(), 1, "delivered, and owed no more");
        // The other leaves without subscribing, and is owed nothing more.
        hub.detached(identifier(3));
        assert!(
            settles(&deliveries).await,
            "nothing is owed once one has its notice and the other has gone"
        );
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
        // Publishing never waits, so once it has returned everything it queued is queued: the
        // absence is read then, not after a quiet moment.
        hub.publish_direct(16, &Arc::new(vec![b'c'; 8]), 0);
        hub.require_resync_all(ResyncReason::AgentStreamGap, 24, 0);
        assert!(
            slow.try_recv().is_none(),
            "nothing more is queued until the client resubscribes, not even a second marker"
        );
    }

    /// Every reason there is, so a new one cannot be added without being measured below.
    fn every_reason() -> [ResyncReason; 4] {
        let reasons = [
            ResyncReason::SendQueueFull,
            ResyncReason::HistoryEvicted,
            ResyncReason::ProjectionReset,
            ResyncReason::AgentStreamGap,
        ];
        for reason in reasons {
            match reason {
                ResyncReason::SendQueueFull
                | ResyncReason::HistoryEvicted
                | ResyncReason::ProjectionReset
                | ResyncReason::AgentStreamGap => {}
            }
        }
        reasons
    }

    #[test]
    fn a_marker_is_charged_at_least_what_it_encodes_to() {
        for reason in every_reason() {
            let widest = ResyncRequired {
                reason,
                cursor: U64::new(u64::MAX),
                oldest_retained_cursor: U64::new(u64::MAX),
            };
            let encoded = crate::snapshot::wire::measure(&widest)
                .expect("a marker encodes")
                .bytes;
            assert!(
                encoded <= RESYNC_MARKER_BYTES,
                "a {reason:?} marker encodes to {encoded} bytes and is charged \
                 {RESYNC_MARKER_BYTES}"
            );
            assert_eq!(OutputDelivery::Resync(widest).len(), RESYNC_MARKER_BYTES);
        }
    }

    /// A subscriber is told once for each fresh state it has to install, and the telling is
    /// charged. However many reasons arise before it resubscribes, one marker is queued; after it
    /// has, the next reason is news again.
    #[test]
    fn a_marker_is_charged_and_queued_once_until_the_subscriber_resubscribes() {
        let mut hub = OutputHub::new();
        let mut stream = hub.subscribe(identifier(1), 1024, Presentation::Direct);
        for cursor in 0..8 {
            hub.require_resync(identifier(1), ResyncReason::ProjectionReset, cursor, 0);
            hub.require_resync_all(ResyncReason::AgentStreamGap, cursor, 0);
        }
        assert_eq!(
            stream.queued_bytes(),
            RESYNC_MARKER_BYTES,
            "one marker, charged"
        );
        let marker = stream.try_recv().expect("the subscriber is told");
        assert!(matches!(
            &marker,
            OutputDelivery::Resync(ResyncRequired {
                reason: ResyncReason::ProjectionReset,
                ..
            })
        ));
        assert!(stream.try_recv().is_none(), "and told once");
        stream.written(marker.len());
        assert_eq!(stream.queued_bytes(), 0, "reading it gives its bytes back");

        let mut fresh = hub.subscribe(identifier(1), 1024, Presentation::Direct);
        hub.require_resync_all(ResyncReason::AgentStreamGap, 8, 0);
        assert!(matches!(
            fresh.try_recv(),
            Some(OutputDelivery::Resync(ResyncRequired {
                reason: ResyncReason::AgentStreamGap,
                ..
            }))
        ));
        assert_eq!(fresh.queued_bytes(), RESYNC_MARKER_BYTES);
    }

    #[test]
    fn a_subscriber_whose_end_has_gone_is_removed_when_it_is_told_to_resynchronise() {
        let mut hub = OutputHub::new();
        drop(hub.subscribe(identifier(1), 1024, Presentation::Direct));
        let staying = hub.subscribe(identifier(2), 1024, Presentation::Direct);
        hub.require_resync_all(ResyncReason::AgentStreamGap, 0, 0);
        assert_eq!(hub.subscribers(), vec![identifier(2)]);
        // Already resynchronising, so nothing is sent to it; its end going is still noticed.
        drop(staying);
        hub.require_resync(identifier(2), ResyncReason::ProjectionReset, 0, 0);
        assert!(hub.is_empty());
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

    fn test_agent_event() -> kr_protocol::projection::AgentResourceEvent {
        kr_protocol::projection::AgentResourceEvent {
            session_id: kr_protocol::ids::SessionId::new(Uuid::from_bytes([1; 16])),
            application_instance_id: kr_protocol::ids::ApplicationInstanceId::new(
                Uuid::from_bytes([2; 16]),
            ),
            resource_id: kr_protocol::ids::PendingResourceId::new(Uuid::from_bytes([3; 16])),
            state: kr_protocol::gateway::PendingState::Pending,
            content: kr_protocol::projection::AgentResourceContentClass::AuthoredContent,
            durability: kr_protocol::session::Durability::Durable,
            cause: kr_protocol::projection::AgentResourceCause::Recorded,
            actor_id: kr_protocol::scalars::Nullable(None),
            causal_root: "req-1".to_owned(),
            binding_revision: kr_protocol::ids::AgentBindingRevision::new(1),
            stream_generation: U64::new(1),
            sequence: U64::new(1),
            event_id: Uuid::from_bytes([4; 16]),
            parent_sequence: kr_protocol::scalars::Nullable(None),
        }
    }

    #[tokio::test]
    async fn agent_resource_events_are_charged_against_the_queue_and_resynchronise_a_slow_subscriber()
     {
        let mut hub = OutputHub::new();
        let mut slow = hub.subscribe(identifier(1), 100, Presentation::Direct);
        let mut quick = hub.subscribe(identifier(2), 1024, Presentation::Direct);

        let event = test_agent_event();
        // First event charges 60 bytes, fits within slow's limit of 100.
        assert!(!hub.publish_agent_resource(identifier(1), 1, event.clone(), 60, 0));
        assert!(!hub.publish_agent_resource(identifier(2), 1, event.clone(), 60, 0));

        // Quick subscriber drains and marks written.
        let delivery = quick.recv().await.expect("a delivery");
        assert_eq!(delivery.len(), 60);
        quick.written(delivery.len());
        assert_eq!(quick.queued_bytes(), 0);

        // Second event of 60 bytes exceeds slow's limit (60 + 60 = 120 > 100).
        assert!(hub.publish_agent_resource(identifier(1), 2, event.clone(), 60, 0));
        assert!(hub.is_resynchronising(identifier(1)));

        // Quick subscriber receives the second event without being blocked.
        assert!(!hub.publish_agent_resource(identifier(2), 2, event.clone(), 60, 0));
        let second_delivery = quick.recv().await.expect("quick receives second");
        assert_eq!(second_delivery.len(), 60);

        // Slow subscriber receives the first event, then Resync, and nothing after.
        let first = slow.recv().await.expect("slow receives first");
        assert_eq!(first.len(), 60);
        match slow.recv().await.expect("slow receives resync") {
            OutputDelivery::Resync(marker) => {
                assert_eq!(marker.reason, ResyncReason::SendQueueFull);
                assert_eq!(marker.cursor.get(), 2);
            }
            other => panic!("expected resync, got {other:?}"),
        }
    }
}
