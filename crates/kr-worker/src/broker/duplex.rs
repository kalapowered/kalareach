//! One supervised owner per live connection.
//!
//! A native connection has two ends and traffic in both directions, and the whole of this module
//! exists so that nothing confuses one direction for the other or one stage of a write for a
//! later one.
//!
//! * The **upstream** is the process this host launched. It sends requests it wants answered, and
//!   responses to the requests this host sent it.
//! * The **client** is the native terminal the person is looking at, which reached this host
//!   through the bound endpoint and the `kr-hook` forwarder.
//!
//! Three separations are the contract.
//!
//! **Direction.** Both parties mint request identifiers, and neither knows what the other has
//! used. The upstream's request `7` and this host's request `7` are different requests, and a
//! response carrying `7` answers exactly one of them. Every identifier this host mints carries the
//! [`HOST_REQUEST_PREFIX`], so the two sets are disjoint before anything is looked up, and the
//! upstream is refused if it ever mints one in this host's namespace.
//!
//! **Stages of a write.** Queueing a frame, writing its bytes and the upstream acting on it are
//! three facts and this module never reports a later one for an earlier one.
//! [`Sink::queue`] says the owner has taken the frame; [`Queued::delivered`] says what actually
//! reached the socket; and for a request, the upstream's own reply is what says it was acted on.
//! A frame that goes out in part leaves [`Delivery::Partial`], which is uncertainty and never a
//! success — section 11 forbids opening a second backend or replaying an unknown request, so a
//! partial write is never retried.
//!
//! **Queue bounds in bytes.** A queue bounded by frame count accepts an unbounded number of
//! bytes. [`MAX_QUEUED_BYTES`] bounds what is waiting for one end, and a connection whose peer has
//! stopped draining becomes `UPSTREAM_UNAVAILABLE` rather than a growing buffer.
//!
//! Everything here is core code: nothing calls a component, which is why a component fault cannot
//! stall native traffic.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use kr_protocol::broker::ActionProvenance;
use kr_protocol::gateway::{PendingState, ReverseOperation};
use kr_protocol::ids::{
    ApplicationInstanceId, GatewayConnectionId, PendingResourceId, UpstreamRequestId,
};
use kr_protocol::scalars::TimestampMs;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::broker::Broker;
use crate::broker::error::{BrokerError, Result};
use crate::broker::framing::Framing;
use crate::broker::ledger::ClientRequestOutcome;
use crate::broker::methods::{
    PendingTransmission, UpstreamBody, UpstreamDispatch, UpstreamOutcome, UpstreamRequest,
};

/// How many bytes may be waiting to be written to one end of a connection.
///
/// Section 9 bounds outstanding work, and section 11 bounds broker I/O. A count of frames bounds
/// neither: two hundred and fifty-six frames of a megabyte each is a quarter of a gigabyte of
/// buffer held for a peer that has stopped reading.
pub const MAX_QUEUED_BYTES: usize = 1 << 20;

/// How long one frame has to reach the socket before the connection cannot safely continue.
pub const WRITE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// How long the upstream has to answer one operation this host sent it.
///
/// It is shorter than the worker's own submission deadline, so a caller that is waiting is told
/// what happened by the transport rather than by an outer timer that knows nothing about the
/// connection.
pub const ACKNOWLEDGEMENT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(8);

/// How many resolutions one observer may fall behind before its subscription is withdrawn.
pub const MAX_QUEUED_OBSERVATIONS: usize = 64;

/// How many of the native client's own requests may be awaiting an upstream reply at once.
///
/// Each one holds the client's identifier until the upstream answers it. An upstream that reads
/// requests and never replies would otherwise grow that map for as long as the terminal kept
/// asking, so the bound is what a terminal can have outstanding and the rest are refused in place.
pub const MAX_FORWARDED_CLIENT_REQUESTS: usize = 256;

/// How long one of the client's own requests waits for the upstream before it is given up.
///
/// It is generous, because an agent answering a person's request may be thinking for a long time,
/// and it is finite, because an entry nothing will ever answer is an entry nothing will ever
/// remove. When it passes, the client is told rather than left waiting on a reply that is not
/// coming.
pub const CLIENT_REPLY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

/// How often the owner looks for client requests whose deadline has passed.
///
/// It is short because it is also how long a teardown waits for this work to notice that the
/// connection is going, and a teardown that timed out would abandon the requests it should have
/// given back. Scanning a bounded map once a second costs nothing.
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// What every request identifier this host mints begins with.
///
/// The upstream mints identifiers for the requests it sends and this host mints identifiers for
/// the requests it sends. Without a namespace those are one counter kept by two parties that never
/// compare notes: a response carrying `7` would resolve whichever request the reader looked up
/// first. The prefix makes the two sets disjoint, so a response says which direction it belongs to
/// before anything is correlated.
pub const HOST_REQUEST_PREFIX: &str = "kr-";

/// What became of one frame that was queued for writing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Every byte of the frame reached the socket and was flushed.
    Transmitted,
    /// Some of the frame reached the peer and the rest did not.
    ///
    /// The peer has seen a fragment, so nothing about this frame can be replayed and nothing about
    /// it succeeded.
    Partial,
    /// Nothing of the frame reached the peer.
    Unsent,
}

impl Delivery {
    /// Turns what happened into the refusal a caller is owed, or nothing when it went.
    fn refusal(self) -> Option<BrokerError> {
        match self {
            Self::Transmitted => None,
            Self::Partial => Some(BrokerError::UpstreamUnavailable {
                detail: "part of this frame reached the upstream and the rest did not, so whether \
                         it read the operation cannot be established and nothing sends it again"
                    .to_owned(),
            }),
            Self::Unsent => Some(BrokerError::UpstreamUnavailable {
                detail: "the framing connection could not carry this frame".to_owned(),
            }),
        }
    }
}

/// One frame the owner has taken responsibility for writing.
#[derive(Debug)]
pub struct Queued {
    report: tokio::sync::oneshot::Receiver<Delivery>,
}

impl Queued {
    /// Waits for the owner to say what reached the socket.
    ///
    /// The owner holds the write deadline, so this answers whether or not the peer is draining.
    pub async fn delivered(self) -> Delivery {
        // The owner reports every frame it took, including the ones it could not write, so a
        // dropped sender means the owner itself went before this frame's turn came.
        self.report.await.unwrap_or(Delivery::Unsent)
    }
}

/// What the owner does once it knows what reached the socket.
///
/// It runs in the writer's own task, in the order the frames were written, so the work that
/// depends on a write finishing does not happen in whichever reader queued it. That is what keeps
/// a reader reading: a frame the peer is not draining holds up the writer and nothing else.
type AfterDelivery = Box<dyn FnOnce(Delivery) + Send>;

/// One thing on its way to one end of a connection.
enum Outbound {
    /// A frame to write.
    Frame {
        body: Vec<u8>,
        report: tokio::sync::oneshot::Sender<Delivery>,
        after: Option<AfterDelivery>,
    },
    /// The end of this end's admission.
    ///
    /// It travels in the queue rather than beside it, so the boundary is exact: everything queued
    /// before it is written, and nothing queued after it exists, because admission was closed
    /// before it was sent.
    Close,
}

impl std::fmt::Debug for Outbound {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame { body, .. } => formatter
                .debug_struct("Frame")
                .field("bytes", &body.len())
                .finish(),
            Self::Close => formatter.write_str("Close"),
        }
    }
}

/// One end of a connection, as something frames are queued on.
///
/// Queueing is not writing. What this returns says the owner has the frame and has reserved the
/// bytes for it; [`Queued::delivered`] is what says whether the bytes went.
#[derive(Clone, Debug)]
pub struct Sink {
    frames: tokio::sync::mpsc::UnboundedSender<Outbound>,
    framing: Framing,
    queued: Arc<AtomicUsize>,
    closed: Arc<std::sync::atomic::AtomicBool>,
    limit: usize,
}

impl Sink {
    /// Queues one body for writing, framed.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UpstreamUnavailable`] when this end has stopped taking frames, when
    /// the owner has gone, or when this end already holds [`MAX_QUEUED_BYTES`] waiting to be
    /// written. Section 11: if the framing connection cannot safely continue, say so; do not open
    /// a hidden second backend.
    pub fn queue(&self, body: &[u8]) -> Result<Queued> {
        self.queue_then(body, None)
    }

    /// The same, with work the owner does once it knows what reached the socket.
    ///
    /// # Errors
    ///
    /// Returns what [`Sink::queue`] does. The work is not run when the frame is refused here,
    /// because nothing was taken.
    pub fn queue_then(&self, body: &[u8], after: Option<AfterDelivery>) -> Result<Queued> {
        if self.closed.load(Ordering::Acquire) {
            return Err(BrokerError::UpstreamUnavailable {
                detail: "this connection has stopped taking frames".to_owned(),
            });
        }
        let framed = self.framing.encode(body);
        self.reserve(framed.len())?;
        let (report, receiver) = tokio::sync::oneshot::channel();
        let length = framed.len();
        if self
            .frames
            .send(Outbound::Frame {
                body: framed,
                report,
                after,
            })
            .is_err()
        {
            self.queued.fetch_sub(length, Ordering::Release);
            return Err(BrokerError::UpstreamUnavailable {
                detail: "this connection is no longer being written".to_owned(),
            });
        }
        Ok(Queued { report: receiver })
    }

    /// Stops this end taking frames, and lets the writer finish what it already holds.
    ///
    /// A teardown that left admission open would take an answer this host had admitted, reserve
    /// its bytes and never write them, while its resource said it had gone.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = self.frames.send(Outbound::Close);
    }

    /// Returns true when this end has stopped taking frames.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Returns how many bytes are waiting to be written to this end.
    #[must_use]
    pub fn queued_bytes(&self) -> usize {
        self.queued.load(Ordering::Acquire)
    }

    fn reserve(&self, bytes: usize) -> Result<()> {
        let mut held = self.queued.load(Ordering::Acquire);
        loop {
            let wanted = held.saturating_add(bytes);
            if wanted > self.limit {
                return Err(BrokerError::UpstreamUnavailable {
                    detail: format!(
                        "this connection already holds {held} bytes waiting to be written and one \
                         end may hold {}, so it cannot safely carry {bytes} more",
                        self.limit
                    ),
                });
            }
            match self.queued.compare_exchange_weak(
                held,
                wanted,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(seen) => held = seen,
            }
        }
    }
}

/// Builds one end's sink and the task that empties it.
///
/// `failing` is the owner's own stop: a write that does not finish is a connection this host
/// cannot go on using, and the owner is told rather than left to discover it one lost frame at a
/// time.
fn sink<W>(
    framing: Framing,
    writer: W,
    failing: Stopping,
) -> (Sink, impl std::future::Future<Output = ()> + Send)
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (frames, queue) = tokio::sync::mpsc::unbounded_channel();
    let queued = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sink = Sink {
        frames,
        framing,
        queued: Arc::clone(&queued),
        closed: Arc::clone(&closed),
        limit: MAX_QUEUED_BYTES,
    };
    // The writer holds the flag and not a sink. Holding a sink would hold a sender, and a
    // connection whose every sink had been dropped would leave a writer waiting for a frame that
    // nothing could ever queue.
    (sink, drain(writer, queue, queued, closed, failing))
}

/// How an end tells the owner it can no longer be used.
#[derive(Clone, Debug)]
struct Stopping {
    stopping: Arc<tokio::sync::Notify>,
    stopped: Arc<std::sync::atomic::AtomicBool>,
}

impl Stopping {
    /// Ends the owner's reading.
    fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.stopping.notify_waiters();
    }
}

/// Writes one end's frames, one at a time, and says what happened to each.
async fn drain<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut queue: tokio::sync::mpsc::UnboundedReceiver<Outbound>,
    queued: Arc<AtomicUsize>,
    closed: Arc<std::sync::atomic::AtomicBool>,
    failing: Stopping,
) {
    let mut usable = true;
    while let Some(outbound) = queue.recv().await {
        let Outbound::Frame {
            body,
            report,
            after,
        } = outbound
        else {
            // Admission closed, and everything that was queued before it has been written.
            break;
        };
        let length = body.len();
        // Once one frame has failed the stream is no longer one this host can write to, and the
        // frames behind it never went. Telling their senders so is what keeps a caller from
        // waiting on a write that will not happen.
        let delivery = if usable {
            write_frame(&mut writer, &body).await
        } else {
            Delivery::Unsent
        };
        queued.fetch_sub(length, Ordering::Release);
        if usable && delivery != Delivery::Transmitted {
            usable = false;
            // A connection with a half-written frame on it is one nothing can go on using: the
            // peer has seen a fragment and nothing can say what it made of it. So admission ends
            // here and the owner stops reading, rather than every later frame being lost quietly.
            // What is already queued is still reported, each frame as the unsent frame it is.
            closed.store(true, Ordering::Release);
            failing.stop();
        }
        finish(report, after, delivery);
    }
    // A frame that raced the close is one nobody wrote.
    while let Ok(outbound) = queue.try_recv() {
        if let Outbound::Frame { report, after, .. } = outbound {
            finish(report, after, Delivery::Unsent);
        }
    }
}

/// Tells one frame's sender what happened and runs the work that waited on it.
fn finish(
    report: tokio::sync::oneshot::Sender<Delivery>,
    after: Option<AfterDelivery>,
    delivery: Delivery,
) {
    let _ = report.send(delivery);
    if let Some(after) = after {
        after(delivery);
    }
}

/// Writes one whole frame within the deadline, and says how much of it went.
async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, body: &[u8]) -> Delivery {
    let deadline = tokio::time::Instant::now() + WRITE_DEADLINE;
    let mut written = 0;
    while written < body.len() {
        let attempt = tokio::time::timeout_at(deadline, writer.write(&body[written..])).await;
        match attempt {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(bytes)) => written += bytes,
        }
    }
    if written == 0 {
        return Delivery::Unsent;
    }
    if written < body.len() {
        return Delivery::Partial;
    }
    // Bytes accepted by a buffer the host still holds are bytes the peer has not seen. The flush
    // is part of the frame, and a flush that does not finish leaves a frame that partly went.
    match tokio::time::timeout_at(deadline, writer.flush()).await {
        Ok(Ok(())) => Delivery::Transmitted,
        _ => Delivery::Partial,
    }
}

/// What the upstream said went wrong with one operation.
///
/// An error answer is an answer, so the operation reached the upstream. Whether it *did* anything
/// is a different question, and the protocol answers it for exactly one family of errors: the ones
/// that say the frame was never a call this upstream could make. Everything else — an internal
/// error, an application code of the upstream's own — may have happened before the error, so
/// section 9 records it as an outcome nobody can establish rather than as a refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamFailure {
    /// The code the upstream used.
    pub code: i64,
    /// What it said.
    pub message: String,
}

impl UpstreamFailure {
    /// Turns the upstream's error into the refusal or the uncertainty it actually proves.
    #[must_use]
    pub fn into_failure(self) -> BrokerError {
        // The reserved codes that describe the frame rather than its effect: a frame that was not
        // parsed, was not a request, named no such method, or carried parameters the method does
        // not take, was not acted on.
        const NOT_ACTED_ON: [i64; 4] = [-32_700, -32_600, -32_601, -32_602];
        if NOT_ACTED_ON.contains(&self.code) {
            return BrokerError::UpstreamRefused {
                detail: self.message,
            };
        }
        BrokerError::UpstreamUnavailable {
            detail: format!(
                "the upstream answered with {} ({}), which says the operation failed and not that \
                 it did not happen",
                self.code, self.message
            ),
        }
    }
}

/// What the upstream answered one of this host's own requests with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamReply {
    /// The identifier this host sent the request under.
    pub upstream_request_id: UpstreamRequestId,
    /// The turn the upstream named in its answer, where it named one.
    pub turn_id: Option<kr_protocol::ids::AgentTurnId>,
    /// What the upstream said went wrong, when it did not succeed.
    pub refusal: Option<UpstreamFailure>,
}

/// One request of the client's, waiting for the upstream to answer it.
#[derive(Clone, Debug)]
struct Forwarded {
    /// The identifier the client used, which its reply goes back under.
    client: serde_json::Value,
    /// When this host stops waiting for the upstream to answer it.
    expires_at: tokio::time::Instant,
}

/// The requests this host has sent one upstream and not yet had answered.
///
/// It is the owner's, not a dispatch's: two dispatches of one connection that each kept their own
/// would put two requests under one identifier, and an answer to either would be read as an answer
/// to the other.
#[derive(Debug, Default)]
struct Outstanding {
    next: AtomicU64,
    waiting:
        std::sync::Mutex<BTreeMap<UpstreamRequestId, tokio::sync::oneshot::Sender<UpstreamReply>>>,
    /// The requests the native client made, by the identifier this host sent them under.
    ///
    /// The client mints its own identifiers and so does the upstream, so a client request is
    /// forwarded under an identifier of this host's and the client's own is kept here. The
    /// upstream's answer comes back under this host's identifier and is written to the client
    /// under the client's, which is what "preserve upstream IDs" means from the other side.
    ///
    /// It is bounded and each entry has a deadline, because the upstream decides whether a reply
    /// ever comes and this host cannot hold a map that only the upstream can empty.
    forwarded: std::sync::Mutex<BTreeMap<UpstreamRequestId, Forwarded>>,
}

impl Outstanding {
    /// Mints the next identifier in this host's own namespace.
    fn allocate(&self) -> Result<UpstreamRequestId> {
        let next = self.next.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        // It is written in its own JSON form, as a string, so an upstream that echoes it back
        // returns the same identifier and nothing this host minted can equal a bare number the
        // upstream minted.
        let identifier = serde_json::Value::String(format!("{HOST_REQUEST_PREFIX}{next}"));
        UpstreamRequestId::new(identifier.to_string())
            .map_err(|error| BrokerError::invalid(format!("upstream request identifier: {error}")))
    }

    /// Records that this host is waiting for one identifier to be answered.
    ///
    /// What comes back forgets the identifier when it is dropped, however it is dropped: a caller
    /// that gave up, an outer deadline, a connection that ended. Nothing about this connection
    /// grows because a reply never came.
    fn expect(self: &Arc<Self>, id: &UpstreamRequestId) -> Waiting {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.held().insert(id.clone(), sender);
        Waiting {
            outstanding: Arc::clone(self),
            id: id.clone(),
            reply: receiver,
        }
    }

    /// Gives one reply to whatever is waiting for it, and says whether anything was.
    fn answer(&self, reply: UpstreamReply) -> bool {
        let Some(waiting) = self.held().remove(&reply.upstream_request_id) else {
            return false;
        };
        waiting.send(reply).is_ok()
    }

    /// Forgets one identifier, for a request that will never be answered.
    fn forget(&self, id: &UpstreamRequestId) {
        self.held().remove(id);
    }

    /// Records that one identifier this host minted carries a request of the client's.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UpstreamUnavailable`] when this connection already holds
    /// [`MAX_FORWARDED_CLIENT_REQUESTS`] requests the upstream has not answered.
    fn forwarding(&self, id: &UpstreamRequestId, client: serde_json::Value) -> Result<()> {
        let mut mapped = self.mapped();
        if mapped.len() >= MAX_FORWARDED_CLIENT_REQUESTS {
            return Err(BrokerError::UpstreamUnavailable {
                detail: format!(
                    "this connection already has {MAX_FORWARDED_CLIENT_REQUESTS} requests the \
                     upstream has not answered, so it cannot carry another"
                ),
            });
        }
        mapped.insert(
            id.clone(),
            Forwarded {
                client,
                expires_at: tokio::time::Instant::now() + CLIENT_REPLY_DEADLINE,
            },
        );
        Ok(())
    }

    /// Returns the client's own identifier for one request this host forwarded.
    fn client_identifier(&self, id: &UpstreamRequestId) -> Option<serde_json::Value> {
        self.mapped().remove(id).map(|forwarded| forwarded.client)
    }

    /// Takes every client request whose deadline has passed.
    fn expired(&self) -> Vec<(UpstreamRequestId, serde_json::Value)> {
        let now = tokio::time::Instant::now();
        let mut mapped = self.mapped();
        let over: Vec<UpstreamRequestId> = mapped
            .iter()
            .filter(|(_, forwarded)| forwarded.expires_at <= now)
            .map(|(id, _)| id.clone())
            .collect();
        over.into_iter()
            .filter_map(|id| mapped.remove(&id).map(|forwarded| (id, forwarded.client)))
            .collect()
    }

    /// Takes every client request that is still waiting, because this connection is ending.
    fn abandon(&self) -> Vec<(UpstreamRequestId, serde_json::Value)> {
        std::mem::take(&mut *self.mapped())
            .into_iter()
            .map(|(id, forwarded)| (id, forwarded.client))
            .collect()
    }

    /// Returns how many of the client's requests are waiting for the upstream.
    fn forwarded_count(&self) -> usize {
        self.mapped().len()
    }

    fn mapped(&self) -> std::sync::MutexGuard<'_, BTreeMap<UpstreamRequestId, Forwarded>> {
        self.forwarded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn held(
        &self,
    ) -> std::sync::MutexGuard<
        '_,
        BTreeMap<UpstreamRequestId, tokio::sync::oneshot::Sender<UpstreamReply>>,
    > {
        self.waiting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// One identifier this host is waiting for the upstream to answer.
///
/// It is a handle rather than a bare channel so that the entry cannot outlive the wait: the only
/// way to stop waiting is to drop this, and dropping it is what removes the entry.
#[derive(Debug)]
struct Waiting {
    outstanding: Arc<Outstanding>,
    id: UpstreamRequestId,
    reply: tokio::sync::oneshot::Receiver<UpstreamReply>,
}

impl Waiting {
    /// Waits for the reply, or says nothing arrived within the bound.
    async fn within(mut self, deadline: std::time::Duration) -> Option<UpstreamReply> {
        match tokio::time::timeout(deadline, &mut self.reply).await {
            Ok(Ok(reply)) => Some(reply),
            Ok(Err(_)) | Err(_) => None,
        }
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        self.outstanding.forget(&self.id);
    }
}

/// Returns true when this identifier is one this host minted.
#[must_use]
pub fn is_host_minted(id: &UpstreamRequestId) -> bool {
    serde_json::from_str::<serde_json::Value>(id.as_str())
        .ok()
        .and_then(|value| {
            value
                .as_str()
                .map(|text| text.starts_with(HOST_REQUEST_PREFIX))
        })
        .unwrap_or(false)
}

/// One resolution, as every authorised observer of the instance is told about it.
///
/// The sequence is the broker's own stream cursor, taken with the transition and written into the
/// event row in the same transaction. It is what makes a stale delivery something an observer can
/// see rather than something it has to believe: two transitions of one resource arrive in the
/// order they were committed in, and their sequences say so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceTransition {
    /// This event's position in the broker's stream of transitions.
    pub sequence: u64,
    /// The event itself, which never changes and never repeats.
    pub event_id: kr_protocol::scalars::Uuid,
    /// The instance the resource belongs to.
    pub application_instance_id: ApplicationInstanceId,
    /// The resource.
    pub resource_id: PendingResourceId,
    /// The binding revision in force when it changed.
    pub binding_revision: kr_protocol::ids::AgentBindingRevision,
    /// What it became.
    pub state: PendingState,
}

/// Where one authorised observer reads the resolutions of the instance it watches.
#[derive(Debug)]
pub struct Observations {
    events: tokio::sync::mpsc::Receiver<ResourceTransition>,
}

impl Observations {
    /// Waits for the next resolution, or ends when the subscription is withdrawn.
    pub async fn next(&mut self) -> Option<ResourceTransition> {
        self.events.recv().await
    }
}

/// Every connection that is watching, and the bounded queue each one reads.
///
/// Section 12 fans resolutions out to every authorised observer. Who is authorised is the broker's
/// answer (a connection observes the instance it was opened against) and this is the delivery: one
/// bounded queue per connection, withdrawn rather than grown when an observer stops reading.
///
/// There is one of these per broker, held by the broker itself and handed out by
/// [`Broker::observatory`](crate::broker::Broker::observatory). Every clone shares the one
/// registry, so a second gateway subscribing its own connections adds to what the first is
/// watching instead of taking delivery away from it.
#[derive(Clone, Debug, Default)]
pub struct Observatory {
    watching: Arc<
        std::sync::Mutex<
            BTreeMap<GatewayConnectionId, tokio::sync::mpsc::Sender<ResourceTransition>>,
        >,
    >,
}

impl Observatory {
    /// An observatory nobody is watching yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribes one connection, replacing whatever it had before.
    #[must_use]
    pub fn subscribe(&self, connection: GatewayConnectionId) -> Observations {
        let (sender, events) = tokio::sync::mpsc::channel(MAX_QUEUED_OBSERVATIONS);
        self.held().insert(connection, sender);
        Observations { events }
    }

    /// Withdraws one connection's subscription.
    pub fn withdraw(&self, connection: GatewayConnectionId) {
        self.held().remove(&connection);
    }

    /// Delivers one transition to every authorised observer of its instance.
    ///
    /// Who is authorised is the broker's answer and the broker passes it: a connection is told
    /// about an instance only if it is one of that instance's own connections. A subscriber that has fallen [`MAX_QUEUED_OBSERVATIONS`]
    /// behind is withdrawn rather than allowed to grow, because a queue that cannot be bounded is
    /// a queue that ends the session it belongs to.
    pub fn publish(&self, authorised: &[GatewayConnectionId], transition: &ResourceTransition) {
        let mut held = self.held();
        for connection in authorised {
            let Some(sender) = held.get(connection) else {
                continue;
            };
            if sender.try_send(transition.clone()).is_err() {
                held.remove(connection);
            }
        }
    }

    fn held(
        &self,
    ) -> std::sync::MutexGuard<
        '_,
        BTreeMap<GatewayConnectionId, tokio::sync::mpsc::Sender<ResourceTransition>>,
    > {
        self.watching
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// What the worker-owned transport carries prepared operations over.
///
/// This is the production [`UpstreamDispatch`]. It encodes what the core prepared, queues it on
/// the connection the broker admitted the operation against, and answers with what the upstream
/// actually did rather than with the fact that a queue accepted the bytes.
#[derive(Debug)]
pub struct Dispatch {
    connection: GatewayConnectionId,
    upstream: Sink,
    outstanding: Arc<Outstanding>,
    rich: kr_protocol::gateway::RichMethodTable,
    params_field: String,
    request_id_field: String,
    method_field: String,
}

impl Dispatch {
    /// Returns the connection this dispatch writes to.
    #[must_use]
    pub const fn connection(&self) -> GatewayConnectionId {
        self.connection
    }

    /// Returns the upstream method this connection's closed rich table names for one operation.
    ///
    /// Each operation is looked up as itself. Submitting a prompt, queueing one and steering a
    /// turn need one right between them, so choosing by right would send any of the three as
    /// whichever the table happened to list first. A plugin action is named by the action the
    /// package declared: the table still has to list it, so an unknown rich mutation is rejected
    /// rather than guessed at.
    ///
    /// Either way the method passes the closed table's own admission, so a method the table lists
    /// as unsupported is refused here rather than written to the socket.
    fn method_for(&self, request: &UpstreamRequest) -> Result<kr_protocol::ids::UpstreamMethod> {
        if let UpstreamBody::PluginAction { action, .. } = &request.body {
            let method =
                kr_protocol::ids::UpstreamMethod::new(action.as_str()).map_err(|error| {
                    BrokerError::invalid(format!("this action is not a method name: {error}"))
                })?;
            return self
                .rich
                .admit(&method)
                .map(|entry| entry.method.clone())
                .map_err(BrokerError::from);
        }
        self.rich
            .for_operation(request.operation)
            .map(|entry| entry.method.clone())
            .map_err(BrokerError::from)
    }

    /// Builds the parameter member of one prepared operation.
    ///
    /// The turn travels with every operation that names one. Section 12 binds observation and
    /// mutation to instance, execution owner, session **and turn**, and a steer or a cancellation
    /// that reached the upstream without its turn would act on whatever is running when it lands.
    fn parameters(request: &UpstreamRequest) -> Result<serde_json::Value> {
        let mut parameters = match &request.body {
            UpstreamBody::Prompt { draft_id, text } => serde_json::json!({
                "draft_id": draft_id.as_ref().map(ToString::to_string),
                "text": text,
            }),
            UpstreamBody::Steer { text } => serde_json::json!({ "text": text }),
            UpstreamBody::Cancel => serde_json::json!({}),
            // An approval's answer is the frame the core prepared at admission, written by
            // `submit` before it reaches here. There is no second encoding of one.
            UpstreamBody::Approval { .. } => {
                return Err(BrokerError::invalid(
                    "an approval is answered with the frame the core prepared for it, and this \
                     path encodes a request",
                ));
            }
            UpstreamBody::PluginAction {
                plugin_id,
                action,
                draft_id,
                draft_revision,
                parameters,
                operation,
                token,
            } => {
                // The arguments the invocation was admitted with, read as they are. Substituting
                // anything for an encoding this host cannot read would send something other than
                // what the token's digest covers; the admission refuses such an invocation, and
                // this refuses it again rather than trusting that.
                let arguments: serde_json::Value =
                    serde_json::from_slice(parameters).map_err(|error| {
                        BrokerError::invalid(format!(
                            "this invocation's parameters will not encode: {error}"
                        ))
                    })?;
                // The operation the host validated, which is absent until a plan has been checked
                // against this invocation.
                let operation = operation.ok_or_else(|| {
                    BrokerError::invalid(
                        "this invocation has no validated operation to name, so there is nothing \
                         to encode",
                    )
                })?;
                // An action that names a draft names the revision this host checked it at. The
                // identifier on its own denotes whatever the draft holds when the frame lands,
                // and an upstream given only that would act on a draft nobody admitted.
                if draft_id.is_some() != draft_revision.is_some() {
                    return Err(BrokerError::invalid(
                        "a draft-bearing action carries the revision its draft was admitted at",
                    ));
                }
                serde_json::json!({
                    "plugin_id": plugin_id.as_str(),
                    "action": action.as_str(),
                    "operation": operation.as_str(),
                    "draft_id": draft_id.as_ref().map(ToString::to_string),
                    "draft_revision": draft_revision.map(kr_protocol::scalars::U64::get),
                    "parameters": arguments,
                    // Section 11: the effect plan may use only what this invocation permits, and
                    // the token is what says which invocation that is.
                    "action_token": token.as_ref().map(|token| token.token_id.as_str()),
                })
            }
        };
        if let Some(turn_id) = request.turn_id.as_ref() {
            let Some(members) = parameters.as_object_mut() else {
                return Err(BrokerError::invalid(
                    "a prepared operation's parameters are a JSON object",
                ));
            };
            members.insert(
                "turn_id".to_owned(),
                serde_json::Value::String(turn_id.to_string()),
            );
        }
        Ok(parameters)
    }

    /// Queues an answer to one of the upstream's own requests.
    ///
    /// An answer is not a request: the upstream sends nothing back for it, so what the transport
    /// can establish is that the bytes went, and that is what it reports.
    fn answer(&self, request: &UpstreamRequest) -> Result<PendingTransmission> {
        let UpstreamBody::Approval { response, .. } = &request.body else {
            return Err(BrokerError::invalid("this operation is not an answer"));
        };
        // The prepared answer names the connection it was admitted on. Writing it anywhere else
        // would answer one upstream's resource on another's stream.
        if response.request().connection != self.connection {
            return Err(BrokerError::denied(format!(
                "this answer was admitted on {} and this transport speaks for {}",
                response.request().connection,
                self.connection
            )));
        }
        let queued = self.upstream.queue(response.frame())?;
        let upstream_request_id = response.upstream_request_id().clone();
        let turn_id = request.turn_id.clone();
        Ok(PendingTransmission::carried(async move {
            if let Some(refusal) = queued.delivered().await.refusal() {
                return Err(refusal);
            }
            Ok(UpstreamOutcome {
                upstream_request_id: Some(upstream_request_id),
                turn_id,
                provenance: ActionProvenance::UpstreamTypedRpc,
            })
        }))
    }

    /// Queues a request of this host's own and waits for the upstream to answer it.
    fn request(&self, request: &UpstreamRequest) -> Result<PendingTransmission> {
        let upstream_request_id = self.outstanding.allocate()?;
        let method = self.method_for(request)?;
        let identifier: serde_json::Value = serde_json::from_str(upstream_request_id.as_str())
            .map_err(|error| {
                BrokerError::invalid(format!("this identifier will not encode: {error}"))
            })?;
        let mut frame = serde_json::Map::new();
        frame.insert(self.request_id_field.clone(), identifier);
        frame.insert(
            self.method_field.clone(),
            serde_json::Value::String(method.as_str().to_owned()),
        );
        frame.insert(self.params_field.clone(), Self::parameters(request)?);
        let body = serde_json::to_vec(&serde_json::Value::Object(frame)).map_err(|error| {
            BrokerError::invalid(format!("this operation will not encode: {error}"))
        })?;
        // The waiter is registered before the bytes are queued. Registering it afterwards would
        // leave a window in which the upstream's answer arrived and nothing was listening for it.
        let answered = self.outstanding.expect(&upstream_request_id);
        let queued = self.upstream.queue(&body)?;
        let turn_id = request.turn_id.clone();
        Ok(PendingTransmission::carried(async move {
            if let Some(refusal) = queued.delivered().await.refusal() {
                return Err(refusal);
            }
            // The bytes went. What the upstream did with them is the upstream's to say, and until
            // it says so the operation is not one this host can record as applied.
            let Some(reply) = answered.within(ACKNOWLEDGEMENT_DEADLINE).await else {
                return Err(BrokerError::UpstreamUnavailable {
                    detail: format!(
                        "the operation reached the upstream and it did not answer within {} \
                         seconds, so whether it acted on it cannot be established",
                        ACKNOWLEDGEMENT_DEADLINE.as_secs()
                    ),
                });
            };
            if let Some(refusal) = reply.refusal {
                return Err(refusal.into_failure());
            }
            Ok(UpstreamOutcome {
                upstream_request_id: Some(upstream_request_id),
                turn_id: reply.turn_id.or(turn_id),
                provenance: ActionProvenance::UpstreamTypedRpc,
            })
        }))
    }
}

impl UpstreamDispatch for Dispatch {
    fn admit(&self, request: &UpstreamRequest) -> Result<()> {
        // An approval's answer is the frame the core prepared, which needs no method of this
        // table; everything else needs one, and the table has to name exactly one for it.
        if matches!(request.body, UpstreamBody::Approval { .. }) {
            return Ok(());
        }
        self.method_for(request).map(|_| ())
    }

    fn submit(&self, request: &UpstreamRequest) -> Result<PendingTransmission> {
        if matches!(request.body, UpstreamBody::Approval { .. }) {
            return self.answer(request);
        }
        self.request(request)
    }
}

/// What the owner did with one frame, for a caller that watches it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Carried {
    /// A request the upstream sent, recorded and forwarded to the client.
    UpstreamRequest {
        /// The method it named.
        method: kr_protocol::ids::UpstreamMethod,
        /// The resource it created, when it expects a response.
        resource_id: Option<PendingResourceId>,
    },
    /// A reverse request the upstream asked this host to perform.
    Reverse {
        /// What was asked for.
        operation: ReverseOperation,
        /// Whether this host could do it.
        performed: bool,
    },
    /// A request the client made of the upstream, forwarded under an identifier of this host's.
    ClientRequest {
        /// The identifier this host sent it under.
        upstream_request_id: UpstreamRequestId,
        /// How the connection's own table classified the method it named.
        classification: kr_protocol::gateway::NativeClassification,
        /// True when admitting it suspended this instance's rich mutations.
        suspended_rich_mutations: bool,
    },
    /// A notification the client sent, forwarded as it is.
    ClientNotification {
        /// How the connection's own table classified the method it named.
        classification: kr_protocol::gateway::NativeClassification,
        /// True when admitting it suspended this instance's rich mutations.
        suspended_rich_mutations: bool,
    },
    /// A reply the upstream sent to a request the client made, returned to the client.
    ClientReply {
        /// The identifier this host had sent it under.
        upstream_request_id: UpstreamRequestId,
        /// True when the reply was queued for the client.
        returned: bool,
    },
    /// The client's own answer, admitted and queued for the upstream.
    ///
    /// What the resource becomes is what the write turns out to be, which the owner settles: a
    /// frame that went resolves it and a frame that went in part leaves it uncertain.
    ClientAnswer {
        /// The resource it answers.
        resource_id: PendingResourceId,
    },
    /// A reply to one of this host's own requests, given to whatever was waiting for it.
    HostReply {
        /// The identifier this host sent the request under.
        upstream_request_id: UpstreamRequestId,
        /// True when something was still waiting for it.
        awaited: bool,
    },
    /// A response the upstream sent for a request of its own.
    UpstreamResponse,
}

/// Why one connection's owner stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closure {
    /// The upstream's own end closed while the process this host launched had ended.
    ///
    /// Section 7 calls this the native TUI's intentional exit: it ends the instance and stops the
    /// dedicated backend.
    NativeExit,
    /// An end closed and the process this host launched is still running.
    ///
    /// Closing an attachment is not an exit, and nothing of the upstream is stopped for it.
    Detached,
    /// The host asked the owner to stop.
    Shutdown,
}

/// One live connection, owned by one supervised task.
#[derive(Debug)]
pub struct Duplex {
    broker: Arc<Broker>,
    connection: GatewayConnectionId,
    framing: Framing,
    upstream: Sink,
    client: Sink,
    outstanding: Arc<Outstanding>,
    site: kr_protocol::ids::EnvironmentId,
    os_user: String,
    stopping: Arc<tokio::sync::Notify>,
    stopped: Arc<std::sync::atomic::AtomicBool>,
}

impl Duplex {
    /// Builds one owner over an already-opened gateway connection and the two ends it writes to.
    ///
    /// The future it returns is the owner's own write work; it must be driven for anything to
    /// reach either end.
    #[allow(clippy::too_many_arguments)]
    pub fn new<U, C>(
        broker: Arc<Broker>,
        connection: GatewayConnectionId,
        framing: Framing,
        upstream: U,
        client: C,
        site: kr_protocol::ids::EnvironmentId,
        os_user: impl Into<String>,
    ) -> (Arc<Self>, impl std::future::Future<Output = ()> + Send)
    where
        U: AsyncWrite + Unpin + Send + 'static,
        C: AsyncWrite + Unpin + Send + 'static,
    {
        let failing = Stopping {
            stopping: Arc::new(tokio::sync::Notify::new()),
            stopped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let (to_upstream, upstream_writes) = sink(framing, upstream, failing.clone());
        let (to_client, client_writes) = sink(framing, client, failing.clone());
        let owner = Arc::new(Self {
            broker,
            connection,
            framing,
            upstream: to_upstream,
            client: to_client,
            outstanding: Arc::new(Outstanding::default()),
            site,
            os_user: os_user.into(),
            stopping: Arc::clone(&failing.stopping),
            stopped: Arc::clone(&failing.stopped),
        });
        let sweeping = {
            let owner = Arc::clone(&owner);
            async move { owner.sweep().await }
        };
        let writes = async move {
            tokio::join!(upstream_writes, client_writes, sweeping);
        };
        (owner, writes)
    }

    /// Gives up the client requests the upstream has stopped answering, and tells the client.
    ///
    /// It runs beside the two writers and ends with them. A request nothing will ever answer is an
    /// entry nothing would ever remove, so the deadline is what removes it, and the client is told
    /// rather than left holding an identifier this host has forgotten.
    async fn sweep(self: &Arc<Self>) {
        while !self.stopped.load(Ordering::Acquire) {
            for (id, client) in self.outstanding.expired() {
                self.give_up(&id, &client, "the upstream did not answer this request");
            }
            tokio::select! {
                () = tokio::time::sleep(SWEEP_INTERVAL) => {}
                () = self.stopping.notified() => break,
            }
        }
        // The connection is ending. Everything still waiting is given up here rather than left in
        // a map nobody will read again.
        for (id, client) in self.outstanding.abandon() {
            self.give_up(
                &id,
                &client,
                "this connection ended before the upstream answered",
            );
        }
    }

    /// Tells the client that one of its own requests will not be answered.
    fn give_up(&self, id: &UpstreamRequestId, client: &serde_json::Value, why: &str) {
        let Some(held) = self.broker.connection(self.connection) else {
            return;
        };
        let mut body = serde_json::Map::new();
        body.insert(held.table.response_id_field.clone(), client.clone());
        body.insert(
            held.table.error_field.clone(),
            serde_json::json!({
                "code": -32_603,
                "message": format!("{why} ({id})"),
            }),
        );
        let Ok(encoded) = serde_json::to_vec(&serde_json::Value::Object(body)) else {
            return;
        };
        let _ = self.client.queue(&encoded);
    }

    /// Returns how many of the client's own requests are waiting for the upstream.
    #[must_use]
    pub fn forwarded_client_requests(&self) -> usize {
        self.outstanding.forwarded_count()
    }

    /// Returns the connection this owner speaks for.
    #[must_use]
    pub const fn connection(&self) -> GatewayConnectionId {
        self.connection
    }

    /// Returns what carries prepared operations to this connection's upstream.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when the connection is not one the broker holds.
    pub fn dispatch(&self) -> Result<Arc<Dispatch>> {
        let connection = self.broker.connection(self.connection).ok_or_else(|| {
            BrokerError::unknown(format!("no gateway connection {}", self.connection))
        })?;
        Ok(Arc::new(Dispatch {
            connection: self.connection,
            upstream: self.upstream.clone(),
            outstanding: Arc::clone(&self.outstanding),
            rich: connection.rich.clone(),
            params_field: connection.table.params_field.clone(),
            request_id_field: connection.table.request_id_field.clone(),
            method_field: connection.table.method_field.clone(),
        }))
    }

    /// Returns how many bytes are waiting to be written to the upstream.
    #[must_use]
    pub fn queued_to_upstream(&self) -> usize {
        self.upstream.queued_bytes()
    }

    /// Asks this owner to stop reading both ends, and stops either end taking new frames.
    ///
    /// Frames already queued are still written: a shutdown that dropped them would leave an answer
    /// this host had admitted unsent while its resource said it had gone. Nothing new is taken,
    /// because a frame admitted into a connection that is going away is a frame whose bytes would
    /// never be written while its caller waited.
    pub fn shutdown(&self) {
        self.stopped.store(true, Ordering::Release);
        self.stopping.notify_waiters();
        self.upstream.close();
        self.client.close();
    }

    /// Returns true when this owner has been asked to stop.
    #[must_use]
    pub fn stopping(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    /// Carries one frame the upstream sent.
    ///
    /// # Errors
    ///
    /// Returns whatever the broker refuses, and [`BrokerError::UpstreamUnavailable`] when the
    /// client end cannot take the frame.
    pub async fn from_upstream(&self, frame: &[u8], now: TimestampMs) -> Result<Carried> {
        // A request names a method and a response does not, which is the one distinction the
        // qualified table guarantees. Asking the broker to correlate a request would resolve a
        // resource on the strength of a matching identifier alone.
        let forwarded = match self.broker.forward_native(self.connection, frame, now) {
            Ok(carried) => carried,
            Err(_) => return self.upstream_response(frame, now),
        };
        let (forwarded, resource) = forwarded;
        // What the upstream asks this host to do is a separate contract with its own admission,
        // and nothing of it happens on this path.
        if let Some(operation) = self
            .broker
            .connection(self.connection)
            .and_then(|connection| connection.table.reverse_of(&forwarded.method))
        {
            let performed = self.refuse_reverse(operation, frame).await?;
            return Ok(Carried::Reverse {
                operation,
                performed,
            });
        }
        // Recorded first, forwarded second. Section 11 puts the record before the forwarding so
        // that a crash in between leaves a request this host knows about rather than one it does
        // not.
        //
        // Queued, not awaited. Waiting here for the client's own socket would hold this reader,
        // and everything the upstream said behind this frame, behind one end that is not
        // draining. What the write turns out to be is the owner's to act on.
        self.client.queue(frame)?;
        Ok(Carried::UpstreamRequest {
            method: forwarded.method,
            resource_id: resource.map(|resource| resource.resource_id),
        })
    }

    /// Carries one frame the upstream sent that is not a request.
    fn upstream_response(&self, frame: &[u8], now: TimestampMs) -> Result<Carried> {
        let request = self.broker.correlate_response(self.connection, frame)?;
        // This host's own namespace is looked at first and separately. A reply to something this
        // host asked for never reaches the arbitration, whatever identifier the upstream's own
        // pending requests happen to be using.
        if is_host_minted(&request.upstream) {
            // A reply to something the client asked for goes back to the client, under the
            // identifier the client used. It is never an answer to a request of this host's, and
            // it never reaches the arbitration.
            if let Some(client_identifier) = self.outstanding.client_identifier(&request.upstream) {
                return Ok(Carried::ClientReply {
                    upstream_request_id: request.upstream,
                    returned: self.return_to_client(frame, &client_identifier)?,
                });
            }
            let reply = read_reply(
                self.broker.as_ref(),
                self.connection,
                frame,
                &request.upstream,
            )?;
            let awaited = self.outstanding.answer(reply);
            return Ok(Carried::HostReply {
                upstream_request_id: request.upstream,
                awaited,
            });
        }
        self.broker.upstream_response(self.connection, frame, now)?;
        Ok(Carried::UpstreamResponse)
    }

    /// Carries one frame the native client sent.
    ///
    /// The answer is admitted before anything is queued, transmitted next, and recorded last. A
    /// frame that went out in part leaves the resource uncertain, because an answer whose fate
    /// nobody can establish is never answered a second time.
    ///
    /// # Errors
    ///
    /// Returns whatever the broker refuses, including the refusal of a second answer to one
    /// request.
    pub async fn from_client(&self, frame: &[u8], now: TimestampMs) -> Result<Carried> {
        // A frame that names a method is the client asking the upstream for something, not the
        // client answering the upstream. Reading every client frame as an answer would leave the
        // native terminal's own requests and notifications with nowhere to go.
        if let Some(named) = self.client_request(frame)? {
            return self.forward_to_upstream(named, now).await;
        }
        // The admission is held by a guard that outlives this reader. Settling is what the write
        // finishing means, and the write finishing is the owner's to report: an answer whose fate
        // nobody establishes is one the guard settles uncertain, whether the reader is cancelled,
        // the connection ends, or the frame goes out in part.
        let admitted = AdmittedAnswer {
            broker: Arc::clone(&self.broker),
            answer: Some(
                self.broker
                    .admit_native_answer(self.connection, frame, now)?,
            ),
        };
        let resource_id = admitted.resource_id();
        let body = admitted.frame().to_vec();
        // The guard travels with the work that reports the write. If the frame is refused here it
        // is dropped instead, which settles the resource uncertain: the admission was spent and
        // no answer went.
        self.upstream.queue_then(
            &body,
            Some(Box::new(move |delivery: Delivery| {
                admitted.settle(delivery)
            })),
        )?;
        Ok(Carried::ClientAnswer { resource_id })
    }

    /// Reads one frame the client sent, when it is a request or a notification of its own.
    fn client_request(&self, frame: &[u8]) -> Result<Option<ClientFrame>> {
        let held = self.broker.connection(self.connection).ok_or_else(|| {
            BrokerError::unknown(format!("no gateway connection {}", self.connection))
        })?;
        let body: serde_json::Value = serde_json::from_slice(frame).map_err(|error| {
            BrokerError::invalid(format!("this frame is not readable: {error}"))
        })?;
        let Some(members) = body.as_object() else {
            return Err(BrokerError::invalid("a native frame is a JSON object"));
        };
        if !members.contains_key(&held.table.method_field) {
            return Ok(None);
        }
        // The client is not the upstream, and it does not get to mint identifiers in this host's
        // namespace either: an identifier that looked like one of this host's would come back as
        // an answer to something this host asked for.
        let identifier = members.get(&held.table.request_id_field).cloned();
        if let Some(raw) = identifier.as_ref()
            && serde_json::to_string(raw)
                .ok()
                .and_then(|text| UpstreamRequestId::new(text).ok())
                .is_some_and(|id| is_host_minted(&id))
        {
            return Err(BrokerError::invalid(format!(
                "{raw} begins with {HOST_REQUEST_PREFIX}, which names the requests this host \
                 sends, and a client request cannot be one of those"
            )));
        }
        Ok(Some(ClientFrame {
            body,
            identifier,
            request_id_field: held.table.request_id_field.clone(),
            frame: frame.to_vec(),
        }))
    }

    /// Carries one request or notification of the client's to the upstream.
    ///
    /// The frame is admitted before it is queued. The client is the person's own terminal and the
    /// upstream is the agent, and a frame the terminal writes changes upstream state exactly as a
    /// frame the agent writes does; so it is classified with the table this host pinned, its bytes
    /// are retained, its intent is recorded, and a method the table does not classify suspends
    /// this instance's rich mutations before anything is written.
    ///
    /// A notification is then written as it is: there is nothing to correlate. A request is
    /// rewritten under an identifier of this host's own and the client's identifier is kept, so
    /// the upstream's answer comes back to the client under the identifier the client used.
    async fn forward_to_upstream(&self, named: ClientFrame, now: TimestampMs) -> Result<Carried> {
        let ClientFrame {
            mut body,
            identifier,
            request_id_field,
            frame,
        } = named;
        let Some(client_identifier) = identifier else {
            let admitted = self
                .broker
                .admit_client_request(self.connection, &frame, None, now)?;
            let encoded = serde_json::to_vec(&body).map_err(|error| {
                BrokerError::invalid(format!("this notification will not encode: {error}"))
            })?;
            let carried = Carried::ClientNotification {
                classification: admitted.classification,
                suspended_rich_mutations: admitted.suspends_rich_mutations,
            };
            self.queue_client_frame(&encoded, admitted, None)?;
            return Ok(carried);
        };
        let upstream_request_id = self.outstanding.allocate()?;
        let admitted = self.broker.admit_client_request(
            self.connection,
            &frame,
            Some(&upstream_request_id),
            now,
        )?;
        let carried = Carried::ClientRequest {
            upstream_request_id: upstream_request_id.clone(),
            classification: admitted.classification,
            suspended_rich_mutations: admitted.suspends_rich_mutations,
        };
        let minted: serde_json::Value = serde_json::from_str(upstream_request_id.as_str())
            .map_err(|error| {
                BrokerError::invalid(format!("this identifier will not encode: {error}"))
            })?;
        let Some(members) = body.as_object_mut() else {
            return Err(BrokerError::invalid("a native frame is a JSON object"));
        };
        members.insert(request_id_field, minted);
        let encoded = serde_json::to_vec(&body).map_err(|error| {
            BrokerError::invalid(format!("this request will not encode: {error}"))
        })?;
        // The mapping goes in before the bytes, so an answer that arrives at once finds it. It is
        // bounded: a client that asks more than this connection can have outstanding is refused
        // here, with its intent recorded as unsent, rather than growing a map only the upstream
        // could empty.
        if let Err(error) = self
            .outstanding
            .forwarding(&upstream_request_id, client_identifier)
        {
            let _ = self
                .broker
                .client_request_settled(&admitted, ClientRequestOutcome::Unsent);
            return Err(error);
        }
        self.queue_client_frame(&encoded, admitted, Some(upstream_request_id))?;
        Ok(carried)
    }

    /// Queues one frame of the client's and leaves the rest to the owner.
    ///
    /// Nothing here waits for the socket. What the write turns out to be is recorded against the
    /// intent by the writer itself, in the order the frames went, and a request whose bytes never
    /// went gives its identifier mapping back.
    fn queue_client_frame(
        &self,
        encoded: &[u8],
        admitted: crate::broker::ClientRequest,
        forwarded: Option<UpstreamRequestId>,
    ) -> Result<()> {
        let broker = Arc::clone(&self.broker);
        let outstanding = Arc::clone(&self.outstanding);
        let queued = self.upstream.queue_then(
            encoded,
            Some(Box::new(move |delivery: Delivery| {
                let _ = broker.client_request_settled(&admitted, outcome_of(delivery));
                if delivery != Delivery::Transmitted
                    && let Some(id) = forwarded.as_ref()
                {
                    outstanding.client_identifier(id);
                }
            })),
        );
        queued.map(|_| ())
    }

    /// Refuses one reverse request, before anything of it could have an effect.
    ///
    /// The upstream asked this host to act in the agent's own environment. That runs through the
    /// broker's own file authority under an exclusive execution admission, and until that path
    /// exists the request is refused with a qualified reason rather than performed outside it.
    async fn refuse_reverse(&self, operation: ReverseOperation, frame: &[u8]) -> Result<bool> {
        let body: serde_json::Value = serde_json::from_slice(frame).map_err(|error| {
            BrokerError::invalid(format!("this frame is not readable: {error}"))
        })?;
        let connection = self.broker.connection(self.connection).ok_or_else(|| {
            BrokerError::unknown(format!("no gateway connection {}", self.connection))
        })?;
        let upstream_request_id = body
            .get(&connection.table.request_id_field)
            .and_then(|member| serde_json::to_string(member).ok())
            .and_then(|text| UpstreamRequestId::new(text).ok())
            .ok_or_else(|| {
                BrokerError::invalid("a reverse request carries the identifier it is answered on")
            })?;
        // The site is the gateway's, derived from the connection rather than taken from the
        // request: section 12 runs these in the agent's own environment with its own user, and
        // that is true only if the request does not get to say where.
        let reverse = self.broker.reverse_request(
            self.connection,
            upstream_request_id.clone(),
            operation,
            self.site,
            &self.os_user,
        )?;
        let mut answer = serde_json::Map::new();
        answer.insert(
            connection.table.response_id_field.clone(),
            serde_json::from_str(upstream_request_id.as_str()).unwrap_or(serde_json::Value::Null),
        );
        answer.insert(
            connection.table.error_field.clone(),
            serde_json::json!({
                "code": -32_601,
                "message": format!(
                    "{} runs against the host resources this session granted, and this host has \
                     granted none for it",
                    reverse.operation.as_str()
                ),
            }),
        );
        let body = serde_json::to_vec(&serde_json::Value::Object(answer)).map_err(|error| {
            BrokerError::invalid(format!("this answer will not encode: {error}"))
        })?;
        // Queued, not awaited: a refusal is not an effect, and this reader has other frames to
        // read whether or not the upstream is draining.
        self.upstream.queue(&body)?;
        Ok(false)
    }

    /// Writes one upstream reply back to the client under the identifier the client used.
    fn return_to_client(
        &self,
        frame: &[u8],
        client_identifier: &serde_json::Value,
    ) -> Result<bool> {
        let held = self.broker.connection(self.connection).ok_or_else(|| {
            BrokerError::unknown(format!("no gateway connection {}", self.connection))
        })?;
        let mut body: serde_json::Value = serde_json::from_slice(frame).map_err(|error| {
            BrokerError::invalid(format!("this reply is not readable: {error}"))
        })?;
        let Some(members) = body.as_object_mut() else {
            return Err(BrokerError::invalid("a native frame is a JSON object"));
        };
        members.insert(
            held.table.response_id_field.clone(),
            client_identifier.clone(),
        );
        let encoded = serde_json::to_vec(&body).map_err(|error| {
            BrokerError::invalid(format!("this reply will not encode: {error}"))
        })?;
        // Queued, not awaited: this runs inside the upstream reader, and waiting here for the
        // client to drain would hold every frame behind it. The delivery is still watched, so a
        // reply that does not reach the client ends the connection rather than disappearing.
        let failing = Stopping {
            stopping: Arc::clone(&self.stopping),
            stopped: Arc::clone(&self.stopped),
        };
        let client = self.client.clone();
        self.client
            .queue_then(
                &encoded,
                Some(Box::new(move |delivery: Delivery| {
                    if delivery != Delivery::Transmitted {
                        client.close();
                        failing.stop();
                    }
                })),
            )
            .map(|_| true)
    }

    /// Reads one end for as long as it has frames, carrying each one.
    ///
    /// `upstream` says which end this is. The loop ends when the end closes, when the owner is
    /// asked to stop, or when the end sends something this framing cannot be reading; a refusal of
    /// one frame does not end the connection, because one malformed or unanswerable frame is not a
    /// reason to take a working terminal away.
    pub async fn serve<R: AsyncRead + Unpin>(self: &Arc<Self>, reader: R, upstream: bool) {
        self.serve_after(reader, upstream, Vec::new()).await;
    }

    /// The same, continuing from bytes that were already read off this end.
    ///
    /// Authenticating a connection means reading its first frame, and one read can hand back more
    /// than one frame. What was read and not used is given back here rather than dropped, so the
    /// request a bridge wrote immediately after its hello is not lost.
    pub async fn serve_after<R: AsyncRead + Unpin>(
        self: &Arc<Self>,
        mut reader: R,
        upstream: bool,
        held: Vec<u8>,
    ) {
        let mut buffer = held;
        let mut chunk = [0_u8; 8192];
        loop {
            loop {
                match self.framing.decode(&mut buffer) {
                    Ok(Some(frame)) => {
                        let now = kr_ipc::now_ms();
                        let _ = if upstream {
                            self.from_upstream(&frame, now).await
                        } else {
                            self.from_client(&frame, now).await
                        };
                    }
                    Ok(None) => break,
                    // The stream is no longer one this framing can read, so this end is done.
                    Err(_) => return,
                }
            }
            if self.stopped.load(Ordering::Acquire) {
                return;
            }
            let read = tokio::select! {
                read = reader.read(&mut chunk) => read,
                () = self.stopping.notified() => return,
            };
            match read {
                Ok(0) | Err(_) => return,
                Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            }
        }
    }
}

/// One frame the native client sent that is a request or a notification of its own.
#[derive(Debug)]
struct ClientFrame {
    body: serde_json::Value,
    identifier: Option<serde_json::Value>,
    request_id_field: String,
    /// The bytes as the client wrote them, which is what the admission classifies and retains.
    frame: Vec<u8>,
}

/// Turns what reached the socket into what the client's intent is recorded as.
const fn outcome_of(delivery: Delivery) -> ClientRequestOutcome {
    match delivery {
        Delivery::Transmitted => ClientRequestOutcome::Transmitted,
        Delivery::Partial => ClientRequestOutcome::Uncertain,
        Delivery::Unsent => ClientRequestOutcome::Unsent,
    }
}

/// One admitted native answer, held until something says what happened to it.
///
/// Dropping it without saying leaves the resource uncertain, which is what an answer whose fate
/// nobody established is. That covers the writer's task ending, the reader being cancelled, and a
/// caller that returns early.
struct AdmittedAnswer {
    broker: Arc<Broker>,
    answer: Option<crate::broker::NativeAnswer>,
}

impl AdmittedAnswer {
    fn frame(&self) -> &[u8] {
        self.answer
            .as_ref()
            .map_or(&[][..], |answer| answer.frame.as_slice())
    }

    fn resource_id(&self) -> PendingResourceId {
        self.answer.as_ref().map_or_else(
            || PendingResourceId::new(kr_protocol::scalars::Uuid::from_bytes([0; 16])),
            |answer| answer.resource_id,
        )
    }

    /// Settles the resource from what actually reached the upstream.
    fn settle(mut self, delivery: Delivery) {
        let Some(answer) = self.answer.take() else {
            return;
        };
        let now = kr_ipc::now_ms();
        if delivery == Delivery::Transmitted {
            let _ = self.broker.native_answer_sent(&answer, now);
        } else {
            let _ = self.broker.native_answer_uncertain(&answer, now);
        }
    }
}

impl Drop for AdmittedAnswer {
    fn drop(&mut self) {
        let Some(answer) = self.answer.take() else {
            return;
        };
        let _ = self
            .broker
            .native_answer_uncertain(&answer, kr_ipc::now_ms());
    }
}

/// Reads one reply to a request this host sent.
fn read_reply(
    broker: &Broker,
    connection: GatewayConnectionId,
    frame: &[u8],
    upstream_request_id: &UpstreamRequestId,
) -> Result<UpstreamReply> {
    let held = broker
        .connection(connection)
        .ok_or_else(|| BrokerError::unknown(format!("no gateway connection {connection}")))?;
    let body: serde_json::Value = serde_json::from_slice(frame)
        .map_err(|error| BrokerError::invalid(format!("this reply is not readable: {error}")))?;
    let refusal = body
        .get(&held.table.error_field)
        .map(|error| UpstreamFailure {
            code: error
                .get("code")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(-32_603),
            message: error
                .get("message")
                .and_then(serde_json::Value::as_str)
                .map_or_else(|| error.to_string(), ToOwned::to_owned),
        });
    let turn_id = body
        .get(&held.table.result_field)
        .and_then(|result| result.get("turn_id"))
        .and_then(serde_json::Value::as_str)
        .and_then(|text| kr_protocol::ids::AgentTurnId::new(text).ok());
    Ok(UpstreamReply {
        upstream_request_id: upstream_request_id.clone(),
        turn_id,
        refusal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stop nothing is listening for, for a sink built on its own.
    fn stopping() -> Stopping {
        Stopping {
            stopping: Arc::new(tokio::sync::Notify::new()),
            stopped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// One prepared plugin action, as an admission hands it to a transport.
    fn plugin_action(
        draft_id: Option<kr_protocol::ids::DraftId>,
        draft_revision: Option<kr_protocol::scalars::U64>,
    ) -> UpstreamRequest {
        UpstreamRequest {
            admitted: crate::broker::methods::Admitted::new(),
            application_instance_id: ApplicationInstanceId::new(
                kr_protocol::scalars::Uuid::from_bytes([2; 16]),
            ),
            binding_revision: kr_protocol::ids::AgentBindingRevision::new(1),
            operation: kr_protocol::gateway::RichOperation::PluginAction,
            turn_id: None,
            body: UpstreamBody::PluginAction {
                plugin_id: kr_protocol::ids::PluginId::new("kalareach.codex").expect("valid"),
                action: kr_protocol::broker::ActionName::new("draft.attach").expect("valid"),
                draft_id,
                draft_revision,
                parameters: b"{}".to_vec(),
                operation: Some(kr_protocol::broker::PreparedOperation::UpstreamAttachment),
                token: None,
            },
        }
    }

    /// KR-REQ-23.30: what goes on the wire names the draft revision the host checked.
    ///
    /// A draft identifier denotes whatever the draft holds when the frame lands. The revision the
    /// admission was taken against travels with it, so the upstream acts on the draft this host
    /// admitted or on nothing.
    #[test]
    fn a_draft_bearing_action_encodes_the_revision_it_was_admitted_at() {
        let draft_id =
            kr_protocol::ids::DraftId::new(kr_protocol::scalars::Uuid::from_bytes([4; 16]));
        let encoded = Dispatch::parameters(&plugin_action(
            Some(draft_id),
            Some(kr_protocol::scalars::U64::new(7)),
        ))
        .expect("a validated action encodes");
        assert_eq!(
            encoded["draft_id"],
            serde_json::json!(draft_id.to_string()),
            "the draft it acts on"
        );
        assert_eq!(
            encoded["draft_revision"],
            serde_json::json!(7),
            "and the revision that draft stood at when it was admitted"
        );

        // An action that names no draft names no revision, and neither half travels alone.
        let none = Dispatch::parameters(&plugin_action(None, None)).expect("it encodes");
        assert_eq!(none["draft_id"], serde_json::Value::Null);
        assert_eq!(none["draft_revision"], serde_json::Value::Null);
        assert!(
            Dispatch::parameters(&plugin_action(Some(draft_id), None)).is_err(),
            "a draft with no checked revision is not something this host transmits"
        );
    }

    /// KR-REQ-12.13: the two directions mint identifiers in sets that cannot overlap.
    #[test]
    fn the_identifiers_this_host_mints_are_not_ones_an_upstream_could_mint() {
        let outstanding = Outstanding::default();
        let first = outstanding.allocate().expect("an identifier is minted");
        let second = outstanding.allocate().expect("and another");
        assert_ne!(first, second, "each request gets its own");
        assert!(is_host_minted(&first));
        assert!(is_host_minted(&second));

        // A bare number is what an upstream writes, and no number is in this host's namespace.
        for raw in ["1", "7", "\"7\"", "\"session-7\"", "null"] {
            let id = UpstreamRequestId::new(raw.to_owned()).expect("valid");
            assert!(
                !is_host_minted(&id),
                "{raw} is not an identifier this host minted"
            );
        }
    }

    /// Section 9 and section 11: the queue is bounded in bytes, not in frames.
    #[tokio::test]
    async fn a_queue_that_is_full_refuses_rather_than_growing() {
        let (upstream, _client) = tokio::io::duplex(64);
        // Nothing drives the write task, so everything queued stays queued.
        let (sink, _writes) = sink(
            Framing::new(kr_protocol::gateway::NativeFraming::JsonLines),
            upstream,
            stopping(),
        );
        let body = vec![b'x'; 4096];
        let mut accepted = 0;
        while sink.queue(&body).is_ok() {
            accepted += 1;
            assert!(accepted < 10_000, "the bound is reached");
        }
        assert!(
            sink.queued_bytes() <= MAX_QUEUED_BYTES,
            "what is held never passes the bound"
        );
        assert!(
            sink.queued_bytes() + body.len() > MAX_QUEUED_BYTES,
            "and the refusal happened because the bound was reached"
        );
    }

    /// A frame the peer never reads leaves the write deadline, not an unbounded wait.
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_never_reads_leaves_a_partial_delivery() {
        // A pipe of eight bytes with nothing reading it takes the first bytes and then blocks.
        let (writer, reader) = tokio::io::duplex(8);
        let (sink, writes) = sink(
            Framing::new(kr_protocol::gateway::NativeFraming::JsonLines),
            writer,
            stopping(),
        );
        let driving = tokio::spawn(writes);
        let queued = sink.queue(&vec![b'y'; 4096]).expect("it is queued");
        let delivery = queued.delivered().await;
        assert_eq!(
            delivery,
            Delivery::Partial,
            "some of it went into the pipe and the rest never will"
        );
        assert!(delivery.refusal().is_some(), "and that is not a success");
        drop(reader);
        driving.abort();
    }
}
