//! One call that puts a host on the network.
//!
//! The controller's integration with this crate is [`register`] and nothing else. It hands over a
//! configuration, its transport identity and one implementation of [`HostHandler`], and gets back
//! a [`NetworkListener`] it can shut down. Everything between an incoming QUIC connection and an
//! authorised control stream happens here: the handshake, the pre-authorisation surface, the
//! keepalive, the action-window renewal, and the revocation that follows a lost control stream.
//!
//! Keeping that in one call is deliberate. The rules a connection has to obey are not the kind of
//! thing a host should be able to get subtly wrong by wiring the pieces itself.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use iroh::Endpoint;
use iroh::endpoint::Connection;
use kr_crypto::connect::ChallengeLedger;
use kr_crypto::keys::TransportIdentityKeyPair;
use kr_protocol::envelope::{ControlEvent, ControlFrame};
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{ActionWindow, ClientOffer, HostSelection};
use kr_protocol::ids::{ActorId, AuthorityRevision, ConnectionId, ControllerGeneration, DeviceId};
use kr_protocol::scalars::{Digest256, EndpointKey, to_base64url};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::actor::ConnectionActor;
use crate::clock::{ContinuousClock, ContinuousInstant, SystemContinuousClock};
use crate::codec::{FrameReader, FrameWriter};
use crate::config::EndpointConfig;
use crate::deadlines::{Deadlines, TimerDeadlines};
use crate::endpoint::{KEEPALIVE, allow_data_streams, bind_listener, withdraw_data_streams};
use crate::error::{Result, TransportError};
use crate::handshake::{Admitted, HostEpochs, LocalIdentity, PairedDirectory};
use crate::preauth::{PairingSurface, PreAuthLimits};
use crate::scheduler::{SendLimits, StreamBudget};
use crate::streams::{DataStream, RevocationHook, StreamRegistry};
use crate::window::{ActionWindowIssuer, MAX_WINDOW_VALIDITY};

/// A boxed future, so [`HostHandler`] stays usable behind a trait object.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How many connection challenges a host will hold at once.
///
/// A challenge is outstanding only between `hello` and the proof, so this bounds concurrent
/// half-finished handshakes rather than connections. A full ledger is answered by ending idle
/// connections, not by forgetting a challenge.
pub const DEFAULT_MAX_OUTSTANDING_CHALLENGES: usize = 1024;

/// Everything the listener needs beyond the host's own implementation.
#[derive(Debug)]
pub struct ListenerConfig {
    /// The endpoint's selected network services.
    pub endpoint: EndpointConfig,
    /// The host's boot and clock epochs.
    pub epochs: HostEpochs,
    /// The controller generation admitting connections. A replacement generation rebinds every
    /// connection, because an envelope records the generation that admitted it.
    pub controller_generation: ControllerGeneration,
    /// The bulk-stream limits each connection is held to.
    pub send_limits: SendLimits,
    /// What an unpaired connection may do.
    pub preauth_limits: PreAuthLimits,
    /// How long an action window lasts, capped at five minutes.
    pub action_window_validity: Duration,
    /// How many half-finished handshakes may be outstanding.
    pub max_outstanding_challenges: usize,
    /// How often the host sends a control-stream keepalive.
    pub keepalive: Duration,
    /// How long a connection has to finish its handshake and its pairing exchange.
    pub handshake_deadline: Duration,
    /// How many connections may be mid-handshake or unpaired at once, across the whole host.
    pub max_unauthorised_connections: usize,
    /// How many unauthorised connections the host admits in a burst, across every peer.
    pub unauthorised_burst: u32,
    /// How often one place in that burst is returned.
    pub unauthorised_refill: Duration,
    /// The stream kinds this host takes from a device. A stream a device opens whose header names
    /// any other kind is reset before it takes a bulk slot or a place in the registry. A host that
    /// names none takes none, and a device can open no stream but the control stream on its
    /// connections: a connection starts with room for that one stream, and is raised to the room
    /// the bulk streams need when this names a kind and the host first calls
    /// [`DataStreams::recv`], so a device that tries to open a second stream before that waits for
    /// credit that does not come.
    pub accepted_kinds: Vec<StreamKind>,
    /// The deadlines a data stream is held to: the header a device sends, each frame it sends and
    /// each answer it is sent. A host that does not choose them gets [`TimerDeadlines`]; a test
    /// that must not wait for a clock supplies its own.
    pub deadlines: Arc<dyn Deadlines>,
}

impl ListenerConfig {
    /// Builds a configuration with the specified defaults.
    #[must_use]
    pub fn new(
        endpoint: EndpointConfig,
        epochs: HostEpochs,
        controller_generation: ControllerGeneration,
    ) -> Self {
        Self {
            endpoint,
            epochs,
            controller_generation,
            send_limits: SendLimits::default(),
            preauth_limits: PreAuthLimits::default(),
            action_window_validity: MAX_WINDOW_VALIDITY,
            max_outstanding_challenges: DEFAULT_MAX_OUTSTANDING_CHALLENGES,
            keepalive: KEEPALIVE,
            handshake_deadline: DEFAULT_HANDSHAKE_DEADLINE,
            max_unauthorised_connections: DEFAULT_MAX_UNAUTHORISED_CONNECTIONS,
            unauthorised_burst: DEFAULT_UNAUTHORISED_BURST,
            unauthorised_refill: DEFAULT_UNAUTHORISED_REFILL,
            accepted_kinds: Vec::new(),
            deadlines: Arc::new(TimerDeadlines::default()),
        }
    }
}

/// How long an unauthorised connection may stay open.
///
/// A handshake is four frames and a pairing exchange is a handful more, so a minute is generous.
/// The deadline exists because QUIC keepalives would otherwise hold an incomplete handshake open
/// indefinitely, and an incomplete handshake costs the host a task and an admission slot.
pub const DEFAULT_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(60);

/// How many connections may be mid-handshake or unpaired at once.
///
/// A configurable resource limit. It bounds what an endpoint can cost the host before it has proved
/// anything, which is what a per-connection budget alone cannot do: reconnecting resets a
/// per-connection budget, and this does not.
pub const DEFAULT_MAX_UNAUTHORISED_CONNECTIONS: usize = 64;

/// How many unauthorised connections the host admits in a burst.
pub const DEFAULT_UNAUTHORISED_BURST: u32 = 32;

/// How often one place in that burst is returned.
///
/// Concurrency alone does not bound a peer that connects, spends a small budget and reconnects. The
/// bucket does: sustained admissions are one every interval, however many endpoints ask.
pub const DEFAULT_UNAUTHORISED_REFILL: Duration = Duration::from_millis(250);

/// A host-wide bucket of unauthorised admissions.
#[derive(Debug)]
struct AdmissionRate {
    burst: u32,
    refill: Duration,
    state: std::sync::Mutex<AdmissionTokens>,
}

#[derive(Debug)]
struct AdmissionTokens {
    tokens: u32,
    last_refill: std::time::Instant,
}

impl AdmissionRate {
    /// Creates a bucket. A zero refill is no rate limit at all rather than a bucket that never
    /// refills, which would stop the host admitting anything after its first burst.
    fn new(burst: u32, refill: Duration) -> Self {
        Self {
            burst: burst.max(1),
            refill,
            state: std::sync::Mutex::new(AdmissionTokens {
                tokens: burst.max(1),
                last_refill: std::time::Instant::now(),
            }),
        }
    }

    /// Takes one admission, or returns false when the burst is spent.
    fn take(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.refill.is_zero() {
            return true;
        }
        let elapsed = state.last_refill.elapsed();
        {
            let earned = u32::try_from(elapsed.as_nanos() / self.refill.as_nanos().max(1))
                .unwrap_or(u32::MAX);
            if earned > 0 {
                state.tokens = state.tokens.saturating_add(earned).min(self.burst);
                state.last_refill = std::time::Instant::now();
            }
        }
        if state.tokens == 0 {
            return false;
        }
        state.tokens -= 1;
        true
    }
}

/// What the host supplies.
///
/// One trait rather than several, because a host that can answer one of these questions can answer
/// all of them, and a listener that took four separate objects would let a caller pair them wrongly.
pub trait HostHandler: PairedDirectory + Send + Sync + 'static {
    /// Returns the principal this device acts under on this host.
    ///
    /// The host assigns it; nothing on the connection can claim one. A device principal is stable
    /// for the device, which is what makes `(actor_id, action_id)` a de-duplication key.
    fn principal_for(&self, device_id: &DeviceId) -> ActorId;

    /// Returns the pairing implementation, when the host is accepting pairing.
    ///
    /// A host that returns `None` refuses unpaired connections outright, which is what a host with
    /// no outstanding invitation does.
    fn pairing_surface(&self) -> Option<Arc<dyn PairingSurface>>;

    /// Returns the authority revision this host holds now.
    ///
    /// The listener reads it once a connection's QUIC handshake is done and before the host's own
    /// handshake begins, so before the peer can have been told it is accepted, and hands it to
    /// [`Self::serve`] as
    /// [`AuthorisedSession::authorised_under`]. A host registers a connection only once it is
    /// served, after the handshake has finished, and a withdrawal of authority can land in
    /// between and find no registration to take away. The revision read here is what lets the host
    /// see that the connection was authorised before that withdrawal.
    fn authority_revision(&self) -> AuthorityRevision;

    /// Serves one authorised connection until it ends.
    ///
    /// The listener has already proved both authorisation keys, allocated the connection identity,
    /// issued the first action window and started the keepalive. What is left is the host's own:
    /// reading requests, checking authority and answering.
    ///
    /// This future is dropped when the control stream ends, which is a cancellation: destructors
    /// run, but nothing after an outstanding `await` finishes. Work that must complete — a durable
    /// commit, a dispatch marker — belongs to an owner that outlives the connection, not to this
    /// future.
    ///
    /// A host that takes data streams reads [`AuthorisedSession::data_streams`] on a task of its
    /// own, and its first call to [`DataStreams::recv`] is what lets the device open streams: it
    /// raises the connection's stream limit from the control stream's one. The listener cannot
    /// know when the host has finished its own check of the device, so that is the host's to
    /// arrange: it calls `recv` only after that check, never before it. A read task started before
    /// the check gives a device the credit to open nine streams (with the default allowance) for
    /// as long as the check takes, each with a buffer. At most
    /// [`MAX_PENDING_HEADERS`](crate::streams::MAX_PENDING_HEADERS) of them have a header being
    /// read at once, under a deadline, and at most [`DATA_STREAM_QUEUE_DEPTH`] wait in the queue.
    fn serve(self: Arc<Self>, session: AuthorisedSession) -> BoxFuture<'static, ()>;

    /// Called when a connection's control stream ends.
    ///
    /// Section 23: closing or failing the control stream revokes every associated data stream and
    /// stops remote lease renewal. The data streams are revoked by the listener before this runs;
    /// stopping renewal is the host's half, because the host owns the leases.
    fn control_stream_lost(&self, _connection_id: ConnectionId) {}

    /// Called by the task that reads a device's control stream, once for each frame it reads and
    /// before the frame is queued for [`Self::serve`].
    ///
    /// A frame waits in the connection's queue for a handler that is answering an earlier one, and
    /// until the handler reaches it the host has not seen it. What this returns travels with the
    /// frame ([`ReceivedFrame::take_hold`]) and is dropped with it, so a host can account for a
    /// request from the moment it was read, and its accounting ends with the frame wherever that
    /// is: answered, dropped from a full queue, or left in the queue of a connection that ended.
    /// It runs on the reader and must not wait.
    fn frame_read(&self, _device_id: &DeviceId, _frame: &ControlFrame) -> Option<FrameHold> {
        None
    }
}

/// What a host holds for a control frame from the moment the stream's reader has read it. The
/// transport does not look inside it.
pub type FrameHold = Box<dyn std::any::Any + Send + Sync>;

/// The control stream of an authorised connection.
///
/// The writer is shared, because the keepalive and the window renewal send on the same stream the
/// host answers requests on. The reader is not: exactly one task reads a stream.
///
/// Both directions report their end to the connection's supervisor. Section 23 gives the control
/// stream's failure a consequence — every data stream revoked, remote lease renewal stopped — and
/// that consequence cannot wait for a handler that may be blocked on a worker.
#[derive(Debug)]
pub struct ControlChannel {
    writer: Arc<Mutex<FrameWriter>>,
    frames: tokio::sync::mpsc::Receiver<ReceivedFrame>,
    lost: Arc<ControlLoss>,
}

/// A control frame and when the host read it from the stream, on the host's continuous clock.
///
/// Section 9 measures a requested lifetime from the receipt of the request. A frame waits in the
/// connection's queue for a handler that is answering an earlier one, and a lifetime measured from
/// the moment the handler reaches it would hand back what that wait spent. The stamp is made by the
/// task that reads the stream, before the frame is queued, and a handler cannot make one.
pub struct ReceivedFrame {
    frame: ControlFrame,
    received_at: ContinuousInstant,
    hold: Option<FrameHold>,
}

impl std::fmt::Debug for ReceivedFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReceivedFrame")
            .field("frame", &self.frame)
            .field("received_at", &self.received_at)
            .field("held", &self.hold.is_some())
            .finish()
    }
}

impl ReceivedFrame {
    /// A frame the host has just read from a stream, stamped on `clock`, with what the host holds
    /// for it.
    ///
    /// The control stream's reader makes these itself. A host that reads frames from a data stream
    /// ([`AuthorisedSession::data_streams`]) makes one for each, with the connection's clock
    /// ([`AuthorisedSession::clock`]) and what it holds for the frame from the moment it was read
    /// ([`HostHandler::frame_read`]), so that a frame from either stream goes through the same
    /// door.
    #[must_use]
    pub fn read(frame: ControlFrame, clock: &dyn ContinuousClock, hold: Option<FrameHold>) -> Self {
        Self {
            received_at: clock.now(),
            frame,
            hold,
        }
    }

    /// A frame read at `received_at`, for this host's own tests.
    #[cfg(feature = "testing")]
    #[must_use]
    pub const fn at(frame: ControlFrame, received_at: ContinuousInstant) -> Self {
        Self {
            frame,
            received_at,
            hold: None,
        }
    }

    /// What the host held for this frame when the reader read it ([`HostHandler::frame_read`]), if
    /// it held anything. The host that takes it owns it from then on.
    pub fn take_hold(&mut self) -> Option<FrameHold> {
        self.hold.take()
    }

    /// The frame.
    #[must_use]
    pub const fn frame(&self) -> &ControlFrame {
        &self.frame
    }

    /// When the host read it, on its continuous clock.
    #[must_use]
    pub const fn received_at(&self) -> ContinuousInstant {
        self.received_at
    }

    /// The frame and when it was read.
    #[must_use]
    pub fn into_parts(self) -> (ControlFrame, ContinuousInstant) {
        (self.frame, self.received_at)
    }
}

impl ControlChannel {
    /// Sends one control frame.
    ///
    /// # Errors
    ///
    /// Returns a framing error when the frame exceeds the control bound, and a stream error when
    /// the stream has ended.
    pub async fn send(&self, frame: &ControlFrame) -> Result<()> {
        let outcome = self.writer.lock().await.write_message(frame).await;
        if outcome.is_err() {
            self.lost.declare();
        }
        outcome
    }

    /// Returns the next control frame and when it was read, or `None` once the stream has ended.
    ///
    /// The stream is read by the connection itself, not by this call: a handler that is waiting on
    /// a worker must not be what decides whether the control stream is still alive. Frames are
    /// queued for the handler up to [`CONTROL_QUEUE_DEPTH`]; a handler that falls that far behind
    /// loses the connection rather than holding the transport open. A frame is stamped when it is
    /// read, whatever the handler is doing then.
    pub async fn recv(&mut self) -> Option<ReceivedFrame> {
        self.frames.recv().await
    }

    /// How many frames the reader has read and the handler has not taken yet, for this host's own
    /// tests, which wait on that rather than on time.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn queued(&self) -> usize {
        self.frames.len()
    }

    /// Returns a handle that can send without holding the channel.
    #[must_use]
    pub fn sender(&self) -> ControlSender {
        ControlSender {
            writer: Arc::clone(&self.writer),
            lost: Arc::clone(&self.lost),
        }
    }
}

/// A send-only handle on a control stream.
#[derive(Clone, Debug)]
pub struct ControlSender {
    writer: Arc<Mutex<FrameWriter>>,
    lost: Arc<ControlLoss>,
}

impl ControlSender {
    /// Sends one control frame.
    ///
    /// A failure is reported to the connection's supervisor before it is returned.
    ///
    /// # Errors
    ///
    /// As [`ControlChannel::send`].
    pub async fn send(&self, frame: &ControlFrame) -> Result<()> {
        let outcome = self.writer.lock().await.write_message(frame).await;
        if outcome.is_err() {
            self.lost.declare();
        }
        outcome
    }

    /// Sends one control frame for as long as `admits` holds, and says whether it went.
    ///
    /// The writer is taken first, and then `admits` decides at every attempt to hand bytes to the
    /// stream, and holds what it decided on until the attempt has ended
    /// ([`kr_transport::codec::Admission`](crate::codec::Admission)): a frame that waited behind
    /// the keepalive, behind a window renewal or behind a peer that stopped reading is never
    /// written under authority that went while it waited. `admits` is evaluated inside a poll, so
    /// it must not block and must not wait on this stream.
    ///
    /// Returns `Ok(false)` when it refused. Nothing more can be written on the stream after that:
    /// a frame abandoned part way through leaves it in pieces, and it is reset.
    ///
    /// # Errors
    ///
    /// As [`ControlChannel::send`].
    pub async fn send_while(
        &self,
        frame: &ControlFrame,
        admits: crate::codec::Admission<'_>,
    ) -> Result<bool> {
        let mut writer = self.writer.lock().await;
        // Asked before anything is written, so that a frame refused at once leaves the stream whole.
        if !admits(&mut || {}) {
            return Ok(false);
        }
        let outcome = writer.write_message_while(frame, admits).await;
        if outcome.is_err() {
            self.lost.declare();
        }
        outcome
    }
}

/// One authorised connection, handed to the host.
#[derive(Debug)]
pub struct AuthorisedSession {
    /// The underlying iroh connection, for opening and accepting data streams.
    pub connection: Connection,
    /// The connection identity the host allocated.
    pub connection_id: ConnectionId,
    /// The peer's device identity.
    pub peer_device_id: DeviceId,
    /// The peer's endpoint identity, as authenticated by iroh.
    pub peer_endpoint_id: EndpointKey,
    /// The digest of the transcript both sides signed.
    pub transcript_digest: Digest256,
    /// The offer, as signed.
    pub offer: ClientOffer,
    /// The selection, as signed.
    pub selection: HostSelection,
    /// The actor every request on this connection is attributed to.
    pub actor: ConnectionActor,
    /// The control stream.
    pub control: ControlChannel,
    /// Every data stream of this connection.
    pub streams: Arc<StreamRegistry>,
    /// The data streams the device opened and the listener has admitted, in the order their
    /// headers arrived.
    ///
    /// The listener takes every stream the device opens, reads each header on a task of its own
    /// under the header deadline, and checks the header against this connection and its kind
    /// against [`ListenerConfig::accepted_kinds`]. A stream that passes is sent here, and a stream
    /// that fails any step, or that finds [`DATA_STREAM_QUEUE_DEPTH`] streams waiting, or whose
    /// receiver is gone, is reset. The device can open a second stream only once the host has
    /// called [`DataStreams::recv`]: a host that never reads leaves it at the control stream. A
    /// host that reads once and then stops holds at most [`DATA_STREAM_QUEUE_DEPTH`] streams in the
    /// queue for a device that opens them, each with its registry entry and its flow-control
    /// credit, until the connection ends, and resets the rest. An attachment stream also holds one
    /// of the connection's bulk slots, which the four places share with every other attachment
    /// stream; a stream of any other kind holds none, so a host that accepts one can hold more
    /// streams than the queue's depth: at most as many as the connection's stream limit allows
    /// beside its control stream, 9 with the defaults, of which at most `max_bulk_streams` are
    /// attachment streams. The receiver ends when the connection does, and a stream still queued
    /// when it is dropped is reset.
    pub data_streams: DataStreams,
    /// The deadlines a data stream is held to ([`ListenerConfig::deadlines`]), for the waits a
    /// host makes on a stream's behalf: the lookup that admits it runs under
    /// [`DeadlineKind::Admission`](crate::deadlines::DeadlineKind::Admission).
    pub deadlines: Arc<dyn Deadlines>,
    /// The host's action windows.
    pub windows: Arc<ActionWindowIssuer>,
    /// The window this connection started with.
    pub action_window: ActionWindow,
    /// The host's continuous clock.
    pub clock: Arc<dyn ContinuousClock>,
    /// The authority revision the host held before this connection was authorised
    /// ([`HostHandler::authority_revision`]), and so the latest one its authorisation can have been
    /// decided under.
    pub authorised_under: AuthorityRevision,
}

/// The data streams the listener has admitted and the host has not taken yet.
///
/// A connection starts with room for one stream, the control stream, and its stream limit is
/// raised the first time the host calls [`DataStreams::recv`]. The listener cannot know when the
/// host has finished its own check of the device, so that is the host's to arrange: call `recv`
/// only after the check, never before it (see [`HostHandler::serve`]). A host that names kinds in
/// [`ListenerConfig::accepted_kinds`] and never reads leaves its devices at one stream. Until the
/// first call the accept task waits for a stream the device has no credit to open. Dropping the
/// receiver takes the limit back to one: the credit the library has already allocated to the device
/// stays, and any of it not yet sent is still sent, and the streams that end after that give it no
/// more.
///
/// Dropping it resets every stream still queued, so a host that stops taking streams while its
/// connection stands tells the device each of them was taken away, instead of letting each finish
/// as though it had ended cleanly, and it ends the accept task's work for the host at once: a
/// stream whose header is being read is reset, and a stream that arrives afterwards is reset as it
/// is accepted.
#[derive(Debug)]
pub struct DataStreams {
    queue: Arc<Handoff<Queued>>,
    /// The connection's stream limit, for a host that takes data streams: the first `recv` raises
    /// it and dropping the receiver takes it back.
    credit: Option<Credit>,
}

/// A connection's stream limit, which a host that takes data streams raises by reading them.
#[derive(Debug)]
struct Credit {
    connection: Connection,
    max_bulk_streams: usize,
    /// Set once the first `recv` has raised the limit.
    raised: bool,
}

impl DataStreams {
    /// Returns the next admitted stream, or `None` once the connection has ended.
    ///
    /// The first call raises the connection's stream limit, if the host names any stream kind. The
    /// listener cannot know when the host has finished its own check of the device, so a host makes
    /// that call only after the check: when it comes is the host's to arrange (see
    /// [`HostHandler::serve`]). A stream that was revoked while it waited in the queue, because its
    /// connection lost its control stream, is reset and skipped, never returned. That is the only
    /// check made: a connection that has closed but whose cleanup has not run yet has revoked
    /// nothing, and a stream the host is handed can be revoked after it is returned, so the host
    /// asks [`DataStream::is_revoked`] again where it relies on it.
    pub async fn recv(&mut self) -> Option<DataStream> {
        if let Some(credit) = self.credit.as_mut().filter(|credit| !credit.raised) {
            allow_data_streams(&credit.connection, credit.max_bulk_streams);
            credit.raised = true;
        }
        loop {
            let stream = self.queue.next().await?.into_stream();
            if stream.is_revoked() {
                stream.reset();
                continue;
            }
            return Some(stream);
        }
    }
}

#[cfg(feature = "testing")]
impl DataStreams {
    /// How many admitted streams wait in the queue, for a case that has to know a stream reached
    /// it before it acts on the connection.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.queue.lock().queued.len()
    }
}

impl Drop for DataStreams {
    fn drop(&mut self) {
        // What was queued is dropped here, outside the queue's lock, and so reset; what the
        // accept task tries to queue from now on is handed back to it and dropped there. A
        // device that has opened its streams is given no more credit for the ones that end.
        drop(self.queue.close_receiver());
        if let Some(credit) = self.credit.as_ref().filter(|credit| credit.raised) {
            withdraw_data_streams(&credit.connection);
        }
    }
}

/// The queue between the accept task and the host's receiver.
///
/// One lock holds the queue and whether the receiver is still there, so a stream is either queued
/// before the receiver goes, and closing the receiver takes it, or is refused after, and is handed
/// back to the task that tried to queue it: there is no moment in which it is in neither place,
/// whichever of the two comes first. Dropping a stream that was taken from the queue or handed
/// back is what resets it.
#[derive(Debug)]
struct Handoff<T> {
    state: std::sync::Mutex<HandoffState<T>>,
    /// Wakes the receiver when something was queued or the sender is done.
    arrived: tokio::sync::Notify,
    /// Wakes the accept task when the receiver is gone.
    receiver_gone: tokio::sync::Notify,
}

#[derive(Debug)]
struct HandoffState<T> {
    queued: std::collections::VecDeque<T>,
    depth: usize,
    receiver_gone: bool,
    sender_done: bool,
}

impl<T> Handoff<T> {
    fn new(depth: usize) -> Arc<Self> {
        Arc::new(Self {
            state: std::sync::Mutex::new(HandoffState {
                queued: std::collections::VecDeque::new(),
                depth,
                receiver_gone: false,
                sender_done: false,
            }),
            arrived: tokio::sync::Notify::new(),
            receiver_gone: tokio::sync::Notify::new(),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HandoffState<T>> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Queues `item`, or hands it back when the receiver is gone, the sender is done or the queue
    /// is full. Nothing is queued after the sender is done, so a receiver that has read the end
    /// never has an item left behind it.
    fn push(&self, item: T) -> std::result::Result<(), T> {
        let mut state = self.lock();
        if state.receiver_gone || state.sender_done || state.queued.len() >= state.depth {
            return Err(item);
        }
        state.queued.push_back(item);
        drop(state);
        self.arrived.notify_one();
        Ok(())
    }

    /// Returns the next queued item, or `None` once the sender is done and nothing is left.
    async fn next(&self) -> Option<T> {
        loop {
            {
                let mut state = self.lock();
                if let Some(item) = state.queued.pop_front() {
                    return Some(item);
                }
                if state.sender_done {
                    return None;
                }
            }
            self.arrived.notified().await;
        }
    }

    /// Marks the receiver gone and returns what was queued, for the caller to drop.
    fn close_receiver(&self) -> std::collections::VecDeque<T> {
        let mut state = self.lock();
        state.receiver_gone = true;
        let queued = std::mem::take(&mut state.queued);
        drop(state);
        self.receiver_gone.notify_one();
        queued
    }

    /// Resolves once the receiver is gone.
    async fn receiver_closed(&self) {
        loop {
            if self.lock().receiver_gone {
                return;
            }
            self.receiver_gone.notified().await;
        }
    }

    /// Says the sender queues nothing more, so the receiver ends once it has what is queued.
    fn finish(&self) {
        self.lock().sender_done = true;
        self.arrived.notify_one();
    }
}

/// Tells the queue its sender has ended, however the accept task ends.
///
/// It is made before the task is spawned and moved into it, so it runs when the task's future is
/// dropped without ever having been polled, as well as when the future ends or is dropped part
/// way: a receiver that the host moved to another task is told the end whichever of these happens.
struct QueueEnds(Arc<Handoff<Queued>>);

impl Drop for QueueEnds {
    fn drop(&mut self) {
        self.0.finish();
    }
}

/// A stream waiting in the queue to the host.
///
/// However it leaves the queue without being taken, because the queue is full, the receiver is
/// dropped or the channel is dropped with a stream still in it, dropping it resets the stream:
/// whatever drops the value, the device sees the stream taken away and never a clean end.
#[derive(Debug)]
struct Queued(Option<DataStream>);

impl Queued {
    fn new(stream: DataStream) -> Self {
        Self(Some(stream))
    }

    /// The stream, which the host has taken.
    fn into_stream(mut self) -> DataStream {
        self.0
            .take()
            .expect("a queued stream is present until it is taken")
    }
}

impl Drop for Queued {
    fn drop(&mut self) {
        if let Some(stream) = self.0.take() {
            stream.reset();
        }
    }
}

/// How many admitted data streams a connection holds for a host that has not taken them yet.
///
/// A stream that arrives to a full queue is reset, not waited for: a host that falls this far
/// behind is not made to hold a device's streams open.
pub const DATA_STREAM_QUEUE_DEPTH: usize = 4;

/// The tasks that serve a listener's connections, which the listener ends with itself.
///
/// A connection's task holds the host handler, and what the handler holds, for as long as its peer
/// keeps the connection open and answers the keepalive. Left to run by themselves they would keep a
/// host whose listener has gone alive for as long as any device stayed connected, so the listener
/// owns them: ending the listener ends every one, and its peer sees the connection close.
#[derive(Debug, Default)]
struct ConnectionTasks {
    serving: std::sync::Mutex<Serving>,
}

#[derive(Debug, Default)]
struct Serving {
    tasks: tokio::task::JoinSet<()>,
    /// Set once the listener has ended, so that a connection the accept loop took in the same
    /// moment is not served after the rest were ended.
    ended: bool,
}

impl ConnectionTasks {
    /// Serves one connection on a task of its own, unless the listener has ended.
    fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        let mut serving = self
            .serving
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Connections that have already ended are collected as the next one arrives, so the set
        // holds no more than the connections being served and those that ended since the last
        // arrival.
        while serving.tasks.try_join_next().is_some() {}
        if !serving.ended {
            serving.tasks.spawn(task);
        }
    }

    /// Ends every task and every one that would be spawned from now on, and says whether this call
    /// was the one that ended them.
    ///
    /// Each task is cancelled at its next turn on the runtime, where it drops what it holds: a
    /// connection that was authorised closes with the code a lost control stream gives, a
    /// connection still in its handshake or its pairing exchange closes as it is dropped.
    fn end(&self) -> bool {
        let mut serving = self
            .serving
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let first = !serving.ended;
        serving.ended = true;
        serving.tasks.abort_all();
        first
    }

    /// Takes the tasks that were ended, so that a caller that can wait learns when each has been
    /// dropped. A second caller finds none and has nothing to wait for.
    fn take_ended(&self) -> tokio::task::JoinSet<()> {
        std::mem::take(
            &mut self
                .serving
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .tasks,
        )
    }
}

/// Waits for every ended connection task to have been dropped, and then closes the endpoint, so
/// that each peer is told its connection is closed instead of waiting for it to time out.
///
/// The endpoint is closed after the tasks have gone because a task's own close, with the code a lost
/// control stream gives, has then been made before the endpoint closes what is left with none.
async fn wind_down(endpoint: Endpoint, connections: Arc<ConnectionTasks>) {
    let mut ended = connections.take_ended();
    while ended.join_next().await.is_some() {}
    endpoint.close().await;
}

/// A running listener.
#[derive(Debug)]
pub struct NetworkListener {
    endpoint: Endpoint,
    accept_loop: JoinHandle<()>,
    connections: Arc<ConnectionTasks>,
    /// The runtime the listener was registered on, which closes the endpoint for a listener that is
    /// dropped on a thread that is not one of its own.
    runtime: tokio::runtime::Handle,
    /// The task that closes the endpoint once the connections have ended, when
    /// [`Self::end_connections`] started one, which [`Self::shutdown`] then waits for.
    winding_down: std::sync::Mutex<Option<JoinHandle<()>>>,
    windows: Arc<ActionWindowIssuer>,
}

impl NetworkListener {
    /// Returns the endpoint, for its identity and its addresses.
    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Returns this host's endpoint identity.
    #[must_use]
    pub fn endpoint_id(&self) -> EndpointKey {
        EndpointKey::from_bytes(*self.endpoint.id().as_bytes())
    }

    /// Returns the action-window issuer, so the host can validate a window a request names.
    #[must_use]
    pub fn windows(&self) -> &Arc<ActionWindowIssuer> {
        &self.windows
    }

    /// Stops accepting and ends every connection being served, without waiting for either, and
    /// closes the endpoint on a task of its own once they have gone.
    ///
    /// A host that is being stopped calls this to stop holding itself: each connection's task holds
    /// the host handler for as long as its peer keeps the connection open. Each task is cancelled at
    /// its next turn on the runtime, not before, and its peer sees the connection close. The
    /// listener stays in place, so a [`Self::shutdown`] after this still waits for the endpoint's
    /// close. It can be called from any thread: the close runs on the runtime the listener was
    /// registered on, and is lost only if that runtime has already ended.
    pub fn end_connections(&self) {
        self.accept_loop.abort();
        if self.connections.end() && !self.endpoint.is_closed() {
            let winding = self.runtime.spawn(wind_down(
                self.endpoint.clone(),
                Arc::clone(&self.connections),
            ));
            *self
                .winding_down
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(winding);
        }
    }

    /// Stops accepting, ends every connection being served and closes the endpoint, and returns
    /// once the endpoint is closed.
    ///
    /// The close is started, on a task of its own, before anything is waited for, so a shutdown
    /// that is cancelled while it waits has left the close under way and does not leave the
    /// endpoint open.
    pub async fn shutdown(self) {
        self.end_connections();
        let winding = self
            .winding_down
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(winding) = winding {
            let _ = winding.await;
        }
    }
}

impl Drop for NetworkListener {
    fn drop(&mut self) {
        // A listener nobody holds accepts nothing and serves nobody. The accept loop and each
        // connection's task own a handle on the host, so detached ones would keep that host, its
        // database and its connections alive for as long as the process ran, and a device that
        // stayed connected would keep them for as long as it answered the keepalive. A shutdown
        // that can await the endpoint's close is the orderly end; this is the end that happens
        // either way. Every task is cancelled at its next turn on the runtime, not before, and the
        // endpoint is closed on a task of its own once they have gone: an endpoint dropped without
        // being closed sends its peers nothing, and each would wait for its connection to time out.
        self.end_connections();
    }
}

/// Puts a host on the network.
///
/// # Errors
///
/// Returns a configuration or bind failure. Once it returns, the listener is accepting.
pub async fn register<H: HostHandler>(
    config: ListenerConfig,
    identity: Arc<LocalIdentity>,
    transport_key: &TransportIdentityKeyPair,
    handler: Arc<H>,
) -> Result<NetworkListener> {
    let clock: Arc<dyn ContinuousClock> = Arc::new(SystemContinuousClock::new());
    register_with_clock(config, identity, transport_key, handler, clock).await
}

/// Puts a host on the network against a caller-supplied clock.
///
/// A host that owns a qualified platform time adapter passes it here rather than accepting the
/// default clock.
///
/// # Errors
///
/// As [`register`].
pub async fn register_with_clock<H: HostHandler>(
    config: ListenerConfig,
    identity: Arc<LocalIdentity>,
    transport_key: &TransportIdentityKeyPair,
    handler: Arc<H>,
    clock: Arc<dyn ContinuousClock>,
) -> Result<NetworkListener> {
    config.send_limits.check()?;
    let endpoint = bind_listener(&config.endpoint, transport_key).await?;
    let windows = Arc::new(ActionWindowIssuer::new(
        Arc::clone(&clock),
        config.action_window_validity,
    ));
    let challenges = Arc::new(std::sync::Mutex::new(ChallengeLedger::with_limit(
        config.max_outstanding_challenges,
    )));

    let admission = Arc::new(tokio::sync::Semaphore::new(
        config.max_unauthorised_connections.max(1),
    ));
    let rate = Arc::new(AdmissionRate::new(
        config.unauthorised_burst,
        config.unauthorised_refill,
    ));
    let connections = Arc::new(ConnectionTasks::default());
    let accept_loop = tokio::spawn(accept_loop(
        AcceptLoop {
            endpoint: endpoint.clone(),
            config: Arc::new(config),
            identity,
            handler,
            clock,
            windows: Arc::clone(&windows),
            challenges,
            admission,
            rate,
        },
        Arc::clone(&connections),
    ));

    Ok(NetworkListener {
        endpoint,
        accept_loop,
        connections,
        runtime: tokio::runtime::Handle::current(),
        winding_down: std::sync::Mutex::new(None),
        windows,
    })
}

struct AcceptLoop<H: HostHandler> {
    endpoint: Endpoint,
    config: Arc<ListenerConfig>,
    identity: Arc<LocalIdentity>,
    handler: Arc<H>,
    clock: Arc<dyn ContinuousClock>,
    windows: Arc<ActionWindowIssuer>,
    challenges: Arc<std::sync::Mutex<ChallengeLedger>>,
    /// How many connections may be mid-handshake or unpaired at once, across the whole host.
    admission: Arc<tokio::sync::Semaphore>,
    /// How fast unauthorised connections may be admitted, across the whole host.
    rate: Arc<AdmissionRate>,
}

impl<H: HostHandler> AcceptLoop<H> {
    fn clone_state(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            config: Arc::clone(&self.config),
            identity: Arc::clone(&self.identity),
            handler: Arc::clone(&self.handler),
            clock: Arc::clone(&self.clock),
            windows: Arc::clone(&self.windows),
            challenges: Arc::clone(&self.challenges),
            admission: Arc::clone(&self.admission),
            rate: Arc::clone(&self.rate),
        }
    }
}

async fn accept_loop<H: HostHandler>(loop_state: AcceptLoop<H>, connections: Arc<ConnectionTasks>) {
    while let Some(incoming) = loop_state.endpoint.accept().await {
        // Concurrency alone does not bound a peer that connects, spends a small budget and
        // reconnects, so admissions are rate limited across the whole host as well.
        if !loop_state.rate.take() {
            tracing::debug!(
                "an incoming connection was refused: the host is at its admission rate"
            );
            incoming.refuse();
            continue;
        }
        // An unauthorised connection holds one admission slot from the moment it is accepted until
        // it is either authorised or gone. Without that ceiling a peer could open connections until
        // the host ran out of tasks, and reconnecting would reset every per-connection budget.
        let Ok(slot) = Arc::clone(&loop_state.admission).try_acquire_owned() else {
            tracing::debug!(
                "an incoming connection was refused: the host is at its admission bound"
            );
            incoming.refuse();
            continue;
        };
        let connecting = match incoming.accept() {
            Ok(connecting) => connecting,
            Err(error) => {
                tracing::debug!(%error, "an incoming connection was refused");
                continue;
            }
        };
        let state = loop_state.clone_state();
        connections.spawn(async move {
            if let Err(error) = serve_connection(state, connecting, slot).await {
                tracing::debug!(%error, "a connection ended");
            }
        });
    }
}

async fn serve_connection<H: HostHandler>(
    state: AcceptLoop<H>,
    connecting: iroh::endpoint::Accepting,
    slot: tokio::sync::OwnedSemaphorePermit,
) -> Result<()> {
    // The deadline covers the unauthorised phase and nothing else. An authorised session lasts as
    // long as its peer keeps it, and cancelling one after a minute would be a far worse failure
    // than the one this bound exists to prevent.
    let deadline = state.config.handshake_deadline;
    let admitted = match tokio::time::timeout(deadline, admit(&state, connecting)).await {
        Ok(admitted) => admitted?,
        Err(_) => {
            return Err(TransportError::handshake(
                kr_protocol::error::ErrorCode::ResourceUnavailable,
                "the connection exceeded its handshake deadline",
            ));
        }
    };
    let (connection, admitted, authorised_under) = admitted;

    match admitted {
        Admitted::Unpaired(mut unpaired) => {
            let Some(surface) = state.handler.pairing_surface() else {
                connection.close(REFUSED_UNPAIRED.into(), b"pairing is not open");
                return Ok(());
            };
            let outcome = tokio::time::timeout(
                deadline,
                crate::preauth::serve(
                    &mut unpaired,
                    surface.as_ref(),
                    state.config.preauth_limits,
                    state.clock.as_ref(),
                    state.config.controller_generation,
                ),
            )
            .await;
            connection.close(REFUSED_UNPAIRED.into(), b"the pairing exchange ended");
            match outcome {
                Ok(outcome) => outcome,
                Err(_) => Err(TransportError::handshake(
                    kr_protocol::error::ErrorCode::ResourceUnavailable,
                    "the pairing exchange exceeded its deadline",
                )),
            }
        }
        Admitted::Authorised(authorised) => {
            // An authorised connection is no longer unauthorised traffic, so it releases the
            // admission slot it held; its own limits govern it from here.
            drop(slot);
            serve_authorised(state, connection, authorised, authorised_under).await
        }
    }
}

/// Completes the QUIC handshake and the KalaReach one, under the caller's deadline.
///
/// The authority revision comes back beside the connection: it is the host's revision read once
/// the QUIC handshake is done and before the peer's offer is read, so the peer cannot have been
/// told it is accepted under a revision newer than this ([`HostHandler::authority_revision`]).
async fn admit<H: HostHandler>(
    state: &AcceptLoop<H>,
    connecting: iroh::endpoint::Accepting,
) -> Result<(Connection, Admitted, AuthorityRevision)> {
    // The first bidirectional stream is accepted from the 0-RTT connection, because QUIC marks a
    // stream as early data only when it is accepted while the handshake is still running. Nothing
    // is *read* from it here: the read happens after `handshake_completed`, so no frame is ever
    // acted on before the peer's endpoint identity is authenticated. What this buys is an honest
    // answer to "did this arrive as early data", which the 0-RTT rules below depend on.
    let zero_rtt = connecting.into_0rtt();
    let (send, recv) = zero_rtt
        .accept_bi()
        .await
        .map_err(|error| TransportError::Stream(error.to_string()))?;
    let early_data = recv.is_0rtt();
    let connection = zero_rtt
        .handshake_completed()
        .await
        .map_err(|error| TransportError::Connect(error.to_string()))?;

    let authorised_under = state.handler.authority_revision();
    let admitted = crate::handshake::accept_on(
        &connection,
        send,
        recv,
        early_data,
        &state.identity,
        state.config.epochs,
        state.handler.as_ref(),
        &state.challenges,
        &state.windows,
    )
    .await?;
    Ok((connection, admitted, authorised_under))
}

async fn serve_authorised<H: HostHandler>(
    state: AcceptLoop<H>,
    connection: Connection,
    authorised: Box<crate::handshake::AuthorisedConnection>,
    authorised_under: AuthorityRevision,
) -> Result<()> {
    let connection_id = authorised.connection_id;
    let hook: Arc<dyn RevocationHook> = Arc::new(HandlerHook {
        handler: Arc::clone(&state.handler) as Arc<dyn ControlLossListener>,
    });
    let streams = Arc::new(StreamRegistry::with_deadlines(
        connection_id,
        Arc::new(StreamBudget::new(
            state
                .config
                .send_limits
                .negotiated(authorised.selection.limits),
        )),
        Some(hook),
        authorised.selection.limits,
        Arc::clone(&state.config.deadlines),
    ));
    let lost = Arc::new(ControlLoss::new(Arc::clone(&streams)));
    let (frames_in, frames) = tokio::sync::mpsc::channel(CONTROL_QUEUE_DEPTH);
    let control = ControlChannel {
        writer: Arc::new(Mutex::new(authorised.control_writer)),
        frames,
        lost: Arc::clone(&lost),
    };
    let control_reader = tokio::spawn(control_read_loop(
        authorised.control_reader,
        frames_in,
        connection.clone(),
        Arc::clone(&lost),
        Arc::clone(&state.clock),
        Arc::clone(&state.handler) as Arc<dyn FrameWatch>,
        authorised.peer_device_id,
    ));
    // While this flag is set the keepalive may issue a window. The guard clears it before it
    // retires the connection, and the keepalive retires any window it issued after the flag was
    // cleared, so no window can outlive the connection whichever order the two run in.
    let issuing = Arc::new(std::sync::atomic::AtomicBool::new(true));
    // The guard exists before anything else can fail, so a panic in the host's own code — building
    // a principal, say — still ends the connection's authority rather than leaving it recorded.
    let cleanup = ConnectionCleanup {
        streams: Arc::clone(&streams),
        windows: Arc::clone(&state.windows),
        connection_id,
        keepalive: None,
        control_reader: None,
        data_accept: None,
        issuing: Arc::clone(&issuing),
        connection: connection.clone(),
    };
    let actor = ConnectionActor::network_device(
        state.handler.principal_for(&authorised.peer_device_id),
        authorised.peer_device_id,
        state.config.controller_generation,
        connection_id,
    );
    let keepalive = tokio::spawn(keepalive_loop(Keepalive {
        sender: control.sender(),
        connection: connection.clone(),
        windows: Arc::clone(&state.windows),
        connection_id,
        epochs: state.config.epochs,
        keepalive: state.config.keepalive,
        window_validity: state.config.action_window_validity,
        issuing: Arc::clone(&issuing),
    }));

    // The connection started with room for one stream, the one the control stream is, and it stays
    // so until the host first reads its data streams: the receiver raises the limit then, and only
    // for a host that names a stream kind. When that is relative to the host's own check of the
    // device is the host's to arrange. A host that names none, or never reads, leaves a device's
    // second stream waiting for credit that does not come, and the accept task below waits for a
    // stream the device cannot open.
    //
    // The streams the device opens are taken here, on a task the guard owns beside the keepalive
    // and the control reader, and never by the host's handler: a handler that is answering a
    // control request must not be what decides whether a stream waits.
    let queue = Handoff::new(DATA_STREAM_QUEUE_DEPTH);
    let data_streams = DataStreams {
        queue: Arc::clone(&queue),
        credit: (!state.config.accepted_kinds.is_empty()).then(|| Credit {
            connection: connection.clone(),
            max_bulk_streams: state.config.send_limits.max_bulk_streams,
            raised: false,
        }),
    };
    // Made here, and not in the task's body: a task that is aborted before its first poll never
    // runs its body, and the receiver would wait for ever.
    let ends = QueueEnds(Arc::clone(&queue));
    let data_accept = tokio::spawn(data_accept_loop(
        ends,
        Arc::clone(&streams),
        connection.clone(),
        state.config.accepted_kinds.clone().into(),
        queue,
    ));

    // The guard now owns the keepalive too, so every way out of this function stops it: a panic in
    // the host's handler, a cancellation of this task, or the connection ending underneath it.
    let mut cleanup = cleanup;
    cleanup.keepalive = Some(keepalive);
    cleanup.control_reader = Some(control_reader);
    cleanup.data_accept = Some(data_accept);

    let session = AuthorisedSession {
        connection: connection.clone(),
        connection_id,
        peer_device_id: authorised.peer_device_id,
        peer_endpoint_id: authorised.peer_endpoint_id,
        transcript_digest: authorised.transcript_digest,
        offer: authorised.offer,
        selection: authorised.selection,
        actor,
        control,
        streams: Arc::clone(&streams),
        data_streams,
        deadlines: Arc::clone(&state.config.deadlines),
        windows: Arc::clone(&state.windows),
        action_window: authorised.action_window,
        clock: Arc::clone(&state.clock),
        authorised_under,
    };
    // The handler is raced against the control stream and against the connection. Whichever ends
    // first ends the session: a control stream that failed, or whose peer closed its send
    // direction, has the consequence section 23 gives it straight away rather than waiting for a
    // handler that may be blocked on a worker.
    let served = Arc::clone(&state.handler).serve(session);
    tokio::select! {
        () = served => {}
        () = lost.happened() => {}
        _ = connection.closed() => {}
    }
    drop(cleanup);
    Ok(())
}

/// Ends a connection's authority whatever way the connection ended.
#[derive(Debug)]
struct ConnectionCleanup {
    streams: Arc<StreamRegistry>,
    windows: Arc<ActionWindowIssuer>,
    connection_id: ConnectionId,
    keepalive: Option<tokio::task::JoinHandle<()>>,
    control_reader: Option<tokio::task::JoinHandle<()>>,
    /// The task that takes the device's data streams, whose header tasks end with it.
    data_accept: Option<tokio::task::JoinHandle<()>>,
    issuing: Arc<std::sync::atomic::AtomicBool>,
    connection: Connection,
}

impl Drop for ConnectionCleanup {
    fn drop(&mut self) {
        // The order matters. Issuance is fenced first, so a keepalive that is between its check and
        // its write cannot leave a window behind; then the task is stopped, the connection closed,
        // the streams revoked and the windows retired.
        self.issuing
            .store(false, std::sync::atomic::Ordering::Release);
        if let Some(keepalive) = self.keepalive.take() {
            keepalive.abort();
        }
        if let Some(control_reader) = self.control_reader.take() {
            control_reader.abort();
        }
        if let Some(data_accept) = self.data_accept.take() {
            data_accept.abort();
        }
        self.connection
            .close(CONTROL_LOST.into(), b"the connection ended");
        self.streams.revoke_all();
        self.windows.retire_connection(self.connection_id);
    }
}

/// Whether one connection's control stream has ended.
///
/// A notification alone would not do: the reader task starts before the supervisor waits, so a
/// stream that ends immediately would fire into an empty room. The flag is the durable half, and a
/// waiter checks it before and after it parks.
///
/// Declaring it also revokes the connection's data streams, at once and on the task that saw the
/// loss, so that a read or a write on one fails now and not when the connection's supervisor next
/// runs. It does not run the host's hook: that waits for the cleanup, which runs once the host's
/// handler has been dropped, so a host that registers the connection while it serves is never
/// asked to withdraw it before it has.
#[derive(Debug)]
struct ControlLoss {
    lost: std::sync::atomic::AtomicBool,
    woken: tokio::sync::Notify,
    streams: Arc<StreamRegistry>,
}

impl ControlLoss {
    fn new(streams: Arc<StreamRegistry>) -> Self {
        Self {
            lost: std::sync::atomic::AtomicBool::new(false),
            woken: tokio::sync::Notify::new(),
            streams,
        }
    }

    fn declare(&self) {
        self.lost.store(true, std::sync::atomic::Ordering::Release);
        self.streams.revoke_streams();
        self.woken.notify_waiters();
    }

    fn has_happened(&self) -> bool {
        self.lost.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Resolves as soon as the control stream has ended, whenever that was.
    async fn happened(&self) {
        loop {
            let waiting = self.woken.notified();
            if self.has_happened() {
                return;
            }
            waiting.await;
            if self.has_happened() {
                return;
            }
        }
    }
}

/// How many control frames the connection holds for a handler that has not read them yet.
///
/// Section 9's rule for a slow peer applies to a slow handler too: it is told, rather than allowed
/// to hold the read loop. A handler this far behind loses its connection.
pub const CONTROL_QUEUE_DEPTH: usize = 64;

/// Reads the control stream for one connection, whatever its handler is doing.
///
/// This is what makes the end of the control stream a fact about the connection rather than about
/// the handler's progress: section 23 gives that end a consequence, and the consequence cannot wait
/// for a handler that is blocked on a worker.
async fn control_read_loop(
    mut reader: FrameReader,
    frames: tokio::sync::mpsc::Sender<ReceivedFrame>,
    connection: Connection,
    lost: Arc<ControlLoss>,
    clock: Arc<dyn ContinuousClock>,
    watch: Arc<dyn FrameWatch>,
    device_id: DeviceId,
) {
    while let Ok(Some(frame)) = reader.read_message::<ControlFrame>().await {
        let hold = watch.frame_read(&device_id, &frame);
        match frames.try_send(ReceivedFrame::read(frame, &*clock, hold)) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                connection.close(CONTROL_LOST.into(), b"the control queue overflowed");
                break;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
        }
    }
    lost.declare();
}

/// Takes every stream the device opens on an authorised connection, until the connection ends.
///
/// The loop does nothing slow itself. It takes a stream from the connection
/// ([`StreamRegistry::accept_pending`], which waits for one of the connection's few places for
/// streams that are waiting for their headers) and gives it to a task of its own that reads the
/// header, so a device that sends half a header holds one place for the header deadline and no
/// more, and the stream behind it is taken meanwhile. A stream that passes admission is queued for
/// the host, and a full queue and a host that is gone both hand it back, which resets it.
///
/// The loop waits in the connection's accept until the host reads, and the device has no credit to
/// open a stream before that: the connection's limit is raised by the host's first read.
///
/// When the host's receiver goes away the loop stops working for it. The tasks reading headers are
/// dropped, which resets each stream they held, and the streams that arrive afterwards are reset
/// as they are accepted, with no header read: what the device opened is never left waiting for a
/// host that has stopped, and nothing the loop held stays for the rest of the connection.
async fn data_accept_loop(
    ends: QueueEnds,
    streams: Arc<StreamRegistry>,
    connection: Connection,
    accepted: Arc<[StreamKind]>,
    queue: Arc<Handoff<Queued>>,
) {
    // Held for the whole of the loop; the future owns it from the moment it is made.
    let _ends = ends;
    // Dropped when the host's receiver goes, which aborts every header read that is still waiting
    // and resets its stream.
    let mut headers = tokio::task::JoinSet::new();
    loop {
        // Header tasks that ended are collected as the next stream arrives, so the set holds the
        // streams still waiting and those that ended since the last one.
        while headers.try_join_next().is_some() {}
        // The receiver's closure is looked at first, so once the loop has seen that the host has
        // gone, no further stream is taken and no header is read for one that arrives at the same
        // moment. A receiver dropped on another thread just after this look, while a stream is
        // ready in the same poll, still lets that one stream into a header task, which the next
        // turn aborts and whose stream is reset.
        let taken = tokio::select! {
            biased;
            () = queue.receiver_closed() => break,
            taken = streams.accept_pending(&connection) => taken,
        };
        match taken {
            Ok(pending) => {
                let accepted = Arc::clone(&accepted);
                let queue = Arc::clone(&queue);
                headers.spawn(async move {
                    match pending.open(&accepted).await {
                        // A stream the queue refuses is handed back inside the error and is reset
                        // as it is dropped.
                        Ok(stream) => {
                            if queue.push(Queued::new(stream)).is_err() {
                                tracing::debug!(
                                    "a data stream was reset: the host is not taking more"
                                );
                            }
                        }
                        Err(error) => tracing::debug!(%error, "a data stream was refused"),
                    }
                });
            }
            // A stream refused at the door, which was reset: the next one is taken as usual.
            Err(TransportError::Handshake(error)) => {
                tracing::debug!(%error, "a data stream was refused");
            }
            // The control stream ended or the connection did.
            Err(_) => return,
        }
    }
    drop(headers);
    loop {
        match streams.accept_pending(&connection).await {
            // Dropping the stream resets it.
            Ok(pending) => drop(pending),
            Err(TransportError::Handshake(error)) => {
                tracing::debug!(%error, "a data stream was refused");
            }
            Err(_) => return,
        }
    }
}

/// The QUIC application error code an unpaired connection is closed with when pairing is not open.
pub const REFUSED_UNPAIRED: u32 = 2;

/// The half of [`HostHandler`] the control stream's reader needs.
trait FrameWatch: Send + Sync {
    fn frame_read(&self, device_id: &DeviceId, frame: &ControlFrame) -> Option<FrameHold>;
}

impl<H: HostHandler> FrameWatch for H {
    fn frame_read(&self, device_id: &DeviceId, frame: &ControlFrame) -> Option<FrameHold> {
        HostHandler::frame_read(self, device_id, frame)
    }
}

/// The half of [`HostHandler`] the stream registry needs.
trait ControlLossListener: Send + Sync + std::fmt::Debug {
    fn control_stream_lost(&self, connection_id: ConnectionId);
}

impl<H: HostHandler> ControlLossListener for H {
    fn control_stream_lost(&self, connection_id: ConnectionId) {
        HostHandler::control_stream_lost(self, connection_id);
    }
}

#[derive(Debug)]
struct HandlerHook {
    handler: Arc<dyn ControlLossListener>,
}

impl RevocationHook for HandlerHook {
    fn control_stream_lost(&self, connection_id: ConnectionId) {
        self.handler.control_stream_lost(connection_id);
    }
}

/// What the keepalive task works from.
#[derive(Debug)]
struct Keepalive {
    sender: ControlSender,
    connection: Connection,
    windows: Arc<ActionWindowIssuer>,
    connection_id: ConnectionId,
    epochs: HostEpochs,
    keepalive: Duration,
    window_validity: Duration,
    issuing: Arc<std::sync::atomic::AtomicBool>,
}

/// Sends a keepalive while the connection is idle and renews the action window before it expires.
///
/// The window is renewed at half its validity, which leaves a full half-window of margin for a
/// slow link. Section 9 calls the renewal explicit, and this is where the host is explicit about
/// it: the client never asks.
async fn keepalive_loop(state: Keepalive) {
    let Keepalive {
        sender,
        connection,
        windows,
        connection_id,
        epochs,
        keepalive,
        window_validity,
        issuing,
    } = state;
    let mut keepalive_timer = tokio::time::interval(keepalive);
    keepalive_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut renewal_timer = tokio::time::interval(window_validity / 2);
    renewal_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick of a tokio interval fires immediately; neither message is wanted at once.
    keepalive_timer.tick().await;
    renewal_timer.tick().await;

    loop {
        let frame = tokio::select! {
            _ = keepalive_timer.tick() => ControlFrame::Event(ControlEvent::Keepalive),
            _ = renewal_timer.tick() => {
                if !issuing.load(std::sync::atomic::Ordering::Acquire) {
                    return;
                }
                match windows.issue(connection_id, epochs.boot_epoch) {
                    Ok(window) => {
                        if !issuing.load(std::sync::atomic::Ordering::Acquire) {
                            // The connection ended while this window was being issued, so it is
                            // retired here rather than left for a retirement that already ran.
                            windows.retire(&window.action_window_id);
                            return;
                        }
                        ControlFrame::Event(ControlEvent::ActionWindowRenewed(window))
                    }
                    Err(error) => {
                        tracing::warn!(%error, "an action window could not be renewed");
                        continue;
                    }
                }
            }
        };
        if sender.send(&frame).await.is_err() {
            // The host can no longer write to this connection, so its control stream has failed
            // whatever the read side is doing. Closing the connection is what makes the handler
            // notice, which is what runs the cleanup.
            connection.close(CONTROL_LOST.into(), b"the control stream failed");
            return;
        }
    }
}

/// The QUIC application error code a connection is closed with when its control stream fails.
pub const CONTROL_LOST: u32 = 3;

/// Returns the principal a paired device acts under, derived from its device identity.
///
/// A host with its own principal scheme uses that instead; this exists so a host that has no
/// reason to invent one does not have to.
#[must_use]
pub fn device_principal(device_id: &DeviceId) -> ActorId {
    ActorId::new(format!(
        "device:{}",
        to_base64url(device_id.get().as_bytes())
    ))
    .expect("a base64url device identity is a valid opaque identifier")
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    #[test]
    fn a_device_principal_names_one_device() {
        let first = device_principal(&DeviceId::new(Uuid::from_bytes([1; 16])));
        let second = device_principal(&DeviceId::new(Uuid::from_bytes([2; 16])));
        assert_ne!(first, second);
        assert!(first.as_str().starts_with("device:"));
    }

    #[test]
    fn the_default_configuration_uses_the_specified_intervals() {
        let config = ListenerConfig::new(
            EndpointConfig::default(),
            HostEpochs {
                boot_epoch: kr_protocol::ids::BootEpoch::new(1),
                clock_epoch: kr_protocol::ids::ClockEpoch::new(1),
            },
            ControllerGeneration::new(1),
        );
        assert_eq!(config.keepalive, Duration::from_secs(10));
        assert_eq!(config.action_window_validity, Duration::from_secs(300));
    }

    /// Counts the values of its kind that were dropped, which is what resetting a stream is.
    #[derive(Debug)]
    struct Counted(Arc<std::sync::atomic::AtomicUsize>);

    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn dropped(counter: &Arc<std::sync::atomic::AtomicUsize>) -> usize {
        counter.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Waits for `step`, or fails naming what never came: a bound that turns a missing wake-up
    /// into a failure, and decides nothing.
    async fn awaited<T>(what: &str, step: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(30), step)
            .await
            .unwrap_or_else(|_| panic!("{what} never came"))
    }

    /// The two orders of a send and the receiver's closing, one after the other. One lock covers
    /// each operation, so these are all the outcomes there are: a send before the closing is taken
    /// by it, and a send after is handed back to the task that made it, and neither leaves the
    /// stream in a queue nobody reads. The lock is what shows that no third order exists; the
    /// two tests show that each of the two is handled.
    #[test]
    fn a_stream_queued_after_the_receiver_is_gone_is_handed_back() {
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let queue = Handoff::new(DATA_STREAM_QUEUE_DEPTH);
        drop(queue.close_receiver());

        let handed_back = queue.push(Counted(Arc::clone(&counter)));
        assert!(
            handed_back.is_err(),
            "a stream was queued for a receiver that is gone"
        );
        assert_eq!(dropped(&counter), 0, "the sender, not the queue, holds it");
        drop(handed_back);
        assert_eq!(dropped(&counter), 1);
    }

    /// Nothing is queued once the sender is done: a header task that finishes after the accept task
    /// ended gets its stream back, and a receiver that has read the end never has an item left
    /// behind it.
    #[test]
    fn a_stream_queued_after_the_sender_is_done_is_handed_back() {
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let queue = Handoff::new(DATA_STREAM_QUEUE_DEPTH);
        queue.finish();

        let handed_back = queue.push(Counted(Arc::clone(&counter)));
        assert!(
            handed_back.is_err(),
            "a stream was queued after the sender was done"
        );
        assert_eq!(dropped(&counter), 0, "the sender, not the queue, holds it");
        drop(handed_back);
        assert_eq!(dropped(&counter), 1);
    }

    /// The receiver reads what was queued before the sender was done, and then the end.
    #[tokio::test]
    async fn the_receiver_reads_what_was_queued_and_then_the_end() {
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let queue = Handoff::new(DATA_STREAM_QUEUE_DEPTH);
        assert!(queue.push(Counted(Arc::clone(&counter))).is_ok());
        queue.finish();

        assert!(
            awaited("the queued item", queue.next()).await.is_some(),
            "a queued item was lost at the end"
        );
        assert!(
            awaited("the end", queue.next()).await.is_none(),
            "the end did not follow the last item"
        );
    }

    /// A receiver that is waiting is woken by an item, and by the end of the sender, and the
    /// sender's task is woken by the receiver's closing.
    #[tokio::test]
    async fn a_waiting_receiver_is_woken_by_an_item_and_by_the_end() {
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let queue = Handoff::new(DATA_STREAM_QUEUE_DEPTH);

        let waiting = tokio::spawn({
            let queue = Arc::clone(&queue);
            async move { (queue.next().await.is_some(), queue.next().await.is_none()) }
        });
        tokio::task::yield_now().await;
        assert!(queue.push(Counted(Arc::clone(&counter))).is_ok());
        tokio::task::yield_now().await;
        queue.finish();
        assert_eq!(
            awaited("the receiver's task", waiting)
                .await
                .expect("the receiver's task"),
            (true, true)
        );

        let closed = tokio::spawn({
            let queue = Arc::clone(&queue);
            async move { queue.receiver_closed().await }
        });
        tokio::task::yield_now().await;
        drop(queue.close_receiver());
        awaited("the sender's wait", closed)
            .await
            .expect("the sender's wait ended");
    }

    /// A stream queued before the receiver's closing is taken by it: closing hands back everything
    /// queued at once, and a full queue refuses what does not fit.
    #[test]
    fn closing_the_receiver_takes_everything_queued_and_leaves_nothing() {
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let queue = Handoff::new(DATA_STREAM_QUEUE_DEPTH);
        for _ in 0..DATA_STREAM_QUEUE_DEPTH {
            assert!(queue.push(Counted(Arc::clone(&counter))).is_ok());
        }
        assert!(
            queue.push(Counted(Arc::clone(&counter))).is_err(),
            "a full queue took one more"
        );
        assert_eq!(
            dropped(&counter),
            1,
            "the stream a full queue refused was kept"
        );

        let taken = queue.close_receiver();
        assert_eq!(taken.len(), DATA_STREAM_QUEUE_DEPTH);
        drop(taken);
        assert_eq!(dropped(&counter), 1 + DATA_STREAM_QUEUE_DEPTH);
        assert!(queue.push(Counted(Arc::clone(&counter))).is_err());
    }
}
