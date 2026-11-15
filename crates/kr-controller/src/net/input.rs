//! Terminal input on a stream of its own: the host's door for it.
//!
//! A device sends typing on a stream that carries nothing else, so a key never waits behind a
//! control request and a control request never waits behind a key. The door admits the stream
//! (the environment, the route, the grant's decision for `input.write`, one live stream for each
//! attachment and a bound on the streams of one connection), opens a second link to the
//! attachment's worker, and carries each frame across it.
//!
//! Two quantities are never mixed. The device's window ([`InputAck::Ready`]) is fixed for the
//! stream's life and counts what the device has written and not had accepted. The host's credit
//! toward the worker is in the worker's own unit ([`input_claim`]), belongs to one lease epoch and
//! comes from the worker's events. A frame is forwarded only within credit, so the worker never has
//! to refuse one for room.
//!
//! Four tasks serve one stream, none of which waits for another's work: the stream task reads
//! frames, decides each one afresh and queues it; the lane writer writes the queue to the worker in
//! the order it was read; the lane reader matches the worker's answers to the frames outstanding,
//! in order, and applies its events; and the acknowledgement writer writes what the device is told.
//!
//! The most the host holds for one stream: the frames read and not yet routed, the one being read
//! included, which are at most [`READ_AHEAD_FRAMES`] of at most 64 KiB; the frames passed on within
//! the worker's credit for one epoch (the window the worker states: 32 frames, 512 KiB of key bytes
//! and about 1 KiB each for the envelope), and, when the lease moves to a new epoch while frames of
//! the older one are still queued for the writer, the same again for each such epoch, which only
//! the other views' takeovers cause; the acknowledgements owed to the device, at most
//! [`MAX_UNREAD_ACKS`] (those for accepted frames coalesce); and the record of the epochs whose
//! first refusal has been told, which is kept for an epoch only while a frame of it is at the host
//! (read and not yet answered or refused) or while it is the newest epoch read, so it holds no more
//! epochs than the frames at the host plus one. A device that does not read what it is told loses
//! the stream when more than the first is owed. The epochs of the frames on one stream never go
//! back: a frame of an epoch lower than the newest one read breaks the stream's order, and the
//! stream is cut. The host reads a frame only while fewer than
//! [`READ_AHEAD_FRAMES`] wait, and a frame waits only for credit. A device's reset is heard in every
//! one of these states; its finish is heard once the frames it wrote have been read.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kr_ipc::client::{LinkReader, LinkWriter};
use kr_ipc::framed::FrameWhile;
use kr_protocol::envelope::{ControlEvent, ControlFrame, Outcome, ParamsValue, Request, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamHeader;
use kr_protocol::ids::{AttachmentId, ConnectionId, InputLeaseEpoch, InputSequence, RequestId};
use kr_protocol::input::{
    InputAck, InputBarrier, InputClaim, InputContent, InputFrame, InputWindow, InputWriteParams,
    input_claim,
};
use kr_protocol::local::{ForwardedRequest, InputLane, InputLaneReady};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64};
use kr_transport::deadlines::DeadlineKind;
use kr_transport::streams::{DataReader, DataWriter, StreamHandle};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;

use super::chunks::DataDoor;
use super::dispatch::RemoteConnection;
use super::proxy::CALL_TIMEOUT;

pub(super) mod barrier;
mod serial;
mod stages;

#[cfg(not(feature = "testing"))]
use stages::InputStages;
use stages::Tally;
#[cfg(feature = "testing")]
pub use stages::{InputStageCounts, InputStages, SerialAnswer};

/// What a worker states when it serves typing on a lane of its own.
pub(crate) const INPUT_LANE_CAPABILITY: &str = "input_lane";

/// How many frames the device may have written and not had accepted.
const CLIENT_WINDOW_FRAMES: u32 = 32;

/// How many encoded bytes the device may have written and not had accepted.
const CLIENT_WINDOW_BYTES: u64 = 512 * 1024;

/// How long a frame has from the moment the host passes it on to the worker's answer. The bound is
/// absolute: waiting for the writer or for room in the socket does not renew it. Each side of the
/// lane enforces it on its own, so that neither depends on the other's timer: the writer asks
/// before every write to the socket and does not write a frame past its deadline (it cuts the
/// stream instead), and the reader cuts the stream when the oldest frame that the worker has not
/// answered passes its deadline. The end is a cut in both, and the device is told nothing of the
/// frame: its outcome stays uncertain. Both read the host's own clock. The writer's time limit
/// ends only the writer's own wait for room in the socket; the reader's timer ends that wait too,
/// by cutting the stream, so neither limit is the only thing that ends it.
const FRAME_DEADLINE: Duration = CALL_TIMEOUT;

/// How many frames the host keeps read and not yet routed: the one that waits for the worker's
/// credit, and one more, read so that a device that finishes its stream while nothing is credited
/// is heard (a reset is heard whatever the room, by the transport's own watch for it). A frame's
/// decision and its deadline are taken when it is routed, not when it
/// is read, and from then on its deadline is not renewed while it waits for the lane's writer or
/// for room in the socket: the decision a frame goes out on is the newest one.
const READ_AHEAD_FRAMES: usize = 2;

/// How many acknowledgements the host keeps for a device that does not read them. A device that
/// leaves more owed than this loses the stream, not its connection. The number is a choice, not a
/// consequence of the device's window: the acknowledgements for accepted frames coalesce and a
/// refusal is told once for each epoch, but the worker's events (the end of a lease, a launch
/// marker) are bounded by nothing the device does, so a device that reads more slowly than the
/// worker writes them can reach the bound too.
const MAX_UNREAD_ACKS: usize = 64;

/// How long a detach waits for the worker's notice that the view's lease ended, which comes on the
/// lane's link while the detach's answer comes on another, before the stream ends.
const DETACH_NOTICE_WAIT: Duration = Duration::from_secs(2);

/// How often an admission waiting for a route looks again, besides when a grant choice changes.
const ROUTE_POLL: Duration = Duration::from_millis(25);

/// The device's window, as `Ready` states it.
fn client_window() -> InputWindow {
    InputWindow {
        frames: CLIENT_WINDOW_FRAMES,
        bytes: U64::new(CLIENT_WINDOW_BYTES),
    }
}

/// What the host knows of one stream, which a position check reads
/// ([`InputStreams::position_not_reached`]).
#[derive(Debug, Default)]
struct Record {
    lease: Lease,
    /// The highest sequence the worker accepted, with its epoch, recorded before the device is
    /// told.
    accepted: Option<(InputLeaseEpoch, u64)>,
}

/// What the host knows of the epoch of the lease the stream's attachment holds.
#[derive(Debug)]
enum Lease {
    /// The worker's own lane tells it: the epoch of the lease the attachment holds now, as the
    /// worker last said, or none while it holds none.
    Told(Option<InputLeaseEpoch>),
    /// A worker with no lane tells nothing of its lease, so the host judges a barrier by what the
    /// worker accepted on this stream and by nothing else: the worker's lease has moved past an
    /// epoch only when the worker has accepted typing of a newer one. What the host has read from
    /// the device, and what the worker refused, move nothing: a refusal does not end the lease.
    NotTold,
}

impl Default for Lease {
    fn default() -> Self {
        Self::Told(None)
    }
}

/// One live stream: how to end it, and what the worker has accepted on it.
#[derive(Debug)]
struct Live {
    handle: StreamHandle,
    record: Mutex<Record>,
    /// Woken when the attachment this stream serves is detached.
    detached: tokio::sync::Notify,
}

impl Live {
    fn lock(&self) -> MutexGuard<'_, Record> {
        self.record.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records that the worker accepted frames of `epoch` through `through`.
    fn accept(&self, epoch: InputLeaseEpoch, through: u64) {
        let mut record = self.lock();
        let newer = match record.accepted {
            None => true,
            Some((held, held_through)) => {
                epoch.get() > held.get() || (epoch == held && through > held_through)
            }
        };
        if newer {
            record.accepted = Some((epoch, through));
        }
    }

    /// Records the epoch of the lease this stream's attachment holds now, or that it holds none.
    fn hold(&self, epoch: Option<InputLeaseEpoch>) {
        self.lock().lease = Lease::Told(epoch);
    }

    /// The highest accepted sequence of `epoch`, when the epoch is the one the record holds.
    fn through(&self, epoch: InputLeaseEpoch) -> Option<u64> {
        match self.lock().accepted {
            Some((held, through)) if held == epoch => Some(through),
            _ => None,
        }
    }

    /// Whether the worker has accepted fewer than `count` frames of `epoch`, when `epoch` is the
    /// epoch of the lease this stream's attachment holds now, or, for a worker that tells nothing
    /// of its lease, when the worker has accepted no typing of a newer epoch. For any other epoch
    /// the answer is no: the worker's lease has moved on, and the worker treats such a barrier as
    /// stale. No frame accepted in the epoch is a count of none. A count that the accepted frames
    /// do not make is short whether more frames may still be accepted or none will be, since the
    /// frames behind a refusal are not sent.
    fn short_of(&self, epoch: InputLeaseEpoch, count: u64) -> bool {
        let record = self.lock();
        let judged = match record.lease {
            Lease::Told(held) => held == Some(epoch),
            Lease::NotTold => record
                .accepted
                .is_none_or(|(newest, _)| epoch.get() >= newest.get()),
        };
        if !judged {
            return false;
        }
        let accepted = match record.accepted {
            Some((held, through)) if held == epoch => through.saturating_add(1),
            _ => 0,
        };
        accepted < count
    }
}

/// One attachment of one connection.
type Key = (ConnectionId, AttachmentId);

/// Why a stream was not given a place.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Refusal {
    /// The stream was revoked before it was registered.
    Revoked,
    /// The connection already holds as many input streams as it may.
    TooMany,
}

/// The streams of typing this host serves, and what each has been given.
#[derive(Debug)]
pub(super) struct InputStreams {
    /// How many streams one connection may hold, which is also what the listener allows its peer
    /// to open.
    max_per_connection: usize,
    live: Mutex<BTreeMap<Key, Arc<Live>>>,
    /// Where a suite stops the streams' stages and what it counts there.
    stages: Arc<InputStages>,
    /// Where a suite has this host connect its input lanes, instead of the worker's own endpoint.
    #[cfg(feature = "testing")]
    lane_endpoint: Mutex<Option<kr_ipc::paths::Endpoint>>,
    /// How many stream tasks have ended, however they ended.
    #[cfg(feature = "testing")]
    tasks_ended: watch::Sender<u64>,
}

impl Default for InputStreams {
    fn default() -> Self {
        Self {
            max_per_connection: kr_transport::listener::DEFAULT_MAX_INPUT_STREAMS,
            live: Mutex::new(BTreeMap::new()),
            stages: Arc::default(),
            #[cfg(feature = "testing")]
            lane_endpoint: Mutex::new(None),
            #[cfg(feature = "testing")]
            tasks_ended: watch::channel(0).0,
        }
    }
}

impl InputStreams {
    /// How many input streams one connection may hold.
    pub(super) const fn max_per_connection(&self) -> usize {
        self.max_per_connection
    }

    /// The answer a suite gives a release, a detach or a launch in place of the worker's.
    pub(super) fn scripted_answer(
        &self,
        mutation: &kr_protocol::envelope::MutationRequest,
    ) -> Option<super::proxy::Forwarded> {
        self.stages.scripted_answer(mutation)
    }

    /// Whether the worker behind `proxy` serves typing on a lane of its own, which it says by
    /// stating [`INPUT_LANE_CAPABILITY`]. This is the one choice between the lane and the serial
    /// adapter ([`serial`]), and between giving a release, a detach or a launch the members that
    /// only such a worker reads and taking them out ([`barrier::params_for_worker`]). A worker is
    /// told apart by what it states and never by its level.
    pub(super) fn serves_lane(&self, proxy: &super::proxy::WorkerProxy) -> bool {
        #[cfg(feature = "testing")]
        if self.scripted_lane().is_some() {
            return true;
        }
        proxy.states(INPUT_LANE_CAPABILITY)
    }

    fn live(&self) -> MutexGuard<'_, BTreeMap<Key, Arc<Live>>> {
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Makes `handle` the stream that serves `attachment` of `connection`, and revokes the stream
    /// it replaces. A stream that is revoked already replaces nothing and is given no place, and a
    /// connection that holds its bound of streams for other attachments is given no further one.
    fn stand(
        self: &Arc<Self>,
        connection: ConnectionId,
        attachment: AttachmentId,
        handle: &StreamHandle,
        lease: Lease,
    ) -> Result<Arc<Standing>, Refusal> {
        let key = (connection, attachment);
        let live = Arc::new(Live {
            handle: handle.clone(),
            record: Mutex::new(Record {
                lease,
                accepted: None,
            }),
            detached: tokio::sync::Notify::new(),
        });
        let mut registry = self.live();
        if handle.is_revoked() {
            return Err(Refusal::Revoked);
        }
        let others = registry
            .keys()
            .filter(|(held, other)| *held == connection && *other != attachment)
            .count();
        if others >= self.max_per_connection {
            return Err(Refusal::TooMany);
        }
        let replaced = registry.insert(key, Arc::clone(&live));
        drop(registry);
        if let Some(older) = replaced {
            older.handle.revoke();
        }
        Ok(Arc::new(Standing {
            registry: Arc::clone(self),
            key,
            live,
        }))
    }

    /// Where a suite holds the release of a connection's link before its streams are revoked.
    pub(super) async fn before_the_revoke(&self) {
        self.stages.before_a_release().await;
    }

    /// Revokes every stream of `connection`: its grant ended.
    pub(super) fn revoke_connection(&self, connection: ConnectionId) {
        let streams: Vec<Arc<Live>> = self
            .live()
            .iter()
            .filter(|((held, _), _)| *held == connection)
            .map(|(_, live)| Arc::clone(live))
            .collect();
        for stream in streams {
            stream.handle.revoke();
        }
    }

    /// Tells the stream that serves `attachment` of `connection` that the connection detached it. It
    /// is called for a detach that took effect or may have, and for no other. The stream waits
    /// [`DETACH_NOTICE_WAIT`] for the worker's notice that the lease ended, if the view held it and
    /// none came yet, writes it to the device, and ends. Only the connection that asked is reached:
    /// a worker detaches a named attachment only for the link that holds it, so no other
    /// connection's stream stands on an attachment this call can remove. A request that names no
    /// attachment is not told to this hook.
    pub(super) fn detached(&self, connection: ConnectionId, attachment: AttachmentId) {
        self.stages.detach_told();
        let streams: Vec<Arc<Live>> = self
            .live()
            .iter()
            .filter(|((held_connection, held), _)| {
                *held_connection == connection && *held == attachment
            })
            .map(|(_, live)| Arc::clone(live))
            .collect();
        for stream in streams {
            stream.detached.notify_one();
        }
    }

    /// Whether the host's own record of the stream that serves the barrier's attachment for
    /// `connection` shows that the typing the barrier names has not all been accepted: the worker
    /// has accepted fewer frames of the barrier's epoch than its count. The answer is no, and the
    /// request is forwarded for the worker to decide, when the stream does not stand (it ended or
    /// never opened), and when the barrier's epoch is one that the worker's lease has moved past.
    /// Which epochs those are depends on what the worker tells the host:
    ///
    /// - A worker that serves a lane tells its lease, and the barrier is judged only when its epoch
    ///   is the epoch of the lease the stream's attachment holds now. For any other epoch the worker
    ///   treats the barrier as stale, and the check is advisory: it saves a forward, and the worker
    ///   checks its own position.
    /// - A worker that serves no lane tells nothing, and the host's check is the only one. A
    ///   barrier is judged unless the worker has accepted typing of a newer epoch on this stream,
    ///   which is what shows its lease has moved on. Nothing else moves that: not typing that the
    ///   host has only read, and not a refusal, which does not end the lease.
    ///
    /// Only the connection that opened the stream is reached, so a barrier names no stream of
    /// another connection. The device is never told anything on its stream by a refusal made here.
    pub(super) fn position_not_reached(
        &self,
        connection: ConnectionId,
        barrier: &InputBarrier,
    ) -> bool {
        let live = self
            .live()
            .get(&(connection, barrier.attachment_id))
            .map(Arc::clone);
        let short = live.is_some_and(|live| live.short_of(barrier.epoch, barrier.count.get()));
        if short {
            self.stages.position_refused();
        }
        short
    }
}

#[cfg(feature = "testing")]
impl InputStreams {
    pub(super) fn use_lane_at(&self, endpoint: kr_ipc::paths::Endpoint) {
        *self
            .lane_endpoint
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(endpoint);
    }

    pub(super) fn use_no_lane(&self) {
        *self
            .lane_endpoint
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }

    pub(super) fn tasks_ended(&self) -> watch::Receiver<u64> {
        self.tasks_ended.subscribe()
    }

    pub(super) fn stages(&self) -> &InputStages {
        &self.stages
    }

    fn scripted_lane(&self) -> Option<kr_ipc::paths::Endpoint> {
        self.lane_endpoint
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Counts the end of a stream task, however the task ended, for a suite to wait for.
#[cfg(feature = "testing")]
struct TaskEnd<'a>(&'a InputStreams);

#[cfg(feature = "testing")]
impl Drop for TaskEnd<'_> {
    fn drop(&mut self) {
        self.0.tasks_ended.send_modify(|ended| *ended += 1);
    }
}

/// One stream's place in the registry, which it keeps until it is let go and gives back only if
/// it is still the stream that serves its attachment.
#[derive(Debug)]
struct Standing {
    registry: Arc<InputStreams>,
    key: Key,
    live: Arc<Live>,
}

impl Drop for Standing {
    fn drop(&mut self) {
        let mut live = self.registry.live();
        if live
            .get(&self.key)
            .is_some_and(|serving| Arc::ptr_eq(serving, &self.live))
        {
            live.remove(&self.key);
        }
    }
}

/// How a stream ends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum End {
    /// What the device is owed is written first, and the stream then finishes.
    Graceful,
    /// The stream is reset now. What was not yet written is lost; the device counts it uncertain.
    Cut,
}

/// The credit the host holds toward the worker, and for which epoch.
#[derive(Clone, Copy, Debug)]
enum Window {
    /// This lane's attachment holds no lease; `known` is the newest epoch the lane has heard of.
    None { known: InputLeaseEpoch },
    /// The lane's attachment holds the lease of `epoch`, and the worker has room for this much of
    /// its typing.
    Holder {
        epoch: InputLeaseEpoch,
        frames: u64,
        bytes: u64,
    },
}

impl Window {
    const fn epoch(self) -> InputLeaseEpoch {
        match self {
            Self::None { known } => known,
            Self::Holder { epoch, .. } => epoch,
        }
    }
}

/// A frame the worker has not yet answered.
#[derive(Debug)]
struct Outstanding {
    request_id: RequestId,
    epoch: InputLeaseEpoch,
    sequence: u64,
    deadline: Instant,
    /// Counts the frame as unanswered for as long as the worker has not answered it.
    _unanswered: Tally,
}

/// A frame read from the stream and not yet routed.
struct Held {
    frame: InputFrame,
    _held: Tally,
}

/// What a frame meets at the lane's current state.
#[derive(Debug, Eq, PartialEq)]
enum Routed {
    /// Within credit for the lane's epoch: the credit is taken, and the frame goes on.
    Forward(Instant),
    /// Of an epoch that is not the lane's now, or at or below the newest epoch that was refused:
    /// the host does not pass it on, it costs the worker nothing, and the device is told once that
    /// its epoch is refused.
    Stale,
    /// Of a newer epoch than the lane has a window for, or without credit for it yet.
    Wait,
}

/// A frame the host has decided and queued for the worker.
struct LaneFrame {
    request_id: RequestId,
    epoch: InputLeaseEpoch,
    sequence: u64,
    deadline: Instant,
    standing: crate::service::FeedStanding,
    frame: ControlFrame,
    /// Counts the frame as unanswered from the moment it is queued.
    unanswered: Tally,
}

/// What the four tasks of one stream share.
struct Flow {
    state: Mutex<State>,
    /// Counts every change of the state, so a task that has looked at it waits for the next.
    version: watch::Sender<u64>,
    live: Arc<Live>,
    attachment: AttachmentId,
    stages: Arc<InputStages>,
}

struct State {
    window: Window,
    outstanding: VecDeque<Outstanding>,
    /// What the device is to be told, in the order it is to be told it.
    acks: VecDeque<InputAck>,
    /// The epochs, as numbers, whose first definite refusal has been told to the device: each epoch
    /// is told once. An epoch is kept here while a frame of it is at the host and while it is the
    /// newest epoch read, and no longer: no frame of an epoch that is neither can come, since the
    /// epochs of the frames on a stream never go back. An older epoch's refusal is told when it
    /// comes, and never moves the cutoff down, so a late answer of an older epoch does not replace
    /// what is known of the newer one.
    refused: BTreeSet<u64>,
    /// The newest epoch whose first refusal was told. No frame of it or of an older epoch goes to
    /// the worker. It is one number kept for the life of the stream, apart from the record.
    cutoff: Option<u64>,
    /// The newest epoch of a frame read from the device. The epochs of the frames on a stream never
    /// go back.
    newest_read: Option<u64>,
    /// How many frames of each epoch the host holds: read, and not yet answered or refused.
    holds: BTreeMap<u64, usize>,
    ended: Option<End>,
    next_request: u64,
    /// The newest epoch of this lane's lease whose end the device has been told. The notice of an
    /// older epoch does not stand for the notice of the epoch the view holds now.
    epoch_ended: Option<InputLeaseEpoch>,
    /// Frames queued for the lane's writer or written and not yet answered.
    in_flight: usize,
    stages: Arc<InputStages>,
}

impl Drop for State {
    fn drop(&mut self) {
        // A stream torn down with frames held or a refusal on record gives them back, so the
        // stages count the streams that stand.
        self.stages
            .stream_torn_down(&self.holds, self.refused.len());
    }
}

impl State {
    /// Queues what the device is to be told, and cuts the stream when more is owed than
    /// [`MAX_UNREAD_ACKS`]. The caller wakes the tasks that wait on the state.
    fn tell(&mut self, ack: InputAck) {
        self.acks.push_back(ack);
        if self.acks.len() > MAX_UNREAD_ACKS {
            self.ended = Some(End::Cut);
        }
    }

    /// Whether no frame of `epoch` is passed on: it is the newest refused epoch, or older than it.
    fn cut_off(&self, epoch: InputLeaseEpoch) -> bool {
        self.cutoff.is_some_and(|newest| epoch.get() <= newest)
    }

    /// Whether the device has been told that `epoch` is refused.
    fn told_refused(&self, epoch: InputLeaseEpoch) -> bool {
        self.refused.contains(&epoch.get())
    }

    /// Takes a frame read from the device into the host's hands, and says whether the stream's
    /// order holds: a frame of an epoch lower than the newest one read does not belong on this
    /// stream, and the stream is cut. The caller wakes the tasks that wait on the state.
    fn read(&mut self, epoch: InputLeaseEpoch) -> bool {
        if self.newest_read.is_some_and(|newest| epoch.get() < newest) {
            return false;
        }
        self.newest_read = Some(epoch.get());
        *self.holds.entry(epoch.get()).or_insert(0) += 1;
        self.stages.frame_taken();
        self.forget();
        true
    }

    /// Lets go of a frame of `epoch` that was answered, refused or discarded. Its epoch's record goes
    /// with the last of its frames, unless the epoch is the newest one read.
    fn resolved(&mut self, epoch: InputLeaseEpoch) {
        if let Some(held) = self.holds.get_mut(&epoch.get()) {
            *held -= 1;
            if *held == 0 {
                self.holds.remove(&epoch.get());
            }
            self.stages.frame_let_go();
        }
        self.forget();
    }

    /// Drops the record of every epoch that has no frame at the host and is older than the newest
    /// epoch read: no frame of it can come.
    fn forget(&mut self) {
        let Self {
            refused,
            holds,
            newest_read,
            stages,
            ..
        } = self;
        let before = refused.len();
        refused.retain(|epoch| {
            newest_read.is_none_or(|newest| *epoch >= newest) || holds.contains_key(epoch)
        });
        stages.records_fell(before - refused.len());
    }

    /// Tells the device the first definite refusal of `epoch` when it has not been told one for that
    /// epoch, and says whether it did. The host may refuse frame `k` of an epoch while frames before
    /// `k` are still in flight, with their answers to come: the refusal names what was accepted so
    /// far, and no later acceptance of that epoch is told. The caller wakes the tasks that wait on
    /// the state.
    fn refuse(
        &mut self,
        live: &Live,
        epoch: InputLeaseEpoch,
        sequence: u64,
        error: ProtocolError,
    ) -> bool {
        if !self.refused.insert(epoch.get()) {
            return false;
        }
        self.stages.record_made();
        self.cutoff = Some(
            self.cutoff
                .map_or(epoch.get(), |newest| newest.max(epoch.get())),
        );
        let accepted_through = live.through(epoch).map(InputSequence::new);
        self.tell(InputAck::Refused {
            epoch,
            sequence: InputSequence::new(sequence),
            accepted_through: Nullable(accepted_through),
            error,
        });
        true
    }
}

impl Flow {
    /// The flow of a stream whose worker's lane answered `ready`, or, with no lane to the worker
    /// (`ready` is none), the flow of the serial adapter: it has no window, since it passes each
    /// frame on in turn and the worker decides it, and the worker tells it nothing of the lease.
    fn new(
        live: Arc<Live>,
        attachment: AttachmentId,
        ready: Option<&InputLaneReady>,
        stages: Arc<InputStages>,
    ) -> Arc<Self> {
        let window = match ready {
            Some(ready) => {
                live.hold(ready.holder.then_some(ready.epoch));
                if ready.holder {
                    Window::Holder {
                        epoch: ready.epoch,
                        frames: u64::from(ready.frames),
                        bytes: ready.bytes.get(),
                    }
                } else {
                    Window::None { known: ready.epoch }
                }
            }
            None => Window::None {
                known: InputLeaseEpoch::new(0),
            },
        };
        let mut acks = VecDeque::new();
        acks.push_back(InputAck::Ready {
            window: client_window(),
        });
        Arc::new(Self {
            state: Mutex::new(State {
                window,
                outstanding: VecDeque::new(),
                acks,
                refused: BTreeSet::new(),
                cutoff: None,
                newest_read: None,
                holds: BTreeMap::new(),
                ended: None,
                next_request: 1,
                epoch_ended: None,
                in_flight: 0,
                stages: Arc::clone(&stages),
            }),
            version: watch::channel(0).0,
            live,
            attachment,
            stages,
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn changed(&self) {
        self.version.send_modify(|version| *version += 1);
    }

    fn subscribe(&self) -> watch::Receiver<u64> {
        self.version.subscribe()
    }

    /// Ends the stream. The first end stands, except that a cut replaces a graceful end.
    fn end(&self, how: End) {
        {
            let mut state = self.lock();
            if state.ended != Some(End::Cut) {
                state.ended = Some(how);
                if how == End::Cut {
                    self.stages.stream_cut();
                }
            }
        }
        self.changed();
    }

    fn ended(&self) -> Option<End> {
        self.lock().ended
    }

    fn next_request_id(&self) -> RequestId {
        let mut state = self.lock();
        let id = state.next_request;
        state.next_request += 1;
        RequestId::new(id)
    }

    /// Decides what a frame of `epoch` that claims `claim` meets, and takes the credit when it
    /// goes on.
    fn route(&self, epoch: InputLeaseEpoch, claim: InputClaim) -> Routed {
        let mut state = self.lock();
        {
            if state.cut_off(epoch) {
                Routed::Stale
            } else {
                match &mut state.window {
                    Window::Holder {
                        epoch: held,
                        frames,
                        bytes,
                    } => {
                        if epoch.get() < held.get() {
                            Routed::Stale
                        } else if epoch.get() > held.get() {
                            Routed::Wait
                        } else if *frames >= claim.frames as u64 && *bytes >= claim.bytes as u64 {
                            *frames -= claim.frames as u64;
                            *bytes -= claim.bytes as u64;
                            Routed::Forward(Instant::now() + self.stages.frame_deadline())
                        } else {
                            Routed::Wait
                        }
                    }
                    Window::None { known } => {
                        if epoch.get() <= known.get() {
                            Routed::Stale
                        } else {
                            Routed::Wait
                        }
                    }
                }
            }
        }
    }

    /// Records the first definite refusal of `epoch`, by the host, and queues the word for the
    /// device. A refusal of an epoch that has one is not recorded again. The refused frame is let
    /// go: it is the host's no longer.
    fn refuse(&self, epoch: InputLeaseEpoch, sequence: u64, error: ProtocolError) {
        let told = {
            let mut state = self.lock();
            let told = state.refuse(&self.live, epoch, sequence, error);
            state.resolved(epoch);
            told
        };
        if told {
            self.changed();
        }
    }

    /// Takes a frame read from the device, and says whether the stream's order holds: a frame of an
    /// epoch lower than the newest one read cuts the stream, as a malformed frame does.
    fn take(&self, epoch: InputLeaseEpoch) -> bool {
        self.lock().read(epoch)
    }

    /// Takes back a frame that was entered as outstanding and was not written.
    fn unsent(&self, request_id: RequestId) {
        let mut state = self.lock();
        if state
            .outstanding
            .back()
            .is_some_and(|last| last.request_id == request_id)
        {
            state.outstanding.pop_back();
            state.in_flight -= 1;
        }
    }

    /// Counts a frame queued for the lane's writer as in flight, until it is answered or taken
    /// back.
    fn queued(&self) {
        self.lock().in_flight += 1;
    }

    /// The deadline of the oldest frame the worker has not answered.
    fn oldest_deadline(&self) -> Option<Instant> {
        self.lock().outstanding.front().map(|front| front.deadline)
    }

    /// Whether every frame passed on has been answered, those still queued for the writer
    /// included.
    fn drained(&self) -> bool {
        self.lock().in_flight == 0
    }

    /// Matches one answer from the worker to the oldest frame outstanding. The worker answers a
    /// lane in order, so an answer for any other frame is a breach.
    fn answer(&self, response: &Response) -> bool {
        {
            let mut state = self.lock();
            let Some(front) = state.outstanding.pop_front() else {
                return false;
            };
            state.in_flight -= 1;
            if front.request_id != response.request_id {
                return false;
            }
            // Once an epoch's first refusal is told the content of the answers still in flight for
            // it is ignored. An older epoch whose refusal has not been told is answered for as any
            // epoch is.
            if !state.told_refused(front.epoch) {
                match &response.outcome {
                    Outcome::Ok(_) => {
                        // Recorded before the device is told.
                        self.live.accept(front.epoch, front.sequence);
                        match state.acks.back_mut() {
                            Some(InputAck::Accepted { epoch, through })
                                if *epoch == front.epoch =>
                            {
                                *through = InputSequence::new(front.sequence);
                            }
                            _ => state.tell(InputAck::Accepted {
                                epoch: front.epoch,
                                through: InputSequence::new(front.sequence),
                            }),
                        }
                    }
                    Outcome::Error(error) if error.code == ErrorCode::OutcomeUnknown => {
                        return false;
                    }
                    Outcome::Error(error) => {
                        state.refuse(&self.live, front.epoch, front.sequence, error.clone());
                    }
                }
            }
            state.resolved(front.epoch);
        }
        self.changed();
        true
    }

    /// Applies one event the worker wrote on the lane. Events of one lane apply in the order they
    /// were written, and an older epoch never replaces a newer one.
    fn event(&self, event: &ControlEvent) {
        {
            let mut state = self.lock();
            match event {
                ControlEvent::InputWindow(window) => {
                    if window.epoch.get() >= state.window.epoch().get() {
                        self.live.hold(window.holder.then_some(window.epoch));
                        state.window = if window.holder {
                            Window::Holder {
                                epoch: window.epoch,
                                frames: u64::from(window.frames),
                                bytes: window.bytes.get(),
                            }
                        } else {
                            Window::None {
                                known: window.epoch,
                            }
                        };
                    }
                    if let Some(ended) = window.ended.0 {
                        if state
                            .epoch_ended
                            .is_none_or(|told| told.get() < ended.epoch.get())
                        {
                            state.epoch_ended = Some(ended.epoch);
                        }
                        state.tell(InputAck::EpochEnded {
                            epoch: ended.epoch,
                            fenced_bytes: ended.fenced_bytes,
                        });
                    }
                }
                ControlEvent::InputCredit(credit) => {
                    if let Window::Holder {
                        epoch,
                        frames,
                        bytes,
                    } = &mut state.window
                        && *epoch == credit.epoch
                    {
                        *frames = frames.saturating_add(u64::from(credit.frames));
                        *bytes = bytes.saturating_add(credit.bytes.get());
                    }
                }
                ControlEvent::InputLaunchReserved(launch)
                    if launch.attachment_id == self.attachment =>
                {
                    state.tell(InputAck::LaunchReserved {
                        launch: launch.launch,
                    });
                }
                _ => {}
            }
        }
        self.changed();
    }
}

/// The word the device is given for a frame of an epoch that is not the lane's.
fn lease_lost() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::LeaseLost,
        "this view no longer holds the lease of the epoch its typing belongs to",
    )
}

/// What an admission gives a stream that is not served.
fn refusal(detail: &'static str) -> ProtocolError {
    ProtocolError::new(ErrorCode::ResourceUnavailable, detail)
}

/// Serves one terminal-input stream until it ends.
pub(super) async fn serve(door: Arc<DataDoor>, mut reader: DataReader, writer: DataWriter) {
    #[cfg(feature = "testing")]
    let _ended = TaskEnd(&door.host.input);
    let handle = reader.handle();
    let header = reader.header().clone();
    let Some(admitted) = admit(&door, &header, &handle).await else {
        handle.revoke();
        return;
    };
    let Admitted {
        session,
        attachment,
        standing,
        carry,
    } = admitted;
    let flow = Flow::new(
        Arc::clone(&standing.live),
        attachment,
        match &carry {
            Carry::Lane { ready, .. } => Some(ready),
            Carry::Serial(_) => None,
        },
        Arc::clone(&door.host.input.stages),
    );
    let (queue, queued) = mpsc::unbounded_channel();
    let mut tasks = JoinSet::new();
    let (acked, acks_flushed) = tokio::sync::oneshot::channel();
    tasks.spawn(end_at_detach(Arc::clone(&flow)));
    tasks.spawn({
        let flow = Arc::clone(&flow);
        async move {
            write_acks(writer, &flow).await;
            let _ = acked.send(());
        }
    });
    match carry {
        Carry::Lane {
            reader: lane_reader,
            writer: lane_writer,
            ..
        } => {
            tasks.spawn(write_lane(
                lane_writer,
                queued,
                Arc::clone(&flow),
                Arc::clone(&door.remote),
            ));
            tasks.spawn(read_lane(lane_reader, Arc::clone(&flow)));
            run(
                &door,
                &mut reader,
                &flow,
                &queue,
                session,
                attachment,
                acks_flushed,
            )
            .await;
        }
        Carry::Serial(proxy) => {
            serial::run(
                &door,
                &mut reader,
                &flow,
                &proxy,
                session,
                attachment,
                acks_flushed,
            )
            .await;
        }
    }
    // A graceful end was waited out inside `run`, with what the device is owed written. A stream
    // that was cut or revoked is reset now.
    if flow.ended() != Some(End::Graceful) {
        handle.revoke();
    }
    drop(standing);
}

/// What a stream is given once it is admitted: how its typing reaches the worker.
struct Admitted {
    session: kr_protocol::ids::SessionId,
    attachment: AttachmentId,
    standing: Arc<Standing>,
    carry: Carry,
}

/// How a stream's typing reaches the worker.
enum Carry {
    /// On a lane of its own, which the worker states it serves and has bound.
    Lane {
        ready: InputLaneReady,
        reader: LinkReader,
        writer: LinkWriter,
    },
    /// Over the link that carries the worker's other requests, one call at a time
    /// ([`serial`]), for a worker that does not state the lane.
    Serial(Arc<super::proxy::WorkerProxy>),
}

/// Admits a stream, in the order of the plan: the environment, the route, the grant's decision for
/// `input.write`, the registry (one stream for each attachment, and a bound for the connection),
/// and the lane to the worker, when the worker serves one. Each step that refuses leaves the
/// stream to be reset with nothing forwarded.
async fn admit(
    door: &Arc<DataDoor>,
    header: &StreamHeader,
    handle: &StreamHandle,
) -> Option<Admitted> {
    if header.resource.environment_id != door.remote.environment_id() {
        return None;
    }
    let (Some(session), Some(attachment)) = (
        header.resource.session_id.0,
        header.resource.attachment_id.0,
    ) else {
        return None;
    };
    let mut deadline = door.deadlines.start(DeadlineKind::Admission);
    // The route is fixed before the attach is dispatched, so a device that opens its stream after
    // the attach's answer finds it fixed; one that opens earlier waits for the admission deadline.
    let proxy = tokio::select! {
        proxy = until_routed(&door.remote, session) => proxy?,
        () = &mut deadline => return None,
    };
    door.remote.decide_an_input_frame(session).await.ok()?;
    // The record of the stream is made with the rule that judges a barrier for this worker, so no
    // request is read against a record that does not have it.
    let serves_lane = door.host.input.serves_lane(&proxy);
    let standing = door
        .host
        .input
        .stand(
            door.remote.connection_id(),
            attachment,
            handle,
            if serves_lane {
                Lease::default()
            } else {
                Lease::NotTold
            },
        )
        .ok()?;
    let carry = if serves_lane {
        let lane = InputLane {
            proxy_connection: proxy.connection_id(),
            attachment_id: attachment,
        };
        let (reader, writer, ready) = tokio::select! {
            opened = open_lane(door, &proxy, lane) => opened?,
            () = &mut deadline => return None,
        };
        Carry::Lane {
            ready,
            reader,
            writer,
        }
    } else {
        Carry::Serial(proxy)
    };
    if handle.is_revoked() {
        return None;
    }
    Some(Admitted {
        session,
        attachment,
        standing,
        carry,
    })
}

/// Waits until this connection's route is fixed, and returns the link to the worker when the
/// route is for `session`. A route for another session is no route for this stream.
async fn until_routed(
    remote: &Arc<RemoteConnection>,
    session: kr_protocol::ids::SessionId,
) -> Option<Arc<super::proxy::WorkerProxy>> {
    loop {
        if let Some((fixed, proxy)) = remote.fixed_input_route().await {
            return (fixed == session).then_some(proxy);
        }
        tokio::select! {
            () = remote.until_the_route_may_have_changed() => {}
            () = tokio::time::sleep(ROUTE_POLL) => {}
        }
    }
}

/// Opens the lane of a worker that serves one and binds it: the worker answers with the epoch the
/// lane starts in.
async fn open_lane(
    door: &Arc<DataDoor>,
    proxy: &Arc<super::proxy::WorkerProxy>,
    lane: InputLane,
) -> Option<(LinkReader, LinkWriter, InputLaneReady)> {
    #[cfg(feature = "testing")]
    if let Some(endpoint) = door.host.input.scripted_lane() {
        let connection = kr_ipc::endpoint::Connection::connect(&endpoint)
            .await
            .ok()?;
        let (reader, writer) =
            kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
        return bind(
            LinkReader::over(proxy.level(), reader),
            LinkWriter::over(proxy.level(), writer),
            lane,
        )
        .await;
    }
    let (reader, writer, _level) = door
        .remote
        .controller()
        .open_input_lane(proxy.session_id(), door.remote.receive_limits())
        .await
        .ok()?;
    bind(reader, writer, lane).await
}

/// Names the attachment the lane carries typing for, and reads the worker's answer.
async fn bind(
    mut reader: LinkReader,
    mut writer: LinkWriter,
    lane: InputLane,
) -> Option<(LinkReader, LinkWriter, InputLaneReady)> {
    writer.write(&ControlFrame::InputLane(lane)).await.ok()?;
    match reader.read().await.ok()? {
        ControlFrame::InputLaneReady(ready) => Some((reader, writer, ready)),
        _ => None,
    }
}

/// Reads the stream and routes each frame: forward it within credit, refuse it for a stale epoch,
/// or hold it until the worker's window for its epoch arrives. Returns when the stream ends.
///
/// A read that is dropped part way resets the stream, so one read is kept pending across the
/// loop's waits and is never raced away. For the same reason a stream that the host ends by its own
/// decision keeps that read until `acks_flushed` says that what the device is owed has been written
/// and the stream's writing half has finished: letting the read go sooner would reset the stream
/// under the last acknowledgement.
async fn run(
    door: &Arc<DataDoor>,
    reader: &mut DataReader,
    flow: &Arc<Flow>,
    queue: &mpsc::UnboundedSender<LaneFrame>,
    session: kr_protocol::ids::SessionId,
    attachment: AttachmentId,
    acks_flushed: tokio::sync::oneshot::Receiver<()>,
) {
    let handle = reader.handle();
    let mut version = flow.subscribe();
    // Declared before the pending read, so it is dropped after it.
    let _let_go = ReadLetGo(&flow.stages);
    // Whether the host has room for another frame. The pending read takes data only while it
    // does, and watches for the device's reset while it does not.
    let (room, mut room_rx) = watch::channel(false);
    let mut next = Box::pin(reader.read_message_when::<InputFrame>(&mut room_rx));
    // Frames read and not yet routed, at most [`READ_AHEAD_FRAMES`].
    let mut held: VecDeque<Held> = VecDeque::new();
    let mut reading = true;
    let mut finished = false;
    loop {
        // Marked before the state is looked at, the end included, so a change after the look is
        // never missed.
        version.borrow_and_update();
        flow.stages.after_the_version_mark().await;
        if flow.ended().is_some() || handle.is_revoked() {
            break;
        }
        if let Some(front) = held.front() {
            let claim = input_claim(front.frame.bytes.len());
            match flow.route(front.frame.epoch, claim) {
                Routed::Forward(deadline) => {
                    if let Some(Held { frame, .. }) = held.pop_front() {
                        forward(door, flow, queue, session, attachment, frame, deadline).await;
                    }
                    continue;
                }
                Routed::Stale => {
                    if let Some(Held { frame, .. }) = held.pop_front() {
                        flow.refuse(frame.epoch, frame.sequence.get(), lease_lost());
                    }
                    continue;
                }
                Routed::Wait => {}
            }
        }
        // Reading goes on while fewer than [`READ_AHEAD_FRAMES`] frames wait.
        let may_read = !finished && held.len() < READ_AHEAD_FRAMES;
        if may_read && reading {
            flow.stages.before_a_read().await;
        } else if !finished && reading {
            flow.stages.read_is_full();
        }
        if finished && held.is_empty() && flow.drained() {
            // The device is done and what it wrote is answered: the stream finishes.
            flow.end(End::Graceful);
            break;
        }
        if finished {
            flow.stages.waits_to_drain();
        }
        room.send_replace(may_read);
        tokio::select! {
            _ = version.changed() => {}
            read = &mut next, if reading => {
                match read {
                    Ok(Some(frame)) => {
                        flow.stages.frame_read();
                        if !flow.take(frame.epoch) {
                            // The epochs of the frames on a stream never go back: this one is
                            // not an honest device's, and the stream is cut as for a malformed
                            // frame.
                            flow.end(End::Cut);
                            return;
                        }
                        held.push_back(Held {
                            frame,
                            _held: flow.stages.held_frame(),
                        });
                        // No room is said for the next read until the loop has looked at the
                        // state again.
                        room.send_replace(false);
                        drop(next);
                        next = Box::pin(reader.read_message_when::<InputFrame>(&mut room_rx));
                    }
                    Ok(None) => {
                        finished = true;
                        reading = false;
                    }
                    Err(_) => {
                        flow.end(End::Cut);
                        return;
                    }
                }
            }
            () = handle.revoked() => return,
        }
    }
    if flow.ended() == Some(End::Graceful) {
        // The stream task has read all it will. What the device is owed is written, and the
        // writing half finishes, before the pending read is let go. A write that the device does
        // not read is cut by the write deadline, which ends the wait.
        flow.stages.read_ends();
        let _ = acks_flushed.await;
    }
}

/// Counts, when it is dropped, that a stream task has let go of its read.
struct ReadLetGo<'a>(&'a InputStages);

impl Drop for ReadLetGo<'_> {
    fn drop(&mut self) {
        self.0.read_ends();
    }
}

/// The `input.write` request that carries one frame to the worker.
fn write_request(
    request_id: RequestId,
    session: kr_protocol::ids::SessionId,
    attachment: AttachmentId,
    frame: InputFrame,
) -> Option<Request> {
    let params = InputWriteParams {
        session_id: session,
        attachment_id: attachment,
        epoch: frame.epoch,
        sequence: frame.sequence,
        input: InputContent::Bytes { bytes: frame.bytes },
    };
    let params = ParamsValue::from_typed(&params).ok()?;
    let entry = Method::InputWrite.entry();
    Some(Request {
        request_id,
        method: Method::InputWrite.into(),
        method_version: entry.version,
        params,
    })
}

/// Decides one frame afresh, as a key is decided, and queues it for the lane's writer.
async fn forward(
    door: &Arc<DataDoor>,
    flow: &Arc<Flow>,
    queue: &mpsc::UnboundedSender<LaneFrame>,
    session: kr_protocol::ids::SessionId,
    attachment: AttachmentId,
    frame: InputFrame,
    deadline: Instant,
) {
    let epoch = frame.epoch;
    let sequence = frame.sequence.get();
    let decision = match door.remote.decide_an_input_frame(session).await {
        Ok(decision) => decision,
        Err(error) => {
            flow.refuse(epoch, sequence, error);
            return;
        }
    };
    let request_id = flow.next_request_id();
    let Some(request) = write_request(request_id, session, attachment, frame) else {
        flow.refuse(epoch, sequence, refusal("this typing could not be encoded"));
        return;
    };
    let frame = ControlFrame::ForwardedRead(Box::new(ForwardedRequest {
        request,
        actor: decision.actor,
        authority_deadline_boot_ms: decision.authority_deadline,
        history: None,
    }));
    flow.queued();
    let _ = queue.send(LaneFrame {
        request_id,
        epoch,
        sequence,
        deadline,
        standing: decision.standing,
        frame,
        unanswered: flow.stages.unanswered_frame(),
    });
}

/// Writes the queue to the worker in the order the stream task read it, one frame at a time. The
/// stream's end, the frame's deadline and the authority feed are asked, in that order,
/// immediately before each socket write, which a decision taken before a wait for the socket does
/// not replace, and a frame keeps the deadline it was given.
async fn write_lane(
    mut writer: LinkWriter,
    mut queued: mpsc::UnboundedReceiver<LaneFrame>,
    flow: Arc<Flow>,
    remote: Arc<RemoteConnection>,
) {
    let mut version = flow.subscribe();
    loop {
        version.borrow_and_update();
        if flow.ended().is_some() {
            return;
        }
        let item = tokio::select! {
            item = queued.recv() => match item {
                Some(item) => item,
                None => return,
            },
            _ = version.changed() => {
                if flow.ended().is_some() {
                    return;
                }
                continue;
            }
        };
        if flow.ended().is_some() {
            return;
        }
        flow.stages.before_a_frame_is_judged().await;
        let discarded = {
            let mut state = flow.lock();
            // Behind a refusal of its epoch or a newer one: not passed on, and its epoch is told
            // refused if it has not been.
            if state.cut_off(item.epoch) {
                state.in_flight -= 1;
                state.refuse(&flow.live, item.epoch, item.sequence, lease_lost());
                state.resolved(item.epoch);
                true
            } else {
                state.outstanding.push_back(Outstanding {
                    request_id: item.request_id,
                    epoch: item.epoch,
                    sequence: item.sequence,
                    deadline: item.deadline,
                    _unanswered: item.unanswered,
                });
                false
            }
        };
        // A frame that is discarded leaves nothing in flight, which a stream task that waits for
        // the stream to drain is woken to see.
        flow.changed();
        if discarded {
            continue;
        }
        flow.stages.before_a_lane_write().await;
        // Whether the stream's end was decided, and whether the frame's deadline passed, before a
        // write to the socket that was about to be made. A frame is not given to the worker once
        // the stream has ended, whatever it waited for: the end stands as it was decided, and the
        // device's frame is left with no word of its own, as uncertain. A frame past its deadline
        // is not given to the worker either, and its end is a cut and never a refusal: the
        // device's frame may be answered or not, and it is told nothing of it.
        let mut stopped = false;
        let mut expired = false;
        let written = tokio::time::timeout_at(
            item.deadline,
            writer.write_while(&item.frame, || {
                if flow.ended().is_some() {
                    stopped = true;
                    return false;
                }
                if tokio::time::Instant::now() >= item.deadline {
                    expired = true;
                    return false;
                }
                remote.feed_admits(&item.standing)
            }),
        )
        .await;
        if stopped {
            flow.unsent(item.request_id);
            flow.changed();
            return;
        }
        if expired {
            flow.end(End::Cut);
            return;
        }
        match written {
            Ok(Ok(FrameWhile::Sent)) => {}
            Ok(Ok(FrameWhile::Withdrawn)) => {
                // The worker has none of the frame: it is refused, and the stream ends once the
                // device has been told.
                flow.unsent(item.request_id);
                flow.refuse(
                    item.epoch,
                    item.sequence,
                    ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "the authority behind this typing was withdrawn",
                    ),
                );
                flow.end(End::Graceful);
                return;
            }
            Ok(Ok(FrameWhile::Cut) | Err(_)) | Err(_) => {
                flow.end(End::Cut);
                return;
            }
        }
    }
}

/// Reads the worker's side of the lane: an answer is matched to the oldest frame outstanding, and
/// an event is applied. A worker that does not answer the oldest frame by its deadline, an answer
/// for no frame and a frame of any other kind end the stream.
async fn read_lane(mut reader: LinkReader, flow: Arc<Flow>) {
    let mut version = flow.subscribe();
    loop {
        version.borrow_and_update();
        if flow.ended() == Some(End::Cut) {
            return;
        }
        let due = flow.oldest_deadline();
        let read = tokio::select! {
            read = reader.read() => read,
            _ = version.changed() => {
                if flow.ended() == Some(End::Cut) {
                    return;
                }
                continue;
            }
            () = async {
                match due {
                    Some(due) => tokio::time::sleep_until(due).await,
                    None => std::future::pending().await,
                }
            } => {
                flow.end(End::Cut);
                return;
            }
        };
        if read.is_ok() {
            flow.stages.before_a_lane_answer().await;
        }
        match read {
            Ok(ControlFrame::Response(response)) => {
                if !flow.answer(&response) {
                    flow.end(End::Cut);
                    return;
                }
            }
            Ok(ControlFrame::Event(event)) => flow.event(&event),
            _ => {
                flow.end(End::Cut);
                return;
            }
        }
    }
}

/// Ends the stream when its attachment is detached: the worker's notice that the view's lease ended
/// is waited for, for [`DETACH_NOTICE_WAIT`], when the view held the lease and none came, so the
/// device is told before the stream finishes.
async fn end_at_detach(flow: Arc<Flow>) {
    flow.live.detached.notified().await;
    let mut version = flow.subscribe();
    let wait = async {
        loop {
            version.borrow_and_update();
            {
                let state = flow.lock();
                let Window::Holder { epoch: held, .. } = state.window else {
                    return;
                };
                if state.ended.is_some()
                    || state
                        .epoch_ended
                        .is_some_and(|told| told.get() >= held.get())
                {
                    return;
                }
            }
            if version.changed().await.is_err() {
                return;
            }
        }
    };
    let _ = tokio::time::timeout(DETACH_NOTICE_WAIT, wait).await;
    flow.end(End::Graceful);
    flow.stages.detach_end_asked();
}

/// Writes what the device is told, in order. It never blocks the stream task or the lane, and a
/// device that does not read what it is told is cut by the stream's write deadline: it loses the
/// stream, not the connection.
async fn write_acks(mut writer: DataWriter, flow: &Arc<Flow>) {
    let mut version = flow.subscribe();
    loop {
        version.borrow_and_update();
        let (next, ended) = {
            let mut state = flow.lock();
            (state.acks.pop_front(), state.ended)
        };
        if let Some(ack) = next {
            flow.stages.before_an_ack_write().await;
            if ended == Some(End::Cut) || writer.write_message(&ack).await.is_err() {
                flow.end(End::Cut);
                // Revoked before the writer is dropped: a dropped writer finishes the stream, and a
                // cut that the device read as a finish would tell it that nothing is owed.
                writer.handle().revoke();
                return;
            }
            continue;
        }
        match ended {
            // Everything owed was written when the state was looked at, and finishing the stream is
            // dropping its writer. Whether the stream is finished or reset is decided again under
            // the state's lock, with the writer let go while the lock is held: a cut decided before
            // that is a reset, and one decided after it comes to a stream that has already
            // finished with nothing owed.
            Some(End::Graceful) => {
                flow.stages.after_a_graceful_look().await;
                let state = flow.lock();
                match state.ended {
                    Some(End::Graceful) if state.acks.is_empty() => {
                        drop(writer);
                        return;
                    }
                    Some(End::Cut) => {
                        writer.handle().revoke();
                        return;
                    }
                    // Something more is owed: it is written first.
                    _ => continue,
                }
            }
            Some(End::Cut) => {
                writer.handle().revoke();
                return;
            }
            None => {}
        }
        if version.changed().await.is_err() {
            return;
        }
    }
}
