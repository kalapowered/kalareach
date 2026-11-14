//! The input lane: where one attachment's typing travels, and what becomes of it.
//!
//! Terminal input has a stream of its own. A paired host takes it on a data stream of kind
//! `terminal_input`, one for each attachment, opened once the attachment exists and kept for its
//! life; a host on this machine takes the same typing as ordered `input.write` requests on the
//! connection that attached. [`Session::input_lane`] opens the lane for either, and everything above
//! it is the same.
//!
//! The lane owns the sequence. A caller hands it bytes and learns at once whether they were
//! admitted: [`InputLane::try_send`] takes the next sequence of the lease epoch only for a frame it
//! admits, so a frame it refuses leaves no gap, and the sequences of an epoch are contiguous from 0.
//! Nothing here blocks: a frame waits in the lane's queue until the stream has room, and the lane
//! tells the caller what became of it through [`InputEvent`]s.
//!
//! # The bound
//!
//! At most the host's window of frames and encoded bytes is written to the stream and not yet
//! accepted. The frames that wait behind them, the frames written and not yet accepted, and the
//! frames held for a launch are bounded together by [`MAX_LOCAL_INPUT_FRAMES`] and
//! [`MAX_LOCAL_INPUT_BYTES`]. At the bound [`InputLane::try_send`] refuses with
//! [`InputRefusal::Full`], and nothing already admitted is dropped.
//!
//! # What a caller learns
//!
//! The host accepts frames and says so in order: acceptance is cumulative, and it is never delivery.
//! Four sets say where every frame of the current epoch stands ([`Sets`]): accepted by the
//! session, refused, uncertain (written, neither accepted nor refused) and unsent (never written).
//! The lane reports facts and counts. It writes no sentence for a person.
//!
//! # Order against other requests
//!
//! A request that must come after some typing (a release, a detach, a launch) takes a
//! [`InputLane::mark`]: the first `count` frames of the epoch, counted over every frame admitted,
//! the ones still in the queue included. The lane tells the caller when the host has accepted that
//! many ([`InputEvent::Reached`]) and when it has not and cannot ([`InputEvent::NotReached`]), and
//! the caller then sends its request with the barrier. A launch also starts a hold: later frames wait
//! unsequenced until the worker says it has dealt with the launch, or the caller says so, or the hold
//! ends.
//!
//! # The hold's endings
//!
//! The hold ends at the first of: the worker's marker for the launch, the caller's
//! [`InputLane::release_hold`], the caller's [`InputLane::discard_held`], the host's notice that the
//! epoch ended, a refusal, a new epoch, the stream's end, and the mark of a release or a detach. An
//! ending the caller did not ask for counts the held frames as unsent, and after any ending nothing
//! is released: the keys that were held are never written, least of all under another epoch.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::{FRAME_LENGTH_PREFIX_LEN, StreamHeader, StreamKind, StreamResource};
use kr_protocol::ids::{AttachmentId, EnvironmentId, InputLeaseEpoch, InputSequence, SessionId};
use kr_protocol::input::{
    INPUT_FRAME_OVERHEAD, InputAck, InputBarrier, InputContent, InputFrame, InputWindow,
    InputWriteParams, max_input_bytes,
};
use kr_protocol::limits::MAX_INPUT_FRAME_LEN;
use kr_protocol::method::Method;
use kr_protocol::scalars::{Bytes, Nullable, U64};
use kr_protocol::transfer::{TransferStreamsParams, TransferStreamsResult};
use kr_transport::TransportError;
use kr_transport::deadlines::{DeadlineKind, Deadlines, TimerDeadlines};
use kr_transport::scheduler::StreamBudget;
use kr_transport::streams::{DataReader, DataWriter, StreamHandle};
use tokio::sync::{Notify, mpsc, watch};

use crate::error::{ClientError, Result};
use crate::session::{ConnectionWatch, LaneSupport, LocalInput, Session};
use crate::shown::Shown;

/// How long the open of the stream and the wait for the host's first word may take.
pub const INPUT_OPEN_WAIT: Duration = Duration::from_secs(10);

/// How long the lane waits for the host to accept the frames before a barrier, before it says the
/// barrier was not reached.
pub const BARRIER_WAIT: Duration = Duration::from_secs(2);

/// The most frames the lane holds that the host has not accepted: queued, written and held.
pub const MAX_LOCAL_INPUT_FRAMES: usize = 1_024;

/// The most encoded bytes of those frames, each counted at its widest.
pub const MAX_LOCAL_INPUT_BYTES: usize = 256 * 1024;

/// The most ordered requests a local lane queues behind its typing.
const MAX_ORDERED_WORK: usize = 64;

/// The most notices of an epoch's end that the lane keeps for epochs it has not begun yet.
const MAX_EARLY_ENDS: usize = 8;

/// What a paste's framing begins and ends with. A cut never falls inside either.
const PASTE_START: &[u8] = b"\x1b[200~";
const PASTE_END: &[u8] = b"\x1b[201~";

/// The refusal a host that takes no input stream is told.
const NO_INPUT_STREAM: &str = "This host cannot take typing on a stream of its own.";

/// The bounds a lane waits under: the open is the stream's header phase, and a barrier's wait is the
/// admission phase, which no input stream of the client's has any other use for.
fn lane_bounds() -> TimerDeadlines {
    TimerDeadlines {
        header: INPUT_OPEN_WAIT,
        admission: BARRIER_WAIT,
        ..TimerDeadlines::default()
    }
}

/// What an input lane is for: the attachment whose typing it carries, and the bounds it waits
/// under.
#[derive(Clone)]
pub struct InputTarget {
    /// The environment the session belongs to.
    pub environment_id: EnvironmentId,
    /// The session.
    pub session_id: SessionId,
    /// The attachment that types.
    pub attachment_id: AttachmentId,
    bounds: Arc<dyn Deadlines>,
    worker_states_input_lane: bool,
}

impl InputTarget {
    /// A target with the shipped bounds.
    #[must_use]
    pub fn new(
        environment_id: EnvironmentId,
        session_id: SessionId,
        attachment_id: AttachmentId,
    ) -> Self {
        Self {
            environment_id,
            session_id,
            attachment_id,
            bounds: Arc::new(lane_bounds()),
            worker_states_input_lane: false,
        }
    }

    /// Takes the lane's waits from `bounds`: the open under [`DeadlineKind::Header`] and a barrier's
    /// wait under [`DeadlineKind::Admission`].
    #[must_use]
    pub fn bounded_by(mut self, bounds: Arc<dyn Deadlines>) -> Self {
        self.bounds = bounds;
        self
    }

    /// Says that the worker behind a local connection states the input lane. The caller read that
    /// from the worker's own hello. A local lane asks for the count of discarded bytes only of a
    /// worker that does ([`InputLane::fenced_report`]).
    #[must_use]
    pub const fn worker_states_input_lane(mut self, states: bool) -> Self {
        self.worker_states_input_lane = states;
        self
    }
}

crate::debug_as_name!(InputTarget);

/// A number of frames and the key bytes in them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Count {
    /// Frames.
    pub frames: u64,
    /// Key bytes: what a person typed, without the frames' framing.
    pub bytes: u64,
}

impl Count {
    fn of(bytes: usize) -> Self {
        Self {
            frames: 1,
            bytes: bytes as u64,
        }
    }

    fn add(&mut self, other: Self) {
        self.frames += other.frames;
        self.bytes += other.bytes;
    }

    /// Whether no frame is counted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.frames == 0
    }
}

/// Where every frame of one lease epoch stands.
///
/// The four sets are exact: each frame is in one of them. A frame the host accepted is in
/// `accepted`, and acceptance does not say the program read it. `refused` holds the first refused
/// frame and every later frame of the epoch. `uncertain` holds what was written and is neither
/// accepted nor refused, which may have arrived. `unsent` holds what was never written, the frames
/// held for a launch included.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sets {
    /// Accepted by the session.
    pub accepted: Count,
    /// Refused.
    pub refused: Count,
    /// Written, neither accepted nor refused.
    pub uncertain: Count,
    /// Never written.
    pub unsent: Count,
}

/// A frame the lane admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Writing {
    /// The lease epoch the frame belongs to.
    pub epoch: InputLeaseEpoch,
    /// The frame's sequence. None while the frame is held: a held frame takes its sequence when the
    /// hold releases it.
    pub sequence: Option<InputSequence>,
    /// Key bytes in the frame.
    pub bytes: usize,
}

/// Why the lane did not take what it was given, or did not do what it was asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputRefusal {
    /// The lane's bound is reached: nothing was admitted and no sequence was used.
    Full,
    /// A paste that would fit an empty lane but not the room that is free now.
    NotNow,
    /// Bytes that no empty lane takes: a frame above the negotiated limit, or a paste above what an
    /// empty lane admits ([`InputLane::paste_capacity`]).
    TooLarge,
    /// Nothing to send.
    Empty,
    /// No epoch has begun.
    NoEpoch,
    /// The epoch is over, or the lane is: it takes nothing more until a new epoch begins.
    Over(Over),
    /// A release or a detach has taken its barrier, so the epoch takes no more typing.
    Ending,
    /// A launch already has its hold.
    LaunchWaiting,
    /// A new epoch must have a higher number than the one the lane has.
    EpochNotNew,
    /// The call is for a local lane.
    NotLocal,
}

impl std::fmt::Display for InputRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Full => "the input lane is full",
            Self::NotNow => "the paste fits an empty input lane but not the room that is free now",
            Self::TooLarge => "the input does not fit the input lane",
            Self::Empty => "there is no input to send",
            Self::NoEpoch => "no input lease epoch has begun on this lane",
            Self::Over(_) => "the input epoch is over",
            Self::Ending => "the epoch is ending and takes no more input",
            Self::LaunchWaiting => "a launch is already waiting",
            Self::EpochNotNew => "an epoch must be higher than the one the lane has",
            Self::NotLocal => "ordered requests are for a local lane",
        })
    }
}

impl std::error::Error for InputRefusal {}

/// How an epoch ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Over {
    /// The host refused a frame, and refuses every later frame of the epoch.
    Refused,
    /// The host said the view no longer holds the lease.
    LeaseEnded,
    /// A new epoch began.
    Superseded,
    /// The lane's stream or connection ended.
    StreamEnded,
}

/// Why a barrier was not reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotReached {
    /// The host refused a frame before the barrier.
    Refused,
    /// The epoch ended.
    EpochEnded,
    /// A new epoch began.
    Superseded,
    /// The stream or the connection ended.
    StreamEnded,
    /// The host did not accept the frames within [`BARRIER_WAIT`].
    Timeout,
}

/// Why the lane ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndCause {
    /// The stream was reset, or failed, while the connection stood.
    Reset,
    /// The host finished its side of the stream.
    Finished,
    /// The connection ended. `refusal` is what the host refused the connection with when it was the
    /// host that ended it, which is how a host that withdrew the connection ends it.
    Connection {
        /// The host's refusal of the connection, when it gave one.
        refusal: Option<ProtocolError>,
    },
    /// The host broke the stream's contract, and the lane reset the stream.
    Breach(&'static str),
    /// A local host answered a write with an outcome that does not say whether it was accepted.
    Uncertain(ProtocolError),
    /// The holder dropped the lane.
    Closed,
}

/// What the lane tells its holder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputEvent {
    /// The host accepted frames: every frame of `epoch` up to `through`. `frames` and `bytes` are
    /// what this notice added.
    Accepted {
        /// The epoch.
        epoch: InputLeaseEpoch,
        /// The last accepted sequence.
        through: InputSequence,
        /// Frames this notice newly accepted.
        frames: u64,
        /// Key bytes of those frames.
        bytes: u64,
    },
    /// The host refused a frame, and with it every later frame of the epoch: the epoch is over.
    Refused {
        /// The epoch.
        epoch: InputLeaseEpoch,
        /// The refused frame.
        sequence: InputSequence,
        /// The last sequence accepted before it.
        accepted_through: Option<InputSequence>,
        /// The host's reason.
        error: ProtocolError,
        /// Where the epoch's frames stand.
        sets: Sets,
    },
    /// The host has accepted every frame of the barrier's prefix.
    Reached(InputBarrier),
    /// The host has not accepted them, and the lane will not wait longer for them.
    NotReached {
        /// The barrier.
        barrier: InputBarrier,
        /// Why.
        reason: NotReached,
    },
    /// The worker has dealt with the launch numbered `launch`: later typing is now ordered by its own
    /// fence, or there is nothing left to order. It says nothing of the launch's result.
    LaunchReserved {
        /// The launch.
        launch: u32,
        /// The frames the notice released from the hold: none when the hold was already over or was
        /// held for another launch.
        released: Count,
    },
    /// The host says the view no longer holds the lease of `epoch`, which another view took, the view
    /// released, or a grant's end took. It is not given for an epoch the view itself ended by a
    /// release or a detach.
    EpochEnded {
        /// The epoch.
        epoch: InputLeaseEpoch,
        /// The bytes the end discarded, accepted ones the worker had not written included.
        fenced_bytes: u64,
        /// Where the epoch's frames stand.
        sets: Sets,
    },
    /// The lane has ended, and takes nothing more.
    Ended {
        /// The epoch that was current, when one had begun.
        epoch: Option<InputLeaseEpoch>,
        /// Why.
        cause: EndCause,
        /// Where that epoch's frames stand: for an epoch that was already over, as they stood then.
        sets: Sets,
    },
}

/// The events of one lane, in the order they happened.
#[derive(Debug)]
pub struct InputEvents {
    receiver: mpsc::UnboundedReceiver<InputEvent>,
}

impl InputEvents {
    /// Waits for the next event, and returns none once the lane has ended and every event has been
    /// read.
    pub async fn recv(&mut self) -> Option<InputEvent> {
        self.receiver.recv().await
    }

    /// Returns the next event if one is waiting.
    pub fn try_recv(&mut self) -> Option<InputEvent> {
        self.receiver.try_recv().ok()
    }
}

/// An ordered request's turn, queued behind the typing of a local lane.
type Work = Pin<Box<dyn Future<Output = ()> + Send>>;

enum Entry {
    Frame(Queued),
    Work(Work),
}

struct Queued {
    sequence: u64,
    bytes: Vec<u8>,
    cost: usize,
}

/// A frame written and not yet accepted.
struct Sent {
    sequence: u64,
    key_len: usize,
    cost: usize,
}

/// A frame admitted during a hold: it has no sequence yet.
struct Held {
    bytes: Vec<u8>,
    cost: usize,
}

struct Hold {
    launch: u32,
    frames: VecDeque<Held>,
}

struct Wait {
    id: u64,
    barrier: InputBarrier,
    timer: Option<tokio::task::AbortHandle>,
}

enum Phase {
    Live,
    /// A release or a detach has taken its barrier.
    Ending,
    Over(Over),
}

struct Epoch {
    epoch: InputLeaseEpoch,
    next_sequence: u64,
    queue: VecDeque<Entry>,
    flight: VecDeque<Sent>,
    flight_cost: usize,
    accepted: Count,
    accepted_through: Option<u64>,
    /// Frames dropped from a hold that nobody was given the count of.
    unsent_dropped: Count,
    phase: Phase,
    hold: Option<Hold>,
    waits: Vec<Wait>,
    /// Frames and encoded bytes held against the bound: queued, written and held, and the ordered
    /// requests in the queue (which have no bytes).
    frames_in_use: usize,
    cost_in_use: usize,
    frozen: Option<Sets>,
}

impl Epoch {
    fn new(epoch: InputLeaseEpoch) -> Self {
        Self {
            epoch,
            next_sequence: 0,
            queue: VecDeque::new(),
            flight: VecDeque::new(),
            flight_cost: 0,
            accepted: Count::default(),
            accepted_through: None,
            unsent_dropped: Count::default(),
            phase: Phase::Live,
            hold: None,
            waits: Vec::new(),
            frames_in_use: 0,
            cost_in_use: 0,
            frozen: None,
        }
    }

    const fn proven(&self) -> u64 {
        match self.accepted_through {
            Some(through) => through + 1,
            None => 0,
        }
    }

    fn sets(&self) -> Sets {
        if let Some(frozen) = self.frozen {
            return frozen;
        }
        let mut sets = Sets {
            accepted: self.accepted,
            unsent: self.unsent_dropped,
            ..Sets::default()
        };
        for sent in &self.flight {
            sets.uncertain.add(Count::of(sent.key_len));
        }
        for entry in &self.queue {
            if let Entry::Frame(queued) = entry {
                sets.unsent.add(Count::of(queued.bytes.len()));
            }
        }
        if let Some(hold) = &self.hold {
            for held in &hold.frames {
                sets.unsent.add(Count::of(held.bytes.len()));
            }
        }
        sets
    }

    fn is_over(&self) -> bool {
        matches!(self.phase, Phase::Over(_))
    }

    /// Ends the hold and counts what it held as unsent, which is every ending but the caller's own.
    fn end_hold(&mut self) {
        if let Some(hold) = self.hold.take() {
            for held in hold.frames {
                self.unsent_dropped.add(Count::of(held.bytes.len()));
                self.frames_in_use -= 1;
                self.cost_in_use -= held.cost;
            }
        }
    }

    /// Takes the accepted prefix off the flight.
    fn accept_through(&mut self, through: u64) -> Count {
        let mut newly = Count::default();
        while self
            .flight
            .front()
            .is_some_and(|sent| sent.sequence <= through)
        {
            let Some(sent) = self.flight.pop_front() else {
                break;
            };
            newly.add(Count::of(sent.key_len));
            self.flight_cost -= sent.cost;
            self.frames_in_use -= 1;
            self.cost_in_use -= sent.cost;
        }
        self.accepted.add(newly);
        self.accepted_through = Some(through);
        newly
    }

    /// The last sequence the lane has written.
    fn last_written(&self) -> Option<u64> {
        self.flight
            .back()
            .map(|sent| sent.sequence)
            .or(self.accepted_through)
    }
}

/// What the writer does next.
enum Next {
    Frame {
        epoch: InputLeaseEpoch,
        sequence: u64,
        bytes: Vec<u8>,
    },
    Work(Work),
    Idle,
    Over,
}

struct Core {
    attachment_id: AttachmentId,
    frame_bytes: usize,
    window: InputWindow,
    local: bool,
    epoch: Option<Epoch>,
    early_ends: BTreeMap<u64, u64>,
    next_wait: u64,
    ended: Option<EndCause>,
    events: mpsc::UnboundedSender<InputEvent>,
}

/// The encoded bytes a frame of `key_len` key bytes can take: its length prefix, its framing at
/// the widest, and its bytes. The widest is what the bound counts, so that a frame's cost does not
/// depend on the sequence it takes later.
const fn cost_of(key_len: usize) -> usize {
    FRAME_LENGTH_PREFIX_LEN + INPUT_FRAME_OVERHEAD + key_len
}

impl Core {
    fn emit(&self, event: InputEvent) {
        let _ = self.events.send(event);
    }

    fn live(&self) -> std::result::Result<&Epoch, InputRefusal> {
        if self.ended.is_some() {
            return Err(InputRefusal::Over(Over::StreamEnded));
        }
        let epoch = self.epoch.as_ref().ok_or(InputRefusal::NoEpoch)?;
        match epoch.phase {
            Phase::Live => Ok(epoch),
            Phase::Ending => Err(InputRefusal::Ending),
            Phase::Over(over) => Err(InputRefusal::Over(over)),
        }
    }

    fn fits(epoch: &Epoch, frames: usize, cost: usize) -> bool {
        epoch.frames_in_use + frames <= MAX_LOCAL_INPUT_FRAMES
            && epoch.cost_in_use + cost <= MAX_LOCAL_INPUT_BYTES
    }

    /// Admits `pieces` as one unit: all of them or none, in order.
    fn admit(&mut self, pieces: &[&[u8]]) -> std::result::Result<Vec<Writing>, InputRefusal> {
        self.live()?;
        let total: usize = pieces.iter().map(|piece| cost_of(piece.len())).sum();
        let Some(epoch) = self.epoch.as_mut() else {
            return Err(InputRefusal::NoEpoch);
        };
        if !Self::fits(epoch, pieces.len(), total) {
            return Err(InputRefusal::Full);
        }
        let mut written = Vec::with_capacity(pieces.len());
        for piece in pieces {
            let cost = cost_of(piece.len());
            epoch.frames_in_use += 1;
            epoch.cost_in_use += cost;
            let sequence = if let Some(hold) = epoch.hold.as_mut() {
                hold.frames.push_back(Held {
                    bytes: piece.to_vec(),
                    cost,
                });
                None
            } else {
                let sequence = epoch.next_sequence;
                epoch.next_sequence += 1;
                epoch.queue.push_back(Entry::Frame(Queued {
                    sequence,
                    bytes: piece.to_vec(),
                    cost,
                }));
                Some(InputSequence::new(sequence))
            };
            written.push(Writing {
                epoch: epoch.epoch,
                sequence,
                bytes: piece.len(),
            });
        }
        Ok(written)
    }

    /// Gives the held frames their sequences, in order, behind what is already queued.
    fn release_hold(&mut self) -> Count {
        let Some(epoch) = self.epoch.as_mut() else {
            return Count::default();
        };
        let Some(hold) = epoch.hold.take() else {
            return Count::default();
        };
        let mut released = Count::default();
        for held in hold.frames {
            let sequence = epoch.next_sequence;
            epoch.next_sequence += 1;
            released.add(Count::of(held.bytes.len()));
            epoch.queue.push_back(Entry::Frame(Queued {
                sequence,
                bytes: held.bytes,
                cost: held.cost,
            }));
        }
        released
    }

    fn discard_held(&mut self) -> Count {
        let Some(epoch) = self.epoch.as_mut() else {
            return Count::default();
        };
        let Some(hold) = epoch.hold.take() else {
            return Count::default();
        };
        let mut dropped = Count::default();
        for held in hold.frames {
            dropped.add(Count::of(held.bytes.len()));
            epoch.frames_in_use -= 1;
            epoch.cost_in_use -= held.cost;
        }
        dropped
    }

    fn mark(
        &mut self,
        launch: Option<u32>,
    ) -> std::result::Result<(InputBarrier, Option<u64>), InputRefusal> {
        self.live()?;
        let local = self.local;
        let attachment_id = self.attachment_id;
        let id = self.next_wait;
        let Some(epoch) = self.epoch.as_mut() else {
            return Err(InputRefusal::NoEpoch);
        };
        if launch.is_some() && epoch.hold.is_some() {
            return Err(InputRefusal::LaunchWaiting);
        }
        let barrier = InputBarrier {
            attachment_id,
            epoch: epoch.epoch,
            count: U64::new(epoch.next_sequence),
            launch: Nullable::from(launch),
        };
        match launch {
            // A local lane orders a launch by its queue: later typing waits behind the launch
            // there, so nothing is held.
            Some(launch) if !local => {
                epoch.hold = Some(Hold {
                    launch,
                    frames: VecDeque::new(),
                });
            }
            Some(_) => {}
            None => {
                epoch.end_hold();
                epoch.phase = Phase::Ending;
            }
        }
        if epoch.proven() >= epoch.next_sequence {
            self.emit(InputEvent::Reached(barrier.clone()));
            return Ok((barrier, None));
        }
        self.next_wait += 1;
        let Some(epoch) = self.epoch.as_mut() else {
            return Err(InputRefusal::NoEpoch);
        };
        epoch.waits.push(Wait {
            id,
            barrier: barrier.clone(),
            timer: None,
        });
        Ok((barrier, Some(id)))
    }

    fn arm(&mut self, id: u64, timer: tokio::task::AbortHandle) {
        match self
            .epoch
            .as_mut()
            .and_then(|epoch| epoch.waits.iter_mut().find(|wait| wait.id == id))
        {
            Some(wait) => wait.timer = Some(timer),
            None => timer.abort(),
        }
    }

    fn time_out(&mut self, id: u64) {
        let Some(epoch) = self.epoch.as_mut() else {
            return;
        };
        let Some(at) = epoch.waits.iter().position(|wait| wait.id == id) else {
            return;
        };
        let wait = epoch.waits.remove(at);
        self.emit(InputEvent::NotReached {
            barrier: wait.barrier,
            reason: NotReached::Timeout,
        });
    }

    /// Says `Reached` for every wait the accepted prefix now covers.
    fn satisfy_waits(&mut self) {
        let Some(epoch) = self.epoch.as_mut() else {
            return;
        };
        let proven = epoch.proven();
        let (reached, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut epoch.waits)
            .into_iter()
            .partition(|wait| wait.barrier.count.get() <= proven);
        epoch.waits = waiting;
        for wait in reached {
            if let Some(timer) = wait.timer {
                timer.abort();
            }
            self.emit(InputEvent::Reached(wait.barrier));
        }
    }

    /// Ends the current epoch for `over`, counts every frame in one of the four sets, and leaves the
    /// waits for the caller to answer after the cause is told.
    fn freeze(epoch: &mut Epoch, over: Over) -> (Sets, Vec<Wait>) {
        let mut sets = Sets {
            accepted: epoch.accepted,
            unsent: epoch.unsent_dropped,
            ..Sets::default()
        };
        let mut written = Count::default();
        for sent in &epoch.flight {
            written.add(Count::of(sent.key_len));
        }
        let mut queued = Count::default();
        for entry in &epoch.queue {
            if let Entry::Frame(frame) = entry {
                queued.add(Count::of(frame.bytes.len()));
            }
        }
        if over == Over::Refused {
            sets.refused = written;
            sets.refused.add(queued);
        } else {
            sets.uncertain = written;
            sets.unsent.add(queued);
        }
        if let Some(hold) = &epoch.hold {
            for held in &hold.frames {
                sets.unsent.add(Count::of(held.bytes.len()));
            }
        }
        epoch.frozen = Some(sets);
        epoch.phase = Phase::Over(over);
        epoch.queue.clear();
        epoch.flight.clear();
        epoch.flight_cost = 0;
        epoch.hold = None;
        epoch.frames_in_use = 0;
        epoch.cost_in_use = 0;
        (sets, std::mem::take(&mut epoch.waits))
    }

    fn not_reached(&self, waits: Vec<Wait>, reason: NotReached) {
        for wait in waits {
            if let Some(timer) = wait.timer {
                timer.abort();
            }
            self.emit(InputEvent::NotReached {
                barrier: wait.barrier,
                reason,
            });
        }
    }

    fn begin_epoch(
        &mut self,
        epoch: InputLeaseEpoch,
    ) -> std::result::Result<Option<Sets>, InputRefusal> {
        if self.ended.is_some() {
            return Err(InputRefusal::Over(Over::StreamEnded));
        }
        let mut superseded = None;
        if let Some(current) = self.epoch.as_mut() {
            if epoch.get() <= current.epoch.get() {
                return Err(InputRefusal::EpochNotNew);
            }
            if !current.is_over() {
                let (sets, waits) = Self::freeze(current, Over::Superseded);
                self.not_reached(waits, NotReached::Superseded);
                superseded = Some(sets);
            }
        }
        self.early_ends.retain(|ended, _| *ended >= epoch.get());
        let already_ended = self.early_ends.remove(&epoch.get());
        self.epoch = Some(Epoch::new(epoch));
        if let Some(fenced_bytes) = already_ended {
            self.epoch_ended(epoch, fenced_bytes)
                .map_err(|_| InputRefusal::Over(Over::StreamEnded))?;
        }
        Ok(superseded)
    }

    /// The host's notice that `epoch` ended.
    fn epoch_ended(
        &mut self,
        epoch: InputLeaseEpoch,
        fenced_bytes: u64,
    ) -> std::result::Result<(), &'static str> {
        let Some(current) = self.epoch.as_mut() else {
            self.early(epoch, fenced_bytes)?;
            return Ok(());
        };
        if epoch.get() < current.epoch.get() {
            return Ok(());
        }
        if epoch.get() > current.epoch.get() {
            self.early(epoch, fenced_bytes)?;
            return Ok(());
        }
        // The view ended this epoch itself by a release or a detach, and shows the words of that
        // answer: the host's notice for the same epoch says nothing it has not.
        let own = matches!(current.phase, Phase::Ending);
        if current.is_over() {
            return Ok(());
        }
        let (sets, waits) = Self::freeze(current, Over::LeaseEnded);
        if !own {
            self.emit(InputEvent::EpochEnded {
                epoch,
                fenced_bytes,
                sets,
            });
        }
        self.not_reached(waits, NotReached::EpochEnded);
        Ok(())
    }

    fn early(
        &mut self,
        epoch: InputLeaseEpoch,
        fenced_bytes: u64,
    ) -> std::result::Result<(), &'static str> {
        if self.early_ends.len() >= MAX_EARLY_ENDS {
            return Err("more epochs ended than the lane has begun");
        }
        self.early_ends.insert(epoch.get(), fenced_bytes);
        Ok(())
    }

    /// Applies one word of the host's, or says what contract it broke.
    fn apply(&mut self, ack: InputAck) -> std::result::Result<(), &'static str> {
        match ack {
            InputAck::Ready { .. } => Err("a second ready"),
            InputAck::Accepted { epoch, through } => self.accepted(epoch, through.get()),
            InputAck::Refused {
                epoch,
                sequence,
                accepted_through,
                error,
            } => self.refused(
                epoch,
                sequence.get(),
                accepted_through.as_ref().map(|through| through.get()),
                error,
            ),
            InputAck::LaunchReserved { launch } => {
                self.launch_reserved(launch);
                Ok(())
            }
            InputAck::EpochEnded {
                epoch,
                fenced_bytes,
            } => self.epoch_ended(epoch, fenced_bytes.get()),
        }
    }

    /// Which epoch an acknowledgement is about: the current one, or one the lane has finished with
    /// (None), or one it has not begun, which no frame of its own can have caused.
    fn about(&self, epoch: InputLeaseEpoch) -> std::result::Result<Option<()>, &'static str> {
        let Some(current) = self.epoch.as_ref() else {
            return Err("an acknowledgement before any epoch");
        };
        match epoch.get().cmp(&current.epoch.get()) {
            std::cmp::Ordering::Less => Ok(None),
            std::cmp::Ordering::Equal => Ok(Some(())),
            std::cmp::Ordering::Greater => Err("an acknowledgement for an epoch not begun"),
        }
    }

    fn accepted(
        &mut self,
        epoch: InputLeaseEpoch,
        through: u64,
    ) -> std::result::Result<(), &'static str> {
        if self.about(epoch)?.is_none() {
            return Ok(());
        }
        let Some(current) = self.epoch.as_mut() else {
            return Ok(());
        };
        match current.phase {
            Phase::Over(Over::Refused) => {
                // A refusal has taken every later frame of the epoch.
                return if Some(through) > current.accepted_through {
                    Err("an acceptance past a refused frame")
                } else {
                    Ok(())
                };
            }
            // Frames of an epoch that has ended are no longer counted.
            Phase::Over(_) => return Ok(()),
            Phase::Live | Phase::Ending => {}
        }
        match current.accepted_through {
            Some(before) if through < before => return Err("an acceptance that went back"),
            Some(before) if through == before => return Ok(()),
            _ => {}
        }
        if current.last_written().is_none_or(|last| through > last) {
            return Err("an acceptance of a frame that was never written");
        }
        let newly = current.accept_through(through);
        self.emit(InputEvent::Accepted {
            epoch,
            through: InputSequence::new(through),
            frames: newly.frames,
            bytes: newly.bytes,
        });
        self.satisfy_waits();
        Ok(())
    }

    fn refused(
        &mut self,
        epoch: InputLeaseEpoch,
        sequence: u64,
        accepted_through: Option<u64>,
        error: ProtocolError,
    ) -> std::result::Result<(), &'static str> {
        if self.about(epoch)?.is_none() {
            return Ok(());
        }
        let Some(current) = self.epoch.as_mut() else {
            return Ok(());
        };
        match current.phase {
            Phase::Over(Over::Refused) => return Err("a second refusal in one epoch"),
            Phase::Over(_) => return Ok(()),
            Phase::Live | Phase::Ending => {}
        }
        if sequence != accepted_through.map_or(0, |through| through + 1) {
            return Err("a refusal that does not follow the accepted prefix");
        }
        if accepted_through < current.accepted_through {
            return Err("a refusal that took back an acceptance");
        }
        if current.last_written().is_none_or(|last| sequence > last) {
            return Err("a refusal of a frame that was never written");
        }
        let newly = accepted_through.map(|through| current.accept_through(through));
        let (sets, waits) = Self::freeze(current, Over::Refused);
        if let (Some(newly), Some(through)) = (newly, accepted_through)
            && !newly.is_empty()
        {
            self.emit(InputEvent::Accepted {
                epoch,
                through: InputSequence::new(through),
                frames: newly.frames,
                bytes: newly.bytes,
            });
        }
        // The accepted prefix is in the refusal's sets, and waits it covers are reached.
        let proven = accepted_through.map_or(0, |through| through + 1);
        let (reached, missed): (Vec<_>, Vec<_>) = waits
            .into_iter()
            .partition(|wait| wait.barrier.count.get() <= proven);
        for wait in reached {
            if let Some(timer) = wait.timer {
                timer.abort();
            }
            self.emit(InputEvent::Reached(wait.barrier));
        }
        let mut sets = sets;
        sets.accepted = self.epoch.as_ref().map_or(sets.accepted, |e| e.accepted);
        if let Some(epoch_state) = self.epoch.as_mut() {
            epoch_state.frozen = Some(sets);
        }
        self.emit(InputEvent::Refused {
            epoch,
            sequence: InputSequence::new(sequence),
            accepted_through: accepted_through.map(InputSequence::new),
            error,
            sets,
        });
        self.not_reached(missed, NotReached::Refused);
        Ok(())
    }

    fn launch_reserved(&mut self, launch: u32) {
        let held_for_it = self
            .epoch
            .as_ref()
            .and_then(|epoch| epoch.hold.as_ref())
            .is_some_and(|hold| hold.launch == launch);
        let released = if held_for_it {
            self.release_hold()
        } else {
            Count::default()
        };
        self.emit(InputEvent::LaunchReserved { launch, released });
    }

    /// Ends the lane for `cause`. Returns whether this call ended it.
    fn end(&mut self, cause: EndCause) -> bool {
        if self.ended.is_some() {
            return false;
        }
        let mut waits = Vec::new();
        let (epoch, sets) = match self.epoch.as_mut() {
            Some(current) => {
                let sets = if current.is_over() {
                    current.sets()
                } else {
                    let (sets, taken) = Self::freeze(current, Over::StreamEnded);
                    waits = taken;
                    sets
                };
                (Some(current.epoch), sets)
            }
            None => (None, Sets::default()),
        };
        self.ended = Some(cause.clone());
        self.emit(InputEvent::Ended { epoch, cause, sets });
        self.not_reached(waits, NotReached::StreamEnded);
        true
    }

    /// What the writer does next, within the window.
    fn next(&mut self) -> Next {
        if self.ended.is_some() {
            return Next::Over;
        }
        let window = self.window;
        let Some(epoch) = self.epoch.as_mut() else {
            return Next::Idle;
        };
        match epoch.queue.front() {
            None => Next::Idle,
            Some(Entry::Work(_)) => {
                if !epoch.flight.is_empty() {
                    return Next::Idle;
                }
                match epoch.queue.pop_front() {
                    Some(Entry::Work(work)) => {
                        epoch.frames_in_use -= 1;
                        Next::Work(work)
                    }
                    _ => Next::Idle,
                }
            }
            Some(Entry::Frame(queued)) => {
                let room = epoch.flight.len()
                    < usize::try_from(window.frames).unwrap_or(usize::MAX)
                    && (epoch.flight_cost + queued.cost) as u64 <= window.bytes.get();
                if !room {
                    return Next::Idle;
                }
                let Some(Entry::Frame(queued)) = epoch.queue.pop_front() else {
                    return Next::Idle;
                };
                epoch.flight.push_back(Sent {
                    sequence: queued.sequence,
                    key_len: queued.bytes.len(),
                    cost: queued.cost,
                });
                epoch.flight_cost += queued.cost;
                Next::Frame {
                    epoch: epoch.epoch,
                    sequence: queued.sequence,
                    bytes: queued.bytes,
                }
            }
        }
    }
}

/// What the lane's tasks and its holder share.
struct Shared {
    core: Mutex<Core>,
    wake: Notify,
    over: watch::Sender<bool>,
    handle: Mutex<Option<StreamHandle>>,
    bounds: Arc<dyn Deadlines>,
    connection: ConnectionWatch,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Core> {
        self.core.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Ends the lane: tells the holder, resets the stream and wakes the writer.
    fn end(&self, cause: EndCause) {
        let first = self.lock().end(cause);
        if first {
            self.over.send_replace(true);
            self.wake.notify_one();
            let handle = self
                .handle
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(handle) = handle {
                handle.revoke();
            }
        }
    }

    /// Ends the lane for a failure of the stream or the connection.
    fn end_by_failure(&self) {
        let refusal = self.connection.refusal();
        if self.connection.has_ended() || refusal.is_some() {
            self.end(EndCause::Connection { refusal });
        } else {
            self.end(EndCause::Reset);
        }
    }

    fn apply(&self, ack: InputAck) {
        let outcome = self.lock().apply(ack);
        match outcome {
            Ok(()) => self.wake.notify_one(),
            Err(breach) => self.end(EndCause::Breach(breach)),
        }
    }
}

/// One attachment's input lane.
///
/// Every call is non-blocking and takes effect at once. The lane's tasks write the frames in order
/// and read the host's answers; dropping the lane resets its stream.
pub struct InputLane {
    shared: Arc<Shared>,
    events: Mutex<Option<InputEvents>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    fenced_report: bool,
    local: bool,
}

crate::debug_as_name!(InputLane);

impl Drop for InputLane {
    fn drop(&mut self) {
        self.shared.end(EndCause::Closed);
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl InputLane {
    /// The events of the lane, once: the first call returns them and a later one returns none.
    #[must_use]
    pub fn events(&self) -> Option<InputEvents> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// Begins the lease epoch the view now holds. Frames carry its number and take sequences from 0.
    ///
    /// An epoch that was still going ends here, and the frames of it that were not written are not
    /// written: they are counted unsent in the sets this returns, which are those of the epoch that
    /// ended, or none when it had already ended or there was none. Whatever the hold of that epoch
    /// held is gone with it.
    ///
    /// # Errors
    ///
    /// Returns [`InputRefusal::EpochNotNew`] when `epoch` is not higher than the lane's, and
    /// [`InputRefusal::Over`] when the lane has ended.
    pub fn begin_epoch(
        &self,
        epoch: InputLeaseEpoch,
    ) -> std::result::Result<Option<Sets>, InputRefusal> {
        let outcome = self.shared.lock().begin_epoch(epoch)?;
        self.shared.wake.notify_one();
        Ok(outcome)
    }

    /// Admits one frame of typing.
    ///
    /// The frame takes the next sequence when it is admitted and not held. While a hold is active it
    /// waits unsequenced, counted against the bound, and takes its sequence at the release.
    ///
    /// # Errors
    ///
    /// Returns [`InputRefusal::Full`] at the bound, [`InputRefusal::TooLarge`] for more bytes than
    /// one frame carries, and the refusals of an epoch that has not begun, has ended or is ending.
    /// No refusal takes a sequence.
    pub fn try_send(&self, bytes: &[u8]) -> std::result::Result<Writing, InputRefusal> {
        if bytes.is_empty() {
            return Err(InputRefusal::Empty);
        }
        let mut core = self.shared.lock();
        if bytes.len() > core.frame_bytes {
            return Err(InputRefusal::TooLarge);
        }
        let mut written = core.admit(&[bytes])?;
        drop(core);
        self.shared.wake.notify_one();
        written.pop().ok_or(InputRefusal::Empty)
    }

    /// Admits a paste whole, cut into frames of at most the negotiated limit, none of them ending
    /// inside a paste delimiter. The frames, their delimiters and their framing are reserved in one
    /// step: all are admitted or none is, and a refusal takes no sequence.
    ///
    /// # Errors
    ///
    /// Returns [`InputRefusal::TooLarge`] for a paste that no empty lane admits,
    /// [`InputRefusal::NotNow`] for one that would fit an empty lane and does not fit the room that
    /// is free, and the refusals of [`InputLane::try_send`].
    pub fn try_send_paste(&self, bytes: &[u8]) -> std::result::Result<Vec<Writing>, InputRefusal> {
        if bytes.is_empty() {
            return Err(InputRefusal::Empty);
        }
        let mut core = self.shared.lock();
        let cuts = cuts(bytes, core.frame_bytes);
        let total: usize = cuts.iter().map(|cut| cost_of(cut.len())).sum();
        if cuts.len() > MAX_LOCAL_INPUT_FRAMES || total > MAX_LOCAL_INPUT_BYTES {
            return Err(InputRefusal::TooLarge);
        }
        let pieces: Vec<&[u8]> = cuts.iter().map(|cut| &bytes[cut.clone()]).collect();
        let written = match core.admit(&pieces) {
            Err(InputRefusal::Full) => return Err(InputRefusal::NotNow),
            other => other?,
        };
        drop(core);
        self.shared.wake.notify_one();
        Ok(written)
    }

    /// The most paste bytes an empty lane is certain to admit, whatever the paste holds: the worst
    /// cut of a paste loses a few bytes of each frame to the delimiter it must not split.
    #[must_use]
    pub fn paste_capacity(&self) -> usize {
        paste_capacity(self.shared.lock().frame_bytes)
    }

    /// Takes the barrier for a request that must come after the typing admitted so far.
    ///
    /// The barrier names every frame admitted in this epoch, the queued ones included. The lane then
    /// says [`InputEvent::Reached`] when the host has accepted them, or [`InputEvent::NotReached`]
    /// when it has not and will not, within [`BARRIER_WAIT`] at the latest.
    ///
    /// With a `launch` number, later frames are held, unsequenced, until the hold ends. A launch
    /// asked for while another is held is refused. On a local lane nothing is held: the launch is
    /// ordered by the lane's queue ([`InputLane::after_keys`]).
    ///
    /// With no launch number, the mark is a release's or a detach's: the epoch takes no more typing,
    /// and whatever was held is counted unsent and released by nothing.
    ///
    /// # Errors
    ///
    /// Returns [`InputRefusal::LaunchWaiting`], and the refusals of an epoch that has not begun, is
    /// over, or is already ending.
    pub fn mark(&self, launch: Option<u32>) -> std::result::Result<InputBarrier, InputRefusal> {
        let (barrier, wait) = self.shared.lock().mark(launch)?;
        if let Some(id) = wait {
            let passed = self.shared.bounds.start(DeadlineKind::Admission);
            let weak = Arc::downgrade(&self.shared);
            let timer = tokio::spawn(async move {
                passed.await;
                if let Some(shared) = weak.upgrade() {
                    shared.lock().time_out(id);
                }
            });
            self.shared.lock().arm(id, timer.abort_handle());
        }
        Ok(barrier)
    }

    /// Releases the held frames: they take their sequences, in order, behind what is queued. It does
    /// nothing, and returns nothing, once the hold has ended by any other way.
    pub fn release_hold(&self) -> Count {
        let released = self.shared.lock().release_hold();
        self.shared.wake.notify_one();
        released
    }

    /// Drops the held frames, ends the hold and returns what it dropped: those bytes are counted
    /// here and nowhere else. The next frame takes the next sequence, and the epoch goes on.
    pub fn discard_held(&self) -> Count {
        self.shared.lock().discard_held()
    }

    /// Where the frames of the current epoch stand, or none before an epoch has begun.
    #[must_use]
    pub fn sets(&self) -> Option<Sets> {
        self.shared.lock().epoch.as_ref().map(Epoch::sets)
    }

    /// Whether a request that follows this lane's typing on a local connection asks for the count of
    /// bytes it discarded: only of a worker that states the input lane, which the caller said when it
    /// made the target. A paired host sets this itself on what it forwards, so a network lane says no.
    #[must_use]
    pub const fn fenced_report(&self) -> bool {
        self.fenced_report
    }

    /// Queues `work` behind every frame admitted so far and ahead of every later one, on a local
    /// lane: it runs once the host has answered the frames before it, and the frames after it are
    /// written once it has finished. A release, a detach and a launch go this way, so that a local
    /// host, which handles one connection's requests in the order it reads them, sees them in the
    /// order the view admitted them.
    ///
    /// A lane that ends before the work's turn drops it unpolled.
    ///
    /// # Errors
    ///
    /// Returns [`InputRefusal::NotLocal`] on a network lane, [`InputRefusal::Full`] when too much
    /// work is queued, and the refusals of an epoch that has not begun or is over.
    pub fn after_keys(
        &self,
        work: impl Future<Output = ()> + Send + 'static,
    ) -> std::result::Result<(), InputRefusal> {
        let mut core = self.shared.lock();
        if !self.local {
            return Err(InputRefusal::NotLocal);
        }
        if core.ended.is_some() {
            return Err(InputRefusal::Over(Over::StreamEnded));
        }
        let epoch = core.epoch.as_mut().ok_or(InputRefusal::NoEpoch)?;
        if let Phase::Over(over) = epoch.phase {
            return Err(InputRefusal::Over(over));
        }
        let queued = epoch
            .queue
            .iter()
            .filter(|entry| matches!(entry, Entry::Work(_)))
            .count();
        if queued >= MAX_ORDERED_WORK || epoch.frames_in_use >= MAX_LOCAL_INPUT_FRAMES {
            return Err(InputRefusal::Full);
        }
        epoch.frames_in_use += 1;
        epoch.queue.push_back(Entry::Work(Box::pin(work)));
        drop(core);
        self.shared.wake.notify_one();
        Ok(())
    }
}

/// The most paste bytes an empty lane admits whatever they hold, for frames of `frame_bytes` key
/// bytes at most.
fn paste_capacity(frame_bytes: usize) -> usize {
    let each = frame_bytes.saturating_sub(PASTE_START.len() - 1);
    let overhead = cost_of(0);
    let mut best = 0;
    for frames in 1..=MAX_LOCAL_INPUT_FRAMES {
        let room = MAX_LOCAL_INPUT_BYTES.saturating_sub(overhead * frames);
        best = best.max((frames * each).min(room));
    }
    best
}

/// Cuts a paste into frames of at most `frame_bytes`, never inside a paste delimiter.
fn cuts(bytes: &[u8], frame_bytes: usize) -> Vec<std::ops::Range<usize>> {
    let mut cuts = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let mut end = (at + frame_bytes).min(bytes.len());
        if end < bytes.len() {
            // A delimiter that begins before the cut and ends after it moves the cut to its start.
            let earliest = end.saturating_sub(PASTE_START.len() - 1).max(at + 1);
            if let Some(begin) = (earliest..end).find(|begin| {
                bytes[*begin..].starts_with(PASTE_START) || bytes[*begin..].starts_with(PASTE_END)
            }) {
                end = begin;
            }
        }
        cuts.push(at..end);
        at = end;
    }
    cuts
}

/// Whether a refusal comes before the host accepted anything of the write, so that the frame was
/// refused and not merely left uncertain.
fn refused_before_acceptance(error: &ProtocolError) -> bool {
    match error.code {
        ErrorCode::LeaseLost
        | ErrorCode::InvalidArgument
        | ErrorCode::SessionClosed
        | ErrorCode::ResourceUnavailable => true,
        // A marked refusal can be the answer to a write the worker accepted and then fenced.
        ErrorCode::PermissionDenied => !error.link_fenced,
        _ => false,
    }
}

impl Session {
    /// Opens the input lane of one attachment.
    ///
    /// On a paired host the lane opens a terminal-input stream, after asking whether the host takes
    /// one, and waits for the host's first word under [`INPUT_OPEN_WAIT`]. On a host on this machine
    /// the lane sends the typing as ordered `input.write` requests on this session's connection.
    ///
    /// # Errors
    ///
    /// Returns an unsupported-capability refusal when a paired host takes no input stream, the
    /// failure of an open that is refused or takes too long, and a refusal when the host's first
    /// word is not the one the stream's contract names, or gives a window that no frame fits.
    pub async fn input_lane(&self, target: InputTarget) -> Result<InputLane> {
        let support = self.lane_support();
        let limit = usize::try_from(support.transport.limits().max_input_frame_len.get())
            .unwrap_or(usize::MAX)
            .min(MAX_INPUT_FRAME_LEN);
        let frame_bytes = max_input_bytes(limit);
        if frame_bytes == 0 {
            return Err(refusal(
                ErrorCode::InvalidArgument,
                "the negotiated input frame limit holds no typing",
            ));
        }
        let Some(opener) = support.transport.stream_opener() else {
            return Ok(Self::local_lane(&target, support, frame_bytes));
        };
        match self
            .read_unsignalled::<_, TransferStreamsResult>(
                Method::TransferStreams,
                &TransferStreamsParams {},
            )
            .await
        {
            Ok(taken) if taken.accepted_streams.contains(&StreamKind::TerminalInput) => {}
            Ok(_) => {
                return Err(refusal(ErrorCode::UnsupportedCapability, NO_INPUT_STREAM));
            }
            // The refusal of a method the host does not list is how a host of an earlier build
            // answers; another refusal says its own reason.
            Err(ClientError::Host(refused))
                if refused.code == ErrorCode::PermissionDenied
                    && refused.message == kr_transport::actor::METHOD_NOT_AVAILABLE =>
            {
                return Err(refusal(ErrorCode::UnsupportedCapability, NO_INPUT_STREAM));
            }
            Err(error) => return Err(error),
        }
        Self::network_lane(&target, support, opener, frame_bytes).await
    }

    fn local_lane(target: &InputTarget, support: LaneSupport, frame_bytes: usize) -> InputLane {
        let (shared, events) = shared_for(
            target,
            &support,
            frame_bytes,
            true,
            InputWindow {
                frames: 1,
                bytes: U64::new(u64::MAX),
            },
        );
        let session_id = target.session_id;
        let attachment_id = target.attachment_id;
        let writer = tokio::spawn(local_writer(
            Arc::clone(&shared),
            support.local,
            session_id,
            attachment_id,
        ));
        let watcher = tokio::spawn(watch_connection(Arc::clone(&shared)));
        InputLane {
            shared,
            events: Mutex::new(Some(events)),
            tasks: vec![writer, watcher],
            fenced_report: target.worker_states_input_lane,
            local: true,
        }
    }

    async fn network_lane(
        target: &InputTarget,
        support: LaneSupport,
        opener: Arc<dyn crate::transport::StreamOpener>,
        frame_bytes: usize,
    ) -> Result<InputLane> {
        let header = StreamHeader {
            kind: StreamKind::TerminalInput,
            connection_id: support.transport.connection_id(),
            stream_id: Nullable::null(),
            resource: StreamResource {
                environment_id: target.environment_id,
                session_id: Nullable::some(target.session_id),
                attachment_id: Nullable::some(target.attachment_id),
                transfer_id: Nullable::null(),
            },
        };
        let mut stream = bounded(
            target.bounds.as_ref(),
            DeadlineKind::Header,
            opener.open(header),
        )
        .await?;
        let handle = stream.handle();
        // The first word is the host's window. Reading it is part of the open, under the same bound.
        let ready = bounded(target.bounds.as_ref(), DeadlineKind::Header, async {
            Ok(stream.read_message::<InputAck>().await?)
        })
        .await;
        let window = match ready {
            Ok(Some(InputAck::Ready { window })) => window,
            Ok(_) => {
                handle.revoke();
                return Err(refusal(
                    ErrorCode::InvalidArgument,
                    "the host's first word on the input stream was not its window",
                ));
            }
            Err(error) => {
                handle.revoke();
                return Err(error);
            }
        };
        if window.frames == 0 || window.bytes.get() < cost_of(frame_bytes) as u64 {
            handle.revoke();
            return Err(refusal(
                ErrorCode::InvalidArgument,
                "the host's input window holds no whole frame",
            ));
        }
        let (shared, events) = shared_for(target, &support, frame_bytes, false, window);
        *shared.handle.lock().unwrap_or_else(PoisonError::into_inner) = Some(handle);
        let (reader, writer) = stream.split();
        let tasks = vec![
            tokio::spawn(network_writer(Arc::clone(&shared), writer, opener.budget())),
            tokio::spawn(network_reader(Arc::clone(&shared), reader)),
            tokio::spawn(watch_connection(Arc::clone(&shared))),
        ];
        Ok(InputLane {
            shared,
            events: Mutex::new(Some(events)),
            tasks,
            fenced_report: false,
            local: false,
        })
    }
}

fn shared_for(
    target: &InputTarget,
    support: &LaneSupport,
    frame_bytes: usize,
    local: bool,
    window: InputWindow,
) -> (Arc<Shared>, InputEvents) {
    let (events, receiver) = mpsc::unbounded_channel();
    let shared = Arc::new(Shared {
        core: Mutex::new(Core {
            attachment_id: target.attachment_id,
            frame_bytes,
            window,
            local,
            epoch: None,
            early_ends: BTreeMap::new(),
            next_wait: 0,
            ended: None,
            events,
        }),
        wake: Notify::new(),
        over: watch::channel(false).0,
        handle: Mutex::new(None),
        bounds: Arc::clone(&target.bounds),
        connection: support.connection.clone(),
    });
    (shared, InputEvents { receiver })
}

fn refusal(code: ErrorCode, message: &'static str) -> ClientError {
    ClientError::refusal(code, Shown::said(message))
}

async fn bounded<T>(
    bounds: &dyn Deadlines,
    kind: DeadlineKind,
    wait: impl Future<Output = Result<T>>,
) -> Result<T> {
    let passed = bounds.start(kind);
    tokio::pin!(wait);
    tokio::select! {
        biased;
        outcome = &mut wait => outcome,
        () = passed => Err(ClientError::Transport(TransportError::Deadline(kind))),
    }
}

/// Ends the lane when the connection ends, which an idle lane would not otherwise see.
async fn watch_connection(shared: Arc<Shared>) {
    shared.connection.ended().await;
    shared.end_by_failure();
}

/// Waits for the writer's next piece of work, or for the lane to end.
async fn next_to_write(shared: &Shared, over: &mut watch::Receiver<bool>) -> Option<Next> {
    loop {
        let woken = shared.wake.notified();
        tokio::pin!(woken);
        woken.as_mut().enable();
        match shared.lock().next() {
            Next::Idle => {}
            Next::Over => return None,
            next => return Some(next),
        }
        tokio::select! {
            () = &mut woken => {}
            _ = over.wait_for(|over| *over) => return None,
        }
    }
}

/// Writes the lane's frames to the stream, in order, within the host's window.
async fn network_writer(
    shared: Arc<Shared>,
    mut writer: DataWriter,
    budget: Option<Arc<StreamBudget>>,
) {
    let mut over = shared.over.subscribe();
    while let Some(next) = next_to_write(&shared, &mut over).await {
        let Next::Frame {
            epoch,
            sequence,
            bytes,
        } = next
        else {
            // A network lane queues no ordered work.
            continue;
        };
        let frame = InputFrame {
            epoch,
            sequence: InputSequence::new(sequence),
            bytes: Bytes::new(bytes),
        };
        loop {
            // The wait for room is made before the attempt, so room given back in between is not
            // missed.
            let released = budget.as_ref().map(|budget| budget.released());
            match writer.write_message(&frame).await {
                Ok(()) => break,
                Err(TransportError::LimitExceeded { .. }) if released.is_some() => {
                    let Some(released) = released else { break };
                    tokio::select! {
                        () = released => {}
                        _ = over.wait_for(|over| *over) => return,
                    }
                }
                Err(_) => {
                    shared.end_by_failure();
                    return;
                }
            }
        }
    }
}

/// Reads the host's answers and applies each in the order it came.
async fn network_reader(shared: Arc<Shared>, mut reader: DataReader) {
    loop {
        match reader.read_message::<InputAck>().await {
            Ok(Some(ack)) => shared.apply(ack),
            Ok(None) => {
                shared.end(EndCause::Finished);
                return;
            }
            Err(_) => {
                shared.end_by_failure();
                return;
            }
        }
        if *shared.over.borrow() {
            return;
        }
    }
}

/// Writes the lane's frames as ordered requests on the session's own connection, one at a time, and
/// runs the work queued among them in its turn.
async fn local_writer(
    shared: Arc<Shared>,
    local: LocalInput,
    session_id: SessionId,
    attachment_id: AttachmentId,
) {
    let mut over = shared.over.subscribe();
    while let Some(next) = next_to_write(&shared, &mut over).await {
        match next {
            Next::Work(work) => {
                work.await;
                shared.wake.notify_one();
            }
            Next::Frame {
                epoch,
                sequence,
                bytes,
            } => {
                let params = InputWriteParams {
                    session_id,
                    attachment_id,
                    epoch,
                    sequence: InputSequence::new(sequence),
                    input: InputContent::Bytes {
                        bytes: Bytes::new(bytes),
                    },
                };
                match local.write(&params).await {
                    Ok(_) => shared.apply(InputAck::Accepted {
                        epoch,
                        through: InputSequence::new(sequence),
                    }),
                    Err(ClientError::Host(error)) if refused_before_acceptance(&error) => {
                        let accepted_through = sequence.checked_sub(1).map(InputSequence::new);
                        shared.apply(InputAck::Refused {
                            epoch,
                            sequence: InputSequence::new(sequence),
                            accepted_through: Nullable::from(accepted_through),
                            error,
                        });
                    }
                    Err(ClientError::Host(error)) => {
                        shared.end(EndCause::Uncertain(error));
                        return;
                    }
                    Err(_) => {
                        shared.end_by_failure();
                        return;
                    }
                }
            }
            Next::Idle | Next::Over => {}
        }
    }
}
