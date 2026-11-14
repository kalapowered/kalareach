//! The input lane's parts that live in the input domain: the registry of lanes, the window of the
//! view that holds the keys, and the ordered queue of what the worker writes on a lane.
//!
//! A lane is a second link of one attachment, which carries that attachment's typing as `input.write`
//! requests and carries the worker's credit and window state back. The lane borrows its parent's
//! binding and owns nothing: its cleanup detaches nothing. Everything that decides whether a frame
//! of a lane is accepted is read in the same hold of the input domain that accepts it, so a frame
//! can neither pass a check and be accepted after the parent's withdrawal began, nor be accepted
//! under a lease that moved.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use kr_protocol::envelope::{ControlEvent, ControlFrame};
use kr_protocol::ids::{AttachmentId, ConnectionId};
use kr_protocol::local::{InputLaneReady, LaneCredit, LaneWindow};
use kr_protocol::scalars::U64;

use crate::input_room::{Cost, Outstanding};

/// How many frames a lane may leave unwritten before the host is taken to have stopped reading.
///
/// Credit bounds what the host sends, and so the answers the worker queues; window states follow
/// lease moves, each of which is an act of a person's. A queue that passes this is a link that no
/// longer reads, and it is closed.
const MAX_LANE_FRAMES: usize = 4096;

/// A frame of a lane as the domain admits it: the lane it came on and the request it is, so that
/// the domain can queue the refusal of a frame that breaches the credit before it ends the lane.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LaneFrame {
    pub(crate) lane: LaneId,
    pub(crate) request_id: kr_protocol::ids::RequestId,
}

/// The identity the domain gives a lane when it is bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LaneId(pub(crate) u64);

/// What the domain knows of one bound lane.
#[derive(Debug)]
pub(crate) struct Lane {
    /// The attachment whose typing the lane carries.
    pub(crate) attachment_id: AttachmentId,
    /// The proxy connection that owns the attachment.
    pub(crate) parent: ConnectionId,
    /// Cleared, under the domain's lock, by the first step of the parent's withdrawal.
    pub(crate) parent_ok: bool,
    /// What the worker writes on the lane.
    pub(crate) queue: Arc<LaneQueue>,
}

/// The room kept for the lane of the view that holds the keys.
#[derive(Debug)]
pub(crate) struct Window {
    /// The lane that spends it.
    pub(crate) lane: LaneId,
    /// The lease epoch it belongs to.
    pub(crate) epoch: u64,
    /// The part of it no frame has spent and no frame is holding.
    pub(crate) reserved: Cost,
    /// The claims of this window's frames that are not done with. A new window has a new counter.
    pub(crate) outstanding: Arc<Outstanding>,
}

/// What binding a lane gives the service.
#[derive(Debug)]
pub struct BoundLane {
    /// The lane's identity in the domain.
    pub id: LaneId,
    /// The queue of what the worker writes on it. The answer to the bind is the first frame in it.
    pub queue: Arc<LaneQueue>,
    /// What the answer says.
    pub ready: InputLaneReady,
    /// The older lanes of the same attachment that this one replaced, which are to be closed.
    pub replaced: Vec<Arc<LaneQueue>>,
}

/// The ordered queue of the frames the worker writes on one lane.
///
/// Every frame goes into it under the domain's lock, in the order the ledger changed, and one task
/// drains it to the link. The answers to the lane's `input.write` requests go through it too, so
/// that a window state which says an epoch ended cannot reach the host before an answer of that
/// epoch that was queued first. It is bounded by joining credits into one sum and by closing a lane
/// that stops reading.
#[derive(Debug, Default)]
pub struct LaneQueue {
    items: Mutex<LaneItems>,
    wake: tokio::sync::Notify,
    /// Woken once, for the one task that waits for the close, when the queue closes.
    closed_wake: tokio::sync::Notify,
    closed: AtomicBool,
}

#[derive(Debug, Default)]
struct LaneItems {
    frames: VecDeque<ControlFrame>,
}

impl LaneQueue {
    fn push(&self, join: impl FnOnce(&mut VecDeque<ControlFrame>) -> bool, frame: ControlFrame) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let mut items = self.items.lock().expect("the lane queue is not poisoned");
        if !join(&mut items.frames) {
            items.frames.push_back(frame);
        }
        let overflowed = items.frames.len() > MAX_LANE_FRAMES;
        drop(items);
        if overflowed {
            self.close();
        } else {
            self.wake.notify_one();
        }
    }

    /// Queues a frame behind everything that is queued.
    pub fn push_frame(&self, frame: ControlFrame) {
        self.push(|_| false, frame);
    }

    /// Queues a window state.
    pub fn push_window(&self, window: LaneWindow) {
        self.push_frame(ControlFrame::Event(ControlEvent::InputWindow(window)));
    }

    /// Queues credit. It joins a credit that is still queued only when that credit is for the same
    /// epoch and comes after that epoch's window state: the nearest window state or credit behind
    /// it is the only thing it may join, so credit never passes ahead of the window it follows.
    pub fn push_credit(&self, credit: LaneCredit) {
        let frame = ControlFrame::Event(ControlEvent::InputCredit(credit));
        self.push(
            |frames| {
                for queued in frames.iter_mut().rev() {
                    match queued {
                        ControlFrame::Event(ControlEvent::InputCredit(sum))
                            if sum.epoch == credit.epoch =>
                        {
                            sum.frames = sum.frames.saturating_add(credit.frames);
                            sum.bytes =
                                U64::new(sum.bytes.get().saturating_add(credit.bytes.get()));
                            return true;
                        }
                        ControlFrame::Event(
                            ControlEvent::InputWindow(_) | ControlEvent::InputCredit(_),
                        ) => return false,
                        _ => {}
                    }
                }
                false
            },
            frame,
        );
    }

    /// Takes everything queued, in order.
    pub fn drain(&self) -> Vec<ControlFrame> {
        let mut items = self.items.lock().expect("the lane queue is not poisoned");
        items.frames.drain(..).collect()
    }

    /// Stops the queue: nothing more is queued, and the task that drains it ends the link after
    /// what it has taken.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.wake.notify_one();
        self.closed_wake.notify_one();
    }

    /// Returns whether the queue has been closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Waits until something is queued or the queue is closed.
    pub async fn wait(&self) {
        self.wake.notified().await;
    }

    /// Waits until the queue is closed. One task waits for it: a close that came first is kept.
    pub async fn closed(&self) {
        if !self.is_closed() {
            self.closed_wake.notified().await;
        }
    }
}
