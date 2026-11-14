//! The room for input that waits for the pseudo-terminal.
//!
//! One count of what the worker holds for the terminal, in the unit the worker stores it in: entries
//! and the bytes in them. What a write costs here is what it costs the worker to hold, which is not
//! the size of the frame it arrived in: a key record of a few bytes on the wire spells thousands,
//! and every entry has a cost of its own however short it is.
//!
//! A write is charged when it is queued and given back by the terminal's writer, by the bytes the
//! terminal has taken and, for what is left, when the writer is done with the entry, whether it
//! wrote it, dropped it as stale or expired, or ended. The room therefore stays charged for as long
//! as the worker holds the storage, which is later than the moment a lease ends: the writer removes
//! the entries of an ended lease when it reaches them, and until then they are held.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering, fence};

use crate::session::{InputBatch, MAX_QUEUED_INPUT_BYTES, MAX_QUEUED_INPUT_FRAMES};

/// What a piece of input costs the worker to hold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cost {
    /// How many entries.
    pub frames: usize,
    /// How many bytes, in the form the worker stores them.
    pub bytes: usize,
}

impl Cost {
    /// What a batch holds while it waits: one entry and the bytes in it. A notice that a lease has
    /// changed carries no bytes and holds nothing.
    #[must_use]
    pub fn of(batch: &InputBatch) -> Self {
        match batch {
            InputBatch::LeaseChanged => Self::default(),
            InputBatch::Lease { .. } | InputBatch::Reply { .. } => Self {
                frames: 1,
                bytes: batch.len(),
            },
        }
    }

    /// Returns the cost of both.
    #[must_use]
    pub const fn plus(self, other: Self) -> Self {
        Self {
            frames: self.frames.saturating_add(other.frames),
            bytes: self.bytes.saturating_add(other.bytes),
        }
    }

    /// What a write of `bytes` must find free before it is accepted.
    ///
    /// The recogniser can hold back the start of a paste delimiter and let it go later, on its own
    /// timer, as an entry of its own with at most one delimiter's bytes. That later entry was
    /// accepted with the write that left the prefix, so it is paid for here: one more place, and
    /// the longest delimiter. The queue then never holds more than its bound, whatever the
    /// recogniser releases.
    #[must_use]
    pub const fn claimed_by(bytes: usize) -> Self {
        Self {
            frames: 2,
            bytes: bytes.saturating_add(crate::input::PASTE_END.len()),
        }
    }
}

/// The bound that a write ran into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Full {
    /// The bytes waiting for the terminal are at their limit.
    Bytes,
    /// The writes waiting for the terminal are at their limit.
    Frames,
}

impl fmt::Display for Full {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes => write!(formatter, "{MAX_QUEUED_INPUT_BYTES} bytes"),
            Self::Frames => write!(formatter, "{MAX_QUEUED_INPUT_FRAMES} writes"),
        }
    }
}

/// Says whether `claim` fits beside what `held` already holds, against both bounds.
///
/// # Errors
///
/// Returns the bound that `claim` would pass, bytes before entries.
pub const fn admit(held: Cost, claim: Cost) -> Result<(), Full> {
    let total = held.plus(claim);
    if total.bytes > MAX_QUEUED_INPUT_BYTES {
        Err(Full::Bytes)
    } else if total.frames > MAX_QUEUED_INPUT_FRAMES {
        Err(Full::Frames)
    } else {
        Ok(())
    }
}

/// What the worker holds for the terminal, as the writer shares it with the input domain.
///
/// Only a holder of the input domain charges it, so two charges never race and the bound is never
/// passed; the writer gives back from its own thread, which can only make a read of it too high for
/// a moment, never too low.
#[derive(Debug, Default)]
pub struct InputRoom {
    frames: AtomicUsize,
    bytes: AtomicUsize,
    /// How many of the entries are the host's own answers, which have a share of their own.
    replies: AtomicUsize,
    /// Whether the response lane holds answers that the pump has not yet found room for, from
    /// before the pump reads the room until a pass of it has found the lane empty or its gate
    /// shut. Room that comes back while this is set is room for them, and the writer says so to
    /// the pump.
    replies_waiting: AtomicBool,
    /// When the first answer that waits in the lane lapses, as a reading of the session's
    /// continuous clock in milliseconds, or nothing when none waits. The pump looks again then, so
    /// that an answer past its deadline is dropped and recorded when no room comes back and
    /// nothing else happens.
    reply_expiry_ms: AtomicU64,
    /// Woken when something is owed that only the session can do, among it the answers that wait
    /// in the lane for room.
    pump: Arc<tokio::sync::Notify>,
}

impl InputRoom {
    /// Returns what is held now, queued, on its way to the writer, or being written.
    #[must_use]
    pub fn held(&self) -> Cost {
        Cost {
            frames: self.frames.load(Ordering::Acquire),
            bytes: self.bytes.load(Ordering::Acquire),
        }
    }

    /// Returns how many of the entries held are the host's own answers.
    #[must_use]
    pub fn held_replies(&self) -> usize {
        self.replies.load(Ordering::Acquire)
    }

    /// Says that answers wait in the lane, before the room is read for them.
    ///
    /// The writer gives room back without the input domain, so room can come back at any moment
    /// of a pass of the pump. The two sides agree through this flag and the counts, and each does
    /// its write before its read: the pump says that answers wait and then reads the room, and the
    /// writer gives the room back and then reads whether answers wait. A fence between each
    /// pair puts them in one order for both, so at least one of them sees the other: either the
    /// pump reads the room that came back, or the writer finds the flag set and wakes the pump.
    /// Neither takes a lock.
    pub(crate) fn publish_waiting_replies(&self) {
        self.replies_waiting.store(true, Ordering::SeqCst);
        fence(Ordering::SeqCst);
    }

    /// Records whether the response lane still holds answers after a drain.
    pub(crate) fn set_replies_waiting(&self, waiting: bool) {
        self.replies_waiting.store(waiting, Ordering::SeqCst);
    }

    /// Returns whether the response lane holds answers that the gate allows out, as the pump last
    /// found it.
    #[must_use]
    pub(crate) fn replies_waiting(&self) -> bool {
        self.replies_waiting.load(Ordering::SeqCst)
    }

    /// Wakes the pump if answers wait in the lane, once room has come back. The fence pairs with
    /// the one in [`Self::publish_waiting_replies`].
    fn wake_pump_if_replies_wait(&self) {
        fence(Ordering::SeqCst);
        if self.replies_waiting() {
            self.pump.notify_one();
        }
    }

    /// Records when the first answer that waits in the lane lapses, and returns whether that
    /// differs from what was recorded. Zero is no deadline: a clock reading of zero is the moment
    /// the session began, and no answer is offered then.
    pub(crate) fn set_reply_expiry(&self, at_ms: Option<u64>) -> bool {
        self.reply_expiry_ms
            .swap(at_ms.unwrap_or(0), Ordering::AcqRel)
            != at_ms.unwrap_or(0)
    }

    /// Returns when the first answer that waits in the lane lapses, when one waits.
    #[must_use]
    pub(crate) fn reply_expiry(&self) -> Option<u64> {
        Some(self.reply_expiry_ms.load(Ordering::Acquire)).filter(|at_ms| *at_ms != 0)
    }

    /// Returns what wakes the pump that serves the session.
    pub(crate) fn pump(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.pump)
    }

    /// Charges what a batch costs, as it is queued.
    pub(crate) fn charge(&self, batch: &InputBatch) {
        let cost = Cost::of(batch);
        self.frames.fetch_add(cost.frames, Ordering::AcqRel);
        self.bytes.fetch_add(cost.bytes, Ordering::AcqRel);
        if matches!(batch, InputBatch::Reply { .. }) {
            self.replies.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Takes the debt of one batch the writer has taken, which the writer pays back as it goes.
    pub(crate) fn owed_for(self: &Arc<Self>, batch: &InputBatch) -> Owed {
        Owed {
            room: Arc::clone(self),
            left: Cost::of(batch),
            reply: matches!(batch, InputBatch::Reply { .. }),
        }
    }

    /// Gives back what a batch was charged. It never gives back more than is held, so the count
    /// cannot pass below nothing: a mistake in what is given back would show as a count that is
    /// wrong, not as one that wraps and refuses every write for good.
    fn give_back(&self, cost: Cost) {
        self.give_back_counts(cost, 0);
    }

    /// As [`Self::give_back`], with the answers among the entries that go.
    fn give_back_counts(&self, cost: Cost, replies: usize) {
        for (held, cost) in [
            (&self.frames, cost.frames),
            (&self.bytes, cost.bytes),
            (&self.replies, replies),
        ] {
            if cost > 0 {
                let before = held
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                        Some(held.saturating_sub(cost))
                    })
                    .unwrap_or_default();
                debug_assert!(before >= cost, "more was given back than was charged");
            }
        }
    }
}

/// What the writer still owes the room for the batch it has taken.
///
/// The writer pays back the bytes the terminal takes as it writes them. Dropping what is left
/// pays the rest and the entry itself, which is how every way out of a batch settles it: written
/// whole, dropped as stale or expired, abandoned part way, or cut short by the writer ending.
#[derive(Debug)]
pub(crate) struct Owed {
    room: Arc<InputRoom>,
    left: Cost,
    /// Whether the entry is one of the host's own answers.
    reply: bool,
}

impl Owed {
    /// Gives back `bytes` the terminal has taken.
    pub(crate) fn written(&mut self, bytes: usize) {
        let bytes = bytes.min(self.left.bytes);
        self.left.bytes -= bytes;
        self.room.give_back(Cost { frames: 0, bytes });
    }
}

impl Drop for Owed {
    fn drop(&mut self) {
        self.room
            .give_back_counts(self.left, usize::from(self.reply));
        // What has come back may be the room that an answer in the lane waits for, and the lane is
        // the session's, which the writer does not take: the pump looks again.
        self.room.wake_pump_if_replies_wait();
    }
}
