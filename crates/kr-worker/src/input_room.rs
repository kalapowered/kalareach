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

    /// Returns what is left of this after `other`, in each count, never below nothing.
    #[must_use]
    pub const fn minus(self, other: Self) -> Self {
        Self {
            frames: self.frames.saturating_sub(other.frames),
            bytes: self.bytes.saturating_sub(other.bytes),
        }
    }

    /// Returns the smaller of the two in each count.
    #[must_use]
    pub const fn least(self, other: Self) -> Self {
        Self {
            frames: if self.frames < other.frames {
                self.frames
            } else {
                other.frames
            },
            bytes: if self.bytes < other.bytes {
                self.bytes
            } else {
                other.bytes
            },
        }
    }

    /// Whether `self` is at most `other` in both counts.
    #[must_use]
    pub const fn within(self, other: Self) -> bool {
        self.frames <= other.frames && self.bytes <= other.bytes
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
        // The host's credit is counted in the same unit, so the two sides cannot differ.
        let claim = kr_protocol::input::input_claim(bytes);
        Self {
            frames: claim.frames,
            bytes: claim.bytes,
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

/// What the room holds in all: the bound that every producer shares.
pub const ROOM: Cost = Cost {
    frames: MAX_QUEUED_INPUT_FRAMES,
    bytes: MAX_QUEUED_INPUT_BYTES,
};

/// What the room reserves for the view that holds the keys, so that its frames, which the host
/// sends on credit, are never refused for room: 64 entries and 512 KiB of claims.
pub const LANE_WINDOW: Cost = Cost {
    frames: 64,
    bytes: 512 * 1024,
};

/// The room's terms at one moment, read in one hold of the input domain.
///
/// `held` is what is queued for the terminal, with the writer, or held by the root editor's
/// machine: the actual cost, given back by the writer. `promised` is what an accepted write may
/// still add, its claim less what it was charged when it was accepted, given back whole when the
/// last piece of the write is done with. `reserved` is the unused part of the window. `free` is
/// what is left of the room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ledger {
    /// What the worker holds for the terminal.
    pub held: Cost,
    /// What the window keeps for its lane's frames.
    pub reserved: Cost,
    /// What accepted writes may still add.
    pub promised: Cost,
    /// The rest of the room.
    pub free: Cost,
    /// The claims of the window's frames that are not yet done with.
    pub outstanding: Cost,
}

/// What the top-up waits for: set when a count fell, so that a window which a give-back could
/// have made larger is made larger by the next top-up that reads the counters.
#[derive(Debug, Default)]
pub struct TopUp {
    due: AtomicBool,
    wake: tokio::sync::Notify,
}

impl TopUp {
    /// Says a count fell, and wakes the task that tops the window up. It takes no lock, so a drop
    /// can call it wherever it happens.
    pub fn request(&self) {
        self.due.store(true, Ordering::Release);
        self.wake.notify_one();
    }

    /// Takes the request: true when one was made since the last time. A top-up calls this before
    /// it reads the counters, so a give-back that comes after the read asks again.
    pub fn take(&self) -> bool {
        self.due.swap(false, Ordering::AcqRel)
    }

    /// Says whether a request is waiting, without taking it.
    #[cfg(test)]
    pub(crate) fn is_due(&self) -> bool {
        self.due.load(Ordering::Acquire)
    }

    /// Waits for a request.
    pub async fn asked(&self) {
        self.wake.notified().await;
    }
}

/// The claims of one window's frames that are not yet done with.
///
/// Each window has a counter of its own, and a guard holds the counter of the window it was
/// accepted under, so a stale guard that drops after a takeover lowers the old window's count and
/// never the new one's.
#[derive(Debug, Default)]
pub struct Outstanding {
    frames: AtomicUsize,
    bytes: AtomicUsize,
}

impl Outstanding {
    /// Returns what is outstanding.
    #[must_use]
    pub fn get(&self) -> Cost {
        Cost {
            frames: self.frames.load(Ordering::Acquire),
            bytes: self.bytes.load(Ordering::Acquire),
        }
    }

    fn add(&self, cost: Cost) {
        self.frames.fetch_add(cost.frames, Ordering::AcqRel);
        self.bytes.fetch_add(cost.bytes, Ordering::AcqRel);
    }

    fn sub(&self, cost: Cost) {
        sub_clamped(&self.frames, cost.frames);
        sub_clamped(&self.bytes, cost.bytes);
    }
}

/// Subtracts without passing below nothing: a count that is wrong stays small and shows, and
/// never wraps and refuses every write for good.
fn sub_clamped(count: &AtomicUsize, amount: usize) {
    if amount > 0 {
        let before = count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                Some(held.saturating_sub(amount))
            })
            .unwrap_or_default();
        debug_assert!(before >= amount, "more was given back than was charged");
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
    /// What accepted writes may still add: entries and bytes.
    promised_frames: AtomicUsize,
    promised_bytes: AtomicUsize,
    topup: TopUp,
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

    /// Returns what accepted writes may still add to what is held.
    #[must_use]
    pub fn promised(&self) -> Cost {
        Cost {
            frames: self.promised_frames.load(Ordering::Acquire),
            bytes: self.promised_bytes.load(Ordering::Acquire),
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

    /// Returns the request that the window's top-up waits for.
    #[must_use]
    pub const fn topup(&self) -> &TopUp {
        &self.topup
    }

    /// Charges what a batch costs, as it is queued, and returns the debt that travels with it.
    pub(crate) fn charge(self: &Arc<Self>, batch: &InputBatch) -> Debt {
        let cost = Cost::of(batch);
        self.frames.fetch_add(cost.frames, Ordering::AcqRel);
        self.bytes.fetch_add(cost.bytes, Ordering::AcqRel);
        let reply = matches!(batch, InputBatch::Reply { .. });
        if reply {
            self.replies.fetch_add(1, Ordering::AcqRel);
        }
        Debt {
            room: Arc::clone(self),
            left: cost,
            reply,
        }
    }

    /// Takes the debt of one batch that is charged and whose debt a harness left charged, which the
    /// harness settles by dropping what it takes here.
    pub(crate) fn owed_for(self: &Arc<Self>, batch: &InputBatch) -> Debt {
        Debt {
            room: Arc::clone(self),
            left: Cost::of(batch),
            reply: matches!(batch, InputBatch::Reply { .. }),
        }
    }

    /// Gives back what a batch was charged. It never gives back more than is held, so the count
    /// cannot pass below nothing: a mistake in what is given back would show as a count that is
    /// wrong, not as one that wraps and refuses every write for good.
    fn give_back_counts(&self, cost: Cost, replies: usize) {
        sub_clamped(&self.frames, cost.frames);
        sub_clamped(&self.bytes, cost.bytes);
        sub_clamped(&self.replies, replies);
    }

    fn promise(&self, cost: Cost) {
        self.promised_frames
            .fetch_add(cost.frames, Ordering::AcqRel);
        self.promised_bytes.fetch_add(cost.bytes, Ordering::AcqRel);
    }

    fn unpromise(&self, cost: Cost) {
        sub_clamped(&self.promised_frames, cost.frames);
        sub_clamped(&self.promised_bytes, cost.bytes);
    }
}

/// What a queued batch still owes the room for its storage.
///
/// It starts when the batch is charged and travels with the batch, through the queue, the writer's
/// channel and the write. The writer pays back the bytes the terminal takes as it writes them.
/// Dropping what is left pays the rest and the entry itself, which is how every way out of a batch
/// settles it: written whole, dropped as stale or expired, abandoned part way, never received by
/// the writer, or cut short by the writer ending.
#[derive(Debug)]
pub struct Debt {
    room: Arc<InputRoom>,
    left: Cost,
    /// Whether the entry is one of the host's own answers.
    reply: bool,
}

impl Debt {
    /// Leaves what is still owed charged to the room, so that dropping the debt gives nothing back.
    fn leave_charged(&mut self) {
        self.left = Cost::default();
        self.reply = false;
    }

    /// Gives back `bytes` the terminal has taken.
    pub(crate) fn written(&mut self, bytes: usize) {
        let bytes = bytes.min(self.left.bytes);
        self.left.bytes -= bytes;
        self.room.give_back_counts(Cost { frames: 0, bytes }, 0);
        self.room.topup.request();
    }
}

impl Drop for Debt {
    fn drop(&mut self) {
        self.room
            .give_back_counts(self.left, usize::from(self.reply));
        // What has come back may be the room that an answer in the lane waits for, and the lane is
        // the session's, which the writer does not take: the pump looks again.
        self.room.wake_pump_if_replies_wait();
        self.room.topup.request();
    }
}

/// What one accepted write is still promised against the room.
///
/// Its promise is its claim less what it was charged when it was accepted, and it is given back
/// whole when the last piece of the write is done with, and not before: every piece carries the
/// guard, the batches it makes, the prefix the recogniser holds back, and what the root editor's
/// machine holds. Nothing gives a part of it back earlier, because the guard knows no part. A
/// waiting later entry is therefore counted twice for a while, in `held` and in `promised`, which
/// errs on the side of refusing.
///
/// A guard takes no lock when it drops: it lowers atomic counters and asks for a top-up. It holds
/// the room's ledger and the window's counter, and nothing of the session's input state.
#[derive(Debug)]
pub struct ClaimGuard {
    room: Arc<InputRoom>,
    promise: Cost,
    /// The claim, and the counter of the window the write was accepted under, for a frame of a
    /// lane.
    window: Option<(Cost, Arc<Outstanding>)>,
}

impl ClaimGuard {
    /// Guards a write of `claim` that was charged `charge` now, under `window` when it is a
    /// lane's.
    pub(crate) fn new(
        room: &Arc<InputRoom>,
        claim: Cost,
        charge: Cost,
        window: Option<Arc<Outstanding>>,
    ) -> Arc<Self> {
        let promise = claim.minus(charge);
        room.promise(promise);
        let window = window.map(|outstanding| {
            outstanding.add(claim);
            (claim, outstanding)
        });
        Arc::new(Self {
            room: Arc::clone(room),
            promise,
            window,
        })
    }
}

impl Drop for ClaimGuard {
    fn drop(&mut self) {
        self.room.unpromise(self.promise);
        if let Some((claim, outstanding)) = self.window.take() {
            outstanding.sub(claim);
        }
        // The counters are lower first and the request comes after, so a top-up that took the
        // request before this line reads them again when this one asks.
        self.room.topup.request();
    }
}

/// A batch on its way to the terminal, with what it owes and what guards it.
///
/// The batch itself is plain data that can be compared and cloned; what must not be cloned, the
/// debt for its storage and the guard of the write it came from, rides beside it.
#[derive(Debug)]
pub struct Carried {
    /// The batch.
    pub batch: InputBatch,
    /// What it owes the room, from the moment it was charged. A batch the root editor's machine
    /// holds has none yet: the machine's own count carries it until it is released.
    pub(crate) debt: Option<Debt>,
    /// The guard of the write the batch came from, none for the host's own answers. Nothing reads
    /// it: it is held so that the claim returns when the batch is dropped.
    #[allow(dead_code)]
    pub(crate) guard: Option<Arc<ClaimGuard>>,
}

impl Carried {
    /// A batch with no write behind it to guard, and nothing charged yet.
    #[must_use]
    pub const fn plain(batch: InputBatch) -> Self {
        Self {
            batch,
            debt: None,
            guard: None,
        }
    }

    /// A batch of a write that has a guard.
    pub(crate) const fn guarded(batch: InputBatch, guard: Option<Arc<ClaimGuard>>) -> Self {
        Self {
            batch,
            debt: None,
            guard,
        }
    }

    /// Returns how many bytes the batch holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.batch.len()
    }

    /// Returns whether the batch carries no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.batch.is_empty()
    }

    /// Takes the plain batch out. What it owed and its guard are dropped, which gives them back.
    #[must_use]
    pub fn into_batch(self) -> InputBatch {
        self.batch
    }

    /// Takes the plain batch out and leaves what it was charged in the room, for a harness that
    /// plays the writer and settles what it took itself. The guard of its write is dropped.
    pub(crate) fn into_batch_still_charged(mut self) -> InputBatch {
        if let Some(debt) = self.debt.as_mut() {
            debt.leave_charged();
        }
        self.batch
    }
}
