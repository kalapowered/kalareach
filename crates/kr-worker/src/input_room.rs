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
use std::sync::atomic::{AtomicUsize, Ordering};

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

    /// Charges what a batch costs, as it is queued.
    pub(crate) fn charge(&self, cost: Cost) {
        self.frames.fetch_add(cost.frames, Ordering::AcqRel);
        self.bytes.fetch_add(cost.bytes, Ordering::AcqRel);
    }

    /// Takes the debt of one batch the writer has taken, which the writer pays back as it goes.
    pub(crate) fn owed_for(self: &Arc<Self>, batch: &InputBatch) -> Owed {
        Owed {
            room: Arc::clone(self),
            left: Cost::of(batch),
        }
    }

    /// Gives back what a batch was charged. It never gives back more than is held, so the count
    /// cannot pass below nothing: a mistake in what is given back would show as a count that is
    /// wrong, not as one that wraps and refuses every write for good.
    fn give_back(&self, cost: Cost) {
        for (held, cost) in [(&self.frames, cost.frames), (&self.bytes, cost.bytes)] {
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
        self.room.give_back(self.left);
    }
}
