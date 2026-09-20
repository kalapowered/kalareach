//! The clock readings this crate is given, and never takes.
//!
//! Nothing here reads a clock. Every decision that depends on time takes a [`Reading`] from the
//! caller, which is what makes a thirty-second cooldown, a two-second debounce, a fifteen-minute
//! idle unload and a thirty-second execution deadline testable without waiting for any of them.
//!
//! Two clocks arrive together because they answer different questions. The continuous one measures
//! intervals and needs nobody's trust: it is monotonic within one boot, so an aging position, a
//! cooldown and a deadline are all differences on it. The wall clock says *when* something happened
//! for a person reading it, and it is the one a last-success time is shown from. No interval here
//! is ever worked out from two wall-clock readings, because a clock somebody can set forward is not
//! a scale two readings share.

use kr_protocol::scalars::TimestampMs;

/// One reading of both clocks, taken at the same moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reading {
    monotonic_ms: u64,
    wall_ms: TimestampMs,
}

impl Reading {
    /// Builds a reading from the continuous clock and the wall clock.
    #[must_use]
    pub const fn new(monotonic_ms: u64, wall_ms: u64) -> Self {
        Self {
            monotonic_ms,
            wall_ms: TimestampMs::new(wall_ms),
        }
    }

    /// Returns the boot-scoped continuous reading, in milliseconds.
    #[must_use]
    pub const fn monotonic_ms(self) -> u64 {
        self.monotonic_ms
    }

    /// Returns the wall-clock moment.
    #[must_use]
    pub const fn wall_ms(self) -> TimestampMs {
        self.wall_ms
    }

    /// Returns how long has passed since an earlier continuous reading.
    ///
    /// A reading that is somehow earlier than the one it is compared with answers nought rather
    /// than wrapping, because a negative interval is not a shorter one.
    #[must_use]
    pub const fn since_ms(self, earlier_monotonic_ms: u64) -> u64 {
        self.monotonic_ms.saturating_sub(earlier_monotonic_ms)
    }

    /// Returns this reading advanced by an interval, which is what a test drives a deadline with.
    #[must_use]
    pub const fn after_ms(self, interval_ms: u64) -> Self {
        Self {
            monotonic_ms: self.monotonic_ms.saturating_add(interval_ms),
            wall_ms: TimestampMs::new(self.wall_ms.get().saturating_add(interval_ms)),
        }
    }
}
