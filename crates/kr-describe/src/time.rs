//! The clock readings this crate is given, and the one interval it measures for itself.
//!
//! Every decision that depends on time takes a [`Reading`] from the caller, which is what makes a
//! thirty-second cooldown, a two-second debounce and a fifteen-minute idle unload testable without
//! waiting for any of them. The exception is the execution deadline. It runs from dequeue to
//! publication, which is inside one call, so no caller can hand a reading in halfway through:
//! [`JobClock`] is the clock that interval is measured on, and a test drives it by hand for the
//! same reason every other interval here takes a reading.
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

/// The clock one running job is measured against.
///
/// Every *decision* in this crate still takes a [`Reading`] from its caller. This is the one
/// interval a caller cannot supply: the execution deadline runs from dequeue to publication, which
/// is inside a single call, so whatever measures it has to read a clock during that call. A host
/// takes [`JobClock::monotonic`], which is the process's own continuous clock. A test takes
/// [`JobClock::by_hand`] and moves it, which is how a thirty-second deadline and a load that
/// outruns it are driven by tests that finish in microseconds.
#[derive(Clone, Debug)]
pub struct JobClock(std::sync::Arc<Face>);

/// Which clock a [`JobClock`] is reading.
#[derive(Debug)]
enum Face {
    /// The process's continuous clock, from the moment this one was built.
    Continuous(std::time::Instant),
    /// A reading somebody moves, in milliseconds.
    ByHand(std::sync::atomic::AtomicU64),
}

impl JobClock {
    /// Builds a clock over the process's own continuous clock, which is what a host runs on.
    #[must_use]
    pub fn monotonic() -> Self {
        Self(std::sync::Arc::new(Face::Continuous(
            std::time::Instant::now(),
        )))
    }

    /// Builds a clock at nought that moves only when [`JobClock::advance_ms`] moves it.
    #[must_use]
    pub fn by_hand() -> Self {
        Self::by_hand_at(0)
    }

    /// Builds a clock at a given initial reading that moves only when [`JobClock::advance_ms`] moves it.
    #[must_use]
    pub fn by_hand_at(initial_ms: u64) -> Self {
        Self(std::sync::Arc::new(Face::ByHand(
            std::sync::atomic::AtomicU64::new(initial_ms),
        )))
    }

    /// Returns the reading now, in milliseconds since this clock was built.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        match &*self.0 {
            Face::Continuous(since) => {
                u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
            }
            Face::ByHand(held) => held.load(std::sync::atomic::Ordering::Acquire),
        }
    }

    /// Moves a clock that is moved by hand.
    ///
    /// The continuous clock moves itself, so it ignores this rather than pretending to jump: a
    /// product that could move its own deadline forward would have a deadline that means nothing.
    pub fn advance_ms(&self, interval_ms: u64) {
        if let Face::ByHand(held) = &*self.0 {
            let _ = held.fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |reading| Some(reading.saturating_add(interval_ms)),
            );
        }
    }
}

impl Default for JobClock {
    fn default() -> Self {
        Self::monotonic()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reading_arithmetic() {
        let r = Reading::new(100, 200);
        assert_eq!(r.monotonic_ms(), 100);
        assert_eq!(r.wall_ms().get(), 200);
        assert_eq!(r.since_ms(50), 50);
        assert_eq!(r.since_ms(150), 0);
        let next = r.after_ms(50);
        assert_eq!(next.monotonic_ms(), 150);
        assert_eq!(next.wall_ms().get(), 250);
    }

    #[test]
    fn job_clock_by_hand_advances() {
        let clock = JobClock::by_hand();
        assert_eq!(clock.now_ms(), 0);
        clock.advance_ms(500);
        assert_eq!(clock.now_ms(), 500);
        let clone = clock.clone();
        clone.advance_ms(250);
        assert_eq!(clock.now_ms(), 750);
    }

    #[test]
    fn job_clock_monotonic_cannot_be_advanced_by_hand() {
        let clock = JobClock::monotonic();
        let before = clock.now_ms();
        clock.advance_ms(10_000);
        let after = clock.now_ms();
        assert!(after.saturating_sub(before) < 1000);
    }
}
