//! The suspend-aware continuous clock every deadline in this crate is measured on.
//!
//! Section 9 fixes one time contract: expiry is measured on a suspend-aware continuous elapsed
//! time anchor, and "a timer that excludes sleep cannot extend authority". Neither of the clocks
//! the standard library offers satisfies that on its own:
//!
//! * [`std::time::Instant`] is monotonic but stops while the machine is suspended on every
//!   platform this product ships to, so a five-second lease would survive a suspension of any
//!   length.
//! * [`std::time::SystemTime`] keeps running across a suspension but can step backwards, and a
//!   rollback must never enlarge a lifetime.
//!
//! [`ContinuousClock`] combines them so that each covers the other's failure: elapsed time is the
//! larger of the two measurements, and the result is held to a high-water mark so it can never go
//! backwards. That is conservative in the only direction the specification permits. A suspension
//! shows up as wall-clock movement the monotonic clock did not see, so authority expires. A
//! forward wall-clock step expires objects early, which section 9 allows outright. A backward
//! step is simply not observed, because a smaller measurement never wins.
//!
//! The clock needs no platform matrix and no unsafe code, which is why it is built this way rather
//! than from `CLOCK_BOOTTIME` and its differently named equivalents.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// A point on a continuous clock, as elapsed time since that clock's anchor.
///
/// Two instants are comparable only when they come from the same clock. The anchor is arbitrary
/// and private, so nothing can mistake one for a wall-clock time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContinuousInstant(Duration);

impl ContinuousInstant {
    /// Returns how much time passed between `earlier` and this instant, saturating at zero.
    #[must_use]
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.0.saturating_sub(earlier.0)
    }

    /// Returns this instant advanced by `duration`, or `None` on overflow.
    #[must_use]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(Self)
    }

    /// Returns the elapsed time since the clock's anchor.
    ///
    /// Only diagnostics should need this. Comparisons use the ordering.
    #[must_use]
    pub const fn since_anchor(self) -> Duration {
        self.0
    }
}

/// Reads the suspend-aware continuous clock.
///
/// A host that owns a qualified platform time adapter implements this over that adapter; nothing
/// in this crate assumes the default implementation.
pub trait ContinuousClock: Send + Sync + std::fmt::Debug {
    /// Returns the current instant.
    fn now(&self) -> ContinuousInstant;
}

/// The default clock: monotonic and wall-clock readings, whichever has advanced further.
///
/// One instance holds the anchor for every instant it produces, so all of a host's deadlines are
/// measured against the same origin. Clone it; the anchor and the high-water mark are shared.
#[derive(Clone, Debug)]
pub struct SystemContinuousClock {
    inner: Arc<Anchor>,
}

#[derive(Debug)]
struct Anchor {
    monotonic: Instant,
    wall: SystemTime,
    /// The largest elapsed time observed so far, in nanoseconds. It makes the clock monotonic even
    /// if a reading regresses.
    high_water_nanos: AtomicU64,
}

impl SystemContinuousClock {
    /// Anchors a clock at the current moment.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Anchor {
                monotonic: Instant::now(),
                wall: SystemTime::now(),
                high_water_nanos: AtomicU64::new(0),
            }),
        }
    }
}

impl Default for SystemContinuousClock {
    fn default() -> Self {
        Self::new()
    }
}

impl ContinuousClock for SystemContinuousClock {
    fn now(&self) -> ContinuousInstant {
        let monotonic = self.inner.monotonic.elapsed();
        // A backward wall clock yields an error, which is exactly the case where the wall reading
        // must not contribute: it would shorten nothing and could only pull the maximum down.
        let wall = self
            .inner
            .wall
            .elapsed()
            .unwrap_or_else(|_| Duration::from_secs(0));
        let observed = monotonic.max(wall);
        let nanos = u64::try_from(observed.as_nanos()).unwrap_or(u64::MAX);
        let previous = self
            .inner
            .high_water_nanos
            .fetch_max(nanos, Ordering::AcqRel);
        ContinuousInstant(Duration::from_nanos(nanos.max(previous)))
    }
}

/// A clock a test drives by hand.
///
/// Deadline behaviour is the part of this crate that is hardest to observe from the outside, so
/// the tests advance time rather than sleeping through it.
#[derive(Clone, Debug, Default)]
pub struct ManualClock {
    nanos: Arc<AtomicU64>,
}

impl ManualClock {
    /// Creates a clock anchored at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Advances the clock.
    pub fn advance(&self, duration: Duration) {
        let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        self.nanos.fetch_add(nanos, Ordering::AcqRel);
    }
}

impl ContinuousClock for ManualClock {
    fn now(&self) -> ContinuousInstant {
        ContinuousInstant(Duration::from_nanos(self.nanos.load(Ordering::Acquire)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_clock_never_goes_backwards() {
        let clock = SystemContinuousClock::new();
        let first = clock.now();
        let second = clock.now();
        assert!(second >= first);
        assert_eq!(second.saturating_duration_since(second), Duration::ZERO);
    }

    #[test]
    fn a_manual_clock_advances_exactly_as_told() {
        let clock = ManualClock::new();
        let start = clock.now();
        clock.advance(Duration::from_millis(5_000));
        let later = clock.now();
        assert_eq!(
            later.saturating_duration_since(start),
            Duration::from_millis(5_000)
        );
        assert_eq!(start.saturating_duration_since(later), Duration::ZERO);
    }

    #[test]
    fn an_instant_advanced_by_a_duration_compares_after_it() {
        let clock = ManualClock::new();
        let start = clock.now();
        let deadline = start
            .checked_add(Duration::from_secs(5))
            .expect("a deadline five seconds out");
        assert!(deadline > start);
        clock.advance(Duration::from_secs(4));
        assert!(clock.now() < deadline);
        clock.advance(Duration::from_secs(2));
        assert!(clock.now() > deadline);
    }
}
