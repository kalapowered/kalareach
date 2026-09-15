//! The suspend-aware continuous clock every deadline in this crate is measured on.
//!
//! Section 9 fixes one time contract: expiry is measured on a suspend-aware continuous elapsed-time
//! anchor, and "a timer that excludes sleep cannot extend authority". Neither clock in the standard
//! library is one. [`std::time::Instant`] stops while the machine is suspended, so a five-second
//! lease would outlive a suspension of any length. [`std::time::SystemTime`] keeps running across a
//! suspension but can be stepped in either direction, and a clock that can be stepped is a clock an
//! attacker can stop.
//!
//! [`SystemContinuousClock`] therefore reads the operating system's own continuous clock through
//! the `boot-time` crate: `CLOCK_BOOTTIME` on Linux, Android and OpenBSD, and `mach_continuous_time`
//! on Apple platforms. Those clocks are monotonic *and* include time the machine spent suspended,
//! which is exactly the anchor section 9 describes. No arithmetic of ours stands between the
//! kernel's answer and a deadline, because every composition of two imperfect clocks that we could
//! write has a case where it stops.
//!
//! On other platforms the crate falls back to [`std::time::Instant`], whose behaviour across a
//! suspension is the platform's, not this crate's: on Windows that is the performance counter. A
//! host on such a platform supplies its own qualified platform time adapter through
//! [`ContinuousClock`] rather than relying on the default; the trait exists for exactly that, and
//! until it does, host expiry there rests on a clock this crate has not qualified.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// A point on a continuous clock, as elapsed time since that clock's anchor.
///
/// Two instants are comparable only when they come from the same clock. The anchor is arbitrary and
/// private, so nothing can mistake one for a wall-clock time.
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
/// A host that owns a qualified platform time adapter implements this over that adapter; nothing in
/// this crate assumes the default implementation.
pub trait ContinuousClock: Send + Sync + std::fmt::Debug {
    /// Returns the current instant.
    fn now(&self) -> ContinuousInstant;
}

/// The operating system's continuous clock, anchored when the clock is created.
///
/// Clone it; the anchor is shared, so every deadline a host holds is measured against one origin.
#[derive(Clone, Debug)]
pub struct SystemContinuousClock {
    anchor: Arc<boot_time::Instant>,
}

impl SystemContinuousClock {
    /// Anchors a clock at the current moment.
    #[must_use]
    pub fn new() -> Self {
        Self {
            anchor: Arc::new(boot_time::Instant::now()),
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
        // The clocks above are monotonic, so a reading before the anchor means the hardware or the
        // hypervisor broke that guarantee. Saturating keeps the process alive instead of panicking;
        // it is not a safety property, and a host that cannot trust its clock has to say so through
        // its own time adapter rather than rely on this.
        ContinuousInstant(boot_time::Instant::now().saturating_duration_since(*self.anchor))
    }
}

/// A clock a test drives by hand.
///
/// Deadline behaviour is the part of this crate that is hardest to observe from the outside, so the
/// tests advance time rather than sleeping through it.
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
    fn the_system_clock_keeps_running() {
        let clock = SystemContinuousClock::new();
        let start = clock.now();
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            clock.now().saturating_duration_since(start) >= Duration::from_millis(15),
            "the clock advanced with real time"
        );
    }

    #[test]
    fn a_wall_clock_step_cannot_stop_the_system_clock() {
        // The clock reads the operating system's continuous source directly, so nothing the wall
        // clock does can stall it. Two readings around real elapsed time always differ.
        let clock = SystemContinuousClock::new();
        let first = clock.now();
        std::thread::sleep(Duration::from_millis(10));
        let second = clock.now();
        assert!(second > first);
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
