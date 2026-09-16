//! The clock expiries are measured on.
//!
//! An expiry is a wall-clock instant, because it is a retention policy rather than an authority
//! deadline: "twenty-four hours" has to survive a restart and a suspend, which a process-anchored
//! reading does not. Authority deadlines are the transport's own continuous clock and are decided
//! before a request reaches this service; nothing here lengthens one.

use kr_protocol::scalars::TimestampMs;

/// The clock this service reads expiries from.
pub trait Clock: std::fmt::Debug + Send + Sync {
    /// Returns the current wall-clock instant, in milliseconds since the Unix epoch.
    fn now_ms(&self) -> TimestampMs;
}

/// The operating system's wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> TimestampMs {
        kr_ipc::now_ms()
    }
}

/// A clock the caller sets.
///
/// An expiry sweep runs at an instant the caller chooses, so a host reconciling a long suspend, or
/// a test covering the twenty-four-hour and seven-day windows, drives this rather than waiting.
#[derive(Debug)]
pub struct ManualClock {
    now_ms: std::sync::atomic::AtomicU64,
}

impl ManualClock {
    /// Creates a clock reading `now_ms`.
    #[must_use]
    pub fn new(now_ms: u64) -> Self {
        Self {
            now_ms: std::sync::atomic::AtomicU64::new(now_ms),
        }
    }

    /// Sets the instant this clock reads.
    pub fn set(&self, now_ms: u64) {
        self.now_ms
            .store(now_ms, std::sync::atomic::Ordering::SeqCst);
    }

    /// Moves this clock forward.
    pub fn advance(&self, millis: u64) {
        self.now_ms
            .fetch_add(millis, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> TimestampMs {
        TimestampMs::new(self.now_ms.load(std::sync::atomic::Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manual_clock_reads_what_it_was_set_to() {
        let clock = ManualClock::new(1000);
        assert_eq!(clock.now_ms(), TimestampMs::new(1000));
        clock.advance(500);
        assert_eq!(clock.now_ms(), TimestampMs::new(1500));
        clock.set(7);
        assert_eq!(clock.now_ms(), TimestampMs::new(7));
    }

    #[test]
    fn the_system_clock_moves_forward() {
        let clock = SystemClock;
        assert!(clock.now_ms().get() > 0);
    }
}
