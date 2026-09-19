//! What the host time contract answers, as the engine receives it.
//!
//! Nothing in this crate reads a clock. Every decision that depends on time takes a [`HostReading`]
//! from the caller, which is what makes the engine a state machine rather than a process: the same
//! events and the same readings produce the same outcomes on any machine, and a test drives an
//! escalation or a quiet-hours release by handing over the reading it wants rather than by waiting.
//!
//! Two clocks arrive, because two different questions are being asked:
//!
//! * **The continuous clock** measures intervals. A de-duplication window, an idle reminder and an
//!   escalation step are all "how long since", and the boot-scoped continuous clock answers that
//!   without anyone trusting anything. It counts suspended time, so a machine that slept through
//!   an idle interval still owes the reminder when it wakes.
//! * **The wall clock** decides quiet hours, which are a time of day rather than a duration. A host
//!   that cannot prove its wall clock cannot prove it is inside a quiet window, and
//!   [`HostReading::wall_proven`] carries that fact rather than hiding it.

use kr_protocol::scalars::TimestampMs;

/// Milliseconds in a day.
pub const MS_IN_DAY: u64 = 86_400_000;

/// Milliseconds in a minute.
pub const MS_IN_MINUTE: u64 = 60_000;

/// One reading of the host time contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostReading {
    /// The boot-scoped continuous clock, in milliseconds. Intervals are measured on this.
    pub continuous_ms: u64,
    /// What the wall clock reads, as the host time contract reports it.
    pub wall_ms: TimestampMs,
    /// Whether this host can prove that reading.
    ///
    /// False leaves quiet hours unenforced. A suppression decided on a clock the host cannot prove
    /// would withhold a notification at an hour nobody chose, and the failure that matters here is
    /// the silent one.
    pub wall_proven: bool,
}

impl HostReading {
    /// Builds a reading.
    #[must_use]
    pub const fn new(continuous_ms: u64, wall_ms: u64, wall_proven: bool) -> Self {
        Self {
            continuous_ms,
            wall_ms: TimestampMs::new(wall_ms),
            wall_proven,
        }
    }

    /// Returns the millisecond of the UTC day this reading falls in.
    #[must_use]
    pub const fn ms_of_day(&self) -> u64 {
        self.wall_ms.get() % MS_IN_DAY
    }

    /// Returns the minute of the UTC day this reading falls in.
    #[must_use]
    pub const fn minute_of_day(&self) -> u64 {
        self.ms_of_day() / MS_IN_MINUTE
    }

    /// Returns this reading advanced by `millis` on both clocks.
    ///
    /// The wall clock is advanced with the continuous one, which is what an undisturbed machine
    /// does. A test that wants them to disagree builds the second reading itself.
    #[must_use]
    pub const fn advanced(&self, millis: u64) -> Self {
        Self {
            continuous_ms: self.continuous_ms.saturating_add(millis),
            wall_ms: TimestampMs::new(self.wall_ms.get().saturating_add(millis)),
            wall_proven: self.wall_proven,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reading_reports_the_minute_of_the_utc_day_it_falls_in() {
        // 1970-01-02 03:04 UTC.
        let reading = HostReading::new(
            0,
            MS_IN_DAY + 3 * 60 * MS_IN_MINUTE + 4 * MS_IN_MINUTE,
            true,
        );
        assert_eq!(reading.minute_of_day(), 3 * 60 + 4);
        assert_eq!(reading.ms_of_day(), (3 * 60 + 4) * MS_IN_MINUTE);
    }

    #[test]
    fn advancing_a_reading_moves_both_clocks_together() {
        let reading = HostReading::new(1_000, 5_000, true);
        let later = reading.advanced(2_500);
        assert_eq!(later.continuous_ms, 3_500);
        assert_eq!(later.wall_ms.get(), 7_500);
        assert!(later.wall_proven);
    }
}
