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

/// An interval measured from a moment the host may have to re-anchor.
///
/// The continuous clock restarts with the machine, so a reading written down in one boot means
/// nothing in the next. An interval is therefore kept as how much of it had already passed at an
/// anchor, plus the continuous reading of that anchor. Re-anchoring is then arithmetic on the part
/// that is durable, and an interval that was already overdue stays overdue instead of being
/// clipped to however long this machine has been running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elapsed {
    at_anchor_ms: u64,
    anchor_continuous_ms: u64,
}

impl Elapsed {
    /// An interval that starts now.
    #[must_use]
    pub const fn starting(reading: HostReading) -> Self {
        Self {
            at_anchor_ms: 0,
            anchor_continuous_ms: reading.continuous_ms,
        }
    }

    /// An interval that had already run for `waited_ms` at this reading.
    #[must_use]
    pub const fn already(waited_ms: u64, reading: HostReading) -> Self {
        Self {
            at_anchor_ms: waited_ms,
            anchor_continuous_ms: reading.continuous_ms,
        }
    }

    /// How long the interval has run at this reading.
    #[must_use]
    pub const fn ms(self, reading: HostReading) -> u64 {
        self.at_anchor_ms.saturating_add(
            reading
                .continuous_ms
                .saturating_sub(self.anchor_continuous_ms),
        )
    }

    /// The continuous reading at which this interval reaches `after_ms`.
    ///
    /// An interval already past `after_ms` answers with its own anchor, which is in the past, so a
    /// caller that takes the earliest deadline wakes at once rather than waiting out an interval
    /// that has already run.
    #[must_use]
    pub const fn due_at(self, after_ms: u64) -> u64 {
        self.anchor_continuous_ms
            .saturating_add(after_ms.saturating_sub(self.at_anchor_ms))
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
    fn an_interval_keeps_what_had_already_passed_when_the_clock_restarts() {
        let before = HostReading::new(900_000, 5_000_000, true);
        let interval = Elapsed::already(240_000, before);
        assert_eq!(interval.ms(before), 240_000);
        assert_eq!(interval.ms(before.advanced(60_000)), 300_000);
        assert_eq!(interval.due_at(300_000), 960_000);

        // The machine restarted one second ago; the interval had still run for four minutes.
        let after = HostReading::new(1_000, 5_060_000, true);
        let reanchored = Elapsed::already(300_000, after);
        assert_eq!(
            reanchored.due_at(300_000),
            1_000,
            "an interval that is already overdue is due now, not in five more minutes"
        );
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
