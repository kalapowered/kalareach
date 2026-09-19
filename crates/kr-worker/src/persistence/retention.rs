//! What retained output is kept, for how long, and what its removal leaves behind.
//!
//! Section 20: *keep local session output for seven days with a 1 GiB host-wide cap and a 128 MiB
//! per-session cap; use the first applicable limit.* And then, in the paragraph after it: *these
//! are simultaneous upper bounds, not reserved capacity for every session. A busy host can evict
//! an individual session's oldest retained output before its own cap, with explicit history-gap
//! cursors.*
//!
//! Three things follow from reading those two paragraphs together.
//!
//! * **All three bounds hold at once.** A session inside its own 128 MiB is still evicted when
//!   the host is over 1 GiB, because the host bound is not a sum of per-session allowances. The
//!   session cap is a ceiling, never a reservation.
//! * **"The first applicable limit" names which bound is doing the work**, not which one to check
//!   instead of the others. It is what a person is told and what an eviction records, so a person
//!   looking at a gap can see whether their own session was large or the host was busy.
//! * **Nothing is removed quietly.** Every eviction produces a cursor range, and a reader asking
//!   for a cursor inside it is told the range is gone rather than served a shorter answer.
//!
//! Receipts are not part of any of this. Section 20 gives them a separately budgeted store and 30
//! days, so history pressure cannot delete a live dispatch barrier or a de-duplication record.

use std::time::Duration;

use kr_protocol::recovery::HistoryGap;
use kr_protocol::scalars::{TimestampMs, U64};

/// How long retained session output is kept.
pub const OUTPUT_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The host-wide cap on retained session output, in bytes.
pub const HOST_CAP_BYTES: u64 = 1024 * 1024 * 1024;

/// The per-session cap on retained session output, in bytes.
pub const SESSION_CAP_BYTES: u64 = 128 * 1024 * 1024;

/// Which bound forced an eviction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RetentionLimit {
    /// Output older than the retention period.
    Age,
    /// The host-wide byte cap.
    HostCap,
    /// This session's own byte cap.
    SessionCap,
}

impl RetentionLimit {
    /// Every limit, in the order section 20 states them.
    ///
    /// The order is what "the first applicable limit" refers to, so it is fixed here rather than
    /// left to whichever check a caller happens to run first.
    pub const ALL: &'static [Self] = &[Self::Age, Self::HostCap, Self::SessionCap];

    /// Returns the stable name this limit is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Age => "age",
            Self::HostCap => "host_cap",
            Self::SessionCap => "session_cap",
        }
    }
}

/// What one session and its host are holding now.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pressure {
    /// Retained output bytes in this session.
    pub session_bytes: u64,
    /// Retained output bytes across every session on this host, including this one.
    pub host_bytes: u64,
    /// When the oldest retained output in this session was produced.
    pub oldest_at_ms: Option<TimestampMs>,
}

/// The retention this host applies to session output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputRetention {
    /// How long output is kept.
    pub max_age: Duration,
    /// The host-wide byte cap.
    pub host_cap_bytes: u64,
    /// The per-session byte cap.
    pub session_cap_bytes: u64,
}

impl Default for OutputRetention {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl OutputRetention {
    /// Section 20's own figures.
    pub const DEFAULT: Self = Self {
        max_age: OUTPUT_RETENTION,
        host_cap_bytes: HOST_CAP_BYTES,
        session_cap_bytes: SESSION_CAP_BYTES,
    };

    /// Builds a retention with other figures, for a host that is configured differently.
    #[must_use]
    pub const fn new(max_age: Duration, host_cap_bytes: u64, session_cap_bytes: u64) -> Self {
        Self {
            max_age,
            host_cap_bytes,
            session_cap_bytes,
        }
    }

    /// Returns the instant before which output is past its retention.
    #[must_use]
    pub fn expires_before(self, now_ms: TimestampMs) -> TimestampMs {
        let age = u64::try_from(self.max_age.as_millis()).unwrap_or(u64::MAX);
        TimestampMs::new(now_ms.get().saturating_sub(age))
    }

    /// Returns whether one limit applies under this pressure.
    #[must_use]
    pub fn applies(self, limit: RetentionLimit, pressure: &Pressure, now_ms: TimestampMs) -> bool {
        match limit {
            RetentionLimit::Age => pressure
                .oldest_at_ms
                .is_some_and(|oldest| oldest < self.expires_before(now_ms)),
            RetentionLimit::HostCap => pressure.host_bytes > self.host_cap_bytes,
            RetentionLimit::SessionCap => pressure.session_bytes > self.session_cap_bytes,
        }
    }

    /// Returns the first limit that applies, in the order section 20 states them.
    #[must_use]
    pub fn first_applicable(
        self,
        pressure: &Pressure,
        now_ms: TimestampMs,
    ) -> Option<RetentionLimit> {
        RetentionLimit::ALL
            .iter()
            .copied()
            .find(|limit| self.applies(*limit, pressure, now_ms))
    }

    /// Returns how many bytes this session gives up so every cap holds at once.
    ///
    /// The host cap is not divided between sessions, so a session under pressure from it gives up
    /// what the host is over by, bounded by what the session actually holds. Whichever of the two
    /// caps asks for more is what applies, because both are upper bounds and both have to hold.
    #[must_use]
    pub fn bytes_over_cap(self, pressure: &Pressure) -> u64 {
        let over_host = pressure
            .host_bytes
            .saturating_sub(self.host_cap_bytes)
            .min(pressure.session_bytes);
        let over_session = pressure
            .session_bytes
            .saturating_sub(self.session_cap_bytes);
        over_host.max(over_session)
    }
}

/// One eviction, and the cursor range it left behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Eviction {
    /// Which bound forced it.
    pub limit: RetentionLimit,
    /// The first cursor that is gone.
    pub from_cursor: u64,
    /// The first cursor that is still retained.
    pub to_cursor: u64,
    /// How many bytes went.
    pub bytes: u64,
    /// When it happened.
    pub at_ms: TimestampMs,
}

impl Eviction {
    /// Returns the gap a reader is told about.
    #[must_use]
    pub const fn gap(&self) -> HistoryGap {
        HistoryGap {
            from_cursor: U64::new(self.from_cursor),
            to_cursor: U64::new(self.to_cursor),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 24 * 60 * 60 * 1000;

    fn now() -> TimestampMs {
        TimestampMs::new(30 * DAY)
    }

    #[test]
    fn the_defaults_are_the_figures_section_twenty_states() {
        let retention = OutputRetention::DEFAULT;
        assert_eq!(retention.max_age, Duration::from_secs(7 * 24 * 60 * 60));
        assert_eq!(retention.host_cap_bytes, 1024 * 1024 * 1024);
        assert_eq!(retention.session_cap_bytes, 128 * 1024 * 1024);
    }

    #[test]
    fn output_older_than_seven_days_is_past_its_retention() {
        let retention = OutputRetention::DEFAULT;
        let stale = Pressure {
            oldest_at_ms: Some(TimestampMs::new(now().get() - 8 * DAY)),
            ..Pressure::default()
        };
        assert!(retention.applies(RetentionLimit::Age, &stale, now()));
        let fresh = Pressure {
            oldest_at_ms: Some(TimestampMs::new(now().get() - 6 * DAY)),
            ..Pressure::default()
        };
        assert!(!retention.applies(RetentionLimit::Age, &fresh, now()));
    }

    #[test]
    fn the_caps_are_simultaneous_upper_bounds_rather_than_a_reservation() {
        let retention = OutputRetention::DEFAULT;
        // This session is well inside its own cap and the host is over its.
        let pressure = Pressure {
            session_bytes: 64 * 1024 * 1024,
            host_bytes: HOST_CAP_BYTES + 16 * 1024 * 1024,
            oldest_at_ms: Some(now()),
        };
        assert!(!retention.applies(RetentionLimit::SessionCap, &pressure, now()));
        assert!(retention.applies(RetentionLimit::HostCap, &pressure, now()));
        assert_eq!(
            retention.first_applicable(&pressure, now()),
            Some(RetentionLimit::HostCap)
        );
        assert_eq!(retention.bytes_over_cap(&pressure), 16 * 1024 * 1024);
    }

    #[test]
    fn a_session_over_its_own_cap_gives_up_what_it_is_over_by() {
        let retention = OutputRetention::DEFAULT;
        let pressure = Pressure {
            session_bytes: SESSION_CAP_BYTES + 5,
            host_bytes: SESSION_CAP_BYTES + 5,
            oldest_at_ms: Some(now()),
        };
        assert_eq!(
            retention.first_applicable(&pressure, now()),
            Some(RetentionLimit::SessionCap)
        );
        assert_eq!(retention.bytes_over_cap(&pressure), 5);
    }

    #[test]
    fn the_first_applicable_limit_is_the_first_in_the_order_section_twenty_states() {
        let retention = OutputRetention::DEFAULT;
        let everything = Pressure {
            session_bytes: SESSION_CAP_BYTES + 1,
            host_bytes: HOST_CAP_BYTES + 1,
            oldest_at_ms: Some(TimestampMs::new(now().get() - 9 * DAY)),
        };
        assert_eq!(
            retention.first_applicable(&everything, now()),
            Some(RetentionLimit::Age)
        );
        assert_eq!(
            RetentionLimit::ALL,
            &[
                RetentionLimit::Age,
                RetentionLimit::HostCap,
                RetentionLimit::SessionCap
            ]
        );
    }

    #[test]
    fn a_session_the_host_cap_cannot_reach_gives_up_no_more_than_it_holds() {
        let retention = OutputRetention::DEFAULT;
        let pressure = Pressure {
            session_bytes: 1024,
            host_bytes: HOST_CAP_BYTES * 2,
            oldest_at_ms: Some(now()),
        };
        assert_eq!(retention.bytes_over_cap(&pressure), 1024);
    }

    #[test]
    fn nothing_applies_when_every_bound_holds() {
        let retention = OutputRetention::DEFAULT;
        let pressure = Pressure {
            session_bytes: 1,
            host_bytes: 1,
            oldest_at_ms: Some(now()),
        };
        assert_eq!(retention.first_applicable(&pressure, now()), None);
        assert_eq!(retention.bytes_over_cap(&pressure), 0);
    }

    #[test]
    fn an_eviction_carries_the_range_a_reader_is_told_about() {
        let eviction = Eviction {
            limit: RetentionLimit::HostCap,
            from_cursor: 0,
            to_cursor: 4096,
            bytes: 4096,
            at_ms: now(),
        };
        let gap = eviction.gap();
        assert_eq!(gap.from_cursor.get(), 0);
        assert_eq!(gap.to_cursor.get(), 4096);
        assert_eq!(eviction.limit.as_str(), "host_cap");
    }
}
