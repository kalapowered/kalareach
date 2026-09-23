//! What the host time contract answers, as the engine receives it.
//!
//! Nothing in this crate reads a clock. Every decision that depends on time takes a [`HostReading`]
//! from the caller, which is what makes the engine a state machine rather than a process: the same
//! events and the same readings produce the same outcomes on any machine, and a test drives an
//! escalation or a quiet-hours release by handing over the reading it wants rather than by waiting.
//!
//! Two clocks arrive, because two different questions are being asked, and each answers only its
//! own:
//!
//! * **The continuous clock** measures every interval. A de-duplication window, an idle reminder
//!   and an escalation step are all "how long since", and the boot-scoped continuous clock answers
//!   that without anyone trusting anything: it only goes forward, nobody can set it, and it counts
//!   suspended time, so a machine that slept through an idle interval still owes the reminder when
//!   it wakes. It means nothing outside its own boot, which is why every anchor written down here
//!   carries the boot it was taken in.
//! * **The wall clock** decides quiet hours, which are a time of day rather than a duration, and
//!   it says when something happened for a person reading a record. A host that cannot prove its
//!   wall clock cannot prove it is inside a quiet window, and [`HostReading::wall_proven`] carries
//!   that fact rather than hiding it.
//!
//! **No interval is ever measured from a wall-clock moment.** A wall clock can be set, and a host
//! that trusts one still trusts it after somebody moves it forward an hour: two readings it vouches
//! for are not two readings on one scale. An interval whose anchor was taken in another boot is
//! therefore started again rather than worked out across the gap, which makes a reminder late
//! instead of making it fire the moment a clock is corrected.

use core::fmt::Write;

use kr_protocol::scalars::TimestampMs;
use sha2::{Digest, Sha256};

/// Milliseconds in a day.
pub const MS_IN_DAY: u64 = 86_400_000;

/// Milliseconds in a minute.
pub const MS_IN_MINUTE: u64 = 60_000;

/// One boot of one machine, as this engine compares them.
///
/// The continuous clock restarts with the machine, so a reading of it means nothing without the
/// boot it was taken in. This is that boot, reduced to something fixed-width the store can write
/// down and two readings can be compared by. It is never interpreted, only compared.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BootMark([u8; 16]);

impl BootMark {
    /// Returns the mark for a host's own boot identity, whatever shape that identity has.
    #[must_use]
    pub fn of(identity: &[u8]) -> Self {
        let digest = Sha256::digest(identity);
        let mut mark = [0u8; 16];
        mark.copy_from_slice(&digest[..16]);
        Self(mark)
    }

    /// Returns the mark the store wrote down.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the bytes a store writes down.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Returns the mark as the hexadecimal the store keeps it in.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut text = String::with_capacity(32);
        for byte in &self.0 {
            write!(text, "{byte:02x}").expect("writing to a string cannot fail");
        }
        text
    }

    /// Returns the mark a store read back, or `None` for text that is not one.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let at = index * 2;
            *byte = u8::from_str_radix(text.get(at..at + 2)?, 16).ok()?;
        }
        Some(Self(bytes))
    }
}

/// A moment an interval is measured from, on the only clock that can measure one.
///
/// It is the continuous reading at that moment and the boot it was taken in. An anchor from
/// another boot measures nothing: the continuous clock it names restarted, and no arithmetic
/// across the two is sound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    /// The boot the reading was taken in.
    pub boot: BootMark,
    /// The continuous reading at that moment.
    pub continuous_ms: u64,
}

impl Anchor {
    /// Builds an anchor.
    #[must_use]
    pub const fn new(boot: BootMark, continuous_ms: u64) -> Self {
        Self {
            boot,
            continuous_ms,
        }
    }

    /// How long has run since this anchor at `reading`, when the two are on one clock.
    ///
    /// `None` when they are not, which is every anchor from another boot. A caller then starts the
    /// interval again rather than guessing at the gap.
    #[must_use]
    pub fn elapsed_at(&self, reading: HostReading) -> Option<u64> {
        (self.boot == reading.boot)
            .then(|| reading.continuous_ms.saturating_sub(self.continuous_ms))
    }
}

/// One reading of the host time contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostReading {
    /// The boot this reading was taken in.
    pub boot: BootMark,
    /// The boot-scoped continuous clock, in milliseconds. Intervals are measured on this.
    pub continuous_ms: u64,
    /// What the wall clock reads, as the host time contract reports it.
    pub wall_ms: TimestampMs,
    /// Whether this host can prove that reading.
    ///
    /// False leaves quiet hours unenforced. A suppression decided on a clock the host cannot prove
    /// would withhold a notification at an hour nobody chose, and the failure that matters here is
    /// the silent one. It says nothing about intervals: no interval is measured from a wall-clock
    /// moment, because a clock a host trusts is still a clock somebody can set.
    pub wall_proven: bool,
}

impl HostReading {
    /// Builds a reading.
    #[must_use]
    pub const fn new(boot: BootMark, continuous_ms: u64, wall_ms: u64, wall_proven: bool) -> Self {
        Self {
            boot,
            continuous_ms,
            wall_ms: TimestampMs::new(wall_ms),
            wall_proven,
        }
    }

    /// Returns this reading as an anchor an interval can be measured from.
    #[must_use]
    pub const fn anchor(&self) -> Anchor {
        Anchor::new(self.boot, self.continuous_ms)
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
            boot: self.boot,
            continuous_ms: self.continuous_ms.saturating_add(millis),
            wall_ms: TimestampMs::new(self.wall_ms.get().saturating_add(millis)),
            wall_proven: self.wall_proven,
        }
    }

    /// Returns this reading as it stood at an earlier continuous reading, or this reading itself
    /// when `continuous_ms` is not earlier.
    ///
    /// A timer is decided against what the host has certified it has read, and that certificate
    /// is a moment on the continuous clock that can be behind the present. Both clocks move back
    /// together, which is what an undisturbed machine's clocks did over the same interval.
    #[must_use]
    pub const fn at_or_before(&self, continuous_ms: u64) -> Self {
        if continuous_ms >= self.continuous_ms {
            return *self;
        }
        let back = self.continuous_ms - continuous_ms;
        Self {
            boot: self.boot,
            continuous_ms,
            wall_ms: TimestampMs::new(self.wall_ms.get().saturating_sub(back)),
            wall_proven: self.wall_proven,
        }
    }
}

/// An interval, as the engine holds it while it is running.
///
/// It is how much had already passed at a moment, plus the continuous reading of that moment, so
/// asking how long it has run is one subtraction on a clock nobody can set. It lives only as long
/// as the process: what the store keeps is the [`Anchor`] the interval starts from, and
/// `Engine::reanchor` builds these again from those anchors when a session comes back. An interval
/// that was already overdue comes back overdue rather than clipped to however long this process
/// has been running.
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

    fn boot(byte: u8) -> BootMark {
        BootMark::from_bytes([byte; 16])
    }

    #[test]
    fn a_reading_reports_the_minute_of_the_utc_day_it_falls_in() {
        // 1970-01-02 03:04 UTC.
        let reading = HostReading::new(
            boot(1),
            0,
            MS_IN_DAY + 3 * 60 * MS_IN_MINUTE + 4 * MS_IN_MINUTE,
            true,
        );
        assert_eq!(reading.minute_of_day(), 3 * 60 + 4);
        assert_eq!(reading.ms_of_day(), (3 * 60 + 4) * MS_IN_MINUTE);
    }

    #[test]
    fn an_interval_keeps_what_had_already_passed_when_the_clock_restarts() {
        let before = HostReading::new(boot(1), 900_000, 5_000_000, true);
        let interval = Elapsed::already(240_000, before);
        assert_eq!(interval.ms(before), 240_000);
        assert_eq!(interval.ms(before.advanced(60_000)), 300_000);
        assert_eq!(interval.due_at(300_000), 960_000);

        // The machine restarted one second ago; the interval had still run for four minutes.
        let after = HostReading::new(boot(1), 1_000, 5_060_000, true);
        let reanchored = Elapsed::already(300_000, after);
        assert_eq!(
            reanchored.due_at(300_000),
            1_000,
            "an interval that is already overdue is due now, not in five more minutes"
        );
    }

    #[test]
    fn an_anchor_measures_nothing_outside_the_boot_it_was_taken_in() {
        let here = HostReading::new(boot(1), 10_000, 5_000_000, true);
        let anchor = here.anchor();
        assert_eq!(anchor.elapsed_at(here.advanced(2_000)), Some(2_000));
        // The machine rebooted. The continuous clock it names restarted, and the wall clock could
        // have been set in between, so there is nothing to measure across the two.
        let next_boot = HostReading::new(boot(2), 12_000, 5_000_000 + 3_602_000, true);
        assert_eq!(anchor.elapsed_at(next_boot), None);
    }

    #[test]
    fn a_boot_mark_survives_the_text_a_store_keeps_it_in() {
        let mark = BootMark::of(b"one machine, one boot");
        assert_eq!(BootMark::from_hex(&mark.to_hex()), Some(mark));
        assert_eq!(mark.to_hex().len(), 32);
        assert_eq!(BootMark::from_hex("not a mark"), None);
        assert_ne!(BootMark::of(b"another boot"), mark);
    }

    #[test]
    fn advancing_a_reading_moves_both_clocks_together() {
        let reading = HostReading::new(boot(1), 1_000, 5_000, true);
        let later = reading.advanced(2_500);
        assert_eq!(later.continuous_ms, 3_500);
        assert_eq!(later.wall_ms.get(), 7_500);
        assert!(later.wall_proven);
    }
}
