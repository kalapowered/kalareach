//! The machine's own continuous clock, shared by every host process on one boot.
//!
//! [`kr_transport::clock`] is the authority for every deadline *inside* one process, and this is
//! not a second one. Its `ContinuousInstant` is anchored privately, which is exactly right for a
//! deadline one process decides and keeps, and exactly what makes it useless for a deadline one
//! process hands to another: two anchors are two origins, and neither means anything to the other.
//!
//! A control daemon does hand a deadline to a worker. What both of them can read is the operating
//! system's own continuous clock, whose origin is the boot rather than either process:
//!
//! | Platform | Clock | Counts a suspend |
//! | --- | --- | --- |
//! | Apple | `mach_continuous_time` | yes |
//! | Linux | `CLOCK_BOOTTIME` | yes |
//! | Windows | `QueryInterruptTime` | yes |
//! | anything else | `CLOCK_MONOTONIC` | the platform's answer, not this crate's |
//!
//! A reading of one of those is comparable between two processes, so a deadline expressed in it is
//! the same deadline on both sides of the socket and nothing has to guess at what the journey cost.
//!
//! Two properties follow, and both matter:
//!
//! * A wall-clock step cannot move it, in either direction. It is not the wall clock.
//! * A deadline from a previous boot reads as long past, because the clock restarts at the boot. A
//!   stale forwarded deadline therefore expires rather than being honoured.
//!
//! # Crossing between two clocks without gaining time
//!
//! Converting a deadline from one clock's scale to another's is two readings and a subtraction, and
//! the order of the two readings decides whether the conversion can *add* time. Read the
//! destination clock first and the source clock second: everything that happens between the two
//! readings then shortens the result, because the remainder is measured from a later moment and
//! anchored at an earlier one. Read them the other way round and a pause between them (a lock, a
//! scheduler, a busy machine) is added to the deadline. [`remaining_of`] and
//! [`transferred_deadline`] are the two halves of that subtraction, and each says which reading it
//! expects to be the later one.

use std::time::Duration;

/// Reads the machine's own continuous clock.
///
/// A host process holds one of these so its conversions can be driven by a test: what a conversion
/// has to get right is the *order* of two readings, and a pause between them is not something a
/// test can arrange with the real clock.
pub trait SharedClock: Send + Sync + std::fmt::Debug {
    /// Returns milliseconds since this boot.
    fn boot_elapsed_ms(&self) -> u64;
}

/// The operating system's own continuous clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemSharedClock;

impl SharedClock for SystemSharedClock {
    fn boot_elapsed_ms(&self) -> u64 {
        boot_elapsed_ms()
    }
}

/// A shared clock a test drives by hand.
#[derive(Clone, Debug, Default)]
pub struct ManualSharedClock {
    elapsed: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl ManualSharedClock {
    /// Creates a clock reading zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Advances the clock.
    pub fn advance(&self, duration: Duration) {
        let milliseconds = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        self.elapsed
            .fetch_add(milliseconds, std::sync::atomic::Ordering::AcqRel);
    }
}

impl SharedClock for ManualSharedClock {
    fn boot_elapsed_ms(&self) -> u64 {
        self.elapsed.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Returns what is left of a deadline measured on the machine's own continuous clock.
///
/// `source_now` is that clock read **after** the destination clock, which is what makes the answer
/// conservative: the remainder is measured from the later of the two readings, so a pause between
/// them shortens it. `None` means the deadline has already passed, which is never carried across as
/// though it had time left.
#[must_use]
pub fn remaining_of(source_now: u64, source_deadline: u64) -> Option<Duration> {
    let remaining = source_deadline
        .checked_sub(source_now)
        .filter(|left| *left > 0)?;
    Some(Duration::from_millis(remaining))
}

/// Anchors what is left of a deadline on a reading of the machine's own continuous clock.
///
/// `destination_now` is that clock read **before** `remaining` was measured on the clock the
/// deadline came from, which is what makes the answer conservative: the remainder is measured from
/// a later moment and anchored at an earlier one, so a pause between the two readings shortens the
/// result rather than lengthening it. `None` means the deadline has already passed.
#[must_use]
pub fn transferred_deadline(destination_now: u64, remaining: Duration) -> Option<u64> {
    if remaining.is_zero() {
        return None;
    }
    let remaining = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
    Some(destination_now.saturating_add(remaining))
}

/// Returns the machine's continuous clock, in milliseconds since this boot.
///
/// Comparable between processes on one boot, and meaningless across boots. Nothing derives a
/// wall-clock time from it.
#[must_use]
#[cfg(target_os = "linux")]
pub fn boot_elapsed_ms() -> u64 {
    from_timespec(rustix::time::clock_gettime(rustix::time::ClockId::Boottime))
}

/// Returns the machine's continuous clock, in milliseconds since this boot.
///
/// Darwin's `CLOCK_MONOTONIC` is `mach_continuous_time` expressed in nanoseconds: Apple documents
/// it as counting from an arbitrary point and continuing to increment while the system is asleep.
/// `CLOCK_UPTIME_RAW` is the counter that stops, and `std::time::Instant` is built on that one,
/// which is why this is not.
#[must_use]
#[cfg(target_vendor = "apple")]
pub fn boot_elapsed_ms() -> u64 {
    from_timespec(rustix::time::clock_gettime(
        rustix::time::ClockId::Monotonic,
    ))
}

/// Returns the machine's continuous clock, in milliseconds since this boot.
///
/// `QueryInterruptTime` counts in hundreds of nanoseconds since the boot and every process reads
/// the same counter, which is what a deadline crossing a pipe needs. It is the *biased* count,
/// which is the one that includes the time the machine spent asleep; the unbiased counter beside it
/// does not, and a deadline measured on that would outlive a suspension of any length, which is the
/// one thing section 9 says a clock must not let happen.
#[must_use]
#[cfg(windows)]
pub fn boot_elapsed_ms() -> u64 {
    windows::interrupt_time() / 10_000
}

/// The one place in this crate that calls the operating system without a safe interface.
///
/// The workspace forbids unsafe code; this crate denies it and relaxes the rule here alone, because
/// no safe interface exposes a boot-scoped continuous clock on this platform with the resolution a
/// five-second deadline needs.
#[cfg(windows)]
mod windows {
    #![expect(
        unsafe_code,
        reason = "the machine's interrupt-time counter has no safe interface on this platform"
    )]

    /// Returns the machine's interrupt time, in hundreds of nanoseconds since the boot.
    ///
    /// The biased count, which includes time the machine spent asleep.
    pub fn interrupt_time() -> u64 {
        let mut ticks = 0_u64;
        // SAFETY: the call writes one unsigned 64-bit word through the pointer it is given and has
        // no other effect. The pointer is to a live local of exactly that type.
        unsafe {
            windows_sys::Win32::System::WindowsProgramming::QueryInterruptTime(&raw mut ticks);
        }
        ticks
    }
}

/// Returns the machine's continuous clock, in milliseconds since this boot.
///
/// On the remaining platforms this is `CLOCK_MONOTONIC`, whose origin is still the boot and which
/// may or may not count through a suspend. A host there is on a clock this build has not qualified,
/// which is the same statement `kr_transport::clock` makes about its own fallback.
#[must_use]
#[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
pub fn boot_elapsed_ms() -> u64 {
    from_timespec(rustix::time::clock_gettime(
        rustix::time::ClockId::Monotonic,
    ))
}

#[cfg(unix)]
fn from_timespec(time: rustix::time::Timespec) -> u64 {
    let seconds = u64::try_from(time.tv_sec).unwrap_or_default();
    let milliseconds = u64::try_from(time.tv_nsec).unwrap_or_default() / 1_000_000;
    seconds.saturating_mul(1_000).saturating_add(milliseconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_never_goes_backwards() {
        let first = boot_elapsed_ms();
        let second = boot_elapsed_ms();
        assert!(second >= first);
    }

    #[test]
    fn the_clock_advances_with_real_time() {
        let start = boot_elapsed_ms();
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(boot_elapsed_ms() >= start + 10);
    }

    #[test]
    fn the_clock_is_older_than_this_process() {
        // Its origin is the boot, not the process, which is the whole reason two processes can
        // compare readings of it. A machine is not booted and then immediately running this test,
        // so the reading is well past zero.
        assert!(
            boot_elapsed_ms() > 1_000,
            "the shared clock counts from the boot rather than from this process"
        );
    }

    #[test]
    fn a_transferred_deadline_never_gains_the_time_between_the_two_readings() {
        // The destination is read first, at 5_000, and the source second, by which time a second
        // has passed. What is left of the source deadline is measured from that later moment.
        let remaining = remaining_of(1_000, 1_100).expect("a hundred milliseconds are left");
        assert_eq!(
            transferred_deadline(5_000, remaining),
            Some(5_100),
            "a deadline crosses with exactly what is left of it"
        );
        assert_eq!(
            remaining_of(2_000, 1_100),
            None,
            "and one whose remaining time was spent between the readings does not cross at all"
        );
    }

    #[test]
    fn a_manual_clock_reads_what_it_was_advanced_by() {
        let clock = ManualSharedClock::new();
        assert_eq!(clock.boot_elapsed_ms(), 0);
        clock.advance(Duration::from_millis(1_000));
        assert_eq!(clock.boot_elapsed_ms(), 1_000);
    }
}
