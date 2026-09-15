//! The machine's own continuous clock, shared by every host process on one boot.
//!
//! [`kr_transport::clock`] is the authority for every deadline *inside* one process, and this is
//! not a second one. Its [`ContinuousInstant`](kr_transport::clock::ContinuousInstant) is anchored
//! privately, which is exactly right for a deadline one process decides and keeps, and exactly what
//! makes it useless for a deadline one process hands to another: two anchors are two origins, and
//! neither means anything to the other.
//!
//! A control daemon does hand a deadline to a worker. What both of them can read is the operating
//! system's own continuous clock — `CLOCK_BOOTTIME` on Linux, `CLOCK_MONOTONIC` on Apple, both
//! monotonic and both counting through a suspend — whose origin is the boot rather than either
//! process. A reading of that is comparable between them, so a deadline expressed in it is the same
//! deadline on both sides of the socket and nothing has to guess at what the journey cost.
//!
//! Two properties follow, and both matter:
//!
//! * A wall-clock step cannot move it, in either direction. It is not the wall clock.
//! * A deadline from a previous boot reads as long past, because the clock restarts at the boot.
//!   A stale forwarded deadline therefore expires rather than being honoured.

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
/// Darwin's `CLOCK_MONOTONIC` is the sleep-inclusive one; `CLOCK_UPTIME_RAW` is the clock that
/// stops, and `std::time::Instant` uses that one, which is why this does not.
#[must_use]
#[cfg(target_vendor = "apple")]
pub fn boot_elapsed_ms() -> u64 {
    from_timespec(rustix::time::clock_gettime(
        rustix::time::ClockId::Monotonic,
    ))
}

/// Returns the machine's continuous clock, in milliseconds since this boot.
///
/// On the remaining platforms this is the monotonic clock, whose origin is still the boot and which
/// may or may not count through a suspend. A host there is on a clock this build has not qualified,
/// which is the same statement `kr_transport::clock` makes about its own fallback.
#[must_use]
#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
pub fn boot_elapsed_ms() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;

    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    let origin = ORIGIN.get_or_init(Instant::now);
    u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX)
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
}
