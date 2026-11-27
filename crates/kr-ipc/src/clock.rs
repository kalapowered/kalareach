//! The machine's own continuous clock, shared by every host process on one boot.
//!
//! `kr_transport::clock` is the authority for every deadline *inside* one process, and this is
//! not a second one. Its `ContinuousInstant` is anchored privately, which is exactly right for a
//! deadline one process decides and keeps, and exactly what makes it useless for a deadline one
//! process hands to another: two anchors are two origins, and neither means anything to the other.
//!
//! A control daemon does hand a deadline to a worker. What both of them can read is the operating
//! system's own continuous clock, whose origin is the boot rather than either process:
//!
//! | Platform | Clock | Counts a suspend |
//! | --- | --- | --- |
//! | Apple | `CLOCK_MONOTONIC` | yes |
//! | Linux | `CLOCK_BOOTTIME` | yes |
//! | Windows | `QueryInterruptTime` | yes |
//! | anything else | `CLOCK_MONOTONIC` | the platform's answer, not this crate's |
//!
//! On Apple systems `CLOCK_MONOTONIC` is the wall clock less the boot time (`kern.boottime`): it
//! counts through sleep, it is not stepped when the wall clock is set (the kernel moves the boot
//! time by the step instead), and it follows the time service's rate adjustments, so it keeps the
//! wall clock's pace. It is not `mach_continuous_time`, which is `CLOCK_MONOTONIC_RAW`, the same
//! count with no adjustment, and which `kr_transport::clock` reads. `CLOCK_UPTIME_RAW`, which is
//! `mach_absolute_time`, stops in sleep and is what [`std::time::Instant`] reads there.
//! [`order_elapsed_ms`] is the counter for the order of two readings, and on Apple systems it reads
//! `CLOCK_MONOTONIC_RAW` and not `CLOCK_MONOTONIC`.
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

    /// Returns the counter that orders two readings taken in different processes of one boot, in
    /// milliseconds since this boot: [`order_elapsed_ms`].
    ///
    /// An implementer states it. A default of [`Self::boot_elapsed_ms`] would let an implementer
    /// that forgot to state it read the clock that a clock set can move on Apple systems, and
    /// nothing would fail.
    fn order_elapsed_ms(&self) -> u64;
}

/// The operating system's own continuous clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemSharedClock;

impl SharedClock for SystemSharedClock {
    fn boot_elapsed_ms(&self) -> u64 {
        boot_elapsed_ms()
    }

    fn order_elapsed_ms(&self) -> u64 {
        order_elapsed_ms()
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

    fn order_elapsed_ms(&self) -> u64 {
        self.boot_elapsed_ms()
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

/// How far the continuous clock may run fast against the wall clock before the difference counts
/// as a rollback, in parts per million.
///
/// The platform's time service keeps the wall clock, and some of the continuous clocks a host's
/// records are measured on are not kept by it, so they differ from it by the oscillator's error:
/// 20 ppm is about 1.7 seconds a day. Which they are, by clock:
///
/// * the daemon's clock record projects on `kr_transport`'s `ContinuousInstant`: on Apple systems
///   that is `mach_continuous_time` (`CLOCK_MONOTONIC_RAW`), which nothing adjusts, on Linux
///   `CLOCK_BOOTTIME`, which keeps the wall clock's pace because the time service slews it, and
///   elsewhere, Windows included, `std::time::Instant`, which nothing adjusts;
/// * this crate's clock, which each worker's time contract reads, is `QueryInterruptTime` on
///   Windows, which nothing adjusts, `CLOCK_BOOTTIME` on Linux and, on Apple systems, a clock that
///   keeps the wall clock's pace, as described above.
///
/// A projection that credits every continuous millisecond counts that error as a rollback once it
/// passes the five-second tolerance, about three days at 20 ppm, and a healthy host then distrusts
/// its own clock until its owner establishes it again. So a projection credits a millisecond less
/// per 10,000 ([`credited`]): a continuous clock up to this fast raises no distrust, and one faster
/// than that still does. Removing the allowance where one clock keeps the wall clock's pace would
/// still leave the others needing it.
///
/// Both of the host's time records project this way, the daemon's clock record and each worker's
/// time contract, and this is the one statement of the rule and of its cost. A wall clock that
/// falls behind the continuous clock by no more than this rate is never read as a rollback, however
/// long that lasts, so it can lose this rate times the elapsed time (6 ms for each minute, about a
/// minute a week) without being seen, and a UTC deadline decided against the proven reading can
/// outlive its time by as much. A single step back is seen when it exceeds the tolerance plus this
/// rate times the time since the record's mark or anchor was last raised.
pub const RATE_ALLOWANCE_PPM: u64 = 100;

/// What `elapsed_ms` of continuous time credits a projection with: all of it less the rate
/// allowance ([`RATE_ALLOWANCE_PPM`]).
#[must_use]
pub const fn credited(elapsed_ms: u64) -> u64 {
    elapsed_ms.saturating_sub(elapsed_ms.saturating_mul(RATE_ALLOWANCE_PPM) / 1_000_000)
}

/// What `elapsed_ms` of continuous time credits, in units of a millionth of a millisecond:
/// [`credited`] without its rounding to a millisecond, for a comparison that has to be exact.
#[must_use]
pub const fn credited_micros(elapsed_ms: u64) -> i128 {
    elapsed_ms as i128 * (1_000_000 - RATE_ALLOWANCE_PPM as i128)
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
/// Darwin's `CLOCK_MONOTONIC` counts from an arbitrary point and continues to increment while the
/// system is asleep, as Apple documents it. It is the wall clock less the boot time, so it is not
/// stepped when the wall clock is set and it follows the time service's rate adjustments;
/// `CLOCK_MONOTONIC_RAW` (`mach_continuous_time`) is the same count with no adjustment.
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

/// One of the three places in this crate that call the operating system without a safe interface.
///
/// The workspace forbids unsafe code; this crate denies it and relaxes the rule for this module,
/// because no safe interface exposes a boot-scoped continuous clock on this platform with the
/// resolution a five-second deadline needs.
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

/// Returns the counter that orders two readings taken in different processes of one boot, in
/// milliseconds since this boot.
///
/// A reading never goes down as the moment it is taken goes up, and it is the same function of the
/// moment in every process of the boot, whatever the wall clock does. That is all an order of two
/// readings needs: a reading that lags the true count, one that is truncated and one that moves in
/// ticks can each only turn a strict order into a tie.
///
/// On Linux and Windows it is [`boot_elapsed_ms`]: `CLOCK_BOOTTIME` is one count that no clock set
/// reaches, and `QueryInterruptTime` is one count that every process reads. On Apple systems it is
/// not. `CLOCK_MONOTONIC`, which [`boot_elapsed_ms`] reads there, is the wall clock less the boot
/// time, so it keeps its order only while the kernel moves the boot time with every clock set. This
/// reads `CLOCK_MONOTONIC_RAW` (`mach_continuous_time`), which counts through sleep, has no
/// adjustment and is reached by no clock set.
///
/// Meaningless across boots.
#[must_use]
#[cfg(not(target_vendor = "apple"))]
pub fn order_elapsed_ms() -> u64 {
    boot_elapsed_ms()
}

/// Returns the counter that orders two readings taken in different processes of one boot, in
/// milliseconds since this boot: `CLOCK_MONOTONIC_RAW` on Apple systems, where
/// [`boot_elapsed_ms`] reads a clock that a clock set can move.
///
/// Meaningless across boots.
#[must_use]
#[cfg(target_vendor = "apple")]
pub fn order_elapsed_ms() -> u64 {
    apple::raw_elapsed_ms()
}

/// The raw continuous clock of Apple systems, read through the one call that has no safe
/// interface.
///
/// The workspace forbids unsafe code; this crate denies it and relaxes the rule for this module and
/// the Windows one, because no safe interface reads `CLOCK_MONOTONIC_RAW` on this platform.
#[cfg(target_vendor = "apple")]
mod apple {
    #![expect(
        unsafe_code,
        reason = "the raw continuous clock has no safe interface on this platform"
    )]

    /// Returns `CLOCK_MONOTONIC_RAW`, in milliseconds since this boot, truncated as
    /// [`super::from_timespec`] truncates.
    ///
    /// A call that fails leaves the reading at zero in a release build; a debug build stops. The
    /// host's record of boots treats that zero as follows. In a boot whose recorded high is above
    /// zero it is a reading below the high, and the boot is spoiled. A boot's first record keeps it
    /// as a high of zero, which every later reading passes, so the next reading is not lost. A
    /// decision never takes a start point at zero, so that access has no point: the text made for
    /// it between that decision and the host's next start in a boot whose counter answers is never
    /// served, and the guard logs nothing. Within the point's own boot a stamp that reads zero is
    /// withheld, since no point is below it; the zero stamp of a later boot is admitted, as is
    /// every stamp of a later boot.
    pub fn raw_elapsed_ms() -> u64 {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: the call writes one `timespec` through the pointer it is given and has no other
        // effect. The pointer is to a live local of exactly that type.
        let status = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &raw mut time) };
        debug_assert_eq!(
            status, 0,
            "CLOCK_MONOTONIC_RAW is read on every Apple system"
        );
        let seconds = u64::try_from(time.tv_sec).unwrap_or_default();
        let milliseconds = u64::try_from(time.tv_nsec).unwrap_or_default() / 1_000_000;
        seconds.saturating_mul(1_000).saturating_add(milliseconds)
    }

    #[cfg(test)]
    unsafe extern "C" {
        fn clock_gettime_nsec_np(clock_id: libc::clockid_t) -> u64;
    }

    /// Returns `CLOCK_MONOTONIC_RAW` in milliseconds through `clock_gettime_nsec_np`, which the
    /// tests hold the counter against: another call of the system, so a fault in the call the
    /// counter reads does not show in both.
    #[cfg(test)]
    pub fn reference_ms() -> u64 {
        // SAFETY: the call reads one clock and has no other effect; it takes an identifier by value.
        unsafe { clock_gettime_nsec_np(libc::CLOCK_MONOTONIC_RAW) / 1_000_000 }
    }
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

    /// The Apple counter, read through the handle the daemon holds: it lies between two readings of
    /// the raw continuous clock that bracket it. The clock `boot_elapsed_ms` reads there is the wall
    /// clock less the boot time, which can differ from the raw one by more than the bracket, so a
    /// counter that reads it instead falls outside. Where the two clocks happen to coincide the
    /// control cannot tell them apart, and the case says so instead of passing as proof.
    #[cfg(target_vendor = "apple")]
    #[test]
    fn the_order_counter_of_an_apple_host_is_the_raw_continuous_clock() {
        let clock: std::sync::Arc<dyn SharedClock> = std::sync::Arc::new(SystemSharedClock);
        let before = apple::reference_ms();
        let order = clock.order_elapsed_ms();
        let after = apple::reference_ms();
        assert!(
            (before..=after).contains(&order),
            "the order counter read {order} ms, outside the raw continuous clock's \
             {before} to {after} ms"
        );
        let before = apple::reference_ms();
        let boot = clock.boot_elapsed_ms();
        let after = apple::reference_ms();
        if (before..=after).contains(&boot) {
            eprintln!(
                "not detected: this host's two continuous clocks read {boot} ms and {before} ms \
                 together, so a counter that read the wrong one would pass here"
            );
        }
    }

    /// The name of the variable that makes this test program the second process of the exchange.
    const EXCHANGE_PEER: &str = "KR_ORDER_COUNTER_EXCHANGE_PEER";

    /// Two processes of one boot read one order counter, in both directions: each reading that the
    /// other process takes after receiving a message is not below the reading that preceded the
    /// message, and both name one boot.
    ///
    /// This is a premise of the order rule. A finite exchange cannot show an
    /// offset smaller than the time the messages take.
    #[test]
    fn two_processes_of_one_boot_read_one_order_counter_in_both_directions() {
        use std::io::{BufRead, Write};

        let epoch = || {
            crate::identity::boot_epoch(&crate::identity::boot_identity().expect("a boot identity"))
                .expect("a boot epoch")
                .get()
        };
        if std::env::var_os(EXCHANGE_PEER).is_some() {
            // The second process: answers each line with the epoch and a reading taken after it.
            let mut lines = std::io::stdin().lock().lines();
            let mut out = std::io::stdout().lock();
            while let Some(Ok(_)) = lines.next() {
                let reading = order_elapsed_ms();
                writeln!(out, "reading {:016x} {reading}", epoch()).expect("the answer is written");
                out.flush().expect("the answer is flushed");
            }
            return;
        }

        let name = module_path!()
            .split_once("::")
            .map(|(_, path)| {
                format!(
                    "{path}::two_processes_of_one_boot_read_one_order_counter_in_both_directions"
                )
            })
            .expect("a module path");
        let mut peer = std::process::Command::new(std::env::current_exe().expect("this program"))
            .args([name.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env(EXCHANGE_PEER, "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("the second process starts");
        let mut to_peer = peer.stdin.take().expect("its input");
        let mut from_peer =
            std::io::BufReader::new(peer.stdout.take().expect("its output")).lines();

        let ours = epoch();
        let mut last = 0_u64;
        for round in 0..1_000 {
            let first = order_elapsed_ms();
            assert!(
                first >= last,
                "round {round}: this process read {first} ms after the other had read {last} ms"
            );
            writeln!(to_peer, "go").expect("the request is written");
            to_peer.flush().expect("the request is flushed");
            let answer = loop {
                let line = from_peer
                    .next()
                    .expect("the second process answers")
                    .expect("its answer is text");
                // The test harness of the second process has written the start of its own line
                // ("test <name> ... ") before the first answer, with no end of line.
                if let Some((_, answer)) = line.split_once("reading ") {
                    break answer.to_owned();
                }
            };
            let (theirs, second) = answer.split_once(' ').expect("an epoch and a reading");
            let second: u64 = second.parse().expect("a reading");
            assert_eq!(
                u64::from_str_radix(theirs, 16).expect("an epoch"),
                ours,
                "round {round}: the two processes name different boots"
            );
            assert!(
                second >= first,
                "round {round}: the other process read {second} ms after this one had read {first} ms"
            );
            last = second;
        }
        drop(to_peer);
        assert!(peer.wait().expect("the second process ends").success());
    }
}
