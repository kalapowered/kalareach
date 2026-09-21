//! The platform time adapter.
//!
//! Section 9 asks for one thing and forbids another. It asks the host to record the
//! synchronisation source, the status of that synchronisation and a bounded uncertainty, using the
//! **actual supported operating-system service**; and it forbids an invented universal
//! "authenticated NTP" call. Nothing here opens a socket, contacts a time server or signs
//! anything. Every field of a reading is an answer the kernel or the platform's own time service
//! gave.
//!
//! | Platform | What is read | What it reports |
//! | --- | --- | --- |
//! | macOS | `ntp_adjtime(2)` with no modes set | the kernel discipline the system time service maintains: the status word, the maximum and estimated error, and the time state as the return value |
//! | Linux | `ntp_adjtime(2)`, the adjtimex status | the same kernel model, maintained by `systemd-timesyncd`, `chronyd` or `ntpd` |
//! | Windows | `w32tm /query /status` | the W32Time service's own report: its source, leap indicator, stratum and root dispersion |
//!
//! The reading half is behind `cfg` because the call is. The **classifier** is not: it turns raw
//! platform values into a [`TimeAdapterReading`] with no syscall at all, which is why one machine
//! can check every platform's classification against `fixtures/time/adapter.json` while only its
//! own reading comes from the kernel.

use core::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use kr_protocol::action::{TimeAdapterReading, TimeSyncSource, TimeSyncStatus};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};

/// Reads the platform's own time service.
///
/// A host that runs on a platform this build has not qualified supplies its own implementation
/// rather than being given a reading nothing measured.
pub trait TimeAdapter: Send + Sync + fmt::Debug {
    /// Returns what the platform says about its clock, now.
    fn read(&self) -> TimeAdapterReading;
}

/// The kernel clock-discipline model both Unix platforms report.
///
/// `ntp_adjtime(2)` is the same interface on macOS, Linux and the BSDs: the status word carries
/// which discipline is running, the maximum and estimated error bound how wrong the clock may be,
/// and the call's return value is the time state. The bit values below are that shared model's,
/// which is what lets this classifier run anywhere; [`tests::the_status_bits_match_this_platform`]
/// checks them against this platform's own headers.
pub mod unix_model {
    /// The phase-locked loop is disciplining the clock.
    pub const STA_PLL: i32 = 0x0001;
    /// A pulse-per-second signal is disciplining the frequency.
    pub const STA_PPSFREQ: i32 = 0x0002;
    /// A pulse-per-second signal is disciplining the phase.
    pub const STA_PPSTIME: i32 = 0x0004;
    /// The frequency-locked loop is disciplining the clock.
    pub const STA_FLL: i32 = 0x0008;
    /// The clock is not synchronised.
    pub const STA_UNSYNC: i32 = 0x0040;
    /// The pulse-per-second signal is present.
    pub const STA_PPSSIGNAL: i32 = 0x0100;
    /// The pulse-per-second signal has excessive jitter.
    pub const STA_PPSJITTER: i32 = 0x0200;
    /// The pulse-per-second frequency is wandering.
    pub const STA_PPSWANDER: i32 = 0x0400;
    /// The pulse-per-second signal is in error.
    pub const STA_PPSERROR: i32 = 0x0800;
    /// The clock hardware itself failed.
    pub const STA_CLOCKERR: i32 = 0x1000;

    /// The clock is synchronised and no leap second is pending.
    pub const TIME_OK: i32 = 0;
    /// A leap second will be inserted.
    pub const TIME_INS: i32 = 1;
    /// A leap second will be deleted.
    pub const TIME_DEL: i32 = 2;
    /// A leap second is in progress.
    pub const TIME_OOP: i32 = 3;
    /// The clock is recovering from a leap second.
    pub const TIME_WAIT: i32 = 4;
    /// The clock is not synchronised.
    pub const TIME_ERROR: i32 = 5;
}

/// One raw reading of the Unix kernel clock-discipline model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnixTimex {
    /// The call's return value: the time state.
    pub time_state: i32,
    /// The status word.
    pub status: i32,
    /// The kernel's bound on how wrong the clock may be, in microseconds.
    pub maxerror_us: i64,
    /// The kernel's estimate of its error, in microseconds.
    pub esterror_us: i64,
}

/// Classifies a Unix kernel reading.
///
/// Pure: it makes no call of its own. The source comes from the discipline bits rather than from
/// the name of a daemon, because the kernel is what the platform's time service acts through and
/// the bits are what say whether it is acting.
#[must_use]
pub fn classify_unix(
    platform: &str,
    api: &str,
    raw: UnixTimex,
    wall_clock_ms: TimestampMs,
) -> TimeAdapterReading {
    use unix_model as model;

    let pulse_per_second = raw.status & (model::STA_PPSFREQ | model::STA_PPSTIME) != 0
        && raw.status & (model::STA_PPSJITTER | model::STA_PPSWANDER | model::STA_PPSERROR) == 0
        && raw.status & model::STA_PPSSIGNAL != 0;
    let disciplined = raw.status & (model::STA_PLL | model::STA_FLL) != 0;
    let unsynchronised = raw.status & model::STA_UNSYNC != 0;

    let source = if unsynchronised {
        // The kernel says the clock is not synchronised. Whatever else is running, that is the
        // answer; a discipline bit beside it means a loop is trying, not that it has succeeded.
        TimeSyncSource::Unsynchronised
    } else if pulse_per_second {
        TimeSyncSource::PulsePerSecond
    } else if disciplined {
        TimeSyncSource::NetworkTimeService
    } else {
        // No discipline and no unsynchronised flag. The kernel is holding a clock somebody set and
        // nothing is keeping it, which is neither of the states above.
        TimeSyncSource::Unclassified
    };

    let status = if raw.status & model::STA_CLOCKERR != 0 {
        TimeSyncStatus::Error
    } else {
        match raw.time_state {
            model::TIME_OK => TimeSyncStatus::Ok,
            model::TIME_INS => TimeSyncStatus::InsertLeap,
            model::TIME_DEL => TimeSyncStatus::DeleteLeap,
            model::TIME_OOP => TimeSyncStatus::LeapInProgress,
            model::TIME_WAIT => TimeSyncStatus::LeapRecovering,
            model::TIME_ERROR => TimeSyncStatus::Error,
            _ => TimeSyncStatus::Unavailable,
        }
    };

    TimeAdapterReading {
        platform: platform.to_owned(),
        api: api.to_owned(),
        source,
        status,
        uncertainty_us: Nullable(bound(raw.maxerror_us)),
        estimated_error_us: Nullable(bound(raw.esterror_us)),
        wall_clock_ms,
    }
}

/// Classifies the W32Time service's own status report.
///
/// Pure, and deliberately conservative about what it does not find: an absent field is an absent
/// bound rather than a bound of zero, and a source line the parser does not recognise leaves the
/// source unclassified instead of guessing at it.
#[must_use]
pub fn classify_windows(
    platform: &str,
    api: &str,
    report: &str,
    wall_clock_ms: TimestampMs,
) -> TimeAdapterReading {
    let mut source_line = None;
    let mut leap = None;
    let mut stratum = None;
    let mut dispersion_s = None;
    let mut delay_s = None;
    for line in report.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match key.as_str() {
            "source" => source_line = Some(value.to_owned()),
            "leap indicator" => leap = leading_number(value),
            "stratum" => stratum = leading_number(value),
            "root dispersion" => dispersion_s = leading_decimal(value),
            "root delay" => delay_s = leading_decimal(value),
            _ => {}
        }
    }

    // The two names W32Time uses when nothing outside the machine is keeping its time. They are
    // matched as names rather than as substrings, because a perfectly good server can be called
    // `time.corp.local` and a substring search would read it as the local clock.
    const NO_SOURCE: [&str; 2] = ["local cmos clock", "free-running system clock"];
    let source = match source_line.as_deref() {
        None => TimeSyncSource::Unclassified,
        Some(name) => {
            // The name is followed by flags on a synchronised host: `time.windows.com,0x9`.
            let named = name
                .split(',')
                .next()
                .unwrap_or(name)
                .trim()
                .to_ascii_lowercase();
            if NO_SOURCE.contains(&named.as_str()) {
                TimeSyncSource::Unsynchronised
            } else {
                // NTP's stratum range is one to fifteen; sixteen means unsynchronised and anything
                // outside it is a report this build cannot read, which is not evidence about
                // anything. Two to fifteen is a service reached over the network.
                //
                // Stratum one says the reference is attached to this machine; it does not say
                // what the reference is. This build reads a reference clock only from the one name
                // W32Time gives its own hardware provider, matched whole rather than as a
                // substring: a name that merely mentions a radio or a receiver is a name, and the
                // tightest bound in the table is not handed out on the strength of one. Any other
                // primary reference is left unclassified, which carries no bound at all.
                const REFERENCE_CLOCK: [&str; 1] = ["hardware reference clock"];
                match stratum {
                    Some(1) if REFERENCE_CLOCK.contains(&named.as_str()) => {
                        TimeSyncSource::PulsePerSecond
                    }
                    Some(level) if (2..=15).contains(&level) => TimeSyncSource::NetworkTimeService,
                    _ => TimeSyncSource::Unclassified,
                }
            }
        }
    };

    let status = match (source, leap) {
        (TimeSyncSource::Unclassified, _) => TimeSyncStatus::Unavailable,
        (TimeSyncSource::Unsynchronised, _) => TimeSyncStatus::Error,
        // The leap indicator is the same four-value field NTP defines, so it reads the same way.
        (_, Some(0)) => TimeSyncStatus::Ok,
        (_, Some(1)) => TimeSyncStatus::InsertLeap,
        (_, Some(2)) => TimeSyncStatus::DeleteLeap,
        (_, Some(3)) => TimeSyncStatus::Error,
        (_, _) => TimeSyncStatus::Unavailable,
    };

    // The service's own bound is the root dispersion plus half the root delay, which is how NTP
    // bounds the error of a reading taken across a round trip. Taking the dispersion alone would
    // understate it, and understating a bound is the one direction that matters here.
    // Both halves or neither. Reading a missing round trip as zero would understate the bound,
    // and understating a bound is the one direction that matters: a host would then treat a
    // reading as tighter than the service is willing to claim.
    let uncertainty_us = match (dispersion_s, delay_s, source) {
        // A reference clock attached to this machine has no round trip to account for.
        (Some(dispersion), _, TimeSyncSource::PulsePerSecond) => {
            Some(U64::new(microseconds_from_seconds(dispersion)))
        }
        (Some(dispersion), Some(delay), TimeSyncSource::NetworkTimeService) => Some(U64::new(
            microseconds_from_seconds(dispersion + delay / 2.0),
        )),
        // A report this build could not classify, or one keeping no clock, carries no bound: a
        // figure beside an answer this host does not understand is not a bound on anything.
        _ => None,
    };

    TimeAdapterReading {
        platform: platform.to_owned(),
        api: api.to_owned(),
        source,
        status,
        uncertainty_us: Nullable(uncertainty_us),
        estimated_error_us: Nullable::null(),
        wall_clock_ms,
    }
}

/// Converts a bound in seconds to microseconds, saturating rather than wrapping.
fn microseconds_from_seconds(seconds: f64) -> u64 {
    if !seconds.is_finite() || seconds <= 0.0 {
        return 0;
    }
    let micros = (seconds * 1_000_000.0).round();
    if micros >= u64::MAX as f64 {
        u64::MAX
    } else {
        // The value is finite, positive and below the maximum, so the conversion is exact enough
        // for a bound expressed in microseconds.
        micros as u64
    }
}

/// Returns the reading a host produces when it could not read its own time service.
///
/// Not knowing is its own state. A host that reports `unavailable` has said something true about
/// itself; one that reports a synchronised clock with a zero bound would be claiming a measurement
/// it never took.
#[must_use]
pub fn unavailable(platform: &str, api: &str, wall_clock_ms: TimestampMs) -> TimeAdapterReading {
    TimeAdapterReading {
        platform: platform.to_owned(),
        api: api.to_owned(),
        source: TimeSyncSource::Unclassified,
        status: TimeSyncStatus::Unavailable,
        uncertainty_us: Nullable::null(),
        estimated_error_us: Nullable::null(),
        wall_clock_ms,
    }
}

fn bound(value: i64) -> Option<U64> {
    // A negative bound is not a bound. The kernel does not produce one, and reading it as a very
    // large unsigned number would turn a broken answer into a confident one.
    u64::try_from(value).ok().map(U64::new)
}

fn leading_number(value: &str) -> Option<i64> {
    let digits: String = value
        .trim()
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

fn leading_decimal(value: &str) -> Option<f64> {
    let number: String = value
        .trim()
        .chars()
        .take_while(|character| character.is_ascii_digit() || *character == '.')
        .collect();
    number.parse().ok()
}

/// The name this build reports for the platform it is running on.
#[must_use]
pub const fn platform_name() -> &'static str {
    if cfg!(target_vendor = "apple") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(windows) {
        "windows"
    } else {
        "unqualified"
    }
}

/// The interface this build reads on the platform it is running on.
#[must_use]
pub const fn platform_api() -> &'static str {
    if cfg!(any(target_vendor = "apple", target_os = "linux")) {
        "ntp_adjtime(2)"
    } else if cfg!(windows) {
        "w32tm /query /status"
    } else {
        "none"
    }
}

/// How long a platform reading stands before this host asks the service again.
///
/// The interfaces are not equally cheap. The kernel clock discipline is one system call, while the
/// Windows time service is read by running a program, and a host that looks at its clocks on every
/// mutation must not start a process on every mutation. What a reading says changes on the scale
/// of a synchronisation interval, so a few seconds of age costs nothing: the bound it carries is
/// milliseconds wide, and the tolerance it is compared against is seconds wide.
pub const READING_VALIDITY: Duration = Duration::from_secs(5);

/// The platform's own time service, read through the interface that platform supports.
#[derive(Debug, Default)]
pub struct PlatformTimeAdapter {
    /// The last reading and the moment it was taken.
    ///
    /// [`Instant`] is the right clock for an age: it is monotonic on every platform this runs on,
    /// and a cache that used the wall clock would be invalidated or extended by exactly the
    /// clock steps this adapter exists to report.
    last: Mutex<Option<(Instant, TimeAdapterReading)>>,
}

impl PlatformTimeAdapter {
    /// Builds an adapter that has not read the service yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last: Mutex::new(None),
        }
    }

    /// Reads the platform's time service without consulting the cache.
    fn read_now(&self) -> TimeAdapterReading {
        let wall_clock_ms = kr_ipc::now_ms();
        #[cfg(any(target_vendor = "apple", target_os = "linux"))]
        {
            match self::unix::read() {
                Some(raw) => classify_unix(platform_name(), platform_api(), raw, wall_clock_ms),
                None => unavailable(platform_name(), platform_api(), wall_clock_ms),
            }
        }
        #[cfg(windows)]
        {
            match self::windows::query() {
                Some(report) => {
                    classify_windows(platform_name(), platform_api(), &report, wall_clock_ms)
                }
                None => unavailable(platform_name(), platform_api(), wall_clock_ms),
            }
        }
        #[cfg(not(any(target_vendor = "apple", target_os = "linux", windows)))]
        {
            unavailable(platform_name(), platform_api(), wall_clock_ms)
        }
    }
}

impl TimeAdapter for PlatformTimeAdapter {
    fn read(&self) -> TimeAdapterReading {
        let now = Instant::now();
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((taken, reading)) = last.as_ref()
            && now.saturating_duration_since(*taken) < READING_VALIDITY
        {
            return reading.clone();
        }
        let reading = self.read_now();
        *last = Some((now, reading.clone()));
        reading
    }
}

/// The one place in this crate outside `pty::descriptor` that calls the operating system without a
/// safe interface.
///
/// `ntp_adjtime(2)` is the interface both Unix platforms expose for the kernel's clock discipline,
/// and no crate in this build wraps it. Section 9 requires the real platform service, so the
/// alternative is not a safer call: it is an invented one, which the specification forbids
/// outright.
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
mod unix {
    #![expect(
        unsafe_code,
        reason = "the kernel clock discipline has no safe interface on this platform"
    )]

    use super::UnixTimex;

    /// Widens a kernel error bound to the width this build records it in.
    ///
    /// The kernel reports it as a `long`, which is 32 bits on some targets and 64 on others, so
    /// the conversion is generic rather than a cast: on a target where it is already 64 bits this
    /// is the identity, and on one where it is not it is a widening.
    fn microseconds<T: Into<i64>>(value: T) -> i64 {
        value.into()
    }

    /// Reads the kernel's clock discipline, or `None` when the call fails.
    ///
    /// `modes` is zero, which makes this a read: the call reports the discipline and changes
    /// nothing. It needs no privilege, which is what lets a worker running as an ordinary user
    /// record its host's time state at all.
    pub fn read() -> Option<UnixTimex> {
        let mut timex: libc::timex = unsafe { std::mem::zeroed() };
        timex.modes = 0;
        // SAFETY: the call reads the kernel's clock discipline and writes it through the pointer it
        // is given, which is to a live local of exactly that type. `modes` is zero, so it sets
        // nothing. Its only other effect is the return value.
        let state = unsafe { libc::ntp_adjtime(&raw mut timex) };
        if state < 0 {
            return None;
        }
        Some(UnixTimex {
            time_state: state,
            status: timex.status,
            maxerror_us: microseconds(timex.maxerror),
            esterror_us: microseconds(timex.esterror),
        })
    }
}

/// The W32Time service's own status report.
///
/// Windows has no equivalent of the kernel discipline interface above. What it has is the time
/// service, and `w32tm /query /status` is the documented way to ask it what it is doing. Asking a
/// real service is a Windows machine's job; here it compiles and its classifier is tested against
/// the fixture.
#[cfg(windows)]
mod windows {
    /// Returns the service's report, or `None` when it could not be asked.
    pub fn query() -> Option<String> {
        let output = std::process::Command::new("w32tm")
            .args(["/query", "/status"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        String::from_utf8(output.stdout).ok()
    }
}

/// An adapter that answers with a reading a caller supplied.
///
/// It exists for two callers: a test that needs a particular platform state, and the fixture
/// check, which replays recorded platform values through the same classifier the real adapter
/// uses.
#[derive(Clone, Debug)]
pub struct RecordedTimeAdapter {
    reading: std::sync::Arc<std::sync::Mutex<TimeAdapterReading>>,
}

impl RecordedTimeAdapter {
    /// Creates an adapter that answers with this reading.
    #[must_use]
    pub fn new(reading: TimeAdapterReading) -> Self {
        Self {
            reading: std::sync::Arc::new(std::sync::Mutex::new(reading)),
        }
    }

    /// Replaces the reading this adapter answers with.
    pub fn set(&self, reading: TimeAdapterReading) {
        *self
            .reading
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = reading;
    }
}

impl TimeAdapter for RecordedTimeAdapter {
    fn read(&self) -> TimeAdapterReading {
        self.reading
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unix_model as model;

    fn stamp() -> TimestampMs {
        TimestampMs::new(1_700_000_000_000)
    }

    fn unix(status: i32, time_state: i32, maxerror_us: i64) -> TimeAdapterReading {
        classify_unix(
            "linux",
            "ntp_adjtime(2)",
            UnixTimex {
                time_state,
                status,
                maxerror_us,
                esterror_us: 500_000,
            },
            stamp(),
        )
    }

    #[test]
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    fn the_status_bits_match_this_platform() {
        assert_eq!(model::STA_PLL, libc::STA_PLL);
        assert_eq!(model::STA_PPSFREQ, libc::STA_PPSFREQ);
        assert_eq!(model::STA_PPSTIME, libc::STA_PPSTIME);
        assert_eq!(model::STA_FLL, libc::STA_FLL);
        assert_eq!(model::STA_UNSYNC, libc::STA_UNSYNC);
        assert_eq!(model::STA_PPSSIGNAL, libc::STA_PPSSIGNAL);
        assert_eq!(model::STA_PPSJITTER, libc::STA_PPSJITTER);
        assert_eq!(model::STA_PPSWANDER, libc::STA_PPSWANDER);
        assert_eq!(model::STA_PPSERROR, libc::STA_PPSERROR);
        assert_eq!(model::STA_CLOCKERR, libc::STA_CLOCKERR);
        assert_eq!(model::TIME_OK, libc::TIME_OK);
        assert_eq!(model::TIME_INS, libc::TIME_INS);
        assert_eq!(model::TIME_DEL, libc::TIME_DEL);
        assert_eq!(model::TIME_OOP, libc::TIME_OOP);
        assert_eq!(model::TIME_WAIT, libc::TIME_WAIT);
        assert_eq!(model::TIME_ERROR, libc::TIME_ERROR);
    }

    #[test]
    fn a_disciplined_kernel_clock_is_the_platforms_time_service() {
        let reading = unix(model::STA_PLL, model::TIME_OK, 62_192);
        assert_eq!(reading.source, TimeSyncSource::NetworkTimeService);
        assert_eq!(reading.status, TimeSyncStatus::Ok);
        assert_eq!(
            reading.uncertainty_us.as_ref().map(|bound| bound.get()),
            Some(62_192)
        );
        assert!(reading.is_qualified());
    }

    #[test]
    fn an_unsynchronised_kernel_is_never_read_as_synchronised() {
        // The discipline bit is set beside the unsynchronised flag, which is what a loop that is
        // trying and has not succeeded looks like.
        let reading = unix(
            model::STA_PLL | model::STA_UNSYNC,
            model::TIME_ERROR,
            16_000,
        );
        assert_eq!(reading.source, TimeSyncSource::Unsynchronised);
        assert_eq!(reading.status, TimeSyncStatus::Error);
        assert!(!reading.is_qualified());
    }

    #[test]
    fn a_pulse_per_second_reference_is_named_as_one() {
        let reading = unix(
            model::STA_PLL | model::STA_PPSTIME | model::STA_PPSSIGNAL,
            model::TIME_OK,
            40,
        );
        assert_eq!(reading.source, TimeSyncSource::PulsePerSecond);
        assert!(reading.is_qualified());
    }

    #[test]
    fn a_pulse_per_second_reference_in_error_is_not_one() {
        let reading = unix(
            model::STA_PLL | model::STA_PPSTIME | model::STA_PPSSIGNAL | model::STA_PPSERROR,
            model::TIME_OK,
            40,
        );
        assert_eq!(
            reading.source,
            TimeSyncSource::NetworkTimeService,
            "the loop is still disciplining the clock; the reference is what failed"
        );
    }

    #[test]
    fn a_clock_nothing_is_keeping_is_unclassified_rather_than_trusted() {
        let reading = unix(0, model::TIME_OK, 500);
        assert_eq!(reading.source, TimeSyncSource::Unclassified);
        assert!(
            !reading.is_qualified(),
            "a clock somebody set by hand is not evidence"
        );
    }

    #[test]
    fn hardware_failure_wins_over_the_time_state() {
        let reading = unix(model::STA_PLL | model::STA_CLOCKERR, model::TIME_OK, 10);
        assert_eq!(reading.status, TimeSyncStatus::Error);
    }

    #[test]
    fn every_leap_state_has_its_own_status() {
        for (state, expected) in [
            (model::TIME_OK, TimeSyncStatus::Ok),
            (model::TIME_INS, TimeSyncStatus::InsertLeap),
            (model::TIME_DEL, TimeSyncStatus::DeleteLeap),
            (model::TIME_OOP, TimeSyncStatus::LeapInProgress),
            (model::TIME_WAIT, TimeSyncStatus::LeapRecovering),
            (model::TIME_ERROR, TimeSyncStatus::Error),
        ] {
            assert_eq!(unix(model::STA_PLL, state, 10).status, expected, "{state}");
        }
        assert_eq!(
            unix(model::STA_PLL, 99, 10).status,
            TimeSyncStatus::Unavailable,
            "a state this build does not know is not read as one it does"
        );
    }

    #[test]
    fn a_negative_bound_is_no_bound_at_all() {
        let reading = unix(model::STA_PLL, model::TIME_OK, -1);
        assert!(reading.uncertainty_us.as_ref().is_none());
        assert!(!reading.is_qualified());
    }

    #[test]
    fn a_reading_nothing_could_be_taken_for_says_so() {
        let reading = unavailable("macos", "ntp_adjtime(2)", stamp());
        assert_eq!(reading.status, TimeSyncStatus::Unavailable);
        assert_eq!(reading.source, TimeSyncSource::Unclassified);
        assert!(!reading.is_qualified());
    }

    #[test]
    fn the_windows_service_report_is_read_from_its_own_fields() {
        let report = "Leap Indicator: 0(no warning)\n\
                      Stratum: 3 (secondary reference - syncd by (S)NTP)\n\
                      Precision: -23 (119.209ns per tick)\n\
                      Root Delay: 0.0289001s\n\
                      Root Dispersion: 0.4083099s\n\
                      ReferenceId: 0x0A0A0A0A (source IP:  10.10.10.10)\n\
                      Source: time.windows.com,0x9\n";
        let reading = classify_windows("windows", "w32tm /query /status", report, stamp());
        assert_eq!(reading.source, TimeSyncSource::NetworkTimeService);
        assert_eq!(reading.status, TimeSyncStatus::Ok);
        assert_eq!(
            reading.uncertainty_us.as_ref().map(|bound| bound.get()),
            Some(422_760),
            "the bound is the root dispersion plus half the round trip"
        );
        assert!(
            reading.is_qualified(),
            "a bound of four hundred milliseconds is inside what a deadline can rest on"
        );
    }

    #[test]
    fn a_windows_bound_looser_than_the_tolerance_is_not_evidence() {
        let report = "Leap Indicator: 0(no warning)\n\
                      Stratum: 5 (secondary reference - syncd by (S)NTP)\n\
                      Root Delay: 0.0100000s\n\
                      Root Dispersion: 9.4083099s\n\
                      Source: time.windows.com,0x9\n";
        let reading = classify_windows("windows", "w32tm /query /status", report, stamp());
        assert_eq!(reading.source, TimeSyncSource::NetworkTimeService);
        assert_eq!(reading.status, TimeSyncStatus::Ok);
        assert_eq!(
            reading.uncertainty_us.as_ref().map(|bound| bound.get()),
            Some(9_413_310)
        );
        assert!(
            !reading.is_qualified(),
            "nine seconds of dispersion is looser than the rollback this host would notice anyway"
        );
    }

    #[test]
    fn a_windows_report_missing_half_the_bound_carries_no_bound() {
        // Reading a missing round trip as zero would understate what the service is willing to
        // claim, and understating a bound is the one direction that matters.
        let report = "Leap Indicator: 0(no warning)\n\
                      Stratum: 3 (secondary reference - syncd by (S)NTP)\n\
                      Root Dispersion: 0.0100000s\n\
                      Source: time.windows.com,0x9\n";
        let reading = classify_windows("windows", "w32tm /query /status", report, stamp());
        assert_eq!(reading.source, TimeSyncSource::NetworkTimeService);
        assert!(reading.uncertainty_us.as_ref().is_none());
        assert!(!reading.is_qualified());
    }

    #[test]
    fn a_windows_stratum_outside_the_range_is_a_report_this_build_cannot_read() {
        for level in ["0 (unspecified)", "16 (unsynchronized)", "99 (nonsense)"] {
            let report = format!(
                "Leap Indicator: 0(no warning)\nStratum: {level}\nRoot Delay: 0.0010000s\nRoot \
                 Dispersion: 0.0100000s\nSource: time.windows.com,0x9\n"
            );
            let reading = classify_windows("windows", "w32tm /query /status", &report, stamp());
            assert_eq!(reading.source, TimeSyncSource::Unclassified, "{level}");
            assert_eq!(reading.status, TimeSyncStatus::Unavailable, "{level}");
            assert!(!reading.is_qualified(), "{level}");
        }
    }

    #[test]
    fn a_windows_server_whose_name_contains_local_is_still_a_server() {
        let report = "Leap Indicator: 0(no warning)\n\
                      Stratum: 3 (secondary reference - syncd by (S)NTP)\n\
                      Root Delay: 0.0010000s\n\
                      Root Dispersion: 0.0100000s\n\
                      Source: time.corp.local,0x9\n";
        let reading = classify_windows("windows", "w32tm /query /status", report, stamp());
        assert_eq!(
            reading.source,
            TimeSyncSource::NetworkTimeService,
            "the two names that mean no source are matched as names, not as substrings"
        );
        assert!(reading.is_qualified());
    }

    #[test]
    fn a_windows_report_this_build_cannot_read_is_not_evidence() {
        // A source line with no stratum beside it, which is what a report this build does not
        // understand looks like. Not knowing is its own state.
        let report = "Source: time.windows.com,0x9\nLeap Indicator: 0(no warning)\n";
        let reading = classify_windows("windows", "w32tm /query /status", report, stamp());
        assert_eq!(reading.source, TimeSyncSource::Unclassified);
        assert_eq!(reading.status, TimeSyncStatus::Unavailable);
        assert!(!reading.is_qualified());
    }

    #[test]
    fn a_windows_reference_clock_is_a_primary_reference_rather_than_stratum_zero() {
        let primary = "Leap Indicator: 0(no warning)\n\
                       Stratum: 1 (primary reference - syncd by radio clock)\n\
                       Root Dispersion: 0.0000400s\n\
                       Source: Hardware Reference Clock\n";
        let reading = classify_windows("windows", "w32tm /query /status", primary, stamp());
        assert_eq!(reading.source, TimeSyncSource::PulsePerSecond);
        assert!(reading.is_qualified());

        let unspecified = "Leap Indicator: 0(no warning)\n\
                           Stratum: 0 (unspecified)\n\
                           Root Dispersion: 0.0000400s\n\
                           Source: time.windows.com,0x9\n";
        let reading = classify_windows("windows", "w32tm /query /status", unspecified, stamp());
        assert_eq!(
            reading.source,
            TimeSyncSource::Unclassified,
            "stratum zero says nothing about what is keeping the clock"
        );

        // A primary reference this build cannot recognise. Stratum one says the reference is
        // attached to this machine; it does not say what the reference is, and the tightest bound
        // in the table is not given out on the strength of a number. A name that merely mentions
        // a radio is a name, so it is not enough either.
        for unrecognised in [
            "something.this.build.does.not.know,0x1",
            "radio.corp.example,0x9",
            "gps-relay.corp.example,0x9",
        ] {
            let report = format!(
                "Leap Indicator: 0(no warning)\n\
                 Stratum: 1 (primary reference - syncd by radio clock)\n\
                 Root Dispersion: 0.0000400s\n\
                 Source: {unrecognised}\n"
            );
            let reading = classify_windows("windows", "w32tm /query /status", &report, stamp());
            assert_eq!(
                reading.source,
                TimeSyncSource::Unclassified,
                "{unrecognised}"
            );
            assert!(!reading.is_qualified());
            assert!(
                reading.uncertainty_us.as_ref().is_none(),
                "a reading this build could not classify carries no bound"
            );
        }
    }

    #[test]
    fn a_windows_host_on_its_own_clock_is_unsynchronised() {
        let report = "Leap Indicator: 3(not synchronized)\n\
                      Stratum: 0 (unspecified)\n\
                      Source: Local CMOS Clock\n";
        let reading = classify_windows("windows", "w32tm /query /status", report, stamp());
        assert_eq!(reading.source, TimeSyncSource::Unsynchronised);
        assert_eq!(reading.status, TimeSyncStatus::Error);
        assert!(reading.uncertainty_us.as_ref().is_none());
    }

    #[test]
    fn a_windows_report_with_no_source_is_unavailable_rather_than_guessed_at() {
        let reading = classify_windows("windows", "w32tm /query /status", "", stamp());
        assert_eq!(reading.source, TimeSyncSource::Unclassified);
        assert_eq!(reading.status, TimeSyncStatus::Unavailable);
    }

    #[test]
    fn a_windows_leap_second_is_carried_rather_than_hidden() {
        for (indicator, expected) in [
            (0, TimeSyncStatus::Ok),
            (1, TimeSyncStatus::InsertLeap),
            (2, TimeSyncStatus::DeleteLeap),
        ] {
            let report = format!(
                "Leap Indicator: {indicator}(warning)\nStratum: 2 (secondary)\nRoot Delay: \
                 0.0010000s\nRoot Dispersion: 0.0010000s\nSource: time.example,0x8\n"
            );
            let reading = classify_windows("windows", "w32tm /query /status", &report, stamp());
            assert_eq!(reading.status, expected, "{indicator}");
            assert!(reading.is_qualified(), "{indicator}");
        }
    }

    #[test]
    fn this_platform_answers_its_own_time_service() {
        // The real adapter, on whatever machine runs this. What is asserted is what every platform
        // owes: it names itself, it names the interface it read, and it produces one of this
        // build's classified states rather than an invented certainty.
        let reading = PlatformTimeAdapter::new().read();
        assert_eq!(reading.platform, platform_name());
        assert_eq!(reading.api, platform_api());
        assert!(TimeSyncSource::ALL.contains(&reading.source));
        assert!(TimeSyncStatus::ALL.contains(&reading.status));
        if reading.status == TimeSyncStatus::Unavailable {
            assert!(
                reading.uncertainty_us.as_ref().is_none(),
                "a reading that could not be taken carries no bound"
            );
        }
        assert!(reading.wall_clock_ms.get() > 0);
    }

    #[test]
    fn a_recorded_adapter_answers_with_what_it_was_given() {
        let adapter = RecordedTimeAdapter::new(unavailable("macos", "ntp_adjtime(2)", stamp()));
        assert_eq!(adapter.read().status, TimeSyncStatus::Unavailable);
        adapter.set(unix(model::STA_PLL, model::TIME_OK, 10));
        assert_eq!(adapter.read().status, TimeSyncStatus::Ok);
    }
}
