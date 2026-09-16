//! What section 27 asks of a host before a timed figure taken on it means anything.
//!
//! The section 27 targets are acceptance targets measured on a reference host: at least four CPU
//! cores and 8 GiB of memory, the operating system and architecture recorded beside the figure,
//! and the host idle apart from the measurement. A harness that runs anywhere has to say which of
//! those it had, because a figure taken on a host that could not give the measurement a processor
//! is a figure about contention.
//!
//! Two rules keep that from becoming a way of skipping a check.
//!
//! A condition is a shortfall only when the host can be shown not to meet it. A processor count
//! below four is a shortfall; a memory figure below 8 GiB is a shortfall; a platform that does not
//! report its memory leaves that condition *unverified*, which is recorded and is not a shortfall,
//! because a harness's own gap is not a property of the host.
//!
//! And a condition never rests on something the application under test could have caused. Section
//! 27's idle host is the hard one: no interface reports whether the machine underneath a shared
//! virtual one is quiet. What this module reads is the time the hypervisor took the processor away
//! from the whole guest, which is a host fact the measured application cannot produce. Beside it,
//! as evidence rather than as a condition, a thread of its own asks to be woken at a steady
//! interval and records how late each wake was; that thread is outside the runtime the measurement
//! runs on, so it reports contention rather than the application's own work, but lateness alone
//! cannot tell a busy neighbour from a slow processor and it decides nothing.
//!
//! Recording the shortfall is the point. A run that could not assert its target still prints the
//! number it measured and names what was missing, so the run is evidence either way.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The processors section 27 asks a reference host for.
pub const REFERENCE_CORES: usize = 4;

/// The memory section 27 asks a reference host for.
pub const REFERENCE_MEMORY_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// The share of a measurement the hypervisor may take from the guest before the host cannot be
/// called idle.
///
/// One part in a hundred. Above that the processor spent a material part of the measurement
/// running something outside this machine, which is exactly the condition section 27 excludes and
/// is not something the application under test can cause.
pub const MAX_STOLEN_SHARE: f64 = 0.01;

/// The host a measurement ran on, as far as it can be read.
#[derive(Debug, Clone)]
pub struct Host {
    /// Whether the build was optimised. A timing taken from an unoptimised build measures the
    /// build.
    pub optimised: bool,
    /// The operating system, which section 27 requires beside every figure.
    pub os: &'static str,
    /// The architecture, likewise.
    pub arch: &'static str,
    /// Logical processors available to this process.
    pub cores: usize,
    /// Total memory, where the platform reports it. `None` leaves the condition unverified.
    pub memory_bytes: Option<u64>,
    /// The one-minute load average, where the platform reports it. Evidence rather than a
    /// condition: it is an average over the minute before the run, so a build that has just
    /// finished still shows in it, and the measurement's own load shows in it too.
    pub load_average: Option<f64>,
}

impl Host {
    /// Reads what this host will say about itself.
    pub fn read() -> Self {
        Self {
            optimised: !cfg!(debug_assertions),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            cores: std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get),
            memory_bytes: total_memory_bytes(),
            load_average: load_average(),
        }
    }

    /// Names every condition section 27 states that this host can be shown not to meet.
    ///
    /// `stolen` is what [`StolenTime`] measured across the whole run, where the platform reports
    /// it. A condition that cannot be read is left out: it is recorded as unverified by
    /// [`Host::lines`] rather than counted against the host.
    pub fn shortfalls(&self, stolen: Option<f64>) -> Vec<String> {
        let mut missing = Vec::new();
        if !self.optimised {
            missing.push("the build is not optimised".to_owned());
        }
        if self.cores < REFERENCE_CORES {
            missing.push(format!(
                "{} processors, below the reference host's {REFERENCE_CORES}",
                self.cores
            ));
        }
        if let Some(bytes) = self.memory_bytes
            && bytes < REFERENCE_MEMORY_BYTES
        {
            missing.push(format!(
                "{} MiB of memory, below the reference host's {} MiB",
                bytes / (1024 * 1024),
                REFERENCE_MEMORY_BYTES / (1024 * 1024)
            ));
        }
        if let Some(share) = stolen
            && share > MAX_STOLEN_SHARE
        {
            missing.push(format!(
                "the hypervisor took {:.2}% of the measurement from this guest, above the {:.2}% a \
                 host idle apart from the measurement shows",
                share * 100.0,
                MAX_STOLEN_SHARE * 100.0
            ));
        }
        missing
    }

    /// The lines a run prints to record what it ran on.
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!(
                "  build             {}",
                if self.optimised { "release" } else { "debug" }
            ),
            format!("  host              {} {}", self.os, self.arch),
            format!(
                "  processors        {} against the reference host's {REFERENCE_CORES}",
                self.cores
            ),
            format!(
                "  memory            {}",
                self.memory_bytes.map_or_else(
                    || "not reported here, so unverified".to_owned(),
                    |bytes| format!(
                        "{} MiB against the reference host's {} MiB",
                        bytes / (1024 * 1024),
                        REFERENCE_MEMORY_BYTES / (1024 * 1024)
                    )
                )
            ),
            format!(
                "  load average      {}",
                self.load_average.map_or_else(
                    || "not reported here".to_owned(),
                    |load| format!("{load:.2}")
                )
            ),
        ]
    }
}

/// How much of a measurement the hypervisor took from this guest.
///
/// The one condition section 27 states that nothing else can answer. "An idle host" is not a
/// property a process can look up, and a shared machine's own load is invisible from inside it,
/// but the time the processor was taken from the whole guest *is* reported where a platform
/// accounts for it. It is a host fact: the application under test cannot produce it, which is what
/// makes it safe to gate on. A platform that does not account for it leaves the condition
/// unverified.
#[derive(Debug)]
pub struct StolenTime {
    started: Option<StolenSample>,
}

#[derive(Debug, Clone, Copy)]
struct StolenSample {
    stolen_ticks: u64,
    at: Instant,
    ticks_per_second: f64,
    cores: f64,
}

impl StolenTime {
    /// Starts counting.
    pub fn start() -> Self {
        Self {
            started: stolen_sample(),
        }
    }

    /// Returns the share of the elapsed processor time the hypervisor took, where this platform
    /// accounts for it.
    pub fn share(&self) -> Option<f64> {
        let first = self.started?;
        let last = stolen_sample()?;
        let elapsed = last.at.duration_since(first.at).as_secs_f64();
        if elapsed <= 0.0 {
            return None;
        }
        let ticks = last.stolen_ticks.saturating_sub(first.stolen_ticks);
        #[expect(
            clippy::cast_precision_loss,
            reason = "a tick count over one measurement is far inside f64's exact range"
        )]
        let seconds = ticks as f64 / first.ticks_per_second;
        Some(seconds / (elapsed * first.cores))
    }
}

/// Reads the guest's stolen-time counter, where the platform keeps one.
///
/// Linux reports it as the eighth field of the aggregate processor line of `/proc/stat`, in the
/// kernel's own tick units. No other supported platform accounts for it, so the condition is
/// unverified there.
fn stolen_sample() -> Option<StolenSample> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let text = std::fs::read_to_string("/proc/stat").ok()?;
    let line = text.lines().next()?;
    let mut fields = line.split_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }
    let stolen_ticks: u64 = fields.nth(7)?.parse().ok()?;
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    #[expect(
        clippy::cast_precision_loss,
        reason = "a processor count is a small integer"
    )]
    let cores = cores as f64;
    Some(StolenSample {
        stolen_ticks,
        at: Instant::now(),
        // The kernel's user-space tick rate, which is 100 on every Linux this build supports.
        ticks_per_second: 100.0,
        cores,
    })
}

/// How late a thread of its own is woken while the measurement runs.
///
/// Evidence, not a condition. It runs outside the runtime the measurement uses, so the application
/// under test cannot delay it through that runtime, but a slow processor and a busy neighbour look
/// the same from here and neither is something to assert on. What it is good for is reading a run
/// afterwards: a figure taken beside tens of milliseconds of lateness is worth less than the same
/// figure taken beside one.
#[derive(Debug)]
pub struct SchedulingProbe {
    late: Arc<Mutex<Vec<Duration>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl SchedulingProbe {
    /// Starts asking to be woken every `interval`, on a thread of its own.
    ///
    /// The interval is well above a platform's sleep granularity, so what it records is lateness
    /// rather than rounding.
    pub fn start(interval: Duration) -> Self {
        let late = Arc::new(Mutex::new(Vec::new()));
        let samples = Arc::clone(&late);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
                let asked = Instant::now() + interval;
                std::thread::sleep(interval);
                let over = Instant::now().saturating_duration_since(asked);
                samples
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(over);
            }
        });
        Self {
            late,
            stop,
            thread: Some(thread),
        }
    }

    /// Stops and returns every lateness it recorded.
    pub fn stop(mut self) -> Vec<Duration> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        std::mem::take(
            &mut *self
                .late
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

impl Drop for SchedulingProbe {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Total memory, where the platform reports it.
fn total_memory_bytes() -> Option<u64> {
    if cfg!(target_os = "linux") {
        let text = std::fs::read_to_string("/proc/meminfo").ok()?;
        let line = text.lines().find(|line| line.starts_with("MemTotal:"))?;
        let kibibytes: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
        return kibibytes.checked_mul(1024);
    }
    if cfg!(target_os = "macos") {
        return sysctl("hw.memsize")?.parse().ok();
    }
    None
}

/// The one-minute load average, where the platform reports it.
fn load_average() -> Option<f64> {
    if cfg!(target_os = "linux") {
        let text = std::fs::read_to_string("/proc/loadavg").ok()?;
        return text.split_whitespace().next()?.parse().ok();
    }
    if cfg!(target_os = "macos") {
        // `{ 1.62 2.08 2.23 }`
        return sysctl("vm.loadavg")?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok();
    }
    None
}

/// Reads one kernel variable, or nothing when this host has no `sysctl`.
fn sysctl(name: &str) -> Option<String> {
    let output = std::process::Command::new("sysctl")
        .arg("-n")
        .arg(name)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
