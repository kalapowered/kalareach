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
//! virtual one is quiet. What this module reads is the share of the processor time the hypervisor
//! took away from the whole guest, which is a host fact the measured application cannot produce.
//! Beside it, as evidence rather than as a condition, a thread of its own asks to be woken at a
//! steady interval and records how late each wake was; that thread is outside the runtime the
//! measurement runs on, so it reports contention rather than the application's own work, but
//! lateness alone cannot tell a busy neighbour from a slow processor and it decides nothing.
//!
//! What the stolen share cannot do is prove the opposite. A zero reading means the hypervisor
//! reported no loss, which is not the same as an idle host: an environment that does not account
//! for stolen time reads zero, and throttling and a neighbour inside the same guest cost time
//! without being stolen. So the cutoff below is this harness's own exclusion rule rather than a
//! threshold section 27 states, and a figure it admits is a figure with no measured shortfall
//! rather than a certified reference-host measurement.
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

/// The share of a measurement the hypervisor may take from the guest before this harness stops
/// asserting a target on it.
///
/// One part in a hundred. Above that the processor spent a material part of the measurement
/// running something outside this machine, which is the one part of section 27's idle host that
/// can be read and is not something the application under test can cause. The number is this
/// harness's exclusion rule: section 27 states the reference host's processors and memory and says
/// the host is idle, and quantifies nothing about how idle.
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
    /// What the platform calls this processor. Section 27 records the host beside every figure
    /// because a rate depends on it, and two hosts of the same architecture are not the same
    /// processor.
    pub processor: Option<String>,
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
            processor: processor_model(),
            load_average: load_average(),
        }
    }

    /// Names every condition section 27 states that this host can be shown not to meet.
    ///
    /// `stolen` is the largest share [`StolenTime`] measured over any one phase of the run, where
    /// the platform accounts for it. A condition that cannot be read is left out: it is recorded as
    /// unverified by [`Host::lines`] rather than counted against the host.
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
                "the hypervisor took {:.2}% of a phase of the measurement from this guest, above \
                 the {:.2}% this harness admits",
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
                "  processor         {}",
                self.processor
                    .clone()
                    .unwrap_or_else(|| "not reported here".to_owned())
            ),
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
/// The one part of section 27's idle host that can be read. "An idle host" is not a property a
/// process can look up, and a shared machine's own load is invisible from inside it, but the share
/// of the processor time the hypervisor took from the whole guest *is* accounted for where a
/// platform keeps it. It is a host fact: the application under test cannot produce it, which is
/// what makes it safe to gate on. A platform that does not account for it leaves the condition
/// unverified, and so does a counter that went backwards between two readings.
///
/// The share is a ratio of the same counters, so nothing here depends on the kernel's tick rate or
/// on how many processors the reading covers: stolen ticks over every tick the whole processor line
/// accounts for. `guest` and `guest_nice` are left out because they repeat time already counted in
/// `user` and `nice`.
#[derive(Debug)]
pub struct StolenTime {
    /// The reading the next span starts from, which is `None` before the first successful one and
    /// again whenever a reading fails.
    started: Option<StolenSample>,
}

/// The processor line's counters at one moment, in whatever ticks the kernel counts in.
#[derive(Debug, Clone, Copy)]
pub struct StolenSample {
    stolen: u64,
    total: u64,
}

impl StolenSample {
    /// Builds a reading from the two counters, which is how a test drives the boundary rules
    /// without a `/proc/stat` that can be made to fail on demand.
    #[must_use]
    pub const fn new(stolen: u64, total: u64) -> Self {
        Self { stolen, total }
    }
}

impl StolenTime {
    /// Starts counting.
    pub fn start() -> Self {
        Self {
            started: stolen_sample(),
        }
    }

    /// Returns the share of the processor time the hypervisor took since the last reading, where
    /// this platform accounts for it, and starts a fresh span from this one.
    ///
    /// Reading it per phase is what lets a run say that each phase stayed inside the cutoff. One
    /// average over a whole run cannot: a phase that lost a tenth of its processor and a phase
    /// that lost nothing average to a figure that looks like neither.
    ///
    /// Every call replaces the reading the next span starts from, including the calls that answer
    /// nothing. A reading that failed therefore leaves the span it ended unverified rather than
    /// rolling that span into the next one, where time from the phase before it would be reported
    /// as the phase after it. A later span recovers on the next successful pair.
    pub fn take(&mut self) -> Option<f64> {
        self.advance(stolen_sample())
    }

    /// The boundary rules, over a reading a caller supplies.
    ///
    /// Separate from [`StolenTime::take`] so the rules can be driven through a reading that failed
    /// without a `/proc/stat` that fails on demand. The store happens before anything can return:
    /// a reading that failed has to become the boundary, or the span it ended is rolled into the
    /// next one and time from the phase before is reported as the phase after.
    pub fn advance(&mut self, last: Option<StolenSample>) -> Option<f64> {
        let first = std::mem::replace(&mut self.started, last);
        let first = first?;
        let last = last?;
        let stolen = last.stolen.checked_sub(first.stolen)?;
        let total = last.total.checked_sub(first.total)?;
        if total == 0 {
            return None;
        }
        #[expect(
            clippy::cast_precision_loss,
            reason = "a tick count over one measurement is far inside f64's exact range"
        )]
        let share = stolen as f64 / total as f64;
        Some(share)
    }
}

/// Reads the aggregate processor line's counters, where the platform keeps them.
///
/// Linux reports them on the first line of `/proc/stat`: `user nice system idle iowait irq softirq
/// steal guest guest_nice`. No other supported platform accounts for stolen time, so the condition
/// is unverified there.
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
    // The first eight fields are the processor's time; `guest` and `guest_nice` after them repeat
    // time `user` and `nice` already counted.
    let counters: Vec<u64> = fields
        .take(8)
        .map(|field| field.parse().ok())
        .collect::<Option<_>>()?;
    if counters.len() < 8 {
        return None;
    }
    Some(StolenSample {
        stolen: counters[7],
        total: counters.iter().copied().try_fold(0u64, u64::checked_add)?,
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

/// Prints one measurement's lines and retains them where a run keeps its evidence.
///
/// Section 27 asks for the figures to be recorded with the host they were taken on and for a
/// release run's evidence to be kept. `KR_TEST_ARTIFACTS_DIR` is where this build puts that, and a
/// run that has not set it prints the record and keeps nothing. Call it before a target is
/// asserted, so a run the target failed on retains the figure and the verdict rather than only the
/// panic.
pub fn report(measurement: &str, lines: &[String]) {
    println!("{measurement}");
    for line in lines {
        println!("{line}");
    }
    let Some(dir) = std::env::var_os("KR_TEST_ARTIFACTS_DIR") else {
        return;
    };
    // A run that asked for its evidence to be kept and could not keep it has no evidence, and a
    // retained directory that happens to hold an earlier record would hide that. So a write that
    // fails fails the run, naming where it was writing and why it could not. The lines are already
    // printed by the time this runs, so nothing measured is lost with the file.
    let dir = std::path::PathBuf::from(dir);
    let mut record = format!("## {measurement}\n\n");
    for line in lines {
        record.push_str(line);
        record.push('\n');
    }
    record.push('\n');
    let path = dir.join("kr-transport-scheduling.md");
    let write = || -> std::io::Result<()> {
        use std::io::Write;
        std::fs::create_dir_all(&dir)?;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?
            .write_all(record.as_bytes())
    };
    if let Err(error) = write() {
        panic!(
            "this run could not keep its evidence at {}: {error}",
            path.display()
        );
    }
}

/// What the platform calls this processor, where it says.
fn processor_model() -> Option<String> {
    if cfg!(target_os = "linux") {
        let text = std::fs::read_to_string("/proc/cpuinfo").ok()?;
        let line = text.lines().find(|line| line.starts_with("model name"))?;
        return Some(line.split_once(':')?.1.trim().to_owned());
    }
    if cfg!(target_os = "macos") {
        return sysctl("machdep.cpu.brand_string");
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
