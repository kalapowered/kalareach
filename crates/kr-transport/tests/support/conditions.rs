//! What section 27 asks of a host before a timed figure taken on it means anything.
//!
//! The section 27 targets are acceptance targets measured on a reference host: at least four CPU
//! cores and 8 GiB of memory, the operating system and architecture recorded beside the figure,
//! and the host idle apart from the measurement. A shared virtual machine meets none of that
//! reliably, and no interface reports whether the machine underneath one is quiet. So a harness
//! that runs anywhere has to say which conditions it had, and assert a target only where it had
//! them: a figure taken on a host that could not give the measurement a processor is a figure
//! about contention, and asserting a target against it would fail runs that say nothing about the
//! product.
//!
//! Recording the shortfall is the point. A run that could not assert its target still prints the
//! number it measured and names what was missing, so the run is evidence either way.

use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The processors section 27 asks a reference host for.
pub const REFERENCE_CORES: usize = 4;

/// The memory section 27 asks a reference host for.
pub const REFERENCE_MEMORY_BYTES: u64 = 8 * 1024 * 1024 * 1024;

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
    /// Total memory, where the platform says.
    pub memory_bytes: Option<u64>,
    /// The one-minute load average, where the platform says. Recorded rather than required: it is
    /// an average over the minute before the run, so a build that has just finished still shows in
    /// it.
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

    /// Names every condition this host does not meet for a harness that needs `worker_threads` of
    /// its own and saw `scheduling_delay` of runtime lateness against `delay_ceiling`.
    ///
    /// The processor count is the reference host's plus the harness's own threads, because this
    /// harness is not the product: it runs both ends of the connection and the transfer in one
    /// process, so the four cores section 27 asks for are the ones its runtime occupies and the
    /// measurement needs processors besides them.
    pub fn shortfalls(
        &self,
        worker_threads: usize,
        scheduling_delay: Duration,
        delay_ceiling: Duration,
    ) -> Vec<String> {
        let mut missing = Vec::new();
        if !self.optimised {
            missing.push("the build is not optimised".to_owned());
        }
        let cores_needed = REFERENCE_CORES + worker_threads;
        if self.cores < cores_needed {
            missing.push(format!(
                "{} processors, below the {cores_needed} the reference host and this harness's own \
                 runtime need together",
                self.cores
            ));
        }
        match self.memory_bytes {
            Some(bytes) if bytes >= REFERENCE_MEMORY_BYTES => {}
            Some(bytes) => missing.push(format!(
                "{} MiB of memory, below the reference host's {} MiB",
                bytes / (1024 * 1024),
                REFERENCE_MEMORY_BYTES / (1024 * 1024)
            )),
            None => missing.push("this platform does not report its memory".to_owned()),
        }
        if scheduling_delay > delay_ceiling {
            missing.push(format!(
                "the runtime was woken {:.3} ms late at p95, above the {:.3} ms a host with a \
                 processor to spare shows, so the host was not idle apart from the measurement",
                scheduling_delay.as_secs_f64() * 1000.0,
                delay_ceiling.as_secs_f64() * 1000.0,
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
            format!("  processors        {}", self.cores),
            format!(
                "  memory            {}",
                self.memory_bytes.map_or_else(
                    || "not reported".to_owned(),
                    |bytes| format!("{} MiB", bytes / (1024 * 1024))
                )
            ),
            format!(
                "  load average      {}",
                self.load_average
                    .map_or_else(|| "not reported".to_owned(), |load| format!("{load:.2}"))
            ),
        ]
    }
}

/// How late this runtime wakes a task that asked to be woken.
///
/// This is the one condition section 27 states that nothing else can answer. "An idle host" is not
/// a property a process can look up, and a shared machine's own load is invisible from inside it.
/// What can be measured is what the figure depends on: whether the runtime carrying the
/// measurement is given a processor when it asks for one. A task that asks for five milliseconds
/// and gets forty says the host had nothing to spare.
#[derive(Debug)]
pub struct SchedulingProbe {
    late: Arc<Mutex<Vec<Duration>>>,
    task: tokio::task::JoinHandle<()>,
}

impl SchedulingProbe {
    /// Starts asking to be woken every `interval` on the current runtime.
    ///
    /// The interval is well above the runtime's timer granularity, so what it records is lateness
    /// rather than rounding.
    pub fn start(interval: Duration) -> Self {
        let late = Arc::new(Mutex::new(Vec::new()));
        let samples = Arc::clone(&late);
        let task = tokio::spawn(async move {
            loop {
                let asked = tokio::time::Instant::now() + interval;
                tokio::time::sleep_until(asked).await;
                let over = tokio::time::Instant::now().saturating_duration_since(asked);
                samples
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(over);
            }
        });
        Self { late, task }
    }

    /// Stops and returns every lateness it recorded.
    pub fn stop(self) -> Vec<Duration> {
        self.task.abort();
        std::mem::take(
            &mut *self
                .late
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
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
