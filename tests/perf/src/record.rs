//! The record a performance figure is kept in, beside the host it was taken on.
//!
//! Section 27 asks for every figure to be recorded with the host it was taken on, the operating
//! system and architecture among it, and for a release run's evidence to be kept. A measurement
//! reads the host at the two edges of what it times with a [`Window`], builds its lines, and
//! [`report`] prints them and appends them under `KR_TEST_ARTIFACTS_DIR` as one Markdown section
//! headed by the identifier it measures (`## KR-PERF-001 ...`). It does that before it asserts
//! anything, so a run whose target failed keeps its figure and its verdict rather than only a panic.
//!
//! The reference host is the one `crates/kr-transport/tests/support/conditions.rs` states, read the
//! same way, so every record is held to the same four processors, the same 8 GiB and the same
//! cutoff on the time a hypervisor took.
//!
//! Suites in other crates include this module by its path rather than keep a copy of their own.

#![allow(
    dead_code,
    reason = "each suite that includes this module uses the part of it that it needs"
)]

use std::io::Write as _;
use std::path::{Path, PathBuf};

#[path = "../../../crates/kr-transport/tests/support/conditions.rs"]
mod conditions;

use conditions::{Host, MAX_STOLEN_SHARE, REFERENCE_CORES, REFERENCE_MEMORY_BYTES, StolenTime};

/// The variable that names where a run keeps its evidence.
pub const ARTIFACTS: &str = "KR_TEST_ARTIFACTS_DIR";

/// The host as a measurement began, and the span the hypervisor's share is read over.
#[derive(Debug)]
pub struct Window {
    entering: Option<String>,
    stolen: StolenTime,
}

impl Window {
    /// Reads the host as a measurement begins.
    #[must_use]
    pub fn open() -> Self {
        Self {
            entering: load_average(),
            stolen: StolenTime::start(),
        }
    }

    /// Reads the host again as the measurement ends.
    #[must_use]
    pub fn close(mut self) -> Conditions {
        Conditions {
            host: Host::read(),
            entering: self.entering,
            leaving: load_average(),
            stolen: self.stolen.take(),
        }
    }
}

/// What the host was while a measurement ran.
#[derive(Debug)]
pub struct Conditions {
    host: Host,
    entering: Option<String>,
    leaving: Option<String>,
    stolen: Option<f64>,
}

impl Conditions {
    /// The lines that record the host, in the order every record gives them.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let host = &self.host;
        let unread = || "unread".to_owned();
        let shortfalls = host.shortfalls(self.stolen);
        vec![
            format!(
                "  build             {}",
                if host.optimised { "release" } else { "debug" }
            ),
            format!("  host              {} {}", host.os, host.arch),
            format!(
                "  processor         {}",
                host.processor.as_deref().unwrap_or("not reported here")
            ),
            format!(
                "  processors        {} against the reference host's {REFERENCE_CORES}",
                host.cores
            ),
            format!(
                "  memory            {}",
                host.memory_bytes.map_or_else(
                    || "not reported here, so unverified".to_owned(),
                    |bytes| format!(
                        "{} MiB against the reference host's {} MiB",
                        bytes / (1024 * 1024),
                        REFERENCE_MEMORY_BYTES / (1024 * 1024)
                    )
                )
            ),
            format!(
                "  load average      {} entering, {} leaving (1, 5 and 15 minutes)",
                self.entering.clone().unwrap_or_else(unread),
                self.leaving.clone().unwrap_or_else(unread)
            ),
            format!(
                "  stolen share      {}",
                match self.stolen {
                    Some(share) => format!(
                        "{:.2}% of the measurement, against the {:.2}% a reference host admits",
                        share * 100.0,
                        MAX_STOLEN_SHARE * 100.0
                    ),
                    None if cfg!(target_os = "linux") =>
                        "could not be read, so unverified".to_owned(),
                    None => "not accounted on this platform, so unverified".to_owned(),
                }
            ),
            if shortfalls.is_empty() {
                "  reference host    no condition read here falls short of it".to_owned()
            } else {
                format!("  reference host    short: {}", shortfalls.join("; "))
            },
        ]
    }
}

/// Returns the one-, five- and fifteen-minute load averages, where the host reports them.
fn load_average() -> Option<String> {
    let first_three = |text: &str| {
        let text = text
            .trim()
            .trim_matches(|character| character == '{' || character == '}');
        let reading: Vec<&str> = text.split_whitespace().take(3).collect();
        (reading.len() == 3).then(|| reading.join(" "))
    };
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|text| first_three(&text))
        .or_else(|| {
            let output = std::process::Command::new("sysctl")
                .args(["-n", "vm.loadavg"])
                .output()
                .ok()?;
            first_three(&String::from_utf8_lossy(&output.stdout))
        })
}

/// Prints one measurement's section and keeps it where the run keeps its evidence.
///
/// A run that has not set `KR_TEST_ARTIFACTS_DIR` prints the section and keeps nothing.
///
/// # Panics
///
/// When the run asked for its evidence to be kept and it could not be written. A run whose evidence
/// is missing has none, and an earlier record in the same place would hide that. The lines are
/// printed first, so nothing measured is lost with the file.
pub fn report(file: &str, measurement: &str, lines: &[String]) {
    let directory = std::env::var_os(ARTIFACTS).map(PathBuf::from);
    report_in(directory.as_deref(), file, measurement, lines);
}

/// [`report`], with the evidence directory given rather than read from the environment.
///
/// # Panics
///
/// As [`report`] does.
pub fn report_in(directory: Option<&Path>, file: &str, measurement: &str, lines: &[String]) {
    println!("{measurement}");
    for line in lines {
        println!("{line}");
    }
    let Some(directory) = directory else {
        return;
    };
    if let Err(error) = keep(directory, file, measurement, lines) {
        panic!(
            "this run could not keep its evidence at {}: {error}",
            directory.join(file).display()
        );
    }
}

/// Appends one section to `file` in `directory`, creating either as needed.
///
/// # Errors
///
/// What the file system refused.
pub fn keep(
    directory: &Path,
    file: &str,
    measurement: &str,
    lines: &[String],
) -> std::io::Result<()> {
    let mut section = format!("## {measurement}\n\n");
    for line in lines {
        section.push_str(line);
        section.push('\n');
    }
    section.push('\n');
    std::fs::create_dir_all(directory)?;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join(file))?
        .write_all(section.as_bytes())
}
