//! `scripts/performance.sh`'s start of each measurement on a machine that has settled.
//!
//! Section 27 measures an idle host, and a machine that has just built the workspace, or has just
//! finished another measurement, is not one: a figure taken then is a figure about whatever the
//! machine was still doing. A run that names a one-minute load in `KR_PERF_SETTLE_LOAD` starts each
//! measurement only once the load is under it, and fails without taking the figure when the load does
//! not fall. A run that names none measures at whatever load the machine has, as it always has.
//!
//! These checks run the script itself with `cargo` standing in for the build and every suite, and
//! with `sysctl` and `sleep` standing in for the machine's load and for the passing of time. The
//! load falls only when the script waits, one reading for each wait, and a measurement leaves it
//! where the build did, so the checks need no real wait and no real load.
//!
//! Unix only: the script is a Unix shell script.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Prints the load as macOS does: `{ one five fifteen }`. The one-minute figure is the reading the
/// run is at, which is the line of the readings file that the number of waits so far points at, and
/// the last line from there on.
const SYSCTL: &str = r#"#!/bin/sh
[ "$*" = "-n vm.loadavg" ] || exit 1
n=$(cat "$KR_STAND_IN_STATE/waited")
reading=$(sed -n "$((n + 1))p" "$KR_STAND_IN_STATE/readings")
[ -n "$reading" ] || reading=$(tail -n 1 "$KR_STAND_IN_STATE/readings")
echo "{ $reading 5.18 7.26 }"
"#;

/// Time passes only when the script waits: each wait is one step along the readings.
const SLEEP: &str = r#"#!/bin/sh
n=$(cat "$KR_STAND_IN_STATE/waited")
echo $((n + 1)) > "$KR_STAND_IN_STATE/waited"
"#;

/// Every invocation is kept. A build succeeds at once. A measurement keeps the one-minute load it
/// started at, and leaves the load back at the first reading, as a build or a measurement leaves
/// a machine busy; every other suite succeeds at once.
const CARGO: &str = r#"#!/bin/sh
echo "$*" >> "$KR_STAND_IN_STATE/calls"
case "$*" in
  build*) exit 0 ;;
  *--ignored*)
    sysctl -n vm.loadavg | tr -d '{}' | awk '{ print $1 }' >> "$KR_STAND_IN_STATE/started"
    echo 0 > "$KR_STAND_IN_STATE/waited"
    echo "the measurement"
    echo "test result: ok. 1 passed; 0 failed; 0 ignored"
    ;;
  *) echo "test result: ok. 3 passed; 0 failed; 0 ignored" ;;
esac
"#;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository")
}

fn stand_in(bin: &Path, name: &str, body: &str) {
    let path = bin.join(name);
    std::fs::write(&path, body).expect("the stand-in");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .expect("the stand-in runs");
}

/// What one run of the script did.
struct Run {
    /// The script's exit status.
    status: Option<i32>,
    /// What it printed.
    printed: String,
    /// The one-minute load each measurement started at, in order.
    started: Vec<String>,
    /// How many times the script ran `cargo` at all.
    calls: usize,
}

/// Runs the script on a machine whose one-minute load reads `readings` as the script waits, with
/// `bound` as `KR_PERF_SETTLE_LOAD` where one is given.
fn performance(readings: &[&str], bound: Option<&str>) -> Run {
    let directory = tempfile::tempdir().expect("a directory");
    let state = directory.path().join("state");
    let bin = directory.path().join("bin");
    let temporary = directory.path().join("tmp");
    for each in [&state, &bin, &temporary] {
        std::fs::create_dir_all(each).expect("a directory");
    }
    std::fs::write(state.join("readings"), readings.join("\n") + "\n").expect("the readings");
    std::fs::write(state.join("waited"), "0\n").expect("the clock");
    stand_in(&bin, "sysctl", SYSCTL);
    stand_in(&bin, "sleep", SLEEP);
    stand_in(&bin, "cargo", CARGO);
    let mut command = Command::new("/bin/bash");
    command
        .arg(repository().join("scripts/performance.sh"))
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", bin.display()),
        )
        .env("TMPDIR", &temporary)
        .env("KR_STAND_IN_STATE", &state)
        .env_remove("KR_PERF_SETTLE_LOAD");
    if let Some(bound) = bound {
        command.env("KR_PERF_SETTLE_LOAD", bound);
    }
    let output = command.output().expect("the script runs");
    let lines = |file: &str| -> Vec<String> {
        std::fs::read_to_string(state.join(file))
            .map(|text| text.lines().map(str::to_owned).collect())
            .unwrap_or_default()
    };
    Run {
        status: output.status.code(),
        printed: format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        started: lines("started"),
        calls: lines("calls").len(),
    }
}

#[test]
fn each_measurement_starts_only_once_the_load_is_under_the_bound() {
    // The build leaves the load high, and every measurement leaves it high again, so each of the
    // four has to wait for it to fall.
    let run = performance(&["6.90", "3.29", "1.20"], Some("1.5"));
    assert_eq!(run.status, Some(0), "{}", run.printed);
    assert_eq!(
        run.started,
        ["1.20", "1.20", "1.20", "1.20"],
        "every measurement started at a load under the bound:\n{}",
        run.printed
    );
}

#[test]
fn a_machine_that_does_not_settle_is_not_measured() {
    let run = performance(&["3.29"], Some("1.5"));
    assert_ne!(run.status, Some(0), "{}", run.printed);
    assert!(
        run.started.is_empty(),
        "no measurement started on a machine that never fell under the bound: {:?}",
        run.started
    );
    assert!(
        run.printed.contains("did not settle") && run.printed.contains("still 3.29"),
        "the run says the machine did not settle, and at what load:\n{}",
        run.printed
    );
}

#[test]
fn a_load_that_cannot_be_read_as_a_number_is_not_a_settled_machine() {
    // What the script prints when nothing answers is read by awk as zero, which is under every
    // bound, so only the script's own check keeps an unreadable load from counting as a quiet one.
    let run = performance(&["unknown"], Some("1.5"));
    assert_ne!(run.status, Some(0), "{}", run.printed);
    assert!(
        run.started.is_empty(),
        "no measurement started on a load that could not be read: {:?}",
        run.started
    );
    assert!(
        run.printed.contains("could not be read") && run.printed.contains("did not settle"),
        "the run says the load could not be read:\n{}",
        run.printed
    );
}

#[test]
fn a_run_that_names_no_bound_measures_at_whatever_load_the_machine_has() {
    let run = performance(&["6.90"], None);
    assert_eq!(run.status, Some(0), "{}", run.printed);
    assert_eq!(run.started, ["6.90", "6.90", "6.90", "6.90"]);
}

#[test]
fn a_bound_that_is_not_a_load_is_refused_before_anything_runs() {
    for bound in ["1,5", "", "0", "-1", "fast"] {
        let run = performance(&["1.20"], Some(bound));
        assert_eq!(run.status, Some(2), "{bound:?}: {}", run.printed);
        assert_eq!(run.calls, 0, "{bound:?}: nothing was built or measured");
    }
}
