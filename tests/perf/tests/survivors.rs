//! `scripts/performance.sh`'s own check that nothing it started outlives it.
//!
//! The script gives its run a temporary root and exports it as `TMPDIR`, so every process a suite
//! starts names that root, and at the end it looks for processes that still name it. Those
//! processes do not all name it the way the script wrote it. macOS's `TMPDIR` ends in a slash, so
//! the root its `mktemp` returns holds `//`, and it lies under `/var`, a link to `/private/var`,
//! so a process that resolved its paths carries the physical path. These checks run the script
//! with `cargo` standing in for the build and every suite, and with a `TMPDIR` that is a link and
//! ends in a slash, on every platform. One of them leaves behind a process that names the run's
//! root by its physical path, as a worker a suite failed to close would.
//!
//! Unix only: the script is a Unix shell script.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The stand-in for `cargo`: every build and every suite succeeds at once and prints what the
/// script looks for. When `KR_PERF_PLANT` names a file, the first measurement also starts a process
/// that names the run's root by its physical path and writes that process's identifier there. The
/// process ends by itself after three minutes whatever becomes of this test.
const CARGO: &str = r#"#!/bin/sh
case "$*" in
  build*) exit 0 ;;
  *--ignored*)
    if [ -n "${KR_PERF_PLANT:-}" ] && [ ! -e "$KR_PERF_PLANT" ]; then
      physical="$(cd "$TMPDIR" && pwd -P)"
      /bin/sh -c 'i=0; while [ "$i" -lt 180 ]; do sleep 1; i=$((i + 1)); done' \
        "$physical/a-worker-nobody-closed" > /dev/null 2>&1 < /dev/null &
      echo "$!" > "$KR_PERF_PLANT"
    fi
    echo "the measurement"
    echo "test result: ok. 1 passed; 0 failed; 0 ignored"
    ;;
  *) echo "test result: ok. 3 passed; 0 failed; 0 ignored" ;;
esac
"#;

/// A process this test planted, ended when the test ends however it ends.
struct Planted(u32);

impl Drop for Planted {
    fn drop(&mut self) {
        let _ = Command::new("/bin/kill").arg(self.0.to_string()).status();
    }
}

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository")
}

/// Runs the script with the stand-in, planting a survivor when `plant` names a file for it.
fn performance(directory: &Path, plant: Option<&Path>) -> Output {
    let bin = directory.join("bin");
    std::fs::create_dir_all(&bin).expect("a directory for the stand-in");
    let cargo = bin.join("cargo");
    std::fs::write(&cargo, CARGO).expect("the stand-in");
    std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o700))
        .expect("the stand-in runs");
    let physical = directory.join("physical");
    std::fs::create_dir_all(&physical).expect("a temporary directory");
    let temporary = directory.join("tmp");
    std::os::unix::fs::symlink(&physical, &temporary).expect("a link to it");
    let mut command = Command::new("/bin/bash");
    command
        .arg(repository().join("scripts/performance.sh"))
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", bin.display()),
        )
        // Through a link and with a trailing slash, as macOS gives it.
        .env("TMPDIR", format!("{}/", temporary.display()))
        .env_remove("KR_PERF_PLANT");
    if let Some(plant) = plant {
        command.env("KR_PERF_PLANT", plant);
    }
    command.output().expect("the script runs")
}

#[test]
fn a_process_that_outlives_the_script_is_reported() {
    let directory = tempfile::tempdir().expect("a directory");
    let plant = directory.path().join("planted");
    let output = performance(directory.path(), Some(&plant));
    let pid: u32 = std::fs::read_to_string(&plant)
        .expect("the stand-in planted a process")
        .trim()
        .parse()
        .expect("its identifier");
    let _planted = Planted(pid);
    let printed = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success(),
        "the script passed with process {pid} still running and naming its root:\n{printed}"
    );
    assert!(
        printed.contains("FAILED: these processes outlived the script")
            && printed
                .lines()
                .any(|line| line.trim_start().starts_with(&format!("{pid} "))),
        "the script names process {pid} as the one that outlived it:\n{printed}"
    );
}

#[test]
fn a_run_that_leaves_nothing_behind_passes_the_check() {
    let directory = tempfile::tempdir().expect("a directory");
    let output = performance(directory.path(), None);
    let printed = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && printed.contains("no process this run started is still running"),
        "a run that started nothing that survives passes the check:\n{printed}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
