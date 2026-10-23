//! What the landing workflow keeps of the tests that need a browser, a desktop session or a phone.
//!
//! Section 21 names a tool for each class of test and asks for the tests' screenshots to be kept in
//! `KR_TEST_ARTIFACTS_DIR` and collected into the CI artifact store. A workflow is how that is
//! delivered, so these hold the two things a deleted step or a moved file would lose without any
//! job going red: the check that refuses a run with no screenshot kept, run on real directories,
//! and a job for each class of test on a runner that has its tool.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// Runs the evidence check on an evidence directory and a directory to search for strays.
fn check(evidence: &Path, strays: &Path) -> Option<i32> {
    Command::new("bash")
        .arg(repository().join("scripts/check-test-evidence.sh"))
        .arg(evidence)
        .arg("companion-screenshots")
        .arg(strays)
        .output()
        .expect("bash runs")
        .status
        .code()
}

/// KR-REQ-21.02: a run whose browser tests kept their screenshots in the evidence directory
/// passes, and a run that kept none, or left one in the temporary directory where the runner would
/// lose it, fails.
#[test]
fn a_run_that_kept_no_screenshot_in_the_evidence_directory_fails() {
    let evidence = TempDir::new().expect("a directory");
    let strays = TempDir::new().expect("a directory");

    // Nothing was kept: the evidence directory has no pictures, or does not exist.
    assert_eq!(check(evidence.path(), strays.path()), Some(1));
    assert_eq!(
        check(&evidence.path().join("absent"), strays.path()),
        Some(1)
    );

    // A picture in the directory, and none elsewhere.
    let kept = evidence.path().join("companion-screenshots");
    fs::create_dir_all(&kept).expect("a directory");
    fs::write(kept.join("kr-companion-shell-chromium.png"), b"\x89PNG").expect("a picture");
    assert_eq!(check(evidence.path(), strays.path()), Some(0));

    // The same run, with one picture written outside the directory.
    fs::write(
        strays.path().join("kr-companion-settings-webkit.png"),
        b"\x89PNG",
    )
    .expect("a picture");
    assert_eq!(check(evidence.path(), strays.path()), Some(1));
}

/// The text of one job of the landing workflow: its header line to the next job's.
fn job(workflow: &str, name: &str) -> String {
    let lines: Vec<&str> = workflow.lines().collect();
    let header = format!("  {name}:");
    let start = lines
        .iter()
        .position(|line| *line == header)
        .unwrap_or_else(|| panic!("the workflow has a {name} job"));
    let is_job = |line: &str| {
        line.len() > 3
            && line.starts_with("  ")
            && !line.starts_with("   ")
            && line.trim_end().ends_with(':')
    };
    let end = lines[start + 1..]
        .iter()
        .position(|line| is_job(line))
        .map_or(lines.len(), |offset| start + 1 + offset);
    lines[start..end].join("\n")
}

/// KR-REQ-21.01: each class of test section 21 names has a job in the landing workflow that runs
/// its tool on a runner that has it: Playwright for browser behaviour, the operating system's own
/// tooling for native controls and for the iOS Simulator on macOS, an Android emulator for the
/// Android phone, and a hosted Windows, Linux and macOS machine each for its platform's tests.
#[test]
fn each_class_of_test_has_a_job_that_runs_its_tool_on_a_runner_that_has_it() {
    let workflow = fs::read_to_string(repository().join(".github/workflows/core-ci.yml"))
        .expect("the landing workflow");
    // (the class, the job, what its runner line holds, what one of its steps runs)
    let classes: [(&str, &str, &[&str], &str); 8] = [
        (
            "browser behaviour, on both kinds of runner",
            "companion",
            &["ubuntu-24.04", "macos-15"],
            "pnpm -C apps/companion e2e",
        ),
        (
            "native macOS controls",
            "companion",
            &["macos-15", "runner.os == 'macOS'"],
            "scripts/desktop-controls-macos.sh",
        ),
        (
            "the iOS Simulator, with Xcode",
            "ios",
            &["runs-on: macos-15"],
            "scripts/ios-app-launch.sh",
        ),
        (
            "an Android emulator",
            "android-app",
            &["runs-on: ubuntu-24.04"],
            "scripts/android-app-launch.sh",
        ),
        (
            "a Windows machine",
            "windows",
            &["runs-on: windows-2025"],
            "cargo build --locked -p companion-tauri --release",
        ),
        (
            "a Linux machine",
            "rust",
            &["runs-on: ubuntu-24.04"],
            "cargo test --locked --workspace",
        ),
        (
            "a macOS machine",
            "macos",
            &["runs-on: macos-15"],
            "cargo test --locked --workspace",
        ),
        (
            "the evidence of the phones' applications is collected",
            "ios",
            &["test-evidence-ios"],
            "KR_TEST_ARTIFACTS_DIR",
        ),
    ];
    for (class, name, runner, step) in classes {
        let text = job(&workflow, name);
        for expected in runner {
            assert!(
                text.contains(expected),
                "{class}: the {name} job has no {expected}"
            );
        }
        assert!(
            text.contains(step),
            "{class}: the {name} job does not run {step}"
        );
    }
    let android = job(&workflow, "android-app");
    assert!(
        android.contains("test-evidence-android"),
        "the Android job keeps its evidence"
    );
}
