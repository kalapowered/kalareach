//! Where `scripts/performance.sh` leaves the records of its measurements.
//!
//! The script gives its suites a temporary folder of its own, the run root, and the suites read the
//! evidence directory through their own reader, which accepts a folder inside that temporary folder
//! and inside `/tmp`. A directory that the caller named under the caller's own temporary folder is
//! outside both, so the suites record under the run root and the script appends what they recorded
//! to the caller's directory before the run root goes. Where no directory is named, the script
//! makes one under the caller's temporary folder and says where it is.
//!
//! These checks run the script with `cargo` standing in for the build and every suite, and with a
//! stand-in for each measurement that records one section through the real record function, which
//! reads the directory through the real reader. The temporary folder ends in a slash, as macOS's
//! does.
//!
//! Unix only: the script is a Unix shell script.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The variable that makes the stand-in measurement record its section.
const CHILD: &str = "KR_STAND_IN_CHILD";

/// The stand-in for `cargo`: every build and every suite succeeds at once, and each measurement
/// runs this test program, which records a section.
const CARGO: &str = r#"#!/bin/sh
case "$*" in
  build*) exit 0 ;;
  *--ignored*)
    echo "the measurement"
    "$KR_STAND_IN_READER" --exact the_stand_in_measurement --nocapture --test-threads=1 || exit 1
    echo "test result: ok. 1 passed; 0 failed; 0 ignored"
    ;;
  *) echo "test result: ok. 3 passed; 0 failed; 0 ignored" ;;
esac
"#;

/// The stand-in measurement: where this program was started by the stand-in `cargo`, it records one
/// section in the evidence directory that its environment names, as a measurement does.
#[test]
fn the_stand_in_measurement() {
    if std::env::var_os(CHILD).is_some() {
        kr_perf::record::report(
            "performance.md",
            "a stand-in measurement",
            &["a figure".to_owned()],
        );
    }
}

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository")
}

/// Runs the script with the stand-in, `temporary` (with a slash at its end) as its temporary
/// folder and `evidence` as the evidence directory, or none.
fn performance(temporary: &Path, evidence: Option<&Path>) -> Output {
    let bin = temporary.join("bin");
    std::fs::create_dir_all(&bin).expect("a directory for the stand-in");
    kr_ipc::testing::place_script(&bin.join("cargo"), CARGO);
    let mut command = Command::new("/bin/bash");
    command
        .arg(repository().join("scripts/performance.sh"))
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", bin.display()),
        )
        .env("TMPDIR", format!("{}/", temporary.display()))
        .env(
            "KR_STAND_IN_READER",
            std::env::current_exe().expect("this program"),
        )
        .env(CHILD, "1")
        .env_remove("RUNNER_TEMP")
        .env_remove("KR_PERF_PLANT")
        .env_remove("KR_PERF_SETTLE_LOAD")
        .env_remove("KR_TEST_ARTIFACTS_DIR");
    if let Some(evidence) = evidence {
        command.env("KR_TEST_ARTIFACTS_DIR", evidence);
    }
    command.output().expect("the script runs")
}

fn sections(record: &Path) -> usize {
    std::fs::read_to_string(record)
        .unwrap_or_default()
        .matches("## a stand-in measurement")
        .count()
}

/// With nothing named, each measurement's record is kept where the script says it is, and the run
/// root is gone.
#[test]
fn records_stand_at_the_place_the_script_prints_when_no_directory_is_named() {
    let temporary = tempfile::tempdir().expect("a temporary folder");
    let output = performance(temporary.path(), None);
    let words = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{}\n{words}",
        String::from_utf8_lossy(&output.stdout)
    );
    let place = words
        .lines()
        .find_map(|line| {
            line.split_once("this run keeps its evidence in ")
                .map(|(_, place)| place)
        })
        .unwrap_or_else(|| panic!("the script does not say where the records are: {words}"));
    let record = Path::new(place).join("performance.md");
    assert_eq!(sections(&record), 4, "{record:?}");
    let left: Vec<String> = std::fs::read_dir(temporary.path())
        .expect("lists the temporary folder")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.starts_with("kalareach-run."))
        .collect();
    assert!(left.is_empty(), "the run root is left: {left:?}");
}

/// A directory that the caller named under the caller's temporary folder, with a section in it
/// already, gets the sections of the measurements after it.
#[test]
fn records_are_appended_to_a_directory_named_under_the_callers_temporary_folder() {
    let temporary = tempfile::tempdir().expect("a temporary folder");
    let evidence = temporary.path().join("evidence");
    std::fs::create_dir_all(&evidence).expect("the named directory");
    std::fs::write(evidence.join("performance.md"), "## an earlier section\n\n").expect("a record");
    let output = performance(temporary.path(), Some(&evidence));
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let record = evidence.join("performance.md");
    let text = std::fs::read_to_string(&record).expect("the record");
    assert!(text.starts_with("## an earlier section"), "{text}");
    assert_eq!(sections(&record), 4, "{text}");
}
