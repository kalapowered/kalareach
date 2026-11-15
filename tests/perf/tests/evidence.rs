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
//! A run that a time-out or a cancel ends keeps what its measurements had recorded: each record
//! reaches the caller's directory as soon as its measurement ends, and the script's exit trap
//! appends what is left when the script ends of its own accord or by TERM or INT; KILL runs no
//! trap, and HUP may not run it under a newer bash. These checks end a run inside a measurement, by
//! TERM, which runs the trap, and by KILL, which does not, with a stand-in measurement that stops
//! after it has recorded.
//!
//! Unix only: the script is a Unix shell script.

#![cfg(unix)]

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::Duration;

/// The variable that makes the stand-in measurement record its section.
const CHILD: &str = "KR_STAND_IN_CHILD";

/// The stand-in for `cargo`: every build and every suite succeeds at once, and each measurement
/// runs this test program, which records a section. Where `KR_STAND_IN_HOLD` names a folder, the
/// measurement that `KR_STAND_IN_HOLD_AT` counts to stops after it has recorded, while the folder
/// holds a file named `held` (which it makes) and for two minutes at most. Where `KR_STAND_IN_LATE`
/// is set, the last measurement leaves a process behind that records one more section once the
/// measurement's own record has been taken out of the run root, and ends.
const CARGO: &str = r###"#!/bin/sh
case "$*" in
  build*) exit 0 ;;
  *--ignored*)
    echo "the measurement"
    "$KR_STAND_IN_READER" --exact the_stand_in_measurement --nocapture --test-threads=1 || exit 1
    if [ -n "${KR_STAND_IN_HOLD:-}" ]; then
      count=$(( $(cat "$KR_STAND_IN_HOLD/count" 2>/dev/null || echo 0) + 1 ))
      echo "$count" > "$KR_STAND_IN_HOLD/count"
      if [ "$count" = "$KR_STAND_IN_HOLD_AT" ]; then
        : > "$KR_STAND_IN_HOLD/held"
        waited=0
        while [ -e "$KR_STAND_IN_HOLD/held" ] && [ "$waited" -lt 120 ]; do
          sleep 1
          waited=$((waited + 1))
        done
      fi
    fi
    case "$*" in
      *idle_resources_for_twenty_sessions*)
        if [ -n "${KR_STAND_IN_LATE:-}" ]; then
          evidence="$KR_TEST_ARTIFACTS_DIR"
          sh -c 'while [ -e "$1/performance.md" ]; do sleep 0.1; done; printf "## a stand-in measurement\n\n" >> "$1/performance.md"' late "$evidence" > /dev/null 2>&1 &
        fi
        ;;
    esac
    echo "test result: ok. 1 passed; 0 failed; 0 ignored"
    ;;
  *) echo "test result: ok. 3 passed; 0 failed; 0 ignored" ;;
esac
"###;

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

/// The script with the stand-in, `temporary` (with a slash at its end) as its temporary folder and
/// `evidence` as the evidence directory, or none.
fn script(temporary: &Path, evidence: Option<&Path>) -> Command {
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
    command
}

/// Runs the script to its end.
fn performance(temporary: &Path, evidence: Option<&Path>) -> Output {
    script(temporary, evidence)
        .output()
        .expect("the script runs")
}

/// The script, started as the leader of a process group of its own, as a runner starts a step, with
/// the measurement that is counted to `at` held after it has recorded.
struct Held {
    child: Child,
    folder: PathBuf,
}

impl Held {
    fn start(temporary: &Path, evidence: &Path, at: u32) -> Held {
        let folder = temporary.join("hold");
        std::fs::create_dir_all(&folder).expect("a folder for the stand-in's marks");
        // To a file, so that nothing waits on a pipe that a process left behind still holds.
        let log = std::fs::File::create(folder.join("log")).expect("a log");
        let child = script(temporary, Some(evidence))
            .env("KR_STAND_IN_HOLD", &folder)
            .env("KR_STAND_IN_HOLD_AT", at.to_string())
            .process_group(0)
            .stdout(log.try_clone().expect("a second handle"))
            .stderr(log)
            .spawn()
            .expect("the script starts");
        Held { child, folder }
    }

    /// Waits until the held measurement has recorded and stopped, and says what the script printed
    /// if it ends first or the wait runs out.
    fn wait_until_held(&mut self) {
        let printed = || std::fs::read_to_string(self.folder.join("log")).unwrap_or_default();
        for _ in 0..600 {
            if self.folder.join("held").exists() {
                return;
            }
            if let Some(status) = self.child.try_wait().expect("polls the script") {
                panic!(
                    "the script ended ({status}) before the measurement was held:\n{}",
                    printed()
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "the measurement was not held within a minute:\n{}",
            printed()
        );
    }

    /// Ends the script and everything it started with `signal`, as a runner ends a step that has
    /// timed out or been cancelled, and waits for the script to end.
    fn end_by(mut self, signal: &str) {
        let sent = Command::new("/bin/bash")
            .args(["-c", r#"kill -s "$0" -- "-$1""#, signal])
            .arg(self.child.id().to_string())
            .status()
            .expect("sends the signal");
        assert!(sent.success(), "the signal {signal} was not sent");
        let status = self.child.wait().expect("the script ends");
        assert!(!status.success(), "the script ended well after {signal}");
    }
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

/// A run that a time-out or a cancel cuts in the middle of a measurement keeps what that
/// measurement had recorded: the exit trap appends it to the caller's directory.
#[test]
fn a_run_ended_by_a_signal_inside_a_measurement_keeps_what_the_measurement_recorded() {
    let temporary = tempfile::tempdir().expect("a temporary folder");
    let evidence = temporary.path().join("evidence");
    std::fs::create_dir_all(&evidence).expect("the named directory");
    let mut run = Held::start(temporary.path(), &evidence, 1);
    run.wait_until_held();
    run.end_by("TERM");
    assert_eq!(
        sections(&evidence.join("performance.md")),
        1,
        "the section that the first measurement recorded is in the caller's directory"
    );
}

/// The record of a measurement that has ended stands in the caller's directory before the next
/// measurement starts, so a run that is killed, which runs no trap, still has it.
#[test]
fn a_run_killed_inside_its_second_measurement_has_the_record_of_the_first() {
    let temporary = tempfile::tempdir().expect("a temporary folder");
    let evidence = temporary.path().join("evidence");
    std::fs::create_dir_all(&evidence).expect("the named directory");
    let mut run = Held::start(temporary.path(), &evidence, 2);
    run.wait_until_held();
    run.end_by("KILL");
    assert_eq!(
        sections(&evidence.join("performance.md")),
        1,
        "the section that the first measurement recorded is in the caller's directory, and the \
         second measurement's, which was still in the run root, is not"
    );
}

/// A record that a process of the run makes after its measurement ended, and that is still in the run
/// root when the survivor check ends, is kept before the run root goes.
#[test]
fn a_record_made_after_its_measurement_ended_is_kept_when_the_run_ends() {
    let temporary = tempfile::tempdir().expect("a temporary folder");
    let evidence = temporary.path().join("evidence");
    std::fs::create_dir_all(&evidence).expect("the named directory");
    let output = script(temporary.path(), Some(&evidence))
        .env("KR_STAND_IN_LATE", "1")
        .output()
        .expect("the script runs");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        sections(&evidence.join("performance.md")),
        5,
        "the four measurements' sections and the late one are in the caller's directory"
    );
}
