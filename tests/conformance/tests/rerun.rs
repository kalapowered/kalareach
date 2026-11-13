//! A step whose first run ends in a file the linker wrote that the system would not start is run
//! again, and the result says so; any other failure is left as it is.

use std::path::Path;

use kr_conformance::fault::{self, Cause};
use kr_conformance::plan::{Group, Reading, Step};
use kr_conformance::run::Place;

/// A step that, on its first run, writes an empty program under the target directory and ends as a
/// build does when the system refuses to start a build script, and succeeds on its second.
const SCRIPT: &str = "marker=$1; file=$2; \
    if [ ! -e \"$marker\" ]; then \
      : > \"$marker\"; mkdir -p \"$(dirname \"$file\")\"; : > \"$file\"; chmod +x \"$file\"; \
      echo \"process didn't exit successfully: \\`$file\\` (exit status: 126)\"; \
      echo \"$file: $file: cannot execute binary file\"; \
      exit 101; \
    fi; \
    echo second-$((1 + 1)); exit 0";

fn step(arguments: &[&Path]) -> Step {
    let mut command: Vec<String> = ["sh", "-c", SCRIPT, "sh"]
        .iter()
        .map(|word| (*word).to_owned())
        .collect();
    command.extend(
        arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned()),
    );
    Step {
        group: Group::Rust,
        what: "a build that links a program".to_owned(),
        command,
        needs: Vec::new(),
        reading: Reading::Build,
        filter: None,
        skips: Vec::new(),
    }
}

#[cfg(unix)]
#[test]
fn a_step_that_linked_an_empty_program_is_run_again_and_the_result_names_the_runner_s_disk() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("repository");
    let evidence = directory.path().join("evidence");
    let profile = root.join("target/debug");
    let unit = "x-0123456789abcdef";
    std::fs::create_dir_all(profile.join(".fingerprint").join(unit)).unwrap();
    std::fs::create_dir_all(&evidence).unwrap();
    let program = profile.join("build").join(unit).join("build-script-build");
    let marker = directory.path().join("ran-once");
    let environment = [(
        "CARGO_TARGET_DIR".to_owned(),
        root.join("target").to_string_lossy().into_owned(),
    )];
    let place = Place {
        root: &root,
        evidence: &evidence,
        environment: &environment,
        lister: Path::new("/nonexistent/kr-conformance"),
    };
    let mut told = Vec::new();
    let done = fault::execute(&step(&[&marker, &program]), 7, &place, &[], &mut |line| {
        told.push(line.to_owned())
    });
    assert_eq!(done.exit, Some(0), "the second run passed");
    assert_eq!(done.error, None);
    let rerun = done.rerun.expect("the step was run again");
    assert_eq!(rerun.cause, Cause::RunnerDisk);
    assert_eq!(rerun.first_exit, Some(101));
    assert_eq!(
        rerun.files,
        ["target/debug/build/x-0123456789abcdef/build-script-build"]
    );
    assert!(
        rerun.reason.contains("the file is empty"),
        "{}",
        rerun.reason
    );
    assert!(rerun.removed >= 2, "the directory and the unit's records");
    assert!(!program.exists(), "the damaged program is removed");
    assert!(!profile.join(".fingerprint").join(unit).exists());
    let first = std::fs::read_to_string(evidence.join(&rerun.first_log)).unwrap();
    assert!(first.contains("cannot execute binary file"));
    assert!(!first.contains("second-2"));
    let second = std::fs::read_to_string(evidence.join(&done.log)).unwrap();
    assert!(second.contains("second-2"));
    assert_ne!(rerun.first_log, done.log);
    let facts = std::fs::read_to_string(evidence.join(&rerun.facts)).unwrap();
    assert!(
        facts.contains("Mach-O header: the file is empty"),
        "{facts}"
    );
    assert!(told.iter().any(|line| line.contains("is run again")));
}

#[test]
fn a_step_that_fails_in_another_way_is_not_run_again() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("repository");
    let evidence = directory.path().join("evidence");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&evidence).unwrap();
    let mut failing = step(&[]);
    failing.command = ["sh", "-c", "echo $0 >> ran; exit 3", "once"]
        .iter()
        .map(|word| (*word).to_owned())
        .collect();
    let place = Place {
        root: &root,
        evidence: &evidence,
        environment: &[],
        lister: Path::new("/nonexistent/kr-conformance"),
    };
    let done = fault::execute(&failing, 1, &place, &[], &mut |_| {});
    assert_eq!(done.exit, Some(3));
    assert!(done.rerun.is_none());
    assert_eq!(
        std::fs::read_to_string(root.join("ran"))
            .unwrap()
            .lines()
            .count(),
        1,
        "the step ran once"
    );
}
