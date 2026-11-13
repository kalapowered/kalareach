//! A step whose first run ends in a file the linker wrote that the system would not start is run
//! again, and the result says so; any other failure is left as it is.

use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;

use kr_conformance::fault;
#[cfg(unix)]
use kr_conformance::fault::Cause;
#[cfg(unix)]
use kr_conformance::plan::Platform;
use kr_conformance::plan::{Group, Reading, Step};
#[cfg(unix)]
use kr_conformance::report::{self, Document, Options};
use kr_conformance::run::Place;

/// A step that, on its first run, writes a program under the target directory, empty or as the
/// third argument says, and ends as a build does when the system refuses to start a build script,
/// and succeeds on its second.
const SCRIPT: &str = "marker=$1; file=$2; \
    if [ ! -e \"$marker\" ]; then \
      : > \"$marker\"; mkdir -p \"$(dirname \"$file\")\"; printf '%s' \"$3\" > \"$file\"; chmod +x \"$file\"; \
      echo \"process didn't exit successfully: \\`$file\\` (exit status: 126)\"; \
      echo \"$file: $file: cannot execute binary file\"; \
      exit 101; \
    fi; \
    echo second-$((1 + 1)); exit 0";

fn step(arguments: &[&Path], content: &str) -> Step {
    let mut command: Vec<String> = ["sh", "-c", SCRIPT, "sh"]
        .iter()
        .map(|word| (*word).to_owned())
        .collect();
    command.extend(
        arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned()),
    );
    command.push(content.to_owned());
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
    let done = fault::execute(
        &step(&[&marker, &program], ""),
        7,
        &place,
        &[],
        &mut |line| told.push(line.to_owned()),
    );
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
    let mut failing = step(&[], "");
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

/// The report over the `forms` tree with `step` as its only step, building into `target`.
#[cfg(unix)]
fn report_over(step: Step, target: &Path, evidence: &Path) -> Document {
    let options = Options {
        root: Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("forms"),
        evidence: kr_conformance::evidence::check_directory(evidence)
            .expect("inside the temporary directory"),
        selection: Some(vec![Group::Rust]),
        all_terminals: false,
        platform: Platform::current(),
        case_tables: &[],
        lanes: &[],
        ignored_runs: None,
        applications: None,
        steps: Some(vec![step]),
        lister: PathBuf::from(env!("CARGO_BIN_EXE_kr-conformance")),
        environment: vec![(
            "CARGO_TARGET_DIR".to_owned(),
            target.to_string_lossy().into_owned(),
        )],
        part: None,
    };
    report::run(&options, &mut |_| {}).unwrap_or_else(|stopped| panic!("{stopped:?}"))
}

/// A run in which a step linked a program that could not be started and the second run passed:
/// where the program is cut short, the run passes, with one warning annotation naming the step and
/// the program and the count as its last line; where it is whole and the kernel shows no storage
/// error, the second run passes as well and the run still ends red.
#[cfg(unix)]
#[test]
fn a_run_with_a_step_run_again_passes_where_the_runner_s_disk_is_shown_and_says_so() {
    let directory = tempfile::tempdir().unwrap();
    let evidence = tempfile::Builder::new()
        .prefix("kr-conformance-evidence.")
        .tempdir()
        .expect("an evidence directory");
    let target = directory.path().join("target");
    let program = target
        .join("debug/build/x-0123456789abcdef")
        .join("build-script-build");
    let marker = directory.path().join("ran-once");
    let document = report_over(step(&[&marker, &program], ""), &target, evidence.path());
    assert!(document.passed(), "{:?}", document.summary.failed_steps);
    assert_eq!(document.summary.rerun_steps, [1]);
    let annotations = document.rerun_annotations();
    assert_eq!(annotations.len(), 1, "{annotations:?}");
    let expected = format!(
        "::warning title=Step 1 was run again::step 1, a build that links a program, was run \
         again after a file that could not be started: {}; the runner's disk: ",
        program.display()
    );
    assert!(annotations[0].starts_with(&expected), "{annotations:?}");
    assert!(!annotations[0].contains('\n'));
    assert_eq!(
        document.rerun_count_line().as_deref(),
        Some("1 steps were run again after a file that could not be started")
    );
}

/// The same step linking a whole program the kernel shows no error for: on a system where the
/// signature is not checked, nothing shows the runner's disk, so the run ends red with no warning.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn a_run_with_a_step_run_again_for_a_whole_program_ends_red_with_no_warning() {
    let directory = tempfile::tempdir().unwrap();
    let evidence = tempfile::Builder::new()
        .prefix("kr-conformance-evidence.")
        .tempdir()
        .expect("an evidence directory");
    let target = directory.path().join("target");
    let program = target
        .join("debug/build/x-0123456789abcdef")
        .join("build-script-build");
    let marker = directory.path().join("ran-once");
    let document = report_over(
        step(&[&marker, &program], "#!/bin/sh\nexit 0\n"),
        &target,
        evidence.path(),
    );
    let rerun = document.steps[0].rerun.as_ref().expect("run again");
    assert_eq!(rerun.cause, Cause::Unexplained);
    assert_eq!(document.steps[0].exit, Some(0), "the second run passed");
    assert!(!document.passed());
    assert_eq!(document.summary.failed_steps, [1]);
    assert!(document.rerun_annotations().is_empty());
    assert!(document.rerun_count_line().is_some());
}

/// A run in which no step was run again prints neither the warning nor the count.
#[cfg(unix)]
#[test]
fn a_run_with_no_step_run_again_prints_no_warning_and_no_count() {
    let directory = tempfile::tempdir().unwrap();
    let evidence = tempfile::Builder::new()
        .prefix("kr-conformance-evidence.")
        .tempdir()
        .expect("an evidence directory");
    let mut passing = step(&[], "");
    passing.command = ["sh", "-c", "exit 0", "once"]
        .iter()
        .map(|word| (*word).to_owned())
        .collect();
    let document = report_over(passing, &directory.path().join("target"), evidence.path());
    assert!(document.passed());
    assert!(document.summary.rerun_steps.is_empty());
    assert!(document.rerun_annotations().is_empty());
    assert_eq!(document.rerun_count_line(), None);
}
