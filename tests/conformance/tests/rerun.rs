//! A step whose first run ends in a file the linker wrote that the system would not start is run
//! again, and the result says so; any other failure is left as it is.

use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::time::Duration;

use kr_conformance::fault;
#[cfg(unix)]
use kr_conformance::fault::Cause;
#[cfg(unix)]
use kr_conformance::plan::Platform;
use kr_conformance::plan::{Group, Reading, Step};
#[cfg(unix)]
use kr_conformance::report::{self, Document, Options};
use kr_conformance::run::Place;

/// A step that, on its first run, writes a program under the target directory, empty or a copy of
/// the file its third argument names, and ends as a build does when the system refuses to start a
/// build script, and succeeds on its second.
const SCRIPT: &str = "marker=$1; file=$2; source=$3; \
    if [ ! -e \"$marker\" ]; then \
      : > \"$marker\"; mkdir -p \"$(dirname \"$file\")\"; \
      if [ -n \"$source\" ]; then cp \"$source\" \"$file\"; else : > \"$file\"; fi; chmod +x \"$file\"; \
      echo \"process didn't exit successfully: \\`$file\\` (exit status: 126)\"; \
      echo \"$file: $file: cannot execute binary file\"; \
      exit 101; \
    fi; \
    echo second-$((1 + 1)); exit 0";

/// The step, given the marker that says it ran once, the program it writes and, where the program
/// is not to be empty, the file it is a copy of.
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

/// A repository, an evidence directory and a target directory with a profile directory in it.
#[cfg(unix)]
struct Tree {
    _directory: tempfile::TempDir,
    root: PathBuf,
    evidence: PathBuf,
    profile: PathBuf,
    marker: PathBuf,
    environment: [(String, String); 1],
}

#[cfg(unix)]
impl Tree {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("repository");
        let evidence = directory.path().join("evidence");
        let profile = root.join("target/debug");
        std::fs::create_dir_all(profile.join(".fingerprint")).unwrap();
        std::fs::create_dir_all(&evidence).unwrap();
        let marker = directory.path().join("ran-once");
        let environment = [(
            "CARGO_TARGET_DIR".to_owned(),
            root.join("target").to_string_lossy().into_owned(),
        )];
        Self {
            _directory: directory,
            root,
            evidence,
            profile,
            marker,
            environment,
        }
    }

    fn place(&self) -> Place<'_> {
        Place {
            root: &self.root,
            evidence: &self.evidence,
            environment: &self.environment,
            lister: Path::new("/nonexistent/kr-conformance"),
        }
    }
}

#[cfg(unix)]
#[test]
fn a_step_that_linked_an_empty_program_is_run_again_and_the_result_names_the_runner_s_disk() {
    let tree = Tree::new();
    let unit = "x-0123456789abcdef";
    std::fs::create_dir_all(tree.profile.join(".fingerprint").join(unit)).unwrap();
    let program = tree
        .profile
        .join("build")
        .join(unit)
        .join("build-script-build");
    let mut told = Vec::new();
    let done = fault::execute(
        &step(&[&tree.marker, &program]),
        7,
        &tree.place(),
        &[],
        &mut Duration::from_secs(3600),
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
    assert!(!tree.profile.join(".fingerprint").join(unit).exists());
    let first = std::fs::read_to_string(tree.evidence.join(&rerun.first_log)).unwrap();
    assert!(first.contains("cannot execute binary file"));
    assert!(!first.contains("second-2"));
    let second = std::fs::read_to_string(tree.evidence.join(&done.log)).unwrap();
    assert!(second.contains("second-2"));
    assert_ne!(rerun.first_log, done.log);
    let facts = std::fs::read_to_string(tree.evidence.join(&rerun.facts)).unwrap();
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
    let done = fault::execute(
        &failing,
        1,
        &place,
        &[],
        &mut std::time::Duration::from_secs(3600),
        &mut |_| {},
    );
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

/// A file under the target directory that is not a program Cargo built, such as a program a test
/// of the repository leaves there or one that is in a profile directory with no record of it in
/// Cargo's, is not a reason to run a step again, whatever the log says of it.
#[cfg(unix)]
#[test]
fn a_file_that_no_build_wrote_is_not_a_reason_to_run_a_step_again() {
    for program in ["target/fixtures/helper", "target/debug/helper"] {
        let tree = Tree::new();
        let program = tree.root.join(program);
        let done = fault::execute(
            &step(&[&tree.marker, &program]),
            1,
            &tree.place(),
            &[],
            &mut Duration::from_secs(3600),
            &mut |_| {},
        );
        assert_eq!(done.exit, Some(101), "the step ran once");
        assert!(done.rerun.is_none(), "{}", program.display());
        assert!(program.exists(), "the file is left where it is");
    }
}

/// Two runs of a step that took longer than the time the report leaves for second runs would end
/// the report before it wrote its result, so the step is not run again, and says why.
#[cfg(unix)]
#[test]
fn a_step_whose_first_run_took_longer_than_the_time_left_is_not_run_again() {
    let tree = Tree::new();
    std::fs::create_dir_all(tree.profile.join(".fingerprint/x-0123456789abcdef")).unwrap();
    let program = tree
        .profile
        .join("build/x-0123456789abcdef/build-script-build");
    let mut slow = step(&[&tree.marker, &program]);
    slow.command[2] = format!("sleep 1; {SCRIPT}");
    let mut nothing_left = Duration::ZERO;
    let done = fault::execute(&slow, 1, &tree.place(), &[], &mut nothing_left, &mut |_| {});
    assert_eq!(done.exit, Some(101), "the step ran once");
    assert!(done.rerun.is_none());
    let error = done.error.expect("the step has the reason");
    assert!(error.contains("is not run again"), "{error}");
}

/// What a second run takes is taken from the time left for second runs, so that a step after it
/// finds less, and none, there.
#[cfg(unix)]
#[test]
fn the_time_a_second_run_takes_is_taken_from_the_time_left_for_second_runs() {
    let mut left = Duration::from_secs(1);
    let run = |left: &mut Duration| {
        let tree = Tree::new();
        std::fs::create_dir_all(tree.profile.join(".fingerprint/x-0123456789abcdef")).unwrap();
        let program = tree
            .profile
            .join("build/x-0123456789abcdef/build-script-build");
        let mut slow = step(&[&tree.marker, &program]);
        slow.command[2] = format!("sleep 1; {SCRIPT}");
        fault::execute(&slow, 1, &tree.place(), &[], left, &mut |_| {})
    };
    let first = run(&mut left);
    assert!(first.rerun.is_some(), "the first step was run again");
    assert_eq!(left, Duration::ZERO, "its second run took the second left");
    let second = run(&mut left);
    assert!(
        second.rerun.is_none(),
        "nothing was left for the second step"
    );
    assert_eq!(second.exit, Some(101));
    let error = second.error.expect("the step has the reason");
    assert!(error.contains("is not run again"), "{error}");
}

/// A step run again whose first run's evidence could not be kept ends red, whatever its second run
/// came to.
#[cfg(unix)]
#[test]
fn a_step_run_again_whose_first_runs_evidence_was_not_kept_ends_red() {
    let tree = Tree::new();
    std::fs::create_dir_all(tree.profile.join(".fingerprint/x-0123456789abcdef")).unwrap();
    // The directory for the facts cannot be made where a file stands.
    std::fs::create_dir_all(tree.evidence.join("conformance")).unwrap();
    std::fs::write(tree.evidence.join("conformance/faults"), "").unwrap();
    let program = tree
        .profile
        .join("build/x-0123456789abcdef/build-script-build");
    let done = fault::execute(
        &step(&[&tree.marker, &program]),
        1,
        &tree.place(),
        &[],
        &mut Duration::from_secs(3600),
        &mut |_| {},
    );
    assert_eq!(done.exit, Some(0), "the second run passed");
    assert!(done.rerun.is_some());
    let error = done.error.expect("the step has an error");
    assert!(error.contains("evidence was not kept"), "{error}");
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

/// A report over a step that writes `source` (or an empty file) where a build script goes, in a
/// target directory with a profile directory.
#[cfg(unix)]
fn rerun_report(source: Option<&Path>) -> (Document, tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let evidence = tempfile::Builder::new()
        .prefix("kr-conformance-evidence.")
        .tempdir()
        .expect("an evidence directory");
    let target = directory.path().join("target");
    std::fs::create_dir_all(target.join("debug/.fingerprint/x-0123456789abcdef")).unwrap();
    let program = target
        .join("debug/build/x-0123456789abcdef")
        .join("build-script-build");
    let marker = directory.path().join("ran-once");
    let mut arguments: Vec<&Path> = vec![&marker, &program];
    arguments.extend(source);
    let document = report_over(step(&arguments), &target, evidence.path());
    (document, evidence, program)
}

/// Whether the cause is the kernel's own evidence. On a machine whose kernel log holds a storage
/// error from the last minutes, the cause of a whole file is the runner's disk, with that evidence
/// in the reason, and a case about the file has nothing to judge there.
#[cfg(unix)]
fn blamed_on_the_kernel_log(rerun: &fault::Rerun) -> bool {
    rerun.cause == Cause::RunnerDisk && rerun.reason.contains("the kernel logged")
}

/// A run in which a step linked a program that was empty and the second run passed: the run
/// passes, with one warning annotation naming the step and the program, and the count as its last
/// line.
#[cfg(unix)]
#[test]
fn a_run_with_a_step_run_again_passes_where_the_runner_s_disk_is_shown_and_says_so() {
    let (document, _evidence, program) = rerun_report(None);
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

/// The same step linking a program that is whole, and no kernel storage error behind it: nothing
/// shows the runner's disk, so the second run passes and the run still ends red, with no warning.
#[cfg(unix)]
#[test]
fn a_run_with_a_step_run_again_for_a_whole_program_ends_red_with_no_warning() {
    let source = tempfile::tempdir().unwrap();
    let script = source.path().join("script");
    std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
    let (document, _evidence, _) = rerun_report(Some(&script));
    let rerun = document.steps[0].rerun.as_ref().expect("run again");
    if blamed_on_the_kernel_log(rerun) {
        return;
    }
    assert_eq!(rerun.cause, Cause::Unexplained, "{}", rerun.reason);
    assert_eq!(document.steps[0].exit, Some(0), "the second run passed");
    assert!(!document.passed());
    assert_eq!(document.summary.failed_steps, [1]);
    assert!(document.rerun_annotations().is_empty());
    assert!(document.rerun_count_line().is_some());
}

/// A program the linker signed, copied whole, is accepted by the system's check of signatures, so
/// where nothing else shows the runner's disk the run ends red. This is the case that a refusal
/// that the system's check makes of every program would turn into a pass.
#[cfg(target_os = "macos")]
#[test]
fn a_whole_program_the_linker_signed_is_not_taken_for_the_runner_s_disk() {
    let program = std::env::current_exe().unwrap();
    let (document, _evidence, _) = rerun_report(Some(&program));
    let rerun = document.steps[0].rerun.as_ref().expect("run again");
    if blamed_on_the_kernel_log(rerun) {
        return;
    }
    assert_eq!(rerun.cause, Cause::Unexplained, "{}", rerun.reason);
    assert!(
        rerun.reason.contains("signature is valid"),
        "{}",
        rerun.reason
    );
    assert!(!document.passed());
    assert!(document.rerun_annotations().is_empty());
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
    let mut passing = step(&[]);
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
