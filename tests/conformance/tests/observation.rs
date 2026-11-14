//! A step that fails because a program could not be run stays failed, runs once, and keeps what the
//! program's file looked like at that moment; the report removes nothing and decides nothing from
//! it.

#![cfg(unix)]

use std::path::{Path, PathBuf};

use kr_conformance::observe::Found;
use kr_conformance::plan::{Group, Platform, Reading, Step};
use kr_conformance::report::{self, Document, Options, Outcome};

fn tree(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// A step that runs `script` with `arguments`, as `$1` and on.
fn shell(what: &str, script: &str, arguments: &[&Path]) -> Step {
    let mut command: Vec<String> = ["sh", "-c", script, "sh"]
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
        what: what.to_owned(),
        command,
        needs: Vec::new(),
        reading: Reading::Build,
        filter: None,
        skips: Vec::new(),
    }
}

fn run(evidence: &Path, lister: PathBuf, steps: Vec<Step>) -> Document {
    let target = std::env::temp_dir().join("kr-conformance-fixture-target-observation");
    let options = Options {
        root: tree("forms"),
        evidence: kr_conformance::evidence::check_directory(evidence)
            .expect("inside the temporary directory"),
        selection: Some(vec![Group::Rust]),
        all_terminals: false,
        platform: Platform::current(),
        case_tables: &[],
        lanes: &[],
        ignored_runs: None,
        applications: None,
        steps: Some(steps),
        lister,
        environment: vec![(
            "CARGO_TARGET_DIR".to_owned(),
            target.to_string_lossy().into_owned(),
        )],
        part: None,
    };
    report::run(&options, &mut |_| {}).unwrap_or_else(|stopped| panic!("{stopped:?}"))
}

fn lister() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kr-conformance"))
}

/// What a build prints when the system refuses a program it linked and the shell then tries it as
/// a script.
const REFUSES: &str = "head -c 8192 /dev/zero > \"$1\"; \
    echo \"process didn't exit successfully: \\`$1\\` (exit status: 126)\"; \
    echo \"$1: $1: cannot execute binary file\"; exit 101";

#[test]
fn a_step_that_could_not_run_a_program_fails_once_and_keeps_the_file_as_it_was_seen() {
    let held = tempfile::tempdir().unwrap();
    let evidence = tempfile::tempdir().unwrap();
    let program = held.path().join("build-script-build");
    let count = held.path().join("count");
    let script = format!("echo x >> \"$2\"; {REFUSES}");
    let document = run(
        evidence.path(),
        lister(),
        vec![shell(
            "a build that links a program",
            &script,
            &[&program, &count],
        )],
    );
    assert_eq!(document.steps[0].exit, Some(101));
    assert!(!document.passed(), "a failed step is a failed night");
    assert_eq!(
        std::fs::read_to_string(&count).unwrap().lines().count(),
        1,
        "the step ran once"
    );
    let observed = document.steps[0].observation.as_ref().expect("observed");
    assert_eq!(observed.programs.len(), 1);
    assert_eq!(observed.programs[0].path, program.to_string_lossy());
    let Found::Read { size, damage, .. } = &observed.programs[0].file else {
        panic!("{:?}", observed.programs[0].file);
    };
    assert_eq!(*size, 8192);
    assert!(damage.as_deref().unwrap().contains("first page"));
    assert_eq!(document.summary.failed_steps, [1]);
    assert_eq!(document.summary.failed_with_damage_seen, [1]);
    assert!(document.summary.failed_otherwise.is_empty());
    assert_eq!(
        document.summary.failure_line().unwrap(),
        "1 failed steps: 1 carry an observation of a program that could not be run with damage \
         seen, 0 failed otherwise"
    );
    assert_eq!(
        std::fs::metadata(&program).unwrap().len(),
        8192,
        "the file is left as it is"
    );
}

#[test]
fn a_test_that_ran_and_failed_is_a_test_failure_whatever_it_printed() {
    let held = tempfile::tempdir().unwrap();
    let evidence = tempfile::tempdir().unwrap();
    let program = held.path().join("program");
    let script = "head -c 8192 /dev/zero > \"$1\"; \
        printf 'running 1 test\\ntest a ... FAILED\\n\\nfailures:\\n\\n---- a stdout ----\\n'; \
        echo \"could not execute process \\`$1\\` (never executed)\"; \
        echo \"$1: $1: cannot execute binary file\"; \
        echo \"process didn't exit successfully: \\`$1\\` (exit status: 126)\"; \
        printf '\\nfailures:\\n    a\\n\\ntest result: FAILED. 0 passed; 1 failed\\n'; exit 101";
    let document = run(
        evidence.path(),
        lister(),
        vec![shell("a test that prints a refusal", script, &[&program])],
    );
    assert!(document.steps[0].observation.is_none());
    assert_eq!(document.summary.failed_otherwise, [1]);
    assert!(document.summary.failed_with_damage_seen.is_empty());
}

#[test]
fn a_night_of_failed_steps_says_how_many_carry_the_observation_and_how_many_do_not() {
    let held = tempfile::tempdir().unwrap();
    let evidence = tempfile::tempdir().unwrap();
    let program = held.path().join("program");
    let document = run(
        evidence.path(),
        lister(),
        vec![
            shell("a build that links a program", REFUSES, &[&program]),
            shell(
                "a step that fails in another way",
                "echo broken; exit 3",
                &[],
            ),
            shell("a step that passes", "exit 0", &[]),
        ],
    );
    assert_eq!(document.summary.failed_steps, [1, 2]);
    assert_eq!(document.summary.failed_with_damage_seen, [1]);
    assert_eq!(document.summary.failed_otherwise, [2]);
    assert_eq!(
        document.summary.failure_line().unwrap(),
        "2 failed steps: 1 carry an observation of a program that could not be run with damage \
         seen, 1 failed otherwise"
    );
    assert!(!document.passed());
}

#[test]
fn a_program_that_is_whole_or_a_link_does_not_count_as_damage_seen() {
    let held = tempfile::tempdir().unwrap();
    let evidence = tempfile::tempdir().unwrap();
    let whole = held.path().join("whole");
    let behind = held.path().join("behind");
    let link = held.path().join("link");
    let script = "head -c 8192 /dev/zero > \"$2\"; ln -s \"$2\" \"$3\"; \
        printf '#!/bin/sh\\nexit 0\\n' > \"$1\"; \
        echo \"kr-conformance run-one: $1 could not start: no\"; \
        echo \"kr-conformance run-one: $3 could not start: no\"; exit 101";
    let document = run(
        evidence.path(),
        lister(),
        vec![shell(
            "two programs that could not start",
            script,
            &[&whole, &behind, &link],
        )],
    );
    let observed = document.steps[0].observation.as_ref().expect("observed");
    assert!(matches!(
        &observed.programs[0].file,
        Found::Read { damage: None, .. }
    ));
    let Found::Other { kind } = &observed.programs[1].file else {
        panic!("{:?}", observed.programs[1].file);
    };
    assert_eq!(kind, "a link");
    assert!(document.summary.failed_with_damage_seen.is_empty());
    assert_eq!(document.summary.failed_otherwise, [1]);
}

/// A runner that passes every call to the report's own program, except that `arm` (`list-one` or
/// `run-one`) runs `refusal` as a shell script with the test binary's path as `$2`.
fn runner_that(held: &Path, arm: &str, refusal: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let runner = held.join("kr-conformance");
    std::fs::write(
        &runner,
        format!(
            "#!/bin/sh\ncase \"$1\" in\n  {arm}) {refusal};;\n  *) exec \"{}\" \"$@\";;\nesac\n",
            lister().display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o755)).unwrap();
    runner
}

/// The report over the `forms` tree's tests, run through `runner`.
fn tests_through(evidence: &Path, runner: PathBuf) -> Document {
    run(
        evidence,
        runner,
        vec![Step::cargo(
            Group::Rust,
            "the tree's tests",
            &["test", "--locked", "--workspace", "--no-fail-fast"],
        )],
    )
}

#[test]
fn a_test_program_that_could_not_start_is_not_run_with_the_reason_and_not_passed_or_not_built() {
    let held = tempfile::tempdir().unwrap();
    let evidence = tempfile::tempdir().unwrap();
    // A runner that refuses to start any test binary that is run.
    let runner = runner_that(
        held.path(),
        "run-one",
        "echo \"kr-conformance run-one: $2 could not start: Exec format error (os error 8)\" >&2; exit 1",
    );
    let document = tests_through(evidence.path(), runner);
    assert!(!document.passed(), "a step that failed fails the run");
    assert_eq!(document.summary.failed_steps, [1]);
    let counts = &document.summary.tests;
    assert_eq!((counts.passed, counts.failed, counts.not_built), (0, 0, 0));
    assert!(counts.not_run > 0, "{counts:?}");
    let test = &document.identifiers["KR-REQ-03.02"].tests[0];
    assert_eq!(test.outcome, Outcome::NotRun, "{test:?}");
    let reason = test.reason.as_deref().unwrap_or_default();
    assert!(
        reason.contains("could not be started") && reason.contains("Exec format error"),
        "{reason}"
    );
}

#[test]
fn the_shell_s_words_for_a_test_program_do_not_make_its_tests_not_run() {
    let held = tempfile::tempdir().unwrap();
    let evidence = tempfile::tempdir().unwrap();
    let runner = runner_that(
        held.path(),
        "run-one",
        "echo \"$2: $2: cannot execute binary file\" >&2; exit 126",
    );
    let document = tests_through(evidence.path(), runner);
    let test = &document.identifiers["KR-REQ-03.02"].tests[0];
    assert_eq!(test.outcome, Outcome::Failed, "{test:?}");
    assert_eq!(document.summary.tests.not_run, 0);
}

#[test]
fn a_test_that_printed_the_runner_s_refusal_itself_and_then_aborted_stays_failed() {
    let held = tempfile::tempdir().unwrap();
    let evidence = tempfile::tempdir().unwrap();
    // The binary started: it printed that it was running a test, and the test said what the runner
    // says when it cannot start a program, and then the process ended without a summary.
    let runner = runner_that(
        held.path(),
        "run-one",
        "echo \"running 1 test\"; echo \"test documented ... \"; \
         echo \"kr-conformance run-one: $2 could not start: Exec format error (os error 8)\" >&2; exit 134",
    );
    let document = tests_through(evidence.path(), runner);
    let test = &document.identifiers["KR-REQ-03.02"].tests[0];
    assert_eq!(test.outcome, Outcome::Failed, "{test:?}");
    assert!(!document.passed());
}

#[test]
fn a_test_program_with_a_failed_test_is_not_run_whatever_line_the_runner_wrote_before_it() {
    let held = tempfile::tempdir().unwrap();
    let evidence = tempfile::tempdir().unwrap();
    // The runner's refusal comes first, and the program then shows a failed test in its record and
    // its output, with a summary that does not add up to the record.
    let runner = runner_that(
        held.path(),
        "run-one",
        "echo \"kr-conformance run-one: $2 could not start: Exec format error (os error 8)\" >&2; \
         echo \"running 1 test\"; echo \"test documented ... FAILED\"; echo; echo \"failures:\"; \
         echo \"    documented\"; echo; \
         echo \"test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out\"; \
         printf 'failed documented\\n' > \"$KR_CONFORMANCE_RECORDS/$(basename \"$2\")\"; exit 101",
    );
    let document = tests_through(evidence.path(), runner);
    let test = &document.identifiers["KR-REQ-03.02"].tests[0];
    assert_eq!(test.outcome, Outcome::Failed, "{test:?}");
}

#[test]
fn a_step_that_a_later_step_follows_keeps_the_file_as_it_was_when_it_ended() {
    let held = tempfile::tempdir().unwrap();
    let evidence = tempfile::tempdir().unwrap();
    let program = held.path().join("build-script-build");
    let document = run(
        evidence.path(),
        lister(),
        vec![
            shell("a build that links a program", REFUSES, &[&program]),
            shell(
                "a step that writes the program whole",
                "printf '#!/bin/sh\\nexit 0\\n' > \"$1\"",
                &[&program],
            ),
        ],
    );
    assert_eq!(document.summary.failed_steps, [1]);
    let observed = document.steps[0].observation.as_ref().expect("observed");
    let Found::Read { size, damage, .. } = &observed.programs[0].file else {
        panic!("{:?}", observed.programs[0].file);
    };
    assert_eq!(*size, 8192, "the file as the first step left it");
    assert!(damage.as_deref().unwrap().contains("first page"));
    assert_eq!(std::fs::metadata(&program).unwrap().len(), 17);
    assert!(document.steps[1].observation.is_none());
}

#[test]
fn a_program_the_runner_refused_at_the_listing_is_observed_though_the_step_has_no_exit_code() {
    let held = tempfile::tempdir().unwrap();
    let evidence = tempfile::tempdir().unwrap();
    let runner = runner_that(
        held.path(),
        "list-one",
        "echo \"kr-conformance list-one: $2 could not start: Exec format error (os error 8)\" >&2; exit 1",
    );
    let document = tests_through(evidence.path(), runner);
    let step = &document.steps[0];
    assert_eq!(step.exit, None, "{step:?}");
    assert!(step.error.is_some());
    assert_eq!(document.summary.failed_steps, [1]);
    let observed = step.observation.as_ref().expect("observed");
    assert!(observed.programs[0].said_by_runner, "{observed:?}");
    assert!(observed.programs[0].lines[0].contains("list-one"));
}
