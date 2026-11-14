//! The program that Cargo runs each test binary through is a private copy of the report's own
//! program, on every platform: damage to the program's shared file after the copy was made does
//! not reach a listing or a run, and a run whose build directory is the copy's place is refused
//! before its first step.

use std::path::{Path, PathBuf};

use kr_conformance::plan::{Group, Platform, Step};
use kr_conformance::report::{self, Options, Outcome, Stopped};

fn tree(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// The report over the `forms` tree's tests, run through `lister`, with `target` as the directory
/// its steps build in and `base` as the directory the copy's own directory is made in.
fn options(evidence: &Path, base: &Path, lister: PathBuf, target: &Path) -> Options {
    Options {
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
        steps: Some(vec![Step::cargo(
            Group::Rust,
            "the tree's tests",
            &["test", "--locked", "--workspace", "--no-fail-fast"],
        )]),
        lister,
        environment: vec![(
            "CARGO_TARGET_DIR".to_owned(),
            target.to_string_lossy().into_owned(),
        )],
        part: None,
        runner_base: base.to_path_buf(),
    }
}

#[test]
fn the_runner_cargo_gets_is_a_copy_that_stays_whole_when_the_original_is_damaged() {
    let held = tempfile::tempdir().expect("a directory");
    let program = Path::new(env!("CARGO_BIN_EXE_kr-conformance"));
    let shared = held.path().join(program.file_name().expect("a file name"));
    kr_ipc::testing::place_program(program, &shared);
    let evidence = tempfile::tempdir().expect("an evidence directory");
    let base = tempfile::tempdir().expect("a directory for the copy");
    let target = std::env::temp_dir().join("kr-conformance-fixture-target-private-runner");
    let options = options(evidence.path(), base.path(), shared.clone(), &target);
    let mut damaged = false;
    let document = report::run(&options, &mut |line| {
        if line.starts_with("step 1 of 1") {
            std::fs::write(&shared, vec![0_u8; 65536]).expect("the shared file is damaged");
            damaged = true;
        }
    })
    .unwrap_or_else(|stopped| panic!("{stopped:?}"));
    assert!(
        damaged,
        "the program was damaged once the report had copied it"
    );
    let copies: Vec<_> = std::fs::read_dir(base.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        copies.len(),
        1,
        "the copy's directory is made in the base: {copies:?}"
    );
    let step = &document.steps[0];
    assert_eq!(step.exit, Some(0), "{step:?}");
    assert_eq!(step.error, None);
    let tests: Vec<_> = document
        .identifiers
        .values()
        .flat_map(|record| &record.tests)
        .collect();
    assert!(!tests.is_empty(), "the listing found tests");
    assert!(
        tests.iter().all(|test| test.outcome == Outcome::Passed),
        "{tests:?}"
    );
}

#[test]
fn a_build_directory_that_holds_the_copy_s_base_ends_the_run_before_its_first_step() {
    let evidence = tempfile::tempdir().expect("an evidence directory");
    let held = tempfile::tempdir()
        .expect("a directory that is both the copy's place and a build directory");
    let lister = PathBuf::from(env!("CARGO_BIN_EXE_kr-conformance"));
    let options = options(evidence.path(), held.path(), lister, held.path());
    let mut announced = 0;
    let result = report::run(&options, &mut |_| announced += 1);
    match result {
        Err(Stopped::PrivateCopy(problem)) => {
            assert!(problem.contains("where a step builds"), "{problem}");
        }
        Err(other) => panic!("{other:?}"),
        Ok(_) => panic!("the run went on with the copy in a build directory"),
    }
    assert_eq!(announced, 0, "a step was announced");
    assert!(
        std::fs::read_dir(held.path()).unwrap().next().is_none(),
        "nothing was made in the build directory"
    );
}

/// Runs `command` of the runner `runner` for `program`, which cannot be started, as step `step`
/// when one is given, and returns whether the runner ended with a failure.
fn refused(runner: &Path, command: &str, step: Option<&str>, program: &Path) -> bool {
    let mut run = std::process::Command::new(runner);
    run.arg(command)
        .arg(program)
        .env_remove("KR_CONFORMANCE_STEP")
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null());
    if let Some(step) = step {
        run.env("KR_CONFORMANCE_STEP", step);
    }
    !run.status().expect("the runner starts").success()
}

#[test]
fn the_runner_records_a_program_it_could_not_start_for_its_step_by_its_whole_path_and_nowhere_else()
{
    // Each command has a folder of its own, so that a record that one made is not read as the
    // other's.
    for command in ["run-one", "list-one"] {
        let held = tempfile::tempdir().expect("a directory");
        let program = Path::new(env!("CARGO_BIN_EXE_kr-conformance"));
        let runner = held.path().join(program.file_name().expect("a file name"));
        kr_ipc::testing::place_program(program, &runner);
        let first = held.path().join("no-such-dir").join("prog-0123");
        let second = held.path().join("other-dir").join("prog-0123");
        for (step, program) in [
            (Some("3"), &first),
            (Some("3"), &second),
            (Some("4"), &first),
        ] {
            assert!(refused(&runner, command, step, program), "{command}");
        }
        // Without a step, or with a word that is no number, there is no record.
        for step in [None, Some(""), Some("../3"), Some("3x")] {
            assert!(refused(&runner, command, step, &second), "{command}");
        }
        let line = |step: &str, number: &str| {
            std::fs::read_to_string(held.path().join("refusals").join(step).join(number))
                .ok()
                .and_then(|record| record.lines().next().map(str::to_owned))
        };
        assert_eq!(line("3", "0").as_deref(), first.to_str(), "{command}");
        assert_eq!(line("3", "1").as_deref(), second.to_str(), "{command}");
        assert_eq!(line("4", "0").as_deref(), first.to_str(), "{command}");
        assert_eq!(line("3", "2"), None, "{command}");
        assert_eq!(line("4", "1"), None, "{command}");
        let mut steps: Vec<String> = std::fs::read_dir(held.path().join("refusals"))
            .expect("the folder of the records")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        steps.sort();
        assert_eq!(steps, ["3", "4"], "{command}");
    }
}
