//! The report gives Cargo a private copy of its own program as the runner for every listing and
//! every run, so a step that writes a damaged file at the program's path in the shared build
//! directory does not break the report's own machinery.

#![cfg(unix)]

use std::path::{Path, PathBuf};

use kr_conformance::plan::{Group, Platform, Reading, Step};
use kr_conformance::report::{self, Options, Outcome, Stopped};

fn tree(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// A step that writes zeros over `path`, as a program the linker wrote in a burst of failed disk
/// writes reads.
fn zeroing(path: &Path) -> Step {
    Step {
        group: Group::Rust,
        what: "a build that damages the report's program".to_owned(),
        command: vec![
            "sh".to_owned(),
            "-c".to_owned(),
            "head -c 65536 /dev/zero > \"$1\"".to_owned(),
            "sh".to_owned(),
            path.to_string_lossy().into_owned(),
        ],
        needs: Vec::new(),
        reading: Reading::Build,
        filter: None,
        skips: Vec::new(),
    }
}

fn options(evidence: &Path, base: &Path, lister: PathBuf, steps: Vec<Step>) -> Options {
    let target = std::env::temp_dir().join("kr-conformance-fixture-target-private-copy");
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
        steps: Some(steps),
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
fn a_step_that_writes_zeros_at_the_programs_shared_path_does_not_break_a_later_listing() {
    let held = tempfile::tempdir().expect("a directory");
    let shared = held.path().join("kr-conformance");
    std::fs::copy(env!("CARGO_BIN_EXE_kr-conformance"), &shared).expect("a program to damage");
    let evidence = tempfile::tempdir().expect("an evidence directory");
    let base = tempfile::tempdir().expect("a directory for the copy");
    let steps = vec![
        zeroing(&shared),
        Step::cargo(
            Group::Rust,
            "the tree's tests",
            &["test", "--locked", "--workspace", "--no-fail-fast"],
        ),
    ];
    let document = report::run(
        &options(evidence.path(), base.path(), shared.clone(), steps),
        &mut |_| {},
    )
    .unwrap_or_else(|stopped| panic!("{stopped:?}"));
    assert_eq!(
        std::fs::metadata(&shared).expect("the shared file").len(),
        65536,
        "the first step damaged the shared path"
    );
    let listed = &document.steps[1];
    assert_eq!(listed.exit, Some(0), "{listed:?}");
    assert_eq!(listed.error, None);
    assert!(
        document
            .identifiers
            .values()
            .flat_map(|record| &record.tests)
            .all(|test| test.outcome == Outcome::Passed),
        "{:?}",
        document.identifiers
    );
}

/// A step that makes `path`, to show that it ran.
fn marking(path: &Path) -> Step {
    let mut step = zeroing(path);
    step.what = "a step that leaves a mark".to_owned();
    step.command[2] = ": > \"$1\"".to_owned();
    step
}

#[test]
fn a_program_that_cannot_be_copied_ends_the_run_with_a_failure_before_its_first_step() {
    let held = tempfile::tempdir().expect("a directory");
    let evidence = tempfile::tempdir().expect("an evidence directory");
    let base = tempfile::tempdir().expect("a directory for the copy");
    let mark = held.path().join("ran");
    let missing = held.path().join("no-such-program");
    let steps = vec![marking(&mark)];
    match report::run(
        &options(evidence.path(), base.path(), missing, steps),
        &mut |_| {},
    ) {
        Err(Stopped::PrivateCopy(problem)) => {
            assert!(problem.contains("no-such-program"), "{problem}");
        }
        Err(other) => panic!("{other:?}"),
        Ok(_) => panic!("the run went on with no copy of its program"),
    }
    assert!(!mark.exists(), "a step ran");
}
