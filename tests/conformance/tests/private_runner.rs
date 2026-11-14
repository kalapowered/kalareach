//! The program that Cargo runs each test binary through is a private copy of the report's own
//! program, on every platform: damage to the program's shared file after the copy was made does
//! not reach a listing or a run.

use std::path::{Path, PathBuf};

use kr_conformance::plan::{Group, Platform, Step};
use kr_conformance::report::{self, Options, Outcome};

fn tree(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn the_runner_cargo_gets_is_a_copy_that_stays_whole_when_the_original_is_damaged() {
    let held = tempfile::tempdir().expect("a directory");
    let program = Path::new(env!("CARGO_BIN_EXE_kr-conformance"));
    let shared = held.path().join(program.file_name().expect("a file name"));
    std::fs::copy(program, &shared).expect("a program to damage");
    let evidence = tempfile::tempdir().expect("an evidence directory");
    let target = std::env::temp_dir().join("kr-conformance-fixture-target-private-runner");
    let options = Options {
        root: tree("forms"),
        evidence: kr_conformance::evidence::check_directory(evidence.path())
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
        lister: shared.clone(),
        environment: vec![(
            "CARGO_TARGET_DIR".to_owned(),
            target.to_string_lossy().into_owned(),
        )],
        part: None,
    };
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
