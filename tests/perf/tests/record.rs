//! The record a figure is kept in.

use kr_perf::record::{Window, keep, report_in};

#[test]
fn each_figure_is_a_section_of_its_own_appended_under_its_heading() {
    let directory = tempfile::tempdir().expect("a directory");
    let evidence = directory.path().join("evidence");
    keep(
        &evidence,
        "suite.md",
        "KR-PERF-001 the first figure",
        &["  figure            1".to_owned()],
    )
    .expect("the first section is kept");
    report_in(
        Some(&evidence),
        "suite.md",
        "KR-PERF-002 the second figure",
        &[
            "  figure            2".to_owned(),
            "  verdict           met".to_owned(),
        ],
    );
    let kept = std::fs::read_to_string(evidence.join("suite.md")).expect("the record");
    assert_eq!(
        kept,
        "## KR-PERF-001 the first figure\n\n  figure            1\n\n\
         ## KR-PERF-002 the second figure\n\n  figure            2\n  verdict           met\n\n",
        "a later figure is appended after an earlier one, never written over it"
    );
}

#[test]
#[should_panic(expected = "this run could not keep its evidence at")]
fn a_run_whose_evidence_cannot_be_kept_fails() {
    // The evidence directory would be inside a file, which no platform allows.
    let directory = tempfile::tempdir().expect("a directory");
    let file = directory.path().join("a-file");
    std::fs::write(&file, b"").expect("a file");
    report_in(
        Some(&file.join("evidence")),
        "suite.md",
        "KR-PERF-001 a figure",
        &["  figure            1".to_owned()],
    );
}

#[test]
fn a_run_that_keeps_no_evidence_writes_nothing() {
    let directory = tempfile::tempdir().expect("a directory");
    report_in(
        None,
        "suite.md",
        "KR-PERF-001 a figure",
        &["  figure            1".to_owned()],
    );
    assert!(
        std::fs::read_dir(directory.path())
            .expect("the directory")
            .next()
            .is_none(),
        "nothing was written anywhere this test can see"
    );
}

#[test]
fn the_conditions_name_the_host_and_the_reference_host_it_is_held_to() {
    let lines = Window::open().close().lines();
    let labels: Vec<&str> = lines
        .iter()
        .map(|line| line.split_whitespace().next().unwrap_or_default())
        .collect();
    assert_eq!(
        labels,
        [
            "build",
            "host",
            "processor",
            "processors",
            "memory",
            "load",
            "stolen",
            "reference"
        ],
        "every record gives the same conditions in the same order: {lines:#?}"
    );
    assert!(
        lines[1].contains(std::env::consts::OS) && lines[1].contains(std::env::consts::ARCH),
        "the operating system and architecture are recorded: {}",
        lines[1]
    );
    assert!(
        lines[3].ends_with("against the reference host's 4"),
        "{}",
        lines[3]
    );
    assert!(
        lines[4].ends_with("against the reference host's 8192 MiB")
            || lines[4].contains("unverified"),
        "{}",
        lines[4]
    );
    assert!(lines[5].contains(" entering, "), "{}", lines[5]);
    if cfg!(debug_assertions) {
        assert!(
            lines[7].contains("the build is not optimised"),
            "an unoptimised build is short of the reference host: {}",
            lines[7]
        );
    }
}
