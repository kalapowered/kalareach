//! Replays every committed scenario under `fixtures/shell-bridge/`.
//!
//! The corpus in the library states what each step must produce; these files are that corpus as
//! data, and this harness is the proof that the two agree. Each shell package's own tests read the
//! same files, so a package and the worker are checked against one set of expectations rather than
//! against each other.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use kr_shell_integration::contract::events::{NativeReason, PreEofDecision};
use kr_shell_integration::contract::fixtures::{
    FIXTURES_DIRECTORY, PreEofStep, Scenario, Script, render, replay, scenarios,
};
use kr_shell_integration::contract::qualification::DetachExclusion;

fn fixtures_root() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.push("..");
    root.push("..");
    for part in FIXTURES_DIRECTORY.split('/') {
        root.push(part);
    }
    root
}

fn committed(root: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root).expect("the scenario directory is readable") {
        let entry = entry.expect("a directory entry is readable");
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".json") {
            continue;
        }
        let contents = std::fs::read_to_string(entry.path()).expect("a scenario file is readable");
        files.push((name, contents));
    }
    files.sort();
    files
}

fn load() -> Vec<Scenario> {
    committed(&fixtures_root())
        .into_iter()
        .map(|(name, contents)| {
            serde_json::from_str(&contents)
                .unwrap_or_else(|error| panic!("{name} does not decode as a scenario: {error}"))
        })
        .collect()
}

#[test]
fn every_committed_scenario_holds_against_the_contract() {
    let scenarios = load();
    assert!(
        scenarios.len() >= 40,
        "the corpus has shrunk to {} scenarios",
        scenarios.len()
    );
    let mut checks = 0;
    let mut failures = Vec::new();
    for scenario in &scenarios {
        let replayed = replay(scenario);
        assert!(
            replayed.checks > 0,
            "{} asserts nothing at all",
            scenario.id
        );
        checks += replayed.checks;
        failures.extend(replayed.failures);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(
        checks > scenarios.len(),
        "{checks} expectations across {} scenarios is too few",
        scenarios.len()
    );
}

#[test]
fn the_committed_files_are_the_corpus() {
    let root = fixtures_root();
    let on_disk: BTreeSet<String> = committed(&root).into_iter().map(|(name, _)| name).collect();
    let expected: BTreeSet<String> = scenarios()
        .iter()
        .map(|scenario| scenario.file_name())
        .collect();
    assert_eq!(
        on_disk, expected,
        "run `cargo run -p kr-shell-integration --bin kr-shell-fixtures` and commit the result"
    );
    for scenario in scenarios() {
        let path = root.join(scenario.file_name());
        let contents = std::fs::read_to_string(&path).expect("a scenario file is readable");
        assert_eq!(
            contents,
            render(&scenario),
            "{} differs from the corpus; run `cargo run -p kr-shell-integration --bin \
             kr-shell-fixtures` and commit the result",
            path.display()
        );
    }
}

#[test]
fn the_corpus_covers_the_requirement_rows_the_contract_carries() {
    let scenarios = load();
    let covered: BTreeSet<String> = scenarios
        .iter()
        .flat_map(|scenario| scenario.covers.iter().cloned())
        .collect();
    for row in [
        "KR-REQ-07.39",
        "KR-REQ-07.70",
        "KR-REQ-07.73",
        "KR-REQ-07.74",
        "KR-REQ-07.75",
        "KR-REQ-07.76",
        "KR-REQ-07.77",
        "KR-REQ-07.78",
        "KR-REQ-07.79",
        "KR-REQ-07.80",
        "KR-REQ-07.81",
        "KR-REQ-07.82",
        "KR-REQ-07.83",
        "KR-REQ-07.84",
        "KR-REQ-07.89",
    ] {
        assert!(covered.contains(row), "no scenario covers {row}");
    }
}

#[test]
fn the_ten_exclusions_each_have_their_own_case() {
    let scenarios = load();
    let exclusions = scenarios
        .iter()
        .find(|scenario| scenario.id == "detach-condition-exclusions")
        .map(|scenario| scenario.script.clone())
        .expect("the exclusion scenario is committed");
    let Script::PreEof(script) = exclusions else {
        panic!("the exclusion scenario drives the pre-EOF decision");
    };
    let mut names = Vec::new();
    let mut excluded = Vec::new();
    for step in &script.steps {
        if let PreEofStep::Offer { name, expect, .. } = step {
            names.push(name.clone());
            if let PreEofDecision::Native {
                reason: NativeReason::Excluded(exclusion),
            } = expect
            {
                excluded.push(*exclusion);
            }
        }
    }
    for exclusion in DetachExclusion::ALL {
        assert!(
            excluded.contains(exclusion),
            "no case produces {}",
            exclusion.as_str()
        );
    }
    assert!(
        excluded.contains(&DetachExclusion::NotManagedRootEditor),
        "no case covers the requirement that the reader is the managed root editor"
    );
    let count = names.len();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), count, "two cases share a name");
}

#[test]
fn every_decision_point_has_committed_scenarios() {
    let scenarios = load();
    let kinds: Vec<&str> = scenarios
        .iter()
        .map(|scenario| match scenario.script {
            Script::Handshake(_) => "handshake",
            Script::Fence(_) => "fence",
            Script::PreEof(_) => "pre_eof",
            Script::Launch(_) => "launch",
        })
        .collect();
    for kind in ["handshake", "fence", "pre_eof", "launch"] {
        assert!(
            kinds.contains(&kind),
            "no committed scenario drives the {kind} decision"
        );
    }
}
