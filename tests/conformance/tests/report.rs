//! The report over trees of its own, whose every key and every outcome is known in advance.
//!
//! Each tree under `tests/fixtures/` is a Cargo workspace of its own, so the repository's
//! workspace never builds it: `forms` keys rows in every form the report reads and ignores
//! nothing, `outcomes` has a test that passes, one that fails and ones that are ignored, `known`
//! has a test that records a known difference, and `refused` names a row past the end of section
//! 21's table and a bare section. The runs build into a target directory of their own under the
//! platform's temporary directory.
//!
//! KR-REQ-29.01.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kr_conformance::id::{Identifier, Refusal};
use kr_conformance::map::{self, Binding, Declarations, Map, Place};
use kr_conformance::plan::{self, Group, Platform, Step};
use kr_conformance::report::{self, Document, Options, Outcome, Stopped, Verdict};

fn tree(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn identifier(text: &str) -> Identifier {
    text.parse().expect("an identifier")
}

fn map_of(name: &str, typescript: bool) -> Map {
    map::build(
        &tree(name),
        &Declarations {
            case_tables: &[],
            lanes: &[],
            typescript: typescript.then_some(&["."][..]),
            scripts: &[],
        },
    )
}

/// The tests each identifier keys, as `target name` and how, in order.
fn keyed(map: &Map) -> BTreeMap<String, Vec<(String, Binding)>> {
    map.keys
        .iter()
        .map(|(identifier, places)| {
            let tests = places
                .iter()
                .map(|(place, key)| {
                    let named = match place {
                        Place::Rust { target, name } => format!("{} {name}", target.name),
                        Place::RustModule { target, module } => {
                            format!("{} {module}::*", target.name)
                        }
                        Place::TypeScript { title, .. } => title.clone(),
                        Place::Lane { file, .. } => file.clone(),
                    };
                    (named, key.binding)
                })
                .collect();
            (identifier.to_string(), tests)
        })
        .collect()
}

/// Runs the report over `name` with its tests as the only step.
fn run(name: &str) -> Result<(Document, tempfile::TempDir), Stopped> {
    let evidence = tempfile::Builder::new()
        .prefix("kr-conformance-evidence.")
        .tempdir()
        .expect("an evidence directory");
    let target = std::env::temp_dir().join(format!("kr-conformance-fixture-target-{name}"));
    let options = Options {
        root: tree(name),
        evidence: kr_conformance::evidence::check_directory(evidence.path())
            .expect("inside the temporary directory"),
        selection: Some(vec![Group::Rust]),
        platform: Platform::current(),
        case_tables: &[],
        lanes: &[],
        applications: None,
        steps: Some(vec![Step::cargo(
            Group::Rust,
            "the tree's tests",
            &["test", "--locked", "--workspace", "--no-fail-fast"],
        )]),
        environment: vec![(
            "CARGO_TARGET_DIR".to_owned(),
            target.to_string_lossy().into_owned(),
        )],
    };
    report::run(&options, &mut |_| {}).map(|document| (document, evidence))
}

#[test]
fn every_comment_form_and_a_case_table_key_their_tests() {
    let map = map_of("forms", false);
    assert!(map.refused.is_empty(), "{:?}", map.refused);
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    let keyed = keyed(&map);
    let expect = |row: &str, tests: &[(&str, Binding)]| {
        let want: Vec<(String, Binding)> = tests
            .iter()
            .map(|(name, binding)| ((*name).to_owned(), *binding))
            .collect();
        assert_eq!(keyed.get(row), Some(&want), "{row}");
    };
    expect(
        "KR-REQ-02.02",
        &[
            ("forms tests::the_table_is_read", Binding::CaseTable),
            ("flow reads_the_table", Binding::CaseTable),
        ],
    );
    expect(
        "KR-REQ-02.03",
        &[("forms tests::*", Binding::ModuleComment)],
    );
    expect("KR-REQ-03.01", &[("flow ::*", Binding::ModuleComment)]);
    expect(
        "KR-REQ-03.02",
        &[("flow documented", Binding::AttachedComment)],
    );
    expect(
        "KR-REQ-03.03",
        &[("flow commented", Binding::AttachedComment)],
    );
    expect(
        "KR-REQ-03.04",
        &[("flow commented_inside", Binding::CommentInside)],
    );
    expect(
        "KR-REQ-03.05",
        &[("flow commented_inside", Binding::CommentInside)],
    );
    expect(
        "KR-REQ-03.06",
        &[
            ("flow first_in_the_section", Binding::SectionComment),
            ("flow second_in_the_section", Binding::SectionComment),
        ],
    );
    expect(
        "KR-REQ-03.07",
        &[("flow kr_req_03_07_named_by_its_name", Binding::TestName)],
    );
    expect(
        "KR-REQ-03.08",
        &[("flow calls_the_shared_case", Binding::CalledFunction)],
    );
    assert_eq!(keyed.len(), 10, "and nothing else: {keyed:?}");
}

#[test]
fn a_tree_with_nothing_ignored_reports_every_identifier_as_run() {
    let (document, _evidence) = run("forms").unwrap_or_else(|stopped| panic!("{stopped:?}"));
    assert_eq!(document.identifiers.len(), 10);
    for (identifier, record) in &document.identifiers {
        assert_eq!(record.verdict, Verdict::Passed, "{identifier}: {record:?}");
        assert!(
            record
                .tests
                .iter()
                .all(|test| test.outcome == Outcome::Passed),
            "{identifier}: {:?}",
            record.tests
        );
    }
    // The module comment of the test file keys every test in it, each by its own name.
    assert_eq!(document.identifiers["KR-REQ-03.01"].tests.len(), 8);
    assert!(document.passed());
}

#[test]
fn an_ignored_test_is_not_counted_and_a_failing_test_fails_its_identifier() {
    let (document, _evidence) = run("outcomes").unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let verdict = |row: &str| document.identifiers[row].verdict;
    assert_eq!(verdict("KR-REQ-04.01"), Verdict::Passed);
    assert_eq!(
        verdict("KR-REQ-04.02"),
        Verdict::NotRun,
        "an identifier whose every test was ignored is not run"
    );
    let ignored = &document.identifiers["KR-REQ-04.02"].tests[0];
    assert_eq!(ignored.outcome, Outcome::Ignored);
    assert_eq!(
        ignored.reason.as_deref(),
        Some("needs a device; the device lane runs it")
    );
    assert_eq!(verdict("KR-REQ-04.03"), Verdict::Failed);
    let both = &document.identifiers["KR-REQ-04.04"];
    assert_eq!(both.verdict, Verdict::Passed);
    assert_eq!(
        (both.counts.passed, both.counts.ignored),
        (1, 1),
        "the ignored test is not counted as passed"
    );
    assert!(!document.passed(), "a failing test fails the run");
    assert_eq!(document.summary.failed, 1);
}

#[test]
fn a_test_that_records_a_known_difference_is_never_counted_as_a_pass() {
    let (document, _evidence) = run("known").unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let both = &document.identifiers["KR-REQ-07.01"];
    assert_eq!(both.verdict, Verdict::Passed, "the ordinary test passed");
    assert_eq!((both.counts.passed, both.counts.known_difference), (1, 1));
    let only = &document.identifiers["KR-REQ-07.02"];
    assert_eq!(
        only.verdict,
        Verdict::KnownDifference,
        "a known difference alone is not a pass"
    );
    assert_eq!(only.tests[0].outcome, Outcome::KnownDifference);
    assert_eq!(only.tests[0].known_differences[0].grid, "four cells");
    assert_eq!(
        document.known_differences.len(),
        1,
        "listed in a section of its own"
    );
    assert_eq!(
        document.known_differences[0].identifiers,
        ["KR-REQ-07.01", "KR-REQ-07.02"]
    );
    assert_eq!(document.summary.known_difference, 1);
    assert!(document.passed(), "a known difference fails nothing");
}

#[test]
fn a_mention_on_product_code_is_a_reference_and_keys_no_test() {
    let map = map_of("outcomes", false);
    let row = identifier("KR-REQ-05.01");
    assert!(!map.keys.contains_key(&row));
    let references: Vec<&str> = map.references[&row]
        .iter()
        .map(|r| r.context.as_str())
        .collect();
    assert_eq!(
        references,
        ["the documentation of a module that is not test code"]
    );
}

#[test]
fn a_comment_naming_a_row_past_the_acceptance_table_is_refused_before_anything_runs() {
    let Err(Stopped::Refused(refused)) = run("refused") else {
        panic!("a refused mention stops the report");
    };
    let mut refusals: Vec<Refusal> = refused
        .iter()
        .map(|refused| refused.refusal.clone())
        .collect();
    refusals.sort_by_key(|refusal| format!("{refusal:?}"));
    assert_eq!(
        refusals,
        [
            Refusal::Malformed("KR-REQ-09".to_owned()),
            Refusal::OutsideAcceptanceTable("KR-ACC-036".to_owned()),
        ]
    );
    assert!(
        refused
            .iter()
            .all(|refused| refused.source.starts_with("src/lib.rs:"))
    );
}

#[test]
fn the_result_names_every_command_and_no_path_of_the_checkout() {
    let (document, evidence) = run("forms").unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let text = serde_json::to_string(&document).expect("serialises");
    let root = tree("forms");
    assert!(
        !text.contains(&*root.to_string_lossy()),
        "the result names the checkout's path"
    );
    assert!(
        !text.contains(env!("CARGO_MANIFEST_DIR")),
        "the result names the checkout's path"
    );
    let test = &document.identifiers["KR-REQ-03.02"].tests[0];
    assert_eq!(
        test.command.as_deref(),
        Some("cargo test --locked -p forms --test flow -- --exact documented")
    );
    assert_eq!(
        document.steps[0].command,
        "cargo test --locked --workspace --no-fail-fast"
    );
    assert!(document.steps[0].log.starts_with("conformance/logs/"));
    assert!(evidence.path().join(&document.steps[0].log).is_file());
    assert_eq!(document.schema, report::SCHEMA);
    assert!(!document.run.commit.id.is_empty());
    assert_eq!(
        document.run.terminal_profile.profile, "unknown",
        "this tree has no terminal profile"
    );
}

#[test]
fn a_target_no_step_runs_is_not_run_with_the_reason() {
    // The same tree, with a step that runs only its library: the integration tests are keyed, and
    // nothing ran them.
    let evidence = tempfile::tempdir().expect("an evidence directory");
    let target = std::env::temp_dir().join("kr-conformance-fixture-target-forms-lib");
    let options = Options {
        root: tree("forms"),
        evidence: kr_conformance::evidence::check_directory(evidence.path()).expect("inside"),
        selection: None,
        platform: Platform::current(),
        case_tables: &[],
        lanes: &[],
        applications: None,
        steps: Some(vec![Step::cargo(
            Group::Rust,
            "the library's tests",
            &["test", "--locked", "--lib"],
        )]),
        environment: vec![(
            "CARGO_TARGET_DIR".to_owned(),
            target.to_string_lossy().into_owned(),
        )],
    };
    let document = report::run(&options, &mut |_| {}).expect("runs");
    let unrun = &document.identifiers["KR-REQ-03.02"];
    assert_eq!(unrun.verdict, Verdict::NotRun);
    assert_eq!(unrun.tests[0].outcome, Outcome::NotRun);
    assert!(
        unrun.tests[0]
            .reason
            .as_deref()
            .is_some_and(|reason| !reason.is_empty())
    );
    assert_eq!(
        document.identifiers["KR-REQ-02.03"].verdict,
        Verdict::Passed
    );
    // A full run lists every row of section 21's and section 27's tables, named or not.
    assert!(document.identifiers.contains_key("KR-ACC-001"));
    assert!(document.identifiers.contains_key("KR-PERF-010"));
    assert_eq!(document.identifiers["KR-ACC-001"].verdict, Verdict::NotRun);
    assert!(document.passed(), "a test no step runs fails nothing");
}

#[test]
fn a_test_a_steps_own_flags_leave_out_is_not_run_rather_than_not_built() {
    let evidence = tempfile::tempdir().expect("an evidence directory");
    let target = std::env::temp_dir().join("kr-conformance-fixture-target-outcomes-ignored");
    let options = Options {
        root: tree("outcomes"),
        evidence: kr_conformance::evidence::check_directory(evidence.path()).expect("inside"),
        selection: Some(vec![Group::Rust]),
        platform: Platform::current(),
        case_tables: &[],
        lanes: &[],
        applications: None,
        steps: Some(vec![Step::cargo(
            Group::Rust,
            "the ignored tests alone",
            &["test", "--locked", "--lib", "--", "--ignored"],
        )]),
        environment: vec![(
            "CARGO_TARGET_DIR".to_owned(),
            target.to_string_lossy().into_owned(),
        )],
    };
    let document = report::run(&options, &mut |_| {}).expect("runs");
    let passes = &document.identifiers["KR-REQ-04.01"].tests[0];
    assert_eq!(passes.outcome, Outcome::NotRun, "{passes:?}");
    assert!(
        passes
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("ignored by default"))
    );
    assert_eq!(
        document.identifiers["KR-REQ-04.02"].verdict,
        Verdict::Passed,
        "the ignored test ran"
    );
    assert!(document.passed(), "nothing that ran failed");
}

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

#[test]
fn the_end_to_end_group_runs_what_the_end_to_end_script_runs() {
    let script = std::fs::read_to_string(repository().join("scripts").join("end-to-end.sh"))
        .expect("the script");
    let listed: Vec<(String, String)> = script
        .lines()
        .filter_map(|line| line.trim().strip_prefix('"'))
        .filter_map(|entry| entry.split_once('|'))
        .filter_map(|(target, _)| target.split_once(':'))
        .map(|(package, suite)| (package.to_owned(), suite.to_owned()))
        .collect();
    let planned: Vec<(String, String)> = plan::END_TO_END_SUITES
        .iter()
        .map(|(package, suite)| ((*package).to_owned(), (*suite).to_owned()))
        .collect();
    assert_eq!(
        planned, listed,
        "scripts/end-to-end.sh's suites, in its order"
    );
    assert!(
        script.contains("-- --test-threads=1 $ignored"),
        "one test at a time"
    );
    assert!(
        script.contains("if [ \"$suite\" = \"network\" ]; then\n    ignored=\"--include-ignored\"")
    );
}

#[test]
fn the_performance_group_takes_what_the_performance_script_takes() {
    let script = std::fs::read_to_string(repository().join("scripts").join("performance.sh"))
        .expect("the script");
    let listed: Vec<(String, String)> = script
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (kind, name) = line.split_once(' ')?;
            let name = name.strip_suffix(" || failed=1")?;
            match kind {
                "measurement" => Some(("test performance".to_owned(), name.to_owned())),
                "input_measurement" => Some(("bench input_latency".to_owned(), name.to_owned())),
                _ => None,
            }
        })
        .collect();
    let planned: Vec<(String, String)> = plan::MEASUREMENTS
        .iter()
        .map(|(target, name)| ((*target).to_owned(), (*name).to_owned()))
        .collect();
    assert_eq!(
        planned, listed,
        "scripts/performance.sh's measurements, in its order"
    );
    assert!(script.contains("-- --ignored --exact --nocapture \"$name\""));
}

#[test]
#[ignore = "reads TypeScript with the packages' own compiler, which `pnpm install --frozen-lockfile` installs; the report's typescript group runs it"]
fn typescript_comment_forms_and_titles_key_their_tests() {
    let map = map_of("typescript", true);
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    let keyed = keyed(&map);
    let all = [
        "the forms has a comment inside",
        "the forms is attached",
        "the forms is not keyed by the note above",
        "the forms KR-REQ-06.05 is named in its title",
    ];
    let titles = |row: &str| -> Vec<String> {
        let mut titles: Vec<String> = keyed
            .get(row)
            .map(|tests| tests.iter().map(|(title, _)| title.clone()).collect())
            .unwrap_or_default();
        titles.sort();
        titles
    };
    let mut every: Vec<String> = all.iter().map(|title| (*title).to_owned()).collect();
    every.sort();
    assert_eq!(
        titles("KR-REQ-06.01"),
        every,
        "the file's header keys every test"
    );
    assert_eq!(
        titles("KR-REQ-06.02"),
        every,
        "the suite's comment keys every test inside it"
    );
    assert_eq!(titles("KR-REQ-06.03"), ["the forms is attached"]);
    assert_eq!(titles("KR-REQ-06.04"), ["the forms has a comment inside"]);
    assert_eq!(
        titles("KR-REQ-06.05"),
        ["the forms KR-REQ-06.05 is named in its title"]
    );
    assert!(!map.keys.contains_key(&identifier("KR-REQ-06.06")));
    assert!(map.references.contains_key(&identifier("KR-REQ-06.06")));
}
