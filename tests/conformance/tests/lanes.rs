//! The report over the phone applications' unit tests: the Kotlin and Swift test files as they were
//! committed, and the results Gradle and Xcode wrote for them, taken from real runs (the files in
//! `tests/fixtures/lane-results/`, with the machine's name and the simulator's identifier taken
//! out, pruned to the files of the tree in `tests/fixtures/lanes/`). The `-failing` results are
//! those of the same tests with one assertion broken, and `ios-xcode-26.3.json` is the iOS result
//! of the Xcode on a hosted runner.
//!
//! KR-REQ-29.01.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kr_conformance::lane::{self, Case};
use kr_conformance::libtest::Outcome as LibtestOutcome;
use kr_conformance::map::{self, Declarations, Map, Place};
use kr_conformance::plan::{self, Group, Platform, Reading, Step, Tests};
use kr_conformance::report::{self, Document, Gathered, Options, Outcome, Verdict};
use kr_conformance::run::Executed;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn map_of(root: &Path) -> Map {
    map::build(
        root,
        &Declarations {
            case_tables: &[],
            lanes: plan::LANES,
            typescript: None,
            scripts: &[],
        },
    )
}

fn options(platform: Platform) -> Options {
    Options {
        root: fixtures().join("lanes"),
        evidence: PathBuf::from("/tmp/e"),
        selection: Some(vec![Group::Phones]),
        all_terminals: false,
        platform,
        case_tables: &[],
        lanes: plan::LANES,
        applications: None,
        steps: None,
        lister: PathBuf::from("/tmp/l"),
        environment: Vec::new(),
    }
}

fn step(platform: Platform) -> Step {
    plan::steps(platform, &[Group::Phones], "/tmp/e", None)
        .pop()
        .expect("a phones step")
}

fn executed(step: Step, exit: i32, cases: Result<Vec<Case>, String>) -> Executed {
    let (lane, error) = match cases {
        Ok(cases) => (Some(cases), None),
        Err(error) => (None, Some(error)),
    };
    Executed {
        step,
        exit: Some(exit),
        seconds: 0,
        log: "conformance/logs/x.log".to_owned(),
        binaries: Vec::new(),
        built: Vec::new(),
        listed: BTreeMap::new(),
        vitest: None,
        lane,
        tools: vec![("gradle".to_owned(), "8.14.3".to_owned())],
        error,
    }
}

fn junit(name: &str) -> Vec<Case> {
    lane::read_junit(&fixtures().join("lane-results").join(name)).expect("the fixture's results")
}

fn xcode(name: &str) -> Vec<Case> {
    lane::read_xcode(&fixtures().join("lane-results").join(name)).expect("the fixture's results")
}

fn assemble(platform: Platform, map: &Map, steps: &[Executed]) -> Document {
    report::assemble(
        &options(platform),
        &[Group::Phones],
        map,
        steps,
        Gathered::default(),
        "2026-10-08T00:00:00Z".to_owned(),
    )
}

fn counts(document: &Document, row: &str) -> (Verdict, usize, usize, usize) {
    let record = &document.identifiers[row];
    (
        record.verdict,
        record.counts.passed,
        record.counts.failed,
        record.counts.not_run,
    )
}

#[test]
fn a_row_the_android_lane_ran_reads_passed_and_the_ios_files_say_where_they_run() {
    let map = map_of(&fixtures().join("lanes"));
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    let document = assemble(
        Platform::Linux,
        &map,
        &[executed(step(Platform::Linux), 0, Ok(junit("junit")))],
    );
    assert!(document.passed(), "{:?}", document.problems);
    // VoiceCaptureGateTest.kt has ten cases and names the row; the Swift file is another report's.
    assert_eq!(
        counts(&document, "KR-REQ-15.34"),
        (Verdict::Passed, 10, 0, 1)
    );
    assert_eq!(
        counts(&document, "KR-REQ-15.35"),
        (Verdict::Passed, 14, 0, 1)
    );
    let tests = &document.identifiers["KR-REQ-15.34"].tests;
    let swift = tests
        .iter()
        .find(|test| test.test.ends_with("VoiceCaptureStateTests.swift"))
        .expect("the Swift file's record");
    assert_eq!(swift.outcome, Outcome::NotRun);
    assert!(
        swift
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("macOS report")),
        "{swift:?}"
    );
    let case = tests
        .iter()
        .find(|test| test.test.ends_with("nothing_is_captured_without_a_permit"))
        .expect("a case's record");
    assert_eq!(
        case.command.as_deref(),
        Some(
            "bash scripts/android-unit-tests.sh -- --tests to.kala.reach.companion.mobile.VoiceCaptureGateTest.nothing_is_captured_without_a_permit"
        )
    );
    assert!(
        case.source.ends_with("VoiceCaptureGateTest.kt:13"),
        "{case:?}"
    );
    assert_eq!(document.run.toolchain.phones["gradle"], "8.14.3");
}

#[test]
fn a_row_the_ios_lane_ran_reads_passed_from_every_class_of_the_file_that_names_it() {
    let map = map_of(&fixtures().join("lanes"));
    let document = assemble(
        Platform::MacOs,
        &map,
        &[executed(step(Platform::MacOs), 0, Ok(xcode("ios.json")))],
    );
    assert!(document.passed(), "{:?}", document.problems);
    // The file declares five test classes with 39 cases; LaunchPlanTests.swift names no row.
    assert_eq!(
        counts(&document, "KR-REQ-15.34"),
        (Verdict::Passed, 39, 0, 1)
    );
    let case = document.identifiers["KR-REQ-15.34"]
        .tests
        .iter()
        .find(|test| {
            test.test
                .ends_with("VoiceCaptureGateTests.testNothingIsCapturedWithoutAPermit()")
        })
        .expect("a case's record");
    assert_eq!(
        case.command.as_deref(),
        Some(
            "bash scripts/ios-unit-tests.sh -- -only-testing:KalaReachNativeTests/VoiceCaptureGateTests/testNothingIsCapturedWithoutAPermit"
        )
    );
}

#[test]
fn a_failing_case_fails_every_row_its_file_names_and_the_run() {
    let map = map_of(&fixtures().join("lanes"));
    let android = assemble(
        Platform::Linux,
        &map,
        &[executed(
            step(Platform::Linux),
            1,
            Ok(junit("junit-failing")),
        )],
    );
    assert!(!android.passed());
    assert_eq!(counts(&android, "KR-REQ-15.34"), (Verdict::Failed, 9, 1, 1));
    // The file is the unit of keying, so the row the file names beside it fails with it.
    assert_eq!(counts(&android, "KR-REQ-15.35").0, Verdict::Failed);
    assert!(android.failures_outside_identifiers.is_empty());
    let ios = assemble(
        Platform::MacOs,
        &map,
        &[executed(
            step(Platform::MacOs),
            65,
            Ok(xcode("ios-failing.json")),
        )],
    );
    assert!(!ios.passed());
    assert_eq!(counts(&ios, "KR-REQ-15.34").0, Verdict::Failed);
    let failed: Vec<&str> = ios.identifiers["KR-REQ-15.34"]
        .tests
        .iter()
        .filter(|test| test.outcome == Outcome::Failed)
        .map(|test| test.test.as_str())
        .collect();
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert!(failed[0].ends_with("testNothingIsCapturedWithoutAPermit()"));
}

#[test]
fn a_file_the_lane_ran_and_reported_nothing_of_is_failed_and_never_not_run() {
    let map = map_of(&fixtures().join("lanes"));
    let mut cases = junit("junit");
    cases.retain(|case| case.class.ends_with("VoiceServiceActionsTest"));
    let document = assemble(
        Platform::Linux,
        &map,
        &[executed(step(Platform::Linux), 0, Ok(cases))],
    );
    let gate = document.identifiers["KR-REQ-15.34"]
        .tests
        .iter()
        .find(|test| test.test.ends_with("VoiceCaptureGateTest.kt"))
        .expect("the file's record");
    assert_eq!(gate.outcome, Outcome::Failed);
    assert_eq!(
        document.identifiers["KR-REQ-15.34"].verdict,
        Verdict::Failed
    );
}

#[test]
fn a_lane_whose_results_cannot_be_read_fails_all_its_files() {
    let map = map_of(&fixtures().join("lanes"));
    let document = assemble(
        Platform::Linux,
        &map,
        &[executed(
            step(Platform::Linux),
            1,
            Err("the directory holds no JUnit file".to_owned()),
        )],
    );
    assert!(!document.passed());
    assert_eq!(document.summary.failed_steps, [1]);
    for row in ["KR-REQ-15.34", "KR-REQ-15.35"] {
        assert_eq!(document.identifiers[row].verdict, Verdict::Failed, "{row}");
    }
    assert!(
        document.identifiers["KR-REQ-15.34"]
            .tests
            .iter()
            .any(|test| test
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("no JUnit file")))
    );
}

#[test]
fn a_failed_case_in_a_file_no_row_names_is_listed_and_touches_no_row() {
    let map = map_of(&fixtures().join("lanes"));
    let mut cases = xcode("ios.json");
    cases
        .iter_mut()
        .find(|case| case.class == "LaunchPlanTests")
        .expect("a case of the unkeyed file")
        .outcome = LibtestOutcome::Failed;
    let document = assemble(
        Platform::MacOs,
        &map,
        &[executed(step(Platform::MacOs), 65, Ok(cases))],
    );
    assert!(!document.passed());
    assert_eq!(document.failures_outside_identifiers.len(), 1);
    assert!(document.failures_outside_identifiers[0].contains("LaunchPlanTests"));
    assert!(document.problems.is_empty(), "{:?}", document.problems);
    assert_eq!(counts(&document, "KR-REQ-15.34").0, Verdict::Passed);
}

#[test]
fn a_case_no_file_can_be_given_to_fails_every_row_of_its_lane() {
    // Whichever way the reading of the sources went wrong, a result that cannot be given to one
    // file cannot be given to any row: here a class no file declares, and a class the reading
    // missed in a file that names the rows.
    let map = map_of(&fixtures().join("lanes"));
    let elsewhere = Case {
        class: "ElsewhereTests".to_owned(),
        name: "testElsewhere()".to_owned(),
        selector: "KalaReachNativeTests/ElsewhereTests/testElsewhere".to_owned(),
        outcome: LibtestOutcome::Passed,
        note: None,
    };
    let mut cases = xcode("ios.json");
    cases.push(elsewhere);
    let mut missed = map_of(&fixtures().join("lanes"));
    let swift = "apps/companion/native/ios/Tests/VoiceCaptureStateTests.swift";
    missed
        .lane_classes
        .get_mut(swift)
        .expect("the file's classes")
        .retain(|class| class != "VoiceRecorderReaderTests");
    // A class two files list: the first reading is wrong in one of them.
    let mut twice = map_of(&fixtures().join("lanes"));
    twice
        .lane_classes
        .get_mut("apps/companion/native/ios/Tests/LaunchPlanTests.swift")
        .expect("the second file's classes")
        .push("VoiceRecorderReaderTests".to_owned());
    for (map, cases, why) in [
        (&map, cases, "ElsewhereTests"),
        (&missed, xcode("ios.json"), "VoiceRecorderReaderTests"),
        (&twice, xcode("ios.json"), "more than one file"),
    ] {
        let document = assemble(
            Platform::MacOs,
            map,
            &[executed(step(Platform::MacOs), 0, Ok(cases))],
        );
        assert!(!document.passed());
        assert_eq!(document.problems.len(), 1, "{:?}", document.problems);
        assert!(document.problems[0].contains(why));
        for row in ["KR-REQ-15.34", "KR-REQ-15.35", "KR-REQ-15.36", "KR-ACC-014"] {
            assert_eq!(document.identifiers[row].verdict, Verdict::Failed, "{row}");
        }
        let swift_record = document.identifiers["KR-REQ-15.34"]
            .tests
            .iter()
            .find(|test| test.test.ends_with("VoiceCaptureStateTests.swift"))
            .expect("the Swift file's record");
        assert!(
            swift_record
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains(why)),
            "{swift_record:?}"
        );
    }
}

#[test]
fn a_class_given_to_the_wrong_single_file_still_fails_the_run() {
    // The limit of the rule: a class missed in its own file and listed in another that names no row
    // stays attributed to that other file. Its failure then fails the run and is listed among the
    // failures outside any row, though the rows of the file that holds the class read from its
    // other classes.
    let mut map = map_of(&fixtures().join("lanes"));
    map.lane_classes
        .get_mut("apps/companion/native/ios/Tests/VoiceCaptureStateTests.swift")
        .expect("the file's classes")
        .retain(|class| class != "VoiceRecorderReaderTests");
    map.lane_classes
        .get_mut("apps/companion/native/ios/Tests/LaunchPlanTests.swift")
        .expect("the second file's classes")
        .push("VoiceRecorderReaderTests".to_owned());
    let mut cases = xcode("ios.json");
    cases
        .iter_mut()
        .find(|case| case.class == "VoiceRecorderReaderTests")
        .expect("a case of the class")
        .outcome = LibtestOutcome::Failed;
    let document = assemble(
        Platform::MacOs,
        &map,
        &[executed(step(Platform::MacOs), 65, Ok(cases))],
    );
    assert!(!document.passed());
    assert_eq!(document.failures_outside_identifiers.len(), 1);
    assert!(document.failures_outside_identifiers[0].contains("VoiceRecorderReaderTests"));
}

#[test]
fn a_selection_without_the_phones_group_leaves_the_lane_files_out() {
    let map = map_of(&fixtures().join("lanes"));
    let mut selected = options(Platform::Linux);
    selected.selection = Some(vec![Group::Rust]);
    let document = report::assemble(
        &selected,
        &[Group::Rust],
        &map,
        &[],
        Gathered::default(),
        "2026-10-08T00:00:00Z".to_owned(),
    );
    assert!(document.identifiers.is_empty());
    let document = assemble(Platform::Linux, &map, &[]);
    assert_eq!(document.identifiers.len(), 5);
}

#[test]
fn a_windows_run_that_selects_the_phones_group_gives_no_rust_test_the_phones_reason() {
    use kr_conformance::workspace::{TargetId, TargetKind};
    let target = TargetId {
        package: "kr-client".to_owned(),
        kind: TargetKind::Lib,
        name: "kr_client".to_owned(),
    };
    let mut map = Map::default();
    map.keys
        .entry("KR-REQ-29.01".parse().expect("an identifier"))
        .or_default()
        .insert(
            Place::Rust {
                target,
                name: "a_test".to_owned(),
            },
            map::Key {
                binding: map::Binding::AttachedComment,
                source: "crates/kr-client/src/lib.rs:1".to_owned(),
            },
        );
    let mut windows = options(Platform::Windows);
    // The groups are the ones the run selected; leaving the selection open lists the test whatever ran.
    windows.selection = None;
    let document = report::assemble(
        &windows,
        &[Group::Rust, Group::Phones],
        &map,
        &[],
        Gathered::default(),
        "2026-10-08T00:00:00Z".to_owned(),
    );
    let record = &document.identifiers["KR-REQ-29.01"].tests[0];
    assert_eq!(record.outcome, Outcome::NotRun);
    assert!(
        record
            .reason
            .as_deref()
            .is_some_and(|reason| !reason.contains("phone")),
        "{record:?}"
    );
}

#[test]
fn the_phones_group_is_planned_for_linux_and_macos_and_not_for_windows() {
    let runs = |platform| plan::steps(platform, &[Group::Phones], "/tmp/e", None);
    assert_eq!(
        runs(Platform::Linux)[0].reading,
        Reading::Lane(Tests::Junit)
    );
    assert_eq!(
        runs(Platform::MacOs)[0].reading,
        Reading::Lane(Tests::Xcode)
    );
    assert!(runs(Platform::Windows).is_empty());
    assert!(plan::group_absent_reason(Group::Phones, Platform::Windows).is_some());
    assert_eq!(Group::ALL.last(), Some(&Group::Phones));
}

#[test]
fn a_nested_class_belongs_to_the_file_of_the_class_around_it_and_to_no_other() {
    let directory = "apps/companion/native/android/src/test/kotlin/p";
    let mut map = Map::default();
    map.lane_classes
        .insert(format!("{directory}/Outer.kt"), vec!["p.Outer".to_owned()]);
    map.lane_classes
        .insert(format!("{directory}/Inner.kt"), vec!["p.Inner".to_owned()]);
    let case = |class: &str| Case {
        class: class.to_owned(),
        name: "t".to_owned(),
        selector: format!("{class}.t"),
        outcome: LibtestOutcome::Passed,
        note: None,
    };
    let document = assemble(
        Platform::Linux,
        &map,
        &[executed(
            step(Platform::Linux),
            0,
            Ok(vec![case("p.Outer$Inner"), case("p.Inner")]),
        )],
    );
    assert!(document.problems.is_empty(), "{:?}", document.problems);
    let document = assemble(
        Platform::Linux,
        &map,
        &[executed(
            step(Platform::Linux),
            0,
            Ok(vec![case("p.Elsewhere")]),
        )],
    );
    assert_eq!(document.problems.len(), 1, "{:?}", document.problems);
}

#[test]
fn the_result_tree_reads_the_same_from_the_two_xcode_versions_that_wrote_it() {
    // One was written by the Xcode of a developer's Mac, the other by the newest one a hosted runner
    // has; the cases and their results are the same.
    let named = |cases: Vec<Case>| -> Vec<(String, String, LibtestOutcome)> {
        cases
            .into_iter()
            .map(|case| (case.class, case.name, case.outcome))
            .collect()
    };
    let developer = named(xcode("ios.json"));
    let runner = named(xcode("ios-xcode-26.3.json"));
    assert_eq!(developer.len(), 49);
    assert_eq!(runner, developer);
}

#[test]
fn results_that_disagree_with_themselves_are_refused() {
    let gate = std::fs::read_to_string(
        fixtures()
            .join("lane-results")
            .join("junit")
            .join("TEST-to.kala.reach.companion.mobile.VoiceCaptureGateTest.xml"),
    )
    .expect("a result file");
    assert_eq!(lane::parse_junit(&gate).expect("as written").len(), 10);
    // A case the file's own count does not include.
    let without_a_case: String = gate
        .lines()
        .filter(|line| !line.contains("capture_ends_at_the_deadline_by_itself"))
        .map(|line| format!("{line}\n"))
        .collect();
    assert!(
        lane::parse_junit(&without_a_case)
            .expect_err("a count that is not kept")
            .contains("states 10 tests")
    );
    // A failure the file's counts do not include.
    let failing = std::fs::read_to_string(
        fixtures()
            .join("lane-results")
            .join("junit-failing")
            .join("TEST-to.kala.reach.companion.mobile.VoiceCaptureGateTest.xml"),
    )
    .expect("a result file");
    assert!(lane::parse_junit(&failing).is_ok());
    assert!(
        lane::parse_junit(&failing.replace("failures=\"1\"", "failures=\"0\""))
            .expect_err("a failure that is not counted")
            .contains("failures")
    );
    let directory = tempfile::tempdir().expect("a directory");
    assert!(lane::read_junit(directory.path()).is_err());
    // A case reported twice, here by two files that hold the same class.
    std::fs::write(directory.path().join("a.xml"), &gate).expect("a copy");
    std::fs::write(directory.path().join("b.xml"), &gate).expect("a copy");
    assert!(
        lane::read_junit(directory.path())
            .expect_err("a case that is reported twice")
            .contains("reported twice")
    );

    let tree = std::fs::read_to_string(fixtures().join("lane-results").join("ios-failing.json"))
        .expect("a result tree");
    let mut value: serde_json::Value = serde_json::from_str(&tree).expect("JSON");
    assert!(lane::parse_xcode(&value).is_ok());
    // A suite that failed with no failed case under it.
    set_result(
        &mut value,
        "testNothingIsCapturedWithoutAPermit()",
        "Passed",
    );
    assert!(
        lane::parse_xcode(&value)
            .expect_err("a failure nothing accounts for")
            .contains("no case under it failed")
    );
    // A case reported twice.
    let mut repeated: serde_json::Value = serde_json::from_str(&tree).expect("JSON");
    let suite = repeated
        .pointer_mut("/testNodes/0/children/0/children/0/children")
        .and_then(|children| children.as_array_mut())
        .expect("the cases of a suite");
    let first = suite[0].clone();
    suite.push(first);
    assert!(
        lane::parse_xcode(&repeated)
            .expect_err("a case that is reported twice")
            .contains("reported twice")
    );
    // A result this report does not read is not guessed at, and an expected failure is not a pass.
    set_result(
        &mut value,
        "testNothingIsCapturedWithoutAPermit()",
        "unknown",
    );
    assert!(lane::parse_xcode(&value).is_err());
    set_result(
        &mut value,
        "testNothingIsCapturedWithoutAPermit()",
        "Expected Failure",
    );
    let cases = lane::parse_xcode(&value).expect("read");
    let expected: Vec<&Case> = cases
        .iter()
        .filter(|case| case.outcome == LibtestOutcome::Failed)
        .collect();
    assert_eq!(expected.len(), 1);
    assert!(expected[0].note.is_some());
    // Xcode ends 0 over a case that failed as expected, and only that case is a failure.
    assert!(lane::agree_with_exit(Some(0), &cases).is_ok());
    assert!(lane::agree_with_exit(Some(65), &cases).is_err());
}

/// Sets the result of the node called `name` wherever it is in `value`.
fn set_result(value: &mut serde_json::Value, name: &str, result: &str) {
    if value["name"] == name {
        value["result"] = serde_json::json!(result);
    }
    if let Some(children) = value.get_mut("children").and_then(|c| c.as_array_mut()) {
        for child in children {
            set_result(child, name, result);
        }
    }
    if let Some(nodes) = value.get_mut("testNodes").and_then(|c| c.as_array_mut()) {
        for node in nodes {
            set_result(node, name, result);
        }
    }
}

#[cfg(unix)]
#[test]
fn the_report_runs_a_lane_step_and_reads_what_it_left_in_the_evidence() {
    let evidence = tempfile::Builder::new()
        .prefix("kr-conformance-evidence.")
        .tempdir()
        .expect("an evidence directory");
    let checked = kr_conformance::evidence::check_directory(evidence.path())
        .expect("inside the temporary directory");
    let results = checked.join("conformance").join("android");
    let mut step = step(Platform::Linux);
    step.command = vec![
        "sh".to_owned(),
        "-c".to_owned(),
        // The first value of a name stands, and a name with no value is unknown.
        "echo 'kr-tool: gradle: 8.14.3'; echo 'kr-tool: java: '; echo 'kr-tool: gradle: 9.9'; cp -R \"$0\" \"${1#--results=}\"".to_owned(),
        fixtures()
            .join("lane-results")
            .join("junit")
            .to_string_lossy()
            .into_owned(),
        format!("--results={}", results.display()),
    ];
    let mut run = options(Platform::Linux);
    run.evidence = checked;
    run.steps = Some(vec![step]);
    run.lister = PathBuf::from(env!("CARGO_BIN_EXE_kr-conformance"));
    let document = report::run(&run, &mut |_| {}).expect("the run");
    assert!(document.passed(), "{:?}", document.problems);
    assert_eq!(
        counts(&document, "KR-REQ-15.34"),
        (Verdict::Passed, 10, 0, 1)
    );
    assert_eq!(document.run.toolchain.phones["gradle"], "8.14.3");
    assert_eq!(document.run.toolchain.phones["java"], "unknown");
}

#[test]
fn a_phone_test_file_whose_braces_do_not_balance_is_one_problem_that_names_it() {
    let root = tempfile::tempdir().expect("a directory");
    let kotlin = "apps/companion/native/android/src/test/kotlin/to/kala/reach/companion/mobile/VoiceCaptureGateTest.kt";
    let source = fixtures().join("lanes").join(kotlin);
    let target = root.path().join(kotlin);
    std::fs::create_dir_all(target.parent().expect("a directory")).expect("directories");
    let text = std::fs::read_to_string(&source).expect("the fixture");
    let cut = text.rfind('}').expect("a closing brace");
    std::fs::write(&target, &text[..cut]).expect("a file");
    // The directory holds no Cargo workspace, which is a problem of its own; the file has one.
    let map = map_of(root.path());
    assert!(
        map.keys
            .values()
            .flat_map(|places| places.keys())
            .any(|place| matches!(place, Place::Lane { file, .. } if file == kotlin))
    );
    let own: Vec<&String> = map
        .problems
        .iter()
        .filter(|problem| problem.starts_with(kotlin))
        .collect();
    assert_eq!(own.len(), 1, "{:?}", map.problems);
    assert!(
        own[0].contains("cannot be read for its classes"),
        "{:?}",
        map.problems
    );
}

#[test]
fn a_phone_test_file_that_names_a_row_and_declares_no_class_is_a_problem() {
    let root = tempfile::tempdir().expect("a directory");
    let kotlin = "apps/companion/native/android/src/test/kotlin/to/kala/reach/companion/mobile/VoiceCaptureGateTest.kt";
    let target = root.path().join(kotlin);
    std::fs::create_dir_all(target.parent().expect("a directory")).expect("directories");
    let text = std::fs::read_to_string(fixtures().join("lanes").join(kotlin)).expect("the fixture");
    let text = text.replace(
        "class VoiceCaptureGateTest {",
        "object VoiceCaptureGateTest {",
    );
    std::fs::write(&target, text).expect("a file");
    let map = map_of(root.path());
    assert!(
        map.keys
            .values()
            .flat_map(|places| places.keys())
            .any(|place| matches!(place, Place::Lane { file, .. } if file == kotlin))
    );
    let own: Vec<&String> = map
        .problems
        .iter()
        .filter(|problem| problem.starts_with(kotlin))
        .collect();
    assert_eq!(own.len(), 1, "{:?}", map.problems);
    assert!(own[0].contains("declares no class"), "{:?}", map.problems);
}

#[test]
fn every_phone_test_file_of_the_repository_that_names_a_row_declares_the_class_of_its_tests() {
    let map = map_of(&repository());
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    let keyed: Vec<&String> = map
        .keys
        .values()
        .flat_map(|places| places.keys())
        .filter_map(|place| match place {
            Place::Lane { file, .. } => Some(file),
            _ => None,
        })
        .collect();
    assert!(!keyed.is_empty());
    for file in keyed {
        assert!(
            map.lane_classes
                .get(file)
                .is_some_and(|classes| !classes.is_empty()),
            "{file} declares no class"
        );
    }
}
