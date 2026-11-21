//! The report over trees of its own, whose every key and every outcome is known in advance.
//!
//! Each tree under `tests/fixtures/` is a Cargo workspace of its own, so the repository's
//! workspace never builds it: `forms` keys rows in every form the report reads, ignores nothing
//! and has a documentation test, `outcomes` has a test that passes, one that fails and ones that
//! are ignored or panic as they should, `interleaved` has a test that leaves half a line on the
//! standard error, `known` has a test that records a known difference, `refused` names a row past the
//! end of section 21's table and a bare section, `expansions`, which is read and never built,
//! calls cases through macros and attributes the report cannot see into, and `conventions`, read
//! and never built as well, steps outside the conventions a helper key relies on, and `late`, whose
//! macro writes a file while its library compiles (its package `racy` has two test programs that
//! do, its package `shared` a library and two test programs that do), and `several`, three
//! libraries whose first test program fails to be listed. The runs build into a target directory
//! of their own under the platform's temporary directory.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use kr_conformance::id::{Identifier, Refusal};
use kr_conformance::libtest::{Binary, Outcome as LibtestOutcome};
use kr_conformance::map::Key;
use kr_conformance::map::{self, Binding, Declarations, Map, Place, TypeScriptRead};
use kr_conformance::plan::{self, Platform, Reading, Step};
use kr_conformance::plan_file::{IgnoredRun, Plan, Runs, TerminalProfileFile, Values};
use kr_conformance::report::{self, Document, Gathered, Options, Outcome, Stopped, Verdict};
use kr_conformance::run::Executed;
use kr_conformance::workspace::{Package, Target, TargetId, TargetKind};

fn tree(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// The program Cargo runs each test binary through while a step's tests are listed.
fn lister() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kr-conformance"))
}

fn identifier(text: &str) -> Identifier {
    text.parse().expect("an identifier")
}

/// The directory whose installed compiler reads the TypeScript of the fixtures, which have no
/// `node_modules` of their own.
fn compiler_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("apps")
        .join("companion")
}

fn map_of(name: &str, typescript: bool) -> Map {
    let directories = vec![".".to_owned()];
    let compiler = compiler_directory();
    map::build(
        &tree(name),
        &Declarations {
            case_tables: &[],
            lanes: &[],
            manifests: &["Cargo.toml".to_owned()],
            ignored_runs: None,
            plan_commands: &[],
            typescript: typescript.then_some(TypeScriptRead {
                packages: directories.as_slice(),
                skip_directories: &[],
                compiler_from: &[],
                compiler: Some(&compiler),
            }),
            scripts: &[],
            lane_directories: &[],
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
    run_step(name, &["test", "--locked", "--workspace", "--no-fail-fast"])
}

/// Runs the report over `name` with one `cargo` command as the only step.
fn run_step(name: &str, arguments: &[&str]) -> Result<(Document, tempfile::TempDir), Stopped> {
    run_step_through(name, arguments, lister())
}

/// Runs the report over `name` with one `cargo` command as the only step, `lister` being the
/// program Cargo runs each test binary through.
fn run_step_through(
    name: &str,
    arguments: &[&str],
    lister: PathBuf,
) -> Result<(Document, tempfile::TempDir), Stopped> {
    let plan = Plan::of_steps(
        "rust",
        vec![Step::cargo("rust", "the tree's tests", arguments)],
    );
    run_plan_through(name, plan, lister)
}

/// Runs the report over `name` with `plan`, `lister` being the program Cargo runs each test binary
/// through.
fn run_plan_through(
    name: &str,
    plan: Plan,
    lister: PathBuf,
) -> Result<(Document, tempfile::TempDir), Stopped> {
    let evidence = tempfile::Builder::new()
        .prefix("kr-conformance-evidence.")
        .tempdir()
        .expect("an evidence directory");
    let target = std::env::temp_dir().join(format!("kr-conformance-fixture-target-{name}"));
    let base = tempfile::tempdir().expect("a directory for the copy");
    let options = Options {
        root: tree(name),
        evidence: kr_conformance::evidence::check_directory(evidence.path())
            .expect("inside the temporary directory"),
        selection: Some(vec!["rust".to_owned()]),
        all_terminals: false,
        platform: Platform::current(),
        typescript_compiler: None,
        applications: None,
        plan,
        lister,
        environment: vec![(
            "CARGO_TARGET_DIR".to_owned(),
            target.to_string_lossy().into_owned(),
        )],
        part: None,
        runner_base: base.path().to_path_buf(),
    };
    report::run(&options, &mut |_| {}).map(|document| (document, evidence))
}

/// KR-REQ-29.01, the part about reproducible commands and the identity of a run: the terminal
/// profile of a result is read from the file the plan names, relative to the tested root, and a
/// file that holds no profile gives `unknown`. A file that is not there never gets this far: the
/// loader refuses the plan.
#[test]
fn the_terminal_profile_of_a_result_is_what_the_file_the_plan_names_holds() {
    let step = || {
        vec![Step::cargo(
            "rust",
            "the tree's tests",
            &["test", "--locked"],
        )]
    };
    for (path, profile, term) in [
        ("profile.json", "xterm-test/1", "xterm-256color"),
        ("Cargo.toml", "unknown", "unknown"),
    ] {
        let plan = Plan {
            terminal_profile: Some(TerminalProfileFile {
                path: path.to_owned(),
            }),
            ..Plan::of_steps("rust", step())
        };
        let (document, _evidence) = run_plan_through("forms", plan, lister())
            .unwrap_or_else(|stopped| panic!("{stopped:?}"));
        let recorded = document
            .run
            .terminal_profile
            .expect("the plan names a file");
        assert_eq!(
            (recorded.profile.as_str(), recorded.term.as_str()),
            (profile, term)
        );
    }
}

/// KR-REQ-29.01, the part about mapping tests to acceptance identifiers: a key written in each
/// comment form the report reads, and in a case table, maps the tests it covers to the identifier it
/// names, and nothing else is keyed. Not shown here: which identifiers a contract or schema change
/// affects.
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
    expect(
        "KR-REQ-03.01",
        &[
            ("flow commented", Binding::AttachedComment),
            ("flow ::*", Binding::ModuleComment),
        ],
    );
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
        &[
            (
                "flow calls_a_case_its_module_brings_up",
                Binding::CalledFunction,
            ),
            ("flow calls_the_shared_case", Binding::CalledFunction),
            (
                "flow other::calls_the_shared_case_by_its_path",
                Binding::CalledFunction,
            ),
        ],
    );
    assert_eq!(keyed.len(), 10, "and nothing else: {keyed:?}");
}

#[test]
fn a_call_a_macro_or_attribute_may_rewrite_move_or_rename_keys_nothing() {
    // The tree is read and never built: the macros and crates its tests name are not there. It
    // keeps to the conventions a helper key relies on, so the reading declines these keys itself.
    let map = map_of("expansions", false);
    assert!(map.refused.is_empty(), "{:?}", map.refused);
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    for (row, context) in [
        ("KR-REQ-03.11", "which no test is proved to call"),
        ("KR-REQ-03.16", "which no test is proved to call"),
        ("KR-REQ-03.17", "which an attribute may rewrite"),
        ("KR-REQ-03.18", "which an attribute may rewrite"),
        ("KR-REQ-03.19", "which no test is proved to call"),
        ("KR-REQ-03.26", "which an attribute may rewrite"),
        ("KR-REQ-03.27", "which an attribute may rewrite"),
        ("KR-REQ-03.29", "which no test is proved to call"),
        ("KR-REQ-03.30", "which a cfg may leave out of a build"),
        ("KR-REQ-03.32", "which no test is proved to call"),
        ("KR-REQ-03.33", "which a cfg may leave out of a build"),
        ("KR-REQ-03.36", "which a cfg may leave out of a build"),
        ("KR-REQ-03.38", "which no test is proved to call"),
        ("KR-REQ-03.42", "which no test is proved to call"),
        ("KR-REQ-03.43", "which no test is proved to call"),
        ("KR-REQ-03.44", "which a cfg may leave out of a build"),
        ("KR-REQ-03.68", "which no test is proved to call"),
    ] {
        let row = identifier(row);
        assert!(
            !map.keys.contains_key(&row),
            "{row}: {:?}",
            map.keys.get(&row)
        );
        assert!(
            map.references.get(&row).is_some_and(|references| references
                .iter()
                .any(|reference| reference.context.contains(context))),
            "{row}: {:?}",
            map.references.get(&row)
        );
    }
    let keyed = keyed(&map);
    assert_eq!(
        keyed.get("KR-REQ-03.14"),
        Some(&vec![(
            "flow calls_the_case_plainly".to_owned(),
            Binding::CalledFunction
        )])
    );
    // One name in two modules names two tests, each keyed by its own comment.
    assert_eq!(
        keyed.get("KR-REQ-03.57"),
        Some(&vec![(
            "samename first::example".to_owned(),
            Binding::AttachedComment
        )])
    );
    assert_eq!(
        keyed.get("KR-REQ-03.58"),
        Some(&vec![(
            "samename second::example".to_owned(),
            Binding::AttachedComment
        )])
    );
    // A `use` written as text imports nothing, so it leaves the rest of its target proved.
    assert_eq!(
        keyed.get("KR-REQ-03.31"),
        Some(&vec![
            (
                "strings calls_the_case_beside_text".to_owned(),
                Binding::CalledFunction
            ),
            (
                "strings prints_and_calls_the_case".to_owned(),
                Binding::CalledFunction
            ),
        ])
    );
}

/// The problems a map found, each matched to one expected `(file:line, words)`; none is left over.
fn expect_problems(map: &Map, expected: &[(&str, &str)]) {
    let mut unmatched: Vec<&String> = map.problems.iter().collect();
    for (at, words) in expected {
        let found = unmatched
            .iter()
            .position(|problem| problem.starts_with(&format!("{at}: ")) && problem.contains(words));
        match found {
            Some(index) => {
                unmatched.remove(index);
            }
            None => panic!(
                "no problem at {at} saying {words:?} among {:#?}",
                map.problems
            ),
        }
    }
    assert!(
        unmatched.is_empty(),
        "problems not expected: {unmatched:#?}"
    );
}

#[test]
fn a_source_outside_the_conventions_is_a_problem_and_keys_no_helper() {
    // The tree is read and never built. Each target steps outside the conventions a helper key
    // relies on, as the compiler would build it: the report names the file and the line, and the
    // helpers of that target key nothing.
    let map = map_of("conventions", false);
    assert!(map.refused.is_empty(), "{:?}", map.refused);
    let helper = "a keyed helper's name, is written here as";
    expect_problems(
        &map,
        &[
            ("tests/absent.rs:3", "module missing has no file"),
            (
                "tests/absolute.rs:8",
                "a `use` of `shared`, a keyed helper's name, that the reading does not follow",
            ),
            (
                "tests/braced.rs:16",
                "the header of this `fn`, from its keyword to its body or `;`, holds where a macro's repetition opens or ends",
            ),
            (
                "tests/braced.rs:22",
                "the header of this `fn`, from its keyword to its body or `;`, holds where a macro's repetition opens or ends",
            ),
            (
                "tests/carrier/mod.rs:1",
                "a `path` attribute inside a module's own file",
            ),
            (
                "tests/aliased.rs:3",
                "`println` is declared here as the name `as` gives",
            ),
            ("tests/chosen.rs:4", "a `cfg_attr` chooses"),
            (
                "tests/escaped.rs:4",
                "a `path` attribute whose value is anything but a string of printable ASCII",
            ),
            ("tests/innerchosen.rs:3", "a `cfg_attr` chooses"),
            (
                "tests/elsewhere/deep.rs:2",
                "`assert_eq` is declared here as a macro",
            ),
            (
                "tests/emitcore.rs:13",
                "`core` is declared here as a module",
            ),
            (
                "tests/emitcore.rs:14",
                "`println` is declared here as the name `as` gives",
            ),
            (
                "tests/emitted.rs:11",
                "`println` is declared here as a macro",
            ),
            (
                "tests/emitted.rs:11",
                "`shared`, a keyed helper's name, is written here as a function inside",
            ),
            (
                "tests/exported.rs:14",
                "`println` is declared here as a macro",
            ),
            (
                "tests/exported.rs:16",
                "`case`, a keyed helper's name, is written here as a function inside",
            ),
            (
                "tests/exported.rs:31",
                "`assert_eq` is declared here as a macro",
            ),
            (
                "tests/exported.rs:33",
                "`other_case`, a keyed helper's name, is written here as a function inside",
            ),
            (
                "tests/flow.rs:3",
                "`Clone` is declared here as a `use` of something other",
            ),
            ("tests/flow.rs:12", helper),
            ("tests/flow.rs:26", helper),
            ("tests/flow.rs:41", helper),
            ("tests/gapped.rs:3", "`println` is declared here as a macro"),
            ("tests/gapped.rs:5", helper),
            (
                "tests/hidden.rs:6",
                "a module file declared inside a function",
            ),
            (
                "tests/identity.rs:3",
                "`assert` is declared here as a macro",
            ),
            (
                "tests/identity.rs:13",
                "`core` is declared here as a module",
            ),
            (
                "tests/identity.rs:16",
                "`println` is declared here as a macro",
            ),
            ("tests/identity.rs:17", helper),
            (
                "tests/imported.rs:4",
                "a `use` of `shared`, a keyed helper's name, that the reading does not follow",
            ),
            ("tests/inner.rs:9", "a function inside a function"),
            (
                "tests/inline/declared.rs:2",
                "`assert_eq` is declared here as a macro",
            ),
            (
                "tests/loaded/neighbour.rs:2",
                "`assert_eq` is declared here as a macro",
            ),
            (
                "tests/marked/mod.rs:1",
                "a first line that starts `#!` without `[` right after it",
            ),
            (
                "tests/marked/mod.rs:1",
                "is a character outside ASCII outside a comment or a literal",
            ),
            (
                "tests/moved/sub.rs:2",
                "`println` is declared here as a macro",
            ),
            (
                "tests/pages/mod.rs:1",
                "a `path` attribute inside a module's own file",
            ),
            (
                "tests/pages/mod.rs:1",
                "a first line that starts `#!` without `[` right after it",
            ),
            (
                "tests/localcore.rs:3",
                "`core` is declared here as a module",
            ),
            ("tests/localcore.rs:6", helper),
            (
                "tests/localcore.rs:10",
                "`println` is declared here as the name `as` gives",
            ),
            (
                "tests/qualified.rs:9",
                "the keyed helper `Fn` has the name of a trait a type writes like a call",
            ),
            ("tests/raw.rs:5", helper),
            (
                "tests/renamed.rs:4",
                "`shared`, a keyed helper's name, is written here as the name `as` gives",
            ),
            (
                "tests/repeated.rs:9",
                "the header of this `fn`, from its keyword to its body or `;`, holds where a macro's repetition opens or ends",
            ),
            (
                "tests/repeated.rs:9",
                "`core` is written here in a macro whose metavariables or repetitions may make it a declaration",
            ),
            (
                "tests/repeated.rs:15",
                "the header of this `enum`, from its keyword to its body or `;`, holds where a macro's repetition opens or ends",
            ),
            (
                "tests/repeated.rs:15",
                "`shared`, a keyed helper's name, is written here as part of a macro whose metavariables or repetitions",
            ),
            (
                "tests/rewritten.rs:11",
                "`core` is written here in a macro whose metavariables or repetitions may make it a declaration",
            ),
            (
                "tests/rewritten.rs:17",
                "`len`, a keyed helper's name, is written here as part of a macro whose metavariables or repetitions",
            ),
            (
                "tests/rewritten.rs:23",
                "`len`, a keyed helper's name, is written here as part of a macro whose metavariables or repetitions",
            ),
            (
                "tests/rewritten.rs:57",
                "`core` is written here in a macro whose metavariables or repetitions may make it a declaration",
            ),
            (
                "tests/shadowed.rs:8",
                "`println` is declared here as a macro",
            ),
            ("tests/shadowed.rs:10", helper),
            (
                "tests/sugar.rs:5",
                "the keyed helper `Fn` has the name of a trait a type writes like a call",
            ),
            ("tests/taken.rs:8", "a constant or a static"),
            (
                "tests/taken.rs:19",
                "`imported`, a keyed helper's name, is written here as the name `as` gives",
            ),
            ("tests/taken.rs:23", "a trait in a type"),
            ("tests/text.rs:10", "`println` is declared here as a macro"),
            (
                "tests/tools.rs:3",
                "`clippy` is declared here as the name `as` gives",
            ),
            ("tests/traits.rs:10", "a type or a trait"),
            (
                "tests/twice.rs:6",
                "defines the test `example` more than once (tests/twice.rs:6, tests/twice.rs:11)",
            ),
            ("tests/unicode.rs:12", "is an identifier outside ASCII"),
            (
                "tests/variants.rs:8",
                "defines the test `example` more than once (tests/variants.rs:8, tests/variants.rs:14)",
            ),
            ("vintage/tests/old.rs:1", "the 2015 edition"),
        ],
    );
    assert!(
        map.keys
            .values()
            .flat_map(BTreeMap::values)
            .all(|key| key.binding != Binding::CalledFunction),
        "{:?}",
        keyed(&map)
    );
    for row in [
        "KR-REQ-03.12",
        "KR-REQ-03.13",
        "KR-REQ-03.15",
        "KR-REQ-03.20",
        "KR-REQ-03.21",
        "KR-REQ-03.22",
        "KR-REQ-03.23",
        "KR-REQ-03.24",
        "KR-REQ-03.25",
        "KR-REQ-03.28",
        "KR-REQ-03.34",
        "KR-REQ-03.35",
        "KR-REQ-03.37",
        "KR-REQ-03.39",
        "KR-REQ-03.40",
        "KR-REQ-03.41",
        "KR-REQ-03.45",
        "KR-REQ-03.46",
        "KR-REQ-03.47",
        "KR-REQ-03.48",
        "KR-REQ-03.49",
        "KR-REQ-03.50",
        "KR-REQ-03.51",
        "KR-REQ-03.52",
        "KR-REQ-03.53",
        "KR-REQ-03.54",
        "KR-REQ-03.59",
        "KR-REQ-03.60",
        "KR-REQ-03.61",
        "KR-REQ-03.62",
        "KR-REQ-03.63",
        "KR-REQ-03.64",
        "KR-REQ-03.65",
        "KR-REQ-03.66",
        "KR-REQ-03.67",
        "KR-REQ-03.69",
        "KR-REQ-03.70",
        "KR-REQ-03.71",
        "KR-REQ-03.72",
        "KR-REQ-03.73",
        "KR-REQ-03.74",
    ] {
        let row = identifier(row);
        assert!(
            map.references
                .get(&row)
                .is_some_and(|references| references.iter().all(|reference| reference
                    .context
                    .contains("steps outside the conventions a helper key relies on"))),
            "{row}: {:?}",
            map.references.get(&row)
        );
    }
}

#[test]
fn a_test_record_takes_its_command_and_what_it_needs_from_the_same_run() {
    // On Windows the client's whole library lists the credential store's case as ignored, and
    // the step that runs it with `--ignored` reads the switch that lets it write the store: the
    // record's command is that step's, so what the command needs is that step's as well.
    let name = "sync::keys::tests::a_key_kept_in_the_platform_store_is_read_back_from_it_and_taken_away_again";
    let target = TargetId {
        package: "kr-client".to_owned(),
        kind: TargetKind::Lib,
        name: "kr_client".to_owned(),
    };
    let row = identifier("KR-REQ-29.01");
    let mut map = Map {
        packages: vec![package_of(
            "kr-client",
            ".",
            &[(TargetKind::Lib, "kr_client", true)],
        )],
        ..Map::default()
    };
    map.keys.entry(row).or_default().insert(
        Place::Rust {
            target: target.clone(),
            name: name.to_owned(),
        },
        Key {
            binding: Binding::AttachedComment,
            source: "crates/kr-client/src/sync/keys.rs:698".to_owned(),
        },
    );
    let steps = core_plan().steps(
        Platform::Windows,
        &rust_group(),
        &Values::evidence("/tmp/e"),
        None,
    );
    let whole = steps
        .iter()
        .find(|step| step.what == "the client's stores and their directory flush")
        .expect("the client's library")
        .clone();
    let switched = steps
        .iter()
        .find(|step| step.command.iter().any(|word| word == name))
        .expect("the credential store's case")
        .clone();
    assert_eq!(switched.needs, [plan::SECRET_STORE_VARIABLE.to_owned()]);
    let executed = |step: Step, outcome: LibtestOutcome| Executed {
        step,
        exit: Some(0),
        seconds: 0,
        log: "conformance/logs/x.log".to_owned(),
        binaries: vec![(
            Some(target.clone()),
            Binary {
                executable: "kr_client-0.exe".to_owned(),
                source: "src/lib.rs".to_owned(),
                tests: [(name.to_owned(), outcome)].into(),
                ..Binary::default()
            },
        )],
        built: vec![target.clone()],
        listed: [(target.clone(), [name.to_owned()].into())].into(),
        vitest: None,
        lane: None,
        tools: Vec::new(),
        error: None,
        blocked: None,
        observation: None,
        timed_out: false,
    };
    let options = Options {
        root: PathBuf::from("/tmp/r"),
        evidence: PathBuf::from("/tmp/e"),
        selection: Some(vec!["rust".to_owned()]),
        all_terminals: false,
        platform: Platform::Windows,
        plan: core_plan(),
        typescript_compiler: None,
        applications: None,
        lister: PathBuf::from("/tmp/l"),
        environment: Vec::new(),
        part: None,
        runner_base: PathBuf::new(),
    };
    let document = report::assemble(
        &options,
        &rust_group(),
        &map,
        &[
            executed(whole, LibtestOutcome::Ignored(None)),
            executed(switched, LibtestOutcome::Passed),
        ],
        Gathered::default(),
        "2026-09-26T00:00:00Z".to_owned(),
    );
    let record = &document.identifiers["KR-REQ-29.01"].tests[0];
    assert_eq!(record.outcome, Outcome::Passed);
    assert!(
        record
            .command
            .as_deref()
            .is_some_and(|command| command.contains("--ignored")),
        "{record:?}"
    );
    assert_eq!(record.needs, [plan::SECRET_STORE_VARIABLE], "{record:?}");
}

/// KR-REQ-29.01, the part about machine-readable results, on Windows: a TypeScript test that a run
/// selects with `--group typescript` is recorded as not run, with the reason that the suites are
/// qualified on Linux and macOS, because no step of the Windows plan reads it.
#[test]
fn a_typescript_test_that_a_windows_run_selects_is_not_run_and_says_where_it_is_qualified() {
    let row = identifier("KR-REQ-29.01");
    let mut map = Map::default();
    map.keys.entry(row).or_default().insert(
        Place::TypeScript {
            package: "packages/protocol".to_owned(),
            file: "packages/protocol/src/a.test.ts".to_owned(),
            line: 3,
            title: "a title".to_owned(),
        },
        Key {
            binding: Binding::Title,
            source: "packages/protocol/src/a.test.ts:3".to_owned(),
        },
    );
    let groups = vec!["typescript".to_owned()];
    let options = Options {
        root: PathBuf::from("/tmp/r"),
        evidence: PathBuf::from("/tmp/e"),
        selection: Some(groups.clone()),
        all_terminals: false,
        platform: Platform::Windows,
        plan: core_plan(),
        typescript_compiler: None,
        applications: None,
        lister: PathBuf::from("/tmp/l"),
        environment: Vec::new(),
        part: None,
        runner_base: PathBuf::new(),
    };
    let document = report::assemble(
        &options,
        &groups,
        &map,
        &[],
        Gathered::default(),
        "2026-09-26T00:00:00Z".to_owned(),
    );
    let record = &document.identifiers["KR-REQ-29.01"].tests[0];
    assert_eq!(record.outcome, Outcome::NotRun, "{record:?}");
    assert_eq!(
        record.reason.as_deref(),
        Some("the TypeScript suites are qualified on Linux and macOS"),
        "{record:?}"
    );
}

/// KR-REQ-29.01, the part about results mapped to acceptance IDs with reproducible commands: a
/// TypeScript test whose package's step was not run because a set-up step failed is not run, with
/// the set-up step's number, and is not failed; the same test, its step run and reporting it, is
/// passed.
#[test]
fn a_typescript_test_whose_step_was_not_run_for_a_set_up_step_is_not_run_with_its_number() {
    let package = "apps/companion";
    let file = "apps/companion/src/forms.test.ts";
    let mut map = Map::default();
    map.keys
        .entry(identifier("KR-REQ-29.01"))
        .or_default()
        .insert(
            Place::TypeScript {
                package: package.to_owned(),
                file: file.to_owned(),
                line: 7,
                title: "keeps its title".to_owned(),
            },
            Key {
                binding: Binding::Title,
                source: format!("{file}:7"),
            },
        );
    let groups = vec!["typescript".to_owned()];
    let step = core_plan()
        .steps(Platform::Linux, &groups, &Values::evidence("/tmp/e"), None)
        .into_iter()
        .find(|step| matches!(&step.reading, Reading::Vitest { directory } if directory == package))
        .expect("the companion's Vitest step");
    let options = Options {
        root: PathBuf::from("/tmp/r"),
        evidence: PathBuf::from("/tmp/e"),
        selection: Some(groups.clone()),
        all_terminals: false,
        platform: Platform::Linux,
        plan: core_plan(),
        typescript_compiler: None,
        applications: None,
        lister: PathBuf::from("/tmp/l"),
        environment: Vec::new(),
        part: None,
        runner_base: PathBuf::new(),
    };
    let assemble = |executed: Executed| {
        report::assemble(
            &options,
            &groups,
            &map,
            &[executed],
            Gathered::default(),
            "2026-11-20T00:00:00Z".to_owned(),
        )
    };
    let blocked = kr_conformance::run::not_run(&step, 4, "the set-up", "exited with status 1");
    let document = assemble(blocked.clone());
    let record = &document.identifiers["KR-REQ-29.01"];
    assert_eq!(record.verdict, Verdict::NotRun, "{record:?}");
    assert_eq!(record.counts.failed, 0, "{record:?}");
    let test = &record.tests[0];
    assert_eq!(test.outcome, Outcome::NotRun, "{test:?}");
    assert_eq!(
        test.reason.as_deref(),
        Some(
            "the step that runs the package's tests was not run because its set-up step 4 (the \
             set-up) exited with status 1"
        ),
        "{test:?}"
    );
    assert_eq!(test.runs.len(), 1, "{test:?}");
    assert_eq!(
        (test.runs[0].step, test.runs[0].outcome.clone()),
        (1, Outcome::NotRun)
    );
    // The same test with its step run and the test reported: passed.
    let mut ran = blocked;
    ran.error = None;
    ran.blocked = None;
    ran.exit = Some(0);
    ran.vitest = Some(
        [(
            (file.to_owned(), 7),
            vec![kr_conformance::vitest::Case {
                titles: vec!["keeps its title".to_owned()],
                outcome: LibtestOutcome::Passed,
            }],
        )]
        .into(),
    );
    let document = assemble(ran);
    let record = &document.identifiers["KR-REQ-29.01"];
    assert_eq!(record.verdict, Verdict::Passed, "{record:?}");
    assert_eq!(record.tests[0].outcome, Outcome::Passed, "{record:?}");
}

/// KR-REQ-29.01, the part about reproducible commands and the identity of a run: the version of the
/// compiler that read the map is in the result's toolchain, as the document and as JSON, and the
/// field is left out when no TypeScript was read.
#[test]
fn the_result_records_the_compiler_version_the_map_was_read_with_and_leaves_it_out_when_none_read()
{
    let assembled = |version: Option<&str>| {
        let map = Map {
            typescript_version: version.map(str::to_owned),
            ..Map::default()
        };
        let groups = vec!["rust".to_owned()];
        let options = Options {
            root: PathBuf::from("/tmp/r"),
            evidence: PathBuf::from("/tmp/e"),
            selection: Some(groups.clone()),
            all_terminals: false,
            platform: Platform::Linux,
            plan: core_plan(),
            typescript_compiler: None,
            applications: None,
            lister: PathBuf::from("/tmp/l"),
            environment: Vec::new(),
            part: None,
            runner_base: PathBuf::new(),
        };
        let document = report::assemble(
            &options,
            &groups,
            &map,
            &[],
            Gathered::default(),
            "2026-09-26T00:00:00Z".to_owned(),
        );
        let json = serde_json::to_value(&document).expect("serialises");
        (document.run.toolchain.typescript, json)
    };
    let (version, json) = assembled(Some("9.9.9"));
    assert_eq!(version.as_deref(), Some("9.9.9"));
    assert_eq!(json["run"]["toolchain"]["typescript"], "9.9.9", "{json}");
    let (version, json) = assembled(None);
    assert_eq!(version, None);
    assert!(
        json["run"]["toolchain"].get("typescript").is_none(),
        "{json}"
    );
}

/// KR-REQ-29.01, the part about machine-readable results: a run over a tree that ignores nothing
/// reports every identifier it keys with a verdict and, for each test that keys it, the outcome; a
/// test keyed twice is recorded once, by its own comment.
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
    // The module comment of the test file keys every test in it, each by its own name, and a test
    // its own comment keys as well is recorded once, by that comment.
    let module = &document.identifiers["KR-REQ-03.01"].tests;
    assert_eq!(module.len(), 15);
    let commented: Vec<_> = module
        .iter()
        .filter(|test| test.test == "forms --test flow commented")
        .collect();
    assert_eq!(commented.len(), 1);
    assert_eq!(commented[0].keyed_by, Binding::AttachedComment);
    assert!(document.passed());
}

/// The map of the `outcomes` tree, held to `runs` for the keyed tests an ordinary run leaves out.
fn held_to(runs: &[IgnoredRun]) -> Map {
    map::build(
        &tree("outcomes"),
        &Declarations {
            case_tables: &[],
            lanes: &[],
            manifests: &["Cargo.toml".to_owned()],
            ignored_runs: Some(runs),
            plan_commands: &core_plan().linux_commands(),
            typescript: None,
            scripts: &[],
            lane_directories: &[],
        },
    )
}

/// The one step that runs the ignored tests of `outcomes`, which the tree's own manifest stands in
/// for: a file with a line `line`.
fn outcomes_run(line: &str) -> IgnoredRun {
    outcomes_entry(
        &[],
        Runs::Command {
            file: "Cargo.toml".to_owned(),
            line: line.to_owned(),
        },
    )
}

fn outcomes_entry(cases: &[&str], runs: Runs) -> IgnoredRun {
    IgnoredRun {
        package: "outcomes".to_owned(),
        target: "--lib".to_owned(),
        cases: cases.iter().map(|case| (*case).to_owned()).collect(),
        runs,
    }
}

#[test]
fn a_keyed_test_an_ordinary_run_leaves_out_and_no_step_runs_stops_the_map() {
    let unrun = held_to(&[]);
    assert_eq!(unrun.problems.len(), 1, "{:?}", unrun.problems);
    for name in [
        "tests::is_ignored",
        "tests::is_ignored_too",
        "tests::is_ignored_for_a_reason_over_two_lines",
    ] {
        assert!(
            unrun.problems[0].contains(name),
            "{name} is named: {:?}",
            unrun.problems
        );
    }
    assert!(
        !unrun.problems[0].contains("tests::passes"),
        "a test an ordinary run runs is not named: {:?}",
        unrun.problems
    );

    let run = held_to(&[outcomes_run("harness = false")]);
    assert!(run.problems.is_empty(), "{:?}", run.problems);
}

#[test]
fn a_step_that_lost_its_command_or_has_nothing_left_to_run_stops_the_map() {
    let gone = held_to(&[outcomes_run("--ignored")]);
    assert_eq!(gone.problems.len(), 1, "{:?}", gone.problems);
    assert!(
        gone.problems[0].contains("Cargo.toml holds no line `--ignored`"),
        "{:?}",
        gone.problems
    );

    let stale = held_to(&[
        outcomes_run("harness = false"),
        outcomes_entry(
            &["tests::passes"],
            Runs::Command {
                file: "Cargo.toml".to_owned(),
                line: "harness = false".to_owned(),
            },
        ),
    ]);
    assert_eq!(stale.problems.len(), 1, "{:?}", stale.problems);
    assert!(
        stale.problems[0].contains("tests::passes")
            && stale.problems[0].contains("no keyed ignored test needs"),
        "{:?}",
        stale.problems
    );
}

/// What `ignored::check` finds in a file `ci.sh` that holds `script`, for an entry whose line is
/// `line` (and whose tests a call passes, when `names_with` is given), covering the three ignored
/// tests of `outcomes`.
fn found_in(
    script: &str,
    line: &'static str,
    names_with: Option<&'static [&'static str]>,
) -> Vec<String> {
    found_in_file("ci.sh", script, line, names_with)
}

fn found_in_file(
    file: &'static str,
    script: &str,
    line: &'static str,
    names_with: Option<&'static [&'static str]>,
) -> Vec<String> {
    let map = held_to(&[]);
    let directory = tempfile::tempdir().expect("a directory");
    std::fs::write(directory.path().join(file), script).expect("the script");
    let runs = [outcomes_entry(
        &[],
        match names_with {
            None => Runs::Command {
                file: file.to_owned(),
                line: line.to_owned(),
            },
            Some(names_with) => Runs::Supplied {
                file: file.to_owned(),
                line: line.to_owned(),
                names_with: names_with.iter().map(|word| (*word).to_owned()).collect(),
            },
        },
    )];
    kr_conformance::ignored::check(&map, directory.path(), &runs, &[]).problems
}

const NAMES: &str =
    "tests::is_ignored tests::is_ignored_too tests::is_ignored_for_a_reason_over_two_lines";
const COMMAND: &str = "cargo test --lib -- --ignored --exact tests::is_ignored tests::is_ignored_too tests::is_ignored_for_a_reason_over_two_lines";

#[test]
fn a_command_is_the_line_the_entry_gives_and_nothing_else() {
    let ok = |script: String| {
        let found = found_in(&script, COMMAND, None);
        assert!(found.is_empty(), "{script}: {found:?}");
    };
    let refused = |script: String, said: &str| {
        let found = found_in(&script, COMMAND, None);
        assert_eq!(found.len(), 1, "{script}: {found:?}");
        assert!(found[0].contains(said), "{script}: {found:?}");
    };

    // The line as the entry gives it passes: alone, among other lines, continued over several
    // lines, with white space of another width, with a comment at its end.
    ok(COMMAND.to_owned());
    ok(format!("true\n{COMMAND}\ntrue"));
    ok(format!(
        "cargo test --lib -- --ignored --exact \\\n  {NAMES}"
    ));
    ok(format!(
        "cargo  test --lib   -- --ignored --exact\t{NAMES} # why"
    ));

    // A word added anywhere in the line, whatever it is, is a line the entry does not give: after
    // the names (a skip in either form, a listing, a build only, a filter, a second separator, a
    // quoted flag, a variable, a redirection that goes on, a brace, a process substitution) or
    // before or inside the command.
    for added in [
        "--skip tests::is_ignored_too",
        "--skip=tests::is_ignored_too",
        "\"--skip=tests::is_ignored_too\"",
        "--list",
        "--no-run",
        "--bench",
        "-h",
        "no_such_case",
        "--",
        "--logfile",
        "$extra",
        "--nocapture",
        "2>&1 --list",
        "&>/dev/null --skip tests::is_ignored_too",
        ">|out --list",
        "2>'x;y' --list",
        "} --list",
        ">(:) --list",
        "&& true",
        "| cat",
    ] {
        refused(format!("{COMMAND} {added}"), "holds no line");
    }
    for changed in [
        "cargo test --lib --config 'x' -- --ignored --exact",
        "cargo t --lib -- --ignored --exact",
        "cargo +stable test --lib -- --ignored --exact",
        "cargo test --lib -- --skip --ignored --exact",
        "cargo test --lib --ignored --exact",
        "cargo test --lib -- --ignored",
        "RUSTFLAGS=x cargo test --lib -- --ignored --exact",
        "timeout 1 cargo test --lib -- --ignored --exact",
        "true ! cargo test --lib -- --ignored --exact",
        "true if cargo test --lib -- --ignored --exact",
        "echo cargo test --lib -- --ignored --exact",
        "run: : cargo test --lib -- --ignored --exact",
        "{ cargo test --lib -- --ignored --exact }",
    ] {
        refused(format!("{changed} {NAMES}"), "holds no line");
    }

    // White space is the shell's: a space or a tab. A no-break space, an em space, a vertical tab or
    // a carriage return is part of a word, and a `#` after one is not a comment.
    for separator in ['\u{a0}', '\u{2003}', '\u{b}', '\r'] {
        refused(
            format!("cargo test --lib -- --ignored{separator}--exact {NAMES}"),
            "holds no line",
        );
        refused(format!("{COMMAND}{separator}"), "holds no line");
        refused(format!("{COMMAND} {separator}# why"), "holds no line");
    }
    ok(format!("{COMMAND}\t# why"));

    // A backslash and the new line after it are taken out and nothing is put in their place, so
    // two names with no white space beside the join are one word, as the shell has them.
    refused(
        "cargo test --lib -- --ignored --exact tests::is_ignored\\\ntests::is_ignored_too \
         tests::is_ignored_for_a_reason_over_two_lines"
            .to_owned(),
        "holds no line",
    );
    ok("cargo test --lib -- --ignored --exact tests::is_ignored \\\n  tests::is_ignored_too \\\n  \
        tests::is_ignored_for_a_reason_over_two_lines"
        .to_owned());

    // In a workflow, an entry whose own line is a `run:` field (`run:` or `- run:`) is a plain
    // scalar, where a backslash is not a continuation. A `run:` line that continues another line
    // is not a field.
    for prefix in ["run:", "- run:"] {
        let entry: &'static str = Box::leak(format!("{prefix} {COMMAND}").into_boxed_str());
        let found = found_in_file("ci.yml", &format!("{entry}\n"), entry, None);
        assert!(found.is_empty(), "{found:?}");
        let split = format!("{prefix} cargo test --lib -- --ignored \\\n  --exact {NAMES}");
        let found = found_in_file("ci.yml", &split, entry, None);
        assert_eq!(found.len(), 1, "{found:?}");
        let continued = format!("echo \\\n{entry}\n");
        let found = found_in_file("ci.yml", &continued, entry, None);
        assert_eq!(
            found.len(),
            1,
            "{prefix} after a continuing line: {found:?}"
        );
    }
    // Any other entry's line follows the shell, in a script and in a workflow alike: a line that
    // ends in a backslash joins the next one, whatever words it holds, `run:` among them.
    for file in ["ci.sh", "ci.yml"] {
        for before in [
            "echo run: \\",
            ": run: \\",
            "echo - run: \\",
            "run: \\",
            "- run: \\",
            "echo \\\nrun: \\",
            "echo \\\n- run: \\",
            ": \\\nrun: \\",
        ] {
            let found = found_in_file(file, &format!("{before}\n{COMMAND}\n"), COMMAND, None);
            assert_eq!(found.len(), 1, "{file} {before}: {found:?}");
            assert!(
                found[0].contains("holds no line"),
                "{file} {before}: {found:?}"
            );
        }
    }
    // A reader may end a line at a carriage return, a next line, a line or paragraph separator, a
    // vertical tab or a form feed where the shell does not (a YAML parser, a CR LF file), and bash
    // drops a NUL, so that `\`, a NUL and a new line are one continuation. A line that holds one is
    // never taken alone: it joins the next, and no command that holds one is a line the map matches.
    for file in ["ci.sh", "ci.yml"] {
        for end in [
            '\0', '\r', '\u{85}', '\u{2028}', '\u{2029}', '\u{b}', '\u{c}',
        ] {
            let found = found_in_file(file, &format!("echo \\{end}\n{COMMAND}\n"), COMMAND, None);
            assert_eq!(found.len(), 1, "{file} {end:?}: {found:?}");
        }
        let found = found_in_file(file, &format!("echo \\\r\n{COMMAND}\r\n"), COMMAND, None);
        assert_eq!(found.len(), 1, "{file} CR LF: {found:?}");
    }

    // A comment, and the words of two lines, are not the line.
    refused(format!("# {COMMAND}"), "holds no line");
    refused(
        format!("cargo test --lib \\\n  # -- --ignored --exact {NAMES}"),
        "holds no line",
    );
    refused(
        format!("cargo test --lib\n-- --ignored --exact {NAMES}"),
        "holds no line",
    );
    // The line it is nearest to is shown.
    refused(
        format!("{COMMAND} --list"),
        "the nearest line is `cargo test --lib -- --ignored --exact",
    );
}

#[test]
fn a_command_that_selects_by_name_names_every_test_the_entry_covers() {
    // The entry's own line leaves a test out: the table is wrong, and the map says so.
    let found = |line: &'static str| found_in(line, line, None);
    let one = found("cargo test --lib -- --ignored --exact tests::is_ignored");
    assert_eq!(one.len(), 1, "{one:?}");
    assert!(
        one[0].contains("does not name tests::is_ignored_for_a_reason_over_two_lines"),
        "{one:?}"
    );
    assert!(found(COMMAND).is_empty());

    // A line of the entry that skips a covered test, or only lists or builds, is the table's error.
    for (line, said) in [
        (
            "cargo test --lib -- --ignored --exact tests::is_ignored tests::is_ignored_too tests::is_ignored_for_a_reason_over_two_lines --skip tests::is_ignored_too",
            "skips tests::is_ignored_too",
        ),
        (
            "cargo test --lib -- --ignored --exact tests::is_ignored tests::is_ignored_too tests::is_ignored_for_a_reason_over_two_lines --skip=tests::is_ignored_too",
            "skips tests::is_ignored_too",
        ),
        (
            "cargo test --lib -- --ignored --list",
            "does not run the tests",
        ),
        (
            "cargo test --lib --no-run -- --ignored",
            "does not run the tests",
        ),
    ] {
        let wrong = found(line);
        assert_eq!(wrong.len(), 1, "{line}: {wrong:?}");
        assert!(wrong[0].contains(said), "{line}: {wrong:?}");
    }
}

#[test]
fn a_command_whose_names_a_call_passes_finds_them_on_the_calls() {
    const PASSING: &str = "cargo test --lib -- --ignored --exact \"$1\"";
    let found = |script: &str| found_in(script, PASSING, Some(&["call"]));
    let calls = format!(
        "{PASSING}\ncall tests::is_ignored\ncall tests::is_ignored_too\ncall tests::is_ignored_for_a_reason_over_two_lines"
    );
    assert!(found(&calls).is_empty(), "{:?}", found(&calls));

    // A line that has the call's words, but does not begin with them, names nothing.
    for line in [
        "echo call tests::is_ignored_too",
        "fail \"call tests::is_ignored_too did not run\"",
        "# call tests::is_ignored_too",
    ] {
        let script = format!(
            "{PASSING}\ncall tests::is_ignored\n{line}\ncall tests::is_ignored_for_a_reason_over_two_lines"
        );
        let wrong = found(&script);
        assert_eq!(wrong.len(), 1, "{line}: {wrong:?}");
        assert!(
            wrong[0].contains("does not name tests::is_ignored_too"),
            "{line}: {wrong:?}"
        );
    }

    // A line that holds a character the shell does not read as the map does (a carriage return, a
    // NUL) joins the next line, and no name is found on a command that holds one: the name on the
    // next line is the argument of another command.
    for unread in ['\r', '\0', '\u{2028}'] {
        for line in [
            format!("echo {unread}\ntests::is_ignored_too"),
            format!("call tests::is_ignored {unread}\necho tests::is_ignored_too"),
            format!("call tests::is_ignored {unread}\n# tests::is_ignored_too"),
        ] {
            let script = format!(
                "{PASSING}\ncall tests::is_ignored\n{line}\ncall tests::is_ignored_for_a_reason_over_two_lines"
            );
            let wrong = found(&script);
            assert_eq!(wrong.len(), 1, "{line:?}: {wrong:?}");
            assert!(
                wrong[0].contains("does not name tests::is_ignored_too"),
                "{line:?}: {wrong:?}"
            );
        }
    }

    // The command itself is still the line the entry gives and nothing else.
    let narrowed = calls.replace(PASSING, &format!("{PASSING} --skip x"));
    assert_eq!(found(&narrowed).len(), 1, "{:?}", found(&narrowed));
}

#[test]
fn a_step_of_the_report_is_found_in_the_plan_and_a_step_nothing_runs_is_shown() {
    // A step of the report's own plan is found in the plan, with exactly its words.
    let plan = |line: &str| {
        outcomes_entry(
            &[],
            Runs::Plan {
                line: line.to_owned(),
            },
        )
    };
    let applications = "cargo test --locked -p kr-conformance --test applications -- --ignored --test-threads=1 --show-output";
    let found = held_to(&[plan(applications)]);
    assert!(found.problems.is_empty(), "{:?}", found.problems);
    let absent = held_to(&[plan("cargo test --test no_such_target")]);
    assert_eq!(absent.problems.len(), 1, "{:?}", absent.problems);
    let shorter = held_to(&[plan(
        "cargo test --locked -p kr-conformance --test applications -- --ignored",
    )]);
    assert_eq!(shorter.problems.len(), 1, "{:?}", shorter.problems);

    // Tests run by hand and tests nothing runs are shown, and are not problems.
    let by_hand = held_to(&[outcomes_entry(
        &[],
        Runs::ByHand {
            why: "a person does".to_owned(),
        },
    )]);
    assert!(
        by_hand.problems.is_empty()
            && by_hand
                .warnings
                .iter()
                .any(|w| w.contains("run by hand: a person does"))
    );
    let nowhere = held_to(&[outcomes_entry(
        &[],
        Runs::Nowhere {
            why: "it cannot yet".to_owned(),
        },
    )]);
    assert!(
        nowhere.problems.is_empty()
            && nowhere
                .warnings
                .iter()
                .any(|w| w.contains("run by nothing: it cannot yet"))
    );
}

#[test]
fn a_helper_is_named_beside_the_flags_that_ask_for_it() {
    let helper = |file: &str| {
        outcomes_entry(
            &["tests::"],
            Runs::Helper {
                file: file.to_owned(),
            },
        )
    };
    assert!(held_to(&[helper("spawns.txt")]).problems.is_empty());
    // The flags of another spawn, far from the helper's name, do not stand for its own.
    let far = held_to(&[helper("spawns_far.txt")]);
    assert_eq!(far.problems.len(), 1, "{:?}", far.problems);
    assert!(
        far.problems[0].contains("starts tests::is_ignored without"),
        "{:?}",
        far.problems
    );
    // Every start of a helper needs its own flags, not only one of them.
    let one = |file: &str| {
        [
            outcomes_entry(
                &["tests::is_ignored"],
                Runs::Helper {
                    file: file.to_owned(),
                },
            ),
            outcomes_entry(
                &[
                    "tests::is_ignored_too",
                    "tests::is_ignored_for_a_reason_over_two_lines",
                ],
                Runs::ByHand {
                    why: "a person does".to_owned(),
                },
            ),
        ]
    };
    let twice = held_to(&one("spawns_twice.txt"));
    assert_eq!(twice.problems.len(), 1, "{:?}", twice.problems);
    assert!(
        twice.problems[0].contains("starts tests::is_ignored without"),
        "{:?}",
        twice.problems
    );
    // A reason an ignore gives, over several lines, is not code that asks for a helper.
    let reason = held_to(&one("reason.txt"));
    assert_eq!(reason.problems.len(), 1, "{:?}", reason.problems);
    assert!(
        reason.problems[0].contains("starts tests::is_ignored without"),
        "{:?}",
        reason.problems
    );
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
    // A program with a harness of its own was run, and its failure would be the step's; it
    // reports no test by name, so its documentation keys none.
    assert!(document.steps[0].error.is_none(), "{:?}", document.steps[0]);
    assert!(
        document
            .identifiers
            .get("KR-REQ-04.06")
            .is_none_or(|own| own.tests.is_empty())
    );
    let map = map_of("outcomes", false);
    assert!(!map.keys.contains_key(&identifier("KR-REQ-04.06")));
    assert!(map.references.contains_key(&identifier("KR-REQ-04.06")));
    // A test that returned early and said why passed without doing what it is for.
    let early = &document.identifiers["KR-REQ-04.05"];
    assert_eq!(early.verdict, Verdict::NotRun);
    assert_eq!(early.tests[0].outcome, Outcome::NotRun);
    assert_eq!(
        early.tests[0].reason.as_deref(),
        Some("it returned early and said why: skipped: OUTCOMES_DEVICE names no device to drive")
    );
    // The harness prints the name of a test that should panic with " - should panic" after it,
    // which is no name in the test's binary.
    let panics = &document.identifiers["KR-REQ-04.08"];
    assert_eq!(panics.verdict, Verdict::Passed, "{:?}", panics.tests);
    // An ignore reason of two lines, the second of which starts as an entry of the harness's record
    // does.
    let two_lines = &document.identifiers["KR-REQ-04.09"].tests[0];
    assert_eq!(two_lines.outcome, Outcome::Ignored, "{two_lines:?}");
    assert_eq!(
        two_lines.reason.as_deref(),
        Some("needs a device\nok when one is named")
    );
}

#[test]
fn a_result_line_that_follows_half_a_line_of_standard_error_is_still_the_tests_result() {
    // Two test threads, so that the harness reports the result of the one test as it comes,
    // whatever the machine's processors are.
    let (document, evidence) = run_step(
        "interleaved",
        &[
            "test",
            "--locked",
            "--workspace",
            "--no-fail-fast",
            "--",
            "--test-threads=2",
        ],
    )
    .unwrap_or_else(|stopped| panic!("{stopped:?}"));
    // The run is the one this test is for: the half line and the harness's result line are one
    // line of the step's log.
    let log = std::fs::read_to_string(evidence.path().join(&document.steps[0].log))
        .expect("the step's log");
    assert!(
        log.lines()
            .any(|line| line.starts_with("this host has no model file, test ")),
        "the half line is not followed by a result on its line:\n{log}"
    );
    assert!(document.steps[0].error.is_none(), "{:?}", document.steps[0]);
    let tests = &document.identifiers["KR-REQ-04.11"].tests;
    assert_eq!(tests.len(), 1, "{tests:?}");
    assert_eq!(tests[0].outcome, Outcome::Passed, "{:?}", tests[0]);
    assert!(document.passed());
}

/// A program to stand where the report's own does as Cargo's runner: it lists the tests as the
/// report's does, and runs each test binary without the harness's option to write a record. It
/// leaves `record` as each binary's record when that is given.
#[cfg(unix)]
fn runner_that_asks_for_no_record(directory: &Path, record: Option<&str>) -> PathBuf {
    let path = directory.join("runner");
    let leave = record.map_or_else(String::new, |text| {
        format!("printf '%s\\n' '{text}' > \"$KR_CONFORMANCE_RECORDS/$(basename \"$2\")\"\n")
    });
    let script = format!(
        "#!/bin/sh\ncase \"$1\" in\n  run-one)\n{leave}    shift\n    exec \"$@\" ;;\n  *) exec '{}' \"$@\" ;;\nesac\n",
        lister().display()
    );
    kr_ipc::testing::place_script(&path, script);
    path
}

#[cfg(unix)]
#[test]
fn a_binary_that_left_no_record_that_can_be_used_is_not_read_from_its_output() {
    let directory = tempfile::tempdir().expect("a directory");
    for (record, why) in [
        (None, "the harness left no record of its run"),
        (Some("this is not an entry"), "its record could not be read"),
    ] {
        let lister = runner_that_asks_for_no_record(directory.path(), record);
        let (document, _evidence) = run_step_through(
            "forms",
            &["test", "--locked", "--workspace", "--no-fail-fast"],
            lister,
        )
        .unwrap_or_else(|stopped| panic!("{stopped:?}"));
        let error = document.steps[0].error.as_deref().unwrap_or_default();
        assert!(error.contains(why), "{error}");
        let tests: Vec<_> = document
            .identifiers
            .values()
            .flat_map(|identifier| &identifier.tests)
            .collect();
        assert!(!tests.is_empty());
        for test in tests {
            assert_eq!(test.outcome, Outcome::Failed, "{test:?}");
            assert!(
                test.reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains(why)),
                "{test:?}"
            );
        }
        assert!(!document.passed());
    }
}

/// A program to stand where the report's own does as Cargo's runner when a step's tests cannot be
/// listed: it writes `earlier` lines and then `last` (which the shell expands) to its standard
/// error, and fails.
#[cfg(unix)]
fn runner_that_cannot_list(directory: &Path, earlier: usize, last: &str) -> PathBuf {
    let path = directory.join("runner-that-cannot-list");
    let script = format!(
        "#!/bin/sh\ni=0\nwhile [ \"$i\" -lt {earlier} ]; do\n  echo \"an earlier line $i\" >&2\n  i=$((i + 1))\ndone\necho \"{last}\" >&2\nexit 3\n"
    );
    kr_ipc::testing::place_script(&path, script);
    path
}

#[cfg(unix)]
#[test]
fn a_listing_that_fails_leaves_what_it_said_in_the_log_and_the_end_of_it_in_the_steps_error() {
    let directory = tempfile::tempdir().expect("a directory");
    // Cargo gives a test binary's runner the manifest directory of its package, which is inside
    // the checkout.
    let lister = runner_that_cannot_list(
        directory.path(),
        200,
        "cannot write in $CARGO_MANIFEST_DIR: the volume is full",
    );
    let (document, evidence) = run_step_through(
        "forms",
        &["test", "--locked", "--workspace", "--no-fail-fast"],
        lister,
    )
    .unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let step = &document.steps[0];
    let error = step.error.as_deref().unwrap_or_default();
    assert!(error.contains("did not list the step's tests"), "{error}");
    assert!(
        !error.contains("targets failed") && !error.contains("rerun pass"),
        "Cargo's account of the failed targets stands in the place of what they said: {error}"
    );
    assert!(
        error.contains("the volume is full"),
        "the error does not name what the listing said last: {error}"
    );
    assert!(
        !error.contains("an earlier line 0"),
        "the error holds the whole of a long standard error: {error}"
    );
    assert!(error.len() < 2_000, "{} bytes: {error}", error.len());
    let log = std::fs::read_to_string(evidence.path().join(&step.log)).expect("the step's log");
    for expected in ["an earlier line 0", "an earlier line 199"] {
        assert!(
            log.lines().any(|line| line == expected),
            "the log lacks {expected:?}:\n{log}"
        );
    }
    let root = tree("forms").to_string_lossy().into_owned();
    assert!(
        log.lines()
            .any(|line| line.contains(&root) && line.ends_with("the volume is full")),
        "the log lacks the last line, with the checkout's path in it:\n{log}"
    );
    let text = serde_json::to_string(&document).expect("serialises");
    assert!(
        !text.contains(&root),
        "the result names the checkout's path: {error}"
    );
    assert!(!document.passed());
}

/// The lister is Cargo's runner, and Cargo shows only that the runner failed. The status of the test
/// binary the lister ran, or that it could not start it, is on the lister's standard error beside
/// the listing's frame on its standard output, so that a failed listing names it.
#[test]
fn a_test_binary_the_lister_could_not_run_to_the_end_says_so_on_its_standard_error() {
    let ran = |arguments: &[&str]| {
        let output = std::process::Command::new(lister())
            .arg("list-one")
            .args(arguments)
            .output()
            .expect("the lister runs");
        assert_eq!(output.status.code(), Some(1));
        (
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    let (framed, said) = ran(&["/nowhere/a-test-binary-that-is-not-there", "--list"]);
    assert!(framed.contains("could not start"), "{framed}");
    assert!(said.contains("could not start"), "{said}");
    #[cfg(unix)]
    {
        let (framed, said) = ran(&["/bin/sh", "-c", "exit 7"]);
        assert!(framed.contains("\t7"), "{framed}");
        assert!(said.contains("exit status: 7"), "{said}");
    }
}

/// A program to stand where the report's own does as Cargo's runner when the first test program
/// cannot be listed: it says `why` on its standard error and fails, once, and is silent and well
/// for every program after that.
#[cfg(unix)]
fn runner_whose_first_program_cannot_be_listed(directory: &Path, why: &str) -> PathBuf {
    let path = directory.join("runner-whose-first-program-cannot-be-listed");
    let marker = directory.join("ran-once");
    let script = format!(
        "#!/bin/sh\n[ -e \"{marker}\" ] && exit 0\n: > \"{marker}\"\necho \"{why}\" >&2\nexit 3\n",
        marker = marker.display()
    );
    kr_ipc::testing::place_script(&path, script);
    path
}

/// With several libraries Cargo goes on after the first program that fails, and what it writes for
/// the others (a line for each program and each library's documentation tests) comes after the
/// failure, so it fills the end of the standard error. The error names what the failed program said,
/// which comes before Cargo's account of it, and none of Cargo's own lines.
#[cfg(unix)]
#[test]
fn a_listing_whose_first_program_fails_names_what_it_said_and_not_what_cargo_wrote_after_it() {
    let directory = tempfile::tempdir().expect("a directory");
    let lister = runner_whose_first_program_cannot_be_listed(
        directory.path(),
        "cannot write in $CARGO_MANIFEST_DIR: the volume is full",
    );
    let (document, evidence) = run_step_through(
        "several",
        &["test", "--locked", "--workspace", "--no-fail-fast"],
        lister,
    )
    .unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let step = &document.steps[0];
    let error = step.error.as_deref().unwrap_or_default();
    assert!(error.contains("did not list the step's tests"), "{error}");
    assert!(
        error.contains("the volume is full"),
        "the error does not name what the first program said: {error}"
    );
    // The target directory is outside the checkout, and Cargo's status lines name the programs in
    // it: they belong in the log, and not in the result.
    for status in [
        "Finished",
        "Running unittests",
        "kr-conformance-fixture-target",
    ] {
        assert!(!error.contains(status), "{status} is in the error: {error}");
    }
    let log = std::fs::read_to_string(evidence.path().join(&step.log)).expect("the step's log");
    for status in ["Running unittests", "kr-conformance-fixture-target"] {
        assert!(log.contains(status), "{status} is not in the log:\n{log}");
    }
    for cargo in [
        "Doc-tests",
        "Caused by",
        "didn't exit successfully",
        "rerun pass",
        "targets failed",
    ] {
        assert!(
            !error.contains(cargo),
            "the error holds a line of Cargo's ({cargo}): {error}"
        );
    }
}

/// A crate whose macro writes a file into the build script's output directory while the crate
/// compiles (Tauri's context macro does it with an application's icon and front end) is out of date
/// to Cargo in the next call: the file is newer than the start of the compile that read it. The
/// step's tests are built once, and neither the listing nor the run builds them again.
#[test]
fn a_file_a_macro_writes_while_a_crate_compiles_does_not_have_the_listing_build_it_again() {
    let evidence = tempfile::tempdir().expect("an evidence directory");
    // A target directory of its own, so that the macro runs in this test's build.
    let target = tempfile::tempdir().expect("a target directory");
    let base = tempfile::tempdir().expect("a directory for the copy");
    let options = Options {
        root: tree("late"),
        evidence: kr_conformance::evidence::check_directory(evidence.path()).expect("inside"),
        selection: Some(vec!["rust".to_owned()]),
        all_terminals: false,
        platform: Platform::current(),
        typescript_compiler: None,
        applications: None,
        plan: Plan::of_steps(
            "rust",
            vec![Step::cargo(
                "rust",
                "the tree's tests",
                &["test", "--locked", "-p", "late", "--no-fail-fast"],
            )],
        ),
        lister: lister(),
        environment: vec![(
            "CARGO_TARGET_DIR".to_owned(),
            target.path().to_string_lossy().into_owned(),
        )],
        part: None,
        runner_base: base.path().to_path_buf(),
    };
    let document = report::run(&options, &mut |_| {}).expect("runs");
    let step = &document.steps[0];
    assert!(step.error.is_none(), "{step:?}");
    let log = std::fs::read_to_string(evidence.path().join(&step.log)).expect("the step's log");
    assert!(
        log.lines().any(|line| line.contains("Compiling late ")),
        "the build did not compile the crate, so the macro did not run in it:\n{log}"
    );
    assert!(
        !log.contains("the listing compiled again"),
        "the listing built what the build before it had built:\n{log}"
    );
    let run = log
        .split("\n== cargo test ")
        .nth(1)
        .expect("the log holds the step's run");
    assert!(
        !run.contains("Compiling "),
        "the run built what the build before it had built:\n{log}"
    );
    assert!(document.passed());
}

/// Two test programs of one package that expand the macro are independent of each other, so Cargo
/// may compile them at the same time, and one may read the file while the other writes it. Nothing
/// then says which read it whole, but the file's time, so the build leaves it as it is and the
/// next call compiles them again, as it did before.
#[test]
fn a_file_two_test_programs_may_write_and_read_at_once_keeps_its_time() {
    let evidence = tempfile::tempdir().expect("an evidence directory");
    let target = tempfile::tempdir().expect("a target directory");
    let base = tempfile::tempdir().expect("a directory for the copy");
    let options = Options {
        root: tree("late"),
        evidence: kr_conformance::evidence::check_directory(evidence.path()).expect("inside"),
        selection: Some(vec!["rust".to_owned()]),
        all_terminals: false,
        platform: Platform::current(),
        typescript_compiler: None,
        applications: None,
        plan: Plan::of_steps(
            "rust",
            vec![Step::cargo(
                "rust",
                "the package's tests",
                &["test", "--locked", "-p", "racy", "--no-fail-fast"],
            )],
        ),
        lister: lister(),
        environment: vec![(
            "CARGO_TARGET_DIR".to_owned(),
            target.path().to_string_lossy().into_owned(),
        )],
        part: None,
        runner_base: base.path().to_path_buf(),
    };
    let document = report::run(&options, &mut |_| {}).expect("runs");
    let step = &document.steps[0];
    assert!(step.error.is_none(), "{step:?}");
    let log = std::fs::read_to_string(evidence.path().join(&step.log)).expect("the step's log");
    assert!(
        log.lines().any(|line| line.contains("is left to Cargo")),
        "the build dated a file that two compiles read:\n{log}"
    );
}

/// A library that expands the macro, and two test programs that do it after the library (a test
/// program waits for the library it links), find the file the library wrote, whole, and only read
/// it. Nothing is written beside a read, so the build dates the file, and the next call of Cargo
/// has nothing to build.
#[test]
fn a_file_a_library_wrote_and_two_test_programs_read_leaves_the_listing_nothing_to_build() {
    let evidence = tempfile::tempdir().expect("an evidence directory");
    let target = tempfile::tempdir().expect("a target directory");
    let base = tempfile::tempdir().expect("a directory for the copy");
    let options = Options {
        root: tree("late"),
        evidence: kr_conformance::evidence::check_directory(evidence.path()).expect("inside"),
        selection: Some(vec!["rust".to_owned()]),
        all_terminals: false,
        platform: Platform::current(),
        typescript_compiler: None,
        applications: None,
        plan: Plan::of_steps(
            "rust",
            vec![Step::cargo(
                "rust",
                "the package's tests",
                &["test", "--locked", "-p", "shared", "--no-fail-fast"],
            )],
        ),
        lister: lister(),
        environment: vec![(
            "CARGO_TARGET_DIR".to_owned(),
            target.path().to_string_lossy().into_owned(),
        )],
        part: None,
        runner_base: base.path().to_path_buf(),
    };
    let document = report::run(&options, &mut |_| {}).expect("runs");
    let step = &document.steps[0];
    assert!(step.error.is_none(), "{step:?}");
    let log = std::fs::read_to_string(evidence.path().join(&step.log)).expect("the step's log");
    assert!(
        log.lines().any(|line| line.contains("Compiling shared ")),
        "the build did not compile the package, so the macro did not run in it:\n{log}"
    );
    assert!(
        !log.contains("is left to Cargo") && !log.contains("the listing compiled again"),
        "the listing built what the build before it had built:\n{log}"
    );
    assert!(document.passed());
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

/// KR-REQ-29.01, the part about reproducible commands and the identity of a run: the result names
/// the command that ran a keyed test and the command of a step, the log that holds a step's output,
/// the result's schema, the commit and the terminal profile, and it names no path of the checkout.
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
        Some("cargo test --locked --workspace --no-fail-fast --test flow -- --exact documented")
    );
    assert_eq!(
        document.steps[0].command,
        "cargo test --locked --workspace --no-fail-fast -- --show-output"
    );
    assert!(document.steps[0].log.starts_with("conformance/logs/"));
    assert!(evidence.path().join(&document.steps[0].log).is_file());
    assert_eq!(document.schema, report::SCHEMA);
    assert!(!document.run.commit.id.is_empty());
    assert!(
        document.run.terminal_profile.is_none(),
        "the plan of this tree names no terminal profile"
    );
    assert!(
        !text.contains("terminal_profile"),
        "a result leaves the profile out when the plan names no file"
    );
}

#[test]
fn an_evidence_directory_that_holds_an_earlier_report_is_refused() {
    let (_, evidence) = run("forms").unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let target = std::env::temp_dir().join("kr-conformance-fixture-target-forms");
    let base = tempfile::tempdir().expect("a directory for the copy");
    let again = Options {
        root: tree("forms"),
        evidence: kr_conformance::evidence::check_directory(evidence.path()).expect("inside"),
        selection: Some(vec!["rust".to_owned()]),
        all_terminals: false,
        platform: Platform::current(),
        typescript_compiler: None,
        applications: None,
        plan: Plan::of_steps(
            "rust",
            vec![Step::cargo(
                "rust",
                "the tree's tests",
                &["test", "--locked", "--workspace", "--no-fail-fast"],
            )],
        ),
        lister: lister(),
        environment: vec![(
            "CARGO_TARGET_DIR".to_owned(),
            target.to_string_lossy().into_owned(),
        )],
        part: None,
        runner_base: base.path().to_path_buf(),
    };
    match report::run(&again, &mut |_| {}) {
        Err(Stopped::Evidence(problem)) => assert!(problem.contains("earlier run"), "{problem}"),
        other => panic!("a second run in one evidence directory: {other:?}"),
    }
}

#[test]
fn a_target_no_step_runs_is_not_run_with_the_reason() {
    // The same tree, with a step that runs only its library: the integration tests are keyed, and
    // nothing ran them.
    let evidence = tempfile::tempdir().expect("an evidence directory");
    let target = std::env::temp_dir().join("kr-conformance-fixture-target-forms-lib");
    let base = tempfile::tempdir().expect("a directory for the copy");
    let options = Options {
        root: tree("forms"),
        evidence: kr_conformance::evidence::check_directory(evidence.path()).expect("inside"),
        selection: None,
        all_terminals: false,
        platform: Platform::current(),
        typescript_compiler: None,
        applications: None,
        plan: Plan {
            list_table_rows: true,
            ..Plan::of_steps(
                "rust",
                vec![Step::cargo(
                    "rust",
                    "the library's tests",
                    &["test", "--locked", "--lib"],
                )],
            )
        },
        lister: lister(),
        environment: vec![(
            "CARGO_TARGET_DIR".to_owned(),
            target.to_string_lossy().into_owned(),
        )],
        part: None,
        runner_base: base.path().to_path_buf(),
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
    assert!(document.terminals.is_none(), "no terminal was asked for");
    assert!(document.passed(), "a test no step runs fails nothing");
}

#[cfg(unix)]
#[test]
fn a_test_whose_step_stopped_after_building_it_is_not_run_with_the_steps_error() {
    // A runner that ends with a failure for every program it is given, so the step stops after its
    // build, before its tests are listed or run.
    use std::os::unix::fs::PermissionsExt;
    let evidence = tempfile::tempdir().expect("an evidence directory");
    let held = tempfile::tempdir().expect("a directory");
    let failing = held.path().join("kr-conformance");
    std::fs::write(&failing, "#!/bin/sh\nexit 1\n").expect("a runner");
    std::fs::set_permissions(&failing, std::fs::Permissions::from_mode(0o755)).expect("runnable");
    let target = std::env::temp_dir().join("kr-conformance-fixture-target-forms-lib");
    let base = tempfile::tempdir().expect("a directory for the copy");
    let options = Options {
        root: tree("forms"),
        evidence: kr_conformance::evidence::check_directory(evidence.path()).expect("inside"),
        selection: Some(vec!["rust".to_owned()]),
        all_terminals: false,
        platform: Platform::current(),
        typescript_compiler: None,
        applications: None,
        plan: Plan::of_steps(
            "rust",
            vec![Step::cargo(
                "rust",
                "the library's tests",
                &["test", "--locked", "--lib"],
            )],
        ),
        lister: failing,
        environment: vec![(
            "CARGO_TARGET_DIR".to_owned(),
            target.to_string_lossy().into_owned(),
        )],
        part: None,
        runner_base: base.path().to_path_buf(),
    };
    let document = report::run(&options, &mut |_| {}).expect("runs");
    assert!(document.steps[0].error.is_some(), "{:?}", document.steps[0]);
    assert!(
        document.identifiers.contains_key("KR-REQ-02.03"),
        "{:?}",
        document.identifiers.keys().collect::<Vec<_>>()
    );
    let record = &document.identifiers["KR-REQ-02.03"];
    assert_eq!(record.verdict, Verdict::NotRun);
    let reason = record.tests[0].reason.as_deref().unwrap_or_default();
    assert!(
        reason.starts_with("`cargo test --locked --lib")
            && reason.contains("built this target, and no run of it can be read from that step")
            && reason.contains("did not list the step's tests"),
        "{reason}"
    );
    assert!(!document.passed(), "a step that stopped fails the run");
}

#[test]
fn a_test_its_step_stopped_before_reaching_is_not_run_with_the_steps_error() {
    // Without `--no-fail-fast`, Cargo stops at the library's failing test and never runs the
    // integration test it built after it.
    let evidence = tempfile::tempdir().expect("an evidence directory");
    let target = std::env::temp_dir().join("kr-conformance-fixture-target-outcomes-stops");
    let base = tempfile::tempdir().expect("a directory for the copy");
    let options = Options {
        root: tree("outcomes"),
        evidence: kr_conformance::evidence::check_directory(evidence.path()).expect("inside"),
        selection: Some(vec!["rust".to_owned()]),
        all_terminals: false,
        platform: Platform::current(),
        typescript_compiler: None,
        applications: None,
        plan: Plan::of_steps(
            "rust",
            vec![Step::cargo(
                "rust",
                "the tree's tests, stopping at the first failure",
                &["test", "--locked", "--workspace"],
            )],
        ),
        lister: lister(),
        environment: vec![(
            "CARGO_TARGET_DIR".to_owned(),
            target.to_string_lossy().into_owned(),
        )],
        part: None,
        runner_base: base.path().to_path_buf(),
    };
    let document = report::run(&options, &mut |_| {}).expect("runs");
    let error = document.steps[0].error.as_deref().unwrap_or_default();
    assert!(
        error.contains("ended before it ran"),
        "{:?}",
        document.steps[0]
    );
    for row in ["KR-REQ-04.03", "KR-REQ-04.07"] {
        assert!(
            document.identifiers.contains_key(row),
            "{row} is not in the result: {:?}",
            document.identifiers.keys().collect::<Vec<_>>()
        );
    }
    assert_eq!(
        document.identifiers["KR-REQ-04.03"].verdict,
        Verdict::Failed
    );
    let unreached = &document.identifiers["KR-REQ-04.07"];
    assert_eq!(unreached.verdict, Verdict::NotRun);
    let reason = unreached.tests[0].reason.as_deref().unwrap_or_default();
    assert!(
        reason.contains("built this target, and no run of it can be read from that step")
            && reason.contains("ended before it ran"),
        "{reason}"
    );
}

#[test]
fn a_run_asked_for_every_terminal_names_each_one_as_not_run_and_fails_until_its_runs_exist() {
    let evidence = tempfile::tempdir().expect("an evidence directory");
    let target = std::env::temp_dir().join("kr-conformance-fixture-target-forms-lib");
    let base = tempfile::tempdir().expect("a directory for the copy");
    let options = Options {
        root: tree("forms"),
        evidence: kr_conformance::evidence::check_directory(evidence.path()).expect("inside"),
        selection: None,
        all_terminals: true,
        platform: Platform::current(),
        typescript_compiler: None,
        applications: None,
        plan: Plan {
            terminals: core_plan().terminals,
            ..Plan::of_steps(
                "rust",
                vec![Step::cargo(
                    "rust",
                    "the library's tests",
                    &["test", "--locked", "--lib"],
                )],
            )
        },
        lister: lister(),
        environment: vec![(
            "CARGO_TARGET_DIR".to_owned(),
            target.to_string_lossy().into_owned(),
        )],
        part: None,
        runner_base: base.path().to_path_buf(),
    };
    let document = report::run(&options, &mut |_| {}).expect("runs");
    let terminals = document.terminals.as_ref().expect("the matrix");
    let named: Vec<&str> = terminals
        .iter()
        .map(|terminal| terminal.terminal.as_str())
        .collect();
    assert_eq!(
        named,
        [
            "iTerm2",
            "Terminal.app",
            "Ghostty",
            "WezTerm",
            "Windows Terminal",
            "a VTE-based Linux terminal",
            "the VS Code terminal"
        ]
    );
    assert!(
        terminals
            .iter()
            .all(|terminal| terminal.outcome == Outcome::NotRun && !terminal.reason.is_empty())
    );
    // Everything else of the run passed: the matrix alone fails it.
    assert_eq!(document.summary.failed, 0);
    assert!(document.summary.failed_steps.is_empty());
    assert!(
        !document.passed(),
        "a run asked for every terminal fails until they have run"
    );
}

#[test]
fn a_test_a_steps_own_flags_leave_out_is_not_run_rather_than_not_built() {
    let evidence = tempfile::tempdir().expect("an evidence directory");
    let target = std::env::temp_dir().join("kr-conformance-fixture-target-outcomes-ignored");
    let base = tempfile::tempdir().expect("a directory for the copy");
    let options = Options {
        root: tree("outcomes"),
        evidence: kr_conformance::evidence::check_directory(evidence.path()).expect("inside"),
        selection: Some(vec!["rust".to_owned()]),
        all_terminals: false,
        platform: Platform::current(),
        typescript_compiler: None,
        applications: None,
        plan: Plan::of_steps(
            "rust",
            vec![Step::cargo(
                "rust",
                "the ignored tests alone",
                &["test", "--locked", "--lib", "--", "--ignored"],
            )],
        ),
        lister: lister(),
        environment: vec![(
            "CARGO_TARGET_DIR".to_owned(),
            target.to_string_lossy().into_owned(),
        )],
        part: None,
        runner_base: base.path().to_path_buf(),
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

/// A package of the workspace in `workspace`, with its targets: each a kind, a name and whether
/// `cargo test` builds it when it is not asked for by name.
fn package_of(name: &str, workspace: &str, targets: &[(TargetKind, &str, bool)]) -> Package {
    Package {
        name: name.to_owned(),
        version: "0.1.0".to_owned(),
        targets: targets
            .iter()
            .map(|(kind, target, tested)| Target {
                id: target_of(name, *kind, target),
                src_path: PathBuf::from("src/lib.rs"),
                tested_by_default: *tested,
                benchmarked: false,
                required_features: Vec::new(),
                harness: true,
                edition: "2024".to_owned(),
            })
            .collect(),
        features: BTreeMap::new(),
        self_dev_features: BTreeSet::new(),
        manifest: PathBuf::from("Cargo.toml"),
        registry_crates: BTreeSet::new(),
        dependency_names: BTreeSet::new(),
        workspace: workspace.to_owned(),
        workspace_members: vec![name.to_owned()],
        workspace_default_members: vec![name.to_owned()],
    }
}

fn target_of(package: &str, kind: TargetKind, name: &str) -> TargetId {
    TargetId {
        package: package.to_owned(),
        kind,
        name: name.to_owned(),
    }
}

/// Keys the test `test` of `target` to `row`.
fn key_in(map: &mut Map, row: &str, target: &TargetId, test: &str) {
    map.keys.entry(identifier(row)).or_default().insert(
        Place::Rust {
            target: target.clone(),
            name: test.to_owned(),
        },
        Key {
            binding: Binding::AttachedComment,
            source: format!("{}.rs:1", target.name),
        },
    );
}

/// A step that ran to its end and left nothing to read: no program ran, none was built or listed.
fn quiet(step: Step) -> Executed {
    Executed {
        step,
        exit: Some(0),
        seconds: 0,
        log: "conformance/logs/x.log".to_owned(),
        binaries: Vec::new(),
        built: Vec::new(),
        listed: BTreeMap::new(),
        vitest: None,
        lane: None,
        tools: Vec::new(),
        error: None,
        blocked: None,
        observation: None,
        timed_out: false,
    }
}

/// A step that built the program of `target`, listed `tests` in it and ran them, each passing.
fn passing(step: Step, target: &TargetId, tests: &[&str]) -> Executed {
    Executed {
        binaries: vec![(
            Some(target.clone()),
            Binary {
                executable: format!("{}-0", target.name),
                source: "src/lib.rs".to_owned(),
                tests: tests
                    .iter()
                    .map(|test| ((*test).to_owned(), LibtestOutcome::Passed))
                    .collect(),
                ..Binary::default()
            },
        )],
        built: vec![target.clone()],
        listed: [(
            target.clone(),
            tests.iter().map(|test| (*test).to_owned()).collect(),
        )]
        .into(),
        ..quiet(step)
    }
}

/// The result of a Linux run of every group over `map` and what its steps did: a run that selects
/// no group lists a target that no step covers, and one that selects groups does not.
fn assembled(plan: Plan, map: &Map, executed: &[Executed]) -> Document {
    assembled_selecting(plan, map, executed, None)
}

/// [`assembled`] for a run that selects `groups`: it reads the targets that its steps cover.
fn assembled_selecting(
    plan: Plan,
    map: &Map,
    executed: &[Executed],
    groups: Option<Vec<String>>,
) -> Document {
    let options = Options {
        root: PathBuf::from("/tmp/r"),
        evidence: PathBuf::from("/tmp/e"),
        selection: groups,
        all_terminals: false,
        platform: Platform::Linux,
        plan,
        typescript_compiler: None,
        applications: None,
        lister: PathBuf::from("/tmp/l"),
        environment: Vec::new(),
        part: None,
        runner_base: PathBuf::new(),
    };
    report::assemble(
        &options,
        &rust_group(),
        map,
        executed,
        Gathered::default(),
        "2026-11-20T00:00:00Z".to_owned(),
    )
}

/// The reason of the one test the identifier `row` keys.
fn reason_of(document: &Document, row: &str) -> String {
    let record = &document.identifiers[row].tests[0];
    assert_eq!(record.outcome, Outcome::NotRun, "{record:?}");
    record.reason.clone().unwrap_or_default()
}

/// A step that fails before it builds names only the targets its command selects in its own
/// workspace: the other workspace's targets keep their own records, whether they ran or not.
#[test]
fn a_step_that_failed_is_the_reason_of_its_own_workspace_and_no_other() {
    let root = tree("no-root-manifest");
    let plan = Plan::load(&root, None).expect("the fixture's plan");
    let map = map::build(
        &root,
        &Declarations {
            case_tables: &[],
            lanes: &[],
            manifests: &[
                "first/Cargo.toml".to_owned(),
                "second/Cargo.toml".to_owned(),
            ],
            ignored_runs: None,
            plan_commands: &[],
            typescript: None,
            scripts: &[],
            lane_directories: &[],
        },
    );
    let steps = plan.steps(
        Platform::Linux,
        &rust_group(),
        &Values::evidence("/tmp/e"),
        None,
    );
    assert_eq!(steps.len(), 2, "{steps:?}");
    assert_eq!(steps[0].directory, "first");
    assert_eq!(steps[1].directory, "second");
    let beta = target_of("beta", TargetKind::Test, "flow");
    let stopped = Executed {
        exit: Some(101),
        error: Some("its build failed".to_owned()),
        ..quiet(steps[0].clone())
    };
    let named = "no step that ran listed this target; `cd first && cargo test --locked -- --show-output` did not build (its build failed)";

    // The second workspace's step ran its program: its tests pass.
    let ran = passing(steps[1].clone(), &beta, &["passes", "stands_down"]);
    let document = assembled(plan.clone(), &map, &[stopped.clone(), ran]);
    assert_eq!(reason_of(&document, "KR-REQ-03.01"), named);
    assert_eq!(reason_of(&document, "KR-REQ-03.02"), named);
    for row in ["KR-REQ-04.01", "KR-REQ-04.02"] {
        let record = &document.identifiers[row].tests[0];
        assert_eq!(record.outcome, Outcome::Passed, "{record:?}");
        assert_eq!(record.reason, None, "{record:?}");
    }

    // A run that selects the group reads the targets its steps cover, so the first workspace's tests
    // stay in the result, not run, though their step built nothing and ran nothing.
    let ran = passing(steps[1].clone(), &beta, &["passes", "stands_down"]);
    let document = assembled_selecting(
        plan.clone(),
        &map,
        &[stopped.clone(), ran],
        Some(vec!["rust".to_owned()]),
    );
    for row in ["KR-REQ-03.01", "KR-REQ-03.02"] {
        assert!(
            document.identifiers.contains_key(row),
            "{row} is not in the result: {:?}",
            document.identifiers.keys().collect::<Vec<_>>()
        );
        assert_eq!(reason_of(&document, row), named);
    }

    // It ran and listed nothing: its tests are not run, for its own step and not for the first.
    let document = assembled(plan, &map, &[stopped, quiet(steps[1].clone())]);
    assert_eq!(reason_of(&document, "KR-REQ-03.01"), named);
    for row in ["KR-REQ-04.01", "KR-REQ-04.02"] {
        assert_eq!(
            reason_of(&document, row),
            "no step that ran listed this target, though `cd second && cargo test --locked -- --show-output` selects it"
        );
    }
    let command = document.identifiers["KR-REQ-04.01"].tests[0]
        .command
        .clone()
        .unwrap_or_default();
    // Its step built no target, so the command keeps the step's own words.
    assert_eq!(
        command,
        "cd second && cargo test --locked -- --exact passes"
    );
}

/// A target that no step of the selection covers reads which of the two it is: its workspace holds
/// no selected step, or it holds one whose command leaves the target out; a benchmark reads the
/// plan's text for benchmarks first.
#[test]
fn a_target_no_step_covers_reads_whether_its_workspace_or_only_it_is_left_out() {
    use TargetKind::{Bench, Lib, Test};
    let mut map = Map {
        packages: vec![
            package_of(
                "p",
                ".",
                &[(Lib, "p", true), (Test, "t", true), (Bench, "m", false)],
            ),
            package_of("q", "other", &[(Lib, "q", true)]),
        ],
        ..Map::default()
    };
    key_in(&mut map, "KR-REQ-03.01", &target_of("p", Test, "t"), "a");
    key_in(&mut map, "KR-REQ-03.02", &target_of("q", Lib, "q"), "b");
    key_in(&mut map, "KR-REQ-03.03", &target_of("p", Bench, "m"), "c");
    let step = Step::cargo("rust", "the library", &["test", "--locked", "--lib"]);
    let mut plan = Plan::of_steps("rust", vec![step.clone()]);
    plan.unrun.bench = "a benchmark".to_owned();
    let document = assembled(plan, &map, &[quiet(step)]);
    assert_eq!(
        reason_of(&document, "KR-REQ-03.01"),
        "no step of this selection covers this target"
    );
    assert_eq!(
        reason_of(&document, "KR-REQ-03.02"),
        "no step of this selection covers this workspace"
    );
    assert_eq!(
        reason_of(&document, "KR-REQ-03.03"),
        "a benchmark, and no step of this selection covers this target"
    );
}

/// A target that a step selects and that no listing returned reads the step that selects it.
#[test]
fn a_target_a_step_selects_and_no_listing_returned_names_that_step() {
    let lib = target_of("p", TargetKind::Lib, "p");
    let mut map = Map {
        packages: vec![package_of("p", ".", &[(TargetKind::Lib, "p", true)])],
        ..Map::default()
    };
    key_in(&mut map, "KR-REQ-03.01", &lib, "a");
    let step = Step::cargo("rust", "every test", &["test", "--locked"]);
    let document = assembled(
        Plan::of_steps("rust", vec![step.clone()]),
        &map,
        &[quiet(step)],
    );
    assert_eq!(
        reason_of(&document, "KR-REQ-03.01"),
        "no step that ran listed this target, though `cargo test --locked` selects it"
    );
    assert!(document.passed(), "{:?}", document.problems);
}

/// A target that a step built or ran and that no step of the selection covers is a problem of the
/// run: the rule the report reads commands by and Cargo disagree, and the run does not pass.
#[test]
fn a_target_a_step_ran_that_no_step_covers_is_a_problem_and_fails_the_run() {
    use TargetKind::{Lib, Test};
    let lib = target_of("p", Lib, "p");
    let outside = target_of("p", Test, "t");
    let mut map = Map {
        packages: vec![package_of("p", ".", &[(Lib, "p", true), (Test, "t", true)])],
        ..Map::default()
    };
    key_in(&mut map, "KR-REQ-03.01", &lib, "a");
    key_in(&mut map, "KR-REQ-03.02", &outside, "b");
    let step = Step::cargo("rust", "the library", &["test", "--locked", "--lib"]);
    let plan = Plan::of_steps("rust", vec![step.clone()]);
    let covered = assembled(plan.clone(), &map, &[passing(step.clone(), &lib, &["a"])]);
    assert!(
        !covered
            .problems
            .iter()
            .any(|problem| problem.contains("covers it")),
        "{:?}",
        covered.problems
    );
    // The program of an uncovered target is built and run, or it is only built: each is a problem,
    // and neither puts the target into a selection that the steps' commands decide.
    let beyond = passing(step.clone(), &outside, &["b"]);
    let rows = [
        (
            "ran",
            Executed {
                built: Vec::new(),
                ..beyond.clone()
            },
        ),
        (
            "built",
            Executed {
                binaries: Vec::new(),
                listed: BTreeMap::new(),
                ..beyond
            },
        ),
    ];
    for (how, extra) in rows {
        let mut ran = passing(step.clone(), &lib, &["a"]);
        ran.binaries.extend(extra.binaries);
        ran.built.extend(extra.built);
        let document = assembled(plan.clone(), &map, &[ran.clone()]);
        assert_eq!(
            document
                .problems
                .iter()
                .filter(|problem| problem.contains("covers it"))
                .collect::<Vec<_>>(),
            [
                "step 1 built or ran p --test t, but no step of this selection covers it: the selection rule and Cargo disagree"
            ],
            "{how}: {:?}",
            document.problems
        );
        assert!(!document.passed(), "{how}");
        let selected =
            assembled_selecting(plan.clone(), &map, &[ran], Some(vec!["rust".to_owned()]));
        assert!(
            selected.identifiers.contains_key("KR-REQ-03.01"),
            "{how}: {:?}",
            selected.identifiers.keys().collect::<Vec<_>>()
        );
        assert!(
            !selected.identifiers.contains_key("KR-REQ-03.02"),
            "{how}: an uncovered target is in the selection"
        );
    }
}

/// The command of a test is its step's own, in the directory of the test's workspace and with the
/// step's words and its variables that hold no placeholder; a variable that holds one is named in
/// `needs`, because the run gives a placeholder its value. Where no step ran the test, the step
/// that selects it gives the command. A profile is chosen by `--release` or by `--profile`, and
/// Cargo takes one of them, so the two are two commands. The test's own flag stands for the step's
/// target flags where the step built the test's target, and the step's own flag stays where it did
/// not.
#[test]
fn a_command_reproduces_the_step_in_its_directory_with_its_features_profile_and_variables() {
    let lib = target_of("p", TargetKind::Lib, "p");
    let mut map = Map {
        packages: vec![package_of("p", "first", &[(TargetKind::Lib, "p", true)])],
        ..Map::default()
    };
    map.packages[0].features =
        BTreeMap::from([("f".to_owned(), Vec::new()), ("g".to_owned(), Vec::new())]);
    key_in(&mut map, "KR-REQ-03.01", &lib, "a");
    for (profile, built, kept) in [
        (
            vec!["--release", "--features", "f,g"],
            "cd first && A=on B='two words' cargo test --locked -p p --release --features f,g --lib -- --nocapture --exact a",
            "cd first && A=on B='two words' cargo test --locked -p p --lib --release --features f,g -- --nocapture --exact a",
        ),
        (
            vec!["--profile", "ci", "--features", "f"],
            "cd first && A=on B='two words' cargo test --locked -p p --profile ci --features f --lib -- --nocapture --exact a",
            "cd first && A=on B='two words' cargo test --locked -p p --lib --profile ci --features f -- --nocapture --exact a",
        ),
    ] {
        let mut words = vec!["test", "--locked", "-p", "p", "--lib"];
        words.extend(profile);
        words.extend(["--", "--nocapture"]);
        let step = Step {
            directory: "first".to_owned(),
            env: vec![
                ("A".to_owned(), "on".to_owned()),
                ("B".to_owned(), "two words".to_owned()),
                ("C".to_owned(), "/e/x".to_owned()),
            ],
            placeholder_env: vec!["C".to_owned()],
            needs: vec!["S".to_owned()],
            ..Step::cargo("rust", "the library", &words)
        };
        let plan = Plan::of_steps("rust", vec![step.clone()]);
        for (executed, expected) in [
            (passing(step.clone(), &lib, &["a"]), built),
            (quiet(step.clone()), kept),
        ] {
            let document = assembled(plan.clone(), &map, &[executed]);
            let record = &document.identifiers["KR-REQ-03.01"].tests[0];
            assert_eq!(record.command.as_deref(), Some(expected), "{record:?}");
            assert_eq!(record.needs, ["S", "C"], "{record:?}");
        }
    }
}

/// The command that reproduces the test `a` of the library `p` for `step`, where `package` is the
/// package `p` in the root workspace.
fn reproduction(step: &Step, package: Package) -> String {
    reproduction_in(step, vec![package])
}

/// The same, where the workspace holds `packages`, the first of which is the package `p`.
fn reproduction_in(step: &Step, packages: Vec<Package>) -> String {
    let lib = target_of("p", TargetKind::Lib, "p");
    let mut map = Map {
        packages,
        ..Map::default()
    };
    key_in(&mut map, "KR-REQ-03.01", &lib, "a");
    let plan = Plan::of_steps("rust", vec![step.clone()]);
    let document = assembled(plan, &map, &[passing(step.clone(), &lib, &["a"])]);
    document.identifiers["KR-REQ-03.01"].tests[0]
        .command
        .clone()
        .expect("a command")
}

/// A command that reproduces a test passes the test binary the step's options with their values,
/// and leaves out the filters, the options that choose or list tests, and an option, with its value,
/// that holds a placeholder.
#[test]
fn a_command_keeps_the_options_a_step_passes_the_test_binary_with_their_values() {
    let step = |options: &[&str], held: &[&str]| {
        let mut words = vec!["test", "--locked", "-p", "p", "--lib", "--"];
        words.extend(options);
        let step = Step::cargo("rust", "the library", &words);
        let placeholder_words = held
            .iter()
            .map(|word| {
                step.command
                    .iter()
                    .position(|one| one.as_str() == *word)
                    .expect("a word")
            })
            .collect();
        Step {
            placeholder_words,
            ..step
        }
    };
    let rows: &[(&[&str], &[&str], &str)] = &[
        (
            &["--test-threads", "1", "--nocapture"],
            &[],
            "-- --test-threads 1 --nocapture --exact a",
        ),
        (
            &["--format", "terse", "--color=never", "--quiet"],
            &[],
            "-- --format terse --color=never --quiet --exact a",
        ),
        (
            &[
                "--test-threads=2",
                "-Z",
                "unstable-options",
                "--report-time",
            ],
            &[],
            "-- --test-threads=2 -Z unstable-options --report-time --exact a",
        ),
        (
            &[
                "--skip",
                "slow",
                "--logfile",
                "out.txt",
                "--logfile=x",
                "--show-output",
                "--exact",
                "--list",
                "filter",
            ],
            &[],
            "-- --exact a",
        ),
        (
            &["--format", "/e/x", "--nocapture"],
            &["/e/x"],
            "-- --nocapture --exact a",
        ),
        (
            &["--shuffle-seed=/e/s", "--test-threads", "1"],
            &["--shuffle-seed=/e/s"],
            "-- --test-threads 1 --exact a",
        ),
        (
            &["--ensure-time", "--color", "always"],
            &["--ensure-time"],
            "-- --color always --exact a",
        ),
    ];
    let mut wrong = Vec::new();
    for (options, held, expected) in rows {
        let package = package_of("p", ".", &[(TargetKind::Lib, "p", true)]);
        let have = reproduction(&step(options, held), package);
        let want = format!("cargo test --locked -p p --lib {expected}");
        if have != want {
            wrong.push(format!("{options:?}: {have}, not {want}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A command keeps the words of its step as the step wrote them and in order, whatever packages the
/// step selects: its package, feature, profile, platform and configuration words, and each word that
/// it does not read. The test's own target flag follows them where the step built every target that
/// flag names in its packages, and the step's own target flags and test names stay where it did not.
/// A step without `--locked` gives a command without it.
#[test]
fn a_command_keeps_the_words_of_its_step_and_the_targets_flag_follows_the_targets_it_built() {
    let package = package_of("p", ".", &[(TargetKind::Lib, "p", true)]);
    let other = package_of("q", ".", &[(TargetKind::Lib, "q", true)]);
    let lib = target_of("p", TargetKind::Lib, "p");
    let other_lib = target_of("q", TargetKind::Lib, "q");
    let rest = [
        "--target",
        "t",
        "--config",
        "build.jobs=2",
        "--ignore-rust-version",
    ];
    let command_of = |words: &[&str], built: &[&TargetId]| {
        let mut all = vec!["test"];
        all.extend(words);
        all.extend(rest);
        let step = Step::cargo("rust", "the workspace", &all);
        let mut map = Map {
            packages: vec![package.clone(), other.clone()],
            ..Map::default()
        };
        key_in(&mut map, "KR-REQ-03.01", &lib, "a");
        let plan = Plan::of_steps("rust", vec![step.clone()]);
        let executed = Executed {
            built: built.iter().map(|target| (*target).clone()).collect(),
            ..passing(step, &lib, &["a"])
        };
        assembled(plan, &map, &[executed]).identifiers["KR-REQ-03.01"].tests[0]
            .command
            .clone()
            .expect("a command")
    };
    let mut wrong = Vec::new();
    for (words, built, expected) in [
        // The step built every library its flag names: the test's flag stands for `--lib`.
        (
            &[
                "--locked",
                "--workspace",
                "--features",
                "p/f,q/g,f",
                "--lib",
            ][..],
            &[&lib, &other_lib][..],
            "--locked --workspace --features p/f,q/g,f {rest} --lib",
        ),
        (
            &["--workspace", "--exclude", "q", "--all-features", "--tests"][..],
            &[&lib][..],
            "--workspace --exclude q --all-features {rest} --lib",
        ),
        (
            &["-p", "p", "-p", "q", "--features", "q/g", "--lib"][..],
            &[&lib, &other_lib][..],
            "-p p -p q --features q/g {rest} --lib",
        ),
        (
            &["-qp", "p", "--no-default-features"][..],
            &[&lib][..],
            "-qp p --no-default-features {rest} --lib",
        ),
        // The step did not build the library of `q`: its own target flags and test names stay.
        (
            &["--workspace", "--features", "f", "--lib", "x"][..],
            &[&lib][..],
            "--workspace --features f --lib x {rest}",
        ),
        (
            &["--locked", "-p", "p", "-p", "q", "--tests"][..],
            &[][..],
            "--locked -p p -p q --tests {rest}",
        ),
    ] {
        let have = command_of(words, built);
        let want = format!(
            "cargo test {} -- --exact a",
            expected.replace("{rest}", &rest.join(" "))
        );
        if have != want {
            wrong.push(format!("{words:?}: {have}, not {want}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A cargo flag whose value holds a placeholder is left out of the command, because the run gives a
/// placeholder its value.
#[test]
fn a_command_leaves_out_a_cargo_flag_whose_value_holds_a_placeholder() {
    let package = package_of("p", ".", &[(TargetKind::Lib, "p", true)]);
    let step = Step::cargo(
        "rust",
        "the library",
        &[
            "test",
            "--locked",
            "-p",
            "p",
            "--lib",
            "--config",
            "build.target-dir=\"{scratch}/t\"",
            "--config",
            "build.jobs=2",
            "--target",
            "{scratch}/x",
        ],
    );
    let held = |words: &[&str]| -> Vec<usize> {
        words
            .iter()
            .map(|word| {
                step.command
                    .iter()
                    .position(|one| one.as_str() == *word)
                    .expect("a word")
            })
            .collect()
    };
    let step = Step {
        placeholder_words: held(&["build.target-dir=\"{scratch}/t\"", "{scratch}/x"]),
        ..step.clone()
    };
    assert_eq!(
        reproduction(&step, package),
        "cargo test --locked -p p --config build.jobs=2 --lib -- --exact a"
    );
}

/// A test that no step covers gets `--locked`, `-p <package>`, its target's flag and `--features`
/// with the target's required features, and none of the options or variables of a step.
#[test]
fn a_command_for_a_test_no_step_covers_names_its_package_and_its_targets_flag() {
    let lib = target_of("p", TargetKind::Lib, "p");
    let needs = target_of("p", TargetKind::Test, "u");
    let mut owner = package_of(
        "p",
        ".",
        &[(TargetKind::Lib, "p", true), (TargetKind::Test, "u", true)],
    );
    owner.targets[1].required_features = vec!["f".to_owned(), "g".to_owned()];
    let mut map = Map {
        packages: vec![owner, package_of("q", ".", &[(TargetKind::Lib, "q", true)])],
        ..Map::default()
    };
    key_in(&mut map, "KR-REQ-03.01", &lib, "a");
    key_in(&mut map, "KR-REQ-03.02", &needs, "b");
    // The one step selects `q`, so no step covers `p`'s library.
    let step = Step {
        env: vec![("A".to_owned(), "on".to_owned())],
        ..Step::cargo(
            "rust",
            "the other package",
            &["test", "--locked", "-p", "q", "--", "--test-threads", "1"],
        )
    };
    let plan = Plan::of_steps("rust", vec![step.clone()]);
    let document = assembled(plan, &map, &[quiet(step)]);
    assert_eq!(
        document.identifiers["KR-REQ-03.01"].tests[0]
            .command
            .as_deref(),
        Some("cargo test --locked -p p --lib -- --exact a")
    );
    assert_eq!(
        document.identifiers["KR-REQ-03.02"].tests[0]
            .command
            .as_deref(),
        Some("cargo test --locked -p p --features f,g --test u -- --exact b")
    );
}

/// A workspace on disk that Cargo has locked, and the packages the report reads from it.
#[cfg(unix)]
struct OnDisk {
    directory: tempfile::TempDir,
    target: PathBuf,
    packages: Vec<Package>,
}

/// The manifest of the package `name`, with `extra` after its `[package]` table.
#[cfg(unix)]
fn manifest(name: &str, extra: &str) -> String {
    format!(
        "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n{extra}"
    )
}

/// A workspace of the packages `members` with the files `files` (a path in the workspace and its text).
#[cfg(unix)]
fn on_disk(members: &[&str], files: &[(String, String)]) -> OnDisk {
    use std::process::Command;
    let directory = tempfile::tempdir().expect("a directory");
    let root = directory.path();
    let listed: Vec<String> = members.iter().map(|name| format!("\"{name}\"")).collect();
    let mut all = vec![(
        "Cargo.toml".to_owned(),
        format!(
            "[workspace]\nresolver = \"3\"\nmembers = [{}]\n",
            listed.join(", ")
        ),
    )];
    all.extend(files.iter().cloned());
    for (relative, text) in all {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
        std::fs::write(path, text).expect("a file");
    }
    let target = root.join("target");
    let lock = Command::new("cargo")
        .current_dir(root)
        .env("CARGO_TARGET_DIR", &target)
        .args(["generate-lockfile", "--offline"])
        .output()
        .expect("cargo runs");
    assert!(
        lock.status.success(),
        "{}",
        String::from_utf8_lossy(&lock.stderr)
    );
    let read = kr_conformance::workspace::read(root, &["Cargo.toml".to_owned()]);
    assert!(read.problems.is_empty(), "{:?}", read.problems);
    OnDisk {
        directory,
        target,
        packages: read.packages,
    }
}

/// The command the report gives for the test `test` of the target `target`, for the step `step`.
#[cfg(unix)]
fn command_for(disk: &OnDisk, step: &Step, target: &TargetId, test: &str) -> String {
    let mut map = Map {
        packages: disk.packages.clone(),
        ..Map::default()
    };
    key_in(&mut map, "KR-REQ-03.01", target, test);
    let plan = Plan::of_steps("rust", vec![step.clone()]);
    let document = assembled(plan, &map, &[passing(step.clone(), target, &[test])]);
    document.identifiers["KR-REQ-03.01"].tests[0]
        .command
        .clone()
        .expect("a command")
}

/// The command a report gives for a test runs: in a workspace of two packages that each have a
/// feature, a step that turns both on, with options for the test binary, gives a command that Cargo
/// accepts and that runs the test, and a step that selects one of them gives a command for it alone.
#[cfg(unix)]
#[test]
fn a_reproduced_command_runs_for_each_package_of_a_workspace_that_a_step_gave_features() {
    use std::process::Command;
    let mut files = Vec::new();
    for (name, feature) in [("a", "f"), ("b", "g")] {
        files.push((
            format!("{name}/Cargo.toml"),
            manifest(name, &format!("[features]\n{feature} = []\n")),
        ));
        files.push((format!("{name}/src/lib.rs"), String::new()));
        files.push((
            format!("{name}/tests/t{name}.rs"),
            "#[test]\nfn works() {}\n".to_owned(),
        ));
    }
    let disk = on_disk(&["a", "b"], &files);
    let root = disk.directory.path();
    for (words, names, flags) in [
        (
            &["--workspace", "--features", "a/f,b/g"][..],
            &["a", "b"][..],
            " --workspace ",
        ),
        (&["-p", "a", "--features", "f"][..], &["a"][..], " -p a "),
    ] {
        let mut all = vec!["test", "--locked"];
        all.extend(words);
        all.extend(["--", "--test-threads", "1", "--format", "terse"]);
        let step = Step::cargo("rust", "the workspace", &all);
        for name in names {
            let test = target_of(name, TargetKind::Test, &format!("t{name}"));
            let command = command_for(&disk, &step, &test, "works");
            assert!(command.contains(flags), "{command}: lacks `{flags}`");
            let output = Command::new("sh")
                .arg("-c")
                .arg(&command)
                .current_dir(root)
                .env("CARGO_TARGET_DIR", &disk.target)
                .output()
                .expect("a shell runs");
            let shown = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success() && shown.contains("1 passed"),
                "{command}\n{shown}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

/// The workspaces in which another package turns a feature on, in the test's package or in a
/// dependency of it: through a feature that a second package has by the same name (`shared`),
/// through that package's default feature (`default`), through a feature of a package that the
/// test's package does not depend on (`optional`), through a dependency that asks for a feature
/// (`reached`), and through the dev-dependency of a package that the test's package does not depend
/// on (`dev`). Each has the integration test `ta` in the package `a`.
#[cfg(unix)]
fn feature_fixtures() -> Vec<(&'static str, OnDisk)> {
    let on =
        |feature: &str| format!("pub fn on() -> bool {{\n    cfg!(feature = \"{feature}\")\n}}\n");
    let dependent = |name: &str, feature_table: &str, test: &str| {
        vec![
            (
                format!("{name}/Cargo.toml"),
                manifest(
                    name,
                    &format!("[dependencies]\nc = {{ path = \"../c\" }}\n\n{feature_table}"),
                ),
            ),
            (format!("{name}/src/lib.rs"), String::new()),
            (format!("{name}/tests/ta.rs"), test.to_owned()),
        ]
    };
    let c = |table: &str| {
        vec![
            ("c/Cargo.toml".to_owned(), manifest("c", table)),
            ("c/src/lib.rs".to_owned(), on("x")),
        ]
    };
    let x_is_on = "#[test]\nfn x_is_on() {\n    assert!(c::on());\n}\n";
    let mut shared = c("[features]\nx = []\n");
    shared.extend(dependent("a", "[features]\nf = []\n", x_is_on));
    shared.extend(vec![
        (
            "b/Cargo.toml".to_owned(),
            manifest(
                "b",
                "[dependencies]\nc = { path = \"../c\" }\n\n[features]\nf = [\"c/x\"]\n",
            ),
        ),
        ("b/src/lib.rs".to_owned(), String::new()),
    ]);
    let mut default = c("[features]\nx = []\n");
    default.extend(dependent("a", "", x_is_on));
    default.extend(vec![
        (
            "b/Cargo.toml".to_owned(),
            manifest(
                "b",
                "[dependencies]\nc = { path = \"../c\" }\n\n[features]\ndefault = [\"c/x\"]\n",
            ),
        ),
        ("b/src/lib.rs".to_owned(), String::new()),
    ]);
    let optional = vec![
        (
            "b/Cargo.toml".to_owned(),
            manifest("b", "[features]\ng = []\n"),
        ),
        ("b/src/lib.rs".to_owned(), String::new()),
        (
            "a/Cargo.toml".to_owned(),
            manifest(
                "a",
                "[dependencies]\ndep = { package = \"b\", path = \"../b\", optional = true }\n",
            ),
        ),
        ("a/src/lib.rs".to_owned(), String::new()),
        (
            "a/tests/ta.rs".to_owned(),
            "#[test]\nfn dep_is_off() {\n    assert!(!cfg!(feature = \"dep\"));\n}\n".to_owned(),
        ),
    ];
    let reached = vec![
        (
            "b/Cargo.toml".to_owned(),
            manifest(
                "b",
                "[features]\ndefault = [\"g\"]\nf = []\ng = []\nh = []\n",
            ),
        ),
        (
            "b/src/lib.rs".to_owned(),
            [("f", "f"), ("g", "g"), ("h", "h")]
                .iter()
                .map(|(function, feature)| {
                    format!(
                        "pub fn {function}_on() -> bool {{\n    cfg!(feature = \"{feature}\")\n}}\n"
                    )
                })
                .collect(),
        ),
        (
            "a/Cargo.toml".to_owned(),
            manifest(
                "a",
                "[dependencies]\nb = { path = \"../b\", default-features = false }\n\n[features]\nf = []\n",
            ),
        ),
        ("a/src/lib.rs".to_owned(), String::new()),
        (
            "a/tests/ta.rs".to_owned(),
            ["f", "g", "h"]
                .iter()
                .map(|name| {
                    format!("#[test]\nfn {name}_is_on() {{\n    assert!(b::{name}_on());\n}}\n\n")
                })
                .collect(),
        ),
        (
            "c/Cargo.toml".to_owned(),
            manifest(
                "c",
                "[dependencies]\nb = { path = \"../b\", features = [\"h\"] }\n",
            ),
        ),
        ("c/src/lib.rs".to_owned(), String::new()),
    ];
    let dev = {
        let mut files = c("[features]\nx = []\n");
        files.extend(dependent("a", "", x_is_on));
        files.extend(vec![
            (
                "b/Cargo.toml".to_owned(),
                manifest(
                    "b",
                    "[dev-dependencies]\nc = { path = \"../c\", features = [\"x\"] }\n",
                ),
            ),
            ("b/src/lib.rs".to_owned(), String::new()),
        ]);
        files
    };
    vec![
        ("shared", on_disk(&["a", "b", "c"], &shared)),
        ("default", on_disk(&["a", "b", "c"], &default)),
        ("optional", on_disk(&["a", "b"], &optional)),
        ("reached", on_disk(&["a", "b", "c"], &reached)),
        ("dev", on_disk(&["a", "b", "c"], &dev)),
    ]
}

/// The command a report gives for a test builds the test's package with the features that its step
/// built it with, in each way another package can turn a feature on: through a feature that a
/// second package has by the same name, through that package's default feature, through a feature of
/// a package that the test's package does not depend on, and through a dependency that asks for a
/// feature. Each row runs the step's own command and the report's command for the same test, and both
/// must find the test's package built the same way.
#[cfg(unix)]
#[test]
fn a_reproduced_command_builds_the_test_s_package_with_the_features_its_step_built_it_with() {
    use std::process::Command;
    let fixtures = feature_fixtures();
    let ta = target_of("a", TargetKind::Test, "ta");
    for (name, words, test) in [
        ("shared", &["--workspace", "--features", "f"][..], "x_is_on"),
        ("default", &["--workspace"][..], "x_is_on"),
        (
            "optional",
            &["--workspace", "--features", "b/g"][..],
            "dep_is_off",
        ),
        (
            "reached",
            &["--workspace", "--features", "f"][..],
            "f_is_on",
        ),
        ("reached", &["--workspace"][..], "g_is_on"),
        ("reached", &["--workspace"][..], "h_is_on"),
    ] {
        let disk = &fixtures
            .iter()
            .find(|(label, _)| *label == name)
            .expect("a fixture")
            .1;
        let root = disk.directory.path();
        let mut step_words = vec!["test", "--locked"];
        step_words.extend(words);
        step_words.extend(["--test", "ta", "--", "--test-threads", "1"]);
        let step = Step::cargo("rust", "the workspace", &step_words);
        let mut original = vec!["test", "--locked", "--offline"];
        original.extend(words);
        original.extend(["--test", "ta", "--", "--exact", test]);
        let original = Command::new("cargo")
            .current_dir(root)
            .env("CARGO_TARGET_DIR", &disk.target)
            .args(&original)
            .output()
            .expect("cargo runs");
        let shown = String::from_utf8_lossy(&original.stdout);
        assert!(
            original.status.success() && shown.contains("1 passed"),
            "{name} {words:?} {test}: the step's own command fails\n{shown}\n{}",
            String::from_utf8_lossy(&original.stderr)
        );
        let command = command_for(disk, &step, &ta, test);
        assert!(
            command.contains(" --workspace "),
            "{name} {words:?} {test}: {command}: lacks the step's package flags"
        );
        let reproduced = Command::new("sh")
            .arg("-c")
            .arg(&command)
            .current_dir(root)
            .env("CARGO_TARGET_DIR", &disk.target)
            .output()
            .expect("a shell runs");
        let shown = String::from_utf8_lossy(&reproduced.stdout);
        assert!(
            reproduced.status.success() && shown.contains("1 passed"),
            "{name} {words:?} {test}: the report's command fails: {command}\n{shown}\n{}",
            String::from_utf8_lossy(&reproduced.stderr)
        );
    }
}

/// What the report's command for a test did after its step ran in a workspace on disk. The report's
/// own run ran the step, so Cargo's record of its build is the step's `built`, and the command then
/// ran in the same target folder.
#[cfg(unix)]
struct Reproduced {
    /// Why the step itself did not end with exit 0 and no error, when it did not.
    step_failed: Option<String>,
    /// The report's command for the test.
    command: String,
    /// The command's exit status.
    exit: Option<i32>,
    /// What the command printed, both streams in the order they came.
    shown: String,
    /// The lines of it that say a crate was compiled.
    compiled: Vec<String>,
    /// The program of each target of the step's build, by the file name Cargo gave it.
    programs: BTreeMap<TargetId, String>,
    /// The programs the command ran, by file name.
    ran: BTreeSet<String>,
    /// Whether the program that the step's build gave the test's target printed the test's `ok` line.
    passed_in_its_program: bool,
}

#[cfg(unix)]
impl Reproduced {
    /// The programs that the step's build gave `targets`.
    fn programs_of(&self, targets: &[&TargetId]) -> BTreeSet<String> {
        targets
            .iter()
            .filter_map(|target| self.programs.get(*target).cloned())
            .collect()
    }

    /// Every program the step's build made.
    fn all_programs(&self) -> BTreeSet<String> {
        self.programs.values().cloned().collect()
    }
}

/// The file name of the program a `Running` line names, which Cargo writes last, in parentheses.
#[cfg(unix)]
fn program_of(line: &str) -> Option<String> {
    let inside = line.trim_end().strip_suffix(')')?;
    let path = &inside[inside.rfind('(')? + 1..];
    Some(path.rsplit('/').next().unwrap_or(path).to_owned())
}

/// Runs the step `cargo <words>` in the workspace `disk` through the report's own run, takes the
/// command the report gives for the test `test` of `target`, and runs it in the same directory and
/// target folder.
#[cfg(unix)]
fn reproduced(disk: &OnDisk, words: &[&str], target: &TargetId, test: &str) -> Reproduced {
    use std::process::Command;
    let step = Step::cargo("rust", "the workspace", words);
    let root = disk.directory.path();
    let evidence = tempfile::tempdir().expect("a directory");
    let lister = lister();
    let environment = [(
        "CARGO_TARGET_DIR".to_owned(),
        disk.target.to_string_lossy().into_owned(),
    )];
    let place = kr_conformance::run::Place {
        root,
        directory: root,
        evidence: evidence.path(),
        environment: &environment,
        lister: &lister,
        deadline: None,
    };
    let executed = kr_conformance::run::execute(&step, 1, &place, &disk.packages);
    let step_failed = (executed.exit != Some(0) || executed.error.is_some()).then(|| {
        format!(
            "exit {:?}, error {:?}, log {}",
            executed.exit, executed.error, executed.log
        )
    });
    let programs: BTreeMap<TargetId, String> = executed
        .binaries
        .iter()
        .filter(|(_, binary)| !binary.executable.starts_with("doc-tests "))
        .filter_map(|(found, binary)| {
            let name = binary.executable.rsplit('/').next()?.to_owned();
            Some((found.clone()?, name))
        })
        .collect();
    let mut map = Map {
        packages: disk.packages.clone(),
        ..Map::default()
    };
    key_in(&mut map, "KR-REQ-03.01", target, test);
    let plan = Plan::of_steps("rust", vec![step.clone()]);
    let command = assembled(plan, &map, &[executed]).identifiers["KR-REQ-03.01"].tests[0]
        .command
        .clone()
        .expect("a command");
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("( {command} ) 2>&1"))
        .current_dir(root)
        .env("CARGO_TARGET_DIR", &disk.target)
        .output()
        .expect("a shell runs");
    let shown = String::from_utf8_lossy(&output.stdout).into_owned();
    let compiled: Vec<String> = shown
        .lines()
        .filter(|line| line.trim_start().starts_with("Compiling "))
        .map(str::to_owned)
        .collect();
    let mut ran = BTreeSet::new();
    let mut passed_in_its_program = false;
    let own = programs.get(target);
    let mut in_own = false;
    for line in shown.lines() {
        if line.trim_start().starts_with("Running ") {
            let program = program_of(line);
            in_own = program.is_some() && program.as_ref() == own;
            ran.extend(program);
        } else if line.trim_start().starts_with("Doc-tests ") {
            in_own = false;
        } else if in_own && line.trim() == format!("test {test} ... ok") {
            passed_in_its_program = true;
        }
    }
    Reproduced {
        step_failed,
        command,
        exit: output.status.code(),
        shown,
        compiled,
        programs,
        ran,
        passed_in_its_program,
    }
}

/// A file `path` of a workspace on disk with the text `text`.
#[cfg(unix)]
fn file(path: &str, text: &str) -> (String, String) {
    (path.to_owned(), text.to_owned())
}

/// A test, as the integration test of a package holds it.
#[cfg(unix)]
const WORKS: &str = "#[test]\nfn works() {}\n";

/// A library with a unit test.
#[cfg(unix)]
const UNIT: &str = "#[cfg(test)]\nmod tests {\n    #[test]\n    fn works() {}\n}\n";

/// A library that tells which of its features are on.
#[cfg(unix)]
fn tells_features(features: &[&str]) -> String {
    features
        .iter()
        .map(|feature| {
            format!("pub fn {feature}_on() -> bool {{\n    cfg!(feature = \"{feature}\")\n}}\n")
        })
        .collect()
}

/// A test of the step's build runs with it in each case below: the case runs the step, then the
/// command in the same target folder, and the command exits 0, compiles nothing, prints the test's
/// `ok` line from the program that the step's build gave the test's target, and starts only programs
/// of that build.
///
/// Here the step gives a feature of each of two packages. A command for the test's package alone
/// keeps both features and is refused: `-p a` does not take `b/g`.
#[cfg(unix)]
#[test]
fn a_command_for_a_step_with_a_feature_in_each_package_runs_in_the_steps_build() {
    let files = [
        file("a/Cargo.toml", &manifest("a", "[features]\nf = []\n")),
        file("a/src/lib.rs", UNIT),
        file("b/Cargo.toml", &manifest("b", "[features]\ng = []\n")),
        file("b/src/lib.rs", ""),
        file("b/tests/tb.rs", WORKS),
    ];
    let disk = on_disk(&["a", "b"], &files);
    let (a, b) = (
        target_of("a", TargetKind::Lib, "a"),
        target_of("b", TargetKind::Lib, "b"),
    );
    let words = [
        "test",
        "--locked",
        "--workspace",
        "--features",
        "a/f,b/g",
        "--",
        "--test-threads",
        "1",
    ];
    let ran = reproduced(&disk, &words, &a, "tests::works");
    assert_eq!(ran.step_failed, None);
    assert_eq!(ran.exit, Some(0), "{}\n{}", ran.command, ran.shown);
    assert_eq!(ran.compiled, Vec::<String>::new(), "{}", ran.command);
    assert!(ran.passed_in_its_program, "{}\n{}", ran.command, ran.shown);
    assert_eq!(ran.ran, ran.programs_of(&[&a, &b]), "{}", ran.command);
    assert!(ran.command.contains(" --lib "), "{}", ran.command);
}

/// Another package of the step turns a feature on in the test's package or in a dependency of it, or
/// the test's package leaves one off, in each workspace of `feature_fixtures`. A command for the
/// test's package alone builds it again with other features.
#[cfg(unix)]
#[test]
fn a_command_runs_in_the_steps_build_where_another_package_turns_a_feature_on() {
    let ta = target_of("a", TargetKind::Test, "ta");
    let fixtures = feature_fixtures();
    for (name, words, test) in [
        ("shared", &["--workspace", "--features", "f"][..], "x_is_on"),
        ("default", &["--workspace"][..], "x_is_on"),
        (
            "optional",
            &["--workspace", "--features", "b/g"][..],
            "dep_is_off",
        ),
        (
            "reached",
            &["--workspace", "--features", "f"][..],
            "f_is_on",
        ),
        ("reached", &["--workspace"][..], "g_is_on"),
        ("reached", &["--workspace"][..], "h_is_on"),
        ("dev", &["--workspace"][..], "x_is_on"),
    ] {
        let disk = &fixtures
            .iter()
            .find(|(label, _)| *label == name)
            .expect("a fixture")
            .1;
        let mut step = vec!["test", "--locked"];
        step.extend(words);
        step.extend(["--", "--test-threads", "1", "--exact", test]);
        let ran = reproduced(disk, &step, &ta, test);
        let row = format!("{name} {words:?} {test}: {}", ran.command);
        assert_eq!(ran.step_failed, None, "{row}");
        assert_eq!(ran.exit, Some(0), "{row}\n{}", ran.shown);
        assert_eq!(ran.compiled, Vec::<String>::new(), "{row}");
        assert!(ran.passed_in_its_program, "{row}\n{}", ran.shown);
        assert_eq!(ran.ran, ran.programs_of(&[&ta]), "{row}");
        assert!(ran.command.contains(" --test ta "), "{row}");
    }
}

/// The package `b` has a target `ta` that needs a feature the step leaves off, so the step does not
/// build it, and Cargo refuses `--workspace --test ta`. The command keeps the step's own target
/// flags, and `a`'s test finds the features of `b` as the step gave them.
#[cfg(unix)]
#[test]
fn a_command_keeps_the_steps_flags_where_another_package_has_a_target_with_its_features_off() {
    let files = [
        file(
            "b/Cargo.toml",
            &manifest(
                "b",
                "[features]\ndefault = [\"g\"]\nf = []\ng = []\n\n[[test]]\nname = \"ta\"\nrequired-features = [\"f\"]\n",
            ),
        ),
        file("b/src/lib.rs", &tells_features(&["f", "g"])),
        file("b/tests/ta.rs", WORKS),
        file(
            "a/Cargo.toml",
            &manifest(
                "a",
                "[dependencies]\nb = { path = \"../b\", default-features = false }\n",
            ),
        ),
        file("a/src/lib.rs", ""),
        file(
            "a/tests/ta.rs",
            "#[test]\nfn features_match() {\n    assert!(b::g_on());\n    assert!(!b::f_on());\n}\n",
        ),
    ];
    let disk = on_disk(&["a", "b"], &files);
    let (ta, b_ta) = (
        target_of("a", TargetKind::Test, "ta"),
        target_of("b", TargetKind::Test, "ta"),
    );
    let words = ["test", "--locked", "--workspace"];
    let ran = reproduced(&disk, &words, &ta, "features_match");
    assert_eq!(ran.step_failed, None);
    assert!(!ran.programs.contains_key(&b_ta), "the step built b's ta");
    assert_eq!(ran.exit, Some(0), "{}\n{}", ran.command, ran.shown);
    assert_eq!(ran.compiled, Vec::<String>::new(), "{}", ran.command);
    assert!(ran.passed_in_its_program, "{}\n{}", ran.command, ran.shown);
    assert!(ran.ran.is_subset(&ran.all_programs()), "{}", ran.command);
    assert!(!ran.command.contains(" --test ta "), "{}", ran.command);
}

/// A step in a virtual workspace that names no package takes every member, and the member `b` has a
/// target `t` that needs a feature the step leaves off. Cargo refuses `--test t` for it, so the
/// command keeps the step's own words, whichever package holds the test.
#[cfg(unix)]
#[test]
fn a_command_keeps_the_steps_flags_where_a_target_of_another_member_has_its_features_off() {
    let files = [
        file("a/Cargo.toml", &manifest("a", "")),
        file("a/src/lib.rs", ""),
        file("a/tests/t.rs", WORKS),
        file(
            "b/Cargo.toml",
            &manifest(
                "b",
                "[features]\nslow = []\n\n[[test]]\nname = \"t\"\nrequired-features = [\"slow\"]\n",
            ),
        ),
        file("b/src/lib.rs", ""),
        file("b/tests/t.rs", WORKS),
    ];
    let disk = on_disk(&["a", "b"], &files);
    let (t, b_t) = (
        target_of("a", TargetKind::Test, "t"),
        target_of("b", TargetKind::Test, "t"),
    );
    let ran = reproduced(&disk, &["test", "--locked"], &t, "works");
    assert_eq!(ran.step_failed, None);
    assert!(!ran.programs.contains_key(&b_t), "the step built b's t");
    assert_eq!(ran.exit, Some(0), "{}\n{}", ran.command, ran.shown);
    assert_eq!(ran.compiled, Vec::<String>::new(), "{}", ran.command);
    assert!(ran.passed_in_its_program, "{}\n{}", ran.command, ran.shown);
    assert!(ran.ran.is_subset(&ran.all_programs()), "{}", ran.command);
    assert!(!ran.command.contains(" --test t "), "{}", ran.command);
}

/// The package `b` has a target `t` with `test = false` and a harness of its own: the step does not
/// build it, and `--test t` would build it and run it. The command keeps the step's own words.
#[cfg(unix)]
#[test]
fn a_command_keeps_the_steps_flags_where_another_package_has_a_target_that_is_not_tested() {
    let files = [
        file("a/Cargo.toml", &manifest("a", "")),
        file("a/src/lib.rs", ""),
        file("a/tests/t.rs", WORKS),
        file(
            "b/Cargo.toml",
            &manifest(
                "b",
                "[[test]]\nname = \"t\"\ntest = false\nharness = false\n",
            ),
        ),
        file("b/src/lib.rs", ""),
        file(
            "b/tests/t.rs",
            "fn main() {\n    println!(\"b t ran with {:?}\", std::env::args().skip(1).collect::<Vec<_>>());\n}\n",
        ),
    ];
    let disk = on_disk(&["a", "b"], &files);
    let (t, b_t) = (
        target_of("a", TargetKind::Test, "t"),
        target_of("b", TargetKind::Test, "t"),
    );
    let ran = reproduced(&disk, &["test", "--locked", "--workspace"], &t, "works");
    assert_eq!(ran.step_failed, None);
    assert!(!ran.programs.contains_key(&b_t), "the step built b's t");
    assert_eq!(ran.exit, Some(0), "{}\n{}", ran.command, ran.shown);
    assert_eq!(ran.compiled, Vec::<String>::new(), "{}", ran.command);
    assert!(ran.passed_in_its_program, "{}\n{}", ran.command, ran.shown);
    assert!(ran.ran.is_subset(&ran.all_programs()), "{}", ran.command);
    assert!(!ran.command.contains(" --test t "), "{}", ran.command);
}

/// The package `b` has a library with `test = false` that does not compile as a test: the step does
/// not build it as one, and `--lib` would. The command keeps the step's own words.
#[cfg(unix)]
#[test]
fn a_command_keeps_the_steps_flags_where_another_package_has_a_library_that_is_not_tested() {
    let files = [
        file("a/Cargo.toml", &manifest("a", "")),
        file("a/src/lib.rs", UNIT),
        file("b/Cargo.toml", &manifest("b", "[lib]\ntest = false\n")),
        file(
            "b/src/lib.rs",
            "#[cfg(test)]\ncompile_error!(\"b is not built to test\");\n",
        ),
    ];
    let disk = on_disk(&["a", "b"], &files);
    let (a, b) = (
        target_of("a", TargetKind::Lib, "a"),
        target_of("b", TargetKind::Lib, "b"),
    );
    let ran = reproduced(
        &disk,
        &["test", "--locked", "--workspace"],
        &a,
        "tests::works",
    );
    assert_eq!(ran.step_failed, None);
    assert!(!ran.programs.contains_key(&b), "the step built b's library");
    assert_eq!(ran.exit, Some(0), "{}\n{}", ran.command, ran.shown);
    assert_eq!(ran.compiled, Vec::<String>::new(), "{}", ran.command);
    assert!(ran.passed_in_its_program, "{}\n{}", ran.command, ran.shown);
    assert!(ran.ran.is_subset(&ran.all_programs()), "{}", ran.command);
    assert!(!ran.command.contains(" --lib "), "{}", ran.command);
}

/// A step with no package flag in a workspace whose root package is the only default member: the
/// command gives no package flag either, because `--workspace` would take the member `m` and its
/// target `t` that needs a feature the step leaves off.
#[cfg(unix)]
#[test]
fn a_command_gives_no_package_flag_where_the_step_gave_none_in_a_workspace_with_a_root_package() {
    let files = [
        file(
            "Cargo.toml",
            &manifest("r", "[workspace]\nresolver = \"3\"\nmembers = [\"m\"]\n"),
        ),
        file("src/lib.rs", ""),
        file("tests/t.rs", WORKS),
        file(
            "m/Cargo.toml",
            &manifest(
                "m",
                "[features]\nslow = []\n\n[[test]]\nname = \"t\"\nrequired-features = [\"slow\"]\n",
            ),
        ),
        file("m/src/lib.rs", ""),
        file("m/tests/t.rs", WORKS),
    ];
    let disk = on_disk(&["m"], &files);
    let (t, m_t) = (
        target_of("r", TargetKind::Test, "t"),
        target_of("m", TargetKind::Test, "t"),
    );
    let ran = reproduced(&disk, &["test", "--locked"], &t, "works");
    assert_eq!(ran.step_failed, None);
    assert!(!ran.programs.contains_key(&m_t), "the step built m's t");
    assert_eq!(ran.exit, Some(0), "{}\n{}", ran.command, ran.shown);
    assert_eq!(ran.compiled, Vec::<String>::new(), "{}", ran.command);
    assert!(ran.passed_in_its_program, "{}\n{}", ran.command, ran.shown);
    assert_eq!(ran.ran, ran.programs_of(&[&t]), "{}", ran.command);
    assert!(ran.command.contains(" --test t "), "{}", ran.command);
    assert!(!ran.command.contains("--workspace"), "{}", ran.command);
}

/// A `-p` name that no member has selects a package of the dependency graph, which the report does
/// not read. Here `ext` is outside the workspace and has a target `t` that needs a feature the step
/// leaves off, so the step does not build it, and Cargo refuses `--test t` for it. The command keeps
/// the step's own flags, and every program of the step's build runs.
#[cfg(unix)]
#[test]
fn a_command_keeps_the_steps_flags_where_the_step_names_a_package_that_no_member_has() {
    let files = [
        file(
            "Cargo.toml",
            &manifest(
                "a",
                "[dependencies]\next = { path = \"ext\" }\n\n[workspace]\nexclude = [\"ext\"]\n",
            ),
        ),
        file("src/lib.rs", UNIT),
        file("tests/t.rs", WORKS),
        file(
            "ext/Cargo.toml",
            &manifest(
                "ext",
                "[features]\nslow = []\n\n[lib]\ntest = false\ndoctest = false\n\n[[test]]\nname = \"t\"\nrequired-features = [\"slow\"]\n",
            ),
        ),
        file("ext/src/lib.rs", ""),
        file("ext/tests/t.rs", WORKS),
    ];
    let disk = on_disk(&[], &files);
    let (a_t, ext_t) = (
        target_of("a", TargetKind::Test, "t"),
        target_of("ext", TargetKind::Test, "t"),
    );
    let ran = reproduced(
        &disk,
        &["test", "--locked", "-p", "a", "-p", "ext"],
        &a_t,
        "works",
    );
    assert_eq!(ran.step_failed, None);
    assert!(!ran.programs.contains_key(&ext_t), "the step built ext's t");
    assert_eq!(ran.exit, Some(0), "{}\n{}", ran.command, ran.shown);
    assert_eq!(ran.compiled, Vec::<String>::new(), "{}", ran.command);
    assert!(ran.passed_in_its_program, "{}\n{}", ran.command, ran.shown);
    assert_eq!(ran.ran, ran.all_programs(), "{}", ran.command);
    assert!(!ran.command.contains(" --test "), "{}", ran.command);
}

/// Two packages each have the target `ta`, and the step built both: the test's own flag names both,
/// both run, and no other program of the step does.
#[cfg(unix)]
#[test]
fn a_command_starts_only_the_programs_its_target_flag_names_in_the_steps_packages() {
    let files = [
        file("a/Cargo.toml", &manifest("a", "")),
        file("a/src/lib.rs", UNIT),
        file("a/tests/ta.rs", WORKS),
        file("b/Cargo.toml", &manifest("b", "")),
        file("b/src/lib.rs", UNIT),
        file("b/tests/ta.rs", WORKS),
    ];
    let disk = on_disk(&["a", "b"], &files);
    let (a_ta, b_ta) = (
        target_of("a", TargetKind::Test, "ta"),
        target_of("b", TargetKind::Test, "ta"),
    );
    let ran = reproduced(&disk, &["test", "--locked", "--workspace"], &a_ta, "works");
    assert_eq!(ran.step_failed, None);
    assert_eq!(ran.exit, Some(0), "{}\n{}", ran.command, ran.shown);
    assert_eq!(ran.compiled, Vec::<String>::new(), "{}", ran.command);
    assert!(ran.passed_in_its_program, "{}\n{}", ran.command, ran.shown);
    assert!(ran.ran.is_subset(&ran.all_programs()), "{}", ran.command);
    assert_eq!(
        ran.ran,
        ran.programs_of(&[&a_ta, &b_ta]),
        "{}\n{}",
        ran.command,
        ran.shown
    );
    assert!(ran.command.contains(" --test ta "), "{}", ran.command);
}

/// The step gives a test name, and a target of another package has its features off, so the command
/// keeps the step's own words, the name included. After `--` that name is one more exact name: the
/// step's `check` runs as well as `check_one`.
#[cfg(unix)]
#[test]
fn a_command_keeps_a_test_name_of_its_step_as_one_more_exact_name() {
    let files = [
        file("a/Cargo.toml", &manifest("a", "")),
        file("a/src/lib.rs", ""),
        file(
            "a/tests/t.rs",
            "#[test]\nfn check() {}\n\n#[test]\nfn check_one() {}\n",
        ),
        file(
            "b/Cargo.toml",
            &manifest(
                "b",
                "[features]\nslow = []\n\n[[test]]\nname = \"t\"\nrequired-features = [\"slow\"]\n",
            ),
        ),
        file("b/src/lib.rs", ""),
        file("b/tests/t.rs", WORKS),
    ];
    let disk = on_disk(&["a", "b"], &files);
    let (t, b_t) = (
        target_of("a", TargetKind::Test, "t"),
        target_of("b", TargetKind::Test, "t"),
    );
    let ran = reproduced(&disk, &["test", "--locked", "check"], &t, "check_one");
    assert_eq!(ran.step_failed, None);
    assert!(!ran.programs.contains_key(&b_t), "the step built b's t");
    assert_eq!(ran.exit, Some(0), "{}\n{}", ran.command, ran.shown);
    assert_eq!(ran.compiled, Vec::<String>::new(), "{}", ran.command);
    assert!(ran.passed_in_its_program, "{}\n{}", ran.command, ran.shown);
    assert!(
        ran.command.ends_with("check -- --exact check_one"),
        "{}",
        ran.command
    );
    assert!(
        ran.shown
            .lines()
            .any(|line| line.trim() == "test check ... ok"),
        "{}\n{}",
        ran.command,
        ran.shown
    );
}

/// A program with a harness of its own that the step built, and that the test's own flag names in
/// another package, reads its own arguments: it ignores `--exact` and the test's name and runs
/// everything it holds.
#[cfg(unix)]
#[test]
fn a_program_with_a_harness_of_its_own_that_the_command_starts_runs_everything_it_holds() {
    let files = [
        file("a/Cargo.toml", &manifest("a", "")),
        file("a/src/lib.rs", ""),
        file("a/tests/ta.rs", WORKS),
        file(
            "b/Cargo.toml",
            &manifest("b", "[[test]]\nname = \"ta\"\nharness = false\n"),
        ),
        file("b/src/lib.rs", ""),
        file(
            "b/tests/ta.rs",
            "fn main() {\n    println!(\"b ta ran everything, given {:?}\", std::env::args().skip(1).collect::<Vec<_>>());\n}\n",
        ),
    ];
    let disk = on_disk(&["a", "b"], &files);
    let a_ta = target_of("a", TargetKind::Test, "ta");
    let ran = reproduced(&disk, &["test", "--locked", "--workspace"], &a_ta, "works");
    assert_eq!(ran.step_failed, None);
    assert_eq!(ran.exit, Some(0), "{}\n{}", ran.command, ran.shown);
    assert_eq!(ran.compiled, Vec::<String>::new(), "{}", ran.command);
    assert!(ran.passed_in_its_program, "{}\n{}", ran.command, ran.shown);
    assert!(ran.command.contains(" --test ta "), "{}", ran.command);
    assert!(
        ran.shown
            .contains("b ta ran everything, given [\"--exact\", \"works\"]"),
        "{}\n{}",
        ran.command,
        ran.shown
    );
}

/// A test that no step covers, in a target that needs a feature, gets `--features` with it, and
/// Cargo accepts the command.
#[cfg(unix)]
#[test]
fn a_command_for_a_test_no_step_covers_gives_the_features_its_target_needs() {
    let files = [
        file(
            "m/Cargo.toml",
            &manifest(
                "m",
                "[features]\nsuite = []\n\n[[test]]\nname = \"u\"\nrequired-features = [\"suite\"]\n",
            ),
        ),
        file("m/src/lib.rs", ""),
        file("m/tests/u.rs", WORKS),
        file("q/Cargo.toml", &manifest("q", "")),
        file("q/src/lib.rs", ""),
    ];
    let disk = on_disk(&["m", "q"], &files);
    let u = target_of("m", TargetKind::Test, "u");
    let ran = reproduced(&disk, &["test", "--locked", "-p", "q"], &u, "works");
    assert_eq!(ran.step_failed, None);
    assert_eq!(ran.exit, Some(0), "{}\n{}", ran.command, ran.shown);
    assert_eq!(
        ran.command,
        "cargo test --locked -p m --features suite --test u -- --exact works"
    );
    assert!(
        ran.shown
            .lines()
            .any(|line| line.trim() == "test works ... ok"),
        "{}\n{}",
        ran.command,
        ran.shown
    );
}

/// A step that gives `--ignore-rust-version` over a package whose `rust-version` the toolchain does
/// not meet: the command keeps the word, which `Selection` does not read, so Cargo accepts it.
#[cfg(unix)]
#[test]
fn a_command_keeps_a_word_of_its_step_that_the_selection_does_not_read() {
    let files = [
        file("a/Cargo.toml", &manifest("a", "rust-version = \"1.999\"\n")),
        file("a/src/lib.rs", UNIT),
    ];
    let disk = on_disk(&["a"], &files);
    let a = target_of("a", TargetKind::Lib, "a");
    let words = ["test", "--locked", "--workspace", "--ignore-rust-version"];
    let ran = reproduced(&disk, &words, &a, "tests::works");
    assert_eq!(ran.step_failed, None);
    assert_eq!(ran.exit, Some(0), "{}\n{}", ran.command, ran.shown);
    assert_eq!(ran.compiled, Vec::<String>::new(), "{}", ran.command);
    assert!(ran.passed_in_its_program, "{}\n{}", ran.command, ran.shown);
    assert_eq!(ran.ran, ran.programs_of(&[&a]), "{}", ran.command);
    assert!(
        ran.command.contains(" --ignore-rust-version "),
        "{}",
        ran.command
    );
}

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// Core's own plan file.
fn core_plan() -> Plan {
    Plan::load(&repository(), None).expect("core's plan file")
}

/// The selection of the Rust group alone.
fn rust_group() -> Vec<String> {
    vec!["rust".to_owned()]
}

/// The word that follows `flag` in a step's command.
fn word_after(step: &Step, flag: &str) -> Option<String> {
    let at = step.command.iter().position(|word| word == flag)?;
    step.command.get(at + 1).cloned()
}

/// What `scripts/end-to-end.sh` runs, against the plan's end-to-end steps.
fn end_to_end_drift(plan: &Plan) -> Result<(), String> {
    let script = std::fs::read_to_string(repository().join("scripts").join("end-to-end.sh"))
        .expect("the script");
    let listed: Vec<(String, String)> = script
        .lines()
        .filter_map(|line| line.trim().strip_prefix('"'))
        .filter_map(|entry| entry.split_once('|'))
        .filter_map(|(target, _)| target.split_once(':'))
        .map(|(package, suite)| (package.to_owned(), suite.to_owned()))
        .collect();
    // Each Linux step of the group is the build of the worker that the network suite launches, held
    // to its whole command, or a suite: no step passes unread.
    let worker_build = [
        "cargo",
        "build",
        "--locked",
        "-p",
        "kr-worker",
        "--bin",
        "kr-worker",
    ];
    let mut steps: Vec<(Step, (String, String))> = Vec::new();
    let mut builds = 0;
    for step in plan.steps(
        Platform::Linux,
        &["end-to-end".to_owned()],
        &Values::evidence("/tmp/e"),
        None,
    ) {
        if step.reading == Reading::Build {
            if step.command != worker_build {
                return Err(format!(
                    "the end-to-end build step runs {:?}, not {worker_build:?}",
                    step.command
                ));
            }
            builds += 1;
            continue;
        }
        match (word_after(&step, "-p"), word_after(&step, "--test")) {
            (Some(package), Some(suite)) if step.reading == Reading::Cargo => {
                steps.push((step, (package, suite)));
            }
            _ => {
                return Err(format!(
                    "the end-to-end step `{}` is neither the build of the worker nor a suite: {:?}",
                    step.what, step.command
                ));
            }
        }
    }
    if builds != 1 {
        return Err(format!(
            "the end-to-end group has {builds} build steps of the worker, not one"
        ));
    }
    let planned: Vec<(String, String)> = steps.iter().map(|(_, suite)| suite.clone()).collect();
    if planned != listed {
        return Err(format!(
            "scripts/end-to-end.sh's suites, in its order: {listed:?} against the plan's {planned:?}"
        ));
    }
    // Each suite runs as the script runs it: one test at a time, the network suite with its ignored
    // tests as well, and on the platforms the script is run on.
    for (step, (package, suite)) in &steps {
        let mut expected: Vec<String> = [
            "cargo",
            "test",
            "--locked",
            "-p",
            package,
            "--test",
            suite,
            "--",
            "--test-threads=1",
        ]
        .map(str::to_owned)
        .to_vec();
        if suite == "network" {
            expected.push("--include-ignored".to_owned());
        }
        expected.push("--show-output".to_owned());
        if step.command != expected {
            return Err(format!(
                "the end-to-end step for {package} {suite} runs {:?}, not {expected:?}",
                step.command
            ));
        }
    }
    for step in plan.steps.iter().filter(|step| step.group == "end-to-end") {
        if step.platforms != [Platform::Linux, Platform::MacOs] {
            return Err(format!(
                "the end-to-end step {} runs on {:?}, not on Linux and macOS",
                step.id, step.platforms
            ));
        }
    }
    if !script.contains("-- --test-threads=1 $ignored") {
        return Err("the script runs one test at a time".to_owned());
    }
    if !script.contains("if [ \"$suite\" = \"network\" ]; then\n    ignored=\"--include-ignored\"")
    {
        return Err("the script includes the ignored tests of the network suite".to_owned());
    }
    Ok(())
}

#[test]
fn the_end_to_end_group_runs_what_the_end_to_end_script_runs() {
    assert_eq!(end_to_end_drift(&core_plan()), Ok(()));
}

/// The `cargo test` commands a job of the landing workflow runs, each as one line: a folded value
/// is joined, and each line of a literal block is its own command.
fn workflow_commands(job: &str, program: &str) -> Vec<String> {
    let workflow = std::fs::read_to_string(
        repository()
            .join(".github")
            .join("workflows")
            .join("core-ci.yml"),
    )
    .expect("the landing workflow");
    let lines: Vec<&str> = workflow.lines().collect();
    let header = format!("  {job}:");
    let start = lines
        .iter()
        .position(|line| *line == header)
        .unwrap_or_else(|| panic!("the workflow has a {job} job"));
    let is_job = |line: &str| {
        line.len() > 3
            && line.starts_with("  ")
            && !line.starts_with("   ")
            && line.trim_end().ends_with(':')
    };
    let end = lines[start + 1..]
        .iter()
        .position(|line| is_job(line))
        .map_or(lines.len(), |offset| start + 1 + offset);
    let mut commands = Vec::new();
    let mut at = start;
    while at < end {
        let line = lines[at];
        at += 1;
        let Some(value) = line.trim_start().strip_prefix("run:") else {
            continue;
        };
        let indent = line.len() - line.trim_start().len();
        let value = value.trim();
        let mut block = Vec::new();
        while at < end
            && (lines[at].trim().is_empty()
                || lines[at].len() - lines[at].trim_start().len() > indent)
        {
            block.push(lines[at].trim());
            at += 1;
        }
        let found: Vec<String> = match value {
            ">-" | ">" => vec![block.join(" ")],
            "|" | "|-" => block.iter().map(|line| (*line).to_owned()).collect(),
            quoted if quoted.starts_with('"') => vec![quoted.trim_matches('"').to_owned()],
            plain => vec![plain.to_owned()],
        };
        commands.extend(
            found
                .into_iter()
                .filter(|command| command.starts_with(program)),
        );
    }
    commands
}

/// A command with the flags that only say how output is shown taken out, a `--` left with nothing
/// after it as well, and its words spaced once.
fn without_display(command: &str) -> String {
    let mut words: Vec<&str> = command
        .split_whitespace()
        .filter(|word| !matches!(*word, "--nocapture" | "--show-output"))
        .collect();
    if words.last() == Some(&"--") {
        words.pop();
    }
    words.join(" ")
}

/// The test steps the plan holds for Windows are the tests the landing workflow's Windows job runs,
/// its build steps are builds that job also runs, and the workspace step it holds for macOS leaves
/// out, by name, the cases the macOS job's workspace run leaves out.
fn platform_drift(plan: &Plan) -> Result<(), String> {
    // Windows: every `cargo test` of the workflow's Windows job is a step, and every test step is
    // one; what the plan builds first, the Windows job builds too.
    let mut workflow: Vec<String> = workflow_commands("windows", "cargo test")
        .iter()
        .map(|command| without_display(command))
        .collect();
    let (builds, tests): (Vec<Step>, Vec<Step>) = plan
        .steps(
            Platform::Windows,
            &plan.all_groups(),
            &Values::evidence("/tmp/e"),
            None,
        )
        .into_iter()
        .partition(|step| step.command.get(1).is_some_and(|word| word == "build"));
    let mut planned: Vec<String> = tests
        .iter()
        .map(|step| without_display(&step.line()))
        .collect();
    workflow.sort();
    workflow.dedup();
    planned.sort();
    if planned != workflow {
        return Err(format!(
            "the Windows job's tests: {planned:?} against {workflow:?}"
        ));
    }
    let built = workflow_commands("windows", "cargo build");
    if builds.is_empty() {
        return Err("the plan builds nothing first on Windows".to_owned());
    }
    for step in &builds {
        if !built.contains(&step.line()) {
            return Err(format!("{} among {built:?}", step.line()));
        }
    }

    // macOS: the workspace step leaves out what the workflow's macOS job leaves out, by name.
    let workspace = workflow_commands("macos", "cargo test")
        .into_iter()
        .find(|command| command.starts_with("cargo test --locked --workspace"))
        .expect("the macOS job's workspace run");
    let mut left_out: Vec<String> = workspace
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .filter(|pair| pair[0] == "--skip")
        .map(|pair| pair[1].to_owned())
        .collect();
    let mut skipped: Vec<String> = plan.steps(
        Platform::MacOs,
        &rust_group(),
        &Values::evidence("/tmp/e"),
        None,
    )[0]
    .skips
    .iter()
    .map(|(name, _)| name.clone())
    .collect();
    left_out.sort();
    skipped.sort();
    if skipped != left_out {
        return Err(format!(
            "the macOS job's workspace run: {skipped:?} against {left_out:?}"
        ));
    }
    Ok(())
}

/// KR-REQ-29.01, the part about reproducible commands: the platform plans run what the landing
/// workflow runs there.
#[test]
fn the_platform_plans_run_what_the_landing_workflow_runs_there() {
    assert_eq!(platform_drift(&core_plan()), Ok(()));
}

/// What `scripts/performance.sh` measures, against the plan's performance steps.
fn performance_drift(plan: &Plan) -> Result<(), String> {
    let script = std::fs::read_to_string(repository().join("scripts").join("performance.sh"))
        .expect("the script");
    let listed: Vec<(String, String)> = script
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (kind, rest) = line.strip_prefix("measurement_in --")?.split_once(' ')?;
            let (target, name) = rest.split_once(' ')?;
            let name = name.strip_suffix(" || failed=1")?;
            Some((format!("{kind} {target}"), name.to_owned()))
        })
        .collect();
    // Each Linux step that selects a test by its exact name is a measurement of a test or a bench
    // target: none passes unread.
    let mut measurements: Vec<(Step, (String, String))> = Vec::new();
    for step in plan
        .steps(
            Platform::Linux,
            &["performance".to_owned()],
            &Values::evidence("/tmp/e"),
            None,
        )
        .into_iter()
        .filter(|step| step.command.iter().any(|word| word == "--exact"))
    {
        let target = word_after(&step, "--test")
            .map(|target| ("test", target))
            .or_else(|| word_after(&step, "--bench").map(|target| ("bench", target)));
        let (Some((kind, target)), Some(name)) = (target, step.command.last().cloned()) else {
            return Err(format!(
                "the performance step `{}` selects by `--exact` and names no test or bench target: {:?}",
                step.what, step.command
            ));
        };
        measurements.push((step, (format!("{kind} {target}"), name)));
    }
    let planned: Vec<(String, String)> = measurements
        .iter()
        .map(|(_, measurement)| measurement.clone())
        .collect();
    if planned != listed {
        return Err(format!(
            "scripts/performance.sh's measurements, in its order: {listed:?} against the plan's {planned:?}"
        ));
    }
    // Each measurement runs as the script runs it: in release, by its exact name, ignored and
    // uncaptured, and on the platforms the script is run on.
    for (step, (target, name)) in &measurements {
        let (kind, target) = target.split_once(' ').expect("a kind and a target");
        let flag = format!("--{kind}");
        let expected: Vec<&str> = [
            "cargo",
            "test",
            "--locked",
            "--release",
            "-p",
            "kr-worker",
            flag.as_str(),
            target,
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
            name.as_str(),
        ]
        .to_vec();
        if step.command != expected {
            return Err(format!(
                "the measurement {name} runs {:?}, not {expected:?}",
                step.command
            ));
        }
    }
    for step in plan.steps.iter().filter(|step| step.group == "performance") {
        if step.platforms != [Platform::Linux, Platform::MacOs] {
            return Err(format!(
                "the performance step {} runs on {:?}, not on Linux and macOS",
                step.id, step.platforms
            ));
        }
    }
    if !script.contains("-- --ignored --exact --nocapture \"$name\"") {
        return Err("the script runs each measurement exactly, uncaptured".to_owned());
    }
    Ok(())
}

#[test]
fn the_performance_group_takes_what_the_performance_script_takes() {
    assert_eq!(performance_drift(&core_plan()), Ok(()));
}

/// The two group names `scripts/run-conformance.sh` selects by, against the plan's groups.
fn script_groups_drift(plan: &Plan) -> Result<(), String> {
    let script = std::fs::read_to_string(repository().join("scripts").join("run-conformance.sh"))
        .expect("the script");
    let used: Vec<&str> = script
        .lines()
        .filter_map(|line| line.trim().strip_prefix("if selected "))
        .filter_map(|rest| rest.split(';').next())
        .collect();
    if used != ["applications", "typescript"] {
        return Err(format!("the script selects by {used:?}"));
    }
    for name in used {
        if !plan.groups.iter().any(|group| group == name) {
            return Err(format!(
                "the script selects by {name}, which the plan has no group of"
            ));
        }
    }
    Ok(())
}

#[test]
fn the_groups_the_conformance_script_selects_by_are_the_plans() {
    assert_eq!(script_groups_drift(&core_plan()), Ok(()));
}

/// Each drift case fails once, against a planted edit of an in-memory copy of the file: a suite
/// dropped from the end-to-end steps, a Windows step's command edited, a macOS skip removed, a
/// group name edited against the script that selects by it.
#[test]
fn each_drift_case_fails_against_a_planted_edit_of_a_copy_of_the_file() {
    let plan = core_plan();

    let mut dropped = plan.clone();
    let at = dropped
        .steps
        .iter()
        .position(|step| {
            step.group == "end-to-end" && step.command.iter().any(|word| word == "--test")
        })
        .expect("an end-to-end suite");
    dropped.steps.remove(at);
    assert!(end_to_end_drift(&dropped).is_err());

    let mut edited = plan.clone();
    let windows = edited
        .steps
        .iter_mut()
        .find(|step| {
            step.platforms == [Platform::Windows]
                && step.reading == kr_conformance::plan_file::ReadingKind::Cargo
        })
        .expect("a Windows test step");
    windows.command.push("--quiet".to_owned());
    assert!(platform_drift(&edited).is_err());

    let mut kept = plan.clone();
    let macos = kept
        .steps
        .iter_mut()
        .find(|step| step.platforms == [Platform::MacOs] && !step.skips.is_empty())
        .expect("the macOS workspace step");
    macos.skips.remove(0);
    assert!(platform_drift(&kept).is_err());

    let mut measured = plan.clone();
    let at = measured
        .steps
        .iter()
        .position(|step| {
            step.group == "performance" && step.command.iter().any(|word| word == "--exact")
        })
        .expect("a measurement");
    measured.steps.remove(at);
    assert!(performance_drift(&measured).is_err());

    // A flag removed from one step, and a platform changed on one step, for each of the guards of
    // the end-to-end suites and the measurements.
    let step_of = |plan: &Plan, group: &str, word: &str| {
        plan.steps
            .iter()
            .position(|step| step.group == group && step.command.iter().any(|each| each == word))
            .unwrap_or_else(|| panic!("a {group} step with {word}"))
    };
    let mut serial = plan.clone();
    let at = step_of(&serial, "end-to-end", "--test-threads=1");
    serial.steps[at]
        .command
        .retain(|word| word != "--test-threads=1");
    let refused = end_to_end_drift(&serial).expect_err("a suite not run one test at a time");
    assert!(refused.contains("the end-to-end step for"), "{refused}");

    let mut network = plan.clone();
    let at = step_of(&network, "end-to-end", "--include-ignored");
    network.steps[at]
        .command
        .retain(|word| word != "--include-ignored");
    let refused =
        end_to_end_drift(&network).expect_err("a network suite without its ignored tests");
    assert!(refused.contains("the end-to-end step for"), "{refused}");

    let mut elsewhere = plan.clone();
    let at = step_of(&elsewhere, "end-to-end", "--test-threads=1");
    elsewhere.steps[at].platforms.push(Platform::Windows);
    let refused =
        end_to_end_drift(&elsewhere).expect_err("a suite on a platform the script is not run on");
    assert!(refused.contains("runs on"), "{refused}");

    let mut ignored = plan.clone();
    let at = step_of(&ignored, "performance", "--ignored");
    ignored.steps[at].command.retain(|word| word != "--ignored");
    let refused = performance_drift(&ignored)
        .expect_err("a measurement that runs its ignored tests no longer");
    assert!(refused.contains("the measurement"), "{refused}");

    // A step that the guards cannot parse is refused, not skipped: a suite with no `--test`, a
    // build of the worker that is not the plan's own, and a measurement with no target.
    let mut loose = plan.clone();
    let at = step_of(&loose, "end-to-end", "--test-threads=1");
    let mut extra = loose.steps[at].clone();
    extra.command = [
        "cargo",
        "test",
        "--locked",
        "-p",
        "kr-worker",
        "--",
        "--test-threads=1",
    ]
    .map(str::to_owned)
    .to_vec();
    loose.steps.push(extra);
    let refused = end_to_end_drift(&loose).expect_err("an end-to-end step that is no suite");
    assert!(
        refused.contains("is neither the build of the worker nor a suite"),
        "{refused}"
    );

    let mut built = plan.clone();
    let at = step_of(&built, "end-to-end", "build");
    built.steps[at]
        .command
        .retain(|word| word != "--bin" && word != "kr-worker");
    let refused =
        end_to_end_drift(&built).expect_err("a build of the worker that is not the plan's");
    assert!(
        refused.contains("the end-to-end build step runs"),
        "{refused}"
    );

    let mut targetless = plan.clone();
    let at = step_of(&targetless, "performance", "--exact");
    let mut extra = targetless.steps[at].clone();
    extra.command = [
        "cargo",
        "test",
        "--locked",
        "--release",
        "-p",
        "kr-worker",
        "--",
        "--exact",
        "x",
    ]
    .map(str::to_owned)
    .to_vec();
    targetless.steps.push(extra);
    let refused = performance_drift(&targetless).expect_err("a measurement with no target");
    assert!(
        refused.contains("names no test or bench target"),
        "{refused}"
    );

    let mut moved = plan.clone();
    let at = step_of(&moved, "performance", "--ignored");
    moved.steps[at].platforms = vec![Platform::Linux];
    let refused = performance_drift(&moved).expect_err("a measurement on one platform only");
    assert!(refused.contains("runs on"), "{refused}");

    let mut renamed = plan;
    renamed.groups[3] = "javascript".to_owned();
    assert!(script_groups_drift(&renamed).is_err());
}

/// KR-REQ-29.01, the part about mapping tests to acceptance identifiers, in TypeScript: a key in a
/// file's header, in a suite's comment, above or inside a test, in a test's title and in a table of
/// cases maps the tests it covers to the identifier it names, and a mention that keys nothing is
/// only a reference.
#[test]
#[ignore = "reads TypeScript with the packages' own compiler, which `pnpm install --frozen-lockfile` installs; the report's typescript group runs it"]
fn typescript_comment_forms_and_titles_key_their_tests() {
    let map = map_of("typescript", true);
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    let keyed = keyed(&map);
    let all = [
        "the forms has a comment inside",
        "the forms holds %s",
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
    // A table of cases is keyed at the line a run reports each of its rows at: where the call that
    // takes the title opens its arguments, after the table.
    let table: Vec<usize> = map.keys[&identifier("KR-REQ-06.07")]
        .keys()
        .filter_map(|place| match place {
            Place::TypeScript { line, .. } => Some(*line),
            _ => None,
        })
        .collect();
    assert_eq!(table, [26]);
}
