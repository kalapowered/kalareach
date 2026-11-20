//! Where the report finds what it reads, and what the plan file says about it: the manifests of the
//! Rust workspaces, the TypeScript packages and the compiler that reads them, the directories read as
//! scripts and for lanes, and whether a tree is held to its ignored-run entries.
//!
//! Each case maps a copy of a tree under `tests/fixtures/`, made a Git repository first because the
//! loader reads a plan's scripts through Git's index. The cases that read TypeScript are ignored: the
//! compiler comes from this repository's own `apps/companion`, which `pnpm install --frozen-lockfile`
//! installs, and the report's typescript group runs them.

use std::path::{Path, PathBuf};
use std::process::Command;

use kr_conformance::id::Identifier;
use kr_conformance::map::Map;
use kr_conformance::plan::Platform;
use kr_conformance::plan_file::Plan;
use kr_conformance::report::{self, Options};

/// This repository's root.
fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the repository's root")
}

/// The directory whose installed compiler the TypeScript cases read with.
fn compiler() -> PathBuf {
    repository().join("apps").join("companion")
}

fn identifier(text: &str) -> Identifier {
    text.parse().expect("an identifier")
}

fn git(root: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn copy_into(from: &Path, to: &Path, skip: &dyn Fn(&str) -> bool) {
    std::fs::create_dir_all(to).expect("a directory");
    for entry in std::fs::read_dir(from).expect("the fixture") {
        let entry = entry.expect("an entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        let target = to.join(&name);
        if entry.file_type().expect("a type").is_dir() {
            copy_into(&entry.path(), &target, skip);
        } else if !skip(&target.to_string_lossy().replace('\\', "/")) {
            std::fs::copy(entry.path(), &target).expect("a file");
        }
    }
}

/// A copy of the fixture `name` in a directory of its own, made a Git repository whose index holds
/// every file. No commit is made, so a case that reads the commit gets `unknown`.
fn copy_without(name: &str, skip: &dyn Fn(&str) -> bool) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("a directory");
    let root = directory.path().canonicalize().expect("the copy's root");
    copy_into(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name),
        &root,
        skip,
    );
    git(&root, &["init", "-q"]);
    git(&root, &["add", "-A"]);
    (directory, root)
}

fn copy(name: &str) -> (tempfile::TempDir, PathBuf) {
    copy_without(name, &|_| false)
}

fn plan_text(root: &Path) -> String {
    std::fs::read_to_string(root.join("conformance").join("plan.toml")).expect("the fixture's plan")
}

fn load(root: &Path) -> Plan {
    Plan::load(root, None).unwrap_or_else(|refusal| panic!("the fixture's plan loads: {refusal}"))
}

fn options(root: &Path, plan: Plan, compiler: Option<&Path>) -> Options {
    Options {
        root: root.to_path_buf(),
        evidence: PathBuf::new(),
        selection: Some(Vec::new()),
        all_terminals: false,
        platform: Platform::current(),
        plan,
        typescript_compiler: compiler.map(Path::to_path_buf),
        applications: None,
        environment: Vec::new(),
        lister: PathBuf::new(),
        part: None,
        runner_base: PathBuf::new(),
    }
}

fn map_of(root: &Path, plan: Plan, compiler: Option<&Path>, typescript: bool) -> Map {
    report::map_declared(&options(root, plan, compiler), typescript)
}

/// Runs the program with `arguments` and returns its exit code, what it wrote to stdout and what it
/// wrote to stderr.
fn program(arguments: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_kr-conformance"))
        .args(arguments)
        .output()
        .expect("the program runs");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn sources(map: &Map, row: &str) -> Vec<String> {
    map.keys
        .get(&identifier(row))
        .map(|places| places.values().map(|key| key.source.clone()).collect())
        .unwrap_or_default()
}

/// The refusal of `text` as a plan of the repository at `root`.
fn refusal(text: &str, root: &Path) -> String {
    Plan::parse(text, root)
        .expect_err("the plan is refused")
        .to_string()
}

/// KR-REQ-29.01, the part about mapping tests to acceptance identifiers: a repository with no
/// manifest at its root maps every workspace its plan names, each file named relative to the tested
/// root, and what the plan leaves out of its manifests is not mapped.
#[test]
fn a_repository_with_no_root_manifest_maps_each_workspace_its_plan_names() {
    let (_directory, root) = copy("no-root-manifest");
    let plan = load(&root);
    let map = map_of(&root, plan.clone(), None, false);
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    assert_eq!(sources(&map, "KR-REQ-03.01"), ["first/tests/flow.rs:1"]);
    assert_eq!(sources(&map, "KR-REQ-03.02"), ["first/tests/flow.rs:5"]);
    assert_eq!(sources(&map, "KR-REQ-04.01"), ["second/tests/flow.rs:1"]);
    assert_eq!(sources(&map, "KR-REQ-04.02"), ["second/tests/flow.rs:5"]);
    let (code, stdout, stderr) = program(&["map", "--root", &root.to_string_lossy()]);
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(
        stdout.starts_with("4 identifiers keyed to 4 tests;"),
        "{stdout}"
    );
    // Only the first manifest: the second workspace is not read.
    let only_first = plan_text(&root).replace(
        "'first/Cargo.toml', 'second/Cargo.toml'",
        "'first/Cargo.toml'",
    );
    let map = map_of(
        &root,
        Plan::parse(&only_first, &root).expect("a plan of one manifest"),
        None,
        false,
    );
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    assert_eq!(sources(&map, "KR-REQ-03.01"), ["first/tests/flow.rs:1"]);
    assert!(sources(&map, "KR-REQ-04.01").is_empty());
}

/// A package name that two workspaces hold cannot be told apart by a target's identifier, so the
/// map refuses it and names both manifests.
#[test]
fn a_package_name_that_two_workspaces_hold_is_refused_naming_both_manifests() {
    let (_directory, root) = copy("no-root-manifest");
    for file in ["second/Cargo.toml", "second/Cargo.lock"] {
        let text = std::fs::read_to_string(root.join(file)).expect("the file");
        std::fs::write(root.join(file), text.replace("beta", "alpha"))
            .expect("the file is written");
    }
    let map = map_of(&root, load(&root), None, false);
    assert_eq!(map.problems.len(), 1, "{:?}", map.problems);
    let problem = &map.problems[0];
    assert!(
        problem.contains("`alpha`")
            && problem.contains("first/Cargo.toml")
            && problem.contains("second/Cargo.toml"),
        "{problem}"
    );
    let (code, stdout, stderr) = program(&["map", "--root", &root.to_string_lossy()]);
    assert_eq!(code, Some(2), "{stdout}{stderr}");
    assert!(stdout.contains("second/Cargo.toml"), "{stdout}");
}

/// A manifest that the plan names and that is absent, absolute, climbs out of the tree or is a link
/// is refused by the loader before anything is mapped.
#[test]
fn a_manifest_that_is_absent_absolute_climbing_or_a_link_is_refused() {
    let (_directory, root) = copy("no-root-manifest");
    let base = plan_text(&root);
    let planted = |manifest: &str| {
        base.replace(
            "'first/Cargo.toml', 'second/Cargo.toml'",
            &format!("'{manifest}'"),
        )
    };
    #[cfg(unix)]
    std::os::unix::fs::symlink("first/Cargo.toml", root.join("linked.toml")).expect("a link");
    let mut faults = vec![
        ("missing/Cargo.toml", "does not exist"),
        ("/first/Cargo.toml", "is not a relative path"),
        ("first/../first/Cargo.toml", "holds `..`"),
        ("first", "is not a regular file"),
    ];
    if cfg!(unix) {
        faults.push(("linked.toml", "is a link"));
    }
    for (manifest, why) in faults {
        let text = refusal(&planted(manifest), &root);
        assert!(
            text.contains("[rust] manifests") && text.contains(manifest) && text.contains(why),
            "{manifest}: {text}"
        );
    }
    assert!(Plan::parse(&planted("first/Cargo.toml"), &root).is_ok());
}

/// The compiler's directories are directories of the tested root: one that is absent, a file or a
/// path that climbs out of the tree is refused.
#[test]
fn a_compiler_directory_that_is_not_a_directory_of_the_tested_root_is_refused() {
    let (_directory, root) = copy("typescript-only");
    let base = plan_text(&root);
    let planted = |directory: &str| {
        base.replace(
            "compiler_from = []",
            &format!("compiler_from = ['{directory}']"),
        )
    };
    for (directory, why) in [
        ("absent", "is not a directory of the repository"),
        ("web/forms.test.ts", "is not a directory of the repository"),
        ("../elsewhere", "holds `..`"),
    ] {
        let text = refusal(&planted(directory), &root);
        assert!(
            text.contains("[typescript] compiler_from")
                && text.contains(directory)
                && text.contains(why),
            "{directory}: {text}"
        );
    }
    assert!(Plan::parse(&planted("web"), &root).is_ok());
}

/// A lock that a workspace lacks is a problem of the map, found beside the manifest that names it.
#[test]
fn a_lock_that_is_absent_is_a_problem_of_the_map() {
    let (_directory, root) = copy_without("no-root-manifest", &|path| {
        path.ends_with("second/Cargo.lock")
    });
    let map = map_of(&root, load(&root), None, false);
    assert_eq!(map.problems.len(), 1, "{:?}", map.problems);
    assert!(
        map.problems[0].contains("second/Cargo.lock") && map.problems[0].contains("absent"),
        "{}",
        map.problems[0]
    );
    let (code, stdout, stderr) = program(&["map", "--root", &root.to_string_lossy()]);
    assert_eq!(code, Some(2), "{stdout}{stderr}");
}

/// A plan that names no manifest and no package has nothing to read, which is not an error.
#[test]
fn a_plan_that_names_no_manifest_and_no_package_maps_nothing_and_succeeds() {
    let (_directory, root) = copy("ignored-tests");
    let empty = plan_text(&root).replace("manifests = ['Cargo.toml']", "manifests = []");
    std::fs::write(root.join("conformance").join("plan.toml"), empty).expect("the plan is written");
    let (code, stdout, stderr) = program(&["map", "--root", &root.to_string_lossy()]);
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(
        stdout.starts_with(
            "0 identifiers keyed to 0 tests; 0 named only outside tests; 0 refused; 0 problems"
        ),
        "{stdout}"
    );
}

/// A group that the plan names and no step uses is refused.
#[test]
fn a_group_that_no_step_uses_is_refused() {
    let (_directory, root) = copy("ignored-tests");
    let text = plan_text(&root).replace("groups = ['rust']", "groups = ['rust', 'spare']");
    let refused = refusal(&text, &root);
    assert!(
        refused.contains("`spare`") && refused.contains("no step"),
        "{refused}"
    );
}

/// `held = false` turns the ignored-test check off for a tree, so a keyed ignored test that no step
/// runs is accepted; `held = true` holds the tree to the plan's entries and refuses it.
#[test]
fn a_tree_that_is_not_held_to_its_ignored_runs_accepts_a_keyed_ignored_test_with_no_run() {
    let (_directory, root) = copy("ignored-tests");
    let free = map_of(&root, load(&root), None, false);
    assert!(free.problems.is_empty(), "{:?}", free.problems);
    assert_eq!(sources(&free, "KR-REQ-05.01"), ["tests/slow.rs:1"]);
    let (code, stdout, stderr) = program(&["map", "--root", &root.to_string_lossy()]);
    assert_eq!(code, Some(0), "{stdout}{stderr}");

    let held = plan_text(&root).replace("held = false", "held = true");
    std::fs::write(root.join("conformance").join("plan.toml"), held).expect("the plan is written");
    let map = map_of(&root, load(&root), None, false);
    assert!(
        map.problems
            .iter()
            .any(|problem| problem.contains("left out of an ordinary run")),
        "{:?}",
        map.problems
    );
    let (code, stdout, stderr) = program(&["map", "--root", &root.to_string_lossy()]);
    assert_eq!(code, Some(2), "{stdout}{stderr}");
    assert!(stdout.contains("left out of an ordinary run"), "{stdout}");
}

/// A mention outside the identifier grammar stops the map with exit 2, naming the row and where it
/// is written, in a tree that holds no other plan than its own.
#[test]
fn a_mention_outside_the_grammar_is_refused_naming_the_row() {
    let (_directory, root) = copy("ignored-tests");
    let test = root.join("tests").join("slow.rs");
    let text = std::fs::read_to_string(&test).expect("the test");
    std::fs::write(
        &test,
        format!("{text}\n// KR-REQ-31.01: a row past the last section.\n"),
    )
    .expect("the test is written");
    let (code, stdout, stderr) = program(&["map", "--root", &root.to_string_lossy()]);
    assert_eq!(code, Some(2), "{stdout}{stderr}");
    assert!(
        stdout.contains("refused tests/slow.rs:6") && stdout.contains("31"),
        "{stdout}"
    );
}

/// Each key of the plan's `[typescript]` table that names a directory is read where the map reads
/// that directory: the scripts' directories for references in scripts, and the lanes' directories
/// for the references in Kotlin, Swift and Java files. A planted edit of a key changes the map.
#[test]
fn the_directories_the_plan_names_for_scripts_and_lanes_are_the_ones_read() {
    let (_directory, root) = copy("typescript-only");
    let base = plan_text(&root);
    let references = |text: &str| -> Map {
        map_of(
            &root,
            Plan::parse(text, &root).expect("a planted plan"),
            None,
            false,
        )
    };
    let map = references(&base);
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    assert!(
        map.references.contains_key(&identifier("KR-REQ-05.03")),
        "a script"
    );
    assert!(
        map.references.contains_key(&identifier("KR-REQ-05.04")),
        "a lane file"
    );

    let map = references(&base.replace("scripts = ['scripts']", "scripts = []"));
    assert!(
        !map.references.contains_key(&identifier("KR-REQ-05.03")),
        "no script is read"
    );
    assert!(map.references.contains_key(&identifier("KR-REQ-05.04")));

    let map = references(&base.replace("lane_directories = ['mobile']", "lane_directories = []"));
    assert!(map.references.contains_key(&identifier("KR-REQ-05.03")));
    assert!(
        !map.references.contains_key(&identifier("KR-REQ-05.04")),
        "no lane file is read"
    );
}

/// No source of the TypeScript reading names the directory this crate was built in: the compiler
/// comes from the tree that is read, or from the directory the command line gives.
#[test]
fn the_typescript_reading_names_no_directory_of_the_tool_itself() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("typescript.rs");
    let text = std::fs::read_to_string(source).expect("the source");
    assert!(!text.contains("CARGO_MANIFEST_DIR"));
}

/// KR-REQ-29.01, the part about mapping tests to acceptance identifiers, in TypeScript: a tree with
/// no Rust is read with the compiler that the command line names, which replaces the plan's.
#[test]
#[ignore = "reads TypeScript with the packages' own compiler, which `pnpm install --frozen-lockfile` installs; the report's typescript group runs it"]
fn a_typescript_only_tree_is_mapped_with_the_compiler_the_command_line_names() {
    let (_directory, root) = copy("typescript-only");
    let map = map_of(&root, load(&root), Some(&compiler()), true);
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    assert_eq!(sources(&map, "KR-REQ-05.01"), ["web/forms.test.ts:3"]);
    let (code, stdout, stderr) = program(&[
        "map",
        "--root",
        &root.to_string_lossy(),
        "--typescript",
        "--typescript-compiler",
        &compiler().to_string_lossy(),
    ]);
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    // Without a compiler the tree has none to read with.
    let (code, stdout, stderr) =
        program(&["map", "--root", &root.to_string_lossy(), "--typescript"]);
    assert_eq!(code, Some(2), "{stdout}{stderr}");
    assert!(stdout.contains("pnpm install"), "{stdout}");
}

/// KR-REQ-29.01, the part about mapping tests to acceptance identifiers, in TypeScript: each key of
/// the `[typescript]` table that steers the reading changes the map when it is edited: the
/// packages, the directories left out and the compiler's directories.
#[test]
#[ignore = "reads TypeScript with the packages' own compiler, which `pnpm install --frozen-lockfile` installs; the report's typescript group runs it"]
fn every_key_that_steers_the_typescript_reading_changes_the_map_when_it_is_edited() {
    let (_directory, root) = copy("typescript-only");
    let base = plan_text(&root);
    let mapped = |text: &str, compiler: Option<&Path>| -> Map {
        map_of(
            &root,
            Plan::parse(text, &root).expect("a planted plan"),
            compiler,
            true,
        )
    };
    // The directory left out holds one keyed test, and the plan leaves it out.
    let map = mapped(&base, Some(&compiler()));
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    assert!(
        !map.keys.contains_key(&identifier("KR-REQ-05.02")),
        "left out"
    );
    let map = mapped(
        &base.replace("['node_modules', 'generated']", "['node_modules']"),
        Some(&compiler()),
    );
    assert_eq!(
        sources(&map, "KR-REQ-05.02"),
        ["web/generated/built.test.ts:3"]
    );
    // No package: no TypeScript is read.
    let map = mapped(
        &base.replace("packages = ['web']", "packages = []"),
        Some(&compiler()),
    );
    assert!(!map.keys.contains_key(&identifier("KR-REQ-05.01")));
    // The compiler the tree names, found in the tree: a package of the copy that re-exports the
    // installed one.
    let package = root.join("vendor").join("node_modules").join("typescript");
    std::fs::create_dir_all(&package).expect("a package directory");
    std::fs::write(root.join("vendor").join("package.json"), "{}").expect("a manifest");
    std::fs::write(
        package.join("index.js"),
        format!(
            "module.exports = require({:?})\n",
            compiler().join("node_modules").join("typescript")
        ),
    )
    .expect("an entry");
    git(&root, &["add", "-A"]);
    let named = base.replace("compiler_from = []", "compiler_from = ['vendor']");
    let map = mapped(&named, None);
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    assert_eq!(sources(&map, "KR-REQ-05.01"), ["web/forms.test.ts:3"]);
    // None named and none given: the tree has no compiler to read with.
    let map = mapped(&base, None);
    assert!(
        map.problems
            .iter()
            .any(|problem| problem.contains("pnpm install")),
        "{:?}",
        map.problems
    );
}
