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
    // Unix resolves the copy's root, so that every case names the copy by one path (macOS's
    // temporary directory is behind a link); Windows keeps the path as it is, because a resolved
    // path there carries a `\\?\` prefix.
    let root = if cfg!(windows) {
        directory.path().to_path_buf()
    } else {
        directory.path().canonicalize().expect("the copy's root")
    };
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

/// The fixture's plan with its steps run no `cargo`: a `cargo` step runs in a workspace root the
/// plan's manifests name, and a case that plants other manifests is about the map, not the steps.
fn without_cargo(text: &str) -> String {
    let words = "command = ['cargo', 'test', '--locked']";
    assert!(text.contains(words), "the fixture's steps");
    text.replace(words, "command = ['pnpm', 'test']")
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

/// Like [`program`], run in `directory`.
fn program_in(directory: &Path, arguments: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_kr-conformance"))
        .args(arguments)
        .current_dir(directory)
        .output()
        .expect("the program runs");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Plants a compiler in `directory` of the copy at `root`: a package that re-exports the installed
/// one, with `version` as its own when that is given.
fn plant_compiler(root: &Path, directory: &str, version: Option<&str>) {
    let package = root.join(directory).join("node_modules").join("typescript");
    std::fs::create_dir_all(&package).expect("a package directory");
    std::fs::write(root.join(directory).join("package.json"), "{}").expect("a manifest");
    let installed = compiler().join("node_modules").join("typescript");
    let entry = match version {
        None => format!("module.exports = require({installed:?})\n"),
        Some(version) => format!(
            "module.exports = Object.create(require({installed:?}), {{ version: {{ value: {version:?} }} }})\n"
        ),
    };
    std::fs::write(package.join("index.js"), entry).expect("an entry");
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
    let workspaces: Vec<(&str, &str)> = map
        .packages
        .iter()
        .map(|package| (package.name.as_str(), package.workspace.as_str()))
        .collect();
    assert_eq!(workspaces, [("alpha", "first"), ("beta", "second")]);
    let (code, stdout, stderr) = program(&["map", "--root", &root.to_string_lossy()]);
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(
        stdout.starts_with("4 identifiers keyed to 4 tests;"),
        "{stdout}"
    );
    // Only the first manifest: the second workspace is not read.
    let only_first = without_cargo(&plan_text(&root)).replace(
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
    let base = without_cargo(&plan_text(&root));
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

/// Plants a member of the first workspace of a copy of `no-root-manifest`: the root manifest names
/// it, and the copy's index holds it.
fn plant_member(root: &Path) {
    let member = root.join("first").join("member");
    std::fs::create_dir_all(member.join("src")).expect("a directory");
    std::fs::write(
        member.join("Cargo.toml"),
        "[package]\nname = \"member\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n",
    )
    .expect("a manifest");
    std::fs::write(member.join("src").join("lib.rs"), "").expect("a source");
    let first = root.join("first").join("Cargo.toml");
    let text = std::fs::read_to_string(&first).expect("the manifest");
    std::fs::write(
        &first,
        text.replace("[workspace]", "[workspace]\nmembers = [\"member\"]"),
    )
    .expect("the manifest is written");
    git(root, &["add", "-A"]);
}

/// A package belongs to the workspace that Cargo says holds it, named relative to the tested root:
/// the workspace of a manifest spelled with a `.` is the same as without it, and a manifest that is
/// a member's, not the workspace's own, is refused naming the workspace's manifest.
#[test]
fn a_package_belongs_to_the_workspace_cargo_names_and_a_members_manifest_is_refused() {
    let (_directory, root) = copy("no-root-manifest");
    plant_member(&root);
    let base = without_cargo(&plan_text(&root));
    let owners = |manifests: &str| -> (Vec<(String, String)>, Vec<String>) {
        let text = base.replace("'first/Cargo.toml', 'second/Cargo.toml'", manifests);
        let map = map_of(
            &root,
            Plan::parse(&text, &root).expect("a planted plan"),
            None,
            false,
        );
        let owners = map
            .packages
            .iter()
            .map(|package| (package.name.clone(), package.workspace.clone()))
            .collect();
        (owners, map.problems)
    };
    let own = |name: &str, workspace: &str| (name.to_owned(), workspace.to_owned());
    // The workspace's own manifest, spelled plainly and with a `.`: every package of its workspace,
    // the member too, belongs to `first`.
    for manifests in [
        "'first/Cargo.toml', 'second/Cargo.toml'",
        "'./first/Cargo.toml', 'second/Cargo.toml'",
    ] {
        let (owners, problems) = owners(manifests);
        assert!(problems.is_empty(), "{manifests}: {problems:?}");
        assert_eq!(
            owners,
            [
                own("alpha", "first"),
                own("beta", "second"),
                own("member", "first")
            ],
            "{manifests}"
        );
    }
    // A member's manifest names the workspace's own.
    let (_, problems) = owners("'first/member/Cargo.toml', 'second/Cargo.toml'");
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        problems[0].contains("`first/member/Cargo.toml`")
            && problems[0].contains("workspace at `first`")
            && problems[0].contains("`first/Cargo.toml`"),
        "{}",
        problems[0]
    );
    std::fs::write(
        root.join("conformance").join("plan.toml"),
        base.replace(
            "'first/Cargo.toml', 'second/Cargo.toml'",
            "'first/member/Cargo.toml', 'second/Cargo.toml'",
        ),
    )
    .expect("the plan is written");
    let (code, stdout, stderr) = program(&["map", "--root", &root.to_string_lossy()]);
    assert_eq!(code, Some(2), "{stdout}{stderr}");
    assert!(stdout.contains("`first/Cargo.toml`"), "{stdout}");
}

/// A link inside the repository that the plan's path goes through does not make a workspace's own
/// manifest a member's: the workspace is the same file whichever way it is reached, from an
/// absolute root and from a relative one, and a member's manifest through the same link is still
/// refused, naming the workspace's own.
#[cfg(unix)]
#[test]
fn a_workspace_reached_through_a_link_inside_the_repository_keeps_its_own_manifest() {
    let (_directory, root) = copy("no-root-manifest");
    plant_member(&root);
    std::os::unix::fs::symlink("first", root.join("alias")).expect("a link");
    git(&root, &["add", "-A"]);
    let base = without_cargo(&plan_text(&root));
    let write = |manifests: &str| {
        std::fs::write(
            root.join("conformance").join("plan.toml"),
            base.replace("'first/Cargo.toml', 'second/Cargo.toml'", manifests),
        )
        .expect("the plan is written");
    };
    let name = root
        .file_name()
        .expect("a name")
        .to_string_lossy()
        .into_owned();
    let parent = root.parent().expect("a parent").to_path_buf();
    let absolute = root.to_string_lossy().into_owned();
    let roots = [
        (root.clone(), absolute.as_str()),
        (root.clone(), "."),
        (parent, name.as_str()),
    ];
    // The workspace's own manifest, through the link.
    write("'alias/Cargo.toml', 'second/Cargo.toml'");
    let map = map_of(&root, load(&root), None, false);
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    for package in &map.packages {
        if package.name != "beta" {
            assert!(
                ["alias", "first"].contains(&package.workspace.as_str()),
                "{}: {}",
                package.name,
                package.workspace
            );
        }
    }
    for (from, argument) in &roots {
        let (code, stdout, stderr) = program_in(from, &["map", "--root", argument]);
        assert_eq!(code, Some(0), "--root {argument}: {stdout}{stderr}");
        assert!(
            stdout.contains("; 0 refused; 0 problems"),
            "{argument}: {stdout}"
        );
    }
    // A member's manifest through the same link.
    write("'alias/member/Cargo.toml', 'second/Cargo.toml'");
    for (from, argument) in &roots {
        let (code, stdout, stderr) = program_in(from, &["map", "--root", argument]);
        assert_eq!(code, Some(2), "--root {argument}: {stdout}{stderr}");
        assert!(
            stdout.contains("a manifest inside the workspace")
                && stdout.contains("Cargo.toml` in `[rust] manifests`"),
            "--root {argument}: {stdout}"
        );
    }
}

/// A Rust workspace is mapped from a relative root, and from a root that holds `..` and so is not
/// in the form Cargo writes its paths in: the files are named relative to the root and no problem
/// is raised.
#[test]
fn a_rust_workspace_is_mapped_from_a_relative_root_and_from_a_root_that_holds_dots() {
    let (directory, root) = copy("no-root-manifest");
    let dotted = directory.path().join("first").join("..");
    for (from, argument) in [
        (root.clone(), ".".to_owned()),
        (root.parent().expect("a parent").to_path_buf(), {
            root.file_name()
                .expect("a name")
                .to_string_lossy()
                .into_owned()
        }),
        (root.clone(), dotted.to_string_lossy().into_owned()),
    ] {
        let (code, stdout, stderr) = program_in(&from, &["map", "--root", &argument]);
        assert_eq!(code, Some(0), "--root {argument}: {stdout}{stderr}");
        assert!(
            stdout.starts_with("4 identifiers keyed to 4 tests;")
                && stdout.contains("; 0 refused; 0 problems"),
            "--root {argument}: {stdout}"
        );
    }
}

/// A workspace at the tested root is named `.`.
#[test]
fn the_workspace_of_a_root_manifest_is_the_tested_root() {
    let (_directory, root) = copy("ignored-tests");
    let map = map_of(&root, load(&root), None, false);
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    assert!(!map.packages.is_empty());
    for package in &map.packages {
        assert_eq!(package.workspace, ".", "{}", package.name);
    }
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

/// A copy is a Git index with no commit: its commit is `unknown` and its tracked files differ from
/// it. A case that makes a result from a copy states that, or commits the copy.
#[test]
fn a_copy_is_a_git_index_with_no_commit_so_its_commit_is_unknown_and_modified() {
    let (_directory, root) = copy("ignored-tests");
    let commit = kr_conformance::identity::commit(&root);
    assert_eq!(commit.id, "unknown");
    assert!(commit.modified);
}

/// A plan that names no manifest and no package has nothing to read, which is not an error.
#[test]
fn a_plan_that_names_no_manifest_and_no_package_maps_nothing_and_succeeds() {
    let (_directory, root) = copy("ignored-tests");
    let empty =
        without_cargo(&plan_text(&root)).replace("manifests = ['Cargo.toml']", "manifests = []");
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

/// Each top-level key of the plan that names a directory is read where the map reads
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

    // Each key emptied, and each key removed: absent means none.
    for (edit, name) in [
        (
            base.replace("scripts = ['scripts']", "scripts = []"),
            "emptied",
        ),
        (base.replace("scripts = ['scripts']\n", ""), "removed"),
    ] {
        let map = references(&edit);
        assert!(
            !map.references.contains_key(&identifier("KR-REQ-05.03")),
            "no script is read: the key is {name}"
        );
        assert!(map.references.contains_key(&identifier("KR-REQ-05.04")));
    }
    for (edit, name) in [
        (
            base.replace("lane_directories = ['mobile']", "lane_directories = []"),
            "emptied",
        ),
        (
            base.replace("lane_directories = ['mobile']\n", ""),
            "removed",
        ),
    ] {
        let map = references(&edit);
        assert!(map.references.contains_key(&identifier("KR-REQ-05.03")));
        assert!(
            !map.references.contains_key(&identifier("KR-REQ-05.04")),
            "no lane file is read: the key is {name}"
        );
    }
}

/// A plan with no `[typescript]` table reads the scripts and the lane files it names: a repository
/// with Kotlin, Swift or Java lanes and no TypeScript still says where they are.
#[test]
fn a_plan_with_no_typescript_table_reads_the_scripts_and_lanes_it_names() {
    let (_directory, root) = copy("ignored-tests");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("typescript-only");
    for (directory, file) in [("scripts", "note.sh"), ("mobile", "Screen.kt")] {
        std::fs::create_dir_all(root.join(directory)).expect("a directory");
        std::fs::copy(
            fixture.join(directory).join(file),
            root.join(directory).join(file),
        )
        .expect("a file");
    }
    git(&root, &["add", "-A"]);
    let named = plan_text(&root).replacen(
        "groups = ['rust']\n",
        "groups = ['rust']\nscripts = ['scripts']\nlane_directories = ['mobile']\n",
        1,
    );
    assert!(!named.contains("[typescript]"), "{named}");
    let references = |text: &str| -> Map {
        map_of(
            &root,
            Plan::parse(text, &root).expect("a planted plan"),
            None,
            false,
        )
    };
    let map = references(&named);
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    assert!(map.references.contains_key(&identifier("KR-REQ-05.03")));
    assert!(map.references.contains_key(&identifier("KR-REQ-05.04")));
    std::fs::write(root.join("conformance").join("plan.toml"), &named).expect("the plan");
    let (code, stdout, stderr) = program(&["map", "--root", &root.to_string_lossy()]);
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    let map = references(
        &plan_text(&root).replace("scripts = ['scripts']\nlane_directories = ['mobile']\n", ""),
    );
    assert!(!map.references.contains_key(&identifier("KR-REQ-05.03")));
    assert!(!map.references.contains_key(&identifier("KR-REQ-05.04")));
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
    assert_eq!(
        map.typescript_version.as_deref(),
        Some(installed_version().as_str()),
        "the compiler's version is the installed package's"
    );
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

/// The version of the compiler that is installed in `compiler()`.
fn installed_version() -> String {
    let manifest = compiler()
        .join("node_modules")
        .join("typescript")
        .join("package.json");
    let text = std::fs::read_to_string(manifest).expect("the installed compiler's manifest");
    let value: serde_json::Value = serde_json::from_str(&text).expect("JSON");
    value["version"].as_str().expect("a version").to_owned()
}

/// KR-REQ-29.01, the part about mapping tests to acceptance identifiers, in TypeScript: the compiler
/// is the package a directory of `compiler_from` holds in its own `node_modules`, and no directory
/// above it is searched; the first directory that holds one is used, whatever empty directory
/// comes before it; `--typescript-compiler` replaces the plan's directories.
#[test]
#[ignore = "reads TypeScript with the packages' own compiler, which `pnpm install --frozen-lockfile` installs; the report's typescript group runs it"]
fn the_compiler_is_the_package_a_directory_holds_and_no_directory_above_it_is_searched() {
    let (_directory, root) = copy("typescript-only");
    let base = plan_text(&root);
    let mapped = |directories: &str, compiler: Option<&Path>| -> Map {
        let text = base.replace(
            "compiler_from = []",
            &format!("compiler_from = [{directories}]"),
        );
        map_of(
            &root,
            Plan::parse(&text, &root).expect("a planted plan"),
            compiler,
            true,
        )
    };
    // A compiler above the directory the plan names is not that directory's own.
    plant_compiler(&root, "above", None);
    std::fs::create_dir_all(root.join("above").join("inner")).expect("a directory");
    std::fs::write(root.join("above").join("inner").join("package.json"), "{}")
        .expect("a manifest");
    std::fs::create_dir_all(root.join("empty")).expect("a directory");
    std::fs::write(root.join("empty").join("package.json"), "{}").expect("a manifest");
    git(&root, &["add", "-A"]);
    let map = mapped("'above/inner'", None);
    assert!(
        map.problems
            .iter()
            .any(|problem| problem.contains("is not installed in") && problem.contains("inner")),
        "{:?}",
        map.problems
    );
    // A directory with no compiler does not displace a later directory that has one.
    let map = mapped("'empty', 'above'", None);
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    assert_eq!(sources(&map, "KR-REQ-05.01"), ["web/forms.test.ts:3"]);
    // The first directory that holds a compiler is the one used.
    plant_compiler(&root, "first", Some("first"));
    plant_compiler(&root, "second", Some("second"));
    git(&root, &["add", "-A"]);
    let map = mapped("'empty', 'first', 'second'", None);
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    assert_eq!(map.typescript_version.as_deref(), Some("first"));
    // The first directory that holds a package is the one used: a package that does not load is an
    // error, and the next directory's compiler does not take its place.
    let broken = root.join("broken").join("node_modules").join("typescript");
    std::fs::create_dir_all(&broken).expect("a package directory");
    std::fs::write(root.join("broken").join("package.json"), "{}").expect("a manifest");
    std::fs::write(
        broken.join("index.js"),
        "throw new Error('broken on purpose')\n",
    )
    .expect("an entry");
    git(&root, &["add", "-A"]);
    let map = mapped("'empty', 'broken', 'first', 'second'", None);
    assert!(
        map.problems
            .iter()
            .any(|problem| problem.contains("could not be loaded")
                && problem.contains("broken on purpose")
                && problem.contains("broken")),
        "{:?}",
        map.problems
    );
    assert_eq!(map.typescript_version, None);
    // The command line's directory replaces the plan's.
    let map = mapped("'empty', 'first', 'second'", Some(&compiler()));
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    assert_eq!(
        map.typescript_version.as_deref(),
        Some(installed_version().as_str())
    );
}

/// KR-REQ-29.01, the part about mapping tests to acceptance identifiers, in TypeScript: the root may
/// be given as a relative path, and the compiler the plan names in the tree is still found.
#[test]
#[ignore = "reads TypeScript with the packages' own compiler, which `pnpm install --frozen-lockfile` installs; the report's typescript group runs it"]
fn a_relative_root_finds_the_compiler_the_plan_names() {
    let (_directory, root) = copy("typescript-only");
    plant_compiler(&root, "vendor", None);
    git(&root, &["add", "-A"]);
    let named = plan_text(&root).replace("compiler_from = []", "compiler_from = ['vendor']");
    std::fs::write(root.join("conformance").join("plan.toml"), named).expect("the plan");
    let name = root
        .file_name()
        .expect("a name")
        .to_string_lossy()
        .into_owned();
    for (from, argument) in [
        (root.clone(), ".".to_owned()),
        (root.clone(), "./".to_owned()),
        (root.parent().expect("a parent").to_path_buf(), name.clone()),
        (root.join("web"), "..".to_owned()),
    ] {
        let (code, stdout, stderr) =
            program_in(&from, &["map", "--root", &argument, "--typescript"]);
        assert_eq!(code, Some(0), "--root {argument}: {stdout}{stderr}");
        assert!(
            stdout.contains("identifiers keyed to") && stdout.contains("; 0 refused; 0 problems"),
            "--root {argument}: {stdout}"
        );
    }
}

/// KR-REQ-29.01, the part about mapping tests to acceptance identifiers, in TypeScript: a call is a
/// test only when its first argument is a string or a template, or a function follows it. A
/// condition that `test.skip` takes, a step, the fixtures' `use` and `extend` and the four hooks,
/// with a title or with none, are not tests.
#[test]
#[ignore = "reads TypeScript with the packages' own compiler, which `pnpm install --frozen-lockfile` installs; the report's typescript group runs it"]
fn a_typescript_call_is_a_test_only_when_it_names_one() {
    let (_directory, root) = copy("typescript-only");
    let map = map_of(&root, load(&root), Some(&compiler()), true);
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    let file = map
        .typescript
        .iter()
        .find(|file| file.file == "web/calls.test.ts")
        .expect("the file of calls");
    let named = |text: &str| file.calls.iter().any(|call| call.title_text == text);
    for (form, text, is_a_call) in [
        ("a string title", "a string title", true),
        ("a template title", "a template title", true),
        (
            "a template with a substitution",
            "`${named} and more`",
            true,
        ),
        (
            "an identifier title with a function after it",
            "named",
            true,
        ),
        ("a condition named by an identifier", "mobile", false),
        (
            "a condition that compares",
            "process.platform === 'win32'",
            false,
        ),
        ("a step", "a step inside a test", false),
        (
            "a helper that is not a suite",
            "a helper with a title",
            false,
        ),
        ("a hook with a title", "a hook before all", false),
        ("a hook with a title", "a hook before each", false),
        ("a hook with a title", "a hook after all", false),
        ("a hook with a title", "a hook after each", false),
    ] {
        assert_eq!(named(text), is_a_call, "{form}");
    }
    assert_eq!(file.calls.len(), 5, "{:?}", file.calls);
    // Five calls and no more: the suite, four tests, and none of the other calls of the file.
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
    plant_compiler(&root, "vendor", None);
    git(&root, &["add", "-A"]);
    let named = base.replace("compiler_from = []", "compiler_from = ['vendor']");
    let map = mapped(&named, None);
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    assert_eq!(sources(&map, "KR-REQ-05.01"), ["web/forms.test.ts:3"]);
    // Each optional key removed alone is the same as an empty one: no directory is left out, and
    // no compiler directory is named.
    let map = mapped(
        &base.replace("skip_directories = ['node_modules', 'generated']\n", ""),
        Some(&compiler()),
    );
    assert_eq!(
        sources(&map, "KR-REQ-05.02"),
        ["web/generated/built.test.ts:3"],
        "no directory is left out"
    );
    let map = mapped(&base.replace("compiler_from = []\n", ""), Some(&compiler()));
    assert!(map.problems.is_empty(), "{:?}", map.problems);
    assert_eq!(sources(&map, "KR-REQ-05.01"), ["web/forms.test.ts:3"]);
    let map = mapped(&base.replace("compiler_from = []\n", ""), None);
    assert!(
        map.problems
            .iter()
            .any(|problem| problem.contains("no directory names one")),
        "no compiler directory is named: {:?}",
        map.problems
    );
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
