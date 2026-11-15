//! Every task the daemon's process starts, named.
//!
//! A task that no one owns is a task that no one restarts, reports or stops. This holds the list of
//! every place in the daemon's process that starts a task, a blocking pass or a thread
//! (`spawn_sites.txt`) against the source: the controller crate and every local crate that it
//! links are read, each start is found, and a start that has no row, or a row that has no start,
//! fails the case until the list says what the start is.
//!
//! What this holds and what it does not. It holds the set of start sites, keyed by file, function,
//! form and callee: a new start, a removed one, and one start that replaces another in the same
//! function all change the list. It does not hold a lifetime: a helper that is given a longer life
//! without a new start, and a start that only a dependency outside this repository makes, are not
//! seen.
//!
//! The cases after the first run the scan over small trees of source text, so that each way the
//! scan could miss a start is shown by a start that it must find.

#[path = "spawn_sites/roster.rs"]
mod roster;
#[path = "spawn_sites/scan.rs"]
mod scan;

use std::path::{Path, PathBuf};

use roster::Roster;
use scan::{Files, Memory, Scan};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

const DAEMON: &str = "crates/kr-controller";

/// The scan of a tree, with the roster's helper lines.
fn scan_of(files: &dyn Files, daemon: &str, roster: &Roster) -> Scan {
    let daemon = Path::new(daemon);
    let crates = scan::linked_crates(files, daemon).expect("the linked crates are found");
    let roots = scan::root_files(files, &crates, daemon).expect("the roots are found");
    scan::scan(files, &roots, &roster.helper_scopes()).expect("the source is read")
}

fn real_roster() -> Roster {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/spawn_sites.txt");
    let text = std::fs::read_to_string(&path).expect("the roster is read");
    roster::parse(&text).expect("the roster is well formed")
}

#[test]
fn the_roster_names_every_start_of_the_daemon_process() {
    let roster = real_roster();
    let disk = scan::Disk(repository());
    let found = scan_of(&disk, DAEMON, &roster);
    let problems = roster::disagreements(&roster, &found);
    assert!(
        problems.is_empty(),
        "{} disagreement(s) between the roster and the source:\n{}",
        problems.len(),
        problems.join("\n")
    );

    // The scan reached the daemon's own entry point, and the crates it links.
    for file in [
        "crates/kr-controller/src/bin/kr-controller.rs",
        "crates/kr-controller/src/lib.rs",
        "crates/kr-transport/src/listener.rs",
        "crates/kr-plugin-service/src/launcher.rs",
    ] {
        assert!(found.files.contains(file), "the scan did not read {file}");
    }
    // Every long-lived task has a row.
    for number in 1..=35 {
        assert!(
            roster.rows.iter().any(|row| row.task == Some(number)),
            "the roster has no row for long-lived task {number}"
        );
    }
}

/// A tree with one daemon crate, `crates/daemon`, that has a library of the given text and an
/// entry point.
fn daemon_with(library: &str) -> Memory {
    Memory::of(&[
        ("Cargo.toml", "[workspace]\nmembers = []\n"),
        (
            "crates/daemon/Cargo.toml",
            "[package]\nname = \"daemon\"\n\n[[bin]]\nname = \"daemon\"\npath = \"src/main.rs\"\n",
        ),
        ("crates/daemon/src/main.rs", "fn main() {}\n"),
        ("crates/daemon/src/lib.rs", library),
    ])
}

fn roster_of(text: &str) -> Roster {
    roster::parse(text).expect("the fixture roster is well formed")
}

fn problems_of(tree: &Memory, roster: &Roster) -> Vec<String> {
    roster::disagreements(roster, &scan_of(tree, "crates/daemon", roster))
}

/// The forms and callees found, as `form callee`.
fn starts_of(tree: &Memory, roster: &Roster) -> Vec<String> {
    scan_of(tree, "crates/daemon", roster)
        .starts
        .iter()
        .map(|start| format!("{} {}", start.form, start.callee))
        .collect()
}

const ONE_START: &str = "fn work() {}\nfn serve() { tokio::spawn(work()); }\n";
const ONE_ROW: &str =
    "crates/daemon/src/lib.rs | serve | tokio::spawn | work | 1 | request | - | a case\n";

#[test]
fn a_start_with_a_row_agrees_and_a_new_start_without_one_fails() {
    let tree = daemon_with(ONE_START);
    assert_eq!(
        problems_of(&tree, &roster_of(ONE_ROW)),
        Vec::<String>::new()
    );

    let tree = daemon_with(
        "fn work() {}\nfn serve() { tokio::spawn(work()); }\nfn more() { tokio::spawn(work()); }\n",
    );
    let problems = problems_of(&tree, &roster_of(ONE_ROW));
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("no row names") && problems[0].contains("more"));
}

#[test]
fn a_second_start_of_the_same_callee_in_the_same_function_changes_the_count() {
    let tree =
        daemon_with("fn work() {}\nfn serve() { tokio::spawn(work()); tokio::spawn(work()); }\n");
    let problems = problems_of(&tree, &roster_of(ONE_ROW));
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("says 1 start(s) and the source has 2"));
}

#[test]
fn a_start_replaced_by_another_in_the_same_function_fails() {
    // The function, the form and the count are what they were; only what is run changed.
    let tree = daemon_with("fn other() {}\nfn serve() { tokio::spawn(other()); }\n");
    let problems = problems_of(&tree, &roster_of(ONE_ROW));
    assert_eq!(problems.len(), 2, "{problems:?}");
    assert!(
        problems
            .iter()
            .any(|p| p.contains("no row names") && p.contains("other"))
    );
    assert!(
        problems
            .iter()
            .any(|p| p.contains("no start in the source") && p.contains("work"))
    );

    // Replaced inside an async block and a closure, which the callee reads as well.
    let before = daemon_with("fn serve() { tokio::spawn(async move { pass().await }); }\n");
    let after = daemon_with("fn serve() { tokio::spawn(async move { another().await }); }\n");
    let roster = roster_of(
        "crates/daemon/src/lib.rs | serve | tokio::spawn | async{pass} | 1 | request | - | a case\n",
    );
    assert!(problems_of(&before, &roster).is_empty());
    assert_eq!(problems_of(&after, &roster).len(), 2);
}

#[test]
fn a_removed_start_leaves_a_row_with_no_start() {
    let tree = daemon_with("fn serve() {}\n");
    let problems = problems_of(&tree, &roster_of(ONE_ROW));
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("no start in the source"));
}

#[test]
fn a_start_inside_a_macro_body_is_found() {
    let tree = daemon_with(
        "fn serve() {\n\
             tokio::select! { _ = tokio::spawn(job()) => {}, _ = sleep() => {} }\n\
             let _ = matches!(x, Some(_) if pool.spawn_blocking(task()).is_finished());\n\
         }\n\
         macro_rules! start_it { () => { tokio::task::spawn(inner()) } }\n",
    );
    let found = starts_of(&tree, &Roster::default());
    assert!(found.contains(&"tokio::spawn job".to_string()), "{found:?}");
    assert!(
        found.contains(&".spawn_blocking task".to_string()),
        "{found:?}"
    );
    assert!(
        found.contains(&"tokio::task::spawn inner".to_string()),
        "{found:?}"
    );
    let scan = scan_of(&tree, "crates/daemon", &Roster::default());
    assert!(
        scan.starts
            .iter()
            .any(|start| start.function == "macro_rules!start_it" && start.callee == "inner")
    );
}

#[test]
fn every_form_of_a_start_is_found() {
    let tree = daemon_with(
        "fn forms(tasks: &mut Set, runtime: &Handle) {\n\
             tokio::spawn(a());\n\
             tokio::task::spawn(b());\n\
             tokio::task::spawn_blocking(move || c());\n\
             tasks.spawn(d());\n\
             runtime.spawn(e());\n\
             std::thread::spawn(|| f());\n\
             std::thread::Builder::new().name(n()).spawn(|| g());\n\
             let _ = command.spawn();\n\
         }\n",
    );
    let found = starts_of(&tree, &Roster::default());
    for expected in [
        "tokio::spawn a",
        "tokio::task::spawn b",
        "tokio::task::spawn_blocking closure{c}",
        ".spawn d",
        ".spawn e",
        "std::thread::spawn closure{f}",
        ".spawn closure{g}",
    ] {
        assert!(
            found.contains(&expected.to_string()),
            "{expected} not in {found:?}"
        );
    }
    // A method `spawn` with no argument starts a child process.
    assert_eq!(found.len(), 7, "{found:?}");
}

#[test]
fn a_start_in_a_second_crate_is_found_and_a_development_dependency_is_not() {
    let tree = Memory::of(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = []\n[workspace.dependencies]\nlinked = { path = \"crates/linked\" }\n",
        ),
        (
            "crates/daemon/Cargo.toml",
            "[package]\nname = \"daemon\"\n[[bin]]\nname = \"daemon\"\npath = \"src/main.rs\"\n\
             [dependencies]\nlinked = { workspace = true }\n\
             [target.'cfg(unix)'.dependencies]\nnamed = { path = \"../named\" }\n\
             [dev-dependencies]\nonly_tests = { path = \"../only_tests\" }\n",
        ),
        ("crates/daemon/src/main.rs", "fn main() {}\n"),
        ("crates/daemon/src/lib.rs", "pub fn nothing() {}\n"),
        (
            "crates/linked/Cargo.toml",
            "[package]\nname = \"linked\"\n[dependencies]\ndeeper = { path = \"../deeper\" }\n",
        ),
        (
            "crates/linked/src/lib.rs",
            "pub fn run() { tokio::spawn(carry()); }\n",
        ),
        ("crates/deeper/Cargo.toml", "[package]\nname = \"deeper\"\n"),
        (
            "crates/deeper/src/lib.rs",
            "pub fn run() { std::thread::spawn(|| beat()); }\n",
        ),
        ("crates/named/Cargo.toml", "[package]\nname = \"named\"\n"),
        (
            "crates/named/src/lib.rs",
            "pub fn run() { tokio::spawn(listen()); }\n",
        ),
        (
            "crates/only_tests/Cargo.toml",
            "[package]\nname = \"only_tests\"\n",
        ),
        (
            "crates/only_tests/src/lib.rs",
            "pub fn run() { tokio::spawn(fixture()); }\n",
        ),
    ]);
    let scan = scan_of(&tree, "crates/daemon", &Roster::default());
    let files: Vec<&str> = scan
        .starts
        .iter()
        .map(|start| start.file.as_str())
        .collect();
    assert!(files.contains(&"crates/linked/src/lib.rs"), "{files:?}");
    assert!(files.contains(&"crates/deeper/src/lib.rs"), "{files:?}");
    assert!(files.contains(&"crates/named/src/lib.rs"), "{files:?}");
    assert!(
        !files.contains(&"crates/only_tests/src/lib.rs"),
        "{files:?}"
    );

    let crates = scan::linked_crates(&tree, Path::new("crates/daemon")).expect("linked");
    let names: Vec<&str> = crates.iter().map(|linked| linked.name.as_str()).collect();
    assert_eq!(names, ["daemon", "deeper", "linked", "named"]);
}

#[test]
fn only_code_under_a_test_configuration_is_skipped() {
    let tree = Memory::of(&[
        ("Cargo.toml", "[workspace]\n"),
        (
            "crates/daemon/Cargo.toml",
            "[package]\nname = \"daemon\"\n[[bin]]\nname = \"daemon\"\npath = \"src/main.rs\"\n",
        ),
        ("crates/daemon/src/main.rs", "fn main() {}\n"),
        (
            "crates/daemon/src/lib.rs",
            "mod shipped;\n\
             #[cfg(test)]\nmod tests { fn t() { tokio::spawn(in_a_test_module()); } }\n\
             #[cfg(test)]\nmod elsewhere;\n\
             #[cfg(test)]\nfn only_for_tests() { tokio::spawn(in_a_test_function()); }\n\
             #[cfg(all(test, unix))]\nfn also_only_for_tests() { tokio::spawn(in_a_unix_test()); }\n\
             #[cfg(test)]\nconst ONLY: u8 = 1;\n\
             pub fn after_the_attribute() { tokio::spawn(not_skipped_after_an_item_attribute()); }\n\
             #[cfg(not(test))]\npub fn outside_tests() { tokio::spawn(outside()); }\n\
             pub fn inside() {\n\
                 #[cfg(test)]\n\
                 let _ = tokio::spawn(statement_in_a_test());\n\
                 tokio::spawn(statement_before_the_end());\n\
             }\n",
        ),
        (
            "crates/daemon/src/shipped.rs",
            "pub fn run() { tokio::spawn(in_a_later_file()); }\n\
             #[cfg(test)]\nmod tests;\n",
        ),
    ]);
    let found = starts_of(&tree, &Roster::default());
    for expected in [
        "tokio::spawn not_skipped_after_an_item_attribute",
        "tokio::spawn outside",
        "tokio::spawn statement_before_the_end",
        "tokio::spawn in_a_later_file",
    ] {
        assert!(
            found.contains(&expected.to_string()),
            "{expected} not in {found:?}"
        );
    }
    assert_eq!(
        found.len(),
        4,
        "a start under a test configuration was read: {found:?}"
    );
}

#[test]
fn modules_are_found_through_their_declarations() {
    let tree = Memory::of(&[
        ("Cargo.toml", "[workspace]\n"),
        (
            "crates/daemon/Cargo.toml",
            "[package]\nname = \"daemon\"\n[[bin]]\nname = \"daemon\"\npath = \"src/main.rs\"\n",
        ),
        ("crates/daemon/src/main.rs", "fn main() {}\n"),
        (
            "crates/daemon/src/lib.rs",
            "mod flat;\nmod nested;\n#[path = \"elsewhere/moved.rs\"]\nmod moved;\n\
             mod inline { pub fn run() { tokio::spawn(from_inline()); } }\n",
        ),
        ("crates/daemon/src/flat.rs", "mod below;\n"),
        (
            "crates/daemon/src/flat/below.rs",
            "pub fn run() { tokio::spawn(from_below()); }\n",
        ),
        (
            "crates/daemon/src/nested/mod.rs",
            "pub fn run() { tokio::spawn(from_mod_rs()); }\n",
        ),
        (
            "crates/daemon/src/elsewhere/moved.rs",
            "pub fn run() { tokio::spawn(from_a_path()); }\n",
        ),
        (
            "crates/daemon/src/never_declared.rs",
            "pub fn run() { tokio::spawn(never_read()); }\n",
        ),
    ]);
    let found = starts_of(&tree, &Roster::default());
    for expected in [
        "tokio::spawn from_below",
        "tokio::spawn from_mod_rs",
        "tokio::spawn from_a_path",
        "tokio::spawn from_inline",
    ] {
        assert!(
            found.contains(&expected.to_string()),
            "{expected} not in {found:?}"
        );
    }
    assert_eq!(found.len(), 4, "{found:?}");
}

#[test]
fn a_helper_that_runs_its_parameter_is_named_and_its_calls_are_starts() {
    let source = "fn detach<F>(work: F) { tokio::spawn(work); }\nfn use_it() { detach(job()); }\n";
    let tree = daemon_with(source);

    // Without a helper line the helper is a problem of its own.
    let problems = problems_of(&tree, &Roster::default());
    assert!(
        problems
            .iter()
            .any(|p| p.contains("`detach`") && p.contains("no helper line")),
        "{problems:?}"
    );

    // With one, its call is a start under the helper's name.
    let roster = roster_of(
        "helper | detach | crates/daemon/src/lib.rs | a case\n\
         crates/daemon/src/lib.rs | detach | tokio::spawn | work | 1 | request | - | a case\n\
         crates/daemon/src/lib.rs | use_it | detach | job | 1 | request | - | a case\n",
    );
    assert_eq!(problems_of(&tree, &roster), Vec::<String>::new());

    // A helper line for a function that is not one is refused.
    let roster = roster_of("helper | missing | crates/daemon/src/lib.rs | a case\n");
    let problems = problems_of(&daemon_with("fn serve() {}\n"), &roster);
    assert!(
        problems.iter().any(|p| p.contains("`missing`")),
        "{problems:?}"
    );
}

#[test]
fn a_class_that_the_source_decides_must_agree_with_the_source() {
    let awaited = daemon_with("async fn serve() { tokio::task::spawn_blocking(work).await; }\n");
    let row = |class: &str| {
        roster_of(&format!(
            "crates/daemon/src/lib.rs | serve | tokio::task::spawn_blocking | work | 1 | {class} | 7 | a case\n"
        ))
    };
    assert!(problems_of(&awaited, &row("joined")).is_empty());
    let problems = problems_of(&awaited, &row("request"));
    assert!(
        problems.iter().any(|p| p.contains("class joined")),
        "{problems:?}"
    );
    // A start that is awaited at once cannot be a long-lived task by its row.
    let problems = problems_of(&awaited, &row("supervised-later"));
    assert!(
        problems.iter().any(|p| p.contains("class joined")),
        "{problems:?}"
    );

    let gated =
        daemon_with("#[cfg(feature = \"testing\")]\npub fn serve() { tokio::spawn(work()); }\n");
    let row = |class: &str| {
        roster_of(&format!(
            "crates/daemon/src/lib.rs | serve | tokio::spawn | work | 1 | {class} | 7 | a case\n"
        ))
    };
    assert!(problems_of(&gated, &row("test")).is_empty());
    assert!(!problems_of(&gated, &row("request")).is_empty());
    // And a row of class test whose start a shipped build compiles in.
    let problems = problems_of(&daemon_with(ONE_START), &row("test"));
    assert!(
        problems.iter().any(|p| p.contains("shipped build")),
        "{problems:?}"
    );
}

#[test]
fn a_roster_line_that_is_not_a_row_is_refused() {
    assert!(roster::parse("a | b | c\n").is_err(), "too few columns");
    assert!(
        roster::parse("f | g | tokio::spawn | h | 0 | request | - | n\n").is_err(),
        "a count of nought"
    );
    assert!(
        roster::parse("f | g | tokio::spawn | h | 1 | someday | - | n\n").is_err(),
        "an unknown class"
    );
    assert!(
        roster::parse("f | g | tokio::spawn | h | 1 | supervised-later | - | n\n").is_err(),
        "a supervised-later row with no task number"
    );
    let twice = "f | g | tokio::spawn | h | 1 | request | - | n\nf | g | tokio::spawn | h | 1 | request | - | n\n";
    assert!(roster::parse(twice).is_err(), "two rows with one key");
}
