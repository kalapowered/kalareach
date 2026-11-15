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
//! function all change the list. A function that runs a closure or a future of its caller on a
//! task is a helper: its line is listed, and each call of it is a start, keyed by what the caller
//! hands over at the parameter's place. It does not hold a lifetime: a helper that is given a
//! longer life without a new start, and a start that only a dependency outside this repository
//! makes, are not seen.
//!
//! How each class of the roster is held:
//!
//! * `test` is held in both directions: a start that only a test build or the `testing` feature
//!   compiles in has this class, and a row of this class has such a start.
//! * `joined` is held in both directions: a start that is awaited where it stands has this class,
//!   and a row of this class whose start is not awaited where it stands carries a
//!   `join(function on name)` marker in its note, which the case checks against the source: where
//!   the function is the one that holds the start, the start's own handle (`let name = start(..)`)
//!   is awaited under that name in the scope where it is bound, by `name.await` or as the future of
//!   a `select!` branch (not in a branch's handler or precondition, where dropping or aborting it
//!   waits for nothing); where it is another function, that function awaits that name.
//! * `request` names its bound. The note of a `request` row begins with
//!   `bound(form at path:line)`, where the form is one of five (`await`, `owned-set`, `guard`,
//!   `connection-guard`, `channel`; `roster::FORMS` says what each means) and the place is a line of
//!   a file of the tree that holds what the form names: an `.await`, a `JoinSet` that is no `use`,
//!   an `impl .. Drop for ..` (for `connection-guard` of a type with `Connection` in its name), or a
//!   method call that receives. A `request` row with no bound, with another word for its form, with
//!   a place that is no line of a file of the tree or whose line holds none of those words fails.
//!   The check reads the line's words: it does not see that the `.await` is the task's handle's,
//!   that the `JoinSet` is the one the task goes into, that the `Drop` aborts the task, or that the
//!   receive is in every wait of the task; a person's read of the code decides those. A row for which
//!   no place holds is not `request`.
//! * `supervised-later`, `other_crate`, the task numbers and the rest of the notes are held by a
//!   person's read alone. The case holds that each start has a row, not what the row says of the
//!   start's lifetime or whether the class of a row is right: no case can know that a task outlives
//!   its request, so the class of every `other_crate` row is a person's read of the code to the end
//!   of the task. A start whose end the request does not bound is not `request`; where the code does
//!   not show the bound, the row takes the supervisor's class.
//!
//! The linked crates `kr-worker` and `kr-describe` keep a row for each start by name, and a list
//! of the function paths of those two crates that the rest of the daemon's code names
//! (`names` lines) is held in both directions: a path that the code names and the list lacks fails,
//! and so does a listed path that the code no longer names. This does not see a call that goes
//! through another function, which needs a call graph; a method called on a value of a type of
//! those crates; or a function reached through a glob import, which is listed as the glob.
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

/// The linked crates whose own starts have rows by name, and whose paths that the rest of the
/// daemon's code names are listed.
const WATCHED: &[&str] = &["kr-worker", "kr-describe"];

/// The scan of a tree, with the roster's helper lines, listing the paths of the crates named.
fn scan_watching(files: &dyn Files, daemon: &str, roster: &Roster, watched: &[&str]) -> Scan {
    let daemon = Path::new(daemon);
    let crates = scan::linked_crates(files, daemon).expect("the linked crates are found");
    let roots = scan::root_files(files, &crates, daemon).expect("the roots are found");
    let watched: Vec<scan::Watched> = crates
        .iter()
        .filter(|linked| watched.contains(&linked.name.as_str()))
        .map(|linked| scan::Watched {
            ident: linked.name.replace('-', "_"),
            dir: linked.dir.clone(),
        })
        .collect();
    scan::scan(files, &roots, &roster.helper_scopes(), &watched).expect("the source is read")
}

/// The scan of a tree, with the roster's helper lines.
fn scan_of(files: &dyn Files, daemon: &str, roster: &Roster) -> Scan {
    scan_watching(files, daemon, roster, &[])
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
    let found = scan_watching(&disk, DAEMON, &roster, WATCHED);
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
    // Every long-lived task has a row, and so does the family of threads that no request bounds.
    for number in 1..=36 {
        assert!(
            roster.rows.iter().any(|row| row.task == Some(number)),
            "the roster has no row for long-lived task {number}"
        );
    }
}

#[test]
fn every_request_row_names_a_bound_that_its_place_holds() {
    let roster = real_roster();
    let disk = scan::Disk(repository());
    let problems = roster::bound_problems(&roster, &disk);
    assert!(
        problems.is_empty(),
        "{} bound(s) of the roster that do not hold:\n{}",
        problems.len(),
        problems.join("\n")
    );
    // Each of the five forms is in use, so that a roster that held none would not pass unseen.
    for form in roster::FORMS {
        let marker = format!("bound({form} at ");
        assert!(
            roster.rows.iter().any(|row| row.note.starts_with(&marker)),
            "no row names the form {form}"
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

/// The names of the helpers a scan found.
fn helpers_of(tree: &Memory, roster: &Roster) -> Vec<String> {
    scan_of(tree, "crates/daemon", roster)
        .helper_shapes
        .iter()
        .map(|shape| format!("{}@{}", shape.name, shape.position))
        .collect()
}

#[test]
fn a_helper_that_runs_its_parameter_is_named_and_its_calls_are_starts() {
    let source = "fn detach<F: std::future::Future>(work: F) { tokio::spawn(work); }\n\
                  fn use_it() { detach(job()); }\n";
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
fn a_helper_is_seen_in_every_form_that_runs_its_parameter() {
    // Each of these starts something other than the bare parameter: a block that awaits it, a
    // closure that calls it, and a local that was made from it.
    let mut missed = Vec::new();
    for (source, name) in [
        (
            "fn detach(work: impl std::future::Future<Output = ()> + Send + 'static) {\n\
                 tokio::spawn(async move { work.await });\n\
             }\n",
            "detach",
        ),
        (
            "fn on_a_thread(work: impl FnOnce() + Send + 'static) {\n\
                 std::thread::spawn(move || work());\n\
             }\n",
            "on_a_thread",
        ),
        (
            "fn each<S, T>(set: &mut Set, mut serve: S)\n\
             where S: FnMut() -> Option<T>, T: std::future::Future<Output = ()> + Send + 'static {\n\
                 let Some(task) = serve() else { return };\n\
                 set.spawn(task);\n\
             }\n",
            "each",
        ),
        (
            "fn later(work: Box<dyn FnOnce() + Send>) {\n\
                 let task = work;\n\
                 std::thread::spawn(task);\n\
             }\n",
            "later",
        ),
    ] {
        let tree = daemon_with(source);
        let problems = problems_of(&tree, &Roster::default());
        if !problems
            .iter()
            .any(|p| p.contains(&format!("`{name}`")) && p.contains("no helper line"))
        {
            missed.push(name);
        }
    }
    assert!(
        missed.is_empty(),
        "helpers the scan did not see: {missed:?}"
    );

    // The twins start the same way and are not helpers: a parameter that is data, a local that is
    // what a closure returned, and a start that is awaited where it stands.
    for source in [
        "fn notify(label: String) { tokio::spawn(async move { say(label).await }); }\n",
        "fn watch(mut read: impl FnMut() -> Option<u8>) {\n\
             let found = read();\n\
             tokio::spawn(async move { use_it(found).await });\n\
         }\n",
        "async fn blocking(work: impl FnOnce() + Send + 'static) {\n\
             tokio::task::spawn_blocking(work).await;\n\
         }\n",
        "fn launch(first: &Command, before: impl FnOnce()) { spawn_process(first, before); }\n",
    ] {
        let tree = daemon_with(source);
        assert_eq!(
            helpers_of(&tree, &Roster::default()),
            Vec::<String>::new(),
            "{source}"
        );
    }
}

#[test]
fn a_helper_is_seen_through_each_spelling_of_its_parameters_type() {
    // The type that a task runs is a generic of the enclosing `impl` or `trait`, a bare function
    // type, a boxed future under its alias, a reference to a trait object, or a trait that turns
    // into a future.
    let mut missed = Vec::new();
    for (source, name) in [
        (
            "impl<W: Fn() + Send + 'static> Pool<W> {\n\
                 fn later(&self, work: W) { std::thread::spawn(move || work()); }\n\
             }\n",
            "later",
        ),
        (
            "trait Starter<W: std::future::Future<Output = ()> + Send + 'static> {\n\
                 fn begin(&self, work: W) { tokio::spawn(work); }\n\
             }\n",
            "begin",
        ),
        (
            "fn plain(work: fn()) { std::thread::spawn(work); }\n",
            "plain",
        ),
        (
            "fn boxed(work: BoxFuture<'static, ()>) { tokio::spawn(work); }\n",
            "boxed",
        ),
        (
            "fn borrowed(work: &'static dyn Fn()) { std::thread::spawn(move || work()); }\n",
            "borrowed",
        ),
        (
            "fn turned(work: impl IntoFuture<Output = ()> + Send + 'static) {\n\
                 tokio::spawn(async move { work.await });\n\
             }\n",
            "turned",
        ),
    ] {
        let problems = problems_of(&daemon_with(source), &Roster::default());
        if !problems
            .iter()
            .any(|p| p.contains(&format!("`{name}`")) && p.contains("no helper line"))
        {
            missed.push(name);
        }
    }
    assert!(
        missed.is_empty(),
        "helpers the scan did not see: {missed:?}"
    );

    // The twins are not helpers: a generic that no bound makes a closure, and a local that a
    // parameter made and a later `let` of the same name replaced with something else.
    for source in [
        "impl<W> Pool<W> {\n\
             fn later(&self, work: W) { std::thread::spawn(move || work()); }\n\
         }\n",
        "fn shadowed(work: impl FnOnce() + Send + 'static) {\n\
             let task = work;\n\
             drop(task);\n\
             let task = made_elsewhere();\n\
             std::thread::spawn(task);\n\
         }\n",
    ] {
        assert_eq!(
            helpers_of(&daemon_with(source), &Roster::default()),
            Vec::<String>::new(),
            "{source}"
        );
    }
}

#[test]
fn a_method_of_a_helpers_name_is_not_a_call_of_the_helper() {
    let source = "fn detach(work: impl FnOnce() + Send + 'static) { std::thread::spawn(work); }\n\
                  fn serve(session: Session) { detach(|| first()); session.detach(10); }\n";
    let roster = roster_of(
        "helper | detach | crates/daemon/src/lib.rs | a case\n\
         crates/daemon/src/lib.rs | detach | std::thread::spawn | work | 1 | request | - | a case\n\
         crates/daemon/src/lib.rs | serve | detach | closure{first} | 1 | request | - | a case\n",
    );
    assert_eq!(
        problems_of(&daemon_with(source), &roster),
        Vec::<String>::new()
    );

    // The twin: where the helper takes `self`, a call by a method is a start.
    let source = "impl Pool {\n\
                      fn detach(&self, work: impl FnOnce() + Send + 'static) { std::thread::spawn(work); }\n\
                      fn serve(&self) { self.detach(|| first()); }\n\
                  }\n";
    let found = starts_of(&daemon_with(source), &roster);
    assert!(
        found.contains(&".detach closure{first}".to_string()),
        "{found:?}"
    );
}

#[test]
fn a_helpers_call_is_keyed_by_the_argument_at_the_parameters_place() {
    let source = "\
        fn each<S, T>(listener: &Listener, mut serve: S)\n\
        where S: FnMut() -> Option<T>, T: std::future::Future<Output = ()> + Send + 'static {\n\
            let Some(task) = serve() else { return };\n\
            set.spawn(task);\n\
        }\n\
        impl Pool {\n\
            fn within<T>(&self, deadline: u64, read: impl FnOnce() -> T + Send + 'static) {\n\
                std::thread::spawn(move || read());\n\
            }\n\
            fn first(&self) { self.within(10, || reading()); }\n\
            fn second(pool: &Pool) { Pool::within(pool, 10, || other()); }\n\
        }\n\
        fn serve_all(listener: &Listener) { each(&listener, || client()); }\n";
    let roster = roster_of(
        "helper | each | crates/daemon/src/lib.rs | a case\n\
         helper | within | crates/daemon/src/lib.rs | a case\n",
    );
    let found = starts_of(&daemon_with(source), &roster);
    for expected in [
        "each closure{client}",
        ".within closure{reading}",
        "Pool::within closure{other}",
    ] {
        assert!(
            found.contains(&expected.to_string()),
            "{expected} not in {found:?}"
        );
    }
    assert_eq!(
        helpers_of(&daemon_with(source), &roster),
        ["each@1", "within@1"]
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

const JOINED_ELSEWHERE: &str = "\
    async fn serve() { let task = tokio::spawn(work()); drive(task).await; }\n\
    async fn drive(task: Handle) { let _ = task.await; }\n";

fn joined_row(class: &str, note: &str) -> Roster {
    roster_of(&format!(
        "crates/daemon/src/lib.rs | serve | tokio::spawn | work | 1 | {class} | - | {note}\n"
    ))
}

#[test]
fn a_join_that_is_removed_or_never_marked_fails() {
    let tree = daemon_with(JOINED_ELSEWHERE);
    let marked = joined_row("joined", "the handle is awaited: join(drive on task)");
    assert_eq!(problems_of(&tree, &marked), Vec::<String>::new());

    // The join is removed: the handle is dropped and the marker no longer holds.
    let removed = daemon_with(
        "async fn serve() { let task = tokio::spawn(work()); drive(task).await; }\n\
         async fn drive(task: Handle) { drop(task); }\n",
    );
    let problems = problems_of(&removed, &marked);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        problems[0].contains("does not await it there"),
        "{problems:?}"
    );

    // A row of class joined whose start is not awaited where it stands, with no marker.
    let problems = problems_of(&tree, &joined_row("joined", "awaited elsewhere"));
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        problems[0].contains("names where it is joined"),
        "{problems:?}"
    );

    // A marker that names another function, or another name, is not a join of this start.
    for note in ["join(serve on task)", "join(drive on other)"] {
        let problems = problems_of(&tree, &joined_row("joined", note));
        assert_eq!(problems.len(), 1, "{note}: {problems:?}");
    }

    // A marker on a row that is not class joined is a mistake.
    let problems = problems_of(&tree, &joined_row("request", "join(drive on task)"));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("only a row of class joined has a join marker")),
        "{problems:?}"
    );

    // What a `select!` waits on is a join as well, and so is a handle awaited inside a macro.
    let selecting = daemon_with(
        "async fn serve() {\n\
             let task = tokio::spawn(work());\n\
             tokio::select! { done = task => done, () = stop() => {} }\n\
         }\n",
    );
    let marked = joined_row("joined", "the select waits on it: join(serve on task)");
    assert_eq!(problems_of(&selecting, &marked), Vec::<String>::new());
    let not_selected = daemon_with(
        "async fn serve() {\n\
             let task = tokio::spawn(work());\n\
             tokio::select! { () = stop() => {} }\n\
         }\n",
    );
    assert_eq!(problems_of(&not_selected, &marked).len(), 1);
}

#[test]
fn a_select_branch_that_only_drops_or_aborts_the_handle_is_not_a_join() {
    let marked = joined_row("joined", "the select waits on it: join(serve on task)");
    let serving = |branches: &str| {
        daemon_with(&format!(
            "async fn serve() {{\n\
                 let task = tokio::spawn(work());\n\
                 tokio::select! {{ {branches} }}\n\
             }}\n"
        ))
    };

    // The handle is the future of a branch, with or without a precondition, or a handler awaits it.
    for branches in [
        "done = task => done, () = stop() => {}",
        "done = &mut task, if armed => done, () = stop() => {}",
        "biased; () = stop() => { task.await; }",
    ] {
        assert_eq!(
            problems_of(&serving(branches), &marked),
            Vec::<String>::new(),
            "{branches}"
        );
    }

    // A branch whose handler only drops or aborts the handle, or names it in a precondition, does
    // not wait on it.
    for branches in [
        "() = stop() => { drop(task); }",
        "() = stop() => task.abort(),",
        "result = tokio::signal::ctrl_c() => { drop(task); result?; }, () = other() => {}",
        "() = stop(), if task.is_finished() => {}",
    ] {
        let problems = problems_of(&serving(branches), &marked);
        assert_eq!(problems.len(), 1, "{branches}: {problems:?}");
        assert!(
            problems[0].contains("does not await it there"),
            "{branches}: {problems:?}"
        );
    }
}

#[test]
fn a_name_that_a_select_handler_or_branch_binds_is_not_the_handle() {
    let marked = joined_row("joined", "the select waits on it: join(serve on task)");
    let serving = |branches: &str| {
        daemon_with(&format!(
            "async fn serve() {{\n\
                 let task = tokio::spawn(work());\n\
                 tokio::select! {{ {branches} }}\n\
             }}\n"
        ))
    };

    // A local of the handle's name that a branch's pattern or its handler binds is not the handle:
    // awaiting it joins nothing, whatever else the handler does with the handle.
    for branches in [
        // The handler drops the handle and awaits a local of its name.
        "result = tokio::signal::ctrl_c() => { drop(task); let task = async { result }; task.await?; }, () = other() => {}",
        "Some(task) = jobs() => { task.await; }, () = other() => {}",
        "() = stop() => { let task = jobs(); task.await; }",
        "() = stop() => { let (first, task) = pair(); task.await; }",
        "() = stop() => { let task: Handle = jobs(); task.await; }",
        "() = stop() => { if let Some(task) = jobs() { task.await; } }",
        "() = stop() => { while let Some(task) = jobs() { task.await; } }",
        "() = stop() => { for task in jobs() { task.await; } }",
        "() = stop() => { match jobs() { Some(task) => { task.await; } None => {} } }",
        "() = stop() => { match jobs() { Some(task) => task.await, None => () } }",
    ] {
        let problems = problems_of(&serving(branches), &marked);
        assert_eq!(problems.len(), 1, "{branches}: {problems:?}");
        assert!(
            problems[0].contains("does not await it there"),
            "{branches}: {problems:?}"
        );
    }

    // The handle is awaited where the name is not shadowed: before the local is made, in the
    // `let` that makes it, after its scope has ended, in another arm, or under a guard that only
    // mentions it.
    for branches in [
        "() = stop() => { task.await; let task = jobs(); drop(task); }",
        "() = stop() => { let task = task.await; drop(task); }",
        "() = stop() => { { let task = jobs(); drop(task); } task.await; }",
        "() = stop() => { if let Some(task) = jobs() { drop(task); } task.await; }",
        "() = stop() => { for task in jobs() { drop(task); } task.await; }",
        "() = stop() => { match jobs() { Some(task) => drop(task), None => task.await } }",
        "() = stop() => { match jobs() { Some(other) if task.is_finished() => { task.await; } _ => {} } }",
        "Some(other) = jobs() => { task.await; }, () = stop() => {}",
        "done = task => done, Some(task) = jobs() => { drop(task); }",
    ] {
        assert_eq!(
            problems_of(&serving(branches), &marked),
            Vec::<String>::new(),
            "{branches}"
        );
    }

    // A handle handed to another function: a local of the parameter's name is not the parameter.
    let elsewhere = |branches: &str| {
        daemon_with(&format!(
            "async fn serve() {{ let task = tokio::spawn(work()); drive(task).await; }}\n\
             async fn drive(task: Handle) {{ tokio::select! {{ {branches} }} }}\n"
        ))
    };
    let marked = joined_row("joined", "awaited elsewhere: join(drive on task)");
    assert_eq!(
        problems_of(
            &elsewhere("done = task => done, () = stop() => {}"),
            &marked
        ),
        Vec::<String>::new()
    );
    let problems = problems_of(
        &elsewhere("() = stop() => { let task = jobs(); task.await; }"),
        &marked,
    );
    assert_eq!(problems.len(), 1, "{problems:?}");
}

#[test]
fn a_handle_of_the_same_name_in_another_scope_is_not_the_join() {
    let both = roster_of(
        "crates/daemon/src/lib.rs | serve | tokio::spawn | first | 1 | joined | - | join(serve on task)\n\
         crates/daemon/src/lib.rs | serve | tokio::spawn | second | 1 | joined | - | join(serve on task)\n",
    );
    let scoped = |first: &str, second: &str| {
        daemon_with(&format!(
            "async fn serve() {{\n\
                 {{ let task = tokio::spawn(first()); {first} }}\n\
                 {{ let task = tokio::spawn(second()); {second} }}\n\
             }}\n"
        ))
    };

    // Each scope awaits its own handle.
    assert_eq!(
        problems_of(&scoped("task.await;", "task.await;"), &both),
        Vec::<String>::new()
    );
    // One scope's await does not stand for the other scope's handle.
    for (first, second, refused) in [
        ("drop(task);", "task.await;", "first"),
        ("task.await;", "drop(task);", "second"),
    ] {
        let problems = problems_of(&scoped(first, second), &both);
        assert_eq!(problems.len(), 1, "{first} {second}: {problems:?}");
        assert!(
            problems[0].contains(refused),
            "{first} {second}: {problems:?}"
        );
    }

    // A loop's own `task` is not the handle either, and its twin awaits the handle outside the loop.
    let one = roster_of(
        "crates/daemon/src/lib.rs | serve | tokio::spawn | first | 1 | joined | - | join(serve on task)\n",
    );
    let looped = |awaited: &str| {
        daemon_with(&format!(
            "async fn serve() {{\n\
                 let task = tokio::spawn(first());\n\
                 {awaited}\n\
                 for task in rest() {{ task.await; }}\n\
             }}\n"
        ))
    };
    assert_eq!(problems_of(&looped("task.await;"), &one).len(), 0);
    assert_eq!(problems_of(&looped(""), &one).len(), 1);

    // A name awaited after the scope that bound it has ended is not that handle.
    let after = |inside: &str, outside: &str| {
        daemon_with(&format!(
            "async fn serve(task: Handle) {{\n\
                 {{ let task = tokio::spawn(first()); {inside} }}\n\
                 {outside}\n\
             }}\n"
        ))
    };
    assert_eq!(
        problems_of(&after("task.await;", "task.await;"), &one).len(),
        0
    );
    assert_eq!(
        problems_of(&after("drop(task);", "task.await;"), &one).len(),
        1
    );
}

#[test]
fn a_start_awaited_inside_a_macro_is_joined() {
    let tree = daemon_with(
        "async fn serve() {\n\
             let _ = matches!(tokio::task::spawn_blocking(move || work()).await, Ok(_));\n\
         }\n",
    );
    let row = |class: &str| {
        roster_of(&format!(
            "crates/daemon/src/lib.rs | serve | tokio::task::spawn_blocking | closure{{work}} | 1 | {class} | - | a case\n"
        ))
    };
    assert_eq!(problems_of(&tree, &row("joined")), Vec::<String>::new());
    let problems = problems_of(&tree, &row("request"));
    assert!(
        problems.iter().any(|p| p.contains("class joined")),
        "{problems:?}"
    );
}

#[test]
fn the_function_paths_of_a_watched_crate_that_the_code_names_are_listed_in_both_directions() {
    let tree = Memory::of(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = []\n[workspace.dependencies]\nwatched-crate = { path = \"crates/watched\" }\n",
        ),
        (
            "crates/daemon/Cargo.toml",
            "[package]\nname = \"daemon\"\n[[bin]]\nname = \"daemon\"\npath = \"src/main.rs\"\n\
             [dependencies]\nwatched-crate = { workspace = true }\n",
        ),
        ("crates/daemon/src/main.rs", "fn main() {}\n"),
        (
            "crates/daemon/src/lib.rs",
            "use watched_crate::engine::{self, Pool};\n\
             use watched_crate::prelude::*;\n\
             fn serve() {\n\
                 watched_crate::run();\n\
                 engine::start();\n\
                 let _ = Pool::new();\n\
                 let _ = Pool::DEFAULT;\n\
                 let _ = watched_crate::Kind::Fast;\n\
                 let _ = matches!(x, Some(_) if watched_crate::probe(1));\n\
             }\n\
             #[cfg(test)]\nfn only_in_tests() { watched_crate::in_a_test(); }\n",
        ),
        (
            "crates/watched/Cargo.toml",
            "[package]\nname = \"watched-crate\"\n",
        ),
        (
            "crates/watched/src/lib.rs",
            "pub fn run() { tokio::spawn(carry()); }\n\
             fn inside() { crate::run(); watched_crate::from_inside(); }\n",
        ),
    ]);
    let listed = "\
        crates/watched/src/lib.rs | run | tokio::spawn | carry | 1 | other_crate | - | a case\n\
        names | watched_crate::engine::Pool::new\n\
        names | watched_crate::engine::start\n\
        names | watched_crate::prelude::*\n\
        names | watched_crate::probe\n\
        names | watched_crate::run\n";
    let problems_with = |roster: &str| {
        let roster = roster_of(roster);
        let found = scan_watching(&tree, "crates/daemon", &roster, &["watched-crate"]);
        roster::disagreements(&roster, &found)
    };
    assert_eq!(problems_with(listed), Vec::<String>::new());

    // A path that the code names and the list lacks.
    let without = listed.replace("names | watched_crate::probe\n", "");
    let problems = problems_with(&without);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("watched_crate::probe"), "{problems:?}");

    // A listed path that the code no longer names.
    let problems = problems_with(&format!("{listed}names | watched_crate::gone\n"));
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("no longer names"), "{problems:?}");
}

#[test]
fn a_name_that_a_use_renames_is_read_as_the_path_it_stands_for() {
    let tree = Memory::of(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = []\n[workspace.dependencies]\nwatched-crate = { path = \"crates/watched\" }\n",
        ),
        (
            "crates/daemon/Cargo.toml",
            "[package]\nname = \"daemon\"\n[[bin]]\nname = \"daemon\"\npath = \"src/main.rs\"\n\
             [dependencies]\nwatched-crate = { workspace = true }\n",
        ),
        ("crates/daemon/src/main.rs", "fn main() {}\n"),
        (
            "crates/daemon/src/lib.rs",
            "use watched_crate::engine as eng;\n\
             use watched_crate::engine::{self as machinery, start as begin};\n\
             fn serve() {\n\
                 eng::go();\n\
                 machinery::stop();\n\
                 begin();\n\
             }\n",
        ),
        (
            "crates/watched/Cargo.toml",
            "[package]\nname = \"watched-crate\"\n",
        ),
        ("crates/watched/src/lib.rs", "pub fn nothing() {}\n"),
    ]);
    let found = scan_watching(
        &tree,
        "crates/daemon",
        &Roster::default(),
        &["watched-crate"],
    );
    let named: Vec<&str> = found.named.iter().map(String::as_str).collect();
    assert_eq!(
        named,
        [
            "watched_crate::engine::go",
            "watched_crate::engine::start",
            "watched_crate::engine::stop"
        ]
    );
}

#[test]
fn an_optional_dependency_and_a_library_path_are_read() {
    let tree = Memory::of(&[
        ("Cargo.toml", "[workspace]\nmembers = []\n"),
        (
            "crates/daemon/Cargo.toml",
            "[package]\nname = \"daemon\"\n[[bin]]\nname = \"daemon\"\npath = \"src/main.rs\"\n\
             [dependencies]\nextra = { path = \"../extra\", optional = true }\n\
             moved = { path = \"../moved\" }\n",
        ),
        ("crates/daemon/src/main.rs", "fn main() {}\n"),
        ("crates/daemon/src/lib.rs", "pub fn nothing() {}\n"),
        ("crates/extra/Cargo.toml", "[package]\nname = \"extra\"\n"),
        (
            "crates/extra/src/lib.rs",
            "pub fn run() { tokio::spawn(from_an_optional_dependency()); }\n",
        ),
        (
            "crates/moved/Cargo.toml",
            "[package]\nname = \"moved\"\n[lib]\npath = \"src/engine.rs\"\n",
        ),
        (
            "crates/moved/src/engine.rs",
            "pub fn run() { tokio::spawn(from_a_library_path()); }\n",
        ),
        (
            "crates/moved/src/lib.rs",
            "pub fn not_the_library() { tokio::spawn(never_read()); }\n",
        ),
    ]);
    let found = starts_of(&tree, &Roster::default());
    assert_eq!(
        found,
        [
            "tokio::spawn from_an_optional_dependency",
            "tokio::spawn from_a_library_path"
        ],
        "{found:?}"
    );
}

#[test]
fn a_start_under_cfg_any_is_skipped_only_when_every_part_is_a_test() {
    let tree = daemon_with(
        "#[cfg(any(test, unix))]\nfn some_builds() { tokio::spawn(on_unix_or_in_tests()); }\n\
         #[cfg(any(test, feature = \"testing\"))]\nfn unshipped() { tokio::spawn(in_tests_or_testing()); }\n\
         #[cfg(any(test, all(test, unix)))]\nfn only_tests() { tokio::spawn(only_in_tests()); }\n",
    );
    let found = scan_of(&tree, "crates/daemon", &Roster::default());
    let read: Vec<(&str, bool)> = found
        .starts
        .iter()
        .map(|start| (start.callee.as_str(), start.unshipped))
        .collect();
    // A shipped build on a platform that holds `unix` compiles the first in, the second only with
    // the feature that no shipped build enables, and the third never.
    assert_eq!(
        read,
        [
            ("on_unix_or_in_tests", false),
            ("in_tests_or_testing", true)
        ]
    );
}

/// Eleven lines, each of which holds the words of some forms and not of the others.
const BOUND_SOURCE: &str = r#"fn work() {}
async fn awaiting(handle: Handle) { handle.await; }
struct Set { tasks: tokio::task::JoinSet<()> }
impl Drop for Plain { fn drop(&mut self) {} }
impl Drop for ConnectionGuard { fn drop(&mut self) {} }
fn reading(mut gone: Receiver) { let _ = gone.recv(); }
// handle.await; JoinSet; gone.recv()
fn quoted() { let _ = "handle.await impl Drop for ConnectionGuard JoinSet gone.recv()"; }
use tokio::task::JoinSet;
fn quote() { let _ = '"'; handle.await; }
fn escaped() { let _ = "say \" handle.await"; }
"#;

fn bound_problems_of(class: &str, note: &str) -> Vec<String> {
    let roster = roster_of(&format!(
        "crates/daemon/src/lib.rs | serve | tokio::spawn | work | 1 | {class} | - | {note}\n"
    ));
    roster::bound_problems(
        &roster,
        &Memory::of(&[("crates/daemon/src/lib.rs", BOUND_SOURCE)]),
    )
}

#[test]
fn a_bound_holds_where_the_line_of_its_place_holds_what_its_form_names() {
    // Each form, at each line of the source: it holds at the lines that have its words and at no
    // other, whatever the other lines hold (a comment, a string, a `use`).
    let holding: [(&str, &[usize]); 5] = [
        ("await", &[2, 10]),
        ("owned-set", &[3]),
        ("guard", &[4, 5]),
        ("connection-guard", &[5]),
        ("channel", &[6]),
    ];
    for (form, lines) in holding {
        for line in 1..=11 {
            let problems = bound_problems_of(
                "request",
                &format!("bound({form} at crates/daemon/src/lib.rs:{line}); in words"),
            );
            if lines.contains(&line) {
                assert_eq!(problems, Vec::<String>::new(), "{form} at {line}");
            } else {
                assert_eq!(problems.len(), 1, "{form} at {line}: {problems:?}");
                assert!(
                    problems[0].contains("does not hold what the form"),
                    "{form} at {line}: {problems:?}"
                );
            }
        }
    }
}

#[test]
fn a_request_row_with_no_bound_or_a_bad_one_is_refused() {
    let at = |form: &str, place: &str| format!("bound({form} at {place}); in words");
    let cases: [(String, &str); 14] = [
        // No bound, or one that is not at the start of the note.
        (
            "ends with the request that started it".to_string(),
            "begins its note with",
        ),
        (
            format!(
                "ends with its request; {}",
                at("await", "crates/daemon/src/lib.rs:2")
            ),
            "begins its note with",
        ),
        // A form that is none of the five, or a misspelt one.
        (at("joined", "crates/daemon/src/lib.rs:2"), "is none of"),
        (at("gaurd", "crates/daemon/src/lib.rs:4"), "is none of"),
        (at("Await", "crates/daemon/src/lib.rs:2"), "is none of"),
        (at("", "crates/daemon/src/lib.rs:2"), "is none of"),
        // A place that is no `path:line` of a file of the tree.
        (at("await", "crates/daemon/src/lib.rs"), "is no `path:line`"),
        (
            at("await", "crates/daemon/src/lib.rs:two"),
            "is no `path:line`",
        ),
        (
            at("await", "crates/daemon/src/lib.rs:0"),
            "is no `path:line`",
        ),
        (
            at("await", "crates/daemon/src/none.rs:2"),
            "is no file of the tree",
        ),
        (
            at("await", "crates/daemon/src/lib.rs:12"),
            "which has 11 lines",
        ),
        // A marker that is not well formed.
        (
            "bound(await at crates/daemon/src/lib.rs:2".to_string(),
            "is not closed",
        ),
        ("bound(await)".to_string(), "is `bound(form at path:line)`"),
        (
            "bound() in words".to_string(),
            "is `bound(form at path:line)`",
        ),
    ];
    for (note, expected) in cases {
        let problems = bound_problems_of("request", &note);
        assert_eq!(problems.len(), 1, "{note}: {problems:?}");
        assert!(problems[0].contains(expected), "{note}: {problems:?}");
    }

    // A row of another class has no bound, and is refused when it names one.
    for class in ["joined", "other_crate", "test"] {
        assert_eq!(
            bound_problems_of(class, "a case"),
            Vec::<String>::new(),
            "{class}"
        );
        let problems = bound_problems_of(class, "bound(await at crates/daemon/src/lib.rs:2)");
        assert_eq!(problems.len(), 1, "{class}: {problems:?}");
        assert!(
            problems[0].contains("only a row of class request names a bound"),
            "{class}: {problems:?}"
        );
    }
}
