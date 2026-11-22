//! The cases of the held check's reading of the releases of a level, and of its script.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;

use super::held::{Extract, Git, Listed, hold_releases, parse_list, read_releases};
use super::narrower::Reader;
use super::narrower_cases::{ROOT, control, leak, said, the_root};
use super::walker::{Depth, Lookup};

/// A stand-in for git that counts what it is asked, and answers from a table: for each commit the
/// directory its worker crate has, and the id of that crate's subtree.
struct Counting {
    crates: BTreeMap<&'static str, (&'static str, &'static str)>,
    calls: RefCell<Vec<String>>,
    /// Whether the worker's `src` holds a module that is a link to another file.
    linked: bool,
}

impl Counting {
    fn new(crates: &[(&'static str, &'static str, &'static str)]) -> Self {
        Self {
            crates: crates
                .iter()
                .map(|(commit, directory, subtree)| (*commit, (*directory, *subtree)))
                .collect(),
            calls: RefCell::new(Vec::new()),
            linked: false,
        }
    }

    /// The same, with `src/linked.rs` a link to `src/real.rs` and `mod linked;` in the root.
    fn with_a_source_link(mut self) -> Self {
        self.linked = true;
        self
    }

    fn called(&self, what: &str) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|call| call.starts_with(what))
            .count()
    }
}

impl Extract for Counting {
    fn manifests(&self, commit: &str, into: &Path) -> Result<(), String> {
        self.calls.borrow_mut().push(format!("manifests {commit}"));
        let (directory, _) = self.crates[commit];
        std::fs::create_dir_all(into).map_err(|error| error.to_string())?;
        std::fs::write(
            into.join("Cargo.toml"),
            "[workspace]\nresolver = \"3\"\nmembers = [\"crates/*\"]\n",
        )
        .map_err(|error| error.to_string())?;
        for (directory, package) in [(directory, "kr-worker"), ("kr-protocol", "kr-protocol")] {
            let folder = into.join("crates").join(directory);
            std::fs::create_dir_all(folder.join("src")).map_err(|error| error.to_string())?;
            std::fs::write(
                folder.join("Cargo.toml"),
                format!("[package]\nname = \"{package}\"\n"),
            )
            .map_err(|error| error.to_string())?;
            // The entry file that gives the crate a target; the crate's own `src` replaces it.
            std::fs::write(folder.join("src").join("lib.rs"), "")
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    fn subtree(&self, commit: &str, path: &str) -> Result<String, String> {
        self.calls
            .borrow_mut()
            .push(format!("subtree {commit} {path}"));
        Ok(self.crates[commit].1.to_owned())
    }

    fn files(&self, commit: &str, path: &str, into: &Path) -> Result<(), String> {
        self.calls
            .borrow_mut()
            .push(format!("files {commit} {path}"));
        let folder = into.join(path);
        std::fs::create_dir_all(&folder).map_err(|error| error.to_string())?;
        let module = if self.linked { "mod linked;\n" } else { "" };
        std::fs::write(
            folder.join("lib.rs"),
            format!(
                "{module}pub fn check_envelope() {{ let _ = \"{}\"; }}\npub fn helper_fn() {{}}\n",
                self.crates[commit].1
            ),
        )
        .map_err(|error| error.to_string())?;
        if self.linked {
            std::fs::write(folder.join("real.rs"), "pub fn real() {}\n")
                .map_err(|error| error.to_string())?;
            std::os::unix::fs::symlink("real.rs", folder.join("linked.rs"))
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}

fn listed(commits: &[&str]) -> Vec<Listed> {
    commits
        .iter()
        .map(|commit| Listed {
            tag: format!("packages/v0.78.0+{commit}"),
            commit: (*commit).to_owned(),
        })
        .collect()
}

#[test]
fn the_list_of_releases_is_two_words_a_line() {
    assert_eq!(
        parse_list("packages/v0.78.0+aaaaaaaaaaaa aaaaaaaaaaaaffff\n").expect("a list"),
        vec![Listed {
            tag: "packages/v0.78.0+aaaaaaaaaaaa".to_owned(),
            commit: "aaaaaaaaaaaaffff".to_owned(),
        }]
    );
    assert_eq!(parse_list("").expect("an empty list"), Vec::new());
    assert!(parse_list("one\n").is_err());
    assert!(parse_list("one two three\n").is_err());
}

#[test]
fn a_crate_is_extracted_once_for_the_releases_that_have_it_as_it_is() {
    let world = control();
    let entries = std::slice::from_ref(&world.entry);
    let roots = [the_root(ROOT, "kr_worker", Depth::Alone)];
    let read = |extract: &Counting, commits: &[&str], entries: &[_]| {
        let work = tempfile::tempdir().expect("a folder");
        let trees = read_releases(entries, &roots, &listed(commits), extract, work.path())?;
        // Each tree reads the crate's rule as the extraction left it, while the folder is there.
        Ok::<_, String>(
            trees
                .iter()
                .map(|(_, tree)| tree.item("kr_worker", "helper_fn"))
                .collect::<Vec<Lookup>>(),
        )
    };

    // An empty table extracts nothing and asks git nothing.
    let none = Counting::new(&[("c1", "kr-worker", "id1")]);
    let found = read(&none, &["c1"], &[]);
    assert!(none.calls.borrow().is_empty(), "{:?}", none.calls.borrow());
    assert_eq!(found, Ok(Vec::new()));

    // Two releases that share the crate, its path and its subtree: one extraction, and both read it.
    let shared = Counting::new(&[("c1", "kr-worker", "id1"), ("c2", "kr-worker", "id1")]);
    let found = read(&shared, &["c1", "c2"], entries);
    assert_eq!(shared.called("files"), 1, "{:?}", shared.calls.borrow());
    assert!(found.is_ok(), "{found:?}");
    let found = found.unwrap_or_default();
    assert!(matches!(found[0], Lookup::Found(_)), "{found:?}");
    assert_eq!(found[0], found[1]);

    // The same subtree at a new path: the digest holds the path, so it is extracted again.
    let moved = Counting::new(&[("c1", "kr-worker", "id1"), ("c2", "worker", "id1")]);
    let found = read(&moved, &["c1", "c2"], entries);
    assert_eq!(moved.called("files"), 2, "{:?}", moved.calls.borrow());
    assert!(found.is_ok(), "{found:?}");
    let found = found.unwrap_or_default();
    assert!(matches!(found[1], Lookup::Found(_)), "{found:?}");
    assert_ne!(found[0], found[1]);

    // The same path and another subtree: extracted again too.
    let changed = Counting::new(&[("c1", "kr-worker", "id1"), ("c2", "kr-worker", "id2")]);
    let found = read(&changed, &["c1", "c2"], entries);
    assert_eq!(changed.called("files"), 2, "{:?}", changed.calls.borrow());
    assert!(found.is_ok(), "{found:?}");

    // Only the crates the rules are made of are extracted: `kr-protocol` has a manifest and an entry
    // file, and no src of its own.
    assert!(
        shared
            .calls
            .borrow()
            .iter()
            .all(|call| !call.starts_with("files") || call.ends_with("crates/kr-worker/src")),
        "{:?}",
        shared.calls.borrow()
    );

    // Only the crates the rules are made of are members of a tree: the root manifest names them
    // alone, and `kr-protocol` is no crate of the tree though its manifest is there.
    let one = Counting::new(&[("c1", "kr-worker", "id1")]);
    let work = tempfile::tempdir().expect("a folder");
    let trees = read_releases(entries, &roots, &listed(&["c1"]), &one, work.path());
    assert!(trees.is_ok(), "{:?}", trees.as_ref().err());
    let trees = trees.unwrap_or_default();
    assert!(
        matches!(trees[0].1.krate("kr_worker"), Lookup::Found(_)),
        "{:?}",
        trees[0].1.krate("kr_worker")
    );
    assert_eq!(trees[0].1.krate("kr_protocol"), Lookup::Absent);
}

#[test]
fn a_source_link_is_kept_for_the_walkers_refusal() {
    let world = control();
    let entries = std::slice::from_ref(&world.entry);
    let roots = [the_root(ROOT, "kr_worker", Depth::Alone)];
    let work = tempfile::tempdir().expect("a folder");
    let extract = Counting::new(&[("c1", "kr-worker", "id1")]).with_a_source_link();
    let trees = read_releases(entries, &roots, &listed(&["c1"]), &extract, work.path())
        .expect("a link in a source is no reason to refuse the copy");
    // The walker refuses a file reached through a link, as it does in a full checkout: the copy
    // must not turn the link into a regular file that reads as any other.
    let found = trees[0].1.item("kr_worker", "helper_fn");
    assert!(
        matches!(&found, Lookup::Failed(error) if error.contains("reached through a link")),
        "{found:?}"
    );
}

/// The script that holds the narrower table's entries to the releases, run in a tree of its own
/// that has the script, a table file and a `uname` and a `cargo` that answer what a case sets.
struct Script {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    /// What the stand-in `cargo` was asked, a line each.
    cargo: String,
}

/// What the stand-in `cargo test` prints for a run of the check that goes as it should, with
/// `entries` entries and `releases` releases read, as libtest prints it with `--show-output`.
fn a_good_output(entries: usize, releases: usize) -> String {
    format!(
        "running 1 test\n\
         test narrower_rules_are_in_every_release_of_their_level ... ok\n\
         \n\
         successes:\n\
         \n\
         ---- narrower_rules_are_in_every_release_of_their_level stdout ----\n\
         narrower: {entries} entries, {releases} releases read\n\
         \n\
         \n\
         successes:\n\
         \x20   narrower_rules_are_in_every_release_of_their_level\n\
         \n\
         test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 79 filtered out; finished in 0.52s\n"
    )
}

fn a_table(entries: usize) -> String {
    let mut table = String::from("pub const NARROWER: &[Narrower] = &[");
    if entries == 0 {
        table.push_str("];\n");
        return table;
    }
    table.push('\n');
    for _ in 0..entries {
        table.push_str("    Narrower {\n        level: \"0.78\",\n    },\n");
    }
    table.push_str("];\n");
    table
}

fn the_list(releases: usize) -> String {
    (0..releases)
        .map(|at| format!("packages/v0.78.{at}+{at:012x} {at:040x}\n"))
        .collect()
}

/// Runs the script: `uname` says `system`, `table` is the table file, the generator prints `list`,
/// and the test prints `output` and ends with `status`.
fn run_script(system: &str, table: &str, list: &str, output: &str, status: i32) -> Script {
    run_script_with(system, Some(table), list, output, status)
}

/// As [`run_script`], with no table file when `table` is none.
fn run_script_with(
    system: &str,
    table: Option<&str>,
    list: &str,
    output: &str,
    status: i32,
) -> Script {
    use std::os::unix::fs::PermissionsExt;

    let folder = tempfile::tempdir().expect("a folder");
    let root = folder.path();
    let write = |path: &str, text: &str, executable: bool| {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("a folder");
        std::fs::write(&path, text).expect("a file");
        if executable {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("a mode");
        }
    };
    let script =
        std::fs::read_to_string(super::repository().join("scripts/check-narrower-entries.sh"))
            .expect("the script");
    write("scripts/check-narrower-entries.sh", &script, false);
    if let Some(table) = table {
        write(
            "crates/kr-cli/tests/retained_surface/narrower_table.rs",
            table,
            false,
        );
    }
    write("bin/uname", &format!("#!/bin/sh\necho '{system}'\n"), true);
    write("canned/list", list, false);
    write("canned/output", output, false);
    write(
        "bin/cargo",
        &format!(
            "#!/bin/sh\n\
             echo \"$*\" >> '{root}/cargo.log'\n\
             case \"$1\" in\n\
               run) cat '{root}/canned/list' ;;\n\
               test) cat '{root}/canned/output'; exit {status} ;;\n\
               *) echo \"cargo $*\" >&2; exit 99 ;;\n\
             esac\n",
            root = root.display()
        ),
        true,
    );
    let run = std::process::Command::new("bash")
        .arg(root.join("scripts/check-narrower-entries.sh"))
        .env_clear()
        .env(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                root.join("bin").display()
            ),
        )
        .env("HOME", root)
        .output()
        .expect("bash runs");
    Script {
        code: run.status.code(),
        stdout: String::from_utf8_lossy(&run.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&run.stderr).into_owned(),
        cargo: std::fs::read_to_string(root.join("cargo.log")).unwrap_or_default(),
    }
}

#[test]
fn a_platform_that_does_not_run_the_check_is_refused_before_anything_is_built() {
    let run = run_script(
        "MINGW64_NT-10.0",
        &a_table(1),
        &the_list(2),
        &a_good_output(1, 2),
        0,
    );
    assert_eq!(run.code, Some(1), "{}{}", run.stdout, run.stderr);
    assert!(
        run.stderr
            .contains("REFUSED: this check runs on macOS and Linux"),
        "{}",
        run.stderr
    );
    assert_eq!(run.cargo, "");
}

#[test]
fn an_empty_table_has_nothing_to_hold_and_builds_nothing() {
    let run = run_script("Linux", &a_table(0), &the_list(2), &a_good_output(0, 2), 0);
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    assert_eq!(run.stdout, "narrower: 0 entries, nothing to hold\n");
    assert_eq!(run.cargo, "");
}

#[test]
fn a_level_with_no_release_has_nothing_to_hold_and_runs_no_test() {
    let run = run_script("Darwin", &a_table(2), "", &a_good_output(2, 0), 0);
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    assert_eq!(
        run.stdout,
        "narrower: no release at the level, nothing to hold\n"
    );
    assert_eq!(
        run.cargo,
        "run -q --locked -p kr-protocol --bin kr-protocol-gen -- --level-releases\n"
    );
}

#[test]
fn the_output_of_a_run_that_went_as_it_should_passes() {
    let run = run_script("Linux", &a_table(2), &the_list(3), &a_good_output(2, 3), 0);
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    assert!(
        run.stdout
            .ends_with("narrower: 2 entries held in 3 releases\n"),
        "{}",
        run.stdout
    );
    assert_eq!(
        run.cargo,
        "run -q --locked -p kr-protocol --bin kr-protocol-gen -- --level-releases\n\
         test --locked -p kr-cli --test retained_surface -- --ignored --exact narrower_rules_are_in_every_release_of_their_level --show-output --format pretty --color never\n"
    );
}

#[test]
fn each_way_the_output_can_fail_the_run_is_refused_with_its_own_text() {
    let table = a_table(2);
    let list = the_list(3);
    let good = a_good_output(2, 3);
    let refused = |output: &str, status: i32, text: &str| {
        let run = run_script("Linux", &table, &list, output, status);
        (
            run.code,
            run.stderr.contains(text),
            format!("{}{}", run.stdout, run.stderr),
        )
    };
    // The test ended with a status.
    let (code, said, all) = refused(&good, 101, "the check failed (exit 101)");
    assert_eq!((code, said), (Some(1), true), "{all}");
    // No test ran: libtest says `0 passed` and the test's own line is not there.
    let none = good
        .replace("1 passed", "0 passed")
        .replace("79 filtered out", "80 filtered out");
    let (code, said, all) = refused(&none, 0, "did not run and pass exactly one test");
    assert_eq!((code, said), (Some(1), true), "{all}");
    // The test's own line is split by what a child wrote to standard error.
    let split = good.replace(
        "their_level ... ok\n",
        "their_level ... fatal: a child wrote this\nok\n",
    );
    let (code, said, all) = refused(&split, 0, "is not on one line");
    assert_eq!((code, said), (Some(1), true), "{all}");
    // The test read other counts than the script's: of the releases, and of the entries.
    let (code, said, all) = refused(
        &a_good_output(2, 4),
        0,
        "did not read 2 entries and 3 releases",
    );
    assert_eq!((code, said), (Some(1), true), "{all}");
    let (code, said, all) = refused(
        &a_good_output(1, 3),
        0,
        "did not read 2 entries and 3 releases",
    );
    assert_eq!((code, said), (Some(1), true), "{all}");
}

#[test]
fn the_table_file_counts_its_entries() {
    let script =
        std::fs::read_to_string(super::repository().join("scripts/check-narrower-entries.sh"))
            .expect("the script");
    let between = |line: &str, open: &str, close: &str| {
        line.split_once(open)
            .and_then(|(_, rest)| rest.split_once(close))
            .map(|(word, _)| word.to_owned())
            .unwrap_or_else(|| panic!("no `{open}` in {line}"))
    };
    let pattern = between(
        script
            .lines()
            .find(|line| line.contains("grep -c '"))
            .expect("the count"),
        "grep -c '",
        "'",
    );
    let table = script
        .lines()
        .find_map(|line| line.strip_prefix("table="))
        .expect("the table");
    let count = |file: &std::path::Path| {
        let run = std::process::Command::new("grep")
            .arg("-c")
            .arg(&pattern)
            .arg(file)
            .output()
            .expect("grep runs");
        String::from_utf8_lossy(&run.stdout)
            .trim()
            .parse::<usize>()
            .expect("a count")
    };
    assert_eq!(
        count(&super::repository().join(table)),
        super::narrower_table::NARROWER.len()
    );
    let folder = tempfile::tempdir().expect("a folder");
    let two = folder.path().join("two.rs");
    std::fs::write(&two, a_table(2)).expect("a file");
    assert_eq!(count(&two), 2);
}

#[test]
fn a_missing_table_is_refused_before_anything_is_built() {
    let run = run_script_with("Linux", None, &the_list(2), &a_good_output(1, 2), 0);
    assert_eq!(run.code, Some(1), "{}{}", run.stdout, run.stderr);
    assert!(
        run.stderr.contains(
            "REFUSED: crates/kr-cli/tests/retained_surface/narrower_table.rs is not here"
        ),
        "{}",
        run.stderr
    );
    assert_eq!(run.cargo, "");
}

/// The digests of the root and of the helper that the release `commit` has, read through the
/// stand-in with the subtree id `id`.
fn digests_of(commit: &'static str, id: &'static str) -> (String, String) {
    let entries = [control().entry];
    let root = the_root(ROOT, "kr_worker", Depth::Alone);
    let work = tempfile::tempdir().expect("a folder");
    let trees = read_releases(
        &entries,
        std::slice::from_ref(&root),
        &listed(&[commit]),
        &Counting::new(&[(commit, "kr-worker", id)]),
        work.path(),
    )
    .expect("a release");
    let (Lookup::Found(root), Lookup::Found(helper)) = (
        Reader::root(&trees[0].1, &root),
        trees[0].1.item("kr_worker", "helper_fn"),
    ) else {
        panic!("the rule is not in the release")
    };
    (root, helper)
}

#[test]
fn the_release_whose_rule_differs_is_named_with_its_digest() {
    let (root_one, helper_one) = digests_of("c1", "id1");
    let (root_two, helper_two) = digests_of("c2", "id2");
    assert_ne!(root_one, root_two);
    assert_eq!(helper_one, helper_two);
    let leaked = |text: &String| -> &'static str { Box::leak(text.clone().into_boxed_str()) };
    let mut entry = control().entry;
    entry.digest = leaked(&root_one);
    let mut helper = entry.helpers[0].clone();
    helper.now = leaked(&helper_one);
    entry.helpers = leak(vec![helper]);
    let roots = [the_root(ROOT, "kr_worker", Depth::Alone)];
    let work = tempfile::tempdir().expect("a folder");
    let held = hold_releases(
        &[entry],
        &roots,
        &listed(&["c1", "c2"]),
        &Counting::new(&[("c1", "kr-worker", "id1"), ("c2", "kr-worker", "id2")]),
        work.path(),
    )
    .expect("the releases are read");
    assert_eq!((held.entries, held.releases), (1, 2));
    assert_eq!(
        held.problems,
        vec![said(&format!(
            "packages/v0.78.0+c2 has the digest {root_two} for the root, the entry names {root_one}"
        ))]
    );
}

/// `git` in `folder`, with nothing of the person's configuration.
fn git(folder: &Path, arguments: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", folder)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(["-c", "user.name=a", "-c", "user.email=a@example.invalid"])
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args(arguments)
        .current_dir(folder)
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("text")
        .trim()
        .to_owned()
}

#[test]
fn two_releases_read_through_git_have_each_the_crate_they_had() {
    let folder = tempfile::tempdir().expect("a folder");
    let repository = folder.path().join("repository");
    let crate_at = repository.join("crates/kr-worker");
    std::fs::create_dir_all(crate_at.join("src")).expect("a folder");
    git(&repository, &["init", "-q", "-b", "main"]);
    std::fs::write(
        repository.join("Cargo.toml"),
        "[workspace]\nresolver = \"3\"\nmembers = [\"crates/*\"]\n",
    )
    .expect("the root manifest");
    // A crate the worker depends on by path: Cargo reads the workspace only when this crate has
    // its manifest and a target, which the extraction gives it from the entry file.
    let other = repository.join("crates/kr-protocol");
    std::fs::create_dir_all(other.join("src")).expect("a folder");
    std::fs::write(
        other.join("Cargo.toml"),
        "[package]\nname = \"kr-protocol\"\n",
    )
    .expect("a manifest");
    std::fs::write(other.join("src/lib.rs"), "pub fn elsewhere() {}\n").expect("a source");
    std::fs::write(
        crate_at.join("Cargo.toml"),
        "[package]\nname = \"kr-worker\"\n\n[dependencies]\nkr-protocol = { path = \"../kr-protocol\" }\n",
    )
    .expect("a manifest");
    let mut commits = Vec::new();
    for body in ["let _ = 1;", "let _ = 2;"] {
        std::fs::write(
            crate_at.join("src/lib.rs"),
            format!("pub fn check_envelope() {{}}\npub fn helper_fn() {{ {body} }}\n"),
        )
        .expect("a source");
        git(&repository, &["add", "-A"]);
        git(&repository, &["commit", "-q", "-m", body]);
        commits.push(git(&repository, &["rev-parse", "HEAD"]));
    }
    let reader = Git::new(repository);
    let first = reader
        .subtree(&commits[0], "crates/kr-worker")
        .expect("an id");
    let second = reader
        .subtree(&commits[1], "crates/kr-worker")
        .expect("an id");
    assert_ne!(first, second);

    let root = the_root(ROOT, "kr_worker", Depth::Alone);
    let work = folder.path().join("work");
    let trees = read_releases(
        &[control().entry],
        std::slice::from_ref(&root),
        &commits
            .iter()
            .map(|commit| Listed {
                tag: format!("packages/v0.78.0+{}", &commit[..12]),
                commit: commit.clone(),
            })
            .collect::<Vec<_>>(),
        &reader,
        &work,
    )
    .expect("the releases are read");
    let helper = |at: usize| trees[at].1.item("kr_worker", "helper_fn");
    assert!(matches!(helper(0), Lookup::Found(_)), "{:?}", helper(0));
    assert!(matches!(helper(1), Lookup::Found(_)), "{:?}", helper(1));
    assert_ne!(helper(0), helper(1));
}
