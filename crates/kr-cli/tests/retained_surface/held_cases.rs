//! The cases of the held check's reading of the releases of a level, and of its script.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;

use super::held::{Extract, Listed, parse_list, read_releases};
use super::narrower_cases::{ROOT, control, the_root};
use super::walker::{Depth, Lookup};

/// A stand-in for git that counts what it is asked, and answers from a table: for each commit the
/// directory its worker crate has, and the id of that crate's subtree.
struct Counting {
    crates: BTreeMap<&'static str, (&'static str, &'static str)>,
    calls: RefCell<Vec<String>>,
}

impl Counting {
    fn new(crates: &[(&'static str, &'static str, &'static str)]) -> Self {
        Self {
            crates: crates
                .iter()
                .map(|(commit, directory, subtree)| (*commit, (*directory, *subtree)))
                .collect(),
            calls: RefCell::new(Vec::new()),
        }
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
        for (directory, package) in [(directory, "kr-worker"), ("kr-protocol", "kr-protocol")] {
            let folder = into.join("crates").join(directory);
            std::fs::create_dir_all(&folder).map_err(|error| error.to_string())?;
            std::fs::write(
                folder.join("Cargo.toml"),
                format!("[package]\nname = \"{package}\"\n"),
            )
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
        std::fs::write(
            folder.join("lib.rs"),
            "pub fn check_envelope() {}\npub fn helper_fn() {}\n",
        )
        .map_err(|error| error.to_string())
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
        let trees = read_releases(entries, &roots, &listed(commits), extract, work.path())
            .expect("the releases are read");
        // Each tree reads the crate's rule as the extraction left it, while the folder is there.
        trees
            .iter()
            .map(|(_, tree)| tree.item("kr_worker", "helper_fn"))
            .collect::<Vec<Lookup>>()
    };

    // An empty table extracts nothing and asks git nothing.
    let none = Counting::new(&[("c1", "kr-worker", "id1")]);
    assert_eq!(read(&none, &["c1"], &[]), Vec::new());
    assert!(none.calls.borrow().is_empty(), "{:?}", none.calls.borrow());

    // Two releases that share the crate, its path and its subtree: one extraction, and both read it.
    let shared = Counting::new(&[("c1", "kr-worker", "id1"), ("c2", "kr-worker", "id1")]);
    let found = read(&shared, &["c1", "c2"], entries);
    assert_eq!(shared.called("files"), 1, "{:?}", shared.calls.borrow());
    assert!(matches!(found[0], Lookup::Found(_)), "{found:?}");
    assert_eq!(found[0], found[1]);

    // The same subtree at a new path: the digest holds the path, so it is extracted again.
    let moved = Counting::new(&[("c1", "kr-worker", "id1"), ("c2", "worker", "id1")]);
    let found = read(&moved, &["c1", "c2"], entries);
    assert_eq!(moved.called("files"), 2, "{:?}", moved.calls.borrow());
    assert!(matches!(found[1], Lookup::Found(_)), "{found:?}");
    assert_ne!(found[0], found[1]);

    // The same path and another subtree: extracted again too.
    let changed = Counting::new(&[("c1", "kr-worker", "id1"), ("c2", "kr-worker", "id2")]);
    read(&changed, &["c1", "c2"], entries);
    assert_eq!(changed.called("files"), 2, "{:?}", changed.calls.borrow());

    // Only the crates the rules are made of are extracted: `kr-protocol` has a manifest and no src.
    assert!(
        shared
            .calls
            .borrow()
            .iter()
            .all(|call| !call.starts_with("files") || call.ends_with("crates/kr-worker/src")),
        "{:?}",
        shared.calls.borrow()
    );
}
