//! A scan of the crate's product sources (`src/`) for what could make the invocation journal
//! written outside the cases.
//!
//! Only the cases write the journal: the broker's service does not run an invocation. The journal's
//! rows carry no format marker, so a build reads a row that another build wrote as its own row type
//! reads it. Two facts keep that harmless, and the two cases below hold them:
//!
//! - no source outside `win/lifecycle.rs` and `win/lifecycle/` names `serve_operate`,
//!   `run_invocation` or `recover`, the entries that begin an invocation's journal or take one up;
//! - the only implementations of `Trees`, which an invocation needs to resolve its tree, are the
//!   fixtures of `win/lifecycle/fixture.rs`.
//!
//! A change that makes either false lets production code write the journal. It must first decide,
//! with cases of its own, how a build from before the change reads each member that the change adds
//! to a row and how a build after it reads an older row; then it changes this scan.
//!
//! What the scan cannot see: a name that a macro builds, an `impl` split over several lines, and a
//! write that does not go through these entries (a second constructor of the journal). Comment lines
//! are not read. The cases run on every platform.

use std::fs;
use std::path::{Path, PathBuf};

/// The entries of the lifecycle that begin an invocation's journal or take one up: the service's
/// entry, the function that runs one invocation, and the recovery of the journals that a crash left.
const ENTRIES: [&str; 3] = ["serve_operate", "run_invocation", "recover"];

/// What a change that makes the journal reachable from production code must do first.
const MUST: &str = "the journal's rows carry no format marker, so a change that lets production code write the \
journal must first decide, with cases of its own, how a build from before the change reads each member that \
the change adds to a row and how a build after it reads an older row, and then change this scan";

fn sources(dir: &Path, found: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .expect("a source directory is read")
        .map(|entry| entry.expect("an entry is read").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            sources(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

/// The lines of code of every product source, each with its path under `src/` (written with `/`)
/// and its number: the lines that are not comments.
fn code_lines() -> Vec<(String, usize, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&src, &mut files);
    let mut lines = Vec::new();
    for path in &files {
        let relative = path
            .strip_prefix(&src)
            .expect("a source is under src")
            .to_string_lossy()
            .replace('\\', "/");
        let text = fs::read_to_string(path).expect("a source is read");
        for (index, line) in text.lines().enumerate() {
            if !line.trim_start().starts_with("//") {
                lines.push((relative.clone(), index + 1, line.to_owned()));
            }
        }
    }
    lines
}

fn is_identifier_character(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// Whether `line` names `word` as a whole identifier: `recover(` names `recover`, `recovery` does
/// not.
fn names(line: &str, word: &str) -> bool {
    line.match_indices(word).any(|(at, _)| {
        let before = line[..at].chars().next_back();
        let after = line[at + word.len()..].chars().next();
        !before.is_some_and(is_identifier_character) && !after.is_some_and(is_identifier_character)
    })
}

#[test]
fn no_code_outside_the_lifecycle_names_an_entry_that_writes_the_journal() {
    let mut found = Vec::new();
    for (file, number, line) in code_lines() {
        if file == "win/lifecycle.rs" || file.starts_with("win/lifecycle/") {
            continue;
        }
        for entry in ENTRIES {
            if names(&line, entry) {
                found.push(format!("{file}:{number} names {entry}"));
            }
        }
    }
    assert!(found.is_empty(), "{MUST}: {found:#?}");
}

#[test]
fn the_only_implementations_of_the_trees_interface_are_the_fixtures() {
    let mut found = Vec::new();
    for (file, number, line) in code_lines() {
        if file == "win/lifecycle/fixture.rs" {
            continue;
        }
        let code = line.trim_start();
        if code.starts_with("impl") && code.contains("Trees for ") {
            found.push(format!("{file}:{number} implements Trees"));
        }
    }
    assert!(found.is_empty(), "{MUST}: {found:#?}");
}
