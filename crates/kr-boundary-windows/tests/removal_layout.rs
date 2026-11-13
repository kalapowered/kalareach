//! The removal's last deletions in the data directory follow what its own inspection found. The
//! journal's files and the empty `run` and `journal` directories go only where the inspection
//! opened and approved the directory; one that was absent then and is there now is left, and the
//! text says so. A look that follows no link finds what is at a name, a link that points nowhere
//! included.

use std::fs;
use std::path::{Path, PathBuf};

use kr_boundary_windows::records::{Look, Seen, finish_journal_and_run, look};

struct Data {
    _root: tempfile::TempDir,
    journal: PathBuf,
    run: PathBuf,
}

impl Data {
    fn new() -> Data {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("Boundary");
        Data {
            journal: data.join("journal"),
            run: data.join("run"),
            _root: root,
        }
    }

    fn with(self, journal: bool, run: bool) -> Data {
        fs::create_dir_all(self.journal.parent().unwrap()).unwrap();
        if journal {
            fs::create_dir(&self.journal).unwrap();
        }
        if run {
            fs::create_dir(&self.run).unwrap();
        }
        self
    }

    fn finish(&self, seen: Seen) -> Vec<String> {
        finish_journal_and_run(&self.journal, &self.run, seen)
    }
}

const BOTH: Seen = Seen {
    journal: true,
    run: true,
};

fn journal_file(directory: &Path, name: &str) -> PathBuf {
    let path = directory.join(format!("{name}.journal"));
    fs::write(&path, b"{}").unwrap();
    path
}

#[test]
fn directories_that_the_inspection_approved_lose_their_journal_files_and_go_when_empty() {
    let case = Data::new().with(true, true);
    let first = journal_file(&case.journal, "0123");
    let second = journal_file(&case.journal, "4567");
    let failures = case.finish(BOTH);
    assert!(failures.is_empty(), "{failures:?}");
    assert!(!first.exists() && !second.exists());
    assert!(!case.journal.exists() && !case.run.exists());
}

#[test]
fn a_run_directory_that_holds_something_stays_and_is_named() {
    let case = Data::new().with(true, true);
    fs::create_dir(case.run.join("root-0123")).unwrap();
    let failures = case.finish(BOTH);
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(
        failures[0].contains("failed (") && failures[0].contains("the removal run again reads it"),
        "{failures:?}"
    );
    assert!(failures[0].contains(&case.run.display().to_string()));
    assert!(case.run.join("root-0123").exists());
    assert!(!case.journal.exists());
}

#[test]
fn a_journal_directory_with_another_entry_keeps_what_is_not_a_journal_file() {
    let case = Data::new().with(true, false);
    let journal = journal_file(&case.journal, "0123");
    let other = case.journal.join("notes.txt");
    fs::write(&other, b"x").unwrap();
    let failures = case.finish(BOTH);
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(!journal.exists());
    assert!(other.exists());
}

/// Rule 1 at its last place: a directory that was absent at the inspection and is there now was
/// opened by no check, so nothing in it and not the directory itself is deleted, and the text
/// says that it was not there when the removal looked for it.
#[test]
fn a_directory_that_was_absent_at_the_inspection_and_is_there_now_is_left_and_named() {
    for (journal_seen, run_seen) in [(false, false), (true, false), (false, true)] {
        let case = Data::new().with(true, true);
        let kept = journal_file(&case.journal, "0123");
        let root = case.run.join("root-0123");
        fs::create_dir(&root).unwrap();
        let failures = case.finish(Seen {
            journal: journal_seen,
            run: run_seen,
        });
        let said_unseen = |path: &Path| {
            failures.iter().any(|text| {
                text.contains(&path.display().to_string())
                    && text.contains("was not there when the removal looked for it")
                    && text.contains("so it was not removed")
            })
        };
        let case_text = format!("journal seen {journal_seen}, run seen {run_seen}: {failures:?}");
        // The directory that the inspection did not see is left whole and named.
        assert_eq!(said_unseen(&case.journal), !journal_seen, "{case_text}");
        assert_eq!(said_unseen(&case.run), !run_seen, "{case_text}");
        assert!(root.exists(), "{case_text}");
        assert_eq!(kept.exists(), !journal_seen, "{case_text}");
        assert_eq!(case.journal.exists(), !journal_seen, "{case_text}");
        assert!(case.run.exists(), "{case_text}");
    }
}

#[test]
fn directories_that_are_absent_at_the_inspection_and_now_are_nothing_to_remove() {
    let case = Data::new().with(false, false);
    assert!(case.finish(Seen::default()).is_empty());
    // One that the inspection approved and that is gone by now is nothing to remove either.
    assert!(case.finish(BOTH).is_empty());
}

#[cfg(unix)]
#[test]
fn a_link_at_an_unseen_name_is_left_and_what_it_points_to_is_untouched() {
    let case = Data::new().with(false, false);
    let target = case.run.parent().unwrap().join("elsewhere");
    fs::create_dir(&target).unwrap();
    let kept = journal_file(&target, "0123");
    std::os::unix::fs::symlink(&target, &case.journal).unwrap();
    let failures = case.finish(Seen::default());
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(failures[0].contains("was not there when the removal looked for it"));
    assert!(kept.exists());
    assert!(fs::symlink_metadata(&case.journal).is_ok());
}

#[test]
fn a_look_for_an_entry_finds_a_file_a_directory_and_not_an_absent_name() {
    let folder = tempfile::tempdir().unwrap();
    let file = folder.path().join("file");
    fs::write(&file, b"x").unwrap();
    assert!(matches!(look(&file), Look::There));
    assert!(matches!(look(folder.path()), Look::There));
    assert!(matches!(
        look(&folder.path().join("absent")),
        Look::NotThere
    ));
}

/// A look that fails for any reason but the name's absence is neither "there" nor "not there": it
/// answers "not read", with its error.
#[cfg(unix)]
#[test]
fn a_look_that_fails_is_not_read_and_carries_its_error() {
    let folder = tempfile::tempdir().unwrap();
    let file = folder.path().join("file");
    fs::write(&file, b"x").unwrap();
    // A name below a file: the look answers "not a directory", which is not an answer of absence.
    match look(&file.join("below")) {
        Look::Unread(error) => assert_ne!(error.kind(), std::io::ErrorKind::NotFound),
        other => panic!("{other:?}"),
    }
}

/// A journal or run directory that the inspection did not see and whose look fails now is named
/// with the error of the look, and no text says that something is there.
#[cfg(unix)]
#[test]
fn a_directory_that_the_inspection_did_not_see_and_cannot_be_looked_at_is_named_with_its_error() {
    let folder = tempfile::tempdir().unwrap();
    let file = folder.path().join("file");
    fs::write(&file, b"x").unwrap();
    let failures =
        finish_journal_and_run(&file.join("journal"), &file.join("run"), Seen::default());
    assert_eq!(failures.len(), 2, "{failures:?}");
    for text in &failures {
        assert!(
            text.contains("was not there when the removal looked for it")
                && text.contains("a look at it now failed (")
                && !text.contains("something is there"),
            "{text}"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_link_that_points_nowhere_is_something_that_is_there() {
    let folder = tempfile::tempdir().unwrap();
    let link = folder.path().join("Boundary");
    std::os::unix::fs::symlink(folder.path().join("gone"), &link).unwrap();
    // The look that follows a link finds nothing, and the removal then treated the name as free.
    assert!(!link.exists());
    assert!(matches!(look(&link), Look::There));
}
