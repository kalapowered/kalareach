//! A removal acts on the data directory only through what its own inspection found in the same run:
//! a directory that the inspection opened and approved. Where it found none, the removal looks at
//! the path once more, only to refuse with the reason, and nothing is deleted after that look; a
//! directory that was approved empty is removed as it is, and nothing in it is read or deleted.

use std::cell::Cell;
use std::fs;
use std::path::Path;

use kr_boundary_windows::records::{Begin, Inspection, begin, remove_empty};

fn decide(
    found: Inspection<&'static str>,
    there_now: bool,
    quiet: bool,
    asked: &Cell<u32>,
) -> Begin<&'static str> {
    begin(
        found,
        &|| {
            asked.set(asked.get() + 1);
            there_now
        },
        quiet,
        Path::new("Boundary"),
    )
}

/// The table of what a removal does first, from what its inspection found and from whether
/// something is at the directory's name now.
#[test]
fn nothing_is_acted_on_that_the_inspection_did_not_approve() {
    let asked = Cell::new(0);
    // Found absent, and something is there now, in either mode: refused, never finished or removed.
    for quiet in [true, false] {
        match decide(Inspection::Absent, true, quiet, &asked) {
            Begin::Refuse(text) => {
                assert!(
                    text.contains("was not there when the removal looked"),
                    "{text}"
                );
                assert!(text.contains("nothing was removed"), "{text}");
                assert!(!text.contains("nothing is installed"), "{text}");
            }
            other => panic!("quiet {quiet}: {other:?}"),
        }
    }
    // Found absent and still absent: a rollback ends quietly, a removal says nothing is installed.
    assert_eq!(
        decide(Inspection::Absent, false, true, &asked),
        Begin::Nothing
    );
    assert_eq!(
        decide(Inspection::Absent, false, false, &asked),
        Begin::Refuse("nothing is installed".to_owned())
    );
    assert_eq!(
        asked.get(),
        4,
        "the path is looked at once per absent finding"
    );
}

/// A directory that the inspection approved is acted on without another look at its path.
#[test]
fn an_approved_directory_is_not_looked_at_again() {
    let asked = Cell::new(0);
    assert_eq!(
        decide(Inspection::Recorded("manifest"), false, true, &asked),
        Begin::Remove("manifest")
    );
    assert_eq!(
        decide(Inspection::Empty, false, false, &asked),
        Begin::FinishEmpty
    );
    assert_eq!(asked.get(), 0);
}

/// An empty directory goes, and with nothing else. What was put in it after the inspection (a
/// record, `staging` with a file, a plain file) is not deleted, the directory stays, and the
/// refusal names it.
#[test]
fn removing_the_empty_directory_deletes_nothing_in_it() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("Boundary");
    fs::create_dir(&data).unwrap();
    assert!(remove_empty(&data).is_empty());
    assert!(!data.exists());
    assert!(
        remove_empty(&data).is_empty(),
        "a directory that is gone is gone"
    );

    fs::create_dir(&data).unwrap();
    fs::write(data.join("prior.json"), b"{}").unwrap();
    fs::write(data.join("manifest.json"), b"{}").unwrap();
    fs::create_dir(data.join("staging")).unwrap();
    fs::write(data.join("staging").join("policy.xml"), b"x").unwrap();
    let stayed = remove_empty(&data);
    assert_eq!(stayed.len(), 1, "{stayed:?}");
    assert!(stayed[0].contains("Boundary"), "{stayed:?}");
    assert!(data.join("prior.json").exists());
    assert!(data.join("manifest.json").exists());
    assert!(data.join("staging").join("policy.xml").exists());
}
