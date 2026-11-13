//! A removal acts on the data directory only through what its own inspection found in the same run:
//! a directory that the inspection opened and approved. Where it found none, the removal looks at
//! the path once more, only to refuse with the reason, and nothing is deleted after that look; a
//! directory that was approved empty is removed as it is, and nothing in it is read or deleted.

use std::cell::Cell;
use std::fs;
use std::io;
use std::path::Path;

use kr_boundary_windows::records::{Begin, Inspection, Look, begin, remove_empty};

/// What the look at the directory's name answers in a case.
#[derive(Clone, Copy)]
enum Answer {
    There,
    NotThere,
    Unread,
}

fn decide(
    found: Inspection<&'static str>,
    answer: Answer,
    quiet: bool,
    asked: &Cell<u32>,
) -> Begin<&'static str> {
    begin(
        found,
        &|| {
            asked.set(asked.get() + 1);
            match answer {
                Answer::There => Look::There,
                Answer::NotThere => Look::NotThere,
                Answer::Unread => Look::Unread(io::Error::from(io::ErrorKind::PermissionDenied)),
            }
        },
        quiet,
        Path::new("Boundary"),
    )
}

/// The table of what a removal does first, from what its inspection found and from the answer of
/// the look at the directory's name: there, not there, or not read (with its error).
#[test]
fn nothing_is_acted_on_that_the_inspection_did_not_approve() {
    let asked = Cell::new(0);
    // Found absent, and something is there now, in either mode: refused, never finished or removed.
    for quiet in [true, false] {
        match decide(Inspection::Absent, Answer::There, quiet, &asked) {
            Begin::Refuse(text) => {
                assert!(
                    text.contains("was not there when the removal looked"),
                    "{text}"
                );
                assert!(text.contains("something is there now"), "{text}");
                assert!(text.contains("nothing was removed"), "{text}");
            }
            other => panic!("quiet {quiet}: {other:?}"),
        }
    }
    // Found absent, and the look at it now could not be read, in either mode: refused with the
    // error, and the text claims no presence.
    for quiet in [true, false] {
        match decide(Inspection::Absent, Answer::Unread, quiet, &asked) {
            Begin::Refuse(text) => {
                assert!(
                    text.contains("was not there when the removal looked"),
                    "{text}"
                );
                assert!(
                    text.contains("a look at it now failed (permission denied)"),
                    "{text}"
                );
                assert!(text.contains("nothing was removed"), "{text}");
                assert!(!text.contains("something is there"), "{text}");
            }
            other => panic!("quiet {quiet}: {other:?}"),
        }
    }
    // Found absent and still absent: a rollback ends quietly, and a removal says what it read.
    assert_eq!(
        decide(Inspection::Absent, Answer::NotThere, true, &asked),
        Begin::Nothing
    );
    match decide(Inspection::Absent, Answer::NotThere, false, &asked) {
        Begin::Refuse(text) => {
            assert!(
                text.contains("Boundary is not there, so no manifest says what to remove"),
                "{text}"
            );
            // Nothing read the service, the accounts or the policy.
            for other in ["installed", "service", "account", "polic"] {
                assert!(!text.contains(other), "{text}");
            }
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        asked.get(),
        6,
        "the path is looked at once per absent finding"
    );
}

/// A directory that the inspection approved is acted on without another look at its path.
#[test]
fn an_approved_directory_is_not_looked_at_again() {
    let asked = Cell::new(0);
    assert_eq!(
        decide(
            Inspection::Recorded("manifest"),
            Answer::NotThere,
            true,
            &asked
        ),
        Begin::Remove("manifest")
    );
    assert_eq!(
        decide(Inspection::Empty, Answer::NotThere, false, &asked),
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
