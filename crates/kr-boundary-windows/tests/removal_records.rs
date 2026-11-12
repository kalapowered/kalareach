//! The removal deletes the installation's records in an order that lets a failed removal be run
//! again whole: the earlier-state record and the replacements of the manifest first, `staging` when
//! those are gone, and the manifest last. So whatever stays, the manifest stays with it, and the
//! removal that runs again reads it and finishes; and a data directory that holds only what a
//! removal left is never one with records and no manifest.
//!
//! A record that cannot be deleted is a non-empty directory at its name, which no platform lets a
//! file's removal take, and `staging` that cannot be deleted is a file at its name.

use std::fs;
use std::path::{Path, PathBuf};

use kr_boundary_windows::records::{Approved, Records, is_manifest_replacement, remove};

struct Data {
    _root: tempfile::TempDir,
    data: PathBuf,
}

impl Data {
    fn new() -> Data {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("Boundary");
        fs::create_dir(&data).unwrap();
        Data { _root: root, data }
    }

    fn manifest(&self) -> PathBuf {
        self.data.join("manifest.json")
    }

    fn prior(&self) -> PathBuf {
        self.data.join("prior.json")
    }

    fn staging(&self) -> PathBuf {
        self.data.join("staging")
    }

    fn replacement(&self) -> PathBuf {
        self.data.join(format!("manifest-{}.new", "ab".repeat(16)))
    }

    /// The data directory as an installation leaves it: every record, and `staging` with a file in it.
    fn installed() -> Data {
        let case = Data::new();
        for record in [case.manifest(), case.prior(), case.replacement()] {
            fs::write(record, b"{}").unwrap();
        }
        fs::create_dir(case.staging()).unwrap();
        fs::write(case.staging().join("policy.xml"), b"x").unwrap();
        case
    }

    fn remove(&self) -> Vec<String> {
        remove(&Records {
            data: &self.data,
            manifest: &self.manifest(),
            prior: &self.prior(),
            staging: &self.staging(),
            approved: &everything_there(&self.data),
        })
    }

    /// The removal of what the inspection approved, which is `approved`.
    fn remove_approving(&self, approved: &Approved) -> Vec<String> {
        remove(&Records {
            data: &self.data,
            manifest: &self.manifest(),
            prior: &self.prior(),
            staging: &self.staging(),
            approved,
        })
    }
}

/// What an inspection that saw everything in the directory would have approved: the earlier-state
/// record, `staging` and each replacement of the manifest.
fn everything_there(data: &Path) -> Approved {
    Approved {
        prior: true,
        staging: true,
        replacements: fs::read_dir(data)
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.file_name())
            .filter(|name| is_manifest_replacement(&name.to_string_lossy()))
            .collect(),
    }
}

/// Makes the record at `path` impossible to delete: a directory with something in it.
fn block(path: &Path) {
    fs::remove_file(path).ok();
    fs::remove_dir_all(path).ok();
    fs::create_dir(path).unwrap();
    fs::write(path.join("held"), b"x").unwrap();
}

/// Lets go of what `block` made.
fn release(path: &Path) {
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn every_record_and_the_data_directory_go_when_nothing_holds_one() {
    let case = Data::installed();
    let stayed = case.remove();
    assert!(stayed.is_empty(), "{stayed:?}");
    assert!(!case.data.exists());
}

#[test]
fn an_earlier_state_record_that_stays_keeps_the_manifest_and_staging_and_a_second_run_finishes() {
    let case = Data::installed();
    block(&case.prior());
    let stayed = case.remove();
    assert!(
        stayed
            .iter()
            .any(|line| line.contains(&case.prior().display().to_string())),
        "the record that stayed is named: {stayed:?}"
    );
    assert!(case.manifest().is_file(), "the manifest stays with it");
    assert!(
        case.staging().exists(),
        "staging stays while a record stays"
    );
    release(&case.prior());
    assert!(case.remove().is_empty());
    assert!(!case.data.exists());
}

#[test]
fn a_replacement_of_the_manifest_that_stays_keeps_the_manifest_and_staging_and_a_second_run_finishes()
 {
    let case = Data::installed();
    block(&case.replacement());
    let stayed = case.remove();
    assert!(
        stayed
            .iter()
            .any(|line| line.contains(&case.replacement().display().to_string())),
        "{stayed:?}"
    );
    assert!(case.manifest().is_file());
    assert!(case.staging().exists());
    release(&case.replacement());
    assert!(case.remove().is_empty());
    assert!(!case.data.exists());
}

#[test]
fn staging_that_cannot_be_deleted_keeps_the_manifest_and_a_second_run_finishes() {
    let case = Data::installed();
    fs::remove_dir_all(case.staging()).unwrap();
    fs::write(case.staging(), b"not a directory").unwrap();
    let stayed = case.remove();
    assert!(
        stayed
            .iter()
            .any(|line| line.contains(&case.staging().display().to_string())),
        "{stayed:?}"
    );
    assert!(
        case.manifest().is_file(),
        "the manifest goes last: it stays while staging stays"
    );
    assert!(
        !case.prior().exists(),
        "the records before staging are gone"
    );
    fs::remove_file(case.staging()).unwrap();
    fs::create_dir(case.staging()).unwrap();
    assert!(case.remove().is_empty());
    assert!(!case.data.exists());
}

#[test]
fn a_manifest_that_cannot_be_deleted_is_named_and_the_data_directory_stays_with_it() {
    let case = Data::installed();
    block(&case.manifest());
    let stayed = case.remove();
    assert!(
        stayed
            .iter()
            .any(|line| line.contains(&case.manifest().display().to_string())),
        "{stayed:?}"
    );
    assert!(case.manifest().exists());
    assert!(!case.prior().exists() && !case.replacement().exists());
    release(&case.manifest());
    assert!(case.remove().is_empty());
    assert!(!case.data.exists());
}

#[test]
fn something_in_the_data_directory_that_is_not_a_record_keeps_only_the_data_directory() {
    let case = Data::installed();
    fs::write(case.data.join("stray.txt"), b"x").unwrap();
    let stayed = case.remove();
    assert_eq!(stayed.len(), 1, "{stayed:?}");
    assert!(
        stayed[0].contains(&case.data.display().to_string()),
        "{stayed:?}"
    );
    assert!(
        !case.manifest().exists() && !case.staging().exists(),
        "every record is gone and the person is told about the stray file by the next run"
    );
}

use kr_boundary_windows::records::{next_step, remove_with};
use std::ffi::OsString;
use std::io;

/// How a data directory is listed in the cases that make the listing fail.
type Listing = dyn Fn(&Path) -> io::Result<Vec<io::Result<OsString>>>;

impl Data {
    fn remove_listing(&self, names: &Listing) -> Vec<String> {
        remove_with(
            &Records {
                data: &self.data,
                manifest: &self.manifest(),
                prior: &self.prior(),
                staging: &self.staging(),
                approved: &everything_there(&self.data),
            },
            names,
        )
    }
}

/// A listing that fails, and an entry of it that fails, each mean that a replacement of the
/// manifest cannot be ruled out: `staging` and the manifest stay, and the removal says so.
#[test]
fn a_listing_that_fails_keeps_staging_and_the_manifest_and_says_so() {
    let broken: [Box<Listing>; 2] = [
        Box::new(|_| Err(io::Error::other("the listing was refused"))),
        Box::new(|_| {
            Ok(vec![
                Ok(OsString::from("manifest.json")),
                Err(io::Error::other("an entry was refused")),
            ])
        }),
    ];
    for listing in &broken {
        let case = Data::installed();
        let stayed = case.remove_listing(listing.as_ref());
        assert!(
            stayed
                .iter()
                .any(|line| line.contains("a replacement of the manifest cannot be ruled out")),
            "{stayed:?}"
        );
        assert!(case.manifest().is_file(), "the manifest stays");
        assert!(case.staging().exists(), "staging stays");
        assert!(!case.prior().exists(), "the earlier record went");
        // With the listing working again the removal finishes.
        assert!(case.remove().is_empty());
        assert!(!case.data.exists());
    }
}

/// A data directory that is not there has no replacement in it: its listing's error is no failure.
#[test]
fn a_data_directory_that_is_not_there_is_not_a_failed_listing() {
    let case = Data::new();
    fs::remove_dir(&case.data).unwrap();
    assert!(case.remove().is_empty());
}

/// A removal stopped between the manifest's deletion and the directory's leaves an empty data
/// directory; the next removal removes it and ends clean.
#[test]
fn an_empty_data_directory_that_a_stopped_removal_left_is_removed_by_the_next_one() {
    let case = Data::new();
    let stayed = case.remove();
    assert!(stayed.is_empty(), "{stayed:?}");
    assert!(!case.data.exists());
}

/// A directory that cannot be deleted is named, and the words that follow say what is true of the
/// state: the manifest stays, or an empty directory is accepted by a new installation and finished
/// by the next removal, or something else is in it that no handle has checked, so the next removal
/// reads the first entry that it finds and says what to do about it, and nothing says to remove an entry unread.
#[test]
fn the_words_after_a_directory_that_stayed_say_what_is_true_of_the_state() {
    assert!(next_step(true, false).contains("run the removal again"));
    assert!(next_step(true, true).contains("reads the manifest"));
    // The next removal can refuse a link at a replacement's name before it reads the manifest, so
    // the words promise no completion.
    let kept = next_step(true, false);
    assert!(kept.contains("says what remains"), "{kept}");
    assert!(!kept.contains("finishes"), "{kept}");
    let empty = next_step(false, true);
    assert!(empty.contains("accepts an empty data directory"), "{empty}");
    assert!(!empty.contains("refuses"), "{empty}");
    let full = next_step(false, false);
    assert!(full.contains("refuses until they are gone"), "{full}");
    assert!(full.contains("run the removal again"), "{full}");
    assert!(
        full.contains("reads the first entry that it finds on its own handle"),
        "{full}"
    );
    assert!(!full.contains("remove them"), "{full}");
    assert!(!full.contains("accepts"), "{full}");
}

/// Rule 2 at the records: the removal deletes a record only where its own inspection opened it. One
/// that is there now and that the inspection did not see is left where it is and named, and the
/// manifest stays with it, so that the removal run again reads it.
#[test]
fn a_record_that_the_inspection_did_not_see_is_left_and_named() {
    // The earlier-state record.
    let case = Data::installed();
    let stayed = case.remove_approving(&Approved {
        prior: false,
        ..everything_there(&case.data)
    });
    assert!(
        stayed.iter().any(|text| text.contains("prior.json")
            && text.contains("was not there when the removal looked for it")),
        "{stayed:?}"
    );
    assert!(case.prior().exists());
    assert!(case.manifest().exists(), "the manifest stays with it");
    assert!(case.staging().exists(), "nothing after it is deleted");

    // A replacement of the manifest.
    let case = Data::installed();
    let stayed = case.remove_approving(&Approved {
        replacements: Vec::new(),
        ..everything_there(&case.data)
    });
    assert!(
        stayed
            .iter()
            .any(|text| text.contains("manifest-") && text.contains("so it was not removed")),
        "{stayed:?}"
    );
    assert!(case.replacement().exists());
    assert!(case.manifest().exists());
    assert!(!case.prior().exists(), "what the inspection saw is deleted");
}

#[test]
fn a_staging_directory_that_the_inspection_did_not_see_is_not_deleted() {
    let case = Data::installed();
    let stayed = case.remove_approving(&Approved {
        staging: false,
        ..everything_there(&case.data)
    });
    assert!(
        stayed.iter().any(|text| text.contains("staging")
            && text.contains("was not there when the removal looked for it")),
        "{stayed:?}"
    );
    assert!(case.staging().join("policy.xml").exists());
    assert!(case.manifest().exists());
}

#[test]
fn records_that_the_inspection_did_not_see_and_that_are_not_there_are_nothing_to_leave() {
    let case = Data::new();
    fs::write(case.manifest(), b"{}").unwrap();
    // Nothing was seen, nothing is there but the manifest: it goes, and so does the directory.
    let stayed = case.remove_approving(&Approved::default());
    assert!(stayed.is_empty(), "{stayed:?}");
    assert!(!case.data.exists());
}

/// The removal loads the earlier-state record only where its inspection approved it: a record that
/// appeared after the inspection is not read at all, so that its start value, its "was not running"
/// and its baseline decide nothing, and the removal acts as with no record.
#[test]
fn the_earlier_state_record_is_loaded_only_where_the_inspection_approved_it() {
    let approved = Approved {
        prior: true,
        ..Approved::default()
    };
    assert_eq!(approved.prior_record(|| Some(7)), Some(7));
    // Approved, and the record cannot be read: no record, as before.
    assert_eq!(approved.prior_record(|| None::<u32>), None);

    let unseen = Approved::default();
    let mut read = false;
    let loaded = unseen.prior_record(|| {
        read = true;
        Some(7)
    });
    assert_eq!(loaded, None);
    assert!(
        !read,
        "a record that the inspection did not approve is not read"
    );
}
