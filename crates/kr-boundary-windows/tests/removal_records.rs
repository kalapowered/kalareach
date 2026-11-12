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

use kr_boundary_windows::records::{Records, remove};

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
        })
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
