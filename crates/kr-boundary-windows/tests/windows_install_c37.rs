//! Guest cases for where the installation's records are written. They run only in a disposable
//! Windows guest, as SYSTEM, like the cases of `windows_install.rs`.

#![cfg(all(windows, feature = "testing"))]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use kr_boundary_windows::manifest::Manifest;

/// The cases change the process's current directory, which is the process's own: one runs at a time.
static SERIAL: Mutex<()> = Mutex::new(());

/// The names that a folder holds.
fn names_in(folder: &Path) -> BTreeSet<String> {
    std::fs::read_dir(folder)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

#[test]
#[ignore = "needs a disposable Windows guest, as SYSTEM (see windows_install.rs)"]
fn the_manifest_stands_in_the_data_directory_and_in_no_other_place_after_a_save_from_another_current_directory()
 {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let id = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let top = std::env::temp_dir().join(format!("krsave-{id}"));
    let data = top.join("Boundary");
    let elsewhere = top.join("elsewhere");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir(&elsewhere).unwrap();
    let started_in = std::env::current_dir().unwrap();
    let started_names = names_in(&started_in);
    std::env::set_current_dir(&elsewhere).unwrap();
    let path = data.join("manifest.json");

    // A new record, then a replacement of the record that is there: both are saves.
    let mut manifest = Manifest::begin();
    for persons in [Vec::new(), vec!["S-1-5-21-1-2-3-1001".to_owned()]] {
        manifest.persons = persons;
        manifest.save(&path).unwrap();
        assert_eq!(
            Manifest::load(&path).unwrap(),
            manifest,
            "the record in the data directory is not what was saved"
        );
        assert_eq!(
            names_in(&data),
            BTreeSet::from(["manifest.json".to_owned()]),
            "the data directory holds something else than the record after a save"
        );
        assert_eq!(
            names_in(&elsewhere),
            BTreeSet::new(),
            "the current directory holds a new file after a save"
        );
        assert_eq!(
            names_in(&top),
            BTreeSet::from(["Boundary".to_owned(), "elsewhere".to_owned()]),
            "the folder above the data directory holds a new file after a save"
        );
    }
    std::env::set_current_dir(&started_in).unwrap();
    assert_eq!(
        names_in(&started_in),
        started_names,
        "the folder that the process started in holds a new file after a save"
    );
    let _ = std::fs::remove_dir_all(&top);
}
