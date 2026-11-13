//! Guest cases for where the installation's records are written and for what a failure of its first
//! steps leaves. They run only in a disposable Windows guest, as SYSTEM, like the cases of
//! `windows_install.rs`.

#![cfg(all(windows, feature = "testing"))]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use kr_boundary_windows::manifest::{Manifest, forced};
use kr_boundary_windows::win::install::{self, Options, Paths};

/// The cases change the process's current directory and the point where a failure is forced, which
/// are the process's own: one runs at a time.
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

/// The installation's places under names of their own in the system's known folders, so that the
/// run makes the folder above the data directory and the data directory itself.
fn paths_of_its_own(id: &str) -> Paths {
    let system = Paths::system().unwrap();
    let name = format!("KalaReachC37{id}");
    let data = system
        .data_parent()
        .parent()
        .unwrap()
        .join(&name)
        .join("Boundary");
    let program = system.program_top.join(&name).join("Boundary");
    Paths {
        git: program.join("git"),
        program_top: system.program_top.clone(),
        program,
        staging: data.join("staging"),
        journal: data.join("journal"),
        run: data.join("run"),
        manifest: data.join("manifest.json"),
        prior: data.join("prior.json"),
        data,
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_failure_after_the_folder_and_the_data_directory_were_made_leaves_nothing_of_the_run() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let options = Options {
        payload: std::env::temp_dir(),
        person: None,
    };
    // The three points: the protection of the directory, the first record, and the write of that
    // record after its replacement file was made.
    for point in ["protect", "record", "replacement"] {
        let id = &uuid::Uuid::new_v4().simple().to_string()[..8];
        let paths = paths_of_its_own(id);
        let above = paths.data_parent().to_owned();
        assert!(!above.exists(), "the folder above is there before the run");
        forced::fail_the_next(point);
        let result = install::install(&paths, &options, false);
        // A point that was not reached must not stay forced for the next case.
        forced::fail_the_next("none");
        let text = result
            .expect_err("the forced failure stops the installation")
            .to_string();
        assert!(
            text.contains(&format!("a failure forced for a case at the step {point}")),
            "{point}: {text}"
        );
        assert!(
            !paths.data.exists(),
            "{point}: the data directory stays: {text}"
        );
        assert!(!above.exists(), "{point}: the folder above stays: {text}");
        assert!(
            !paths.program.exists() && !paths.program.parent().unwrap().exists(),
            "{point}: something of the program tree was made: {text}"
        );
    }
}
