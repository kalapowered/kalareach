//! Where the companion keeps its records, read from its own source.
//!
//! The application's data folder is chosen in one place, the helper that `companion-platform`
//! offers, so that on Windows every record the companion keeps sits in the folder that stays on
//! this computer and none of it in the folder a roaming profile carries to another one. A call to
//! Tauri's own `app_data_dir` or `app_config_dir` anywhere else, or to its `data_dir` or
//! `config_dir`, or the same folders named as a base directory, would put a record back in the
//! roaming folder, and it cannot be seen from a case that runs the application, so these cases read
//! the source.

use std::path::{Path, PathBuf};

/// What chooses a folder that roams on Windows: Tauri's calls for the application's data and
/// configuration folders and for the user's own, which Tauri takes from the roaming application
/// data folder as well, and the same four folders named as a base directory. The leading dot of the
/// two plain calls keeps `app_data_dir(` and `local_data_dir(` from matching them.
const ROAMING_CHOICES: [&str; 8] = [
    "app_data_dir(",
    "app_config_dir(",
    ".data_dir(",
    ".config_dir(",
    "BaseDirectory::AppData",
    "BaseDirectory::AppConfig",
    "BaseDirectory::Data",
    "BaseDirectory::Config",
];

/// The one file that chooses the folder.
const HELPER: &str = "native/platform/src/data_dir.rs";

/// Whether a line of source chooses a folder that roams on Windows.
fn chooses_a_roaming_folder(line: &str) -> bool {
    ROAMING_CHOICES.iter().any(|choice| line.contains(choice))
}

/// Every Rust source file under `directory`.
fn sources(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("a source folder is read") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            sources(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

/// The scan names each of the eight ways to choose a folder that roams, and none of the ways to
/// choose one that stays on this computer.
#[test]
fn the_scan_names_every_way_to_choose_a_roaming_folder_and_no_other() {
    for line in [
        "let dir = app.path().app_data_dir()?;",
        "let dir = app.path().app_config_dir()?;",
        "app.path().resolve(\"records\", BaseDirectory::AppData)?",
        "app.path().resolve(\"records\", BaseDirectory::AppConfig)?",
        "let dir = app.path().data_dir()?;",
        "let dir = app.path().config_dir()?;",
        "app.path().resolve(\"records\", BaseDirectory::Data)?",
        "app.path().resolve(\"records\", BaseDirectory::Config)?",
    ] {
        assert!(chooses_a_roaming_folder(line), "the scan names: {line}");
    }
    for line in [
        "let dir = app.path().app_local_data_dir()?;",
        "let dir = app.path().app_log_dir()?;",
        "app.path().resolve(\"records\", BaseDirectory::AppLocalData)?",
        "let dir = app.path().local_data_dir()?;",
        "app.path().resolve(\"records\", BaseDirectory::LocalData)?",
        "let dir = companion_data_dir(app)?;",
    ] {
        assert!(
            !chooses_a_roaming_folder(line),
            "the scan lets pass: {line}"
        );
    }
}

/// No call that chooses a folder that roams stands in the companion's own source or in the
/// platform crate's outside the helper, which is the one place that chooses the folder.
#[test]
fn no_call_chooses_a_roaming_folder_outside_the_companion_data_dir_helper() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    sources(&manifest.join("src"), &mut found);
    sources(&manifest.join("../native/platform/src"), &mut found);
    assert!(found.len() > 20, "the sources were found: {}", found.len());
    assert!(
        found.iter().any(|path| path.ends_with(HELPER)),
        "the helper's file was found by its path"
    );

    let mut offenders = Vec::new();
    for path in found {
        if path.ends_with(HELPER) {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("a source file is read");
        for (number, line) in text.lines().enumerate() {
            if chooses_a_roaming_folder(line) {
                offenders.push(format!("{}:{}", path.display(), number + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "each of these calls chooses the data folder where the helper should: {offenders:#?}"
    );
}
