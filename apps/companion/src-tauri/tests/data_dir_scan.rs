//! Where the companion keeps its records, read from its own source.
//!
//! The application's data folder is chosen in one place, the helper that `companion-platform`
//! offers, so that on Windows every record the companion keeps sits in the folder that stays on
//! this computer and none of it in the folder a roaming profile carries to another one. A call to
//! Tauri's own `app_data_dir` anywhere else would put a record back in the roaming folder, and it
//! cannot be seen from a case that runs the application, so this case reads the source.

use std::path::{Path, PathBuf};

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

/// No call of Tauri's `app_data_dir` stands in the companion's own source or in the
/// platform crate's outside the helper, which is the one place that chooses the folder.
#[test]
fn no_app_data_dir_call_stands_outside_the_companion_data_dir_helper() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    sources(&manifest.join("src"), &mut found);
    sources(&manifest.join("../native/platform/src"), &mut found);
    assert!(found.len() > 20, "the sources were found: {}", found.len());

    let mut offenders = Vec::new();
    for path in found {
        if path.file_name().is_some_and(|name| name == "data_dir.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("a source file is read");
        for (number, line) in text.lines().enumerate() {
            if line.contains("app_data_dir(") {
                offenders.push(format!("{}:{}", path.display(), number + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "each of these calls chooses the data folder where the helper should: {offenders:#?}"
    );
}
