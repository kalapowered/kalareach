//! The crate's code names no drive and no folder of its own for the system's places. The system's
//! Windows directory, its Program Files and its ProgramData come from the platform's calls; when a
//! call fails, the failure is reported, and no fixed `C:` path takes its place on a computer whose
//! system is on another drive.

use std::fs;
use std::path::{Path, PathBuf};

fn sources(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

#[test]
fn no_code_of_the_crate_falls_back_to_a_fixed_drive() {
    let mut files = Vec::new();
    sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    assert!(files.len() > 20, "the sources were found: {}", files.len());
    let mut found = Vec::new();
    for path in &files {
        for (number, line) in fs::read_to_string(path).unwrap().lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            if ["C:\\", "c:\\", "\"C:\"", "\"c:\""]
                .iter()
                .any(|fixed| line.contains(fixed))
            {
                found.push(format!(
                    "{}:{}: {}",
                    path.file_name().unwrap().to_string_lossy(),
                    number + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(found.is_empty(), "a fixed drive in the code: {found:#?}");
}
