//! The cases name a built-in account by its identifier (`*S-1-5-32-544`), never by its name: the
//! name is localised on a Windows that is not in English, and a fixture that passes `Administrators`
//! to the permission tool fails there for a reason that has nothing to do with the case. This case
//! reads the cases' sources, so it holds on every platform.

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
fn no_case_passes_the_name_of_a_built_in_account() {
    let mut files = Vec::new();
    sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests"),
        &mut files,
    );
    assert!(files.len() > 10, "the cases were found: {}", files.len());
    // The names are written apart so that this file does not contain them as one text.
    let names = [
        ["\"Admin", "istrators\""].concat(),
        ["\"Us", "ers\""].concat(),
        ["\"Every", "one\""].concat(),
        ["\"SYS", "TEM\""].concat(),
        ["\"Authenticated", " Users\""].concat(),
    ];
    let mut found = Vec::new();
    for path in &files {
        if path
            .file_name()
            .is_some_and(|name| name == "fixture_account_names.rs")
        {
            continue;
        }
        for (number, line) in fs::read_to_string(path).unwrap().lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            if names.iter().any(|name| line.contains(name.as_str())) {
                found.push(format!(
                    "{}:{}: {}",
                    path.file_name().unwrap().to_string_lossy(),
                    number + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(found.is_empty(), "an account named by its name: {found:#?}");
}
