//! Writes the cross-shell bridge scenarios, or checks that the committed ones are current.
//!
//! ```text
//! kr-shell-fixtures            write fixtures/shell-bridge/
//! kr-shell-fixtures --check    fail when a committed file differs from the corpus
//! ```
//!
//! Continuous integration runs the second form, so a change to the contract arrives together with
//! the scenarios that state it.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kr_shell_integration::contract::fixtures::{FIXTURES_DIRECTORY, rendered_files};

fn main() -> ExitCode {
    let check = std::env::args().any(|argument| argument == "--check");
    let root = fixtures_root();
    let files = rendered_files();
    let mut stale = Vec::new();
    if !check && let Err(error) = std::fs::create_dir_all(&root) {
        eprintln!("{}: {error}", root.display());
        return ExitCode::FAILURE;
    }
    for (name, contents) in &files {
        let path = root.join(name);
        if check {
            match std::fs::read_to_string(&path) {
                Ok(current) if &current == contents => {}
                Ok(_) => stale.push(format!("{} differs", path.display())),
                Err(error) => stale.push(format!("{}: {error}", path.display())),
            }
        } else if let Err(error) = std::fs::write(&path, contents) {
            eprintln!("{}: {error}", path.display());
            return ExitCode::FAILURE;
        }
    }
    match committed_files(&root) {
        Ok(committed) => {
            for name in committed {
                if !files.iter().any(|(expected, _)| *expected == name) {
                    stale.push(format!(
                        "{} is committed and no scenario produces it",
                        root.join(&name).display()
                    ));
                }
            }
        }
        Err(error) => stale.push(format!("{}: {error}", root.display())),
    }
    if stale.is_empty() {
        if check {
            println!("{} shell-bridge scenarios are current", files.len());
        } else {
            println!("wrote {} shell-bridge scenarios", files.len());
        }
        return ExitCode::SUCCESS;
    }
    for line in &stale {
        eprintln!("{line}");
    }
    eprintln!(
        "run `cargo run -p kr-shell-integration --bin kr-shell-fixtures` and commit the result"
    );
    ExitCode::FAILURE
}

fn committed_files(root: &Path) -> std::io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str()
            && name.ends_with(".json")
        {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

fn fixtures_root() -> PathBuf {
    // The crate directory is `<workspace>/crates/kr-shell-integration`.
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.push("..");
    root.push("..");
    for part in FIXTURES_DIRECTORY.split('/') {
        root.push(part);
    }
    root
}
