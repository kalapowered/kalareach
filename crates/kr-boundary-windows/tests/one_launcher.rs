//! The broker starts every program through one function. This case reads the crate's sources and
//! fails when any other code can create a process: a second call of the platform's creation
//! function, any other creation function, or a start through the standard library's `Command`.
//!
//! One file starts programs for the setup program, which runs in an administrator's own process and
//! never in the broker: the one function that builds the command for the installation's PowerShell
//! channel and for the installer's two checks, each with an emptied environment. It is listed here
//! by name and by count, so a new start there fails the case too.

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

/// The code of a source file: every line that is not a comment.
fn code(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn count(text: &str, needle: &str) -> usize {
    text.matches(needle).count()
}

#[test]
fn no_code_in_the_crate_creates_a_process_but_the_launcher() {
    let mut files = Vec::new();
    sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    assert!(files.len() > 20, "the sources were found: {}", files.len());
    // The setup program's own starts, by file name and number.
    let setup_starts = [("applocker.rs", 1_usize)];
    let mut launcher_calls = 0;
    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        // The program the guest's cases start as a child: it is built only for them and is not
        // part of the broker.
        if name == "kr-launch-stand-in.rs" {
            continue;
        }
        let text = code(path);
        for other in [
            "CreateProcessW(",
            "CreateProcessWithLogonW",
            "CreateProcessWithTokenW",
            "CreateProcessAsUserA",
            "NtCreateUserProcess",
            "RtlCreateUserProcess",
            "ShellExecute",
            "WinExec",
        ] {
            assert_eq!(count(&text, other), 0, "{other} in {}", path.display());
        }
        let creations = count(&text, "CreateProcessAsUserW(");
        if name == "launch.rs" {
            launcher_calls += creations;
        } else {
            assert_eq!(creations, 0, "a creation call in {}", path.display());
        }
        let allowed = setup_starts
            .iter()
            .find(|entry| entry.0 == name)
            .map_or(0, |entry| entry.1);
        assert_eq!(
            count(&text, "Command::new("),
            allowed,
            "starts through the standard library in {}",
            path.display()
        );
        if allowed == 0 {
            for import in ["process::Command", "process::{Command", "process::*"] {
                assert_eq!(count(&text, import), 0, "{import} in {}", path.display());
            }
        }
    }
    assert_eq!(
        launcher_calls, 1,
        "the launcher makes the one creation call"
    );
}

/// Where a function that makes a permit to resume a child is called: the proof makes its own, and
/// the journal makes an invocation's once the process row is durable.
#[test]
fn a_permit_to_resume_is_made_only_where_it_is_allowed() {
    let mut files = Vec::new();
    sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let mut proof = 0;
    let mut journal = 0;
    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let text = code(path);
        let for_proof = count(&text, "ResumePermit::for_proof(");
        let for_invocation = count(&text, "ResumePermit::for_invocation(");
        match name.as_str() {
            "proof.rs" => proof += for_proof,
            "journal.rs" => {
                assert_eq!(for_proof, 0, "{}", path.display());
                journal += for_invocation;
            }
            // The launcher's own definitions, and the cases' maker that calls the invocation's.
            "launch.rs" => assert_eq!(for_proof, 0, "{}", path.display()),
            _ => {
                assert_eq!(for_proof, 0, "a proof permit in {}", path.display());
                assert_eq!(
                    for_invocation,
                    0,
                    "an invocation permit in {}",
                    path.display()
                );
            }
        }
    }
    assert_eq!(proof, 1, "the proof makes its permit in one place");
    assert_eq!(journal, 1, "the journal makes its permit in one place");
}
