//! Two descriptor kinds name a reader that no other object of the installation has: the proof's
//! unlisted program, which the one boundary account under proof may read and run, and the program
//! files of the installation, which every account may read and run. This case reads the crate's
//! sources and fails when any other place makes an object with either kind, or when the plain file
//! kind takes a reader from its principals.

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

fn sources_of_the_crate() -> Vec<(String, String)> {
    let mut files = Vec::new();
    sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    assert!(files.len() > 20, "the sources were found: {}", files.len());
    files
        .iter()
        .map(|path| {
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                code(path),
            )
        })
        .collect()
}

/// The files that mention the kind, each with the number of mentions, outside `sd.rs`, which
/// defines the kinds.
fn mentions(kind: &str) -> Vec<(String, usize)> {
    sources_of_the_crate()
        .into_iter()
        .filter(|(name, _)| name != "sd.rs")
        .map(|(name, text)| (name, text.matches(kind).count()))
        .filter(|(_, count)| *count > 0)
        .collect()
}

#[test]
fn the_proofs_program_kind_is_made_only_by_the_proof_and_once() {
    assert_eq!(
        mentions("SdKind::ProofProgram"),
        [("proof.rs".to_owned(), 1)],
        "one call in the proof, none elsewhere"
    );
}

#[test]
fn the_program_file_kind_is_made_only_by_the_installation() {
    let found = mentions("SdKind::ProgramFile");
    assert!(!found.is_empty(), "the installation makes program files");
    assert!(
        found.iter().all(|(name, _)| name == "install.rs"),
        "{found:?}"
    );
}

#[test]
fn the_plain_file_kind_takes_no_reader_from_its_principals() {
    let sd = sources_of_the_crate()
        .into_iter()
        .find(|(name, _)| name == "sd.rs")
        .unwrap()
        .1;
    let begin = sd
        .find("SdKind::AdminFile =>")
        .expect("the plain file's arm");
    let end = sd[begin..]
        .find("SdKind::ProgramFile =>")
        .expect("the arm after it");
    let arm = &sd[begin..begin + end];
    assert!(
        !arm.contains("principals") && !arm.contains("users_may_read"),
        "the plain file's descriptor is one text: {arm}"
    );
}
