//! The cryptographic libraries a release pins are read from the workspace's own lock, and a pin
//! that moves without the documents that name it, or is not exact, is refused.
//!
//! The checkout the pins are read from is a copy of the files the reading uses, so that each fault
//! is planted in a copy and never in the repository.

use std::path::{Path, PathBuf};

use kr_release::pins::{PINNED, dependencies};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A checkout holding only the files the pins are read from.
fn checkout() -> tempfile::TempDir {
    let copy = tempfile::tempdir().expect("a directory");
    for file in [
        "Cargo.toml",
        "Cargo.lock",
        "docs/crypto/README.md",
        "docs/pairing/README.md",
    ] {
        let to = copy.path().join(file);
        std::fs::create_dir_all(to.parent().expect("a parent")).expect("a directory");
        std::fs::copy(repository().join(file), to).expect("a copy");
    }
    let vectors = copy.path().join("fixtures/pairing");
    std::fs::create_dir_all(&vectors).expect("a directory");
    for entry in std::fs::read_dir(repository().join("fixtures/pairing")).expect("vectors") {
        let path = entry.expect("an entry").path();
        std::fs::copy(&path, vectors.join(path.file_name().expect("a name"))).expect("a copy");
    }
    copy
}

fn edit(copy: &tempfile::TempDir, file: &str, change: &dyn Fn(String) -> String) {
    let path = copy.path().join(file);
    let text = std::fs::read_to_string(&path).expect("a file");
    let changed = change(text.clone());
    assert_ne!(changed, text, "the change did nothing to {file}");
    std::fs::write(path, changed).expect("a file");
}

/// The eight pins, each at the exact version the workspace names, with the graph the
/// lock resolves for it and the pairing vectors; the unedited checkout is the control of the
/// refusals below.
#[test]
fn the_pins_are_read_from_the_lock_and_held_to_the_documents_and_to_exact_versions() {
    let copy = checkout();
    let read = dependencies(copy.path()).expect("the control passes");
    assert_eq!(read.pinned.len(), PINNED.len());
    assert!(read.pinned.iter().all(|pin| !pin.checksum.is_empty()));
    assert!(!read.vectors.is_empty());

    // A document that names another version than the workspace pins.
    let copy = checkout();
    edit(&copy, "docs/crypto/README.md", &|text| {
        text.replace("| `subtle` | ", "| `subtle` | 9.")
    });
    let refused = dependencies(copy.path()).expect_err("a document that disagrees");
    assert!(refused.to_string().contains("subtle"), "{refused}");

    // A pin that is a range and not one exact version.
    let copy = checkout();
    edit(&copy, "Cargo.toml", &|text| {
        text.replace("subtle = \"=", "subtle = \"^")
    });
    let refused = dependencies(copy.path()).expect_err("a range");
    assert!(refused.to_string().contains("exact"), "{refused}");

    // No vector the pairing profile is held to.
    let copy = checkout();
    std::fs::remove_dir_all(copy.path().join("fixtures/pairing")).expect("gone");
    std::fs::create_dir(copy.path().join("fixtures/pairing")).expect("empty");
    let refused = dependencies(copy.path()).expect_err("no vectors");
    assert!(refused.to_string().contains("no vectors"), "{refused}");
}
