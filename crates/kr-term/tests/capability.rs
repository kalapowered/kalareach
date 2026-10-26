//! The capability manifest: what owns the terminal fixtures, and what moves when one changes.
//!
//! The specification gives the manifest six things to own: sequence classes, terminfo, worker
//! responses, width, wrap and geometry, input encodings and renderer fixtures. `kr-term-fixtures
//! --check` is the step that holds the committed fixtures to the engine in continuous integration,
//! so it is the step that has to notice a fixture no category owns, and one that changed without
//! the manifest.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("terminal")
}

fn copy(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a directory");
    for entry in std::fs::read_dir(from).expect("a directory to copy") {
        let entry = entry.expect("an entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a type").is_dir() {
            copy(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("a copy");
        }
    }
}

/// A copy of the committed fixtures, which a test may change.
fn copied() -> tempfile::TempDir {
    let directory = tempfile::Builder::new()
        .prefix("kr-term-capabilities-")
        .tempdir()
        .expect("a directory");
    copy(&fixtures(), directory.path());
    directory
}

fn check(root: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kr-term-fixtures"))
        .arg("--check")
        .arg("--root")
        .arg(root)
        .output()
        .expect("the fixture tool runs")
}

fn said(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// KR-REQ-08.11: the committed fixtures are current and the manifest lists every one of them under
/// the six things the specification gives it; this is the control for the two cases below.
#[test]
fn the_committed_manifest_owns_every_fixture_under_the_six_categories() {
    let copy = copied();
    let output = check(copy.path());
    assert!(output.status.success(), "{}", said(&output));

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixtures().join("capabilities.json")).expect("the manifest"),
    )
    .expect("JSON");
    let categories: Vec<&str> = manifest["categories"]
        .as_array()
        .expect("categories")
        .iter()
        .map(|category| category["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(
        categories,
        [
            "sequence-classes",
            "terminfo",
            "worker-responses",
            "width-wrap-geometry",
            "input-encodings",
            "renderer-fixtures"
        ]
    );
    for category in manifest["categories"].as_array().expect("categories") {
        assert!(
            !category["fixtures"]
                .as_array()
                .expect("fixtures")
                .is_empty(),
            "{category}"
        );
    }
}

/// KR-REQ-08.11: a fixture that no category owns fails the check, so a file added to the fixtures
/// is given to one of the six things before it can be committed.
#[test]
fn a_fixture_no_category_owns_fails_the_check() {
    let copy = copied();
    std::fs::write(copy.path().join("unowned.json"), "{}\n").expect("a fixture");
    let output = check(copy.path());
    assert!(!output.status.success(), "{}", said(&output));
    let said = said(&output);
    assert!(
        said.contains("unowned.json") && said.contains("no category"),
        "{said}"
    );
}

/// KR-REQ-08.11: a fixture that changed moves the manifest's digest of it, including a fixture the
/// engine does not generate (the client renderer's, which is written by hand), so the change is
/// seen in the manifest's own file and the signed release that carries it.
#[test]
fn a_changed_fixture_moves_the_manifest() {
    let copy = copied();
    let path = copy.path().join("projection.json");
    let mut text = std::fs::read_to_string(&path).expect("the renderer's fixture");
    text.push('\n');
    std::fs::write(&path, text).expect("changed");
    let output = check(copy.path());
    assert!(!output.status.success(), "{}", said(&output));
    assert!(
        said(&output).contains("capabilities.json"),
        "{}",
        said(&output)
    );
}
