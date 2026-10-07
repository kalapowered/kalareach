//! What a build that ships this crate contains.
//!
//! The seams the tests act in are compiled by the `git-fixtures` feature, and a test build of this
//! crate always has it, so no test can show from inside a test build that a shipped build does
//! not. Cargo can: it resolves the features of this crate for the build of everything that depends
//! on it, and for the build of the tests as well, and the two differ in this one feature.

use std::path::Path;
use std::process::Command;

/// Returns what cargo resolves this crate's features to across the whole workspace, counting only
/// the dependency kinds named.
fn resolved_features(kinds: &str) -> String {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let output = Command::new(env!("CARGO"))
        .args(["tree", "--locked", "--workspace", "--prefix", "none"])
        .args(["--invert", "kr-project", "--edges", kinds])
        .args(["--format", "{p} [{f}]"])
        .arg("--manifest-path")
        .arg(&manifest)
        .output()
        .expect("cargo runs");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .expect("this crate heads its own inverted tree")
        .to_owned()
}

/// A build of the crates that ship this one compiles none of its test seams: not through the
/// crate's default features, and not through a crate that asks for them in a dependency a shipped
/// build uses. A test build of the same workspace does have them, which is how this case can tell
/// the two builds apart.
#[test]
fn a_build_that_ships_this_crate_compiles_none_of_its_test_seams() {
    let tests = resolved_features("normal,build,dev");
    assert!(
        tests.contains("git-fixtures"),
        "a test build has the seams the tests act in: {tests}"
    );
    let shipped = resolved_features("normal,build");
    assert!(
        !shipped.contains("git-fixtures"),
        "a shipped build has none of them: {shipped}"
    );
}
