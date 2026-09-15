//! What the validator refuses to read.
//!
//! A package directory is untrusted input. These are the entries that would make the validator
//! read something outside the package, block forever, or measure something other than what it
//! read.

use std::path::Path;

use kr_plugin_sdk::example;
use kr_plugin_sdk::package::{MANIFEST_FILE, PRESENTATION_FILE};
use kr_plugin_sdk::validate::{FindingCode, validate_package_directory};

fn write_valid_package(directory: &Path) {
    std::fs::create_dir_all(directory).expect("the package directory");
    std::fs::write(
        directory.join(MANIFEST_FILE),
        example::example_manifest_json(),
    )
    .expect("the manifest writes");
    std::fs::write(
        directory.join(PRESENTATION_FILE),
        example::example_presentation_json(),
    )
    .expect("the document writes");
}

#[test]
fn the_written_package_is_the_one_the_fixtures_use() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let package = temporary.path().join("package");
    write_valid_package(&package);
    let validated = validate_package_directory(&package);
    assert!(
        validated.report.is_valid(),
        "{:?}",
        validated.report.findings
    );
}

#[cfg(unix)]
#[test]
fn a_parent_directory_link_cannot_redirect_the_walk() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let outside = temporary.path().join("outside");
    std::fs::create_dir_all(outside.join("nested")).expect("the outside tree creates");
    std::fs::write(outside.join("nested/secret.txt"), "not ours").expect("the file writes");

    let package = temporary.path().join("package");
    write_valid_package(&package);
    // A directory inside the package that points at a tree outside it. The walk is anchored to the
    // package's own directory handle, so the link is reported rather than descended into.
    std::os::unix::fs::symlink(&outside, package.join("assets")).expect("the link is made");

    let validated = validate_package_directory(&package);
    assert!(validated.report.has(FindingCode::NotARegularFile));
    assert!(
        !validated
            .report
            .findings
            .iter()
            .any(|finding| finding.detail.contains("not ours")),
        "the walk read something outside the package"
    );
    if let Some(package) = validated.package {
        for file in &package.files {
            assert!(
                !file.path.as_str().starts_with("assets/"),
                "the walk descended into the link"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn a_symbolic_link_is_rejected_rather_than_followed() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let outside = temporary.path().join("outside.json");
    std::fs::write(&outside, "{}").expect("the outside file writes");
    let package = temporary.path().join("package");
    write_valid_package(&package);

    // An asset that points outside the package.
    std::os::unix::fs::symlink(&outside, package.join("linked.json")).expect("the link is made");
    let validated = validate_package_directory(&package);
    assert!(validated.report.has(FindingCode::NotARegularFile));

    // The manifest itself replaced by a link. The scan reports it, and the manifest read refuses
    // it rather than following the link to whatever it points at.
    std::fs::remove_file(package.join("linked.json")).expect("the link is removed");
    std::fs::remove_file(package.join(MANIFEST_FILE)).expect("the manifest is removed");
    std::os::unix::fs::symlink(&outside, package.join(MANIFEST_FILE)).expect("the link is made");
    let validated = validate_package_directory(&package);
    assert!(validated.report.has(FindingCode::NotARegularFile));
    assert!(validated.package.is_none());
}

#[test]
fn a_manifest_larger_than_the_limit_is_not_read() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let package = temporary.path().join("package");
    write_valid_package(&package);
    let oversized =
        "\n".repeat(usize::try_from(kr_plugin_sdk::limits::MANIFEST_BYTES).unwrap() + 1);
    std::fs::write(package.join(MANIFEST_FILE), oversized).expect("the manifest writes");

    let validated = validate_package_directory(&package);
    assert!(validated.report.has(FindingCode::PackageTooLarge));
    assert!(validated.package.is_none());
}

#[test]
fn a_repeated_member_is_reported_before_the_value_tree_loses_it() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let package = temporary.path().join("package");
    write_valid_package(&package);
    let manifest = example::example_manifest_json();
    let doubled = format!(
        "{}  ,\"version\": \"9.9.9\"\n}}\n",
        manifest.trim_end().trim_end_matches('}')
    );
    std::fs::write(package.join(MANIFEST_FILE), doubled).expect("the manifest writes");

    let validated = validate_package_directory(&package);
    assert!(validated.report.has(FindingCode::DuplicateMember));
    assert!(validated.package.is_none());
}
