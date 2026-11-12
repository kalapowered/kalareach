//! The package check tests the package's `sdk_range` before it reads the connector table, so a
//! package that needs a newer SDK is refused for that and nothing else, and a package inside the
//! range with a table that does not read still gets the finding for the table.

use std::path::{Path, PathBuf};

use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::validate::{FindingCode, validate_package_directory};
use kr_plugin_sdk::version::SDK_VERSION;
use serde_json::{Value, json};

fn example_connector() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugins/valid/example-connector")
}

/// A copy of the example connector package under `into`, with its manifest's SDK range and its
/// connector table changed by the two closures.
fn package(into: &Path, range: Option<&str>, table: impl FnOnce(&mut Value)) -> PathBuf {
    let directory = into.join("package");
    std::fs::create_dir_all(&directory).expect("a directory");
    for name in ["plugin.json", "presentation.json", "connector.json"] {
        std::fs::copy(example_connector().join(name), directory.join(name)).expect("copies");
    }
    if let Some(range) = range {
        let path = directory.join("plugin.json");
        let mut manifest: Value =
            serde_json::from_slice(&std::fs::read(&path).expect("reads")).expect("JSON");
        manifest["sdk_range"] = json!(range);
        std::fs::write(&path, serde_json::to_vec_pretty(&manifest).expect("writes"))
            .expect("writes");
    }
    let path = directory.join("connector.json");
    let mut connector: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("reads")).expect("JSON");
    let before = connector.clone();
    table(&mut connector);
    if connector != before {
        let bytes = serde_json::to_vec_pretty(&connector).expect("writes");
        std::fs::write(&path, &bytes).expect("writes");
        // The manifest declares the table's digest and size: bring them up to the changed file, so
        // that a package that is otherwise right is valid.
        let manifest_path = directory.join("plugin.json");
        let mut manifest: Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).expect("reads")).expect("JSON");
        let record = manifest["payloads"]
            .as_array_mut()
            .expect("payloads")
            .iter_mut()
            .find(|payload| payload["path"] == "connector.json")
            .expect("the connector payload");
        record["digest"] = json!(PayloadDigest::of(&bytes).to_string());
        record["size_bytes"] = json!(bytes.len().to_string());
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).expect("writes"),
        )
        .expect("writes");
    }
    directory
}

/// A package that needs a newer SDK is refused with the range as its first and only finding,
/// whether its connector table is one this SDK reads or one with a member it has never heard of
/// (which is what a newer table looks like), and nothing that follows from the unread table is
/// reported: no unreadable manifest, no "ships no connector table" for each action and the
/// backend, no digest finding for a table that was changed.
#[test]
fn a_package_that_needs_a_newer_sdk_is_refused_with_the_range_alone() {
    for (name, table) in [
        ("an unchanged table", None),
        (
            "a table with a member this SDK lacks",
            Some("a_member_of_a_newer_sdk"),
        ),
    ] {
        let home = tempfile::tempdir().expect("a directory");
        let directory = package(home.path(), Some(">=0.1.99, <0.2.0"), |connector| {
            if let Some(member) = table {
                connector[member] = json!(true);
            }
        });
        let validated = validate_package_directory(&directory);
        let findings = &validated.report.findings;
        assert_eq!(findings.len(), 1, "{name}: {findings:?}");
        assert_eq!(
            findings[0].code,
            FindingCode::VersionRangeExcludesHost,
            "{name}"
        );
        assert!(
            findings[0].detail.contains("sdk_range >=0.1.99, <0.2.0")
                && findings[0].detail.contains(SDK_VERSION),
            "{name}: {findings:?}"
        );
        assert!(
            validated.package.is_none(),
            "{name}: nothing is built from it"
        );
    }
}

/// A range with no upper bound that starts above this SDK excludes it as well, and the package is
/// refused for that before its table is read.
#[test]
fn a_range_with_no_upper_bound_that_excludes_this_sdk_is_refused_by_the_range() {
    let home = tempfile::tempdir().expect("a directory");
    let directory = package(home.path(), Some(">=0.1.99"), |connector| {
        connector["a_member_of_a_newer_sdk"] = json!(true);
    });
    let findings = validate_package_directory(&directory).report.findings;
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].code, FindingCode::VersionRangeExcludesHost);
}

/// A table that carries a member that arrived at an SDK version, with a range that admits an SDK
/// version below it, is refused with a finding that names the member and the version: an earlier
/// host would try to run it and refuse it only for a table it cannot read. A range that starts at
/// the arrival passes, and so does a table without the member under a range that admits earlier
/// versions.
#[test]
fn a_table_that_carries_a_listed_member_needs_a_range_that_starts_at_its_arrival() {
    let carries = |connector: &mut Value| {
        connector["messages"] = json!({ "params": "params", "result": "result", "error": "error" });
        connector["observation"] = json!({ "selections": [{
            "method": "status.read",
            "thread": { "segments": [
                { "type": "member", "name": "result" },
                { "type": "member", "name": "thread" },
                { "type": "member", "name": "id" },
            ] },
            "hidden_when": [{
                "place": { "segments": [{ "type": "member", "name": "params" }] },
                "values": ["x"],
            }],
        }] });
    };
    for (range, refused) in [
        (">=0.1.6, <0.2.0", true),
        (">=0.1.7, <0.2.0", false),
        (">=0.1.7-alpha, <0.2.0", true),
        (">=0.1.7, <0.2.0-rc.1", true),
    ] {
        let home = tempfile::tempdir().expect("a directory");
        let directory = package(home.path(), Some(range), carries);
        let findings = validate_package_directory(&directory).report.findings;
        let arrival = findings
            .iter()
            .find(|finding| finding.detail.contains("SelectionRoute.hidden_when"));
        match (refused, arrival) {
            (true, Some(finding)) => {
                assert_eq!(finding.code, FindingCode::ConnectorTableInvalid, "{range}");
                assert!(finding.detail.contains("SDK 0.1.7"), "{}", finding.detail);
            }
            (false, None) => {
                assert!(findings.is_empty(), "{range}: {findings:?}");
            }
            _ => panic!("{range}: {findings:?}"),
        }
    }

    let home = tempfile::tempdir().expect("a directory");
    let directory = package(home.path(), Some(">=0.1.6, <0.2.0"), |_| {});
    let validated = validate_package_directory(&directory);
    assert!(
        validated.report.is_valid(),
        "{:?}",
        validated.report.findings
    );
}

/// A package inside the range keeps what it had: a table with a member this SDK lacks is a finding
/// that says the table does not read.
#[test]
fn a_package_inside_the_range_with_a_broken_table_still_gets_its_parse_finding() {
    let home = tempfile::tempdir().expect("a directory");
    let directory = package(home.path(), None, |connector| {
        connector["a_member_of_a_newer_sdk"] = json!(true);
    });
    let validated = validate_package_directory(&directory);
    let report = &validated.report;
    assert!(
        !report.has(FindingCode::VersionRangeExcludesHost),
        "{:?}",
        report.findings
    );
    let parse = report
        .findings
        .iter()
        .find(|finding| finding.code == FindingCode::ManifestUnreadable)
        .unwrap_or_else(|| panic!("the table does not read: {:?}", report.findings));
    assert_eq!(parse.path.as_deref(), Some("connector.json"));
    assert!(
        parse.detail.contains("a_member_of_a_newer_sdk"),
        "{}",
        parse.detail
    );
}

/// A package inside the range, with a table this SDK reads, is as valid as it was.
#[test]
fn a_package_inside_the_range_is_valid() {
    let validated = validate_package_directory(&example_connector());
    assert!(
        validated.report.is_valid(),
        "{:?}",
        validated.report.findings
    );
}
