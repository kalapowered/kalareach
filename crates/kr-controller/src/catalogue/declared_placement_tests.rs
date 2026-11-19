//! Where a package says its bridge is placed is read from the connector payload the verified
//! manifest pins, only after the manifest's `sdk_range` admits this host, and a table that cannot
//! be used is a refusal, never the application's own layout.

use std::path::Path;

use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::plugin::PluginManifest;
use serde_json::{Value, json};

use super::declared_placement;
use super::native_bridge::Declared;

fn bundled_manifest() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../bundled-plugins/targets/packages/kalareach/gemini-cli/0.5.0");
    serde_json::from_slice(&std::fs::read(path.join("plugin.json")).expect("a manifest"))
        .expect("JSON")
}

fn gemini_table(placement: Option<Value>) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../bundled-plugins/targets/packages/kalareach/gemini-cli/0.5.0/connector.json");
    let mut table: Value =
        serde_json::from_slice(&std::fs::read(path).expect("a table")).expect("JSON");
    if let Some(placement) = placement {
        table["placement"] = placement;
    }
    serde_json::to_vec(&table).expect("writes")
}

fn gemini_placement() -> Value {
    serde_json::to_value(kr_plugin_sdk::placement::Placement::gemini_cli()).expect("a value")
}

/// The Gemini CLI package with `sdk_range` as its range and `table` as its connector payload, in a
/// folder of its own; the manifest names the bytes unless `named` says other bytes.
fn read(sdk_range: &str, table: &[u8], named: Option<&[u8]>) -> Declared {
    let folder = tempfile::tempdir().expect("a folder");
    std::fs::write(folder.path().join("connector.json"), table).expect("writes");
    let named = named.unwrap_or(table);
    let mut manifest = bundled_manifest();
    manifest["sdk_range"] = json!(sdk_range);
    let record = manifest["payloads"]
        .as_array_mut()
        .expect("payloads")
        .iter_mut()
        .find(|payload| payload["path"] == "connector.json")
        .expect("the connector payload");
    record["digest"] = json!(PayloadDigest::of(named).to_string());
    record["size_bytes"] = json!(named.len().to_string());
    let manifest: PluginManifest = serde_json::from_value(manifest).expect("a manifest");
    declared_placement(&manifest, folder.path(), "Gemini CLI")
}

fn refusal(declared: &Declared) -> &str {
    match declared {
        Declared::Refused(why) => why,
        other => panic!("not refused: {other:?}"),
    }
}

#[test]
fn a_placement_is_read_only_after_the_range_test() {
    // A table this host's range test excludes holds a member the table's own reader would refuse:
    // it is the range that refuses, and the table is not read.
    let mut odd = gemini_placement();
    odd["a_member_no_sdk_names"] = json!(true);
    let table = gemini_table(Some(odd));
    let declared = read(">=0.1.0, <0.1.5", &table, None);
    assert!(
        refusal(&declared).contains("sdk_range does not admit"),
        "{declared:?}"
    );
    // And a table that is whole is refused too, never replaced by the application's layout.
    let table = gemini_table(Some(gemini_placement()));
    let declared = read(">=0.1.0, <0.1.5", &table, None);
    assert!(
        refusal(&declared).contains("sdk_range does not admit"),
        "{declared:?}"
    );
}

#[test]
fn a_table_that_does_not_validate_is_refused_and_never_defaulted() {
    let mut parent = gemini_placement();
    parent["directory"] = json!(["..", ".gemini"]);
    let declared = read(">=0.1.9, <0.2.0", &gemini_table(Some(parent)), None);
    assert!(
        refusal(&declared).contains("placement.directory_not_plain"),
        "{declared:?}"
    );
    let mut elsewhere = gemini_placement();
    elsewhere["directory"] = json!([".gemini-elsewhere"]);
    let declared = read(">=0.1.9, <0.2.0", &gemini_table(Some(elsewhere)), None);
    assert!(
        refusal(&declared).contains("placement.directory_not_the_labels"),
        "{declared:?}"
    );
    let declared = read(">=0.1.9, <0.2.0", b"not json at all", None);
    assert!(
        refusal(&declared).contains("cannot be read"),
        "{declared:?}"
    );
    let table = gemini_table(Some(gemini_placement()));
    let declared = read(">=0.1.9, <0.2.0", &table, Some(b"other bytes"));
    assert!(
        refusal(&declared).contains("not the bytes the manifest names"),
        "{declared:?}"
    );
}

#[test]
fn a_package_with_no_connector_table_takes_the_labels_default() {
    let mut manifest = bundled_manifest();
    manifest["payloads"]
        .as_array_mut()
        .expect("payloads")
        .retain(|payload| payload["role"] != "connector");
    let manifest: PluginManifest = serde_json::from_value(manifest).expect("a manifest");
    let folder = tempfile::tempdir().expect("a folder");
    assert_eq!(
        declared_placement(&manifest, folder.path(), "Gemini CLI"),
        Declared::Nothing
    );
    let declared = read(">=0.1.3, <0.2.0", &gemini_table(None), None);
    assert_eq!(declared, Declared::Nothing, "a table that declares none");
    let declared = read(
        ">=0.1.9, <0.2.0",
        &gemini_table(Some(gemini_placement())),
        None,
    );
    assert!(
        matches!(&declared, Declared::Placement(placement) if **placement == kr_plugin_sdk::placement::Placement::gemini_cli()),
        "{declared:?}"
    );
}
