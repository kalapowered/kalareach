//! Checks the generated artefacts and the closed schemas.

use std::path::{Path, PathBuf};

use kr_plugin_sdk::schema::{CONTRACT_FILE_NAME, SCHEMA_FILE_NAME, generated_files};
use kr_plugin_sdk::wit;

fn package_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packages/plugin-sdk")
}

#[test]
fn the_committed_schema_matches_the_rust_types() {
    for (name, expected) in generated_files() {
        let path = package_root().join("schema").join(name);
        let actual = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert_eq!(
            actual,
            expected,
            "{} is out of date; run `cargo run -p kr-plugin-sdk --bin kr-plugin-sdk-gen`",
            path.display()
        );
    }
}

#[test]
fn the_committed_wit_package_matches_the_crate() {
    let path = package_root().join("wit").join(wit::PACKAGE_FILE_NAME);
    let actual = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    assert_eq!(actual, wit::PACKAGE);
}

#[test]
fn the_schema_bundle_names_every_root_document() {
    let (_, text) = generated_files()
        .into_iter()
        .find(|(name, _)| *name == SCHEMA_FILE_NAME)
        .expect("the bundle is generated");
    let bundle: serde_json::Value = serde_json::from_str(&text).expect("the bundle is JSON");
    let properties = bundle["properties"]
        .as_object()
        .expect("the bundle has properties");
    for root in [
        "plugin_manifest",
        "connector_manifest",
        "presentation_manifest",
        "catalogue_index",
        "capability_evidence",
        "document_node",
        "visibility_predicate",
        "vocabulary",
    ] {
        assert!(properties.contains_key(root), "the bundle omits {root}");
    }
    assert!(bundle["$defs"].is_object());
}

#[test]
fn the_contract_table_carries_the_limits_and_the_vocabularies() {
    let (_, text) = generated_files()
        .into_iter()
        .find(|(name, _)| *name == CONTRACT_FILE_NAME)
        .expect("the contract is generated");
    let contract: serde_json::Value = serde_json::from_str(&text).expect("the contract is JSON");

    // Byte counts and durations travel as decimal strings, so a JavaScript consumer cannot lose
    // precision reading them.
    assert_eq!(contract["instance_limits"]["memory_bytes"], "67108864");
    assert_eq!(contract["instance_limits"]["observation_deadline_ms"], "10");
    assert_eq!(
        contract["instance_limits"]["interpretation_deadline_ms"],
        "50"
    );
    assert_eq!(contract["instance_limits"]["snapshot_deadline_ms"], "100");
    assert_eq!(
        contract["instance_limits"]["output_bytes_per_call"],
        "1048576"
    );
    assert_eq!(
        contract["instance_limits"]["observation_queue_bytes"],
        "4194304"
    );
    assert_eq!(contract["instance_limits"]["faults_before_disable"], 3);
    assert_eq!(contract["repository_budgets"]["metadata_bytes"], "67108864");
    assert_eq!(contract["repository_budgets"]["metadata_entries"], "100000");
    assert_eq!(contract["repository_budgets"]["retained_generations"], "2");
    assert_eq!(
        contract["repository_budgets"]["retained_metadata_bytes"],
        "134217728"
    );
    assert_eq!(
        contract["repository_budgets"]["payload_cache_bytes"],
        "1073741824"
    );

    let exports = contract["wit_package"]["exports"]
        .as_array()
        .expect("the exports are an array");
    assert_eq!(exports.len(), 8);
    for export in wit::EXPORTS {
        assert!(
            exports.iter().any(|value| value == export),
            "the contract omits the export {export}"
        );
    }

    let kinds = contract["document_node_kinds"]
        .as_array()
        .expect("the node kinds are an array");
    assert_eq!(kinds.len(), 13);

    let ceiling = contract["default_repository_ceiling"]
        .as_array()
        .expect("the ceiling is an array");
    assert_eq!(ceiling.len(), 3);
}

/// KR-REQ-23.53: every effect class in the generated plugin contract names the rights it needs,
/// and a mutating one needs at least one.
#[test]
fn every_effect_class_in_the_contract_names_its_rights() {
    let (_, text) = generated_files()
        .into_iter()
        .find(|(name, _)| *name == CONTRACT_FILE_NAME)
        .expect("the contract is generated");
    let contract: serde_json::Value = serde_json::from_str(&text).expect("the contract is JSON");
    for entry in contract["effect_classes"]
        .as_array()
        .expect("the effect classes are an array")
    {
        let effect = entry["effect"].as_str().expect("an effect name");
        let mutation = entry["mutation"].as_bool().expect("a mutation flag");
        let rights = entry["required_rights"]
            .as_array()
            .expect("the rights are an array");
        if mutation {
            assert!(!rights.is_empty(), "{effect} is a mutation with no right");
        }
        assert!(entry["required_capability"].is_string());
    }
}
