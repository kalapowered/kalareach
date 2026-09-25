//! The committed JSON Schema and method table must match the Rust types.

use std::path::PathBuf;

use kr_protocol::method::REGISTRY;
use kr_protocol::schema::{
    METHOD_AUTHORITY_FILE_NAME, SCHEMA_FILE_NAME, generated_files, method_authority_table,
    protocol_schema,
};

fn schema_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packages/protocol/schema")
}

/// KR-REQ-23.53: the published authority table is generated from the registry and kept current.
#[test]
fn the_committed_files_match_the_rust_types() {
    // KR-REQ-04.08: the published JSON Schema is generated from the Rust serde types, and the
    // committed document is exactly what they generate.
    for (name, expected) in generated_files() {
        let path = schema_dir().join(name);
        let actual = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert_eq!(
            actual,
            expected,
            "{} is out of date; run `cargo run -p kr-protocol --bin kr-protocol-gen`",
            path.display()
        );
    }
}

#[test]
fn generation_is_deterministic() {
    assert_eq!(generated_files(), generated_files());
}

#[test]
fn the_bundle_names_every_root_message_and_defines_its_types() {
    let schema = protocol_schema();
    let properties = schema["properties"].as_object().expect("properties");
    for root in [
        "actor_envelope",
        "client_offer",
        "grant",
        "host_selection",
        "method_entry",
        "mutation_request",
        "notification",
        "protocol_error",
        "receipt",
        "receipt_response",
        "request",
        "response",
        "session_ref",
        "stream_header",
    ] {
        assert!(
            properties.contains_key(root),
            "{root} is not a root message"
        );
    }
    let definitions = schema["$defs"].as_object().expect("$defs");
    for name in [
        "ActionRight",
        "ActionTarget",
        "ErrorCode",
        "Grant",
        "Method",
        "MethodEntry",
        "ReceiptState",
        "RetryCategory",
        "Uuid",
        "U64",
        "SessionId",
        "AuthorityRevision",
    ] {
        assert!(definitions.contains_key(name), "{name} is not defined");
    }
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
}

#[test]
fn scalars_declare_their_json_representation() {
    let schema = protocol_schema();
    let definitions = &schema["$defs"];
    assert_eq!(definitions["Uuid"]["type"], "string");
    assert_eq!(definitions["Uuid"]["format"], "uuid");
    assert_eq!(definitions["U64"]["type"], "string");
    assert_eq!(definitions["U64"]["pattern"], "^(0|[1-9][0-9]*)$");
    assert_eq!(definitions["Digest256"]["contentEncoding"], "base64url");
    // An identifier writes its scalar's schema out rather than referring to it. A definition that
    // is only a reference to another definition is dropped by the TypeScript generator, and the
    // package exists so no consumer has to hand-write these types.
    assert_eq!(definitions["SessionId"]["format"], "uuid");
    assert_eq!(
        definitions["AuthorityRevision"]["pattern"],
        "^(0|[1-9][0-9]*)$"
    );
    // Canonical base64url only: 43 symbols, the last of which leaves the two bits past the 32nd
    // byte zero.
    assert_eq!(
        definitions["Digest256"]["pattern"],
        "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$"
    );
}

/// KR-REQ-23.14: the published mutation schemas are closed.
#[test]
fn mutation_schemas_are_closed_in_the_generated_document() {
    let schema = protocol_schema();
    for name in [
        "MutationRequest",
        "ActionTarget",
        "Grant",
        "Receipt",
        "ProtocolError",
        "StreamHeader",
        "ClientOffer",
        "HostSelection",
    ] {
        assert_eq!(
            schema["$defs"][name]["additionalProperties"], false,
            "{name} must be a closed schema"
        );
    }
}

#[test]
fn nullable_fields_are_required_and_accept_null() {
    let schema = protocol_schema();
    let target = &schema["$defs"]["ActionTarget"];
    let required: Vec<&str> = target["required"]
        .as_array()
        .expect("required")
        .iter()
        .map(|value| value.as_str().expect("string"))
        .collect();
    for field in [
        "environment_id",
        "session_id",
        "session_epoch",
        "application_instance_id",
        "agent_binding_revision",
    ] {
        assert!(required.contains(&field), "{field} must be required");
    }
    let session = &target["properties"]["session_id"];
    let alternatives = session["anyOf"].as_array().expect("anyOf");
    assert_eq!(alternatives.len(), 2);
    assert!(alternatives.iter().any(|value| value["type"] == "null"));
}

#[test]
fn every_identifier_has_its_own_named_definition() {
    let schema = protocol_schema();
    let vocabulary = schema["properties"]["identifiers"]["properties"]
        .as_object()
        .expect("the identifier vocabulary");
    assert!(
        vocabulary.len() >= 55,
        "the vocabulary names every identifier, found {}",
        vocabulary.len()
    );
    for (field, entry) in vocabulary {
        let reference = entry["$ref"]
            .as_str()
            .unwrap_or_else(|| panic!("{field} is not a reference"));
        let name = reference
            .strip_prefix("#/$defs/")
            .unwrap_or_else(|| panic!("{field} refers outside the bundle"));
        let definition = &schema["$defs"][name];
        assert!(
            definition.get("$ref").is_none(),
            "{name} is a reference to another definition, so the generated types drop it"
        );
        assert!(
            definition.get("type").is_some(),
            "{name} has no concrete type"
        );
    }
}

/// KR-REQ-23.53: the published table lists every method once and says unlisted methods are denied.
#[test]
fn the_method_table_lists_every_method_once() {
    let table = method_authority_table();
    assert_eq!(table["unlisted_methods_are_denied"], true);
    assert_eq!(table["method_count"], REGISTRY.len());
    let methods = table["methods"].as_array().expect("methods");
    assert_eq!(methods.len(), REGISTRY.len());
    let mut names: Vec<&str> = methods
        .iter()
        .map(|entry| entry["name"].as_str().expect("name"))
        .collect();
    let count = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), count, "method names are unique");
}

#[test]
fn the_generated_files_have_the_expected_names() {
    let names: Vec<&str> = generated_files()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert_eq!(names, [SCHEMA_FILE_NAME, METHOD_AUTHORITY_FILE_NAME]);
    for (_, contents) in generated_files() {
        assert!(contents.ends_with('\n'), "each file ends with one newline");
        assert!(!contents.ends_with("\n\n"));
    }
}
