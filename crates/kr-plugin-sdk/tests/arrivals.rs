//! The members that arrived in the schema inside a level: the table that lists them, and the first
//! of them, the conditions under which a selection starts a thread the terminal never shows.

use std::path::{Path, PathBuf};

use kr_plugin_sdk::arrivals::ARRIVALS;
use kr_plugin_sdk::connector::{
    ConditionValue, ConnectorManifest, FieldPath, FieldSegment, RequestCondition, SelectionRoute,
};
use kr_plugin_sdk::ids::MethodName;
use kr_plugin_sdk::scalars::SafeInt;
use kr_plugin_sdk::schema::{package_contract, sdk_schema};
use kr_plugin_sdk::version::{PackageVersion, SDK_VERSION};
use serde_json::{Value, json};

fn path(names: &[&str]) -> FieldPath {
    FieldPath {
        segments: names
            .iter()
            .map(|name| FieldSegment::Member {
                name: (*name).to_owned(),
            })
            .collect(),
    }
}

fn selection(hidden_when: Vec<RequestCondition>) -> SelectionRoute {
    SelectionRoute {
        method: MethodName::new("thread.start").expect("a method name"),
        thread: path(&["result", "thread", "id"]),
        hidden_when,
    }
}

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugins")
}

/// The contract names every member that arrived inside a level, with the definition it is in and
/// the SDK version it arrived at, and the first is the conditions on a selection.
#[test]
fn the_contract_lists_the_members_that_arrived_inside_a_level() {
    let contract = package_contract();
    assert_eq!(contract["sdk_version"], SDK_VERSION);
    assert_eq!(SDK_VERSION, "0.1.7");
    assert_eq!(
        contract["arrivals"],
        json!([{
            "definition": "SelectionRoute",
            "member": "hidden_when",
            "sdk_version": "0.1.7",
        }])
    );
}

/// An entry that names no optional member of a definition only the SDK has, or that arrived at a
/// version the SDK has not reached, could never pass the check of a level, and would read as a
/// promise nobody keeps.
#[test]
fn every_arrival_names_an_optional_member_of_a_definition_only_the_sdk_has() {
    let schema = sdk_schema();
    let protocol = kr_protocol::schema::protocol_schema();
    let host = PackageVersion::parse(SDK_VERSION).expect("a version");
    let mut seen = Vec::new();
    for arrival in ARRIVALS {
        let definition = &schema["$defs"][arrival.definition];
        assert!(
            definition["properties"].get(arrival.member).is_some(),
            "{}.{} is not a member of the SDK's schema",
            arrival.definition,
            arrival.member
        );
        let required = definition["required"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            !required
                .iter()
                .any(|name| name.as_str() == Some(arrival.member)),
            "{}.{} is required",
            arrival.definition,
            arrival.member
        );
        assert!(
            protocol["$defs"].get(arrival.definition).is_none(),
            "{} is a definition the protocol schema has, which the check of a level compares \
             under the protocol's own rule",
            arrival.definition
        );
        let at = PackageVersion::parse(arrival.sdk_version).expect("an exact version");
        assert!(at <= host, "{} arrives after this SDK", arrival.member);
        let key = (arrival.definition, arrival.member);
        assert!(!seen.contains(&key), "{key:?} is listed twice");
        seen.push(key);
    }
}

/// A selection that states no conditions is written as it was before the member existed: the
/// bytes of a package that never heard of it do not change.
#[test]
fn a_table_with_no_conditions_serialises_to_the_bytes_it_had_before() {
    let bytes = serde_json::to_string(&selection(Vec::new())).expect("writes");
    assert_eq!(
        bytes,
        r#"{"method":"thread.start","thread":{"segments":[{"type":"member","name":"result"},{"type":"member","name":"thread"},{"type":"member","name":"id"}]}}"#
    );

    // A released table that predates the member reads and writes back to the same document.
    let released = fixtures_root().join("released/kalareach/codex/0.3.0/connector.json");
    let text = std::fs::read_to_string(&released).expect("the released connector table");
    let table: ConnectorManifest = serde_json::from_str(&text).expect("it reads");
    let written = serde_json::to_value(&table).expect("it writes");
    let original: Value = serde_json::from_str(&text).expect("a document");
    assert_eq!(written, original);
    assert!(
        !text.contains("hidden_when") && !written.to_string().contains("hidden_when"),
        "the member appears nowhere"
    );
}

/// Conditions are a list of places, each with the scalar values it may hold: a string, a boolean
/// or an integer, and nothing else.
#[test]
fn conditions_hold_a_place_and_scalar_values() {
    let conditions = vec![RequestCondition {
        place: path(&["params", "source"]),
        values: vec![
            ConditionValue::Text("clear".to_owned()),
            ConditionValue::Boolean(true),
            ConditionValue::Integer(SafeInt::new(3).expect("in range")),
        ],
    }];
    let written = serde_json::to_value(selection(conditions.clone())).expect("writes");
    assert_eq!(
        written["hidden_when"],
        json!([{
            "place": {"segments": [{"type": "member", "name": "params"}, {"type": "member", "name": "source"}]},
            "values": ["clear", true, 3],
        }])
    );
    let read: SelectionRoute = serde_json::from_value(written).expect("reads");
    assert_eq!(read.hidden_when, conditions);

    for not_a_scalar in [json!(1.5), json!(null), json!({"a": 1}), json!(["x"])] {
        let document = json!({
            "method": "thread.start",
            "thread": {"segments": []},
            "hidden_when": [{"place": {"segments": []}, "values": [not_a_scalar]}],
        });
        assert!(
            serde_json::from_value::<SelectionRoute>(document).is_err(),
            "a condition's value is a string, a boolean or an integer"
        );
    }
}
