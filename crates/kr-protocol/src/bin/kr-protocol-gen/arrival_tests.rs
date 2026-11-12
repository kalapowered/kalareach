//! The rule that lets a listed member arrive in the plugin SDK's schema inside a level, and
//! everything it must not let through.

use serde_json::{Value, json};

use crate::public_contract::{SdkContract, SdkVersion, compare_sdk_for_a_level};

/// A contract file as a release commits it: its SDK version and, when the release has the table,
/// the members that arrived.
fn contract(version: &str, arrivals: Option<&[(&str, &str, &str)]>) -> SdkContract {
    let mut document = json!({ "sdk_version": version });
    if let Some(arrivals) = arrivals {
        document["arrivals"] = arrivals
            .iter()
            .map(|(definition, member, at)| {
                json!({ "definition": definition, "member": member, "sdk_version": at })
            })
            .collect();
    }
    SdkContract::parse(&document.to_string()).expect("a contract")
}

fn sdk_schema() -> Value {
    json!({ "$defs": {
        "Route": {
            "type": "object",
            "properties": { "method": { "type": "string" } },
            "required": ["method"],
            "additionalProperties": false,
        },
        "Wrapper": {
            "type": "object",
            "properties": {
                "route": { "$ref": "#/$defs/Route" },
                "rows": { "type": "array", "items": {
                    "type": "object",
                    "properties": { "a": { "type": "string" } },
                } },
            },
        },
        "Choice": { "oneOf": [{
            "type": "object",
            "properties": { "kind": { "const": "a", "type": "string" } },
            "required": ["kind"],
        }] },
        "Gone": { "type": "object", "properties": {}, "required": [] },
    } })
}

fn protocol_schema() -> Value {
    json!({ "$defs": { "Frame": {
        "type": "object",
        "properties": { "id": { "type": "string" } },
        "required": ["id"],
    } } })
}

/// The schema after the release that adds `hidden` to `Route`, as an optional list.
fn with_hidden(schema: &Value) -> Value {
    let mut grown = schema.clone();
    grown["$defs"]["Route"]["properties"]["hidden"] =
        json!({ "type": "array", "items": { "type": "string" } });
    grown
}

const LISTED: &[(&str, &str, &str)] = &[("Route", "hidden", "0.1.7")];

struct Outcome {
    lines: Vec<String>,
    passed: Vec<String>,
}

fn compare(
    old: &Value,
    new: &Value,
    protocols: (&Value, &Value),
    earlier: &SdkContract,
    head: &SdkContract,
) -> Outcome {
    let mut passed = Vec::new();
    let lines =
        compare_sdk_for_a_level(old, new, protocols, earlier, head, &mut passed).expect("compares");
    Outcome {
        lines,
        passed: passed
            .iter()
            .map(|member| {
                format!(
                    "{} arrived at {}, earlier release at {}",
                    member.member, member.arrived, member.earlier
                )
            })
            .collect(),
    }
}

/// The ordinary case: the member is optional, nothing else changed, the head lists it above the
/// earlier release's SDK version and is above that version itself. It passes, and the pass says
/// which member and both versions.
#[test]
fn a_listed_optional_member_with_a_rise_passes_and_is_named() {
    let (old, protocol) = (sdk_schema(), protocol_schema());
    let new = with_hidden(&old);
    let outcome = compare(
        &old,
        &new,
        (&protocol, &protocol),
        &contract("0.1.6", None),
        &contract("0.1.7", Some(LISTED)),
    );
    assert_eq!(outcome.lines, Vec::<String>::new());
    assert_eq!(
        outcome.passed,
        vec!["Route.hidden arrived at 0.1.7, earlier release at 0.1.6".to_owned()]
    );
}

/// Versions are numbers: 0.1.10 is above 0.1.9, which a comparison of the texts gets wrong.
#[test]
fn versions_are_compared_as_numbers() {
    let (old, protocol) = (sdk_schema(), protocol_schema());
    let new = with_hidden(&old);
    let outcome = compare(
        &old,
        &new,
        (&protocol, &protocol),
        &contract("0.1.9", None),
        &contract("0.1.10", Some(&[("Route", "hidden", "0.1.10")])),
    );
    assert_eq!(outcome.lines, Vec::<String>::new());
    assert_eq!(outcome.passed.len(), 1);
    let lower = compare(
        &old,
        &new,
        (&protocol, &protocol),
        &contract("0.1.10", None),
        &contract("0.1.9", Some(&[("Route", "hidden", "0.1.11")])),
    );
    assert!(lower.passed.is_empty(), "0.1.9 is below 0.1.10");
    assert!(!lower.lines.is_empty());
}

/// A release before the table has an empty one: a member the head lists passes against it.
#[test]
fn a_release_from_before_the_table_has_an_empty_table() {
    let (old, protocol) = (sdk_schema(), protocol_schema());
    let new = with_hidden(&old);
    let earlier = contract("0.1.6", None);
    assert!(earlier.arrivals.is_empty());
    let outcome = compare(
        &old,
        &new,
        (&protocol, &protocol),
        &earlier,
        &contract("0.1.7", Some(LISTED)),
    );
    assert!(outcome.lines.is_empty(), "{:?}", outcome.lines);
}

/// Each of these must still fail, with the member listed and the version risen wherever that
/// would otherwise let it pass.
#[test]
fn what_the_rule_does_not_name_still_fails() {
    let (old, protocol) = (sdk_schema(), protocol_schema());
    let listed_head = contract("0.1.7", Some(LISTED));
    let earlier = contract("0.1.6", None);
    // The run fails when any difference is left, and the member itself passes only where the rule
    // lets it: `refuses` also says that nothing passed.
    let fails = |name: &str, new: &Value, earlier: &SdkContract, head: &SdkContract| {
        let outcome = compare(&old, new, (&protocol, &protocol), earlier, head);
        assert!(
            !outcome.lines.is_empty(),
            "{name} passed: {:?}",
            outcome.passed
        );
        outcome
    };
    let refuses = |name: &str, new: &Value, earlier: &SdkContract, head: &SdkContract| {
        let outcome = fails(name, new, earlier, head);
        assert!(
            outcome.passed.is_empty(),
            "{name} passed: {:?}",
            outcome.passed
        );
        outcome.lines
    };

    // A required member.
    let mut required = with_hidden(&old);
    required["$defs"]["Route"]["required"] = json!(["method", "hidden"]);
    refuses("a required member", &required, &earlier, &listed_head);

    // A member the table does not list: an empty table, and a table that lists another member.
    let new = with_hidden(&old);
    refuses(
        "an unlisted member",
        &new,
        &earlier,
        &contract("0.1.7", Some(&[])),
    );
    refuses(
        "another member's entry",
        &new,
        &earlier,
        &contract("0.1.7", Some(&[("Route", "other", "0.1.7")])),
    );
    refuses(
        "another definition's entry",
        &new,
        &earlier,
        &contract("0.1.7", Some(&[("Wrapper", "hidden", "0.1.7")])),
    );

    // A listed member with no rise: the earlier release is already at the arrival's version, or the
    // table lists the arrival at or below the earlier release's.
    refuses(
        "no rise",
        &new,
        &contract("0.1.7", Some(LISTED)),
        &contract("0.1.7", Some(LISTED)),
    );
    refuses(
        "listed at the earlier version",
        &new,
        &earlier,
        &contract("0.1.7", Some(&[("Route", "hidden", "0.1.6")])),
    );
    refuses(
        "the SDK did not rise",
        &new,
        &earlier,
        &contract("0.1.6", Some(LISTED)),
    );

    // A head whose SDK version is lower, though its table lists the member above the release's.
    refuses(
        "a lower SDK version",
        &new,
        &earlier,
        &contract("0.1.5", Some(LISTED)),
    );

    // A nested member, even when the table lists it by the place the difference names.
    let mut nested = old.clone();
    nested["$defs"]["Wrapper"]["properties"]["rows"]["items"]["properties"]["b"] =
        json!({ "type": "string" });
    let lines = refuses(
        "a nested member",
        &nested,
        &earlier,
        &contract(
            "0.1.7",
            Some(&[("Wrapper", "rows[].b", "0.1.7"), ("Wrapper", "b", "0.1.7")]),
        ),
    );
    assert!(lines[0].contains("Wrapper.rows[].b"), "{lines:?}");
    let mut in_a_variant = old.clone();
    in_a_variant["$defs"]["Choice"]["oneOf"][0]["properties"]["extra"] =
        json!({ "type": "string" });
    refuses(
        "a member of a variant",
        &in_a_variant,
        &earlier,
        &contract(
            "0.1.7",
            Some(&[
                ("Choice#tag:kind=a", "extra", "0.1.7"),
                ("Choice", "extra", "0.1.7"),
            ]),
        ),
    );

    // A changed type, default or bound, beside a member that passes: only the change is reported.
    for (keyword, value) in [
        ("type", json!("integer")),
        ("default", json!("x")),
        ("maxLength", json!(4)),
    ] {
        let mut changed = with_hidden(&old);
        changed["$defs"]["Route"]["properties"]["method"][keyword] = value;
        let lines = fails("a changed member", &changed, &earlier, &listed_head).lines;
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("Route.method changed"), "{lines:?}");
    }

    // A removed member, and a removed definition.
    let mut removed = with_hidden(&old);
    removed["$defs"]["Route"]["properties"]
        .as_object_mut()
        .expect("members")
        .remove("method");
    fails("a removed member", &removed, &earlier, &listed_head);
    let mut dropped = with_hidden(&old);
    dropped["$defs"]
        .as_object_mut()
        .expect("definitions")
        .remove("Gone");
    fails("a removed definition", &dropped, &earlier, &listed_head);

    // A new variant.
    let mut variant = with_hidden(&old);
    variant["$defs"]["Choice"]["oneOf"]
        .as_array_mut()
        .expect("branches")
        .push(json!({
            "type": "object",
            "properties": { "kind": { "const": "b", "type": "string" } },
            "required": ["kind"],
        }));
    fails("a new variant", &variant, &earlier, &listed_head);
}

/// A member of a definition that the protocol schema has stays under the protocol's rule: the
/// table cannot list it into the SDK's, whichever release the protocol schema is of.
#[test]
fn a_member_of_a_definition_the_protocol_schema_shares_fails() {
    let old = json!({ "$defs": { "Frame": {
        "type": "object",
        "properties": { "id": { "type": "string" } },
        "required": ["id"],
    } } });
    let mut new = old.clone();
    new["$defs"]["Frame"]["properties"]["hidden"] = json!({ "type": "string" });
    let none = json!({ "$defs": {} });
    let protocol = protocol_schema();
    let table: &[(&str, &str, &str)] = &[("Frame", "hidden", "0.1.7")];
    for (name, protocols) in [
        ("both", (&protocol, &protocol)),
        ("the release's only", (&protocol, &none)),
        ("the head's only", (&none, &protocol)),
    ] {
        let outcome = compare(
            &old,
            &new,
            protocols,
            &contract("0.1.6", None),
            &contract("0.1.7", Some(table)),
        );
        assert!(
            outcome.passed.is_empty() && outcome.lines == vec!["Frame.hidden added: a member"],
            "{name}: {:?} {:?}",
            outcome.passed,
            outcome.lines
        );
    }
    let outcome = compare(
        &old,
        &new,
        (&none, &none),
        &contract("0.1.6", None),
        &contract("0.1.7", Some(table)),
    );
    assert_eq!(
        outcome.passed.len(),
        1,
        "a definition no protocol schema has"
    );
}

/// An entry of an older release's table that the head changed or removed fails, though the schema
/// is the same: a member that passed once is not one the table may take back or move.
#[test]
fn an_entry_of_an_older_releases_table_that_the_head_changes_or_removes_fails() {
    let (old, protocol) = (with_hidden(&sdk_schema()), protocol_schema());
    let new = old.clone();
    let earlier = contract("0.1.7", Some(LISTED));
    let ok = compare(
        &old,
        &new,
        (&protocol, &protocol),
        &earlier,
        &contract(
            "0.1.8",
            Some(&[("Route", "hidden", "0.1.7"), ("Route", "more", "0.1.8")]),
        ),
    );
    assert!(
        ok.lines.is_empty(),
        "an entry kept, and one more: {:?}",
        ok.lines
    );
    for (name, table) in [
        ("removed", Vec::new()),
        ("moved up", vec![("Route", "hidden", "0.1.8")]),
        ("moved down", vec![("Route", "hidden", "0.1.6")]),
        ("renamed", vec![("Route", "shown", "0.1.7")]),
    ] {
        let lines = compare(
            &old,
            &new,
            (&protocol, &protocol),
            &earlier,
            &contract("0.1.8", Some(&table)),
        )
        .lines;
        assert_eq!(lines.len(), 1, "{name}: {lines:?}");
        assert!(lines[0].contains("Route.hidden"), "{name}: {lines:?}");
    }
}

/// The contract is read strictly: a version that is not three numbers, a table that is not a list
/// of entries, an entry with a member the check does not read, and an entry listed twice are each
/// a failure with a message of its own.
#[test]
fn a_contract_that_does_not_read_fails_with_its_own_message() {
    for (document, expected) in [
        (r#"{"arrivals": []}"#, "no sdk_version"),
        (r#"{"sdk_version": 1}"#, "no sdk_version"),
        (r#"{"sdk_version": "0.1"}"#, "sdk_version"),
        (r#"{"sdk_version": "0.1.7-rc.1"}"#, "sdk_version"),
        (r#"{"sdk_version": "0.1.+7"}"#, "sdk_version"),
        (
            r#"{"sdk_version": "0.1.7", "arrivals": {}}"#,
            "arrivals is not a list",
        ),
        (
            r#"{"sdk_version": "0.1.7", "arrivals": [1]}"#,
            "not an object",
        ),
        (
            r#"{"sdk_version": "0.1.7", "arrivals": [{"definition": "A", "member": "b"}]}"#,
            "no sdk_version as text",
        ),
        (
            r#"{"sdk_version": "0.1.7", "arrivals": [{"definition": "A", "member": "b", "sdk_version": "x"}]}"#,
            "A.b",
        ),
        (
            r#"{"sdk_version": "0.1.7", "arrivals": [{"definition": "A", "member": "b", "sdk_version": "0.1.7", "also": 1}]}"#,
            "also",
        ),
        (
            r#"{"sdk_version": "0.1.7", "arrivals": [{"definition": "A", "member": "b", "sdk_version": "0.1.7"}, {"definition": "A", "member": "b", "sdk_version": "0.1.8"}]}"#,
            "A.b is listed twice",
        ),
        ("not json", "expected"),
    ] {
        let error = SdkContract::parse(document).expect_err(document);
        assert!(error.contains(expected), "{document}: {error}");
    }
    assert_eq!(
        SdkVersion::parse("0.1.7").expect("a version").to_string(),
        "0.1.7"
    );
}

/// The committed schemas, read as files: the shared definitions are real ones, and the head's own
/// member passes against a release that has not got it.
fn committed(path: &str) -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = std::fs::read_to_string(root.join(path)).expect("a committed file");
    serde_json::from_str(&text).expect("JSON")
}

#[test]
fn the_committed_member_passes_against_a_release_without_it_and_a_shared_definition_does_not() {
    let head_sdk = committed("packages/plugin-sdk/schema/kalareach-plugin-sdk.schema.json");
    let protocol = committed("packages/protocol/schema/kalareach-protocol.schema.json");
    let head_contract = SdkContract::parse(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../packages/plugin-sdk/schema/package-contract.json"),
        )
        .expect("the committed contract"),
    )
    .expect("it reads");

    let mut earlier_sdk = head_sdk.clone();
    earlier_sdk["$defs"]["SelectionRoute"]["properties"]
        .as_object_mut()
        .expect("members")
        .remove("hidden_when");
    for name in ["ConditionValue", "RequestCondition"] {
        earlier_sdk["$defs"]
            .as_object_mut()
            .expect("definitions")
            .remove(name);
    }
    let earlier = contract("0.1.6", None);
    let outcome = compare(
        &earlier_sdk,
        &head_sdk,
        (&protocol, &protocol),
        &earlier,
        &head_contract,
    );
    assert_eq!(outcome.lines, Vec::<String>::new());
    assert_eq!(
        outcome.passed,
        vec!["SelectionRoute.hidden_when arrived at 0.1.7, earlier release at 0.1.6".to_owned()]
    );

    // A definition both schemas really have: the table listing a member of it changes nothing.
    let shared = "CommandIntegration";
    assert!(
        head_sdk["$defs"].get(shared).is_some() && protocol["$defs"].get(shared).is_some(),
        "{shared} is a definition both schemas have"
    );
    let mut grown = head_sdk.clone();
    grown["$defs"][shared]["properties"]["hidden"] = json!({ "type": "string" });
    let listing = contract("0.1.7", Some(&[(shared, "hidden", "0.1.7")]));
    let outcome = compare(
        &head_sdk,
        &grown,
        (&protocol, &protocol),
        &earlier,
        &listing,
    );
    assert!(outcome.passed.is_empty(), "{:?}", outcome.passed);
    assert_eq!(
        outcome.lines,
        vec![format!("{shared}.hidden added: a member")]
    );
}
