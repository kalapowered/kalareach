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
        "Named": { "type": "object", "properties": { "name": { "type": "string" } } },
        "Both": { "type": "object", "properties": { "value": { "type": "string" } } },
        "ConnectorManifest": { "type": "object", "properties": {
            "wrapper": { "$ref": "#/$defs/Wrapper" },
            "choice": { "$ref": "#/$defs/Choice" },
            "both": { "$ref": "#/$defs/Both" },
        } },
        "PluginManifest": { "type": "object", "properties": {
            "named": { "$ref": "#/$defs/Named" },
            "both": { "$ref": "#/$defs/Both" },
        } },
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

/// A head whose SDK version is lower than a release's fails on that alone, with the same schema and
/// the same table.
#[test]
fn a_lower_sdk_version_fails_on_its_own() {
    let (old, protocol) = (with_hidden(&sdk_schema()), protocol_schema());
    let table = Some(LISTED);
    let lines = compare(
        &old,
        &old,
        (&protocol, &protocol),
        &contract("0.1.8", table),
        &contract("0.1.7", table),
    )
    .lines;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].contains("0.1.8") && lines[0].contains("0.1.7"),
        "{lines:?}"
    );
}

/// A definition that refers to another definition than it did cannot lend its arrival entry to a
/// member added to a definition it no longer reaches: the comparison names differences by where a
/// definition is used, so the member added to `Route` would be taken for one added to `Other`.
#[test]
fn a_reference_moved_to_another_definition_does_not_carry_an_arrival_with_it() {
    let protocol = protocol_schema();
    let mut old = sdk_schema();
    old["$defs"]["Other"] = json!({
        "type": "object",
        "properties": { "method": { "type": "string" }, "hidden": { "type": "integer" } },
        "required": ["method"],
    });
    // `Route` stays reached from the connector table by a second way, so only the moved reference
    // is left to tell the member from one added to `Other`.
    old["$defs"]["ConnectorManifest"]["properties"]["route"] = json!({ "$ref": "#/$defs/Route" });
    let mut new = with_hidden(&old);
    new["$defs"]["Wrapper"]["properties"]["route"] = json!({ "$ref": "#/$defs/Other" });
    let outcome = compare(
        &old,
        &new,
        (&protocol, &protocol),
        &contract("0.1.6", None),
        &contract("0.1.7", Some(LISTED)),
    );
    assert!(outcome.passed.is_empty(), "{:?}", outcome.passed);
    assert!(
        outcome
            .lines
            .iter()
            .any(|line| line.contains("Wrapper refers to other definitions")),
        "{:?}",
        outcome.lines
    );
    assert!(
        outcome
            .lines
            .iter()
            .any(|line| line == "Route.hidden added: a member")
    );
}

/// The first optional member of a definition that has no members yet is an arrival like any other:
/// such a definition has no `properties` to hold the member's absence.
#[test]
fn the_first_member_of_a_definition_with_none_passes() {
    let (mut old, protocol) = (sdk_schema(), protocol_schema());
    old["$defs"]["Empty"] = json!({ "type": "object", "additionalProperties": false });
    old["$defs"]["ConnectorManifest"]["properties"]["empty"] = json!({ "$ref": "#/$defs/Empty" });
    let mut new = old.clone();
    new["$defs"]["Empty"]["properties"] = json!({ "first": { "type": "string" } });
    let outcome = compare(
        &old,
        &new,
        (&protocol, &protocol),
        &contract("0.1.6", None),
        &contract("0.1.7", Some(&[("Empty", "first", "0.1.7")])),
    );
    assert_eq!(outcome.lines, Vec::<String>::new());
    assert_eq!(outcome.passed.len(), 1);
}

/// A listed member passes only in a definition that the connector table reaches and the package
/// manifest does not: a host parses all of `plugin.json` before it can test the range, so a member
/// there would stop an earlier host before it read the range. Each of these fails with a message
/// of its own, though the table lists the member and the SDK version rises.
#[test]
fn a_listed_member_outside_the_connector_tables_definitions_fails_with_its_own_message() {
    let protocol = protocol_schema();
    let (earlier, head) = (
        contract("0.1.6", None),
        contract(
            "0.1.7",
            Some(&[("Named", "hidden", "0.1.7"), ("Both", "hidden", "0.1.7")]),
        ),
    );
    for (definition, expected) in [
        ("Named", "Named is not reached from ConnectorManifest"),
        ("Both", "Both is reached from PluginManifest"),
    ] {
        let old = sdk_schema();
        let mut new = old.clone();
        new["$defs"][definition]["properties"]["hidden"] = json!({ "type": "string" });
        let outcome = compare(&old, &new, (&protocol, &protocol), &earlier, &head);
        assert!(
            outcome.passed.is_empty(),
            "{definition}: {:?}",
            outcome.passed
        );
        assert_eq!(outcome.lines.len(), 1, "{definition}: {:?}", outcome.lines);
        assert!(
            outcome.lines[0].starts_with(&format!("{definition}.hidden added: a member; "))
                && outcome.lines[0].contains(expected),
            "{definition}: {:?}",
            outcome.lines
        );
    }

    // A schema without the two roots cannot say where a definition is reached from.
    let old = json!({ "$defs": { "Route": {
        "type": "object",
        "properties": { "method": { "type": "string" } },
    } } });
    let mut new = old.clone();
    new["$defs"]["Route"]["properties"]["hidden"] = json!({ "type": "string" });
    let outcome = compare(
        &old,
        &new,
        (&protocol, &protocol),
        &contract("0.1.6", None),
        &contract("0.1.7", Some(LISTED)),
    );
    assert!(outcome.passed.is_empty(), "{:?}", outcome.passed);
    assert!(
        outcome
            .lines
            .iter()
            .any(|line| line.contains("has no ConnectorManifest definition")),
        "{:?}",
        outcome.lines
    );
}

/// The protocol's read-only metadata marker has no meaning in the SDK's schema: an optional member
/// added to an SDK definition that carries it fails unless the table lists it, and passes by the
/// table, with its name in the run, when it does.
#[test]
fn the_protocols_read_only_marker_means_nothing_in_the_sdk_schema() {
    let protocol = protocol_schema();
    let mut old = sdk_schema();
    old["$defs"]["Marked"] = json!({
        "type": "object",
        "x-kalareach-read-only-metadata": true,
        "properties": { "a": { "type": "string" } },
    });
    old["$defs"]["ConnectorManifest"]["properties"]["marked"] = json!({ "$ref": "#/$defs/Marked" });
    let mut new = old.clone();
    new["$defs"]["Marked"]["properties"]["extra"] = json!({ "type": "string" });

    // The protocol's comparison passes this member; the SDK's does not.
    assert!(
        crate::public_contract::compare(&old, &new)
            .expect("compares")
            .is_empty()
    );
    for (name, earlier, head) in [
        (
            "no entry",
            contract("0.1.6", None),
            contract("0.1.7", Some(&[])),
        ),
        (
            "no rise",
            contract("0.1.7", None),
            contract("0.1.7", Some(&[("Marked", "extra", "0.1.7")])),
        ),
    ] {
        let outcome = compare(&old, &new, (&protocol, &protocol), &earlier, &head);
        assert!(outcome.passed.is_empty(), "{name}: {:?}", outcome.passed);
        assert_eq!(
            outcome.lines,
            vec!["Marked.extra added: a member".to_owned()],
            "{name}"
        );
    }
    let listed = compare(
        &old,
        &new,
        (&protocol, &protocol),
        &contract("0.1.6", None),
        &contract("0.1.7", Some(&[("Marked", "extra", "0.1.7")])),
    );
    // Listed, with a rise, the member still fails: the marker is a key a plain closed object does
    // not have, and the message names it.
    assert!(listed.passed.is_empty(), "{:?}", listed.passed);
    assert!(
        listed
            .lines
            .iter()
            .any(|line| line.contains("x-kalareach-read-only-metadata at its top")),
        "{:?}",
        listed.lines
    );
}

/// A listed member passes only in a definition that is an object in both schemas: a string
/// definition that gains `properties` is not an object gaining a member.
#[test]
fn a_listed_member_passes_only_in_an_object_definition() {
    let protocol = protocol_schema();
    let mut old = sdk_schema();
    old["$defs"]["Label"] = json!({ "type": "string" });
    old["$defs"]["ConnectorManifest"]["properties"]["label"] = json!({ "$ref": "#/$defs/Label" });
    let mut new = old.clone();
    new["$defs"]["Label"]["properties"] = json!({ "extra": { "type": "string" } });
    let outcome = compare(
        &old,
        &new,
        (&protocol, &protocol),
        &contract("0.1.6", None),
        &contract("0.1.7", Some(&[("Label", "extra", "0.1.7")])),
    );
    assert!(outcome.passed.is_empty(), "{:?}", outcome.passed);
    assert_eq!(outcome.lines.len(), 1, "{:?}", outcome.lines);
    assert!(
        outcome.lines[0].starts_with("Label.extra added: a member; ")
            && outcome.lines[0].contains("Label is not an object"),
        "{:?}",
        outcome.lines
    );
}

/// A listed member passes only in a plain closed object. A definition that composes another can
/// gain the name of a member it has another way and restrict it, so it is refused by the key that
/// composes it; a definition that is open, or that has `anyOf` at its top, is refused too, and the
/// message names what it found.
#[test]
fn a_listed_member_passes_only_in_a_plain_closed_object() {
    let protocol = protocol_schema();
    let table = Some(&[("Route", "hidden", "0.1.7")][..]);
    let outcome_of = |old: &Value, new: &Value| {
        compare(
            old,
            new,
            (&protocol, &protocol),
            &contract("0.1.6", None),
            &contract("0.1.7", table),
        )
    };

    // A required member inherited through `allOf` gains a bound under its own name.
    let mut old = sdk_schema();
    old["$defs"]["Base"] = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": { "hidden": { "type": "string" } },
        "required": ["hidden"],
    });
    old["$defs"]["Route"] = json!({
        "type": "object",
        "additionalProperties": false,
        "allOf": [{ "$ref": "#/$defs/Base" }],
    });
    let mut new = old.clone();
    new["$defs"]["Route"]["properties"] = json!({ "hidden": { "type": "string", "maxLength": 1 } });
    let outcome = outcome_of(&old, &new);
    assert!(outcome.passed.is_empty(), "{:?}", outcome.passed);
    assert!(
        outcome
            .lines
            .iter()
            .any(|line| line.contains("has allOf at its top")),
        "{:?}",
        outcome.lines
    );

    // An open object.
    let mut old = sdk_schema();
    old["$defs"]["Route"]
        .as_object_mut()
        .expect("an object")
        .remove("additionalProperties");
    let new = with_hidden(&old);
    let outcome = outcome_of(&old, &new);
    assert!(outcome.passed.is_empty(), "{:?}", outcome.passed);
    assert!(
        outcome
            .lines
            .iter()
            .any(|line| line.contains("is not closed")),
        "{:?}",
        outcome.lines
    );

    // `anyOf` at its top.
    let mut old = sdk_schema();
    old["$defs"]["Route"]["anyOf"] = json!([{ "required": ["method"] }]);
    let new = with_hidden(&old);
    let outcome = outcome_of(&old, &new);
    assert!(outcome.passed.is_empty(), "{:?}", outcome.passed);
    assert!(
        outcome
            .lines
            .iter()
            .any(|line| line.contains("has anyOf at its top")),
        "{:?}",
        outcome.lines
    );

    // A plain closed object with the annotations the generator writes passes.
    let mut old = sdk_schema();
    old["$defs"]["Route"]["description"] = json!("A route.");
    old["$defs"]["Route"]["title"] = json!("Route");
    let new = with_hidden(&old);
    let outcome = outcome_of(&old, &new);
    assert_eq!(outcome.lines, Vec::<String>::new());
    assert_eq!(outcome.passed.len(), 1);
}

/// A null branch that says more than `{"type": "null"}` is compared like any other branch, for the
/// protocol's comparison and for the SDK's, beside a member that passes too: a changed `not` or
/// `default` in it is a difference.
#[test]
fn a_changed_null_branch_is_a_difference_for_both_comparisons() {
    let protocol = protocol_schema();
    let mut old = sdk_schema();
    old["$defs"]["Opt"] = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": { "x": { "anyOf": [{ "$ref": "#/$defs/Both" }, { "type": "null" }] } },
    });
    old["$defs"]["ConnectorManifest"]["properties"]["opt"] = json!({ "$ref": "#/$defs/Opt" });
    for change in [
        json!({ "type": "null", "not": {} }),
        json!({ "type": "null", "default": null }),
    ] {
        let mut new = old.clone();
        new["$defs"]["Opt"]["properties"]["x"]["anyOf"][1] = change.clone();
        let lines = crate::public_contract::compare(&old, &new).expect("compares");
        assert!(
            lines.iter().any(|line| line.starts_with("Opt.x")),
            "the protocol's comparison: {change}: {lines:?}"
        );
        let outcome = compare(
            &old,
            &with_hidden(&new),
            (&protocol, &protocol),
            &contract("0.1.6", None),
            &contract("0.1.7", Some(LISTED)),
        );
        assert_eq!(outcome.passed.len(), 1, "{change}");
        assert!(
            outcome.lines.iter().any(|line| line.starts_with("Opt.x")),
            "the SDK's comparison: {change}: {:?}",
            outcome.lines
        );
    }
    // An annotation added to the null branch changes nothing a reader sees: descriptions and titles
    // are ignored whether or not the branch is the plain null one.
    let mut annotated = old.clone();
    annotated["$defs"]["Opt"]["properties"]["x"]["anyOf"][1]["description"] = json!("nothing");
    let same = crate::public_contract::compare(&old, &annotated).expect("compares");
    assert!(same.is_empty(), "{same:?}");
}

/// A `description` or `title` key inside a `default`, a `const`, an `enum` or `examples` is data,
/// not an annotation: changing it is a difference for both comparisons, beside a member that
/// passes too. A member that is merely named `default` has a schema for its value, and the
/// annotations in that schema stay ignored.
#[test]
fn literal_data_is_compared_whole_for_both_comparisons() {
    let protocol = protocol_schema();
    let mut old = sdk_schema();
    old["$defs"]["Route"]["properties"]["opt"] =
        json!({ "type": "object", "default": { "description": "old" } });
    old["$defs"]["Route"]["properties"]["kind"] = json!({ "const": { "title": "a" } });
    old["$defs"]["Route"]["properties"]["pick"] =
        json!({ "enum": [{ "description": "a" }, { "description": "b" }] });
    for (member, keyword, value) in [
        ("opt", "default", json!({ "description": "new" })),
        ("kind", "const", json!({ "title": "b" })),
        (
            "pick",
            "enum",
            json!([{ "description": "a" }, { "description": "c" }]),
        ),
    ] {
        let mut new = old.clone();
        new["$defs"]["Route"]["properties"][member][keyword] = value;
        let lines = crate::public_contract::compare(&old, &new).expect("compares");
        assert_eq!(
            lines,
            vec![format!("Route.{member} changed: {keyword}")],
            "the protocol's comparison"
        );
        let outcome = compare(
            &old,
            &with_hidden(&new),
            (&protocol, &protocol),
            &contract("0.1.6", None),
            &contract("0.1.7", Some(LISTED)),
        );
        assert_eq!(outcome.passed.len(), 1, "{member}");
        assert_eq!(
            outcome.lines,
            vec![format!("Route.{member} changed: {keyword}")],
            "the SDK's comparison"
        );
    }

    let mut old = sdk_schema();
    old["$defs"]["Route"]["properties"]["default"] =
        json!({ "type": "string", "description": "a" });
    let mut new = old.clone();
    new["$defs"]["Route"]["properties"]["default"]["description"] = json!("b");
    let lines = crate::public_contract::compare(&old, &new).expect("compares");
    assert!(lines.is_empty(), "a member named default: {lines:?}");
}

/// The text of a string constant can be anything, so no text may stand for another branch: a
/// branch beside two equal branches, whose text is the twins' text with a number added, is
/// compared like any other. A changed keyword in it is a difference for both comparisons, beside a
/// member that passes too.
#[test]
fn branch_keys_cannot_collide_for_both_comparisons() {
    let protocol = protocol_schema();
    for (text, twin) in [
        (r#"{"title":"x"}@2"#, json!({ "title": "x" })),
        ("{}@2", json!({})),
    ] {
        let mut old = sdk_schema();
        old["$defs"]["Route"]["properties"]["choice"] = json!({ "anyOf": [
            { "const": text, "maxLength": 100 },
            { "const": twin },
            { "const": twin },
        ] });
        let mut new = old.clone();
        new["$defs"]["Route"]["properties"]["choice"]["anyOf"][0]["maxLength"] = json!(0);
        let wanted = vec![format!("Route.choice#const:{text} changed: maxLength")];
        let lines = crate::public_contract::compare(&old, &new).expect("compares");
        assert_eq!(lines, wanted, "the protocol's comparison: {text}");
        let outcome = compare(
            &old,
            &with_hidden(&new),
            (&protocol, &protocol),
            &contract("0.1.6", None),
            &contract("0.1.7", Some(LISTED)),
        );
        assert_eq!(outcome.passed.len(), 1, "{text}");
        assert_eq!(outcome.lines, wanted, "the SDK's comparison: {text}");
    }
}

/// What the level comparison reports for the `Method` definition going from `old` to `new`, each
/// a list of branches that are plain string constants named by `Method`'s own `oneOf` form.
fn method_lines(old: &[Value], new: &[Value]) -> Vec<String> {
    let schema = |branches: &[Value]| json!({ "$defs": { "Method": { "oneOf": branches } } });
    crate::public_contract::compare_for_a_level(
        &schema(old),
        &schema(new),
        &|| Ok(std::collections::BTreeSet::new()),
        &mut Vec::new(),
    )
    .expect("compares")
}

/// The label of a branch that repeats the text of an earlier branch of its choice cannot be the
/// label of any other branch: a method named like that branch's old label is a new method, and the
/// repeated branch, which makes `oneOf` refuse the method it repeats, is a difference. The pair is
/// the one that the label `text@number` joined, in both orders of its last two branches.
#[test]
fn a_repeated_branch_cannot_pass_as_a_new_method_by_its_label() {
    let method = |name: &str| json!({ "const": name, "type": "string" });
    for new in [
        [method("x"), method("x"), method("x@1")],
        [method("x"), method("x@1"), method("x")],
    ] {
        let lines = method_lines(&[method("x")], &new);
        assert_eq!(
            lines,
            vec!["Method#1@const:x added: a variant".to_owned()],
            "{new:?}"
        );
    }
    // Plain additions still pass, a method named like a label among them.
    assert!(method_lines(&[method("x")], &[method("x"), method("y")]).is_empty());
    assert!(method_lines(&[method("x")], &[method("x"), method("x@1")]).is_empty());
    // A branch that repeats the text of an earlier one is not a new method even when no other
    // branch names it as a string: the integer constant 5 and the text "5" have one text.
    let lines = method_lines(
        &[json!({ "const": 5 })],
        &[json!({ "const": 5 }), method("5")],
    );
    assert_eq!(lines, vec!["Method#1@const:5 added: a variant".to_owned()]);
}

/// Two equal branches are told apart by their number, and a third branch that differs is reported
/// by its own key, for both comparisons.
#[test]
fn equal_branches_beside_one_that_differs_compare_by_number() {
    let protocol = protocol_schema();
    let mut old = sdk_schema();
    old["$defs"]["Route"]["properties"]["choice"] = json!({ "anyOf": [
        { "const": {}, "maxLength": 5 },
        { "const": {}, "maxLength": 5 },
        { "type": "string", "maxLength": 100 },
    ] });
    for (position, key) in [(0, "const:{}"), (1, "1@const:{}"), (2, "type:string")] {
        let mut new = old.clone();
        new["$defs"]["Route"]["properties"]["choice"]["anyOf"][position]["maxLength"] = json!(0);
        let wanted = vec![format!("Route.choice#{key} changed: maxLength")];
        let lines = crate::public_contract::compare(&old, &new).expect("compares");
        assert_eq!(lines, wanted, "the protocol's comparison: {key}");
        let outcome = compare(
            &old,
            &with_hidden(&new),
            (&protocol, &protocol),
            &contract("0.1.6", None),
            &contract("0.1.7", Some(LISTED)),
        );
        assert_eq!(outcome.passed.len(), 1, "{key}");
        assert_eq!(outcome.lines, wanted, "the SDK's comparison: {key}");
    }
    let same = crate::public_contract::compare(&old, &old.clone()).expect("compares");
    assert!(same.is_empty(), "{same:?}");
}

/// A member of a definition that the protocol schema has stays under the protocol's rule: the
/// table cannot list it into the SDK's, whichever release the protocol schema is of.
#[test]
fn a_member_of_a_definition_the_protocol_schema_shares_fails() {
    let old = json!({ "$defs": {
        "Frame": {
            "type": "object",
            "additionalProperties": false,
            "properties": { "id": { "type": "string" } },
            "required": ["id"],
        },
        "ConnectorManifest": { "type": "object", "properties": {
            "frame": { "$ref": "#/$defs/Frame" },
        } },
        "PluginManifest": { "type": "object", "properties": {} },
    } });
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
        (r#"{"sdk_version": "0.01.7"}"#, "sdk_version"),
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
