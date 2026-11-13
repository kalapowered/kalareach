//! The rule that lets a listed member arrive in the plugin SDK's schema inside a level, and
//! everything it must not let through.

use serde_json::{Value, json};

use crate::public_contract::{DIALECT, SdkContract, SdkVersion, compare_sdk_for_a_level};

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
    json!({ "$schema": DIALECT, "$defs": {
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

/// What the level comparison reports for the whole schemas `old` and `new`.
fn level_lines(old: &Value, new: &Value) -> Vec<String> {
    crate::public_contract::compare_for_a_level(
        old,
        new,
        &|| Ok(std::collections::BTreeSet::new()),
        &mut Vec::new(),
    )
    .expect("compares")
}

/// What the level comparison reports for a schema whose only definition is `Method`, going from
/// `old` to `new`, each given whole.
fn method_definition_lines(old: &Value, new: &Value) -> Vec<String> {
    level_lines(
        &json!({ "$schema": DIALECT, "$defs": { "Method": old } }),
        &json!({ "$schema": DIALECT, "$defs": { "Method": new } }),
    )
}

/// What the level comparison reports for the `Method` definition going from `old` to `new`, each
/// a list of branches that is the definition's `oneOf` and nothing else.
fn method_lines(old: &[Value], new: &[Value]) -> Vec<String> {
    method_definition_lines(&json!({ "oneOf": old }), &json!({ "oneOf": new }))
}

/// A branch of `Method` as every committed one is: a plain text constant.
fn method(name: &str) -> Value {
    json!({ "const": name, "type": "string" })
}

/// The line that a new method gives.
fn added(name: &str) -> String {
    format!("Method#const:{name} added: a variant")
}

/// The label of a branch that repeats the text of an earlier branch of its choice cannot be the
/// label of any other branch: the repeated branch, which makes `oneOf` refuse the method it
/// repeats, is a difference, and a method with a name like its label is not one that passes. The
/// pair is the one that the label `text@number` joined, in both orders of its last two branches.
/// A name with an `@` is no method's name, so the method of that pair is a difference too.
#[test]
fn a_repeated_branch_cannot_pass_as_a_new_method_by_its_label() {
    for new in [
        [method("x"), method("x"), method("x@1")],
        [method("x"), method("x@1"), method("x")],
    ] {
        let lines = method_lines(&[method("x")], &new);
        assert_eq!(
            lines,
            vec!["Method#1@const:x added: a variant".to_owned(), added("x@1")],
            "{new:?}"
        );
    }
    // Plain additions still pass.
    assert!(method_lines(&[method("x")], &[method("x"), method("y")]).is_empty());
    // A method named like a label is no method: its name has no shape that a method's name has.
    assert_eq!(
        method_lines(&[method("x")], &[method("x"), method("x@1")]),
        vec![added("x@1")]
    );
    // The integer constant 5 and the text "5" are two branches of two keys. The old schema accepts
    // the number 5 and refuses the text; the new one accepts both. The definition lists a constant
    // that is not a text, so no line under it passes.
    let lines = method_lines(
        &[json!({ "const": 5 })],
        &[json!({ "const": 5 }), method("5")],
    );
    assert_eq!(lines, vec![added("5")]);
}

/// A branch of a list nested in a branch of `Method` can have the label of a method named like
/// that label: the definition has a branch that is more than a text constant, so no line under it
/// passes, in either direction of the change.
#[test]
fn a_nested_branch_cannot_pass_as_a_new_method_by_its_label() {
    let nested = |name: &str, inner: Value| {
        let mut branch = method(name);
        branch["oneOf"] = inner;
        branch
    };
    let string = || json!({ "type": "string" });
    for (old, new, line) in [
        // The inner list repeats its branch, and a method has the label of that second branch.
        (
            vec![nested("x", json!([method("x")]))],
            vec![
                nested("x", json!([method("x"), method("x")])),
                method("x#1@const:x"),
            ],
            "Method#const:x#1@const:x added: a variant",
        ),
        // The inner list gains a branch of a text that a method has the label of, and the
        // opposite direction.
        (
            vec![nested("A", json!([string()]))],
            vec![
                nested(
                    "A",
                    json!([string(), { "type": "string", "maxLength": 100 }]),
                ),
                method("A#1@type:string"),
            ],
            "Method#const:A#1@type:string added: a variant",
        ),
        (
            vec![nested("A", json!([{ "type": "integer" }]))],
            vec![
                nested("A", json!([{ "type": "integer" }, string()])),
                method("A#type:string"),
            ],
            "Method#const:A#type:string added: a variant",
        ),
    ] {
        assert_eq!(method_lines(&old, &new), vec![line.to_owned()], "{new:?}");
    }
    // A plain new method with dots in its name still passes.
    assert!(
        method_lines(
            &[method("host.info")],
            &[method("host.info"), method("session.read.all")]
        )
        .is_empty()
    );
}

/// Other lists have the place `Method` as its `oneOf` has: its `anyOf` and the inner list of a
/// nullable pair. A branch of one of them gives the line of a new method, so the line of a new
/// method passes only where `Method` is a plain `oneOf` list in both schemas. None of these is:
/// each has an `anyOf` and a branch that is not a text constant (an `anyOf` beside a plain `oneOf`
/// is held by the keyword loop of the case for definitions that are not plain lists).
#[test]
fn a_list_of_another_keyword_at_the_place_of_method_does_not_pass_as_a_new_method() {
    let integer = || json!({ "type": "integer" });
    let nothing = || json!({ "type": "null" });
    let five = "Method#value:5 added: a variant".to_owned();
    for (old, new) in [
        // The inner list of a nullable pair. The old schema accepts the number 5; the new one
        // refuses it, because both branches of the inner list match it.
        (
            json!({ "oneOf": [integer()], "anyOf": [{ "oneOf": [integer()] }, nothing()] }),
            json!({
                "oneOf": [integer(), method("5")],
                "anyOf": [{ "oneOf": [integer(), { "const": 5 }] }, nothing()],
            }),
        ),
        // A direct `anyOf`. The old schema refuses the number 5; the new one accepts it, beside
        // the text "5" that it adds.
        (
            json!({ "oneOf": [integer()], "anyOf": [{ "const": 0 }, { "type": "string" }] }),
            json!({
                "oneOf": [integer(), method("5")],
                "anyOf": [{ "const": 0 }, { "type": "string" }, { "const": 5 }],
            }),
        ),
        // The same with a text before it. The old schema accepts only "a"; the new one accepts
        // "a" and the number 5, and refuses the text "5".
        (
            json!({ "oneOf": [method("a"), integer()], "anyOf": [{ "const": "a" }] }),
            json!({
                "oneOf": [method("a"), integer(), method("5")],
                "anyOf": [{ "const": "a" }, { "const": 5 }],
            }),
        ),
    ] {
        assert_eq!(
            method_definition_lines(&old, &new),
            vec![added("5"), five.clone()],
            "{new}"
        );
    }
}

/// A reference that moves from `Method` to a new definition is compared with the old `Method`
/// under its name, so a branch of the new definition has the place `Method` too. Its constant is
/// the number 5, `true`, `false` or `null`, and the line it gives is not the line of the text of
/// the same name: the old schema accepted "a" at `Request.method`, the new one accepts "a" and the
/// constant. The text of that name is a method that passes where `Method` stands alone.
#[test]
fn a_definition_that_a_reference_moves_to_does_not_give_the_line_of_a_new_method() {
    for (name, constant) in [
        ("5", json!(5)),
        ("true", json!(true)),
        ("false", json!(false)),
        ("null", json!(null)),
    ] {
        let old = json!({ "$schema": DIALECT, "$defs": {
            "Method": { "oneOf": [method("a")] },
            "Request": { "type": "object", "properties": {
                "method": { "$ref": "#/$defs/Method" },
            } },
        } });
        let new = json!({ "$schema": DIALECT, "$defs": {
            "Method": { "oneOf": [method("a"), method(name)] },
            "Code": { "oneOf": [method("a"), { "const": constant }] },
            "Request": { "type": "object", "properties": {
                "method": { "$ref": "#/$defs/Code" },
            } },
        } });
        assert_eq!(
            level_lines(&old, &new),
            vec![format!("Method#value:{constant} added: a variant")],
            "{name}"
        );
        assert!(
            method_lines(&[method("a")], &[method("a"), method(name)]).is_empty(),
            "{name}"
        );
    }
    // A branch of the new definition that is a text constant, and a name that `Method` does not
    // add, is a difference: `Request.method` now accepts "b".
    let old = json!({ "$schema": DIALECT, "$defs": {
        "Method": { "oneOf": [method("a")] },
        "Request": { "type": "object", "properties": { "method": { "$ref": "#/$defs/Method" } } },
    } });
    let new = json!({ "$schema": DIALECT, "$defs": {
        "Method": { "oneOf": [method("a"), method("c")] },
        "Code": { "oneOf": [method("a"), method("b")] },
        "Request": { "type": "object", "properties": { "method": { "$ref": "#/$defs/Code" } } },
    } });
    assert_eq!(level_lines(&old, &new), vec![added("b")]);
    // A line of another kind with a method's label is no new method: a member added to the branch
    // "x" of the new definition has the label of the method "x.b", which `Method` adds.
    let mut with_member = method("x");
    with_member["properties"] = json!({ "b": { "type": "string" } });
    let old = json!({ "$schema": DIALECT, "$defs": {
        "Method": { "oneOf": [method("x")] },
        "Request": { "type": "object", "properties": { "method": { "$ref": "#/$defs/Method" } } },
    } });
    let new = json!({ "$schema": DIALECT, "$defs": {
        "Method": { "oneOf": [method("x"), method("x.b")] },
        "Code": { "oneOf": [with_member] },
        "Request": { "type": "object", "properties": { "method": { "$ref": "#/$defs/Code" } } },
    } });
    assert_eq!(
        level_lines(&old, &new),
        vec!["Method#const:x.b added: a member".to_owned()]
    );
}

/// The definition is the list of plain text constants that the rule is written for in both
/// schemas, or no line under it passes. A branch that is not a constant (a name now matches two
/// branches, so `oneOf` refuses a name the old schema accepted), a constant that is not a text, a
/// branch that says more than its name, and a keyword beside `oneOf` each make the definition
/// accept something other than its names, in the old list, in the new one, or in both.
#[test]
fn a_definition_that_is_not_a_list_of_plain_text_constants_passes_no_line() {
    let b = added("b");
    let odd = [
        // Not a constant: "b" matches this branch and its own, so the new `oneOf` refuses "b",
        // which the old list accepted.
        json!({ "type": "string" }),
        // Not a text: the list accepts the number 5, which no name of it says.
        json!({ "const": 5 }),
        // No `type`: no value changes; it is not the plain text constant that the rule is for.
        json!({ "const": "c" }),
        // Another `type`: no value changes ("c" is not an integer, so the branch accepts nothing).
        json!({ "const": "c", "type": "integer" }),
        // More than its name: the branch refuses its own name "c", which a plain one accepts.
        json!({ "const": "c", "type": "string", "maxLength": 0 }),
        // A choice inside: "c" matches the inner branch once and the outer constant once, so no
        // value changes here, but the label of an inner branch can be a method's.
        json!({ "const": "c", "type": "string", "oneOf": [{ "type": "string" }] }),
        // An annotation that is not a text decides nothing, and is no annotation of the rule.
        json!({ "const": "c", "type": "string", "description": { "const": 1 } }),
    ];
    for branch in &odd {
        // In both lists: the line of "b" stays, and nothing else is reported.
        let lines = method_lines(
            &[method("a"), branch.clone()],
            &[method("a"), branch.clone(), method("b")],
        );
        assert_eq!(lines, vec![b.clone()], "in both: {branch}");
        // In the old list only, and in the new list only: the line of "b" stays.
        let lines = method_lines(&[method("a"), branch.clone()], &[method("a"), method("b")]);
        assert!(lines.contains(&b), "in the old list: {branch}: {lines:?}");
        let lines = method_lines(&[method("a")], &[method("a"), branch.clone(), method("b")]);
        assert!(lines.contains(&b), "in the new list: {branch}: {lines:?}");
    }
    // A keyword beside `oneOf` in the definition: the old and the new schema, each alone or both.
    for (keyword, value) in [
        // No value changes: every branch is a string already.
        ("type", json!("string")),
        // The schema that has it refuses every text, "a" included, which the other one accepts.
        ("maxLength", json!(0)),
        // The schema that has it refuses "a", which the other one accepts.
        ("not", json!({ "const": "a" })),
        // An annotation that is not a text: no value changes.
        ("description", json!({ "const": 1 })),
        // A list at the place `Method`, so a branch of it can give the line of a method.
        ("anyOf", json!([{ "const": "a" }])),
    ] {
        let list = |names: &[&str]| -> Value {
            json!({ "oneOf": names.iter().map(|name| method(name)).collect::<Vec<_>>() })
        };
        let with = |names: &[&str]| {
            let mut definition = list(names);
            definition[keyword] = value.clone();
            definition
        };
        let lines = method_definition_lines(&with(&["a"]), &with(&["a", "b"]));
        assert_eq!(lines, vec![b.clone()], "in both: {keyword}");
        let lines = method_definition_lines(&list(&["a"]), &with(&["a", "b"]));
        assert!(lines.contains(&b), "in the new: {keyword}: {lines:?}");
        let lines = method_definition_lines(&with(&["a"]), &list(&["a", "b"]));
        assert!(lines.contains(&b), "in the old: {keyword}: {lines:?}");
    }
}

/// A new name makes a place that uses `Method` accept more only where that place gains values
/// when `Method` does. A use inside a `oneOf` beside a branch that accepts the new name, inside a
/// `not` or inside an `if` can lose or gain values the other way, and the comparer reports a use
/// that is the same in both schemas at no line, so the change shows only as a new name under
/// `Method`. No line under `Method` passes where a place uses it so, directly or through another
/// definition that reaches it.
#[test]
fn a_new_method_does_not_pass_where_a_use_of_method_does_not_widen() {
    let reference = json!({ "$ref": "#/$defs/Method" });
    for (extra, says) in [
        (
            json!({ "Call": { "type": "object", "properties": { "method": { "oneOf": [
                reference.clone(), { "const": "b", "type": "string" } ] } } } }),
            // The old schema accepts "b" as a `Call.method` (only the second branch matches); the
            // new one refuses it (both match).
            "a oneOf beside a branch that accepts the new name",
        ),
        (
            json!({ "Name": { "type": "string", "not": reference.clone() } }),
            // The old schema accepts "b" as a `Name`; the new one refuses it.
            "a not",
        ),
        (
            json!({ "Envelope": { "type": "object",
                "if": { "properties": { "method": reference.clone() } },
                "then": true, "else": { "maxProperties": 1 } } }),
            // The new schema accepts `{"method": "b", "x": 1}`, which the old one refuses.
            "an if",
        ),
        (
            json!({ "Call": { "type": "object", "properties": { "method": { "oneOf": [
                { "$dynamicRef": "#/$defs/Method" }, { "const": "b", "type": "string" } ] } } } }),
            // A `$dynamicRef` to a definition without an anchor is a `$ref`: the old schema
            // accepts "b" as a `Call.method`; the new one refuses it.
            "a dynamic reference in a oneOf",
        ),
        (
            json!({ "Name": { "type": "string", "not": { "$dynamicRef": "#/$defs/Method" } } }),
            // The old schema accepts "b" as a `Name`; the new one refuses it.
            "a dynamic reference in a not",
        ),
        (
            json!({ "Name": { "type": "string", "not": { "$ref": "#/$defs/M%65thod" } },
                    "M%65thod": {} }),
            // A validator decodes the name, so the reference is to `Method`: the old schema
            // accepts "b" as a `Name`; the new one refuses it.
            "an encoded reference in a not",
        ),
        (
            json!({ "Name": { "type": "string", "not": { "$ref": "#/$defs/Method#" } },
                    "Method#": {} }),
            // Some validators remove a trailing `#`, so the reference is to `Method`: the old
            // schema accepts "b" as a `Name`; the new one refuses it.
            "a reference with a trailing #",
        ),
        (
            json!({
                "Holder": { "type": "object", "properties": { "m": reference.clone() } },
                "Choice": { "oneOf": [{ "$ref": "#/$defs/Holder" }, { "type": "object" }] },
            }),
            // Through another definition: the old schema accepts `{"m": "b"}` as a `Choice` (only
            // the plain object matches); the new one refuses it (both branches match).
            "a oneOf beside a branch, one definition away",
        ),
    ] {
        let lines = level_lines(
            &with_methods(&extra, &["a"]),
            &with_methods(&extra, &["a", "b"]),
        );
        assert_eq!(lines, vec![added("b")], "{says}");
    }
    // The use is in one schema only: the use is a difference of its own beside the new name, and
    // the new name does not pass for either direction of the change.
    let using = json!({ "Name": { "type": "string", "not": reference } });
    let without = json!({ "Name": { "type": "string" } });
    for (old, new) in [(&using, &without), (&without, &using)] {
        let lines = level_lines(&with_methods(old, &["a"]), &with_methods(new, &["a", "b"]));
        assert!(lines.contains(&added("b")), "{lines:?}");
    }
}

/// A reference that the walk follows reaches, in every validator, the definition that its name
/// says. A name that some validator decodes (`~`), cuts (a tab, a line feed, a carriage return, a
/// space at the end) or reads as more than one pointer segment (`/`), and a keyword that gives a
/// place an address, a name or a target that depends on where it is evaluated (`$id`, `id`,
/// `$anchor`, `$dynamicAnchor`, `$recursiveAnchor`, `$recursiveRef`), can send a reference to
/// another place than the one that the walk reads, and another dialect (`$schema`) can change
/// what `Method` means. No line under `Method` passes
/// beside one, wherever it stands (also in a schema that stands under a name that is a keyword,
/// as a text under such a name, and in a constant, a default or a keyword that the walk does not
/// know) and even where nothing in the schema refers to it.
#[test]
fn a_new_method_does_not_pass_where_a_reference_can_reach_another_place() {
    let reference = || json!({ "$ref": "#/$defs/Method" });
    // `Name` is a string that is not the definition `name`, which holds nothing; a validator that
    // changes `name` before it reads the reference reads another definition.
    let not_named = |name: &str| -> Value {
        let mut definitions = json!({
            "Name": { "type": "string", "not": { "$ref": format!("#/$defs/{name}") } } });
        definitions[name] = json!({});
        definitions
    };
    // A place that uses `Method` as a property, with `keyword` beside the reference.
    let holder_with = |keyword: &str, value: Value| -> Value {
        let mut place = reference();
        place[keyword] = value;
        json!({ "Holder": { "type": "object", "properties": { "m": place } } })
    };
    for (extra, says) in [
        (
            not_named("Met\thod"),
            // A validator that removes a tab reads `Method`: the old schema accepts "b" as a
            // `Name`; the new one refuses it.
            "a tab in the name",
        ),
        (
            not_named("Met\nhod"),
            // A validator that removes a line feed reads `Method`: the old schema accepts "b" as
            // a `Name`; the new one refuses it.
            "a line feed in the name",
        ),
        (
            not_named("Met\rhod"),
            // A validator that removes a carriage return reads `Method`: the old schema accepts
            // "b" as a `Name`; the new one refuses it.
            "a carriage return in the name",
        ),
        (
            not_named("Method "),
            // A validator that strips a space at the end reads `Method`: the old schema accepts
            // "b" as a `Name`; the new one refuses it.
            "a space at the end of the name",
        ),
        (
            not_named(""),
            // No definition of a protocol or a plugin SDK schema has an empty name, and a pointer
            // that ends in an empty segment is read in more than one way: nothing is claimed.
            "an empty name",
        ),
        (
            json!({
                "A~B": { "properties": { "m": reference() } },
                "A~0B": {},
                "Name": { "not": { "$ref": "#/$defs/A~0B" } },
            }),
            // A validator reads `~0` as `~`, so the reference is to `A~B`, which holds `Method`
            // as a property: the old schema accepts `{"m": "b"}` as a `Name`; the new one refuses
            // it.
            "a ~ in the name",
        ),
        (
            json!({
                "Holder": { "properties": { "m": reference() } },
                "Holder/properties/m": {},
                "Name": { "type": "string", "not": { "$ref": "#/$defs/Holder/properties/m" } },
            }),
            // A validator reads the name as three segments, which reach the property `m` of
            // `Holder`, that is `Method`: the old schema accepts "b" as a `Name`; the new one
            // refuses it.
            "a / in the name",
        ),
        (
            holder_with("$id", json!("https://example.test/m")),
            // A reference in a place that has an address of its own is resolved against that
            // address, so it reaches the `Method` of the resource at that address, if there is
            // one, and not the schema's.
            "an address of its own",
        ),
        (
            json!({
                "X": {},
                "Name": { "type": "string", "not": { "$ref": "#/$defs/X" } },
                "Holder": { "type": "object", "properties": { "m": {
                    "id": "#$defs/X", "$ref": "#/$defs/Method" } } },
            }),
            // A resolver that reads `id` takes `#/$defs/X` for the place that carries `id`, which
            // is `Method`: the old schema accepts "b" as a `Name`; the new one refuses it.
            "an id",
        ),
        (
            holder_with("$anchor", json!("m")),
            // An anchor names a place that a reference from another schema document (an address
            // that ends in `#m`) reaches, and the walk sees none of them.
            "an anchor that nothing in the schema refers to",
        ),
        (
            holder_with("$dynamicAnchor", json!("m")),
            // A `$dynamicRef` of another schema, evaluated through this one, reaches the place
            // that carries the anchor, and the walk sees none of them.
            "a dynamic anchor that nothing in the schema refers to",
        ),
        (
            holder_with("$recursiveAnchor", json!(true)),
            // `"$recursiveAnchor": true` marks a resource root that a `$recursiveRef` can select.
            // This place is no resource root, so the row shows only that the walk refuses the
            // keyword.
            "a recursive anchor that nothing in the schema refers to",
        ),
        (
            holder_with("$schema", json!("http://json-schema.org/draft-04/schema#")),
            // A validator that reads the dialect of each place reads draft-04 here, which has no
            // `const`: each branch of `Method` accepts every text, so the old schema accepts
            // `{"m": "a"}` as a `Holder` (one branch matches) and the new one refuses it (two do).
            "another dialect for a place",
        ),
        (
            json!({
                "X": {},
                "Name": { "type": "string", "not": { "$ref": "#/$defs/X" } },
                "D": { "$defs": { "id": "#$defs/X", "$ref": "#/$defs/Method" } },
            }),
            // A resolver that reads every object for `id` takes a text under the name `id` for
            // the address of the map, which holds `Method`: the old schema accepts "b" as a
            // `Name`; the new one refuses it.
            "a text under a name that is a keyword, in a nested map of definitions",
        ),
        (
            json!({
                "X": {},
                "Name": { "type": "string", "not": { "$ref": "#/$defs/X" } },
                "D": { "type": "object", "properties": {
                    "$anchor": "$defs/X", "$ref": "#/$defs/Method" } },
            }),
            // The same through `$anchor` in a map of properties.
            "a text under a name that is a keyword, in a map of properties",
        ),
        (
            json!({
                "X": {},
                "Name": { "type": "string", "not": { "$ref": "#/$defs/X" } },
                "id": "#$defs/X",
            }),
            // A definition that is a text, among the definitions of the schema: the walk refuses
            // a text under a name. (A text under `$ref`, another keyword's name, is refused by the
            // cut, as every definition name that begins with `$` is.)
            "a definition that is a text, named like a keyword",
        ),
        (
            json!({
                "Holder": { "type": "object", "properties": { "m": reference() } },
                "Again": { "$recursiveRef": "#" },
            }),
            // A `$recursiveRef` resolves `#` where it stands and, where that place has
            // `"$recursiveAnchor": true`, selects the outermost such place of the evaluation: the
            // walk cannot tell which places have one.
            "a recursive reference",
        ),
        (
            json!({ "D": { "dependentSchemas": { "properties": {
                "$id": "https://example.test/x" } } } }),
            // `properties` is a name here: the schema under it applies to an object that has a
            // member `properties`, and its `$id` gives that schema an address of its own.
            "a keyword in a schema that stands under a name that is a keyword",
        ),
        (
            json!({ "D": { "$defs": { "properties": { "$anchor": "m" } } } }),
            // The same in a nested `$defs`: an anchor in a definition named `properties`.
            "an anchor in a nested definition named like a keyword",
        ),
        (
            json!({ "D": { "default": { "properties": { "$id": "https://example.test/x" } } } }),
            // A resolver that searches the whole document for an `$id` (the legacy resolver of a
            // Python validator) finds it in a default as it finds one in a schema.
            "an address in a default",
        ),
        (
            json!({ "D": { "x-vendor": { "properties": { "$id": "https://example.test/x" } } } }),
            // The same in a keyword that the walk does not know.
            "an address in an unknown keyword",
        ),
    ] {
        let lines = level_lines(
            &with_methods(&extra, &["a"]),
            &with_methods(&extra, &["a", "b"]),
        );
        assert_eq!(lines, vec![added("b")], "{says}");
    }
}

/// A keyword that gives a place an address, a name, a target that depends on the place that
/// evaluates it or a dialect is refused in data as well (the value of a `default`): a resolver that
/// searches the whole document for an address or an anchor finds one there as it finds one in a
/// schema. Each of the eight is refused by itself, so that a keyword missing from the list is seen.
#[test]
fn each_scope_keyword_is_refused_in_data() {
    for keyword in [
        "$id",
        "id",
        "$anchor",
        "$dynamicAnchor",
        "$recursiveAnchor",
        "$dynamicRef",
        "$recursiveRef",
        "$schema",
    ] {
        let extra =
            json!({ "D": { "default": { "kind": { keyword: "https://example.test/x" } } } });
        let lines = level_lines(
            &with_methods(&extra, &["a"]),
            &with_methods(&extra, &["a", "b"]),
        );
        assert_eq!(lines, vec![added("b")], "{keyword} in a default");
    }
}

/// The keywords of the schema beside `$defs` use definitions too: a use of `Method` at the root
/// that does not widen blocks the line, as one in a definition does, and the root's properties,
/// which is how the generated schemas use definitions, widen. The root may name the one dialect
/// that the walk is written for, and no other.
#[test]
fn a_new_method_does_not_pass_where_the_root_uses_method_without_widening() {
    let reference = json!({ "$ref": "#/$defs/Method" });
    let holder =
        json!({ "Holder": { "type": "object", "properties": { "m": reference.clone() } } });
    let with_root = |root: &Value, names: &[&str]| -> Value {
        let mut schema = with_methods(&holder, names);
        for (keyword, member) in root.as_object().into_iter().flatten() {
            schema[keyword] = member.clone();
        }
        schema
    };
    for (root, says) in [
        (
            json!({ "not": reference.clone() }),
            // The old schema accepts "b" as a whole; the new one refuses it.
            "a not at the root",
        ),
        (
            json!({ "not": { "$ref": "#/$defs/Holder" } }),
            // The old schema accepts `{"m": "b"}` as a whole; the new one refuses it.
            "a not at the root, one definition away",
        ),
        (
            json!({ "$schema": "http://json-schema.org/draft-04/schema#" }),
            // Draft-04 has no `const`: `Method` accepts every text with one name and none with
            // two, so the old schema accepts `{"m": "a"}` as a `Holder` and the new one refuses it.
            "another dialect at the root",
        ),
    ] {
        let lines = level_lines(&with_root(&root, &["a"]), &with_root(&root, &["a", "b"]));
        assert_eq!(lines, vec![added("b")], "{says}");
    }
    let properties = json!({
        "$schema": DIALECT,
        "properties": { "m": reference, "n": { "$ref": "#/$defs/Holder" } },
    });
    let lines = level_lines(
        &with_root(&properties, &["a"]),
        &with_root(&properties, &["a", "b"]),
    );
    assert!(lines.is_empty(), "{lines:?}");
}

/// A root that names no dialect is read in the dialect that the reader defaults to, and an older
/// dialect has no `const`: `Method` of one name accepts every text and `Method` of two names none,
/// so the old schema accepts `{"m": "a"}` as a `Holder` and the new one refuses it. Without the
/// dialect in either schema, or in both, the new method is a difference.
#[test]
fn a_new_method_does_not_pass_where_a_root_names_no_dialect() {
    let holder = json!({ "Holder": { "type": "object",
        "properties": { "m": { "$ref": "#/$defs/Method" } } } });
    let with_dialect = |names: &[&str]| with_methods(&holder, names);
    let without_dialect = |names: &[&str]| {
        let mut schema = with_methods(&holder, names);
        schema.as_object_mut().expect("an object").remove("$schema");
        schema
    };
    assert_eq!(
        level_lines(&with_dialect(&["a"]), &with_dialect(&["a", "b"])),
        Vec::<String>::new(),
        "the control names the dialect"
    );
    for (old, new, says) in [
        (
            without_dialect(&["a"]),
            without_dialect(&["a", "b"]),
            "neither",
        ),
        (
            without_dialect(&["a"]),
            with_dialect(&["a", "b"]),
            "the old only",
        ),
        (
            with_dialect(&["a"]),
            without_dialect(&["a", "b"]),
            "the new only",
        ),
    ] {
        let lines = level_lines(&old, &new);
        assert!(
            lines.contains(&added("b")),
            "no dialect in {says}: {lines:?}"
        );
    }
}

/// A listed member of the SDK's schema arrives only where both schemas name the dialect that the
/// comparison reads them in: its definition's uses are read by that dialect's keywords.
#[test]
fn a_listed_member_does_not_arrive_where_a_schema_names_no_dialect() {
    let protocol = protocol_schema();
    let without = |schema: &Value| {
        let mut schema = schema.clone();
        schema.as_object_mut().expect("an object").remove("$schema");
        schema
    };
    let (old, new) = (sdk_schema(), with_hidden(&sdk_schema()));
    for (old, new, says) in [
        (without(&old), without(&new), "neither"),
        (without(&old), new.clone(), "the old only"),
        (old.clone(), without(&new), "the new only"),
    ] {
        let outcome = compare(
            &old,
            &new,
            (&protocol, &protocol),
            &contract("0.1.6", None),
            &contract("0.1.7", Some(LISTED)),
        );
        assert!(
            outcome
                .lines
                .contains(&"Route.hidden added: a member".to_owned()),
            "no dialect in {says}: {:?}",
            outcome.lines
        );
        assert!(outcome.passed.is_empty(), "{says}");
    }
}

/// The place of the schema's own root is `$root`, so a definition with a name that begins with `$`
/// cannot be told from it and is refused. The schema is a definition `$root` marked as read-only
/// metadata and a nullable pair at the root: the old pair's closed object refuses `{"note": "x"}`,
/// the new one accepts it, and the line of the root's member `$root.note added: a member` is the
/// label of a member of the marked definition.
#[test]
fn a_definition_named_like_the_roots_place_is_refused() {
    let schema = |with_note: bool| {
        let mut object = json!({ "type": "object", "properties": {},
            "additionalProperties": false });
        if with_note {
            object["properties"]["note"] = json!({ "type": "string" });
        }
        json!({ "$schema": DIALECT,
            "$defs": { "$root": { "type": "object", "properties": {},
                "x-kalareach-read-only-metadata": true } },
            "anyOf": [object, { "type": "null" }] })
    };
    let outcome = crate::public_contract::compare(&schema(false), &schema(true));
    assert!(outcome.is_err(), "{outcome:?}");
}

/// A rule excuses a line only where every keyword that the walk meets is one that it models:
/// the applicators, the validation keywords whose value is plain data, the annotations and the
/// product's own two (`tsType` and the read-only marker). A keyword that is none of these, beside
/// the use of the definition or above it, may change what a place accepts in a way that the walk
/// does not read, so the line is reported. The keyword is the same in both schemas, so the target's
/// difference is the only one. The method rule, the listed arrival and the read-only member each
/// read the uses through the walk; the new section reads both schemas through the same walk, where
/// no use stands, and its definition by its own keys.
#[test]
fn an_unmodelled_keyword_beside_a_use_or_above_it_excuses_nothing() {
    let place = |reference: &str, position: &str| {
        let (member, outer) = match position {
            "beside" => (
                json!({ "$ref": reference, "x-unmodelled": true }),
                json!({}),
            ),
            _ => (
                json!({ "$ref": reference }),
                json!({ "x-unmodelled": true }),
            ),
        };
        let mut holder = json!({ "type": "object", "properties": { "m": member } });
        for (keyword, value) in outer.as_object().into_iter().flatten() {
            holder[keyword] = value.clone();
        }
        holder
    };
    for position in ["beside", "above"] {
        // The method rule: `Holder.m` is a use of `Method`.
        let extra = json!({ "Holder": place("#/$defs/Method", position) });
        let lines = level_lines(
            &with_methods(&extra, &["a"]),
            &with_methods(&extra, &["a", "b"]),
        );
        assert!(
            lines.contains(&added("b")),
            "the method rule, {position}: {lines:?}"
        );
        // The listed arrival: `Holder.m` is a use of `Route`.
        let protocol = protocol_schema();
        let mut old = sdk_schema();
        old["$defs"]["Holder"] = place("#/$defs/Route", position);
        let new = with_hidden(&old);
        let outcome = compare(
            &old,
            &new,
            (&protocol, &protocol),
            &contract("0.1.6", None),
            &contract("0.1.7", Some(LISTED)),
        );
        assert!(
            outcome
                .lines
                .contains(&"Route.hidden added: a member".to_owned())
                && outcome.passed.is_empty(),
            "the listed arrival, {position}: {:?}",
            outcome.lines
        );
        // The read-only member: `Holder.m` is a use of `Info`.
        let object = |with_member: bool| {
            let mut definition = json!({ "type": "object", "x-kalareach-read-only-metadata": true,
                "properties": { "id": { "type": "string" } }, "required": ["id"] });
            if with_member {
                definition["properties"]["note"] = json!({ "type": "string" });
            }
            definition
        };
        let schema = |with_member: bool| {
            json!({ "$schema": DIALECT, "$defs": { "Info": object(with_member),
                "Holder": place("#/$defs/Info", position) } })
        };
        let lines =
            crate::public_contract::compare(&schema(false), &schema(true)).expect("compares");
        assert!(
            lines.contains(&"Info.note added: a member".to_owned()),
            "the read-only member, {position}: {lines:?}"
        );
    }
    // At the place itself: the keys of the configuration document and of a read-only object are
    // read as a list, so a key that is none of them is a difference.
    let document = |with_push: bool| {
        let mut properties = json!({ "version": { "type": "integer" } });
        if with_push {
            properties["push"] = json!({ "type": "object" });
        }
        json!({ "$schema": DIALECT, "$defs": { "ConfigurationDocument": { "type": "object",
            "properties": properties, "additionalProperties": false, "x-unmodelled": true } } })
    };
    let (lines, passed) = section_lines(&document(false), &document(true));
    assert_eq!(
        (lines, passed),
        (
            vec!["ConfigurationDocument.push added: a member".to_owned()],
            vec![]
        ),
        "the new section"
    );
    let info = |with_note: bool| {
        let mut definition = json!({ "$schema": DIALECT, "$defs": { "Info": {
            "type": "object", "x-kalareach-read-only-metadata": true, "x-unmodelled": true,
            "properties": { "id": { "type": "string" } } } } });
        if with_note {
            definition["$defs"]["Info"]["properties"]["note"] = json!({ "type": "string" });
        }
        definition
    };
    let lines = crate::public_contract::compare(&info(false), &info(true)).expect("compares");
    assert!(
        lines.contains(&"Info.note added: a member".to_owned()),
        "the read-only member: {lines:?}"
    );
}
/// A change of a keyword of the root beside a new method is a difference of its own: the old
/// schema accepts the texts of `Method` as a whole (its root is a string that is also a `Method`);
/// the new one, whose root is a number that is also a `Method`, accepts no value. Nothing under
/// `$defs` differs but the method, so the new method passes and the root's line is the only one.
#[test]
fn a_change_of_the_roots_type_beside_a_new_method_is_reported() {
    let with_root = |root_type: &str, names: &[&str]| {
        let mut schema = with_methods(&json!({}), names);
        schema["$ref"] = json!("#/$defs/Method");
        schema["type"] = json!(root_type);
        schema
    };
    let (old, new) = (
        with_root("string", &["a"]),
        with_root("number", &["a", "b"]),
    );
    assert_eq!(
        level_lines(&old, &new),
        vec!["$root changed: type".to_owned()]
    );
    assert_eq!(
        crate::public_contract::compare(&old, &new),
        Ok(vec!["$root changed: type".to_owned(), added("b")])
    );
}

/// Where every use of `Method` widens with it, the new name passes: a use as a property (also one
/// whose name is a keyword), an item, an additional property, a pattern property, in an `anyOf`,
/// an `allOf`, a nullable pair, beside an annotation, as a whole definition, through another
/// definition, and nowhere at all.
#[test]
fn a_new_method_passes_where_every_use_of_method_widens() {
    let reference = || json!({ "$ref": "#/$defs/Method" });
    let uses = json!({
        "Property": { "type": "object", "properties": {
            "method": reference(), "not": reference(), "oneOf": reference() } },
        "Items": { "type": "array", "items": reference() },
        "Tuple": { "type": "array", "prefixItems": [reference(), { "type": "integer" }] },
        "Open": { "type": "object", "additionalProperties": reference() },
        "Pattern": { "type": "object", "patternProperties": { "^m": reference() } },
        "Either": { "anyOf": [reference(), { "type": "integer" }] },
        "Both": { "allOf": [reference(), { "type": "string" }] },
        "Nullable": { "anyOf": [reference(), { "type": "null" }] },
        "Described": { "$ref": "#/$defs/Method", "description": "a method" },
        "Chain": { "type": "object", "properties": { "inner": { "$ref": "#/$defs/Property" } } },
        // A definition whose name has an upper-case letter, a digit and an underscore.
        "Chain_2": { "anyOf": [{ "$ref": "#/$defs/Chain" }, { "type": "null" }] },
        "Outer": { "type": "object", "properties": { "next": { "$ref": "#/$defs/Chain_2" } } },
        // Names that are keywords, in each of the six maps of names, are names (a schema, a
        // boolean or a list stands under each): no place has an address.
        "Named": { "oneOf": [
            { "type": "object", "properties": { "id": { "type": "string" },
                "$id": { "type": "string" }, "$anchor": { "type": "string" } },
                "patternProperties": { "id": { "type": "string" } } },
            { "type": "null" }] },
        "Mapped": { "type": "object", "$defs": { "id": { "type": "string" } },
            "definitions": { "$id": true },
            "dependentSchemas": { "id": { "required": ["x"] } },
            "dependencies": { "$anchor": ["x"] } },
        // Data under the plain keywords that holds no keyword that the walk refuses.
        "Data": { "default": { "kind": 1 }, "examples": [{ "m": "a" }], "const": null,
            "tsType": "Kind", "format": "uuid", "minLength": 1 },
    });
    assert!(
        level_lines(
            &with_methods(&uses, &["a"]),
            &with_methods(&uses, &["a", "b"])
        )
        .is_empty()
    );
    let none = json!({ "Other": { "type": "string" } });
    assert!(
        level_lines(
            &with_methods(&none, &["a"]),
            &with_methods(&none, &["a", "b"])
        )
        .is_empty()
    );
}

/// A schema whose only definitions are `extra` and a `Method` that lists `names`.
fn with_methods(extra: &Value, names: &[&str]) -> Value {
    let mut definitions = extra.clone();
    definitions["Method"] =
        json!({ "oneOf": names.iter().map(|name| method(name)).collect::<Vec<_>>() });
    json!({ "$schema": DIALECT, "$defs": definitions })
}

/// A name that has not the shape of a method's name (lower-case letters, digits and underscores in
/// words, with single dots between) is no new method, whether it is the line's name or any other
/// name of the old list or the new one: the definition is then not the list the rule is for. In
/// the first case the new schema accepts a text that the old one refuses, which no method's name
/// says. `#`, `@`, `[` and `{` mark a branch, a numbered branch, an item and an additional
/// property in a label, so a name that holds one can look like the label of another place. Where
/// a name is in both lists, the new list adds only "c", which has the shape, and its line is
/// reported too.
#[test]
fn a_name_that_is_not_the_shape_of_a_methods_is_no_new_method() {
    for name in [
        "Host.info",
        "a#b",
        "a..b",
        ".a",
        "a.",
        "",
        "a b",
        "a-b",
        "a[0]",
        "a{}",
        "x@1",
        "a:b",
        "é",
    ] {
        assert_eq!(
            method_lines(&[method("a")], &[method("a"), method(name)]),
            vec![added(name)],
            "{name:?}"
        );
        // In the new list beside a name that is an addition of the right shape: both are kept.
        let lines = method_lines(&[method("a")], &[method("a"), method(name), method("c")]);
        assert!(lines.contains(&added("c")), "{name:?}: {lines:?}");
        // In both lists, beside a name that is an addition of the right shape.
        let lines = method_lines(
            &[method("a"), method(name)],
            &[method("a"), method(name), method("c")],
        );
        assert_eq!(lines, vec![added("c")], "{name:?}");
    }
    // Names of the shape: letters, digits and underscores in words, with single dots between.
    for name in [
        "b",
        "a.b",
        "a_b",
        "b2",
        "a.1",
        "1",
        "session.read.all",
        "true",
        "null",
    ] {
        assert!(
            method_lines(&[method("a")], &[method("a"), method(name)]).is_empty(),
            "{name:?}"
        );
    }
}

/// The names of the old list are all in the new list, and each name stands once in its list. A
/// method that goes beside one that arrives is a difference, so a new method does not pass there:
/// the old schema accepted "b". A name twice in a list is refused by that list's `oneOf` (the text
/// "a" in the old list below, the text "b" in the new one), so no new method passes beside it.
#[test]
fn a_new_method_passes_only_beside_the_old_names_each_once() {
    // "b" goes and "c" arrives.
    assert_eq!(
        method_lines(&[method("a"), method("b")], &[method("a"), method("c")]),
        vec!["Method#const:b removed: a variant".to_owned(), added("c")]
    );
    // A name twice in the old list, and in the new list.
    let lines = method_lines(
        &[method("a"), method("a")],
        &[method("a"), method("a"), method("b")],
    );
    assert_eq!(lines, vec![added("b")]);
    let lines = method_lines(&[method("a")], &[method("a"), method("b"), method("b")]);
    assert_eq!(
        lines,
        vec!["Method#1@const:b added: a variant".to_owned(), added("b")]
    );
}

/// One new method, several at once, and a new method beside changed descriptions and titles of the
/// definition and of old branches pass, in any order of the list: the annotations decide nothing.
#[test]
fn a_new_method_beside_a_changed_description_passes() {
    assert!(method_lines(&[method("a")], &[method("a"), method("b")]).is_empty());
    assert!(
        method_lines(
            &[method("a.b")],
            &[
                method("a.b"),
                method("c_d.e2"),
                method("f"),
                method("session.read.all"),
                method("9"),
            ]
        )
        .is_empty()
    );
    let described = |name: &str, text: &str| {
        let mut branch = method(name);
        branch["description"] = json!(text);
        branch
    };
    let old = json!({ "description": "the methods", "oneOf": [described("a", "the first")] });
    let mut titled = described("b", "the new one");
    titled["title"] = json!("B");
    let new = json!({
        "description": "all the methods",
        "title": "Method",
        "oneOf": [titled, described("a", "the first, said again")],
    });
    assert!(method_definition_lines(&old, &new).is_empty());
}

/// The head's own `Method` is the list that the rule is written for, so the rule is in force for
/// the real definition: with its last name left out of the earlier schema, that name is a new
/// method that passes; a name of another shape added to the head's list does not.
#[test]
fn the_committed_method_is_a_list_of_plain_method_names_and_a_new_one_passes() {
    let head = committed("packages/protocol/schema/kalareach-protocol.schema.json");
    let branches = head["$defs"]["Method"]["oneOf"].as_array().expect("a list");
    assert!(!branches.is_empty());
    let mut seen = std::collections::BTreeSet::new();
    for branch in branches {
        let name = branch["const"].as_str().expect("a text constant");
        let words_are_plain = |word: &str| {
            !word.is_empty()
                && word
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        };
        assert!(name.split('.').all(words_are_plain), "{name}");
        assert_eq!(branch["type"], json!("string"), "{name}");
        assert!(seen.insert(name), "{name} stands once");
    }
    let mut earlier = head.clone();
    let last = earlier["$defs"]["Method"]["oneOf"]
        .as_array_mut()
        .expect("a list")
        .pop()
        .expect("a branch");
    assert_eq!(level_lines(&earlier, &head), Vec::<String>::new(), "{last}");
    let mut grown = head.clone();
    grown["$defs"]["Method"]["oneOf"]
        .as_array_mut()
        .expect("a list")
        .push(method("Not.a.method"));
    assert_eq!(level_lines(&head, &grown), vec![added("Not.a.method")]);
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
    for (position, key) in [(0, "value:{}"), (1, "1@value:{}"), (2, "type:string")] {
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
    let old = json!({ "$schema": DIALECT, "$defs": {
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

/// What the level comparison reports for a configuration document going from `old` to `new`, and
/// the sections it passes, where the build lists the section "push" above the release's level.
fn section_lines(old: &Value, new: &Value) -> (Vec<String>, Vec<String>) {
    let mut passed = Vec::new();
    let lines = crate::public_contract::compare_for_a_level(
        old,
        new,
        &|| Ok(std::collections::BTreeSet::from(["push".to_owned()])),
        &mut passed,
    )
    .expect("compares");
    (lines, passed)
}

/// A new section passes only where the document is a plain closed object in both schemas, so that
/// its own `properties` are the only list with the label `ConfigurationDocument.push`. An open
/// document, a nullable pair of an open object and a `$ref` with `properties` beside it give the
/// same label from a list where the member restricts a value that the earlier schema accepted.
#[test]
fn a_new_section_passes_only_in_a_plain_closed_document() {
    let section = json!({ "type": "object" });
    let closed = |with_push: bool| {
        let mut properties = json!({ "version": { "type": "integer" } });
        if with_push {
            properties["push"] = section.clone();
        }
        json!({ "$schema": DIALECT, "$defs": { "ConfigurationDocument": {
            "type": "object", "properties": properties, "additionalProperties": false } } })
    };
    let (lines, passed) = section_lines(&closed(false), &closed(true));
    assert_eq!((lines, passed), (vec![], vec!["push".to_owned()]));
    let wanted = vec!["ConfigurationDocument.push added: a member".to_owned()];
    let open = |with_push: bool| {
        let mut definition = json!({ "type": "object", "properties": {
            "version": { "type": "integer" } } });
        if with_push {
            definition["properties"]["push"] = section.clone();
        }
        definition
    };
    for (old, new, says) in [
        (
            json!({ "$schema": DIALECT, "$defs": { "ConfigurationDocument": open(false) } }),
            json!({ "$schema": DIALECT, "$defs": { "ConfigurationDocument": open(true) } }),
            // The old schema accepts `{"push": 5}`; the new one refuses it.
            "an open document",
        ),
        (
            json!({ "$schema": DIALECT, "$defs": { "ConfigurationDocument": {
                "anyOf": [open(false), { "type": "null" }] } } }),
            json!({ "$schema": DIALECT, "$defs": { "ConfigurationDocument": {
                "anyOf": [open(true), { "type": "null" }] } } }),
            // The same, in the one schema of a nullable pair: the old schema accepts `{"push": 5}`.
            "an open object in a nullable pair",
        ),
        (
            json!({ "$schema": DIALECT, "$defs": { "Base": open(false),
                "ConfigurationDocument": { "$ref": "#/$defs/Base" } } }),
            json!({ "$schema": DIALECT, "$defs": { "Base": open(false), "ConfigurationDocument": {
                "$ref": "#/$defs/Base", "properties": { "push": section.clone() } } } }),
            // The same, beside a reference to an open object: the old schema accepts `{"push": 5}`.
            "a reference with properties beside it",
        ),
    ] {
        let (lines, passed) = section_lines(&old, &new);
        assert_eq!((lines, passed), (wanted.clone(), vec![]), "{says}");
    }
    // The document is open in one schema only: the change of `additionalProperties` is a line of
    // its own, and the section does not pass beside it, whichever schema is the open one.
    let closed_with = |with_push: bool| closed(with_push)["$defs"].clone();
    for (old, new, says) in [
        (
            open(false),
            closed_with(true)["ConfigurationDocument"].clone(),
            "open, then closed",
        ),
        (
            closed_with(false)["ConfigurationDocument"].clone(),
            open(true),
            "closed, then open",
        ),
    ] {
        let wrap = |definition: Value| json!({ "$schema": DIALECT, "$defs": { "ConfigurationDocument": definition } });
        let (lines, passed) = section_lines(&wrap(old), &wrap(new));
        assert!(
            lines.contains(&wanted[0]) && passed.is_empty(),
            "{says}: {lines:?}"
        );
    }
    // A keyword of the schema's own root that uses the document: in a `oneOf` beside a plain
    // object, the old root accepts `{"push": {}}` (only the plain object matches) and the new one
    // refuses it (both match). A bare reference among the root's `properties` is the bundle's own
    // entry, and a use as a property only widens with its target; any other entry is read.
    let with_root = |schema: &Value, keyword: &str, member: Value| {
        let mut schema = schema.clone();
        schema[keyword] = member;
        schema
    };
    let document = json!({ "$ref": "#/$defs/ConfigurationDocument" });
    let (lines, passed) = section_lines(
        &with_root(
            &closed(false),
            "oneOf",
            json!([document, { "type": "object" }]),
        ),
        &with_root(
            &closed(true),
            "oneOf",
            json!([document, { "type": "object" }]),
        ),
    );
    assert_eq!(
        (lines, passed),
        (wanted.clone(), vec![]),
        "a oneOf at the root"
    );
    let (lines, passed) = section_lines(
        &with_root(
            &closed(false),
            "$ref",
            json!("#/$defs/ConfigurationDocument"),
        ),
        &with_root(
            &closed(true),
            "$ref",
            json!("#/$defs/ConfigurationDocument"),
        ),
    );
    assert_eq!(
        (lines, passed),
        (wanted.clone(), vec![]),
        "a reference at the root"
    );
    // A member of the root's `properties` that is more than a bare reference is read: under a
    // `not`, the old root accepts `{"config": {"push": {}}}` and the new one refuses it.
    let (lines, passed) = section_lines(
        &with_root(
            &closed(false),
            "properties",
            json!({ "config": { "not": document.clone() } }),
        ),
        &with_root(
            &closed(true),
            "properties",
            json!({ "config": { "not": document.clone() } }),
        ),
    );
    assert_eq!(
        (lines, passed),
        (wanted.clone(), vec![]),
        "a not under a root property"
    );
    // A `$dynamicRef` with a pointer reaches the document as a `$ref` does.
    let dynamic = json!({ "$dynamicRef": "#/$defs/ConfigurationDocument" });
    let (lines, passed) = section_lines(
        &with_root(
            &closed(false),
            "oneOf",
            json!([dynamic, { "type": "object" }]),
        ),
        &with_root(
            &closed(true),
            "oneOf",
            json!([dynamic, { "type": "object" }]),
        ),
    );
    assert_eq!(
        (lines, passed),
        (wanted.clone(), vec![]),
        "a $dynamicRef at the root"
    );
    let listed = json!({ "configuration_document": document });
    let (lines, passed) = section_lines(
        &with_root(&closed(false), "properties", listed.clone()),
        &with_root(&closed(true), "properties", listed),
    );
    assert_eq!(
        (lines, passed),
        (vec![], vec!["push".to_owned()]),
        "the root's properties"
    );
}

/// A new section is excused only where every keyword of both schemas, at the place and on the path
/// from the root to it, is one that the walk models: an unmodelled keyword anywhere (at the root, in
/// another definition, inside the document) and a reference to the document under a keyword that the
/// walk does not read as a reference (`$dynamicRef`, `$recursiveRef`) leave the section as a line, as
/// does a use that the walk reads. A schema that names no dialect is refused as it is for the other
/// rules. The keyword stands in both schemas, in the earlier one only and in the new one only, so
/// that the section is the only difference that can be excused. (A `$ref` of another form is
/// refused when the schema is cut, which is not this rule's.)
#[test]
fn a_new_section_passes_only_where_every_keyword_of_both_schemas_is_modelled() {
    let schema = |with_push: bool| {
        let mut properties = json!({ "version": { "type": "integer" } });
        if with_push {
            properties["push"] = json!({ "type": "object" });
        }
        json!({ "$schema": DIALECT, "$defs": { "ConfigurationDocument": {
            "type": "object", "properties": properties, "additionalProperties": false } } })
    };
    let wanted = "ConfigurationDocument.push added: a member".to_owned();
    // Modelled keywords at the same places change nothing: annotations at the root, a definition
    // that the document does not use and a keyword of a member.
    let modelled = |schema: &mut Value| {
        schema["title"] = json!("The bundle");
        schema["description"] = json!("The messages of the bundle.");
        schema["$defs"]["Other"] = json!({ "type": "object", "description": "Another one.",
            "properties": { "name": { "type": "string", "format": "uri", "minLength": 1,
                "tsType": "string" } }, "required": ["name"] });
        schema["$defs"]["ConfigurationDocument"]["properties"]["version"]["minimum"] = json!(1);
    };
    let (mut old, mut new) = (schema(false), schema(true));
    modelled(&mut old);
    modelled(&mut new);
    assert_eq!(
        section_lines(&old, &new),
        (vec![], vec!["push".to_owned()]),
        "modelled keywords"
    );
    let rows: [(&str, fn(&mut Value)); 11] = [
        ("an unmodelled keyword at the root", |schema| {
            schema["x-unmodelled"] = json!(true);
        }),
        ("an unmodelled keyword in another definition", |schema| {
            schema["$defs"]["Other"] = json!({ "type": "object", "x-unmodelled": true });
        }),
        (
            "an unmodelled keyword in a member of the document",
            |schema| {
                schema["$defs"]["ConfigurationDocument"]["properties"]["version"]["x-unmodelled"] =
                    json!(true);
            },
        ),
        ("a use of the document", |schema| {
            schema["$defs"]["Holder"] = json!({ "type": "object", "properties": {
                "c": { "$ref": "#/$defs/ConfigurationDocument" } } });
        }),
        ("a dynamic reference with an encoded pointer", |schema| {
            schema["$defs"]["Holder"] = json!({ "type": "object", "properties": {
                "c": { "$dynamicRef": "#/%24defs/ConfigurationDocument" } } });
        }),
        ("a dynamic reference at the root", |schema| {
            schema["$dynamicRef"] = json!("#/%24defs/ConfigurationDocument");
        }),
        ("a recursive reference at the root", |schema| {
            schema["$recursiveRef"] = json!("#");
        }),
        (
            "a bundle entry that is a reference of another form",
            |schema| {
                schema["properties"] =
                    json!({ "c": { "$ref": "#/%24defs/ConfigurationDocument" } });
            },
        ),
        (
            "a bundle entry with a keyword beside its reference",
            |schema| {
                schema["properties"] = json!({ "c": { "$ref": "#/$defs/ConfigurationDocument",
                "description": "The document." } });
            },
        ),
        (
            "a root property that uses the document in an anyOf",
            |schema| {
                schema["properties"] = json!({ "c": { "anyOf": [
                { "$ref": "#/$defs/ConfigurationDocument" }, { "type": "null" }] } });
            },
        ),
        ("a dynamic reference with an address", |schema| {
            schema["$defs"]["Holder"] = json!({ "type": "object", "properties": {
                "c": { "$dynamicRef": "https://example.com/bundle#/$defs/ConfigurationDocument" } } });
        }),
    ];
    let mut excused = Vec::new();
    for (says, edit) in rows {
        for (in_the_old, in_the_new) in [(true, true), (true, false), (false, true)] {
            let (mut old, mut new) = (schema(false), schema(true));
            if in_the_old {
                edit(&mut old);
            }
            if in_the_new {
                edit(&mut new);
            }
            let (lines, passed) = section_lines(&old, &new);
            if !lines.contains(&wanted) || !passed.is_empty() {
                excused.push(format!("{says} (earlier {in_the_old}, new {in_the_new})"));
            }
        }
    }
    // A schema that names no dialect is read in whatever dialect the reader defaults to.
    for (in_the_old, in_the_new) in [(true, true), (true, false), (false, true)] {
        let (mut old, mut new) = (schema(false), schema(true));
        if in_the_old {
            old.as_object_mut().expect("object").remove("$schema");
        }
        if in_the_new {
            new.as_object_mut().expect("object").remove("$schema");
        }
        let (lines, passed) = section_lines(&old, &new);
        if !lines.contains(&wanted) || !passed.is_empty() {
            excused.push(format!(
                "no dialect (earlier {in_the_old}, new {in_the_new})"
            ));
        }
    }
    assert!(excused.is_empty(), "the section passed: {excused:#?}");
}

/// A listed member of the SDK's schema arrives only where every use of its definition widens with
/// it. In a `oneOf` beside a plain object, or in a `not`, a closed object that gains a member
/// makes the place refuse a value that it accepted.
#[test]
fn a_listed_member_does_not_arrive_where_a_use_of_its_definition_does_not_widen() {
    let (protocol, route) = (protocol_schema(), json!({ "$ref": "#/$defs/Route" }));
    for (extra, says) in [
        (
            json!({ "Holder": { "oneOf": [route.clone(), { "type": "object" }] } }),
            // The old schema accepts `{"method": "a", "hidden": []}` as a `Holder` (only the plain
            // object matches); the new one refuses it (both match).
            "a oneOf beside a plain object",
        ),
        (
            json!({ "Holder": { "not": route.clone() } }),
            // The old schema accepts `{"method": "a", "hidden": []}` as a `Holder` (it is no
            // `Route`); the new one refuses it.
            "a not",
        ),
    ] {
        let mut old = sdk_schema();
        for (name, definition) in extra.as_object().into_iter().flatten() {
            old["$defs"][name] = definition.clone();
        }
        let new = with_hidden(&old);
        let outcome = compare(
            &old,
            &new,
            (&protocol, &protocol),
            &contract("0.1.6", None),
            &contract("0.1.7", Some(LISTED)),
        );
        assert_eq!(
            outcome.lines,
            vec!["Route.hidden added: a member".to_owned()],
            "{says}"
        );
        assert!(outcome.passed.is_empty(), "{says}");
    }
}

/// The uses of a listed member's definition are read in both schemas, each by itself: a use that
/// does not widen in the earlier schema alone, or in the new schema alone, still keeps the member
/// from arriving. The definition `Holder` stands in one schema only.
#[test]
fn a_listed_member_does_not_arrive_where_one_schema_alone_has_a_use_that_does_not_widen() {
    let (protocol, not_a_route) = (
        protocol_schema(),
        json!({ "not": { "$ref": "#/$defs/Route" } }),
    );
    for (in_the_old, says) in [
        // The old schema accepts `{"method": "a", "hidden": []}` as a `Holder` (it is no `Route`);
        // the new schema has no `Holder`, so nothing there decides it.
        (
            true,
            "a use that does not widen in the earlier schema alone",
        ),
        // The earlier schema has no `Holder`; the new one refuses the value above as a `Holder`.
        (false, "a use that does not widen in the new schema alone"),
    ] {
        let mut old = sdk_schema();
        let mut new = with_hidden(&old);
        if in_the_old {
            old["$defs"]["Holder"] = not_a_route.clone();
        } else {
            new["$defs"]["Holder"] = not_a_route.clone();
        }
        let outcome = compare(
            &old,
            &new,
            (&protocol, &protocol),
            &contract("0.1.6", None),
            &contract("0.1.7", Some(LISTED)),
        );
        assert!(
            outcome
                .lines
                .contains(&"Route.hidden added: a member".to_owned()),
            "{says}: {:?}",
            outcome.lines
        );
        assert!(outcome.passed.is_empty(), "{says}");
    }
}

/// The public contract passes an optional member of a read-only metadata object only where the
/// line is a member line of an open object of its own properties and every use of the object is
/// one that a narrower object only narrows (a property, an item, an `anyOf`): in a `oneOf` beside a
/// plain object or in a `not`, the member makes the new schema accept a value that the old one
/// refuses. A variant whose text holds a dot and a member of a variant have labels of the same
/// form, so a definition named like their place must not stand for it; a nullable pair of a closed
/// object and a `$ref` give the label from another list.
#[test]
fn a_member_of_a_read_only_metadata_object_passes_only_in_an_open_plain_object() {
    let marker = "x-kalareach-read-only-metadata";
    let object = |with_member: bool| {
        let mut definition = json!({ "type": "object", marker: true,
            "properties": { "id": { "type": "string" } }, "required": ["id"] });
        if with_member {
            definition["properties"]["note"] = json!({ "type": "string" });
        }
        definition
    };
    let schema =
        |definition: &Value| json!({ "$schema": DIALECT, "$defs": { "Info": definition.clone() } });
    let passes = crate::public_contract::compare(&schema(&object(false)), &schema(&object(true)));
    assert_eq!(passes, Ok(vec![]));
    let info = json!({ "$ref": "#/$defs/Info" });
    let used = |definition: &Value, holder: Option<&Value>| {
        let mut schema = json!({ "$schema": DIALECT, "$defs": { "Info": definition.clone() } });
        if let Some(holder) = holder {
            schema["$defs"]["Holder"] = holder.clone();
        }
        schema
    };
    // Where the object is used as a property, a narrower object only narrows the place, so the
    // member passes.
    let property = json!({ "type": "object", "properties": { "info": info.clone() } });
    assert_eq!(
        crate::public_contract::compare(
            &used(&object(false), Some(&property)),
            &used(&object(true), Some(&property))
        ),
        Ok(vec![])
    );
    // A member narrows the object: the value `{"id": "x", "note": 5}` matches the open object, so a
    // `Holder` that is a `oneOf` of it and a plain object refuses it in the old schema (both
    // branches match) and accepts it in the new one (the plain object alone matches), and a `Holder`
    // that is a `not` of it accepts the value in the new schema and refuses it in the old one.
    // `unevaluatedProperties` reads which members the object evaluated, and a new member makes it
    // evaluate more: `{"info": {"id": "x", "note": "y"}}` is refused by the old schema (`note` is
    // unevaluated) and accepted by the new one.
    for (holder, says) in [
        (
            json!({ "oneOf": [info.clone(), { "type": "object" }] }),
            "a oneOf beside a plain object",
        ),
        (json!({ "not": info.clone() }), "a not"),
        (
            json!({ "type": "object", "properties": { "info": {
                "$ref": "#/$defs/Info", "unevaluatedProperties": false } } }),
            "an unevaluatedProperties beside the reference",
        ),
        (
            json!({ "allOf": [info], "unevaluatedProperties": false }),
            "an unevaluatedProperties beside an allOf",
        ),
    ] {
        // The `Holder` stands in both schemas, in the earlier one only or in the new one only.
        for (old_holder, new_holder, where_) in [
            (Some(&holder), Some(&holder), "both"),
            (Some(&holder), None, "the earlier only"),
            (None, Some(&holder), "the new only"),
        ] {
            let lines = crate::public_contract::compare(
                &used(&object(false), old_holder),
                &used(&object(true), new_holder),
            )
            .expect("compares");
            assert!(
                lines.contains(&"Info.note added: a member".to_owned()),
                "{says}, in {where_}: {lines:?}"
            );
        }
    }
    let rows = [
        (
            // A new method whose name has a dot is the line `Method#const:a.b added: a variant`.
            json!({ "$schema": DIALECT, "$defs": { "Method": { "oneOf": [{ "const": "a", "type": "string" }] },
                "Method#const:a": object(false) } }),
            json!({ "$schema": DIALECT, "$defs": { "Method": { "oneOf": [{ "const": "a", "type": "string" },
                { "const": "a.b", "type": "string" }] }, "Method#const:a": object(false) } }),
            "Method#const:a.b added: a variant",
        ),
        (
            // A member of a variant is the line `Choice#tag:kind=x.note added: a member`.
            json!({ "$schema": DIALECT, "$defs": { "Choice": { "oneOf": [{ "type": "object",
                "properties": { "kind": { "const": "x" } } }] },
                "Choice#tag:kind=x": object(false) } }),
            json!({ "$schema": DIALECT, "$defs": { "Choice": { "oneOf": [{ "type": "object",
                "properties": { "kind": { "const": "x" }, "note": { "type": "string" } } }] },
                "Choice#tag:kind=x": object(false) } }),
            "Choice#tag:kind=x.note added: a member",
        ),
        (
            // A closed object in a nullable pair, marked at the top: the old schema refuses `note`.
            json!({ "$schema": DIALECT, "$defs": { "Info": { marker: true, "anyOf": [{ "type": "object",
                "properties": { "id": { "type": "string" } }, "additionalProperties": false },
                { "type": "null" }] } } }),
            json!({ "$schema": DIALECT, "$defs": { "Info": { marker: true, "anyOf": [{ "type": "object",
                "properties": { "id": { "type": "string" }, "note": { "type": "string" } },
                "additionalProperties": false }, { "type": "null" }] } } }),
            "Info.note added: a member",
        ),
    ];
    // A marked object that is closed or composed in one schema only is no open plain object there:
    // the old schema refuses `note` when it is closed, and a composed one may restrict it.
    let with_key = |with_member: bool, key: &str, value: Value| {
        let mut definition = object(with_member);
        definition[key] = value;
        definition
    };
    let one_schema_only = [
        (
            with_key(false, "additionalProperties", json!(false)),
            object(true),
        ),
        (
            with_key(false, "allOf", json!([{ "type": "object" }])),
            object(true),
        ),
        (
            object(false),
            with_key(true, "additionalProperties", json!(false)),
        ),
        (
            object(false),
            with_key(true, "allOf", json!([{ "type": "object" }])),
        ),
    ];
    let rows = rows.into_iter().chain(
        one_schema_only.map(|(old, new)| (schema(&old), schema(&new), "Info.note added: a member")),
    );
    for (old, new, line) in rows {
        let lines = crate::public_contract::compare(&old, &new).expect("compares");
        assert!(
            lines.iter().any(|reported| reported.starts_with(line)),
            "{line}: {lines:?}"
        );
    }
}
