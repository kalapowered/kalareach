//! A package declares how its bridge's forwarder reads the application's hook payload. These cases
//! build a whole package directory around the example connector, state the member in its connector
//! table, and run the package check every host, publisher and pipeline runs.

use std::path::{Path, PathBuf};

use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::hook_events::{HookEvents, HookEventsRefusal, HookReport};
use kr_plugin_sdk::schema::package_contract;
use kr_plugin_sdk::validate::{FindingCode, Validated, validate_package_directory};
use kr_plugin_sdk::version::SDK_VERSION;
use serde_json::{Value, json};

const FIXTURE: &str = include_str!("fixtures/hook_events_claude_code.json");

fn example_connector() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugins/valid/example-connector")
}

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("the fixture is JSON")
}

fn place(names: &[&str]) -> Value {
    json!({ "segments": names.iter().map(|name| json!({ "type": "member", "name": name })).collect::<Vec<_>>() })
}

/// The example connector package under `into`, with `sdk_range` as its range, `table` applied to
/// its connector table and, when `forwarder` is true, a command integration that starts the
/// forwarder.
fn package(
    into: &Path,
    sdk_range: &str,
    forwarder: bool,
    table: impl FnOnce(&mut Value),
) -> PathBuf {
    let directory = into.join("package");
    std::fs::create_dir_all(&directory).expect("a directory");
    for name in ["plugin.json", "presentation.json", "connector.json"] {
        std::fs::copy(example_connector().join(name), directory.join(name)).expect("copies");
    }
    let manifest_path = directory.join("plugin.json");
    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("reads")).expect("JSON");
    manifest["sdk_range"] = json!(sdk_range);
    if forwarder {
        manifest["capabilities"]
            .as_array_mut()
            .expect("capabilities")
            .push(json!({
                "capability": "command_integration.launch",
                "reason": "Start the agent with the flags its bridge needs"
            }));
        manifest["command_integration"] = json!({
            "command": "example-agent",
            "flags": ["--example-flag"],
            "variables": [],
            "grant_statement": "Starts the agent in KalaReach sessions with what its bridge needs"
        });
        manifest["match_rules"][0]["executable"]["file_stem"] = json!("example-agent");
    }
    let path = directory.join("connector.json");
    let mut connector: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("reads")).expect("JSON");
    table(&mut connector);
    let bytes = serde_json::to_vec_pretty(&connector).expect("writes");
    std::fs::write(&path, &bytes).expect("writes");
    // The manifest declares the table's digest and size: bring them up to the changed file.
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
    directory
}

fn check(sdk_range: &str, forwarder: bool, table: impl FnOnce(&mut Value)) -> Validated {
    let home = tempfile::tempdir().expect("a directory");
    let directory = package(home.path(), sdk_range, forwarder, table);
    validate_package_directory(&directory)
}

/// A package of SDK 0.1.8 that starts a forwarder and states `events` as its hook events.
fn declaring(events: Value) -> Validated {
    check(">=0.1.8, <0.2.0", true, |table| {
        table["hook_events"] = events;
    })
}

/// The check refuses the package for the refusal's name, as a finding on the connector table, and
/// for no other member of the table.
fn assert_refused_by_name(validated: &Validated, refusal: HookEventsRefusal) {
    let named: Vec<_> = validated
        .report
        .findings
        .iter()
        .filter(|finding| finding.detail.contains(refusal.name()))
        .collect();
    assert!(
        named
            .iter()
            .any(|finding| finding.code == FindingCode::ConnectorTableInvalid),
        "{} is a finding of the connector table: {:?}",
        refusal.name(),
        validated.report.findings
    );
}

/// What the Claude Code map is, with `edit` applied.
fn edited(edit: impl FnOnce(&mut Value)) -> Value {
    let mut value = fixture();
    edit(&mut value);
    value
}

#[test]
fn a_package_may_declare_the_claude_code_map_and_the_check_accepts_it() {
    let validated = declaring(fixture());
    assert!(
        validated.report.findings.is_empty(),
        "{:?}",
        validated.report.findings
    );
    let package = validated.package.expect("a package");
    let events = package
        .connector
        .expect("a table")
        .hook_events
        .expect("the member is read");
    assert_eq!(events, HookEvents::claude_code());
}

#[test]
fn the_default_map_equals_the_fixture_a_package_may_copy() {
    let default = HookEvents::claude_code();
    assert_eq!(
        serde_json::to_value(&default).expect("writes"),
        fixture(),
        "the fixture is the default as JSON"
    );
    let read: HookEvents = serde_json::from_str(FIXTURE).expect("reads");
    assert_eq!(read, default);
    assert_eq!(default.refusals(), Vec::new());
    assert!(
        default
            .events
            .iter()
            .any(|event| event.report == HookReport::SessionStarted
                && event.continued_by.as_deref() == Some("compact"))
    );
}

#[test]
fn a_map_place_with_no_segment_is_refused_by_name() {
    let validated = declaring(edited(|map| map["event"] = json!({ "segments": [] })));
    assert_refused_by_name(&validated, HookEventsRefusal::PlaceEmpty);
}

#[test]
fn a_map_place_deeper_than_three_is_refused_by_name() {
    let validated = declaring(edited(|map| map["thread"] = place(&["a", "b", "c", "d"])));
    assert_refused_by_name(&validated, HookEventsRefusal::PlaceTooDeep);
}

#[test]
fn a_map_place_with_an_index_is_refused_by_name() {
    let validated = declaring(edited(|map| {
        map["event"] = json!({ "segments": [{ "type": "index", "index": 0 }] });
    }));
    assert_refused_by_name(&validated, HookEventsRefusal::PlaceHasIndex);
}

#[test]
fn a_map_member_that_is_empty_is_refused_by_name() {
    let validated = declaring(edited(|map| map["event"] = place(&[""])));
    assert_refused_by_name(&validated, HookEventsRefusal::PlaceMemberBad);
    let long = "m".repeat(65);
    let validated = declaring(edited(|map| map["event"] = place(&[&long])));
    assert_refused_by_name(&validated, HookEventsRefusal::PlaceMemberBad);
}

#[test]
fn a_map_place_that_is_the_start_of_another_is_refused_by_name() {
    let validated = declaring(edited(|map| {
        map["event"] = place(&["hook"]);
        map["thread"] = place(&["hook", "session"]);
    }));
    assert_refused_by_name(&validated, HookEventsRefusal::PlacesOverlap);
    // The contact's input is an object whose member `request_id` is read, so a place that is the
    // input itself is the start of that one.
    let validated = declaring(edited(|map| {
        map["details"]["tool_name"] = place(&["tool_input"]);
    }));
    assert_refused_by_name(&validated, HookEventsRefusal::PlacesOverlap);
    // Two roles that read one member as a value do not overlap.
    let validated = declaring(edited(|map| {
        map["contact"]["agreeing"][2]["place"] = place(&["tool_name"]);
    }));
    assert!(
        validated.report.findings.is_empty(),
        "{:?}",
        validated.report.findings
    );
}

#[test]
fn a_map_with_no_event_is_refused_by_name() {
    let validated = declaring(edited(|map| {
        map["events"] = json!([]);
        map.as_object_mut().expect("an object").remove("contact");
    }));
    assert_refused_by_name(&validated, HookEventsRefusal::NoEvents);
}

#[test]
fn a_map_of_more_than_thirty_two_events_is_refused_by_name() {
    let validated = declaring(edited(|map| {
        map["events"] = Value::Array(
            (0..33)
                .map(|index| json!({ "name": format!("Event{index}"), "report": "notification" }))
                .collect(),
        );
        map.as_object_mut().expect("an object").remove("contact");
        map["details"]["start_source"] = Value::Null;
    }));
    assert_refused_by_name(&validated, HookEventsRefusal::TooManyEvents);
}

#[test]
fn a_map_event_name_that_is_empty_is_refused_by_name() {
    let validated = declaring(edited(|map| map["events"][1]["name"] = json!("")));
    assert_refused_by_name(&validated, HookEventsRefusal::EventNameBad);
    let validated = declaring(edited(|map| map["events"][1]["name"] = json!("Bell\u{7}")));
    assert_refused_by_name(&validated, HookEventsRefusal::EventNameBad);
}

#[test]
fn a_map_with_two_events_of_one_name_is_refused_by_name() {
    let validated = declaring(edited(|map| {
        map["events"][1]["name"] = json!("SessionStart")
    }));
    assert_refused_by_name(&validated, HookEventsRefusal::EventDuplicate);
}

#[test]
fn a_continuation_on_another_report_is_refused_by_name() {
    let validated = declaring(edited(|map| {
        map["events"][1]["continued_by"] = json!("compact");
    }));
    assert_refused_by_name(&validated, HookEventsRefusal::ContinuedByMisplaced);
    let validated = declaring(edited(|map| {
        map["details"]
            .as_object_mut()
            .expect("an object")
            .remove("start_source");
    }));
    assert_refused_by_name(&validated, HookEventsRefusal::ContinuedByMisplaced);
}

#[test]
fn a_contact_template_that_names_another_word_is_refused_by_name() {
    for template in [
        "mcp__{server}__{other}",
        "mcp__{server}",
        "mcp__{tool}",
        "mcp__{server}__{tool}__{server_}",
        "MCP__{server}__{tool}",
        "mcp {server} {tool}",
        "",
    ] {
        let validated = declaring(edited(|map| {
            map["contact"]["tool_name"] = json!(template);
        }));
        assert_refused_by_name(&validated, HookEventsRefusal::ContactTemplateBad);
    }
    let long = format!("{}{{server}}{{tool}}", "a".repeat(60));
    let validated = declaring(edited(|map| map["contact"]["tool_name"] = json!(long)));
    assert_refused_by_name(&validated, HookEventsRefusal::ContactTemplateBad);
}

#[test]
fn a_contact_no_event_can_report_is_refused_by_name() {
    let validated = declaring(edited(|map| {
        map["events"] = json!([{ "name": "SessionEnd", "report": "session_ended" }]);
        map["details"]
            .as_object_mut()
            .expect("an object")
            .remove("start_source");
    }));
    assert_refused_by_name(&validated, HookEventsRefusal::ContactWithoutToolFinished);
}

#[test]
fn a_contact_with_no_tool_name_place_is_refused_by_name() {
    let validated = declaring(edited(|map| {
        map["details"]
            .as_object_mut()
            .expect("an object")
            .remove("tool_name");
    }));
    assert_refused_by_name(&validated, HookEventsRefusal::ContactWithoutToolNamePlace);
}

#[test]
fn a_map_over_eight_kib_is_refused_by_name() {
    // Fifty members that name the contact's server, each a place of three members of sixty-four
    // characters that a JSON writer escapes: every other bound holds, and the value takes well over
    // eight kibibytes.
    let long = |tag: char| format!("{}{tag}", "\"".repeat(62));
    let validated = declaring(edited(|map| {
        map["contact"]["agreeing"] = Value::Array(
            ('a'..='z')
                .chain('A'..='Z')
                .map(|tag| {
                    json!({
                        "place": place(&[&long(tag), &long(tag), &long(tag)]),
                        "names": "server",
                    })
                })
                .collect(),
        );
    }));
    assert_refused_by_name(&validated, HookEventsRefusal::TooLarge);
}

#[test]
fn a_map_in_a_package_that_starts_no_forwarder_is_refused_by_name() {
    let validated = check(">=0.1.8, <0.2.0", false, |table| {
        table["hook_events"] = fixture();
    });
    assert_refused_by_name(&validated, HookEventsRefusal::NoForwarder);
}

#[test]
fn the_arrival_table_lists_hook_events_at_the_sdk_version() {
    assert_eq!(SDK_VERSION, "0.1.9");
    let contract = package_contract();
    let listed: Vec<&Value> = contract["arrivals"]
        .as_array()
        .expect("a table")
        .iter()
        .filter(|entry| entry["member"] == "hook_events")
        .collect();
    assert_eq!(
        listed,
        [&json!({
            "definition": "ConnectorManifest",
            "member": "hook_events",
            "sdk_version": "0.1.8",
        })]
    );
}

#[test]
fn a_package_that_uses_hook_events_needs_an_sdk_range_from_its_arrival() {
    let refused = check(">=0.1.7, <0.2.0", true, |table| {
        table["hook_events"] = fixture();
    });
    assert!(
        refused
            .report
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::ConnectorTableInvalid
                && finding.detail.contains("ConnectorManifest.hook_events")
                && finding.detail.contains("SDK 0.1.8")),
        "{:?}",
        refused.report.findings
    );
    let accepted = check(">=0.1.8, <0.2.0", true, |table| {
        table["hook_events"] = fixture();
    });
    assert!(
        accepted.report.findings.is_empty(),
        "{:?}",
        accepted.report.findings
    );
}

/// A table that declares no map is written with the bytes it had before the member existed: every
/// connector table the repository keeps reads and writes back to the same document.
#[test]
fn a_table_that_declares_no_map_serialises_to_the_bytes_it_had_before() {
    fn tables(under: &Path, found: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(under).expect("a directory").flatten() {
            let path = entry.path();
            if path.is_dir() {
                tables(&path, found);
            } else if path
                .file_name()
                .is_some_and(|name| name == "connector.json")
            {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    tables(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugins"),
        &mut found,
    );
    assert!(found.len() >= 2, "the repository keeps connector tables");
    for path in found {
        let text = std::fs::read_to_string(&path).expect("reads");
        let Ok(table) = serde_json::from_str::<kr_plugin_sdk::connector::ConnectorManifest>(&text)
        else {
            // A table kept to be refused does not read, and is not one that declares a map.
            continue;
        };
        assert!(table.hook_events.is_none());
        let written = serde_json::to_value(&table).expect("writes");
        let original: Value = serde_json::from_str(&text).expect("a document");
        assert_eq!(written, original, "{}", path.display());
        assert!(
            !written.to_string().contains("hook_events"),
            "{}",
            path.display()
        );
    }
}
