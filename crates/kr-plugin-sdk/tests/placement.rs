//! A package declares where its bridge's files are placed. These cases state the member in the
//! connector table of a whole package directory and run the package check every host, publisher
//! and pipeline runs, and check the placement type and its engine directly.

use std::path::{Path, PathBuf};

use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::placement::{Placement, PlacementRefusal, Shape, is_plain_component};
use kr_plugin_sdk::schema::package_contract;
use kr_plugin_sdk::validate::{FindingCode, Validated, validate_package_directory};
use kr_plugin_sdk::version::SDK_VERSION;
use serde_json::{Value, json};

const CLAUDE_FIXTURE: &str = include_str!("fixtures/placement_claude_code.json");
const GEMINI_FIXTURE: &str = include_str!("fixtures/placement_gemini_cli.json");

fn bundled(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../bundled-plugins/targets/packages/kalareach")
        .join(name)
        .join("0.5.0")
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a directory");
    for entry in std::fs::read_dir(from).expect("lists") {
        let entry = entry.expect("an entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("copies");
        }
    }
}

/// The bundled Gemini CLI package under a fresh directory, with `sdk_range` as its range and
/// `table` applied to its connector table, its payload record brought up to the changed file.
fn gemini_package(sdk_range: &str, table: impl FnOnce(&mut Value)) -> Validated {
    let home = tempfile::tempdir().expect("a directory");
    let directory = home.path().join("package");
    copy_tree(&bundled("gemini-cli"), &directory);
    let manifest_path = directory.join("plugin.json");
    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("reads")).expect("JSON");
    manifest["sdk_range"] = json!(sdk_range);
    let path = directory.join("connector.json");
    let mut connector: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("reads")).expect("JSON");
    table(&mut connector);
    let bytes = serde_json::to_vec_pretty(&connector).expect("writes");
    std::fs::write(&path, &bytes).expect("writes");
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
    validate_package_directory(&directory)
}

/// The bundled Gemini CLI package under a fresh directory with the file `relative` holding `bytes`.
fn gemini_package_with_file(relative: &str, bytes: &[u8]) -> Validated {
    let home = tempfile::tempdir().expect("a directory");
    let directory = home.path().join("package");
    copy_tree(&bundled("gemini-cli"), &directory);
    std::fs::write(directory.join(relative), bytes).expect("writes");
    validate_package_directory(&directory)
}

fn claude() -> Value {
    serde_json::from_str(CLAUDE_FIXTURE).expect("the fixture is JSON")
}

fn gemini() -> Value {
    serde_json::from_str(GEMINI_FIXTURE).expect("the fixture is JSON")
}

fn placement(value: &Value) -> Placement {
    serde_json::from_value(value.clone()).expect("a placement")
}

fn refused(placement: &Placement, refusal: PlacementRefusal) {
    assert!(
        placement
            .refusals()
            .iter()
            .any(|found| found.refusal == refusal),
        "{} is not among {:?}",
        refusal.name(),
        placement.refusals()
    );
}

fn refused_with(edit: impl FnOnce(&mut Value), refusal: PlacementRefusal) {
    let mut table = claude();
    edit(&mut table);
    refused(&placement(&table), refusal);
}

fn stated_by_package(placement: &Value) -> Validated {
    gemini_package(">=0.1.9, <0.2.0", |table| {
        table["placement"] = placement.clone();
    })
}

#[test]
fn a_package_may_declare_the_gemini_cli_placement_and_the_check_accepts_it() {
    let validated = stated_by_package(&gemini());
    assert!(
        validated.report.is_valid(),
        "{:?}",
        validated.report.findings
    );
    assert!(validated.package.is_some_and(|package| {
        package
            .connector
            .is_some_and(|table| table.placement.is_some())
    }));
}

#[test]
fn the_default_placements_equal_the_fixtures_a_package_may_copy() {
    assert_eq!(
        serde_json::to_value(Placement::claude_code()).unwrap(),
        claude()
    );
    assert_eq!(
        serde_json::to_value(Placement::gemini_cli()).unwrap(),
        gemini()
    );
    assert!(Placement::claude_code().refusals().is_empty());
    assert!(Placement::gemini_cli().refusals().is_empty());
    assert_eq!(Placement::for_label("Quill CLI"), None);
}

#[test]
fn a_placement_directory_with_a_parent_component_is_refused_by_name() {
    refused_with(
        |table| table["directory"] = json!(["..", ".claude"]),
        PlacementRefusal::DirectoryNotPlain,
    );
    refused_with(
        |table| table["directory"] = json!([".claude", "."]),
        PlacementRefusal::DirectoryNotPlain,
    );
}

#[test]
fn a_placement_directory_that_is_absolute_is_refused_by_name() {
    refused_with(
        |table| table["directory"] = json!(["/etc"]),
        PlacementRefusal::DirectoryNotPlain,
    );
    refused_with(
        |table| table["directory"] = json!(["C:"]),
        PlacementRefusal::DirectoryNotPlain,
    );
}

#[test]
fn a_placement_directory_with_a_separator_is_refused_by_name() {
    refused_with(
        |table| table["directory"] = json!([".claude/skills"]),
        PlacementRefusal::DirectoryNotPlain,
    );
    refused_with(
        |table| table["directory"] = json!(["a\\b"]),
        PlacementRefusal::DirectoryNotPlain,
    );
    refused_with(
        |table| table["directory"] = json!([""]),
        PlacementRefusal::DirectoryNotPlain,
    );
}

#[test]
fn a_placement_directory_deeper_than_three_is_refused_by_name() {
    refused_with(
        |table| table["directory"] = json!(["a", "b", "c", "d"]),
        PlacementRefusal::DirectoryTooDeep,
    );
    refused_with(
        |table| table["directory"] = json!([]),
        PlacementRefusal::DirectoryTooDeep,
    );
}

#[test]
fn a_placement_whose_label_names_a_default_must_declare_its_directory() {
    let mut elsewhere = claude();
    elsewhere["directory"] = json!([".claude-elsewhere"]);
    let elsewhere = placement(&elsewhere);
    assert!(
        elsewhere
            .refusals_for_label("Claude Code")
            .iter()
            .any(|found| found.refusal == PlacementRefusal::DirectoryNotTheLabels)
    );
    let mut area = claude();
    area["area"] = json!("plugins");
    assert!(
        placement(&area)
            .refusals_for_label("Claude Code")
            .iter()
            .any(|found| found.refusal == PlacementRefusal::DirectoryNotTheLabels)
    );
    let mut unchecked = claude();
    unchecked.as_object_mut().unwrap().remove("one_per_name");
    assert!(
        placement(&unchecked)
            .refusals_for_label("Claude Code")
            .iter()
            .any(|found| found.refusal == PlacementRefusal::DirectoryNotTheLabels)
    );
    assert!(
        Placement::claude_code()
            .refusals_for_label("Claude Code")
            .is_empty()
    );
}

#[test]
fn a_placement_in_a_compiled_directory_must_be_under_that_label() {
    let own = Placement::claude_code();
    let found = own.refusals_for_label("Quill CLI");
    assert!(
        found
            .iter()
            .any(|found| found.refusal == PlacementRefusal::DirectoryNotTheLabels),
        "{found:?}"
    );
    let mut quill = claude();
    quill["directory"] = json!([".quill"]);
    assert!(placement(&quill).refusals_for_label("Quill CLI").is_empty());
}

#[test]
fn a_placement_tail_that_is_not_plain_is_refused_by_name() {
    for tail in [
        "../x.json",
        "/x.json",
        "a/b/c/d.json",
        "a\\b.json",
        "",
        "a//b.json",
    ] {
        refused_with(
            |table| table["files"][0]["tail"] = json!(tail),
            PlacementRefusal::TailNotPlain,
        );
    }
}

/// Windows reads a device name as the device whatever extension follows it, in any case, so a
/// component that is one cannot be a folder or a file there: every place a component stands
/// refuses it, and a name that only resembles one stays accepted.
#[test]
fn a_placement_component_that_is_a_windows_device_name_is_refused_by_name() {
    for name in [
        "nul",
        "NUL",
        "con.json",
        "Aux",
        "prn.tar.gz",
        "com1",
        "COM9.txt",
        "com0",
        "lpt1",
        "LPT9.json",
        "nul .txt",
    ] {
        assert!(!is_plain_component(name), "{name:?} is a device name");
        refused_with(
            |table| table["directory"] = json!([name]),
            PlacementRefusal::DirectoryNotPlain,
        );
        refused_with(
            |table| table["area"] = json!(name),
            PlacementRefusal::AreaNotPlain,
        );
        refused_with(
            |table| table["files"][0]["tail"] = json!(name),
            PlacementRefusal::TailNotPlain,
        );
        refused_with(
            |table| table["files"][0]["tail"] = json!(format!("inner/{name}")),
            PlacementRefusal::TailNotPlain,
        );
    }
    for name in [
        "console",
        "com10",
        "com",
        "lpt",
        "lptx.json",
        "nulls.json",
        "auxiliary",
        "a.con",
        ".nul",
        "com1x",
        "my-nul",
    ] {
        assert!(is_plain_component(name), "{name:?} only resembles one");
        let mut table = claude();
        table["directory"] = json!([name]);
        table["area"] = json!(name);
        table["files"][0]["tail"] = json!(format!("{name}/{name}"));
        let component_refusals: Vec<&str> = placement(&table)
            .refusals()
            .iter()
            .filter(|found| {
                matches!(
                    found.refusal,
                    PlacementRefusal::DirectoryNotPlain
                        | PlacementRefusal::AreaNotPlain
                        | PlacementRefusal::TailNotPlain
                )
            })
            .map(|found| found.refusal.name())
            .collect();
        assert_eq!(component_refusals, Vec::<&str>::new(), "{name:?}");
    }
}

/// Windows shell does not keep a name that ends in a dot or a space, so no place of a placement
/// ends in one, and a dot or a space inside a name is not refused.
#[test]
fn a_placement_component_that_ends_in_a_dot_or_a_space_is_refused_by_name() {
    for name in ["plugins.", "plugins ", "a..", "x. ", " plugins"] {
        assert!(!is_plain_component(name), "{name:?} ends or starts badly");
        refused_with(
            |table| table["directory"] = json!([name]),
            PlacementRefusal::DirectoryNotPlain,
        );
        refused_with(
            |table| table["area"] = json!(name),
            PlacementRefusal::AreaNotPlain,
        );
        refused_with(
            |table| table["files"][0]["tail"] = json!(name),
            PlacementRefusal::TailNotPlain,
        );
        refused_with(
            |table| table["files"][0]["tail"] = json!(format!("inner/{name}")),
            PlacementRefusal::TailNotPlain,
        );
    }
    for name in ["my plugins", "a.b", ".hidden", "a. b"] {
        assert!(is_plain_component(name), "{name:?} is plain");
    }
}

#[test]
fn a_placement_with_a_repeated_tail_is_refused_by_name() {
    refused_with(
        |table| table["files"][1]["tail"] = json!(".claude-plugin/plugin.json"),
        PlacementRefusal::TailDuplicate,
    );
}

#[test]
fn a_placement_with_no_file_or_nine_files_is_refused_by_name() {
    refused_with(|table| table["files"] = json!([]), PlacementRefusal::NoFile);
    refused_with(
        |table| {
            let file = table["files"][2].clone();
            let mut files = Vec::new();
            for number in 0..9 {
                let mut next = file.clone();
                next["tail"] = json!(format!("hooks/{number}.json"));
                files.push(next);
            }
            table["files"] = json!(files);
        },
        PlacementRefusal::NoFile,
    );
}

#[test]
fn a_placement_shape_deeper_than_eight_is_refused_by_name() {
    refused_with(
        |table| {
            let mut shape = json!({ "kind": "boolean" });
            for _ in 0..9 {
                shape = json!({ "kind": "array", "items": shape });
            }
            table["files"][0]["shape"] = shape;
        },
        PlacementRefusal::ShapeTooDeep,
    );
}

#[test]
fn a_placement_with_a_command_form_and_no_command_kind_is_refused_by_name() {
    refused_with(
        |table| {
            table["files"] = json!([{
                "tail": ".claude-plugin/plugin.json",
                "shape": table["files"][0]["shape"],
            }]);
        },
        PlacementRefusal::ShapeHasNoCommand,
    );
}

#[test]
fn a_placement_with_a_repeated_shape_member_is_refused_by_name() {
    refused_with(
        |table| {
            let members = table["files"][0]["shape"]["members"]
                .as_array_mut()
                .unwrap();
            let again = members[0].clone();
            members.push(again);
        },
        PlacementRefusal::ShapeMemberDuplicate,
    );
}

#[test]
fn a_placement_with_text_that_names_a_place_is_refused_by_name() {
    for text in ["/etc/passwd", "a\\b", "c:", "~", "$HOME", "`id`", ".", ".."] {
        refused_with(
            |table| {
                table["files"][0]["shape"]["members"][1]["shape"] =
                    json!({ "kind": "exact", "value": text });
            },
            PlacementRefusal::TextNamesAPlace,
        );
        refused_with(
            |table| table["files"][0]["shape"]["members"][1]["name"] = json!(text),
            PlacementRefusal::TextNamesAPlace,
        );
    }
}

#[test]
fn a_name_check_that_names_no_manifest_with_a_directory_name_is_refused_by_name() {
    refused_with(
        |table| table["one_per_name"]["manifest"] = json!("hooks/hooks.json"),
        PlacementRefusal::NameCheckBad,
    );
}

#[test]
fn a_placement_that_declares_an_enabling_key_a_last_file_or_a_path_prefix_is_refused_as_an_unknown_member()
 {
    for (member, value) in [
        (
            "enabling",
            json!(["settings.json", "enabledPlugins.", "@skills-dir"]),
        ),
        ("last", json!(".gemini-extension-install.json")),
    ] {
        let mut table = claude();
        table[member] = value;
        assert!(
            serde_json::from_value::<Placement>(table.clone()).is_err(),
            "{member} is an unknown member"
        );
        let validated = stated_by_package(&table);
        assert!(!validated.report.is_valid());
    }
    let mut prefix = gemini();
    prefix["files"][0]["shape"]["members"][1]["shape"] =
        json!({ "kind": "record_path", "prefix": "/dev/null/" });
    assert!(serde_json::from_value::<Placement>(prefix).is_err());
}

/// The root of a placed file is one JSON object: a shape whose root is any other kind is refused
/// by name, and the two kinds of root a file may have are accepted.
#[test]
fn a_placement_file_whose_root_is_not_an_object_or_a_map_is_refused_by_name() {
    for (what, root) in [
        (
            "an array",
            json!({ "kind": "array", "items": { "kind": "command_handler" } }),
        ),
        ("text", json!({ "kind": "text", "max_bytes": 64 })),
        ("a boolean", json!({ "kind": "boolean" })),
        ("a number", json!({ "kind": "number" })),
        ("exact text", json!({ "kind": "exact", "value": "local" })),
        ("a command handler", json!({ "kind": "command_handler" })),
        ("a directory name", json!({ "kind": "directory_name" })),
        ("a record path", json!({ "kind": "record_path" })),
        ("a server", json!({ "kind": "stdio_server" })),
    ] {
        let mut table = claude();
        table["files"][2]["shape"] = root;
        let found = placement(&table).refusals();
        assert!(
            found
                .iter()
                .any(|error| error.refusal == PlacementRefusal::FileNotAnObject
                    && error.to_string().contains("hooks/hooks.json")),
            "{what}: {found:?}"
        );
    }
    for (what, root) in [
        (
            "an object",
            json!({ "kind": "object", "members": [] }),
        ),
        (
            "a map",
            json!({ "kind": "map", "values": { "kind": "boolean" } }),
        ),
    ] {
        let mut table = claude();
        table["files"][2]["shape"] = root;
        assert!(
            !placement(&table)
                .refusals()
                .iter()
                .any(|error| error.refusal == PlacementRefusal::FileNotAnObject),
            "{what} is a root a file may have"
        );
    }
}

/// The package check reads each file a bridge installs for a repeated member name before any value
/// is made of it, in either order, when the repeat is spelt with an escape and under an object and
/// an array root: a value keeps the last of two, and the host places the bytes.
#[test]
fn a_bridge_file_that_repeats_a_member_name_is_refused_by_the_package_check() {
    let handler = |command: &str, repeat: &str| {
        format!(r#"{{"type": "command", {repeat} "command": "{command}", "timeout": 5}}"#)
    };
    for (what, hooks) in [
        (
            "an object root, the forwarder last",
            format!(
                r#"{{"hooks": {{"SessionStart": [{{"hooks": [{}]}}]}}}}"#,
                handler("{kr_hook} gemini-cli hook", r#""command": "other","#)
            ),
        ),
        (
            "an object root, the forwarder first",
            format!(
                r#"{{"hooks": {{"SessionStart": [{{"hooks": [{}]}}]}}}}"#,
                handler("other", r#""command": "{kr_hook} gemini-cli hook","#)
            ),
        ),
        (
            "an object root, an escaped repeat",
            format!(
                r#"{{"hooks": {{"SessionStart": [{{"hooks": [{}]}}]}}}}"#,
                handler("{kr_hook} gemini-cli hook", r#""comm\u0061nd": "other","#)
            ),
        ),
        (
            "an array root, the forwarder last",
            format!(
                "[{}]",
                handler("{kr_hook} gemini-cli hook", r#""command": "other","#)
            ),
        ),
        (
            "an array root, the forwarder first",
            format!(
                "[{}]",
                handler("other", r#""command": "{kr_hook} gemini-cli hook","#)
            ),
        ),
        (
            "an array root, an escaped repeat",
            format!(
                "[{}]",
                handler("{kr_hook} gemini-cli hook", r#""comm\u0061nd": "other","#)
            ),
        ),
    ] {
        let validated = gemini_package_with_file("bridge/hooks.json", hooks.as_bytes());
        assert!(
            validated.report.findings.iter().any(|finding| {
                finding.code == FindingCode::DuplicateMember
                    && finding.path.as_deref() == Some("bridge/hooks.json")
                    && finding.detail.contains("\"command\"")
            }),
            "{what}: {:?}",
            validated.report.findings
        );
        assert!(!validated.report.is_valid(), "{what}");
    }
}

#[test]
fn a_placement_over_sixteen_kib_is_refused_by_name() {
    refused_with(
        |table| {
            let members: Vec<Value> = (0..400)
                .map(|number| {
                    json!({
                        "name": format!("member{number:04}xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
                        "shape": { "kind": "boolean" },
                    })
                })
                .collect();
            table["files"][0]["shape"]["members"] = json!(members);
        },
        PlacementRefusal::TooLarge,
    );
}

#[test]
fn a_table_that_declares_a_placement_is_refused_by_the_package_check_by_name() {
    let mut table = gemini();
    table["directory"] = json!(["..", ".gemini"]);
    let validated = stated_by_package(&table);
    assert!(validated.report.findings.iter().any(|finding| {
        finding.code == FindingCode::ConnectorTableInvalid
            && finding
                .detail
                .contains(PlacementRefusal::DirectoryNotPlain.name())
    }));
    let mut elsewhere = gemini();
    elsewhere["directory"] = json!([".gemini-elsewhere"]);
    let validated = stated_by_package(&elsewhere);
    assert!(validated.report.findings.iter().any(|finding| {
        finding.code == FindingCode::ConnectorTableInvalid
            && finding
                .detail
                .contains(PlacementRefusal::DirectoryNotTheLabels.name())
    }));
}

#[test]
fn the_arrival_table_lists_placement_at_the_sdk_version() {
    assert_eq!(SDK_VERSION, "0.1.9");
    let contract = package_contract();
    let listed: Vec<&Value> = contract["arrivals"]
        .as_array()
        .expect("a table")
        .iter()
        .filter(|entry| entry["member"] == "placement")
        .collect();
    assert_eq!(
        listed,
        [&json!({
            "definition": "ConnectorManifest",
            "member": "placement",
            "sdk_version": "0.1.9",
        })]
    );
}

#[test]
fn a_package_that_uses_placement_needs_an_sdk_range_from_its_arrival() {
    let refused = gemini_package(">=0.1.8, <0.2.0", |table| {
        table["placement"] = gemini();
    });
    assert!(
        refused.report.findings.iter().any(|finding| {
            finding.code == FindingCode::ConnectorTableInvalid && finding.detail.contains("0.1.9")
        }),
        "{:?}",
        refused.report.findings
    );
    let accepted = gemini_package(">=0.1.9, <0.2.0", |table| {
        table["placement"] = gemini();
    });
    assert!(accepted.report.is_valid(), "{:?}", accepted.report.findings);
}

#[test]
fn the_two_connector_tables_keep_their_bytes_with_no_placement() {
    for name in ["gemini-cli", "claude-code"] {
        let bytes = std::fs::read(bundled(name).join("connector.json")).expect("reads");
        let table: kr_plugin_sdk::connector::ConnectorManifest =
            serde_json::from_slice(&bytes).expect("a table");
        assert!(table.placement.is_none());
        let written = serde_json::to_value(&table).expect("writes");
        assert_eq!(written, serde_json::from_slice::<Value>(&bytes).unwrap());
        assert!(written.get("placement").is_none());
    }
}

/// The six registration files the bundled packages install, each read under its default
/// placement for the folder the package installs into.
fn bundled_files(name: &str, label: &str) -> Vec<(String, Value)> {
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(bundled(name).join("plugin.json")).unwrap()).unwrap();
    assert_eq!(manifest["native_bridge"]["application"], label);
    manifest["native_bridge"]["install"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|step| step["type"] == "install_file")
        .map(|step| {
            let destination = step["destination"].as_str().unwrap();
            let bytes =
                std::fs::read(bundled(name).join(step["source"].as_str().unwrap())).unwrap();
            (
                destination.to_owned(),
                serde_json::from_slice(&bytes).unwrap(),
            )
        })
        .collect()
}

#[test]
fn the_default_placements_accept_the_bundled_registration_files() {
    for (name, label) in [("claude-code", "Claude Code"), ("gemini-cli", "Gemini CLI")] {
        let placement = Placement::for_label(label).expect("a default");
        let files = bundled_files(name, label);
        assert_eq!(files.len(), 3);
        for (destination, value) in files {
            let rest = destination
                .strip_prefix(&format!("{}/", placement.area))
                .unwrap();
            let (folder, tail) = rest.split_once('/').unwrap();
            placement
                .check_file(tail, folder, &value)
                .unwrap_or_else(|why| panic!("{destination}: {why}"));
        }
    }
}

#[test]
fn a_registration_string_that_names_a_place_is_refused_whatever_the_shape() {
    let placement = Placement::gemini_cli();
    let (_, hooks) = bundled_files("gemini-cli", "Gemini CLI")
        .into_iter()
        .find(|(destination, _)| destination.ends_with("hooks/hooks.json"))
        .unwrap();
    let handler = |value: &Value| value["hooks"]["SessionStart"][0]["hooks"][0].clone();
    assert!(handler(&hooks).is_object());
    for text in ["/", "\\", ":", "~", "$", "`", ".", ".."] {
        let mut in_a_value = hooks.clone();
        in_a_value["hooks"]["SessionStart"][0]["matcher"] = json!(format!("a{text}b"));
        let mut in_a_name = hooks.clone();
        in_a_name["hooks"]["SessionStart"][0]["hooks"][0]["name"] = json!(format!("a{text}b"));
        let mut in_a_key = hooks.clone();
        let events = in_a_key["hooks"].as_object_mut().unwrap();
        let group = events.remove("SessionStart").unwrap();
        events.insert(format!("Event{text}"), group);
        let mut lone = hooks.clone();
        lone["hooks"]["SessionStart"][0]["matcher"] = json!(text);
        let mut cases = vec![in_a_value, in_a_name, in_a_key];
        if text == "." || text == ".." {
            cases = vec![lone];
        }
        for value in cases {
            assert!(
                placement
                    .check_file("hooks/hooks.json", "kalareach", &value)
                    .is_err(),
                "{text:?} passed in {value}"
            );
        }
    }
}

#[test]
fn a_string_like_a_dot_in_a_longer_name_is_not_a_place() {
    let placement = Placement::gemini_cli();
    let (_, hooks) = bundled_files("gemini-cli", "Gemini CLI")
        .into_iter()
        .find(|(destination, _)| destination.ends_with("hooks/hooks.json"))
        .unwrap();
    let mut value = hooks;
    value["hooks"]["SessionStart"][0]["matcher"] = json!(".*");
    placement
        .check_file("hooks/hooks.json", "kalareach", &value)
        .expect("a pattern with a dot in it is not a lone dot");
}

#[test]
fn the_record_path_is_the_one_text_the_walk_lets_through() {
    let placement = Placement::gemini_cli();
    let record = json!({ "type": "local", "source": "/dev/null/kalareach" });
    placement
        .check_file(".gemini-extension-install.json", "kalareach", &record)
        .expect("the record path");
    let other = json!({ "type": "local", "source": "/dev/null/other" });
    assert!(
        placement
            .check_file(".gemini-extension-install.json", "kalareach", &other)
            .is_err()
    );
    let (_, mut manifest) = bundled_files("gemini-cli", "Gemini CLI")
        .into_iter()
        .find(|(destination, _)| destination.ends_with("gemini-extension.json"))
        .unwrap();
    manifest["description"] = json!("/dev/null/kalareach");
    assert!(
        placement
            .check_file("gemini-extension.json", "kalareach", &manifest)
            .is_err()
    );
    assert!(matches!(
        placement.shape_of(".gemini-extension-install.json"),
        Some(shape @ Shape::Object { .. }) if shape.holds_record_path()
    ));
}

fn quill_bridge(label: &str) -> kr_plugin_sdk::plugin::NativeBridge {
    let mut bridge: Value = serde_json::from_slice(
        &std::fs::read(bundled("gemini-cli").join("plugin.json")).expect("reads"),
    )
    .expect("JSON");
    let mut bridge = bridge["native_bridge"].take();
    bridge["application"] = json!(label);
    let step = |destination: &str, digest: &str| {
        json!({
            "type": "install_file",
            "source": "bridge/x.json",
            "destination": destination,
            "digest": digest,
        })
    };
    let digest = "ed5b5291f2e39bf679e945135210c5aee7863b8b8dbaa049dd53598507f172cb";
    bridge["install"] = json!([
        step("plugins/quill-bridge/plugin.json", digest),
        step("plugins/quill-bridge/hooks/hooks.json", digest),
    ]);
    bridge["remove"] = json!([
        { "type": "remove_file", "destination": "plugins/quill-bridge/hooks/hooks.json", "digest": digest },
        { "type": "remove_file", "destination": "plugins/quill-bridge/plugin.json", "digest": digest },
    ]);
    serde_json::from_value(bridge).expect("a recipe")
}

fn quill_placement() -> Placement {
    let mut table = claude();
    table["directory"] = json!([".quill"]);
    table["area"] = json!("plugins");
    table["files"] = json!([
        { "tail": "plugin.json", "shape": claude()["files"][0]["shape"] },
        { "tail": "hooks/hooks.json", "shape": claude()["files"][2]["shape"] },
    ]);
    table["one_per_name"]["manifest"] = json!("plugin.json");
    placement(&table)
}

#[test]
fn the_host_states_what_it_reads_of_a_placement_in_its_own_words() {
    let placement = quill_placement();
    assert!(
        placement.refusals().is_empty(),
        "{:?}",
        placement.refusals()
    );
    let text = placement
        .statement(&quill_bridge("Quill CLI"))
        .expect("a reading");
    assert_eq!(
        text,
        "This package places files for \"Quill CLI\" in a folder it chose: \
         .quill/plugins/quill-bridge/ under your home folder, files plugin.json, hooks/hooks.json. \
         \"Quill CLI\", or any other program that reads that folder, can run what the files hold, \
         as you, with your permissions and outside the plugin sandbox. The host places these \
         files only after it has checked that each is JSON with no repeated member name, that \
         every entry named command in them starts the KalaReach forwarder by its path, and that \
         no other name or text in them holds a slash, a backslash, a colon, a tilde, a dollar \
         sign or a backtick or is a lone dot or two dots. The host does not check what \
         \"Quill CLI\", or another program, does with the other settings in these files, and a \
         plain file name in them can be read by a program as a path. Removing the package takes \
         out only what this host placed; a file that has changed since stays in place, and the \
         host reports what it cannot remove."
    );
}

#[test]
fn an_application_label_that_is_not_plain_is_refused_for_the_statement() {
    for label in ["Quill \"CLI\"", "Quill/CLI"] {
        let found = quill_placement().statement(&quill_bridge(label));
        assert!(
            found.is_err_and(|error| error.refusal == PlacementRefusal::ApplicationNotPlain),
            "{label:?}"
        );
    }
}

#[test]
fn a_publishers_words_holding_the_placement_label_are_refused() {
    let validated = gemini_package(">=0.1.9, <0.2.0", |_| {});
    assert!(
        validated.report.is_valid(),
        "{:?}",
        validated.report.findings
    );
    let home = tempfile::tempdir().expect("a directory");
    let directory = home.path().join("package");
    copy_tree(&bundled("gemini-cli"), &directory);
    let manifest_path = directory.join("plugin.json");
    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("reads")).expect("JSON");
    manifest["native_bridge"]["grant_statement"] = json!(format!(
        "Harmless. {} Reads nothing.",
        kr_protocol::confirmation::PLACEMENT_STATEMENT_LABEL
    ));
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let refused = validate_package_directory(&directory);
    assert!(
        refused.report.findings.iter().any(|finding| {
            finding.code == FindingCode::BridgeRecipeInvalid
                && finding
                    .detail
                    .contains("before its own reading of a placement")
        }),
        "{:?}",
        refused.report.findings
    );
}

#[test]
fn the_statement_bound_is_the_sum_of_the_contract_limits() {
    use kr_protocol::confirmation::{INTEGRATION_STATEMENT_LABEL, STATEMENT_CHARS};
    assert_eq!(
        STATEMENT_CHARS,
        kr_plugin_sdk::text::Summary::LIMIT
            + 1
            + INTEGRATION_STATEMENT_LABEL.len()
            + 1
            + kr_plugin_sdk::integration::MAX_STATEMENT_CHARS,
        "today's sum"
    );
    assert_eq!(STATEMENT_CHARS, 5054);
}

/// The longest reading `statement` can return is the bound: the one label whose reading holds a
/// key sentence, with every field at its largest, equals it, and the longest reading of any other
/// label is shorter.
#[test]
fn the_longest_reading_of_a_placement_is_the_bound() {
    let component = "n".repeat(64);
    let mut table = claude();
    table["directory"] = json!([component, component, component]);
    table["area"] = json!(component);
    let shape = claude()["files"][2]["shape"].clone();
    let tails: Vec<Value> = (0..8)
        .map(|number| {
            let tail = format!("{}/{}/{number:0>64}", "t".repeat(64), "u".repeat(64));
            let shape = if number == 0 {
                json!({ "kind": "object", "members": [
                    { "name": "source", "required": true, "shape": { "kind": "record_path" } }] })
            } else {
                shape.clone()
            };
            json!({ "tail": tail, "shape": shape })
        })
        .collect();
    table["files"] = json!(tails);
    table.as_object_mut().unwrap().remove("one_per_name");
    let placement = placement(&table);
    let folder = "f".repeat(128);
    let recipe = |label: &str, key: bool| {
        let mut bridge = serde_json::to_value(quill_bridge(label)).expect("a value");
        let mut steps = vec![json!({
            "type": "install_file", "source": "bridge/x.json",
            "digest": "ed5b5291f2e39bf679e945135210c5aee7863b8b8dbaa049dd53598507f172cb",
            "destination": format!("{component}/{folder}/{}", tails[0]["tail"].as_str().unwrap()),
        })];
        if key {
            steps.push(json!({
                "type": "add_configuration_key", "file": "settings.json",
                "key": format!("enabledPlugins.{folder}@skills-dir"), "value": "true"
            }));
        }
        bridge["install"] = json!(steps);
        serde_json::from_value::<kr_plugin_sdk::plugin::NativeBridge>(bridge).expect("a recipe")
    };
    let longest = placement
        .statement(&recipe("Claude Code", true))
        .expect("the longest reading is within the bound");
    assert!(longest.contains("It also sets enabledPlugins."), "the key sentence is in it");
    assert_eq!(
        longest.chars().count(),
        kr_plugin_sdk::placement::MAX_PLACEMENT_STATEMENT_CHARS,
        "the bound is the longest reading"
    );
    let other = placement
        .statement(&recipe(&"A".repeat(64), false))
        .expect("a reading with no key sentence");
    assert!(
        other.chars().count() < kr_plugin_sdk::placement::MAX_PLACEMENT_STATEMENT_CHARS,
        "a label with no key sentence reads shorter: {}",
        other.chars().count()
    );
}

/// A Claude Code recipe that installs the hooks file of the plugin folder `kalareach-channels` and
/// adds `step`, where one is given.
fn claude_recipe(label: &str, step: Option<Value>) -> kr_plugin_sdk::plugin::NativeBridge {
    let mut bridge = serde_json::to_value(quill_bridge(label)).expect("a value");
    let mut steps = vec![json!({
        "type": "install_file", "source": "bridge/x.json",
        "digest": "ed5b5291f2e39bf679e945135210c5aee7863b8b8dbaa049dd53598507f172cb",
        "destination": "skills/kalareach-channels/hooks/hooks.json",
    })];
    steps.extend(step);
    bridge["install"] = json!(steps);
    serde_json::from_value(bridge).expect("a recipe")
}

fn key_step(file: &str, key: &str, value: &str) -> Value {
    json!({ "type": "add_configuration_key", "file": file, "key": key, "value": value })
}

/// The host's reading quotes one key, the one the label's application reads for the plugin's
/// folder, in words the host writes; a recipe with no key step has no key sentence.
#[test]
fn the_host_writes_the_labels_one_enabling_key_and_nothing_a_recipe_says() {
    let placement = Placement::claude_code();
    let with = placement
        .statement(&claude_recipe(
            "Claude Code",
            Some(key_step(
                "settings.json",
                "enabledPlugins.kalareach-channels@skills-dir",
                "true",
            )),
        ))
        .expect("a reading");
    assert!(
        with.contains(
            "It also sets enabledPlugins.kalareach-channels@skills-dir to true in \
             .claude/settings.json, and keeps your other settings in that file. "
        ),
        "{with}"
    );
    assert!(with.contains("takes out only what this host placed and the key it set;"));
    let without = placement
        .statement(&claude_recipe("Claude Code", None))
        .expect("a reading");
    assert!(!without.contains("It also sets"), "{without}");
}

/// Every configuration key step but the label's one enabling key is refused by name before a
/// statement is made, and the refusal quotes nothing the recipe says: a free sentence, the host's
/// own labels and a value, a file or a folder that is not the label's.
#[test]
fn a_key_that_is_not_the_labels_one_is_refused_before_a_statement_is_made() {
    use kr_protocol::confirmation::{INTEGRATION_STATEMENT_LABEL, PLACEMENT_STATEMENT_LABEL};
    let exact = "enabledPlugins.kalareach-channels@skills-dir";
    let integration = format!("x {INTEGRATION_STATEMENT_LABEL} Runs nothing.");
    let placement_label = format!("x {PLACEMENT_STATEMENT_LABEL} Reads nothing.");
    let cases: Vec<(&str, &str, Option<Value>)> = vec![
        ("a free sentence", "Claude Code", Some(key_step("settings.json", "Runs nothing.", "true"))),
        ("the integration label", "Claude Code", Some(key_step("settings.json", &integration, "true"))),
        ("the placement label", "Claude Code", Some(key_step("settings.json", &placement_label, "true"))),
        ("another plugin's folder", "Claude Code", Some(key_step("settings.json", "enabledPlugins.other@skills-dir", "true"))),
        ("another file", "Claude Code", Some(key_step("other.json", exact, "true"))),
        ("another value", "Claude Code", Some(key_step("settings.json", exact, "false"))),
        ("a value with a space", "Claude Code", Some(key_step("settings.json", exact, "true "))),
        ("another label", "Gemini CLI", Some(key_step("settings.json", exact, "true"))),
    ];
    for (what, label, step) in cases {
        let found = Placement::claude_code().statement(&claude_recipe(label, step));
        let error = found.expect_err(what);
        assert_eq!(error.refusal, PlacementRefusal::KeyNotTheLabels, "{what}");
        assert!(
            !error.to_string().contains("Runs nothing") && !error.to_string().contains("Reads nothing"),
            "{what}: the refusal quotes the recipe: {error}"
        );
    }
    // A key with no file of the plugin's folder beside it has no folder to enable.
    let mut bridge = serde_json::to_value(claude_recipe("Claude Code", None)).expect("a value");
    bridge["install"] = json!([key_step("settings.json", exact, "true")]);
    let bridge: kr_plugin_sdk::plugin::NativeBridge = serde_json::from_value(bridge).expect("a recipe");
    let error = Placement::claude_code().statement(&bridge).expect_err("no folder");
    assert_eq!(error.refusal, PlacementRefusal::KeyNotTheLabels);
}

/// The bundled package `name` under a fresh directory with an SDK range that holds the arrival of
/// a placement, `manifest` applied to its manifest and `table` to its connector table, the table's
/// payload record brought up to the changed file.
fn package_edited(
    name: &str,
    manifest: impl FnOnce(&mut Value),
    table: impl FnOnce(&mut Value),
) -> Validated {
    let home = tempfile::tempdir().expect("a directory");
    let directory = home.path().join("package");
    copy_tree(&bundled(name), &directory);
    let manifest_path = directory.join("plugin.json");
    let mut plugin: Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("reads")).expect("JSON");
    plugin["sdk_range"] = json!(">=0.1.9, <0.2.0");
    manifest(&mut plugin);
    let path = directory.join("connector.json");
    let mut connector: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("reads")).expect("JSON");
    table(&mut connector);
    let bytes = serde_json::to_vec_pretty(&connector).expect("writes");
    std::fs::write(&path, &bytes).expect("writes");
    let record = plugin["payloads"]
        .as_array_mut()
        .expect("payloads")
        .iter_mut()
        .find(|payload| payload["path"] == "connector.json")
        .expect("the connector payload");
    record["digest"] = json!(PayloadDigest::of(&bytes).to_string());
    record["size_bytes"] = json!(bytes.len().to_string());
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&plugin).expect("writes"))
        .expect("writes");
    validate_package_directory(&directory)
}

/// The package check refuses a key the label's application does not read, for a package that
/// declares its layout and for one that does not, once and by name; the unedited packages are
/// accepted.
#[test]
fn the_package_check_refuses_every_key_but_the_labels_one() {
    use kr_protocol::confirmation::INTEGRATION_STATEMENT_LABEL;
    let named = |validated: &Validated| {
        validated
            .report
            .findings
            .iter()
            .filter(|finding| {
                finding.code == FindingCode::BridgeRecipeInvalid
                    && finding.detail.contains(PlacementRefusal::KeyNotTheLabels.name())
            })
            .count()
    };
    let control = package_edited("claude-code", |_| {}, |_| {});
    assert_eq!(named(&control), 0, "{:?}", control.report.findings);
    let claude_table = |table: &mut Value| table["placement"] = claude();
    let words = format!("x {INTEGRATION_STATEMENT_LABEL} Runs nothing.");
    for (what, key) in [
        ("another folder", "enabledPlugins.other@skills-dir".to_owned()),
        ("a free sentence", "Runs nothing.".to_owned()),
        ("the integration label", words),
    ] {
        let edit = |manifest: &mut Value| {
            manifest["native_bridge"]["install"][3]["key"] = json!(key);
        };
        let undeclared = package_edited("claude-code", edit, |_| {});
        assert_eq!(named(&undeclared), 1, "{what}, no declaration: {:?}", undeclared.report.findings);
        assert!(!undeclared.report.is_valid(), "{what}");
        let declared = package_edited("claude-code", edit, claude_table);
        assert_eq!(named(&declared), 1, "{what}, declared: {:?}", declared.report.findings);
        assert!(!declared.report.is_valid(), "{what}");
    }
    // A label with no key of its own adds none.
    let gemini = package_edited(
        "gemini-cli",
        |manifest| {
            let install = manifest["native_bridge"]["install"].as_array_mut().expect("steps");
            install.push(key_step("settings.json", "enabledPlugins.kalareach@skills-dir", "true"));
        },
        |_| {},
    );
    assert_eq!(named(&gemini), 1, "{:?}", gemini.report.findings);
}

/// The package check reads every file a recipe installs: a file it did not keep, because other
/// files of the package filled its cache first, is refused and not skipped, and the same package
/// with fewer other files, where the check keeps it, is read.
#[test]
fn a_bridge_file_the_check_did_not_keep_is_refused() {
    let unread = |pads: usize| {
        let home = tempfile::tempdir().expect("a directory");
        let directory = home.path().join("package");
        copy_tree(&bundled("gemini-cli"), &directory);
        // The cache holds 8 MiB: the other root file of the package and the pads fill it to the
        // byte, in whatever order they are read, so no file of a folder below it is kept.
        let readme = std::fs::metadata(directory.join("README.md")).expect("a file").len() as usize;
        for number in 0..pads {
            let size = if number + 1 == pads { (1 << 20) - readme } else { 1 << 20 };
            std::fs::write(directory.join(format!("pad-{number}.bin")), vec![0_u8; size])
                .expect("writes");
        }
        validate_package_directory(&directory)
            .report
            .findings
            .iter()
            .filter(|finding| {
                finding.code == FindingCode::BridgeRecipeInvalid
                    && finding.path.as_deref() == Some("bridge/hooks.json")
                    && finding.detail.contains("was not read whole")
            })
            .count()
    };
    assert_eq!(unread(0), 0, "the control keeps every bridge file");
    assert_eq!(unread(8), 1, "eight other files fill the cache before the bridge's");
}

/// The package check composes the host's whole statement, the publisher's words, the reading of
/// the placement and the reading of the command integration, and holds it to the one limit an
/// owner is shown whole: the longest that fits is accepted, and one character more is refused
/// though each part is within its own limit.
#[test]
fn the_package_check_holds_the_whole_statement_to_the_shared_limit() {
    use kr_protocol::confirmation::{STATEMENT_CHARS, install_statement};
    let base: Value = serde_json::from_slice(
        &std::fs::read(bundled("claude-code").join("plugin.json")).expect("reads"),
    )
    .expect("JSON");
    let with_filler = |length: usize| {
        let mut manifest = base.clone();
        manifest["command_integration"]["flags"]
            .as_array_mut()
            .expect("flags")
            .push(json!("x".repeat(length)));
        manifest
    };
    let parts = |manifest: &Value| {
        let bridge: kr_plugin_sdk::plugin::NativeBridge =
            serde_json::from_value(manifest["native_bridge"].clone()).expect("a recipe");
        let integration: kr_plugin_sdk::integration::CommandIntegration =
            serde_json::from_value(manifest["command_integration"].clone()).expect("an integration");
        let reading = Placement::claude_code().statement(&bridge).expect("a reading");
        let words = bridge.grant_statement.as_str().to_owned();
        (words, reading, integration.statement())
    };
    let composed = |manifest: &Value| {
        let (words, reading, integration) = parts(manifest);
        install_statement(Some(&words), Some(&reading), Some(&integration))
            .expect("a statement")
            .chars()
            .count()
    };
    let exact = 1 + (STATEMENT_CHARS - composed(&with_filler(1)));
    assert_eq!(composed(&with_filler(exact)), STATEMENT_CHARS, "the longest that fits");
    let (words, reading, integration) = parts(&with_filler(exact + 1));
    assert!(words.chars().count() <= kr_plugin_sdk::text::Summary::LIMIT);
    assert!(reading.chars().count() <= kr_plugin_sdk::placement::MAX_PLACEMENT_STATEMENT_CHARS);
    assert!(integration.chars().count() <= kr_plugin_sdk::integration::MAX_STATEMENT_CHARS);

    let whole = |length: usize| {
        let validated = package_edited(
            "claude-code",
            |manifest| *manifest = with_filler(length),
            |table| table["placement"] = claude(),
        );
        validated
            .report
            .findings
            .iter()
            .filter(|finding| finding.detail.contains("whole statement"))
            .map(|finding| finding.detail.clone())
            .collect::<Vec<_>>()
    };
    assert!(whole(exact).is_empty(), "the longest that fits is accepted: {:?}", whole(exact));
    let over = whole(exact + 1);
    assert_eq!(over.len(), 1, "one character more is refused: {over:?}");
    assert!(over[0].contains("5055 characters"), "{over:?}");
}

/// The plugin documentation names the placement declaration, each floor the host holds before it
/// places a file, and what it does not check or place: each by its own words, in the section that
/// describes the declaration and in the SDK page that dates it.
#[test]
fn the_plugin_documentation_names_the_placement_declaration_and_what_is_not_placed() {
    let docs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/plugins");
    let readme = std::fs::read_to_string(docs.join("README.md")).expect("the plugin reference");
    let section = readme
        .split("### Placement")
        .nth(1)
        .and_then(|rest| rest.split("\n#").next())
        .expect("the reference has a Placement section");
    for (what, words) in [
        ("the member", "`placement` member of its connector table"),
        (
            "plain components",
            "one to three plain components under the account's home",
        ),
        (
            "a Windows device name",
            "not a name Windows opens as a device",
        ),
        ("no link", "follows no link in it"),
        ("the default's link", "a person may keep as a link"),
        (
            "a copy of a default",
            "package that copies a compiled default's layout",
        ),
        (
            "another label's directory",
            "the directory of another label's default is refused",
        ),
        (
            "a folder the host makes",
            "placed only into a folder the host makes",
        ),
        ("no repeated member", "JSON with no repeated member name"),
        (
            "the forwarder by its path",
            "every member named `command` starts the forwarder",
        ),
        ("the placeholder", "by its placeholder"),
        (
            "text that names a place",
            "a slash, a backslash, a colon, a tilde, a dollar sign or a backtick",
        ),
        (
            "the residual",
            "It does not check what the application does with the members that remain",
        ),
        ("the label", "The host's exact reading of the placement:"),
        ("the range", "\">=0.1.9, <0.2.0\""),
        ("no fallback", "never the application's own layout"),
        (
            "code is not placed",
            "a placement of code waits on a ruling of its own",
        ),
    ] {
        assert!(
            section.contains(words),
            "the Placement section does not say {what}: {words}"
        );
    }
    let sdk = std::fs::read_to_string(docs.join("sdk.md")).expect("the SDK page");
    assert!(
        sdk.contains("The `placement` member of a connector table is in version 0.1.9."),
        "the SDK page dates the member"
    );
}
