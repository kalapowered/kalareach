//! A package's skill target is held to rules of its own: a word, plain places below the home or
//! the project folder, a format that agrees with its file name, and the capability that the owner
//! confirms on every release. Each refusal is named, and none hides another.

use std::path::{Path, PathBuf};

use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::skill_target::{
    COMPILED_WORDS, DocumentFormat, SkillConfiguration, SkillLocation, SkillTarget, problems,
};
use kr_plugin_sdk::validate::validate_package_directory;
use serde_json::{Value, json};

fn example_connector() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugins/valid/example-connector")
}

/// A copy of the example connector under `into` that declares `skill_target` in its table, with
/// the capability requested or not, and its manifest's digest of the table brought up to date.
fn package(
    into: &Path,
    skill_target: Value,
    requests_the_capability: bool,
    table: impl FnOnce(&mut Value),
) -> PathBuf {
    let directory = into.join("package");
    std::fs::create_dir_all(&directory).expect("a directory");
    for name in ["plugin.json", "presentation.json", "connector.json"] {
        std::fs::copy(example_connector().join(name), directory.join(name)).expect("copies");
    }
    let path = directory.join("connector.json");
    let mut connector: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("reads")).expect("JSON");
    connector["skill_target"] = skill_target;
    table(&mut connector);
    let bytes = serde_json::to_vec_pretty(&connector).expect("writes");
    std::fs::write(&path, &bytes).expect("writes");
    let manifest_path = directory.join("plugin.json");
    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("reads")).expect("JSON");
    manifest["sdk_range"] = json!(">=0.1.11, <0.2.0");
    if requests_the_capability {
        manifest["capabilities"]
            .as_array_mut()
            .expect("capabilities")
            .push(json!({
                "capability": "skill_target.install",
                "reason": "Install the contact skill for the agent this package names"
            }));
    }
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

/// A declaration that is right: the word `amp`, a user location with a document and a deadline, a
/// project location with the skills only.
fn amp() -> Value {
    json!({
        "word": "amp",
        "user": {
            "skills": [".amp", "skills"],
            "configuration": {
                "path": [".amp", "settings.json"],
                "format": "json_command_args",
                "shared": false,
                "deadline": { "field": "timeout", "unit": "seconds" }
            }
        },
        "project": { "skills": [".amp", "skills"] }
    })
}

/// Every finding of the package check of a package declaring `target`, as its text.
fn findings(target: Value, requests_the_capability: bool) -> Vec<String> {
    let home = tempfile::tempdir().expect("a directory");
    let directory = package(home.path(), target, requests_the_capability, |_| {});
    validate_package_directory(&directory)
        .report
        .findings
        .iter()
        .map(|finding| finding.detail.clone())
        .collect()
}

fn refused_by(target: &Value, name: &str) -> bool {
    findings(target.clone(), true)
        .iter()
        .any(|detail| detail.contains(&format!("skill_target.{name}")))
}

fn with(edit: impl FnOnce(&mut Value)) -> Value {
    let mut target = amp();
    edit(&mut target);
    target
}

/// K1: a declaration that is right validates for a release whose range starts at the arrival.
#[test]
fn a_declared_skill_target_validates_when_the_range_starts_at_the_arrival() {
    let found = findings(amp(), true);
    assert!(found.is_empty(), "{found:?}");
}

/// K2: a word the host compiles in is refused by name.
#[test]
fn a_skill_target_naming_a_compiled_word_is_refused_by_name() {
    for word in COMPILED_WORDS {
        assert!(
            refused_by(
                &with(|target| target["word"] = json!(word)),
                "word_compiled"
            ),
            "{word}"
        );
    }
}

/// K3: a word outside the grammar is refused by name, and so are the words that end as a record
/// name does.
#[test]
fn a_skill_target_word_outside_the_grammar_is_refused_by_name() {
    let long = "a".repeat(33);
    for word in [
        "Amp",
        "aMp",
        "a b",
        "a/b",
        "../x",
        "amp_",
        "",
        long.as_str(),
    ] {
        assert!(
            refused_by(&with(|target| target["word"] = json!(word)), "word_shape"),
            "{word:?}"
        );
    }
    for word in ["amp-user", "amp-project", "amp-0123456789abcdef"] {
        assert!(
            refused_by(
                &with(|target| target["word"] = json!(word)),
                "word_ambiguous_with_a_record"
            ),
            "{word}"
        );
    }
}

/// K4: a place that is not plain is refused by the name of what is wrong with it.
#[test]
fn a_skill_target_place_that_is_not_plain_is_refused_by_name() {
    let long = format!(".{}", "a".repeat(64));
    let cases: [(Value, &str); 11] = [
        (json!([".amp", ".."]), "component_not_plain"),
        (json!([".amp", "a/b"]), "component_not_plain"),
        (json!([".amp", "C:"]), "component_not_plain"),
        (json!([".amp", "a\u{7}b"]), "component_not_plain"),
        (json!([".amp", long]), "component_too_long"),
        (json!([".a", "b", "c", "d"]), "too_deep"),
        (json!(["amp", "skills"]), "not_hidden_first"),
        (json!([".amp", "CON"]), "component_reserved_on_windows"),
        (json!([".amp", "NUL.json"]), "component_reserved_on_windows"),
        (json!([".amp", "COM1"]), "component_reserved_on_windows"),
        (json!([".amp", "skills."]), "component_ends_in_dot"),
    ];
    for (components, name) in cases {
        let target = with(|target| target["user"]["skills"] = components.clone());
        assert!(refused_by(&target, name), "{components}: {name}");
    }
}

/// K5: the skills folder and the configuration path may not be one place or one inside the other,
/// whatever the case of their letters.
#[test]
fn a_skill_target_whose_places_overlap_is_refused_by_name() {
    for (skills, path) in [
        (json!([".amp", "x.json"]), json!([".amp", "x.json"])),
        (json!([".amp"]), json!([".amp", "x.json"])),
        (json!([".amp", "x.json"]), json!([".amp"])),
        (json!([".amp", "x.json"]), json!([".AMP", "X.JSON"])),
    ] {
        let target = with(|target| {
            target["user"]["skills"] = skills.clone();
            target["user"]["configuration"]["path"] = path.clone();
        });
        assert!(refused_by(&target, "places_overlap"), "{skills} and {path}");
    }
}

/// K6: the format agrees with the file name's suffix, and a format word the SDK does not have is
/// refused by the table's own reading.
#[test]
fn a_skill_target_format_that_disagrees_with_its_file_name_is_refused_by_name() {
    for (format, name, agrees) in [
        ("codex_toml", "settings.json", false),
        ("codex_toml", "config.toml", true),
        ("json_command_args", "config.toml", false),
        ("json_command_args", "settings.json", true),
        ("json_local_command_list", "config.toml", false),
        ("json_local_command_list", "opencode.json", true),
    ] {
        let target = with(|target| {
            target["user"]["configuration"]["format"] = json!(format);
            target["user"]["configuration"]["path"] = json!([".amp", name]);
            target["user"]["configuration"]["deadline"] = Value::Null;
            target["user"]["configuration"]
                .as_object_mut()
                .expect("an object")
                .remove("deadline");
        });
        assert_eq!(
            refused_by(&target, "format_disagrees_with_name"),
            !agrees,
            "{format} at {name}"
        );
    }
    let unknown = with(|target| target["user"]["configuration"]["format"] = json!("xml"));
    let found = findings(unknown, true);
    assert!(
        found
            .iter()
            .any(|detail| detail.contains("unknown variant `xml`")),
        "{found:?}"
    );
}

/// K7: a deadline is refused on a shared document, in the command-list form and under a member name
/// that the entry holds already.
#[test]
fn a_deadline_on_a_shared_document_or_a_command_list_or_with_a_field_that_names_an_entry_member_is_refused_by_name()
 {
    let shared = with(|target| target["user"]["configuration"]["shared"] = json!(true));
    assert!(refused_by(&shared, "shared_with_deadline"));
    let list = with(|target| {
        target["user"]["configuration"]["format"] = json!("json_local_command_list");
    });
    assert!(refused_by(&list, "deadline_with_command_list"));
    for field in ["type", "command", "args", "env", "enabled", "Command"] {
        let target = with(|target| {
            target["user"]["configuration"]["deadline"]["field"] = json!(field);
        });
        assert!(refused_by(&target, "deadline_field_collides"), "{field}");
    }
    for field in ["", "1a", "a-b", "a b"] {
        let target = with(|target| {
            target["user"]["configuration"]["deadline"]["field"] = json!(field);
        });
        assert!(refused_by(&target, "deadline_field_shape"), "{field:?}");
    }
}

/// K8: a declaration in a package that does not request the capability is refused by name, as a
/// finding about the table's file.
#[test]
fn a_skill_target_in_a_package_that_does_not_request_the_capability_is_refused_by_name() {
    let found = findings(amp(), false);
    assert!(
        found
            .iter()
            .any(|detail| detail.contains("skill_target.without_capability")),
        "{found:?}"
    );
}

/// K12: a declaration with no location, an empty list of components and a deadline member with a
/// bad name is refused by name, every reason reported.
#[test]
fn a_skill_target_with_no_location_or_an_empty_list_is_refused_by_name() {
    let none = with(|target| {
        let object = target.as_object_mut().expect("an object");
        object.remove("user");
        object.remove("project");
    });
    assert!(refused_by(&none, "no_location"));
    let empty = with(|target| target["user"]["skills"] = json!([]));
    assert!(refused_by(&empty, "no_components"));
}

/// K10: the capability is confirmed on every release, needs an installation grant and reads by its
/// wire string.
#[test]
fn the_skill_target_capability_is_confirmed_on_every_release() {
    let capability: PluginCapability =
        serde_json::from_value(json!("skill_target.install")).expect("the wire string reads");
    assert_eq!(capability, PluginCapability::SkillTargetInstall);
    assert_eq!(capability.as_str(), "skill_target.install");
    assert!(capability.confirmed_on_every_release());
    assert!(capability.requires_installation_grant());
    assert!(!capability.within_default_ceiling());
}

/// K11: the places of the twelve compiled layouts meet the rules a declaration is held to, except
/// the OpenCode project document `opencode.json`, whose first component is not hidden: the one
/// compiled exception.
#[test]
fn the_compiled_documents_meet_the_rules_the_host_checks() {
    let location = |skills: &[&str], path: &[&str], format| SkillLocation {
        skills: skills.iter().map(|part| (*part).to_owned()).collect(),
        configuration: Some(SkillConfiguration {
            path: path.iter().map(|part| (*part).to_owned()).collect(),
            format,
            shared: false,
            deadline: None,
        }),
    };
    use DocumentFormat::{CodexToml, JsonCommandArgs, JsonLocalCommandList};
    let compiled = [
        (
            location(
                &[".agents", "skills"],
                &[".codex", "config.toml"],
                CodexToml,
            ),
            true,
        ),
        (
            location(&[".claude", "skills"], &[".claude.json"], JsonCommandArgs),
            true,
        ),
        (
            location(&[".claude", "skills"], &[".mcp.json"], JsonCommandArgs),
            true,
        ),
        (
            location(
                &[".config", "opencode", "skills"],
                &[".config", "opencode", "opencode.json"],
                JsonLocalCommandList,
            ),
            true,
        ),
        (
            location(
                &[".opencode", "skills"],
                &["opencode.json"],
                JsonLocalCommandList,
            ),
            false,
        ),
        (
            location(
                &[".gemini", "skills"],
                &[".gemini", "settings.json"],
                JsonCommandArgs,
            ),
            true,
        ),
        (
            location(
                &[".kimi-code", "skills"],
                &[".kimi-code", "mcp.json"],
                JsonCommandArgs,
            ),
            true,
        ),
        (
            location(&[".kimi", "skills"], &[".mcp.json"], JsonCommandArgs),
            true,
        ),
        (
            location(
                &[".qoder", "skills"],
                &[".qoder", "settings.json"],
                JsonCommandArgs,
            ),
            true,
        ),
        (
            location(&[".qoder", "skills"], &[".mcp.json"], JsonCommandArgs),
            true,
        ),
    ];
    for (location, meets) in compiled {
        let target = SkillTarget {
            word: "probe".to_owned(),
            user: Some(location.clone()),
            project: None,
        };
        let found = problems(&target, true);
        assert_eq!(found.is_empty(), meets, "{location:?}: {found:?}");
        if !meets {
            assert!(
                found
                    .iter()
                    .all(|problem| problem.name == "skill_target.not_hidden_first")
            );
        }
    }
}

/// The host's reading of a declaration, written from the approved sentences, for three
/// declarations: a user scope with no document, a project scope with a document and a deadline, and
/// both scopes with a document that other agents also read.
#[test]
fn the_host_reading_of_a_declared_skill_target_is_the_text_the_owner_confirms() {
    let target = |value: Value| -> SkillTarget { serde_json::from_value(value).expect("a target") };
    let opening = "The package names the agent \"amp\" and says where the host installs the KalaReach \
                   contact skill for it, on macOS and Linux. Installing this package does not install \
                   the skill, and the host starts no process when a person who manages this host \
                   installs it.";
    let closing = |scopes: &str| {
        format!(
            "The host keeps the other settings in each configuration file, follows no link below \
             the home folder or the project folder, and replaces no skill file and no entry named \
             kalareach that it did not write. It does not check which program reads these places or \
             how it uses their contents, and another program's own settings may be among them. kr \
             skill remove --agent amp {scopes}, with --project-dir for a project, takes out only \
             what this host wrote and finds unchanged, also after this package is gone, and reports \
             what it leaves in place. Removing the package does not remove the skill."
        )
    };

    let user_only = target(json!({
        "word": "amp",
        "user": { "skills": [".amp", "skills"] }
    }));
    assert_eq!(
        user_only.statement(),
        format!(
            "{opening} For the user scope, kr skill install --agent amp --scope user makes the host \
             write its own files SKILL.md, TOOLS.md and manifest.json into \
             .amp/skills/kalareach-contact/ under the home folder of the account that runs this \
             host. The host adds no server entry for this scope. {}",
            closing("--scope user")
        )
    );

    let with_deadline = target(json!({
        "word": "amp",
        "project": {
            "skills": [".amp", "skills"],
            "configuration": {
                "path": [".amp", "mcp.json"],
                "format": "json_command_args",
                "shared": false,
                "deadline": { "field": "timeout", "unit": "milliseconds" }
            }
        }
    }));
    assert_eq!(
        with_deadline.statement(),
        format!(
            "{opening} For a project, kr skill install --agent amp --scope project --project-dir \
             with the project folder makes the host write its own files SKILL.md, TOOLS.md and \
             manifest.json into .amp/skills/kalareach-contact/ under that project folder, and adds \
             one entry named kalareach to .amp/mcp.json under that folder, as mcpServers.kalareach \
             of a JSON file, with a command and its arguments. The entry starts kr with the \
             arguments agent-tools --stdio and sets timeout to 660000 (milliseconds) and \
             KR_TOOL_DEADLINE_MS to 660000. {}",
            closing("--scope project")
        )
    );

    let shared = target(json!({
        "word": "amp",
        "user": { "skills": [".amp", "skills"] },
        "project": {
            "skills": [".amp", "skills"],
            "configuration": {
                "path": [".mcp.json"],
                "format": "json_command_args",
                "shared": true
            }
        }
    }));
    let text = shared.statement();
    assert!(
        text.contains(
            "The package says that other agents also read .mcp.json, so the entry there is the same \
             for every installation that writes it and sets no time limit, and the host removes it \
             only when no other installation of this host still claims it."
        ),
        "{text}"
    );
    assert!(
        text.ends_with(&closing("--scope user or --scope project")),
        "{text}"
    );
}

/// The longest reading is the maximum the whole statement is budgeted with: a word and three
/// components of the longest length in each scope, the longest field name, over every format,
/// every way of sharing and every deadline.
#[test]
fn the_skill_target_reading_at_its_longest_is_its_maximum() {
    use kr_plugin_sdk::skill_target::MAX_SKILL_TARGET_STATEMENT_CHARS;
    let component = "a".repeat(64);
    let places: Vec<Value> = vec![json!(component); 3];
    let mut longest = 0;
    for format in ["codex_toml", "json_command_args", "json_local_command_list"] {
        for shared in [true, false] {
            for deadline in [
                None,
                Some(json!({ "field": "f".repeat(32), "unit": "seconds" })),
                Some(json!({ "field": "f".repeat(32), "unit": "milliseconds" })),
            ] {
                let mut configuration = json!({
                    "path": places, "format": format, "shared": shared
                });
                if let Some(deadline) = deadline {
                    configuration["deadline"] = deadline;
                }
                let location = json!({ "skills": places, "configuration": configuration });
                let target: SkillTarget = serde_json::from_value(json!({
                    "word": "a".repeat(32), "user": location, "project": location
                }))
                .expect("a target");
                longest = longest.max(target.statement().chars().count());
            }
        }
    }
    assert_eq!(longest, MAX_SKILL_TARGET_STATEMENT_CHARS);
}

/// K9: the texts about a place say what is true of it: a first component that does not start with a
/// dot is refused as one that does not, and the reading the owner confirms puts the configuration
/// of the user scope "under that folder", as it does the project's.
#[test]
fn the_texts_about_a_place_say_what_is_true_of_it() {
    let target = with(|target| target["user"]["skills"] = json!(["amp", "skills"]));
    let found = findings(target, true);
    assert!(
        found
            .iter()
            .any(|detail| detail
                .contains("the first component of the skills does not start with a dot")),
        "{found:?}"
    );
    let reading = serde_json::from_value::<SkillTarget>(amp())
        .expect("a target")
        .statement();
    assert!(
        reading.contains("to .amp/settings.json under that folder, "),
        "{reading}"
    );
    assert!(!reading.contains("under that home folder"), "{reading}");
}
