//! The registrations that start the forwarder, pinned.
//!
//! The Claude Code connector package installs three files into the user's own Claude Code
//! directory, and those files are what start this forwarder. Their copies under
//! `fixtures/bridges/claude-code/` are the bytes the package publishes (the plugins repository at
//! `f369c549f2ec5fa851d5d5f849261f225f7fd65c`, `plugins/kalareach/claude-code/bridge/`), pinned here
//! by the SHA-256 digests the package's own recipe names. They name the forwarder by the
//! placeholder `{kr_hook}`, which the host replaces with the installed forwarder's path when it
//! writes the files; this suite checks the placeholder stands where the host replaces it, and that
//! the forwarder still answers what the new files invoke. A package change moves the copies and the
//! digests together.
//!
//! The Gemini CLI connector package installs an extension, three files, into the user's own Gemini
//! CLI directory: its manifest, its hooks and its install record. Their copies under
//! `fixtures/bridges/gemini-cli/` are the bytes the package publishes (the plugins repository at
//! `f369c549f2ec5fa851d5d5f849261f225f7fd65c`, `plugins/kalareach/gemini-cli/bridge/`), pinned the
//! same way.
//!
//! Qoder CLI reads its hooks from the settings its launch is given, so nothing is installed for it:
//! its registration is the two elements a launch adds to Qoder CLI's argument vector, `--settings`
//! and the inline JSON that follows it, in `fixtures/bridges/qoder-cli/flags.json`, pinned the same
//! way.
//!
//! What a launch adds comes from each release's own command integration, which its manifest
//! declares. The manifests of the three released packages are under `fixtures/plugins/released/`,
//! copied byte for byte from the plugins repository at `bb50ebb41f7ebe4e5fb8cb388b816c849007306d`,
//! and pinned by their SHA-256 digests, which are the package hashes an owner confirms at
//! installation.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.42 | every test below: the registration and the forwarder agree |
//! | KR-REQ-12.18 | `the_hooks_file_registers_the_five_observing_events_within_the_deadline` |
//! | KR-REQ-12.20 | `the_gemini_cli_extension_registers_its_three_events_as_plain_words` |
//! | KR-REQ-12.22 | `the_qoder_cli_flags_pass_its_hooks_in_exec_form_and_nothing_else` |
//! | KR-REQ-12.27 | the Gemini CLI and Qoder CLI registration tests: every timeout the forwarder's deadline fits inside |
//! | KR-REQ-12.18, KR-REQ-12.20, KR-REQ-12.22 | `the_released_declarations_are_what_a_launch_adds`: each release's command integration |

use kr_hook::cli::{ClaudeCode, Cli, Command, Hooks};

/// A copy, beside the other fixtures at the top of the repository, in the application's own
/// directory.
fn fixture(application: &str, name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/bridges")
        .join(application)
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn json(application: &str, name: &str) -> serde_json::Value {
    serde_json::from_slice(&fixture(application, name)).expect("the fixture is JSON")
}

/// The members of a JSON object, sorted.
fn members(value: &serde_json::Value) -> Vec<&str> {
    let mut members: Vec<&str> = value
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    members.sort_unstable();
    members
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The invocation a registration names, parsed by the forwarder's own command line.
///
/// The registration names the forwarder by the placeholder, which is what the host replaces with
/// the installed forwarder's path.
fn parsed(command: &serde_json::Value, args: &serde_json::Value) -> Command {
    assert_eq!(
        command,
        kr_plugin_sdk::forwarder::PLACEHOLDER,
        "the registration starts the forwarder"
    );
    let args: Vec<&str> = args
        .as_array()
        .expect("an argument list")
        .iter()
        .map(|arg| arg.as_str().expect("text"))
        .collect();
    <Cli as clap::Parser>::try_parse_from(std::iter::once("kr-hook").chain(args.iter().copied()))
        .unwrap_or_else(|error| {
            panic!("{args:?} is not an invocation the forwarder accepts: {error}")
        })
        .command
}

/// The digests the package's installation recipe records for each file.
#[test]
fn the_bridge_files_are_the_bytes_the_package_publishes() {
    for (name, digest) in [
        (
            "hooks.json",
            "c81a5d098b6282ddfc1111183e308e3ab6094bcb76a6455019df7133c0f0f641",
        ),
        (
            "mcp-servers.json",
            "b514ddff583d9c3d926233ce402b4e7d27eb3b76cffce369f5ea4cb30460c82a",
        ),
        (
            "plugin-manifest.json",
            "1cb6238953bafc5e2872e8af3a430d94ca8452c11e51dc43946889f7268b126c",
        ),
    ] {
        assert_eq!(sha256(&fixture("claude-code", name)), digest, "{name}");
    }
}

/// KR-REQ-12.18: the hooks file registers the forwarder's hook invocation for exactly the five
/// events whose exit codes refuse nothing, for every tool and notification (no matcher), each with
/// a timeout the forwarder's own deadline fits inside. Each is in exec form and runs in the
/// foreground: Claude Code starts the forwarder itself, with no shell between them, which is what
/// lets the worker order the hooks by when Claude Code started each one.
#[test]
fn the_hooks_file_registers_the_five_observing_events_within_the_deadline() {
    let hooks = json("claude-code", "hooks.json");
    let events = hooks["hooks"].as_object().expect("events");
    let mut names: Vec<&str> = events.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "Notification",
            "PostToolUse",
            "PostToolUseFailure",
            "SessionEnd",
            "SessionStart"
        ]
    );
    for (event, groups) in events {
        let groups = groups.as_array().expect("matcher groups");
        assert_eq!(groups.len(), 1, "{event}");
        assert!(
            groups[0].get("matcher").is_none(),
            "{event} matches everything"
        );
        let handlers = groups[0]["hooks"].as_array().expect("handlers");
        assert_eq!(handlers.len(), 1, "{event}");
        let handler = &handlers[0];
        let mut fields: Vec<&str> = handler
            .as_object()
            .expect("a handler")
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            ["args", "command", "timeout", "type"],
            "{event}: exec form, no shell, not in the background"
        );
        assert_eq!(handler["type"], "command", "{event}");
        assert_eq!(
            parsed(&handler["command"], &handler["args"]),
            Command::ClaudeCode {
                surface: ClaudeCode::Hook
            },
            "{event}"
        );
        let timeout = handler["timeout"].as_u64().expect("a timeout in seconds");
        assert_eq!(
            timeout,
            if event == "SessionEnd" { 1 } else { 5 },
            "{event}"
        );
        assert!(
            kr_hook::hook::HOOK_DEADLINE < std::time::Duration::from_secs(timeout),
            "{event}: the forwarder answers before Claude Code would cancel it"
        );
    }
}

/// KR-REQ-11.42: the MCP server file starts the forwarder's channel invocation over standard input
/// and output, under the server name the plugin manifest declares as its channel, which is the name
/// the forwarder introduces itself by. The manifest is off by default: the settings key the recipe
/// adds is what turns it on.
#[test]
fn the_channel_registration_starts_the_forwarders_channel_under_its_name() {
    let servers = json("claude-code", "mcp-servers.json");
    let servers = servers["mcpServers"].as_object().expect("servers");
    assert_eq!(servers.len(), 1);
    let (name, server) = servers.iter().next().expect("one server");
    assert_eq!(server["type"], "stdio");
    assert_eq!(
        parsed(&server["command"], &server["args"]),
        Command::ClaudeCode {
            surface: ClaudeCode::Channel
        }
    );
    assert_eq!(name, kr_hook::claude_code::channel::SERVER_NAME);

    let manifest = json("claude-code", "plugin-manifest.json");
    assert_eq!(
        manifest["channels"],
        serde_json::json!([{"server": name}]),
        "the plugin declares that server as its channel"
    );
    assert_eq!(manifest["defaultEnabled"], false);
    assert_eq!(manifest["name"], "kalareach-channels");
}

/// The digest of the two elements a Qoder CLI launch adds, so a change to them is a deliberate one.
#[test]
fn the_qoder_cli_flags_are_the_pinned_bytes() {
    assert_eq!(
        sha256(&fixture("qoder-cli", "flags.json")),
        "4a23ebef3076b3d7f5aaa817d3f4f78561c48db869c6147b92a503e0c3fb6c23"
    );
}

/// KR-REQ-12.22, KR-REQ-12.27: a Qoder CLI launch adds exactly two elements, `--settings` and the
/// inline JSON after it, and that JSON holds hooks and nothing else: the forwarder's `qoder-cli
/// hook` invocation, in exec form, for exactly the events the forwarder reports for Qoder CLI, for
/// every tool, notification and source (no matcher), in the foreground, each with a timeout in
/// seconds that the forwarder's deadline fits inside.
#[test]
fn the_qoder_cli_flags_pass_its_hooks_in_exec_form_and_nothing_else() {
    let flags: Vec<String> =
        serde_json::from_slice(&fixture("qoder-cli", "flags.json")).expect("the two elements");
    assert_eq!(flags.len(), 2, "{flags:?}");
    assert_eq!(flags[0], "--settings");
    let settings: serde_json::Value =
        serde_json::from_str(&flags[1]).expect("the settings are inline JSON");
    assert_eq!(members(&settings), ["hooks"], "hooks and nothing else");

    let events = &settings["hooks"];
    let mut registered = members(events);
    let mut reported: Vec<&str> = kr_hook::qoder_cli::HOOKS
        .events
        .iter()
        .map(|(event, _)| *event)
        .collect();
    registered.sort_unstable();
    reported.sort_unstable();
    assert_eq!(
        registered, reported,
        "the launch registers exactly the events the forwarder reports for Qoder CLI"
    );
    for (event, groups) in events.as_object().expect("events") {
        let groups = groups.as_array().expect("matcher groups");
        assert_eq!(groups.len(), 1, "{event}");
        assert_eq!(
            members(&groups[0]),
            ["hooks"],
            "{event}: no matcher, not in the background"
        );
        let handlers = groups[0]["hooks"].as_array().expect("handlers");
        assert_eq!(handlers.len(), 1, "{event}");
        let handler = &handlers[0];
        assert_eq!(
            members(handler),
            ["args", "command", "timeout", "type"],
            "{event}: exec form, no shell, no environment, not in the background"
        );
        assert_eq!(handler["type"], "command", "{event}");
        assert_eq!(
            parsed(&handler["command"], &handler["args"]),
            Command::QoderCli {
                surface: Hooks::Hook
            },
            "{event}"
        );
        let timeout = handler["timeout"].as_u64().expect("a timeout in seconds");
        assert_eq!(
            timeout,
            if event == "SessionEnd" { 1 } else { 5 },
            "{event}"
        );
        assert!(
            kr_hook::hook::HOOK_DEADLINE < std::time::Duration::from_secs(timeout),
            "{event}: the forwarder answers before Qoder CLI would stop it"
        );
    }
}

/// The digests the Gemini CLI package's installation recipe records for each file.
#[test]
fn the_gemini_cli_bridge_files_are_the_bytes_the_package_publishes() {
    for (name, digest) in [
        (
            "gemini-extension.json",
            "2ea510ab37639c8f4b9e380c3a168b06771088d31b2b933549213479d5e764e7",
        ),
        (
            "hooks.json",
            "8b5a969d228a005058462485bbbc79bd74fec9fb64a7837dc9efe10987992a18",
        ),
        (
            "gemini-extension-install.json",
            "ed5b5291f2e39bf679e945135210c5aee7863b8b8dbaa049dd53598507f172cb",
        ),
    ] {
        assert_eq!(sha256(&fixture("gemini-cli", name)), digest, "{name}");
    }
}

/// KR-REQ-12.20, KR-REQ-12.27: the extension's hooks file registers the forwarder's `gemini-cli
/// hook` invocation for exactly the events the forwarder reports for Gemini CLI, for every source and
/// notification (no matcher), in the order Gemini CLI chooses (no `sequential`), each as a command
/// of plain words, which bash runs in its own process, and each with a timeout in milliseconds that
/// the forwarder's deadline fits inside. The manifest names the extension and nothing it could load.
/// The install record names a local source nothing can exist under, `/dev/null/kalareach`, and
/// nothing else: where a person's settings list allowed extensions, Gemini CLI refuses to start while
/// an extension directory has no record and tests the list's patterns against the source a record
/// names, and it reads a local extension's updates from that source, a relative one from the
/// session's working directory, where a project could put a newer manifest.
#[test]
fn the_gemini_cli_extension_registers_its_three_events_as_plain_words() {
    let hooks = json("gemini-cli", "hooks.json");
    assert_eq!(members(&hooks), ["hooks"]);
    let events = &hooks["hooks"];
    let mut registered = members(events);
    let mut reported: Vec<&str> = kr_hook::gemini_cli::HOOKS
        .events
        .iter()
        .map(|(event, _)| *event)
        .collect();
    registered.sort_unstable();
    reported.sort_unstable();
    assert_eq!(
        registered, reported,
        "the extension registers exactly the events the forwarder reports for Gemini CLI"
    );
    for (event, groups) in events.as_object().expect("events") {
        let groups = groups.as_array().expect("groups");
        assert_eq!(groups.len(), 1, "{event}");
        assert_eq!(
            members(&groups[0]),
            ["hooks"],
            "{event}: no matcher and no order"
        );
        let handlers = groups[0]["hooks"].as_array().expect("handlers");
        assert_eq!(handlers.len(), 1, "{event}");
        let handler = &handlers[0];
        assert_eq!(
            members(handler),
            ["command", "name", "timeout", "type"],
            "{event}: no environment of its own and nothing else"
        );
        assert_eq!(handler["type"], "command", "{event}");
        assert_eq!(handler["name"], "kalareach", "{event}");
        let command = handler["command"].as_str().expect("a command");
        let words: Vec<&str> = command.split(' ').collect();
        assert_eq!(
            words[0],
            kr_plugin_sdk::forwarder::PLACEHOLDER,
            "{event}: the line starts with the placeholder, which the host writes as one quoted word"
        );
        assert!(
            words[1..].iter().all(|word| {
                !word.is_empty()
                    && word
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric() || character == '-')
            }),
            "{event}: {command:?} is the forwarder and plain words, which bash runs in its own \
             process"
        );
        assert_eq!(
            parsed(&serde_json::json!(words[0]), &serde_json::json!(words[1..])),
            Command::GeminiCli {
                surface: Hooks::Hook
            },
            "{event}"
        );
        let timeout = handler["timeout"]
            .as_u64()
            .expect("a timeout in milliseconds");
        assert_eq!(
            timeout,
            if event == "SessionEnd" { 1000 } else { 5000 },
            "{event}"
        );
        assert!(
            kr_hook::hook::HOOK_DEADLINE < std::time::Duration::from_millis(timeout),
            "{event}: the forwarder answers before Gemini CLI would stop it"
        );
    }

    let manifest = json("gemini-cli", "gemini-extension.json");
    assert_eq!(members(&manifest), ["description", "name", "version"]);
    assert_eq!(manifest["name"], "kalareach");

    let record = json("gemini-cli", "gemini-extension-install.json");
    assert_eq!(
        record,
        serde_json::json!({"source": "/dev/null/kalareach", "type": "local"}),
        "the install record names a local source nothing can exist under"
    );
}

/// A released package's manifest, as the plugins repository published it.
fn released(package: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/plugins/released/kalareach")
        .join(package)
        .join("0.5.0/plugin.json");
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// The command integration a released manifest declares, which the package contract accepts: it
/// names one of the package's own executables, adds only flags and sets only variables the contract
/// permits, and the package asks for the capability that confirms it.
fn declared(package: &str) -> kr_plugin_sdk::integration::CommandIntegration {
    use kr_plugin_sdk::capability::PluginCapability;
    let manifest: kr_plugin_sdk::plugin::PluginManifest =
        serde_json::from_slice(&released(package)).expect("the released manifest reads");
    let integration = manifest
        .command_integration
        .clone()
        .unwrap_or_else(|| panic!("{package} declares a command integration"));
    assert_eq!(
        integration.problems(&manifest.match_rules),
        Vec::<String>::new(),
        "{package}'s declaration is one the package contract accepts"
    );
    assert!(
        manifest
            .capabilities
            .iter()
            .any(|request| request.capability == PluginCapability::CommandIntegrationLaunch),
        "{package} asks for the capability that confirms its integration"
    );
    integration
}

/// Each released manifest is the package its release names: the file's SHA-256 digest is the
/// package hash the development generation's signed index gives that release, so a change to a
/// release's declaration is a deliberate new copy.
#[test]
fn the_released_manifests_are_the_pinned_packages() {
    for (package, digest) in [
        (
            "claude-code",
            "4e967df9fc5c0e3c1feddb1a7767e04f0c6ad02831fc6e455f8291a0882f5214",
        ),
        (
            "gemini-cli",
            "72dd20cf01448d3e1d8cfed962a13f7cf7bc69c7a5abdc5a20b9edcd664f2c4b",
        ),
        (
            "qoder-cli",
            "839be8df1b15cdc500c9f6e4bb5564a6bfff0f2bb6fb8a0497821b9762165a14",
        ),
    ] {
        assert_eq!(sha256(&released(package)), digest, "{package}");
    }
}

/// KR-REQ-12.18, KR-REQ-12.20, KR-REQ-12.22: what each release's integration adds to a launch.
/// Claude Code's channel flag and the plugin it names, and no variable; Gemini CLI's one variable,
/// which makes the launched process run the session, and no flag; Qoder CLI's two elements, which
/// are the pinned registration this suite checks above, and no variable.
#[test]
fn the_released_declarations_are_what_a_launch_adds() {
    let claude = declared("claude-code");
    assert_eq!(claude.command, "claude");
    assert_eq!(
        claude.flags,
        [
            "--dangerously-load-development-channels",
            "plugin:kalareach-channels@skills-dir"
        ]
    );
    assert!(claude.variables.is_empty());

    let gemini = declared("gemini-cli");
    assert_eq!(gemini.command, "gemini");
    assert!(gemini.flags.is_empty());
    assert_eq!(
        gemini.variables,
        [kr_plugin_sdk::integration::IntegrationVariable {
            name: "GEMINI_CLI_NO_RELAUNCH".to_owned(),
            value: "true".to_owned(),
        }]
    );

    let qoder = declared("qoder-cli");
    assert_eq!(qoder.command, "qodercli");
    let pinned: Vec<String> =
        serde_json::from_slice(&fixture("qoder-cli", "flags.json")).expect("the two elements");
    assert_eq!(
        qoder.flags, pinned,
        "the release declares the pinned registration"
    );
    assert!(qoder.variables.is_empty());
}

/// KR-REQ-12.20: Gemini CLI's package is not offered on Windows, where Gemini CLI starts a hook
/// through PowerShell by a bare name and no command route integrates it (its npm shim is a script),
/// so a host there leaves it out as a package that does not support the operating system and says
/// that, as it does for any package. The two packages that start the forwarder directly are offered
/// there, which is the control.
#[test]
fn the_released_gemini_cli_package_is_not_offered_on_windows_and_the_others_are() {
    let platforms = |package: &str| -> Vec<kr_plugin_sdk::matching::OperatingSystem> {
        let manifest: kr_plugin_sdk::plugin::PluginManifest =
            serde_json::from_slice(&released(package)).expect("the released manifest reads");
        manifest
            .platforms
            .iter()
            .map(|platform| platform.os)
            .collect()
    };
    use kr_plugin_sdk::matching::OperatingSystem::{Linux, MacOs, Windows};
    assert_eq!(platforms("gemini-cli"), [Linux, MacOs]);
    for package in ["claude-code", "qoder-cli"] {
        assert!(platforms(package).contains(&Windows), "{package}");
    }
}
