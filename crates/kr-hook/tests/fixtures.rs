//! The Claude Code bridge files the forwarder is registered by, pinned.
//!
//! The Claude Code connector package installs three files into the user's own Claude Code
//! directory, and those files are what start this forwarder. Their copies under
//! `fixtures/bridges/claude-code/` are the bytes the package publishes (the plugins repository at
//! `7f2e71292eff15e8f63d4c331b253080011633c7`, `plugins/kalareach/claude-code/bridge/`), pinned here
//! by the SHA-256 digests the package's own recipe names. A package change moves the copies and
//! the digests together, and this suite then checks that the forwarder still answers what the new
//! files invoke.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.42 | every test below: the installed registration and the forwarder agree |
//! | KR-REQ-12.18 | `the_hooks_file_registers_the_five_observing_events_within_the_deadline` |

use kr_hook::cli::{ClaudeCode, Cli, Command};

/// The copies, beside the other fixtures at the top of the repository.
fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/bridges/claude-code")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn json(name: &str) -> serde_json::Value {
    serde_json::from_slice(&fixture(name)).expect("the fixture is JSON")
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The invocation a registration names, parsed by the forwarder's own command line.
fn parsed(command: &serde_json::Value, args: &serde_json::Value) -> Command {
    assert_eq!(command, "kr-hook", "the registration starts the forwarder");
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
            "bbf177109cbca2bdcbf995fcf06f9cc434df898c86c0272461de0c10e5baf727",
        ),
        (
            "mcp-servers.json",
            "13e39e82aee3be2710c49a6f38f5558e20d18416a0a18e07b72f5dff9de1c4ea",
        ),
        (
            "plugin-manifest.json",
            "1cb6238953bafc5e2872e8af3a430d94ca8452c11e51dc43946889f7268b126c",
        ),
    ] {
        assert_eq!(sha256(&fixture(name)), digest, "{name}");
    }
}

/// KR-REQ-12.18: the hooks file registers the forwarder's hook invocation for exactly the five
/// events whose exit codes refuse nothing, for every tool and notification (no matcher), each with
/// a timeout the forwarder's own deadline fits inside. Each is in exec form and runs in the
/// foreground: Claude Code starts the forwarder itself, with no shell between them, which is what
/// lets the worker order the hooks by when Claude Code started each one.
#[test]
fn the_hooks_file_registers_the_five_observing_events_within_the_deadline() {
    let hooks = json("hooks.json");
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
            kr_hook::claude_code::hook::HOOK_DEADLINE < std::time::Duration::from_secs(timeout),
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
    let servers = json("mcp-servers.json");
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

    let manifest = json("plugin-manifest.json");
    assert_eq!(
        manifest["channels"],
        serde_json::json!([{"server": name}]),
        "the plugin declares that server as its channel"
    );
    assert_eq!(manifest["defaultEnabled"], false);
    assert_eq!(manifest["name"], "kalareach-channels");
}
