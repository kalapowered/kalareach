//! The worker takes a connector from its installed package, and from nothing else.
//!
//! Each case writes a Claude Code shaped connector package the way the catalogue's store extracts
//! one, under its hash, and hands the worker what an installation hands it. What the worker reads
//! is checked against that hash, so a package that is not the installed one, or a file that is not
//! the bytes its manifest names, is refused rather than read.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-12.07 | an integrated command resolves to the connector its installed package carries, and to nothing else; its command, flags and variables are the verified manifest's, and apply only while `command_integration.launch` is granted |
//! | KR-REQ-11.34 | the table a channel is served with is the installed package's own |
//! | KR-REQ-12.22 | Qoder CLI's launch flags give its launch a hook bridge on this installation's own forwarder, for Qoder CLI and nothing else |

use std::path::{Path, PathBuf};

use kr_plugin_sdk::capability::PluginCapability;
use kr_protocol::scalars::Digest256;
use kr_worker::broker::bridge::{BridgeDeclaration, BridgeSurface, InstalledBridge};
use kr_worker::broker::connectors::{
    ConnectorSource, ConnectorSources, InstalledConnector, fixture,
};

/// A directory of the test's own, removed when it is dropped.
struct Store {
    root: PathBuf,
}

impl Store {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("kr-connectors-{name}-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&root).expect("a store directory");
        Self { root }
    }

    fn package(&self) -> ConnectorSource {
        fixture::claude_code_package(&self.root, Path::new("/opt/kalareach/bin/kr-hook"))
            .expect("the package is written")
    }

    fn shaped(&self, shape: &fixture::Shape) -> ConnectorSource {
        fixture::package(&self.root, Path::new("/opt/kalareach/bin/kr-hook"), shape)
            .expect("the package is written")
    }

    /// A file standing in for an installation's forwarder, at `relative` inside the store.
    fn forwarder(&self, relative: &str) -> PathBuf {
        let path = self.root.join(relative);
        std::fs::create_dir_all(path.parent().expect("a directory")).expect("the directory");
        std::fs::write(&path, b"forwarder").expect("the forwarder stands in");
        path
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// KR-REQ-12.07, KR-REQ-11.34: the installed package's table, its command and its bridge.
#[test]
fn kr_req_12_07_an_installed_connector_is_read_from_its_package() {
    let store = Store::new("read");
    let source = store.package();
    let connector =
        InstalledConnector::read(source.clone()).expect("the installed package is read");
    assert_eq!(connector.plugin_id().as_str(), "kalareach/claude-code");
    assert_eq!(connector.package_digest(), source.package_digest);
    let integration = connector
        .integration()
        .expect("the manifest declares the integration");
    assert_eq!(integration.command, fixture::COMMAND);
    assert_eq!(integration.flags, fixture::FLAGS);
    assert!(integration.variables.is_empty());
    assert!(
        connector.table().decision_destination.as_ref().is_some(),
        "the table says how a relayed approval is answered"
    );
    let bridge = connector
        .installed_bridge()
        .expect("the installation put a bridge in place");
    assert_eq!(bridge.plugin_id, connector.plugin_id());
    assert_eq!(bridge.application, "claude-code");
    assert!(bridge.surfaces.contains(&BridgeSurface::Channel));
    assert!(bridge.surfaces.contains(&BridgeSurface::Hook));
    assert!(connector.granted(PluginCapability::ApprovalRespond));
    assert!(connector.matches_executable("/usr/local/bin/claude"));
    assert!(!connector.matches_executable("/usr/local/bin/codex"));

    let sources = ConnectorSources::new();
    assert!(sources.replace(vec![source]).is_empty());
    assert!(sources.for_command("claude").is_some());
    assert!(sources.for_command("codex").is_none());
    assert!(sources.matching("/opt/homebrew/bin/claude").is_some());
    assert!(
        sources.replace(Vec::new()).is_empty(),
        "an installation that hands over nothing leaves nothing integrated"
    );
    assert!(sources.for_command("claude").is_none());
}

/// A file in the package that is not the bytes its manifest names is refused, and nothing is
/// integrated from it.
#[test]
fn a_table_changed_after_installation_is_refused() {
    let store = Store::new("changed");
    let source = store.package();
    let table = source.package_dir.join("connector.json");
    let mut bytes = std::fs::read(&table).expect("the table is read");
    let at = bytes
        .windows(6)
        .position(|window| window == b"\"deny\"")
        .expect("the table maps deny");
    bytes[at + 1] = b'D';
    std::fs::write(&table, &bytes).expect("the table is changed");
    let refusal = InstalledConnector::read(source.clone()).expect_err("a changed table is refused");
    assert!(
        refusal.detail.contains("package check"),
        "{}",
        refusal.detail
    );
    let sources = ConnectorSources::new();
    let refused = sources.replace(vec![source]);
    assert_eq!(refused.len(), 1);
    assert!(sources.for_command("claude").is_none());
}

/// A package directory whose manifest is not the installed hash is another package, whatever it
/// says, and is refused.
#[test]
fn a_package_that_is_not_the_installed_one_is_refused() {
    let store = Store::new("foreign");
    let mut source = store.package();
    source.package_digest = Digest256::from_bytes([7; 32]);
    let refusal = InstalledConnector::read(source).expect_err("a foreign hash is refused");
    assert!(
        refusal.detail.contains("not the installed one"),
        "{}",
        refusal.detail
    );
}

/// A table that names another package is not this package's table.
#[test]
fn a_table_that_names_another_package_is_refused() {
    let store = Store::new("another");
    let source = store.package();
    let table_path = source.package_dir.join("connector.json");
    let table = std::fs::read_to_string(&table_path)
        .expect("the table is read")
        .replace("kalareach/claude-code", "kalareach/codex");
    // The package is written again whole, so every digest in it holds and only the table's
    // plugin differs.
    let files: Vec<(&str, &str, Vec<u8>)> = vec![
        ("connector", "connector.json", table.clone().into_bytes()),
        (
            "presentation",
            "presentation.json",
            fixture::presentation_json().into_bytes(),
        ),
        (
            "native_bridge",
            "bridge/hooks.json",
            std::fs::read(source.package_dir.join("bridge/hooks.json")).expect("read"),
        ),
        (
            "native_bridge",
            "bridge/mcp-servers.json",
            std::fs::read(source.package_dir.join("bridge/mcp-servers.json")).expect("read"),
        ),
        (
            "native_bridge",
            "bridge/plugin-manifest.json",
            std::fs::read(source.package_dir.join("bridge/plugin-manifest.json")).expect("read"),
        ),
    ];
    let manifest = fixture::manifest_json(&files);
    std::fs::write(&table_path, table.as_bytes()).expect("the table is written");
    std::fs::write(source.package_dir.join("plugin.json"), manifest.as_bytes())
        .expect("the manifest is written");
    let digest = kr_plugin_sdk::digest::PayloadDigest::of(manifest.as_bytes());
    let source = ConnectorSource {
        package_digest: Digest256::from_bytes(*digest.as_bytes()),
        ..source
    };
    let refusal = InstalledConnector::read(source).expect_err("another package's table");
    assert!(
        refusal.detail.contains("package check"),
        "{}",
        refusal.detail
    );
}

/// An installation that describes a native bridge it was not granted is refused.
#[test]
fn a_bridge_the_installation_was_not_granted_is_refused() {
    let store = Store::new("ungranted");
    let mut source = store.package();
    source
        .granted
        .remove(&PluginCapability::NativeBridgeInstall);
    let refusal = InstalledConnector::read(source).expect_err("an ungranted bridge is refused");
    assert!(
        refusal.detail.contains("native_bridge.install"),
        "{}",
        refusal.detail
    );
}

/// Two packages that integrate one command name are both left out.
#[test]
fn a_command_two_packages_integrate_resolves_to_neither() {
    let first = Store::new("first");
    let second = Store::new("second");
    let sources = ConnectorSources::new();
    let refused = sources.replace(vec![first.package(), second.package()]);
    assert_eq!(refused.len(), 2);
    assert!(sources.for_command("claude").is_none());
}

/// A manifest's integration names a command one of the package's match rules recognises: the
/// package check refuses a path, another application's name and no name at all, and nothing is
/// integrated from such a package.
#[test]
fn a_command_the_package_does_not_recognise_is_refused() {
    let store = Store::new("command");
    InstalledConnector::read(store.package()).expect("the package as installed is read");
    for command in ["bin/claude", "/usr/local/bin/claude", "codex", ""] {
        let source = fixture::package(
            &store.root,
            Path::new("/opt/kalareach/bin/kr-hook"),
            &fixture::Shape {
                integration: Some(fixture::declaration(command, &fixture::FLAGS, &[])),
                ..fixture::Shape::claude_code()
            },
        )
        .expect("the package is written");
        let refusal = InstalledConnector::read(source.clone()).expect_err("refused");
        assert!(
            refusal.detail.contains("package check")
                && refusal.detail.contains("integration_invalid"),
            "{command:?}: {}",
            refusal.detail
        );
        let sources = ConnectorSources::new();
        assert_eq!(sources.replace(vec![source]).len(), 1, "{command:?}");
        assert!(sources.for_command(command).is_none(), "{command:?}");
    }
}

/// The inline hooks of a `--settings` flag that start the forwarder with `arguments`.
fn hooks_starting(arguments: &[&str]) -> String {
    hooks_running(&serde_json::json!({
        "type": "command", "command": "kr-hook", "args": arguments, "timeout": 5
    }))
}

/// The inline hooks of a `--settings` flag whose one hook is `hook`.
fn hooks_running(hook: &serde_json::Value) -> String {
    serde_json::json!({ "hooks": { "SessionStart": [{ "hooks": [hook] }] } }).to_string()
}

/// KR-REQ-12.22: Qoder CLI's launch flags register the forwarder's hook for Qoder CLI, so the
/// launch admits a hook that says it is Qoder CLI's and runs this installation's own forwarder,
/// and refuses one that says it is another application's, a channel, or that runs another copy.
#[test]
fn kr_req_12_22_qoder_cli_s_flags_give_its_launch_a_hook_bridge_on_this_installation_s_forwarder() {
    let store = Store::new("qoder");
    let launcher = store.forwarder("bin/kr-hook");
    let connector = InstalledConnector::read(store.shaped(&fixture::Shape::qoder_cli()))
        .expect("the installed package is read");
    assert!(
        connector.installed_bridge().is_none(),
        "the installation put no bridge in place"
    );
    let integration = connector
        .integration()
        .expect("the manifest declares the integration");
    assert_eq!(integration.command, "qodercli");
    assert_eq!(integration.flags, fixture::qoder_flags());
    let bridge = connector
        .launch_bridge(&launcher)
        .expect("the flags register the forwarder's hook");
    assert_eq!(
        bridge,
        InstalledBridge {
            plugin_id: connector.plugin_id(),
            application: "qoder-cli".to_owned(),
            surfaces: [BridgeSurface::Hook].into_iter().collect(),
            forwarder: launcher.clone(),
        }
    );
    let declared = |application: &str, surface: BridgeSurface| BridgeDeclaration {
        application: application.to_owned(),
        surface,
    };
    bridge
        .validate(&declared("qoder-cli", BridgeSurface::Hook), Some(&launcher))
        .expect("Qoder CLI's hook, running this installation's forwarder");
    bridge
        .validate(
            &declared("claude-code", BridgeSurface::Hook),
            Some(&launcher),
        )
        .expect_err("another application's hook");
    bridge
        .validate(
            &declared("qoder-cli", BridgeSurface::Channel),
            Some(&launcher),
        )
        .expect_err("a channel the flags do not register");
    let other = store.forwarder("elsewhere/kr-hook");
    bridge
        .validate(&declared("qoder-cli", BridgeSurface::Hook), Some(&other))
        .expect_err("another copy of the forwarder");
}

/// A launch's bridge is the package's own and comes from one place: flags that start the forwarder
/// for another application, for a channel or with other arguments are refused, and so are flags
/// that start it beside the native bridge the package installs. The forwarder appears in a flag
/// only as a hook's own command with its arguments: a shell command that runs it, a path to it and
/// a flag that is not JSON but names it are refused too, beside a native bridge or not.
#[test]
fn flags_that_start_the_forwarder_for_another_application_a_channel_or_a_second_bridge_are_refused()
{
    let store = Store::new("flags");
    let shell_form = hooks_running(&serde_json::json!({
        "type": "command", "command": "kr-hook qoder-cli hook", "timeout": 5
    }));
    let path_form = hooks_running(&serde_json::json!({
        "type": "command", "command": "/opt/kalareach/bin/kr-hook", "args": ["qoder-cli", "hook"]
    }));
    let qoder_flags = |flags: &[&str]| fixture::Shape {
        integration: Some(fixture::declaration("qodercli", flags, &[])),
        ..fixture::Shape::qoder_cli()
    };
    for (shape, what) in [
        (
            qoder_flags(&["--settings", &shell_form]),
            "a shell command that runs the forwarder",
        ),
        (
            qoder_flags(&["--settings", &path_form]),
            "a path to the forwarder",
        ),
        (
            qoder_flags(&["--hook-command=kr-hook qoder-cli hook"]),
            "a flag that is not JSON and names the forwarder",
        ),
        (
            fixture::Shape {
                integration: Some(fixture::declaration(
                    "claude",
                    &["--settings", &shell_form],
                    &[],
                )),
                ..fixture::Shape::claude_code()
            },
            "a shell command that runs the forwarder beside the native bridge",
        ),
        (
            fixture::Shape {
                integration: Some(fixture::declaration(
                    "qodercli",
                    &["--settings", &hooks_starting(&["claude-code", "hook"])],
                    &[],
                )),
                ..fixture::Shape::qoder_cli()
            },
            "another application's hook",
        ),
        (
            fixture::Shape {
                integration: Some(fixture::declaration(
                    "qodercli",
                    &["--settings", &hooks_starting(&["qoder-cli", "channel"])],
                    &[],
                )),
                ..fixture::Shape::qoder_cli()
            },
            "a channel",
        ),
        (
            fixture::Shape {
                integration: Some(fixture::declaration(
                    "qodercli",
                    &[
                        "--settings",
                        &hooks_starting(&["qoder-cli", "hook", "extra"]),
                    ],
                    &[],
                )),
                ..fixture::Shape::qoder_cli()
            },
            "arguments the forwarder does not take from a bridge",
        ),
        (
            fixture::Shape {
                integration: Some(fixture::declaration(
                    "claude",
                    &["--settings", &hooks_starting(&["claude-code", "hook"])],
                    &[],
                )),
                ..fixture::Shape::claude_code()
            },
            "a hook beside the native bridge the package installs",
        ),
    ] {
        let source = store.shaped(&shape);
        let refusal = InstalledConnector::read(source.clone())
            .map(|connector| connector.plugin_id())
            .expect_err(what);
        assert!(
            refusal.detail.contains("kr-hook"),
            "{what}: {}",
            refusal.detail
        );
        let sources = ConnectorSources::new();
        assert_eq!(sources.replace(vec![source]).len(), 1, "{what}");
        assert!(sources.is_empty(), "{what}");
    }
}

/// A native bridge the installation put in place for another application than the package's own is
/// refused.
#[test]
fn an_installed_bridge_for_another_application_is_refused() {
    let store = Store::new("elsewhere");
    let mut source = store.package();
    source
        .bridge
        .as_mut()
        .expect("the installation put the bridge in place")
        .application = "gemini-cli".to_owned();
    let refusal = InstalledConnector::read(source)
        .map(|connector| connector.plugin_id())
        .expect_err("another application's bridge");
    assert!(refusal.detail.contains("gemini-cli"), "{}", refusal.detail);
}

/// A native bridge the package declares and the installation did not put in place leaves its
/// launch with no bridge, so none is admitted.
#[test]
fn a_declared_bridge_the_installation_did_not_apply_leaves_the_launch_with_none() {
    let store = Store::new("unapplied");
    let launcher = store.forwarder("bin/kr-hook");
    let mut source = store.package();
    source.bridge = None;
    let connector = InstalledConnector::read(source).expect("the installed package is read");
    assert!(connector.integration().is_some());
    assert!(connector.launch_bridge(&launcher).is_none());
}

/// KR-REQ-12.07: an integration applies only while the installation holds
/// `command_integration.launch`. Without it the connector is still read and matched, and resolves
/// no command.
#[test]
fn kr_req_12_07_a_withdrawn_integration_grant_keeps_the_connector_and_integrates_nothing() {
    let store = Store::new("withdrawn");
    let mut source = store.package();
    source
        .granted
        .remove(&PluginCapability::CommandIntegrationLaunch);
    let connector =
        InstalledConnector::read(source.clone()).expect("the installed package is read");
    assert!(connector.integration().is_none());
    let sources = ConnectorSources::new();
    assert!(sources.replace(vec![source]).is_empty());
    assert!(sources.for_command(fixture::COMMAND).is_none());
    assert!(sources.matching("/usr/local/bin/claude").is_some());
}

/// Connectors that declare no command integration are held for matching, however many there are,
/// and resolve no command.
#[test]
fn connectors_that_declare_no_integration_are_held_for_matching() {
    let store = Store::new("undeclared");
    let claude = store.shaped(&fixture::Shape {
        integration: None,
        ..fixture::Shape::claude_code()
    });
    let codex = store.shaped(&fixture::Shape {
        plugin_name: "codex",
        display_name: "Codex CLI",
        executable: "codex",
        integration: None,
        native_bridge: false,
        ..fixture::Shape::claude_code()
    });
    let sources = ConnectorSources::new();
    assert!(sources.replace(vec![claude, codex]).is_empty());
    assert!(!sources.is_empty());
    assert!(sources.for_command("claude").is_none());
    assert!(sources.for_command("codex").is_none());
    assert_eq!(
        sources
            .matching("/usr/local/bin/claude")
            .map(|connector| connector.plugin_id().to_string()),
        Some("kalareach/claude-code".to_owned())
    );
    assert_eq!(
        sources
            .matching("/usr/local/bin/codex")
            .map(|connector| connector.plugin_id().to_string()),
        Some("kalareach/codex".to_owned())
    );
}

/// KR-REQ-12.07: a manifest altered to declare other flags is not the installed package, whatever
/// its flags say, and nothing is integrated from it.
#[test]
fn kr_req_12_07_a_manifest_altered_to_declare_other_flags_is_refused() {
    let store = Store::new("altered");
    let source = store.package();
    let manifest = source.package_dir.join("plugin.json");
    let text = std::fs::read_to_string(&manifest)
        .expect("the manifest is read")
        .replace(fixture::FLAGS[1], "plugin:elsewhere@skills-dir");
    std::fs::write(&manifest, text).expect("the manifest is changed");
    let refusal = InstalledConnector::read(source.clone())
        .map(|connector| connector.plugin_id())
        .expect_err("an altered manifest");
    assert!(
        refusal.detail.contains("not the installed one"),
        "{}",
        refusal.detail
    );
    let sources = ConnectorSources::new();
    assert_eq!(sources.replace(vec![source]).len(), 1);
    assert!(sources.for_command(fixture::COMMAND).is_none());
}
