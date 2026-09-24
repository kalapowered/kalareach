//! The worker takes a connector from its installed package, and from nothing else.
//!
//! Each case writes a Claude Code shaped connector package the way the catalogue's store extracts
//! one, under its hash, and hands the worker what an installation hands it. What the worker reads
//! is checked against that hash, so a package that is not the installed one, or a file that is not
//! the bytes its manifest names, is refused rather than read.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-12.07 | an integrated command resolves to the connector its installed package carries, and to nothing else |
//! | KR-REQ-11.34 | the table a channel is served with is the installed package's own |

use std::path::{Path, PathBuf};

use kr_plugin_sdk::capability::PluginCapability;
use kr_protocol::scalars::Digest256;
use kr_worker::broker::bridge::BridgeSurface;
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
    assert_eq!(connector.integration().command, fixture::COMMAND);
    assert_eq!(connector.integration().flags, fixture::FLAGS);
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

/// An integration's command must be a command name one of the package's match rules recognises:
/// a path is not one, and neither is another application's name.
#[test]
fn a_command_the_package_does_not_recognise_is_refused() {
    let store = Store::new("command");
    let valid = store.package();
    InstalledConnector::read(valid.clone()).expect("the package as installed is read");
    for command in ["bin/claude", "/usr/local/bin/claude", "codex", ""] {
        let mut source = valid.clone();
        source.integration.command = command.to_owned();
        let refusal = InstalledConnector::read(source).expect_err("refused");
        assert!(
            refusal.detail.contains("command name") || refusal.detail.contains("match rules"),
            "{command:?}: {}",
            refusal.detail
        );
    }
}
