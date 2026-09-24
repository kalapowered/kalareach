//! The connectors this worker may launch and serve, read from their installed packages.
//!
//! A connector is a catalogue package that carries a `connector.json`: the table that says how an
//! application's protocol frames, routes and classifies, and how a pending approval is answered.
//! The worker takes one from the installed package and from nowhere else. The installation hands
//! the worker what it installed (the package's hash, where its extracted copy is, the command the
//! integration resolves, the native bridge the recipe put in place and the capabilities the
//! installation granted), and [`InstalledConnector::read`] reads the table out of that copy and
//! checks it before anything uses it.
//!
//! # What is checked, and what is not
//!
//! The package is checked with the SDK's own package check, the one a publisher's build and the
//! catalogue pipeline run, so a package this reads is one they would accept. Its hash is its
//! manifest's digest, and the manifest names every other file by digest, so the manifest that
//! hashes to the installed hash vouches for every byte of the table. A signature over that hash is
//! verified once, where the package is installed; the worker does not link the catalogue and
//! verifies the chain the signature covers.
//!
//! A table is never taken from what the installation says about it: only the file in the package
//! directory, checked against the installed hash, is read.
//!
//! # Replacing the set
//!
//! The installation's view is whole each time it is handed over, so [`ConnectorSources::replace`]
//! replaces the whole set at once. A backend already established keeps the connector it was
//! established with: an upgrade affects new launches.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::connector::ConnectorManifest;
use kr_plugin_sdk::plugin::PluginManifest;
use kr_protocol::ids::PluginId;
use kr_protocol::scalars::Digest256;

use crate::broker::bridge::{BridgeSurface, InstalledBridge};

/// The command an integration resolves, and the flags it adds to an invocation of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorCommand {
    /// The command name a person types, with no directory.
    pub command: String,
    /// The flags the integration adds, each one element of the argument vector.
    pub flags: Vec<String>,
}

/// The native bridge an installation put in place for a connector's application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeFacts {
    /// The application name the installed registration invokes the forwarder for.
    pub application: String,
    /// The registrations the installed recipe wrote.
    pub surfaces: BTreeSet<BridgeSurface>,
    /// The forwarder executable the installed registration starts.
    pub forwarder: PathBuf,
}

/// What an installation hands the worker for one installed package that carries a connector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorSource {
    /// The installed package's hash, which is the digest of its manifest.
    pub package_digest: Digest256,
    /// Where the package's extracted copy is.
    pub package_dir: PathBuf,
    /// The command the integration resolves, and its flags.
    pub integration: ConnectorCommand,
    /// The native bridge the installation put in place, where it put one.
    pub bridge: Option<BridgeFacts>,
    /// The capabilities the installation granted, which bound what the package may do here.
    pub granted: BTreeSet<PluginCapability>,
}

/// Why a connector source was not read into a connector.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{detail}")]
pub struct ConnectorRefusal {
    /// What was wrong, for the doctor and the log.
    pub detail: String,
}

impl ConnectorRefusal {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

/// A connector read from its installed package, and checked.
#[derive(Clone, Debug)]
pub struct InstalledConnector {
    source: ConnectorSource,
    manifest: PluginManifest,
    table: ConnectorManifest,
}

impl InstalledConnector {
    /// Reads one connector out of its installed package and checks it.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorRefusal`] naming the first thing that does not hold: the package fails
    /// the SDK's package check (a file that is not the bytes the manifest names, or a table for
    /// another package, among them), its manifest does not hash to the installed hash, it carries
    /// no table, no match rule of the package recognises the command the integration resolves, or
    /// the installation describes a native bridge the package does not declare or was not
    /// granted.
    pub fn read(source: ConnectorSource) -> Result<Self, ConnectorRefusal> {
        let validated = kr_plugin_sdk::validate::validate_package_directory(&source.package_dir);
        if !validated.report.is_valid() {
            let findings: Vec<String> = validated
                .report
                .findings
                .iter()
                .map(ToString::to_string)
                .collect();
            return Err(ConnectorRefusal::new(format!(
                "the package in {} does not pass the package check: {}",
                source.package_dir.display(),
                findings.join("; ")
            )));
        }
        let package = validated.package.ok_or_else(|| {
            ConnectorRefusal::new(format!(
                "the package in {} could not be read",
                source.package_dir.display()
            ))
        })?;
        let manifest_file = package
            .files
            .iter()
            .find(|file| file.path.as_str() == kr_plugin_sdk::package::MANIFEST_FILE)
            .ok_or_else(|| {
                ConnectorRefusal::new(format!(
                    "the package in {} has no manifest",
                    source.package_dir.display()
                ))
            })?;
        if manifest_file.digest.as_bytes() != source.package_digest.as_bytes() {
            return Err(ConnectorRefusal::new(format!(
                "the package in {} is not the installed one: its manifest does not hash to {}",
                source.package_dir.display(),
                kr_plugin_sdk::digest::PayloadDigest::from_bytes(*source.package_digest.as_bytes())
            )));
        }
        // The package check has already refused a table that names another package.
        let plugin_id = package.manifest.plugin_id();
        let table = package.connector.ok_or_else(|| {
            ConnectorRefusal::new(format!("{plugin_id} carries no connector table"))
        })?;
        let command = &source.integration.command;
        if command.is_empty() || command.contains('/') || command.contains('\\') {
            return Err(ConnectorRefusal::new(format!(
                "{plugin_id} integrates {command:?}, which is not a command name"
            )));
        }
        if !package
            .manifest
            .match_rules
            .iter()
            .any(|rule| rule.executable.matches_path(command))
        {
            return Err(ConnectorRefusal::new(format!(
                "{plugin_id} integrates {command:?}, which none of its match rules recognises"
            )));
        }
        if let Some(bridge) = source.bridge.as_ref() {
            if package.manifest.native_bridge.as_ref().is_none() {
                return Err(ConnectorRefusal::new(format!(
                    "the installation describes a native bridge for {plugin_id}, which declares \
                     none"
                )));
            }
            if !source
                .granted
                .contains(&PluginCapability::NativeBridgeInstall)
            {
                return Err(ConnectorRefusal::new(format!(
                    "the installation describes a native bridge for {plugin_id} and was not \
                     granted {}",
                    PluginCapability::NativeBridgeInstall.as_str()
                )));
            }
            if bridge.application.is_empty()
                || bridge.surfaces.is_empty()
                || !bridge.forwarder.is_absolute()
            {
                return Err(ConnectorRefusal::new(format!(
                    "the native bridge installed for {plugin_id} names no application, no \
                     registration or no absolute forwarder"
                )));
            }
        }
        Ok(Self {
            source,
            manifest: package.manifest,
            table,
        })
    }

    /// Returns the package this connector is.
    #[must_use]
    pub fn plugin_id(&self) -> PluginId {
        self.manifest.plugin_id()
    }

    /// Returns the installed package's hash.
    #[must_use]
    pub const fn package_digest(&self) -> Digest256 {
        self.source.package_digest
    }

    /// Returns the package's manifest, as the installed hash names it.
    #[must_use]
    pub const fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    /// Returns the connector's table, read from the installed package.
    #[must_use]
    pub const fn table(&self) -> &ConnectorManifest {
        &self.table
    }

    /// Returns the command the integration resolves, and its flags.
    #[must_use]
    pub const fn integration(&self) -> &ConnectorCommand {
        &self.source.integration
    }

    /// Returns true when the installation granted this capability.
    #[must_use]
    pub fn granted(&self, capability: PluginCapability) -> bool {
        self.source.granted.contains(&capability)
    }

    /// Returns the native bridge installed for this connector's application, where one is.
    #[must_use]
    pub fn installed_bridge(&self) -> Option<InstalledBridge> {
        self.source.bridge.as_ref().map(|bridge| InstalledBridge {
            plugin_id: self.plugin_id(),
            application: bridge.application.clone(),
            surfaces: bridge.surfaces.clone(),
            forwarder: bridge.forwarder.clone(),
        })
    }

    /// Returns true when one of the package's match rules recognises this executable.
    #[must_use]
    pub fn matches_executable(&self, path: &str) -> bool {
        self.manifest
            .match_rules
            .iter()
            .any(|rule| rule.executable.matches_path(path))
    }
}

/// The connectors this worker may launch and serve, by the command each integration resolves.
#[derive(Debug, Default)]
pub struct ConnectorSources {
    by_command: RwLock<BTreeMap<String, Arc<InstalledConnector>>>,
}

impl ConnectorSources {
    /// An empty set: nothing is integrated until an installation hands one over.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the whole set with what the installation handed over now.
    ///
    /// Every source is read and checked; one that fails is left out and returned with its
    /// reason. Two packages that integrate one command name are both left out, because nothing
    /// here can say which of them a person meant.
    pub fn replace(
        &self,
        sources: Vec<ConnectorSource>,
    ) -> Vec<(ConnectorSource, ConnectorRefusal)> {
        let mut refused = Vec::new();
        let mut read: BTreeMap<String, Vec<InstalledConnector>> = BTreeMap::new();
        for source in sources {
            match InstalledConnector::read(source.clone()) {
                Ok(connector) => read
                    .entry(connector.integration().command.clone())
                    .or_default()
                    .push(connector),
                Err(refusal) => refused.push((source, refusal)),
            }
        }
        let mut by_command = BTreeMap::new();
        for (command, mut connectors) in read {
            if connectors.len() == 1 {
                if let Some(connector) = connectors.pop() {
                    by_command.insert(command, Arc::new(connector));
                }
                continue;
            }
            let packages: Vec<String> = connectors
                .iter()
                .map(|connector| connector.plugin_id().to_string())
                .collect();
            for connector in connectors {
                refused.push((
                    connector.source.clone(),
                    ConnectorRefusal::new(format!(
                        "{command:?} is integrated by {}, and one command resolves to one \
                         connector",
                        packages.join(" and ")
                    )),
                ));
            }
        }
        *self
            .by_command
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = by_command;
        refused
    }

    /// Returns the connector whose integration resolves this command name, where one does.
    #[must_use]
    pub fn for_command(&self, command: &str) -> Option<Arc<InstalledConnector>> {
        self.by_command
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(command)
            .cloned()
    }

    /// Returns the connector whose match rules recognise this executable, where exactly one does.
    #[must_use]
    pub fn matching(&self, executable: &str) -> Option<Arc<InstalledConnector>> {
        let held = self
            .by_command
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut matching = held
            .values()
            .filter(|connector| connector.matches_executable(executable));
        let first = matching.next().cloned();
        if matching.next().is_some() {
            return None;
        }
        first
    }
}

/// Builds a connector package the way the catalogue's store extracts one, for this host's tests.
///
/// The package is Claude Code's shape: its Channels table with the decision destination that
/// answers a relayed tool approval, the three bridge files core pins, and a manifest that names
/// every file by digest. It is written under `root` as `packages/<hash>/`, and what comes back is
/// the source an installation would hand over for it. It is compiled away in every shipped build.
#[cfg(feature = "testing")]
pub mod fixture {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use kr_plugin_sdk::capability::PluginCapability;
    use kr_plugin_sdk::digest::PayloadDigest;
    use kr_protocol::scalars::Digest256;

    use super::{BridgeFacts, ConnectorCommand, ConnectorSource};
    use crate::broker::bridge::BridgeSurface;

    /// The command Claude Code's integration resolves.
    pub const COMMAND: &str = "claude";

    /// The flag and value that load the package's channel, each one element.
    pub const FLAGS: [&str; 2] = [
        "--dangerously-load-development-channels",
        "plugin:kalareach-channels@skills-dir",
    ];

    /// The upstream version the fixture's table is qualified for.
    pub const QUALIFIED_VERSION: &str = "2.1.278";

    const HOOKS: &[u8] = include_bytes!("../../../../fixtures/bridges/claude-code/hooks.json");
    const SERVERS: &[u8] =
        include_bytes!("../../../../fixtures/bridges/claude-code/mcp-servers.json");
    const PLUGIN: &[u8] =
        include_bytes!("../../../../fixtures/bridges/claude-code/plugin-manifest.json");

    /// The package's Channels table.
    #[must_use]
    pub fn connector_json() -> String {
        let path = |names: &[&str]| {
            serde_json::json!({
                "segments": names
                    .iter()
                    .map(|name| serde_json::json!({ "type": "member", "name": name }))
                    .collect::<Vec<_>>()
            })
        };
        let table = serde_json::json!({
            "manifest_version": 1,
            "plugin_id": "kalareach/claude-code",
            "protocol": {
                "name": "claude-code-channels",
                "qualified_range": format!("={QUALIFIED_VERSION}"),
                "tested_version": QUALIFIED_VERSION
            },
            "transport": "private_socket",
            "framing": { "type": "line_delimited_json", "max_message_bytes": "1048576" },
            "request_id_path": path(&["params", "request_id"]),
            "method_path": path(&["method"]),
            "response_correlation": { "type": "matching_id", "id_path": path(&["params", "request_id"]) },
            "routes": [
                { "method": "channel.event", "wire_name": "notifications/claude/channel", "direction": "host_to_upstream" },
                { "method": "channel.permission-request", "wire_name": "notifications/claude/channel/permission_request", "direction": "upstream_to_host" },
                { "method": "channel.permission", "wire_name": "notifications/claude/channel/permission", "direction": "host_to_upstream" }
            ],
            "methods": [
                { "method": "channel.event", "class": "mutation", "evidence": "Delivers a message into the session" },
                { "method": "channel.permission-request", "class": "mutation", "evidence": "A tool call the session is waiting on" },
                { "method": "channel.permission", "class": "mutation", "evidence": "Answers the pending request named by request_id" }
            ],
            "decision_destination": {
                "answers": "channel.permission-request",
                "method": "channel.permission",
                "request_id_path": path(&["params", "request_id"]),
                "decision_path": path(&["params", "behavior"]),
                "decisions": [
                    { "decision": "allow", "value": "allow" },
                    { "decision": "deny", "value": "deny" }
                ]
            },
            "volatile_forwarding": false,
            "qualification_note": "A test fixture shaped like the Claude Code connector."
        });
        serde_json::to_string_pretty(&table).expect("a literal table encodes")
    }

    /// The package's presentation: a document that names no action.
    #[must_use]
    pub fn presentation_json() -> String {
        serde_json::to_string_pretty(&serde_json::json!({
            "manifest_version": 1,
            "base_revision": "1",
            "nodes": [{
                "id": "session",
                "revision": "1",
                "body": { "kind": "markdown", "source": "Claude Code, with its channel and its hooks." }
            }],
            "voice": { "status_nodes": ["session"], "choice_controls": [], "detail_nodes": ["session"] }
        }))
        .expect("a literal presentation encodes")
    }

    fn payload(role: &str, path: &str, bytes: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "role": role,
            "path": path,
            "digest": PayloadDigest::of(bytes).to_string(),
            "size_bytes": bytes.len().to_string(),
        })
    }

    /// The package's manifest, naming each file by the digest of `files`.
    #[must_use]
    pub fn manifest_json(files: &[(&str, &str, Vec<u8>)]) -> String {
        let digest_of = |wanted: &str| {
            files
                .iter()
                .find(|(_, path, _)| *path == wanted)
                .map(|(_, _, bytes)| PayloadDigest::of(bytes).to_string())
                .expect("the file is in the package")
        };
        let text = |name: &str| {
            serde_json::json!({
                "parameters": [{
                    "name": name,
                    "kind": { "type": "text", "max_length": 8000, "multiline": true },
                    "label": "Message",
                    "required": true
                }]
            })
        };
        let manifest = serde_json::json!({
            "manifest_version": 1,
            "publisher_id": "kalareach",
            "plugin_name": "claude-code",
            "version": "0.3.0",
            "display_name": "Claude Code",
            "description": "Recognises Claude Code, observes it through hooks and answers its relayed tool approvals.",
            "sdk_range": ">=0.1.1, <0.2.0",
            "wit_range": ">=0.1.0, <0.2.0",
            "source": {
                "repository": "https://github.com/kalapowered/kalareach-plugins",
                "revision": "refs/tags/claude-code-0.3.0"
            },
            "match_rules": [{
                "id": "claude-code-executable",
                "executable": { "file_stem": "claude", "path_suffix": [], "version_range": null },
                "distribution": null,
                "confidence": "inferred"
            }],
            "platforms": [
                { "os": "linux", "architectures": ["x86_64", "aarch64"] },
                { "os": "mac_os", "architectures": ["aarch64"] }
            ],
            "payloads": files
                .iter()
                .map(|(role, path, bytes)| payload(role, path, bytes))
                .collect::<Vec<_>>(),
            "capabilities": [
                { "capability": "metadata.match", "reason": "Recognise Claude Code" },
                { "capability": "presentation.declarative", "reason": "Show the session" },
                { "capability": "broker.semantic_events", "reason": "Read the hooks' observations" },
                { "capability": "upstream.action", "reason": "Deliver a message into the session" },
                { "capability": "native_bridge.install", "reason": "Register the forwarder Claude Code starts" },
                { "capability": "approval.decode", "reason": "Recognise a relayed tool approval" },
                { "capability": "approval.respond", "reason": "Answer a relayed tool approval" }
            ],
            "actions": [
                {
                    "id": "prompt.send",
                    "label": "Send",
                    "effect": "upstream.prompt",
                    "implementation": {
                        "type": "upstream_method",
                        "method": "channel.event",
                        "bindings": [{
                            "parameter": "text",
                            "field": { "segments": [
                                { "type": "member", "name": "params" },
                                { "type": "member", "name": "content" }
                            ] }
                        }]
                    },
                    "parameters": text("text"),
                    "description": "Deliver a message into the session",
                    "confirmation_required": false
                },
                {
                    "id": "approval.answer",
                    "label": "Answer",
                    "effect": "approval.respond",
                    "implementation": { "type": "decision_destination", "decision": "decision" },
                    "parameters": {
                        "parameters": [{
                            "name": "decision",
                            "kind": { "type": "choice", "choices": [
                                { "id": "allow", "label": "Allow" },
                                { "id": "deny", "label": "Deny" }
                            ] },
                            "label": "Decision",
                            "required": true
                        }]
                    },
                    "description": "Answer the tool approval Claude Code is waiting on",
                    "confirmation_required": false
                }
            ],
            "attachments": null,
            "native_bridge": {
                "application": "Claude Code",
                "application_range": ">=2.1.234, <3.0.0",
                "install": [
                    { "type": "install_file", "source": "bridge/plugin-manifest.json", "destination": "skills/kalareach-channels/.claude-plugin/plugin.json", "digest": digest_of("bridge/plugin-manifest.json") },
                    { "type": "install_file", "source": "bridge/mcp-servers.json", "destination": "skills/kalareach-channels/.mcp.json", "digest": digest_of("bridge/mcp-servers.json") },
                    { "type": "install_file", "source": "bridge/hooks.json", "destination": "skills/kalareach-channels/hooks/hooks.json", "digest": digest_of("bridge/hooks.json") },
                    { "type": "add_configuration_key", "file": "settings.json", "key": "enabledPlugins.kalareach-channels@skills-dir", "value": "true" }
                ],
                "remove": [
                    { "type": "remove_configuration_key", "file": "settings.json", "key": "enabledPlugins.kalareach-channels@skills-dir" },
                    { "type": "remove_file", "destination": "skills/kalareach-channels/hooks/hooks.json", "digest": digest_of("bridge/hooks.json") },
                    { "type": "remove_file", "destination": "skills/kalareach-channels/.mcp.json", "digest": digest_of("bridge/mcp-servers.json") },
                    { "type": "remove_file", "destination": "skills/kalareach-channels/.claude-plugin/plugin.json", "digest": digest_of("bridge/plugin-manifest.json") }
                ],
                "grant_statement": "Installs three registration files under your own Claude Code directory and one settings key; Claude Code then starts the KalaReach forwarder itself, under its own permissions and outside the KalaReach plugin sandbox, outside Wasmtime."
            }
        });
        serde_json::to_string_pretty(&manifest).expect("a literal manifest encodes")
    }

    /// Writes the package under `root` as the store extracts it, and returns what an installation
    /// hands over for it, with every capability the package declares granted.
    ///
    /// # Errors
    ///
    /// Returns what writing a file returned.
    pub fn claude_code_package(root: &Path, forwarder: &Path) -> std::io::Result<ConnectorSource> {
        let files: Vec<(&str, &str, Vec<u8>)> = vec![
            ("connector", "connector.json", connector_json().into_bytes()),
            (
                "presentation",
                "presentation.json",
                presentation_json().into_bytes(),
            ),
            ("native_bridge", "bridge/hooks.json", HOOKS.to_vec()),
            ("native_bridge", "bridge/mcp-servers.json", SERVERS.to_vec()),
            (
                "native_bridge",
                "bridge/plugin-manifest.json",
                PLUGIN.to_vec(),
            ),
        ];
        let manifest = manifest_json(&files);
        let digest = PayloadDigest::of(manifest.as_bytes());
        let directory: PathBuf = root.join("packages").join(digest.to_string());
        std::fs::create_dir_all(directory.join("bridge"))?;
        for (_, path, bytes) in &files {
            std::fs::write(directory.join(path), bytes)?;
        }
        std::fs::write(
            directory.join(kr_plugin_sdk::package::MANIFEST_FILE),
            manifest.as_bytes(),
        )?;
        Ok(ConnectorSource {
            package_digest: Digest256::from_bytes(*digest.as_bytes()),
            package_dir: directory,
            integration: ConnectorCommand {
                command: COMMAND.to_owned(),
                flags: FLAGS.iter().map(|flag| (*flag).to_owned()).collect(),
            },
            bridge: Some(BridgeFacts {
                application: "claude-code".to_owned(),
                surfaces: [BridgeSurface::Hook, BridgeSurface::Channel]
                    .into_iter()
                    .collect(),
                forwarder: forwarder.to_path_buf(),
            }),
            granted: [
                PluginCapability::MetadataMatch,
                PluginCapability::DeclarativePresentation,
                PluginCapability::BrokerSemanticEvents,
                PluginCapability::UpstreamAction,
                PluginCapability::NativeBridgeInstall,
                PluginCapability::ApprovalDecode,
                PluginCapability::ApprovalRespond,
            ]
            .into_iter()
            .collect::<BTreeSet<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn a_command_resolves_to_one_connector_or_none() {
        let sources = ConnectorSources::new();
        assert!(sources.for_command("claude").is_none());
        let refused = sources.replace(Vec::new());
        assert!(refused.is_empty());
        assert!(sources.matching("/usr/local/bin/claude").is_none());
    }

    #[test]
    fn a_path_is_not_a_command_name() {
        let source = ConnectorSource {
            package_digest: Digest256::from_bytes([0; 32]),
            package_dir: Path::new("/nonexistent").to_path_buf(),
            integration: ConnectorCommand {
                command: "bin/claude".to_owned(),
                flags: Vec::new(),
            },
            bridge: None,
            granted: BTreeSet::new(),
        };
        assert!(InstalledConnector::read(source).is_err());
    }
}
