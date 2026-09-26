//! The connectors this worker may launch and serve, read from their installed packages.
//!
//! A connector is a catalogue package that carries a `connector.json`: the table that says how an
//! application's protocol frames, routes and classifies, and how a pending approval is answered.
//! The worker takes one from the installed package and from nowhere else. The installation hands
//! the worker what it installed (the package's hash, where its extracted copy is, the native
//! bridge the recipe put in place and the capabilities the installation granted), and
//! [`InstalledConnector::read`] reads the table and the command integration out of that copy and
//! checks them before anything uses them.
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
//! directory, checked against the installed hash, is read. The same holds for the command
//! integration: the command, the flags it adds and the variables it sets are the verified
//! manifest's own, which the owner confirmed with the release, and they apply only while the
//! installation holds `command_integration.launch`.
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
use kr_plugin_sdk::connector::{ConnectorManifest, RouteDirection};
use kr_plugin_sdk::effect::{ActionImplementation, ParameterKind};
use kr_plugin_sdk::plugin::PluginManifest;
use kr_protocol::broker::{DecodingTrust, OfferedDecision};
use kr_protocol::ids::{PluginId, PublisherId, UpstreamMethod};
use kr_protocol::scalars::{CanonicalSet, Digest256, TimestampMs, U64};
use kr_protocol::session::EnvironmentVariable;

use crate::broker::PackageIdentity;
use crate::broker::bridge::{BridgeSurface, InstalledBridge};

/// The command an integration resolves, the flags it adds to an invocation of it and the variables
/// it sets for that invocation, as the verified manifest declares them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorCommand {
    /// The command name a person types, with no directory.
    pub command: String,
    /// The flags the integration adds, each one element of the argument vector, in order.
    pub flags: Vec<String>,
    /// The variables the integration sets for the invocation, in order.
    pub variables: Vec<EnvironmentVariable>,
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

/// One executable a signed qualification record of the connector names: its digest and the
/// version it is.
///
/// The version of an application is taken from here and nowhere else: a record that names the
/// digest of the exact bytes says what those bytes are, and a file beside the executable says
/// nothing that ties it to them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QualifiedExecutable {
    /// The SHA-256 digest of the executable the record names.
    pub digest: Digest256,
    /// The version the record says it is.
    pub version: String,
}

/// What an installation hands the worker for one installed package that carries a connector.
///
/// It says nothing about the package's command integration: the worker reads that from the package
/// itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorSource {
    /// The installed package's hash, which is the digest of its manifest.
    pub package_digest: Digest256,
    /// Where the package's extracted copy is.
    pub package_dir: PathBuf,
    /// The native bridge the installation put in place, where it put one.
    pub bridge: Option<BridgeFacts>,
    /// The capabilities the installation granted, which bound what the package may do here.
    pub granted: BTreeSet<PluginCapability>,
    /// The executables the connector's signed qualification records name.
    pub qualified: Vec<QualifiedExecutable>,
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
    package: PackageIdentity,
    integration: Option<ConnectorCommand>,
    /// The application the integration's flags register the forwarder's hook for, where they
    /// register one: the package's own name.
    flag_hook: Option<String>,
}

impl InstalledConnector {
    /// Reads one connector out of its installed package and checks it.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorRefusal`] naming the first thing that does not hold: the package fails
    /// the SDK's package check (a file that is not the bytes the manifest names, a table for
    /// another package, or a command integration the contract does not permit, among them), its
    /// manifest does not hash to the installed hash, it carries no table, the installation
    /// describes a native bridge the package does not declare, was not granted or that is another
    /// application's, the integration's flags start the forwarder other than as the package's own
    /// hook or beside the native bridge it installs, or its publisher is not one this host can
    /// record.
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
            // A bridge admitted for a launch is the package's own, whatever registered it.
            if bridge.application != package.manifest.plugin_name.as_str() {
                return Err(ConnectorRefusal::new(format!(
                    "the native bridge installed for {plugin_id} starts the forwarder for {:?}, \
                     which is not the package's own",
                    bridge.application
                )));
            }
        }
        let flag_hook = match package.manifest.command_integration.as_ref() {
            None => None,
            Some(declared) => {
                registered_hook(&declared.flags, package.manifest.plugin_name.as_str()).map_err(
                    |why| ConnectorRefusal::new(format!("{plugin_id}'s integration {why}")),
                )?
            }
        };
        if flag_hook.is_some() && package.manifest.native_bridge.is_present() {
            return Err(ConnectorRefusal::new(format!(
                "{plugin_id}'s integration starts {FORWARDER} beside the native bridge the package \
                 installs, and a launch's bridge comes from one of them"
            )));
        }
        let publisher_id =
            PublisherId::new(package.manifest.publisher_id.as_str()).map_err(|error| {
                ConnectorRefusal::new(format!(
                    "{plugin_id}'s publisher is not one this host can record: {error}"
                ))
            })?;
        let identity = PackageIdentity {
            plugin_id,
            publisher_id,
            package_digest: source.package_digest,
        };
        // The package check has already held the declaration to the contract. It applies only
        // while the installation holds the capability the owner confirmed it under.
        let integration = package
            .manifest
            .command_integration
            .as_ref()
            .filter(|_| {
                source
                    .granted
                    .contains(&PluginCapability::CommandIntegrationLaunch)
            })
            .map(|declared| ConnectorCommand {
                command: declared.command.clone(),
                flags: declared.flags.clone(),
                variables: declared
                    .variables
                    .iter()
                    .map(|variable| EnvironmentVariable {
                        name: variable.name.clone(),
                        value: variable.value.clone(),
                    })
                    .collect(),
            });
        Ok(Self {
            source,
            manifest: package.manifest,
            table,
            package: identity,
            integration,
            flag_hook,
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

    /// Returns the installed package: its identifier, its publisher and its hash.
    ///
    /// This is what the package's tables are pinned with, and what a binding of it runs.
    #[must_use]
    pub const fn package(&self) -> &PackageIdentity {
        &self.package
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

    /// Returns the command integration the verified manifest declares, where it declares one and
    /// the installation holds `command_integration.launch`.
    #[must_use]
    pub const fn integration(&self) -> Option<&ConnectorCommand> {
        self.integration.as_ref()
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

    /// Returns the bridge a launch of this connector admits: the one the installation put in
    /// place, or else the hook the integration's own flags register for the launch.
    ///
    /// `launcher` is this installation's own `kr-hook`. A hook the flags register names the
    /// forwarder as a bare command, which the application finds on the launch's search path, and
    /// a hook is admitted only when the process it runs is this file.
    #[must_use]
    pub fn launch_bridge(&self, launcher: &std::path::Path) -> Option<InstalledBridge> {
        if let Some(installed) = self.installed_bridge() {
            return Some(installed);
        }
        self.integration.as_ref()?;
        let application = self.flag_hook.clone()?;
        Some(InstalledBridge {
            plugin_id: self.plugin_id(),
            application,
            surfaces: std::iter::once(BridgeSurface::Hook).collect(),
            forwarder: launcher.to_path_buf(),
        })
    }

    /// Returns the version a signed qualification record names for an executable with this digest,
    /// where one does.
    #[must_use]
    pub fn qualified_version(&self, digest: &Digest256) -> Option<&str> {
        self.source
            .qualified
            .iter()
            .find(|qualified| &qualified.digest == digest)
            .map(|qualified| qualified.version.as_str())
    }

    /// Returns true when one of the package's match rules recognises this executable.
    #[must_use]
    pub fn matches_executable(&self, path: &str) -> bool {
        self.manifest
            .match_rules
            .iter()
            .any(|rule| rule.executable.matches_path(path))
    }

    /// Returns true when one of the package's match rules recognises `command` in the directory
    /// the shell resolved it to, `executable` being the file it found there.
    ///
    /// A shell resolves a command name to the file of that name in a directory on its search path,
    /// so the rule's name is held to the command and its directories to where the file is: a rule
    /// that names the directory its application installs into does not recognise the same name
    /// anywhere else.
    #[must_use]
    pub fn recognises(&self, command: &str, executable: &str) -> bool {
        let executable = executable.replace('\\', "/");
        let Some((directory, _)) = executable.rsplit_once('/') else {
            return false;
        };
        self.matches_executable(&format!("{directory}/{command}"))
    }

    /// Returns the decisions a declarative interpretation offers: the ones the table's decision
    /// destination maps, in the table's order, each labelled as the package's answer action labels
    /// that choice, or with its own name where the action names none.
    #[must_use]
    pub fn offered_decisions(&self) -> Vec<OfferedDecision> {
        let Some(destination) = self.table.decision_destination.as_ref() else {
            return Vec::new();
        };
        let choices =
            self.manifest
                .actions
                .iter()
                .find_map(|action| match &action.implementation {
                    ActionImplementation::DecisionDestination { decision } => action
                        .parameters
                        .parameters
                        .iter()
                        .find(|parameter| &parameter.name == decision)
                        .and_then(|parameter| match &parameter.kind {
                            ParameterKind::Choice { choices } => Some(choices),
                            _ => None,
                        }),
                    _ => None,
                });
        destination
            .decisions
            .iter()
            .map(|mapped| {
                let label = choices
                    .and_then(|choices| {
                        choices
                            .iter()
                            .find(|choice| choice.id == mapped.decision)
                            .map(|choice| choice.label.to_string())
                    })
                    .unwrap_or_else(|| mapped.decision.to_string());
                OfferedDecision {
                    option_id: mapped.decision.to_string(),
                    label,
                }
            })
            .collect()
    }
}

/// The forwarder's name, as a registration names it.
const FORWARDER: &str = "kr-hook";

/// Returns the application an integration's flags register the forwarder's hook for, where they
/// register one.
///
/// The forwarder may appear in a flag in one form only, the one the host applies to a native
/// bridge's files: a JSON object whose `command` is exactly `kr-hook` and whose `args` are the
/// application and `hook`. A launch's flags register only a hook, and only for `own`, the package's
/// own name. Any other mention of the forwarder, in any letter case, a shell command that runs it,
/// a path to it, an argument naming it or a flag that is not JSON, is refused, so no flag starts it
/// in a way the launch's bridge does not account for.
fn registered_hook(flags: &[String], own: &str) -> Result<Option<String>, String> {
    let mut applications = BTreeSet::new();
    for flag in flags {
        match serde_json::from_str::<serde_json::Value>(flag) {
            Ok(document) => forwarder_invocations(&document, &mut applications)?,
            Err(_) if names_forwarder(flag) => {
                return Err(format!(
                    "names {FORWARDER} in {flag:?}, and a launch starts it only as a hook's own \
                     command with its arguments"
                ));
            }
            Err(_) => {}
        }
    }
    if let Some(other) = applications.iter().find(|application| *application != own) {
        return Err(format!(
            "starts {FORWARDER} for {other:?}, and a launch's hooks are the package's own"
        ));
    }
    Ok(applications.into_iter().next())
}

/// Returns true when text names the forwarder, whatever the letter case: a file system that ignores
/// case finds the forwarder under any spelling.
fn names_forwarder(text: &str) -> bool {
    text.to_ascii_lowercase().contains(FORWARDER)
}

fn forwarder_invocations(
    value: &serde_json::Value,
    applications: &mut BTreeSet<String>,
) -> Result<(), String> {
    match value {
        serde_json::Value::Object(members) => {
            let registration =
                members.get("command").and_then(serde_json::Value::as_str) == Some(FORWARDER);
            if registration {
                let arguments = members.get("args").and_then(serde_json::Value::as_array);
                let words: Vec<&str> = arguments
                    .map(|arguments| {
                        arguments
                            .iter()
                            .filter_map(serde_json::Value::as_str)
                            .collect()
                    })
                    .unwrap_or_default();
                match (words.as_slice(), arguments.map(Vec::len)) {
                    ([application, "hook"], Some(2)) => {
                        applications.insert((*application).to_owned());
                    }
                    _ => {
                        return Err(format!(
                            "starts {FORWARDER} with {words:?}, and a launch registers only a hook"
                        ));
                    }
                }
            }
            for (member, nested) in members {
                // The registration's own command is the one place the forwarder's name may be.
                if registration && member == "command" {
                    continue;
                }
                forwarder_invocations(nested, applications)?;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                forwarder_invocations(item, applications)?;
            }
        }
        serde_json::Value::String(text) if names_forwarder(text) => {
            return Err(format!(
                "names {FORWARDER} in {text:?}, and a launch starts it only as a hook's own \
                 command with its arguments"
            ));
        }
        _ => {}
    }
    Ok(())
}

/// The projection schema a request read from a connector's own decision destination is written
/// against.
pub const DECISION_SCHEMA: &str = "kalareach.decision/1";

/// Returns the projection schema a component's decoded request is written against.
///
/// It is the plugin contract's own, named for the WIT version this build speaks
/// (`kalareach.plugin.decoded-request/<WIT version>`): the worker writes it when it converts what a
/// component decoded, and a component cannot choose it.
#[must_use]
pub fn component_schema() -> String {
    format!(
        "kalareach.plugin.decoded-request/{}",
        kr_plugin_sdk::version::WIT_VERSION
    )
}

/// Returns the decoding trust an installation's grants give its connector's package, where they
/// give any.
///
/// The trust is derived from what the installation was granted and from the installed package's
/// own connector table, and never from anything a component reports: none unless `approval.decode`
/// is granted; the package, publisher and installed hash are the installed package's; the methods
/// are the wire names of the routes that carry, towards this host, what the table's decision
/// destination answers; the schemas are [`DECISION_SCHEMA`], and [`component_schema`] as well when
/// the package ships a component; at most as many decisions as the destination maps; and it may
/// encode an answer exactly when `approval.respond` is granted.
///
/// The decision destination is the one statement of which routed request asks for a decision, so a
/// package whose table has none, or whose answers are responses to the request rather than a
/// request of their own, is given no trust here.
#[must_use]
pub fn decoding_trust(connector: &InstalledConnector, now: TimestampMs) -> Option<DecodingTrust> {
    if !connector.granted(PluginCapability::ApprovalDecode) {
        return None;
    }
    let table = connector.table();
    let destination = table.decision_destination.as_ref()?;
    let methods: CanonicalSet<UpstreamMethod> = table
        .routes
        .iter()
        .filter(|route| {
            route.method == destination.answers && route.direction != RouteDirection::HostToUpstream
        })
        .filter_map(|route| UpstreamMethod::new(route.wire_name.clone()).ok())
        .collect();
    if methods.is_empty() {
        return None;
    }
    let mut schema_versions: CanonicalSet<String> =
        std::iter::once(DECISION_SCHEMA.to_owned()).collect();
    if connector.manifest().has_component() {
        schema_versions.insert(component_schema());
    }
    let package = connector.package();
    Some(DecodingTrust {
        plugin_id: package.plugin_id.clone(),
        publisher_id: package.publisher_id.clone(),
        package_digest: package.package_digest,
        methods,
        schema_versions,
        max_decisions: U64::new(u64::try_from(destination.decisions.len()).unwrap_or(u64::MAX)),
        may_encode_response: connector.granted(PluginCapability::ApprovalRespond),
        granted_at: now,
    })
}

/// The connectors this worker may launch and serve: every connector an installation handed over,
/// and, by the command each integration resolves, the ones that integrate a command.
#[derive(Debug, Default)]
pub struct ConnectorSources {
    held: RwLock<Held>,
}

/// One whole set, replaced at once.
#[derive(Debug, Default)]
struct Held {
    /// Every connector read and not refused, whether or not it integrates a command.
    connectors: Vec<Arc<InstalledConnector>>,
    /// The connectors whose integration applies, by the command it resolves.
    by_command: BTreeMap<String, Arc<InstalledConnector>>,
}

impl ConnectorSources {
    /// An empty set: nothing is integrated until an installation hands one over.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true while no connector has been handed over.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.held
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .connectors
            .is_empty()
    }

    /// Replaces the whole set with what the installation handed over now.
    ///
    /// Every source is read and checked; one that fails is left out and returned with its
    /// reason. A connector that integrates no command is held for matching and resolves no
    /// command. Two packages that integrate one command name are both left out, because nothing
    /// here can say which of them a person meant.
    pub fn replace(
        &self,
        sources: Vec<ConnectorSource>,
    ) -> Vec<(ConnectorSource, ConnectorRefusal)> {
        let mut refused = Vec::new();
        let mut connectors = Vec::new();
        let mut integrating: BTreeMap<String, Vec<InstalledConnector>> = BTreeMap::new();
        for source in sources {
            match InstalledConnector::read(source.clone()) {
                Ok(connector) => match connector
                    .integration()
                    .map(|integration| integration.command.clone())
                {
                    Some(command) => integrating.entry(command).or_default().push(connector),
                    None => connectors.push(Arc::new(connector)),
                },
                Err(refusal) => refused.push((source, refusal)),
            }
        }
        let mut by_command = BTreeMap::new();
        for (command, mut claimed) in integrating {
            if claimed.len() == 1 {
                if let Some(connector) = claimed.pop() {
                    let connector = Arc::new(connector);
                    connectors.push(Arc::clone(&connector));
                    by_command.insert(command, connector);
                }
                continue;
            }
            let packages: Vec<String> = claimed
                .iter()
                .map(|connector| connector.plugin_id().to_string())
                .collect();
            for connector in claimed {
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
            .held
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Held {
            connectors,
            by_command,
        };
        refused
    }

    /// Returns the connector whose integration resolves this command name, where one does.
    #[must_use]
    pub fn for_command(&self, command: &str) -> Option<Arc<InstalledConnector>> {
        self.held
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .by_command
            .get(command)
            .cloned()
    }

    /// Returns the connector whose match rules recognise this executable, where exactly one does.
    #[must_use]
    pub fn matching(&self, executable: &str) -> Option<Arc<InstalledConnector>> {
        let held = self
            .held
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut matching = held
            .connectors
            .iter()
            .filter(|connector| connector.matches_executable(executable));
        let first = matching.next().cloned();
        if matching.next().is_some() {
            return None;
        }
        first
    }
}

/// Builds connector packages the way the catalogue's store extracts one, for this host's tests.
///
/// The packages are Claude Code's shape: its Channels table with the decision destination that
/// answers a relayed tool approval, and a manifest that names every file by digest and declares the
/// package's command integration. Claude Code's own also carries the three bridge files core pins;
/// [`Shape`] gives the other shapes the tests need. A package is written under `root` as
/// `packages/<hash>/`, and what comes back is the source an installation would hand over for it.
/// It is compiled away in every shipped build.
#[cfg(feature = "testing")]
pub mod fixture {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use kr_plugin_sdk::capability::PluginCapability;
    use kr_plugin_sdk::digest::PayloadDigest;
    use kr_protocol::scalars::Digest256;

    use super::{BridgeFacts, ConnectorSource};

    /// The digest of the Claude Code executable the connector is qualified against, macOS arm64.
    pub const QUALIFIED_DIGEST: [u8; 32] = [
        0xbd, 0x24, 0x56, 0x62, 0xfb, 0x8a, 0x0e, 0x32, 0x1b, 0x3b, 0xf1, 0x33, 0xe9, 0x30, 0x37,
        0x1d, 0x65, 0x63, 0xc3, 0x87, 0x52, 0x78, 0x85, 0xf3, 0x0b, 0x26, 0x13, 0xae, 0xf3, 0xba,
        0x14, 0xd6,
    ];
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
    const QODER_FLAGS: &[u8] = include_bytes!("../../../../fixtures/bridges/qoder-cli/flags.json");

    /// What one test package is.
    #[derive(Clone, Debug)]
    pub struct Shape {
        /// The package's name under the `kalareach` publisher, which its table names too.
        pub plugin_name: &'static str,
        /// The name a person reads.
        pub display_name: &'static str,
        /// The executable name the package's one match rule recognises.
        pub executable: &'static str,
        /// The directories that rule requires the executable to be in, innermost last.
        pub directory: &'static [&'static str],
        /// The manifest's `command_integration` member, where it carries one.
        pub integration: Option<serde_json::Value>,
        /// Whether the package installs Claude Code's native bridge and the installation put it
        /// in place.
        pub native_bridge: bool,
        /// Whether the package ships a component.
        pub component: bool,
    }

    impl Shape {
        /// Claude Code's package: its channel's two flags, and its native bridge in place.
        #[must_use]
        pub fn claude_code() -> Self {
            Self {
                plugin_name: "claude-code",
                display_name: "Claude Code",
                executable: COMMAND,
                directory: &[],
                integration: Some(declaration(COMMAND, &FLAGS, &[])),
                native_bridge: true,
                component: false,
            }
        }

        /// A Gemini CLI package whose integration sets `GEMINI_CLI_NO_RELAUNCH=true` and adds
        /// `flags`, with no bridge in place.
        #[must_use]
        pub fn gemini_cli(flags: &[&str]) -> Self {
            Self {
                plugin_name: "gemini-cli",
                display_name: "Gemini CLI",
                executable: "gemini",
                directory: &[],
                integration: Some(declaration(
                    "gemini",
                    flags,
                    &[("GEMINI_CLI_NO_RELAUNCH", "true")],
                )),
                native_bridge: false,
                component: false,
            }
        }

        /// A Qoder CLI package whose integration adds the two launch elements core pins, which
        /// register the forwarder's hook, with no bridge in place.
        #[must_use]
        pub fn qoder_cli() -> Self {
            let flags = qoder_flags();
            let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
            Self {
                plugin_name: "qoder-cli",
                display_name: "Qoder CLI",
                executable: "qodercli",
                directory: &[],
                integration: Some(declaration("qodercli", &flags, &[])),
                native_bridge: false,
                component: false,
            }
        }
    }

    /// The two launch elements core pins for Qoder CLI: `--settings`, and its inline hooks.
    ///
    /// # Panics
    ///
    /// Panics when the pinned file is not a list of text.
    #[must_use]
    pub fn qoder_flags() -> Vec<String> {
        serde_json::from_slice(QODER_FLAGS).expect("the pinned flags are a list of text")
    }

    /// A manifest's `command_integration` member.
    #[must_use]
    pub fn declaration(
        command: &str,
        flags: &[&str],
        variables: &[(&str, &str)],
    ) -> serde_json::Value {
        serde_json::json!({
            "command": command,
            "flags": flags,
            "variables": variables
                .iter()
                .map(|(name, value)| serde_json::json!({ "name": name, "value": value }))
                .collect::<Vec<_>>(),
            "grant_statement": "Starts the agent in KalaReach sessions with what its bridge needs."
        })
    }

    /// Claude Code's Channels table.
    #[must_use]
    pub fn connector_json() -> String {
        connector_json_for("kalareach/claude-code")
    }

    /// The Channels table, for the package `plugin_id`.
    fn connector_json_for(plugin_id: &str) -> String {
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
            "plugin_id": plugin_id,
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

    /// Claude Code's manifest, naming each file by the digest of `files`.
    #[must_use]
    pub fn manifest_json(files: &[(&str, &str, Vec<u8>)]) -> String {
        manifest_for(&Shape::claude_code(), files)
    }

    /// The manifest of a package of `shape`, naming each file by the digest of `files`.
    fn manifest_for(shape: &Shape, files: &[(&str, &str, Vec<u8>)]) -> String {
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
        let mut capabilities = vec![
            serde_json::json!({ "capability": "metadata.match", "reason": format!("Recognise {}", shape.display_name) }),
            serde_json::json!({ "capability": "presentation.declarative", "reason": "Show the session" }),
            serde_json::json!({ "capability": "broker.semantic_events", "reason": "Read the hooks' observations" }),
            serde_json::json!({ "capability": "upstream.action", "reason": "Deliver a message into the session" }),
        ];
        if shape.native_bridge {
            capabilities.push(serde_json::json!({ "capability": "native_bridge.install", "reason": "Register the forwarder Claude Code starts" }));
        }
        capabilities.push(serde_json::json!({ "capability": "approval.decode", "reason": "Recognise a relayed tool approval" }));
        capabilities.push(serde_json::json!({ "capability": "approval.respond", "reason": "Answer a relayed tool approval" }));
        if shape.integration.is_some() {
            capabilities.push(serde_json::json!({ "capability": "command_integration.launch", "reason": "Start the agent with the flags its bridge needs" }));
        }
        let mut manifest = serde_json::json!({
            "manifest_version": 1,
            "publisher_id": "kalareach",
            "plugin_name": shape.plugin_name,
            "version": "0.3.0",
            "display_name": shape.display_name,
            "description": format!("Recognises {}, observes it through hooks and answers its relayed tool approvals.", shape.display_name),
            "sdk_range": ">=0.1.2, <0.2.0",
            "wit_range": ">=0.1.0, <0.2.0",
            "source": {
                "repository": "https://github.com/kalapowered/kalareach-plugins",
                "revision": format!("refs/tags/{}-0.3.0", shape.plugin_name)
            },
            "match_rules": [{
                "id": format!("{}-executable", shape.plugin_name),
                "executable": { "file_stem": shape.executable, "path_suffix": shape.directory, "version_range": null },
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
            "capabilities": capabilities,
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
                    "description": format!("Answer the tool approval {} is waiting on", shape.display_name),
                    "confirmation_required": false
                }
            ],
            "attachments": null,
            "native_bridge": null
        });
        if shape.native_bridge {
            manifest["native_bridge"] = serde_json::json!({
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
            });
        }
        if let Some(integration) = &shape.integration {
            manifest["command_integration"] = integration.clone();
        }
        serde_json::to_string_pretty(&manifest).expect("a literal manifest encodes")
    }

    /// Returns the same installation, granted to read files too: a connector whose launch is
    /// granted the directory it was resolved in.
    #[must_use]
    pub fn reading(mut source: ConnectorSource) -> ConnectorSource {
        source.granted.insert(PluginCapability::FilesystemRead);
        source
    }

    /// The bytes the fixture ships as its component: a Wasm component's preamble.
    ///
    /// Nothing here runs a component, and the package check executes nothing, so the fixture's
    /// component is the bytes the manifest names by digest and no more.
    pub const COMPONENT: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];

    /// Writes Claude Code's package under `root` as the store extracts it, and returns what an
    /// installation hands over for it, with every capability the package declares granted.
    ///
    /// # Errors
    ///
    /// Returns what writing a file returned.
    pub fn claude_code_package(root: &Path, forwarder: &Path) -> std::io::Result<ConnectorSource> {
        package(root, forwarder, &Shape::claude_code())
    }

    /// Writes the same package with a Wasm component in it too, and returns what an installation
    /// hands over for it, with every capability the package declares granted.
    ///
    /// # Errors
    ///
    /// Returns what writing a file returned.
    pub fn claude_code_package_with_component(
        root: &Path,
        forwarder: &Path,
    ) -> std::io::Result<ConnectorSource> {
        package(
            root,
            forwarder,
            &Shape {
                component: true,
                ..Shape::claude_code()
            },
        )
    }

    /// Writes a package of `shape` under `root` as the store extracts it, and returns what an
    /// installation hands over for it, with every capability the package declares granted and,
    /// where the shape has one, the native bridge in place with `forwarder`.
    ///
    /// # Errors
    ///
    /// Returns what writing a file returned.
    pub fn package(
        root: &Path,
        forwarder: &Path,
        shape: &Shape,
    ) -> std::io::Result<ConnectorSource> {
        let plugin_id = format!("kalareach/{}", shape.plugin_name);
        let mut files: Vec<(&str, &str, Vec<u8>)> = vec![
            (
                "connector",
                "connector.json",
                connector_json_for(&plugin_id).into_bytes(),
            ),
            (
                "presentation",
                "presentation.json",
                presentation_json().into_bytes(),
            ),
        ];
        if shape.native_bridge {
            files.push(("native_bridge", "bridge/hooks.json", HOOKS.to_vec()));
            files.push(("native_bridge", "bridge/mcp-servers.json", SERVERS.to_vec()));
            files.push((
                "native_bridge",
                "bridge/plugin-manifest.json",
                PLUGIN.to_vec(),
            ));
        }
        if shape.component {
            files.push((
                "component",
                kr_plugin_sdk::package::COMPONENT_FILE,
                COMPONENT.to_vec(),
            ));
        }
        let manifest = manifest_for(shape, &files);
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
        let mut granted: BTreeSet<PluginCapability> = [
            PluginCapability::MetadataMatch,
            PluginCapability::DeclarativePresentation,
            PluginCapability::BrokerSemanticEvents,
            PluginCapability::UpstreamAction,
            PluginCapability::ApprovalDecode,
            PluginCapability::ApprovalRespond,
        ]
        .into_iter()
        .collect();
        if shape.native_bridge {
            granted.insert(PluginCapability::NativeBridgeInstall);
        }
        if shape.integration.is_some() {
            granted.insert(PluginCapability::CommandIntegrationLaunch);
        }
        Ok(ConnectorSource {
            package_digest: Digest256::from_bytes(*digest.as_bytes()),
            package_dir: directory,
            bridge: shape.native_bridge.then(|| BridgeFacts {
                application: "claude-code".to_owned(),
                surfaces: [BridgeSurface::Hook, BridgeSurface::Channel]
                    .into_iter()
                    .collect(),
                forwarder: forwarder.to_path_buf(),
            }),
            granted,
            qualified: Vec::new(),
        })
    }

    #[cfg(test)]
    mod tests {
        /// The digest the connector's qualification record publishes for that executable, in the
        /// form the record writes it.
        const PUBLISHED: &str = "bd245662fb8a0e321b3bf133e930371d6563c387527885f30b2613aef3ba14d6";

        #[test]
        fn the_qualified_digest_is_the_one_the_qualification_record_publishes() {
            let written: String = super::QUALIFIED_DIGEST
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(written, PUBLISHED);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_resolves_to_one_connector_or_none() {
        let sources = ConnectorSources::new();
        assert!(sources.for_command("claude").is_none());
        let refused = sources.replace(Vec::new());
        assert!(refused.is_empty());
        assert!(sources.matching("/usr/local/bin/claude").is_none());
    }
}
