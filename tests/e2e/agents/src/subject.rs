//! The agent a qualification run is about.
//!
//! A [`Subject`] is read once from the build list entry and the manifest of the package installed
//! for it. A case asks the subject, and no literal, for the plugin identifier, the command a person
//! types, the trees of the person's home that the guards compare, the place the stand-in route
//! puts the program and what the manifest declares of a command integration. A package with no
//! `command_integration` has none, and one with no `backend` has no gateway route, so a case that
//! drives the gateway has nothing to run for it ([`Subject::gateway`]).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::integration::{CommandIntegration, IntegrationBackend};
use kr_plugin_sdk::plugin::PluginManifest;
use kr_protocol::ids::PluginId;

use crate::build::{self, Account, Build, Launch, Probe};
use crate::held;

/// The package whose trees, launch and configuration the driver was written for.
const CODEX_PACKAGE: &str = "kalareach/codex";

/// The route through the host's gateway that a package declares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayRoute {
    /// The application server the terminal speaks to, as the manifest declares it.
    pub backend: IntegrationBackend,
}

/// The agent a run is about.
#[derive(Clone, Debug)]
pub struct Subject {
    /// The build list entry of a real route; none on the stand-in route, which has no entry.
    entry: Option<Build>,
    plugin: PluginId,
    command: String,
    launch: Launch,
    person_trees: Vec<String>,
    integration: Option<CommandIntegration>,
    gateway: Option<GatewayRoute>,
    requested: Vec<PluginCapability>,
    version: String,
    package: Option<PathBuf>,
}

impl Subject {
    /// The Codex subject of the stand-in route, read from the Codex package kept in this crate.
    ///
    /// # Panics
    ///
    /// Panics when the package's manifest cannot be read.
    #[must_use]
    pub fn codex() -> Self {
        let bytes =
            std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("codex-package/plugin.json"))
                .expect("the manifest of the Codex package kept in this crate");
        let manifest: PluginManifest = serde_json::from_slice(&bytes)
            .expect("the Codex package's manifest is a plugin manifest");
        let command = manifest
            .command_integration
            .as_ref()
            .map(|integration| integration.command.clone())
            .expect("the Codex package declares the command it integrates");
        Self::made(
            None,
            &manifest,
            command,
            Launch::Native,
            vec![".codex".to_owned()],
        )
        .expect("the Codex package names itself")
    }

    /// The subject of a build list entry and the manifest of the package installed for it.
    ///
    /// # Errors
    ///
    /// Returns why the manifest is not the entry's package's, or the package's name is not a
    /// plugin identifier.
    pub fn from_build(build: &Build, manifest: &PluginManifest) -> Result<Self, String> {
        // Codex's own directory stays Codex's: an entry of another package names its trees itself.
        let trees = if build.package == CODEX_PACKAGE {
            vec![".codex".to_owned()]
        } else {
            build
                .isolation
                .as_ref()
                .map(|isolation| isolation.person_trees.clone())
                .unwrap_or_default()
        };
        Self::made(
            Some(build.clone()),
            manifest,
            build.command.clone(),
            build.launch,
            trees,
        )
    }

    fn made(
        entry: Option<Build>,
        manifest: &PluginManifest,
        command: String,
        launch: Launch,
        person_trees: Vec<String>,
    ) -> Result<Self, String> {
        let named = format!("{}/{}", manifest.publisher_id, manifest.plugin_name);
        let package = entry
            .as_ref()
            .map_or(named.as_str(), |build| build.package.as_str());
        if package != named {
            return Err(format!(
                "the entry is for the package {package}, and the manifest is the package {named}'s"
            ));
        }
        let plugin = PluginId::new(package)
            .map_err(|error| format!("{package} is not a plugin identifier: {error}"))?;
        let gateway = manifest
            .command_integration
            .as_ref()
            .and_then(|integration| integration.backend.clone())
            .map(|backend| GatewayRoute { backend });
        let mut requested: Vec<PluginCapability> = manifest
            .capabilities
            .iter()
            .map(|request| request.capability)
            .collect();
        requested.sort();
        requested.dedup();
        Ok(Self {
            package: (package == CODEX_PACKAGE)
                .then(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("codex-package")),
            entry,
            plugin,
            command,
            launch,
            person_trees,
            integration: manifest.command_integration.clone(),
            gateway,
            requested,
            version: manifest.version.to_string(),
        })
    }

    /// The plugin identifier of the package.
    #[must_use]
    pub fn plugin(&self) -> PluginId {
        self.plugin.clone()
    }

    /// The command a person types to start the agent.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    /// How a launch of the agent reaches its pinned file.
    #[must_use]
    pub const fn launch(&self) -> Launch {
        self.launch
    }

    /// The directories and files of the person's home that a real run compares before and after.
    #[must_use]
    pub fn person_trees(&self) -> &[String] {
        &self.person_trees
    }

    /// Where the stand-in agent is placed in the run, below its directory.
    #[must_use]
    pub fn place(&self) -> String {
        format!("t/{}", self.command)
    }

    /// What the package declares of a command integration; none where it declares none.
    #[must_use]
    pub const fn integration(&self) -> Option<&CommandIntegration> {
        self.integration.as_ref()
    }

    /// The route through the host's gateway; none where the package declares no backend.
    #[must_use]
    pub const fn gateway(&self) -> Option<&GatewayRoute> {
        self.gateway.as_ref()
    }

    /// Why a case that drives the gateway has nothing to run for this subject: the package declares
    /// no gateway backend. None where the subject has a gateway, where the agent is started by hand
    /// (`by_hand`), and in the probe-only run (`probe_only`), which has an entry point of its own.
    #[must_use]
    pub fn gateway_not_run(&self, by_hand: bool, probe_only: bool) -> Option<String> {
        (!by_hand && !probe_only && self.gateway.is_none()).then(|| {
            format!(
                "the package {} declares no gateway backend, so a part that drives the gateway \
                 has nothing to run for it",
                self.plugin
            )
        })
    }

    /// The entry's account; none on the stand-in route and for an entry that has none.
    #[must_use]
    pub fn account(&self) -> Option<&Account> {
        self.entry.as_ref().and_then(|build| build.account.as_ref())
    }

    /// The line typed at the shell to start the agent: the command, and `extra` after it.
    #[must_use]
    pub fn typed_line(&self, extra: &[&str]) -> String {
        std::iter::once(self.command.as_str())
            .chain(extra.iter().copied())
            .map(build::quote)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The agent's configuration files with the entry's arguments and switches written as the keys
    /// of `config.toml`, `root` and `work` standing for the run's directory and working directory.
    /// With `names_a_provider` the file also names the provider the entry routes the build to.
    ///
    /// # Errors
    ///
    /// Returns why no configuration can be made: the subject has no account, or a word of the
    /// entry stands for no key.
    pub fn configuration(
        &self,
        root: &str,
        work: &str,
        names_a_provider: bool,
    ) -> Result<BTreeMap<String, String>, String> {
        let account = self
            .account()
            .ok_or_else(|| "the subject has no account to write a configuration for".to_owned())?;
        if names_a_provider {
            account.configuration_with_switches("config.toml", root, work)
        } else {
            account.configuration_without_provider("config.toml", root, work)
        }
    }

    /// The arguments an isolation probe runs the agent's program with.
    #[must_use]
    pub fn probe_arguments(&self, probe: &Probe) -> Vec<String> {
        probe.arguments.clone()
    }

    /// The environment a session is created with: `variables`, the harness's own, then the names
    /// of the person's account in `user`, the login's variable, the entry's own variables and its
    /// configuration directory's variable naming `config_directory`, without the variables the
    /// entry clears but for the ones it sets itself.
    #[must_use]
    pub fn session_variables(
        &self,
        mut variables: Vec<(String, String)>,
        user: Vec<(String, String)>,
        login: Option<(String, String)>,
        config_directory: &Path,
    ) -> Vec<(String, String)> {
        variables.extend(user);
        variables.extend(login);
        if let Some(account) = self.account() {
            for (name, value) in &account.variables {
                variables.retain(|(existing, _)| existing != name);
                variables.push((name.clone(), value.clone()));
            }
            if let Some(config) = &account.config_directory {
                variables.retain(|(existing, _)| existing != &config.variable);
                variables.push((
                    config.variable.clone(),
                    config_directory.display().to_string(),
                ));
            }
        }
        if let Some(build) = &self.entry {
            let _ = build.without_provider_keys(&mut variables);
        }
        variables
    }

    /// The capabilities the package's manifest requests.
    #[must_use]
    pub fn requested_capabilities(&self) -> &[PluginCapability] {
        &self.requested
    }

    /// The directory of the package the driver keeps for the subject: the Codex package kept in
    /// this crate; none for another subject.
    #[must_use]
    pub fn package(&self) -> Option<&Path> {
        self.package.as_deref()
    }

    /// The version of the package the manifest declares.
    #[must_use]
    pub fn package_version(&self) -> String {
        self.version.clone()
    }

    /// Where the agent's conversations are, relative to the run's directory; none for a subject
    /// with no account.
    #[must_use]
    pub fn record_location(&self) -> Option<PathBuf> {
        self.account().map(held::conversations_relative)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODEX: &str = "kalareach/codex";

    fn committed() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/fixtures/builds.json")).expect("the list")
    }

    /// The entry of `package` in the committed list, projected as the runner projects it for the
    /// driver.
    fn build_of(package: &str) -> Build {
        let list = committed();
        let entry = list["builds"]
            .as_array()
            .and_then(|entries| entries.iter().find(|entry| entry["package"] == package))
            .unwrap_or_else(|| panic!("the committed list has no entry for {package}"));
        let mut out = serde_json::Map::new();
        for name in [
            "package",
            "application",
            "version",
            "prefix",
            "pinned",
            "sha256",
            "command",
            "launch",
            "arguments",
            "runtime",
            "environment",
            "home",
            "ready",
            "harmless",
            "composer",
            "server",
            "transcript",
            "no_account",
            "no_newer",
            "account",
            "isolation",
            "missing",
        ] {
            if let Some(value) = entry.get(name) {
                out.insert(name.to_owned(), value.clone());
            }
        }
        if let Some(newer) = entry.get("newer").filter(|newer| !newer.is_null()) {
            let mut kept = serde_json::Map::new();
            for name in ["version", "prefix", "pinned", "sha256", "ready", "isolated"] {
                if let Some(value) = newer.get(name) {
                    kept.insert(name.to_owned(), value.clone());
                }
            }
            out.insert("newer".to_owned(), serde_json::Value::Object(kept));
        }
        serde_json::from_value(serde_json::Value::Object(out)).expect("a build")
    }

    /// What a package declares of a command integration.
    #[derive(Clone, Copy)]
    enum Integration {
        /// No member.
        None,
        /// The command, flags and variables, and no backend.
        Flags,
        /// The command, flags and variables, and a backend.
        Backend,
    }

    /// The manifest of the in-tree Codex package, named `name` and declaring `integration`.
    fn manifest(name: &str, integration: Integration) -> PluginManifest {
        let mut json: serde_json::Value = serde_json::from_slice(
            &std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("codex-package/plugin.json"))
                .expect("the in-tree manifest"),
        )
        .expect("a manifest");
        json["plugin_name"] = serde_json::json!(name);
        match integration {
            Integration::None => {
                json.as_object_mut()
                    .expect("an object")
                    .remove("command_integration");
            }
            Integration::Flags => {
                json["command_integration"]
                    .as_object_mut()
                    .expect("an object")
                    .remove("backend");
            }
            Integration::Backend => {}
        }
        serde_json::from_value(json).expect("a manifest")
    }

    /// The Codex subject names the plugin, command, trees and place that the driver wrote as
    /// literals, whether it is made for the stand-in route or from the committed entry.
    #[test]
    fn the_codex_subject_names_the_plugin_command_trees_and_place_the_driver_wrote_as_literals() {
        let stand_in = Subject::codex();
        let entry = Subject::from_build(&build_of(CODEX), &manifest("codex", Integration::Backend))
            .expect("the Codex entry's subject");
        for subject in [&stand_in, &entry] {
            assert_eq!(subject.plugin().to_string(), CODEX);
            assert_eq!(subject.command(), "codex");
            assert_eq!(subject.launch(), Launch::Native);
            assert_eq!(subject.person_trees(), [".codex"]);
            assert_eq!(subject.place(), "t/codex");
            assert!(subject.gateway().is_some(), "Codex declares a backend");
        }
    }

    /// Each other committed entry makes a subject that names its own plugin, command and trees,
    /// and none has a gateway.
    #[test]
    fn a_subject_of_each_other_committed_entry_names_its_own_plugin_command_and_trees() {
        let table: [(&str, &str, Launch, &[&str], Integration); 7] = [
            (
                "kalareach/claude-code",
                "claude",
                Launch::Native,
                &[
                    ".claude",
                    ".claude.json",
                    "Library/Caches/claude-cli-nodejs",
                ],
                Integration::Flags,
            ),
            (
                "kalareach/gemini-cli",
                "gemini",
                Launch::Script,
                &[".gemini", ".agents"],
                Integration::Flags,
            ),
            (
                "kalareach/qoder-cli",
                "qodercli",
                Launch::Native,
                &[".qoder"],
                Integration::Flags,
            ),
            (
                "kalareach/opencode",
                "opencode",
                Launch::Native,
                &[
                    ".local/share/opencode",
                    ".cache/opencode",
                    ".config/opencode",
                    ".local/state/opencode",
                ],
                Integration::None,
            ),
            (
                "kalareach/opencode-attach",
                "opencode",
                Launch::Native,
                &[
                    ".local/share/opencode",
                    ".cache/opencode",
                    ".config/opencode",
                    ".local/state/opencode",
                ],
                Integration::None,
            ),
            (
                "kalareach/kimi-cli",
                "kimi",
                Launch::Wheel,
                &[".kimi"],
                Integration::None,
            ),
            (
                "kalareach/kimi-code-cli",
                "kimi",
                Launch::Native,
                &[".kimi-code"],
                Integration::None,
            ),
        ];
        for (package, command, launch, trees, integration) in table {
            let name = package.trim_start_matches("kalareach/");
            let subject = Subject::from_build(&build_of(package), &manifest(name, integration))
                .unwrap_or_else(|why| panic!("{package}: {why}"));
            assert_eq!(subject.plugin().to_string(), package);
            assert_eq!(subject.command(), command, "{package}");
            assert_eq!(subject.launch(), launch, "{package}");
            assert_eq!(subject.person_trees(), trees, "{package}");
            assert_eq!(subject.place(), format!("t/{command}"), "{package}");
            assert!(subject.gateway().is_none(), "{package} has a gateway");
        }
    }

    /// A manifest that is not the package the entry names is refused, naming both.
    #[test]
    fn a_manifest_of_another_package_than_the_entry_names_is_refused() {
        let refused = Subject::from_build(
            &build_of("kalareach/claude-code"),
            &manifest("gemini-cli", Integration::Flags),
        )
        .expect_err("a manifest of another package");
        assert!(
            refused.contains("kalareach/claude-code") && refused.contains("kalareach/gemini-cli"),
            "{refused}"
        );
    }

    /// A package with no command integration gives the subject none and no gateway, one that
    /// declares one without a backend gives an integration and no gateway, and a backend gives a
    /// gateway.
    #[test]
    fn a_backend_gives_a_gateway_and_an_integration_without_one_does_not() {
        let build = build_of("kalareach/kimi-code-cli");
        let subject = |integration| {
            Subject::from_build(&build, &manifest("kimi-code-cli", integration)).expect("a subject")
        };
        let none = subject(Integration::None);
        assert!(none.integration().is_none() && none.gateway().is_none());
        let flags = subject(Integration::Flags);
        assert!(flags.integration().is_some() && flags.gateway().is_none());
        let backend = subject(Integration::Backend);
        assert!(backend.integration().is_some());
        assert_eq!(
            backend
                .gateway()
                .map(|route| route.backend.arguments.clone()),
            Some(vec![
                "app-server".to_owned(),
                "--listen".to_owned(),
                "stdio://".to_owned()
            ])
        );
    }

    /// A case that drives the gateway has nothing to run for a subject with no gateway, unless the
    /// agent is started by hand or the run is the probe-only one; a subject with a gateway always
    /// has something to run.
    #[test]
    fn a_gateway_case_has_nothing_to_run_for_a_subject_with_no_gateway_unless_by_hand_or_probed() {
        let build = build_of("kalareach/kimi-code-cli");
        let without = Subject::from_build(&build, &manifest("kimi-code-cli", Integration::Flags))
            .expect("a subject");
        let why = without
            .gateway_not_run(false, false)
            .expect("a subject with no gateway has nothing to run");
        assert!(
            why.contains("kalareach/kimi-code-cli") && why.contains("declares no gateway backend"),
            "{why}"
        );
        assert_eq!(without.gateway_not_run(true, false), None, "by hand");
        assert_eq!(without.gateway_not_run(false, true), None, "probe only");
        let with = Subject::from_build(&build_of(CODEX), &manifest("codex", Integration::Backend))
            .expect("the Codex subject");
        for (by_hand, probe_only) in [(false, false), (true, false), (false, true)] {
            assert_eq!(with.gateway_not_run(by_hand, probe_only), None);
        }
    }

    /// The Codex subject gives the typed line, the configuration file's bytes, the probes'
    /// arguments, the session's variables and the record's place that the driver gave before.
    #[test]
    fn the_codex_subject_gives_the_line_configuration_probes_variables_and_record_as_before() {
        let build = build_of(CODEX);
        let subject = Subject::from_build(&build, &manifest("codex", Integration::Backend))
            .expect("the Codex entry's subject");
        assert_eq!(subject.typed_line(&[]), "codex");
        assert_eq!(
            subject.typed_line(&["resume", "0199a213-81c0-7800-8aa1-bbab2a035a53"]),
            "codex resume 0199a213-81c0-7800-8aa1-bbab2a035a53"
        );
        let files = |provider| {
            subject
                .configuration("/run", "/work", provider)
                .expect("the configuration")
        };
        assert_eq!(
            files(true)["config.toml"],
            include_str!("../tests/fixtures/codex-config-with-provider.toml")
        );
        assert_eq!(
            files(false)["config.toml"],
            include_str!("../tests/fixtures/codex-config-without-provider.toml")
        );
        let account = build.account.as_ref().expect("an account");
        let probes: Vec<Vec<String>> = account
            .isolated
            .iter()
            .map(|probe| subject.probe_arguments(probe))
            .collect();
        assert_eq!(probes[0], ["mcp", "list"]);
        assert_eq!(probes[1], ["features", "list"]);
        assert_eq!(probes[2], ["debug", "prompt-input"]);
        assert_eq!(probes.len(), 4);
        assert_eq!(probes[3][0], "exec");
        assert_eq!(probes[3].last().map(String::as_str), Some("Say nothing."));
        let config = account
            .config_directory
            .as_ref()
            .expect("a configuration directory");
        let cleared = account.cleared[0].clone();
        let variables = subject.session_variables(
            vec![
                ("PATH".to_owned(), "/bin".to_owned()),
                (cleared.clone(), "kept out".to_owned()),
                (config.variable.clone(), "elsewhere".to_owned()),
            ],
            vec![("USER".to_owned(), "someone".to_owned())],
            Some(("AGENT_LOGIN_VALUE".to_owned(), "a value".to_owned())),
            Path::new("/run/agent-config"),
        );
        assert_eq!(
            variables,
            [
                ("PATH", "/bin"),
                ("USER", "someone"),
                ("AGENT_LOGIN_VALUE", "a value"),
                (config.variable.as_str(), "/run/agent-config"),
            ]
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
        );
        assert_eq!(
            subject.record_location(),
            Some(PathBuf::from("agent-config/sessions"))
        );
    }
}
