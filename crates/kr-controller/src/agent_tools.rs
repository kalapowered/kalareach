//! Installing the contact skill, and undoing exactly what was installed.
//!
//! Section 11 asks for an installation recipe with exact files, hashes, version requirements and
//! removal operations, and for unrelated settings to be preserved. Three rules make that real
//! rather than hoped for.
//!
//! * **Every change is recorded with the digest of what it wrote.** The record is kept in this
//!   host's own state directory, not in the agent's, so an agent that rewrites its configuration
//!   cannot lose it. A removal replays the record in reverse and stops at anything whose digest no
//!   longer matches, because a changed file is somebody's edit.
//! * **An entry is guarded rather than assumed.** An installation refuses to replace a server
//!   entry it did not write. That is what keeps an unrelated `kalareach` entry somebody else
//!   created from being overwritten and then removed.
//! * **The agent's file keeps its other settings.** A TOML configuration is edited in place with a
//!   format-preserving editor, so ordering and comments survive. A JSON configuration is reparsed
//!   and rewritten, which preserves every setting but normalises the document's layout; that is
//!   said plainly in the documentation rather than left to be discovered.
//!
//! The skill files are compiled into this binary, so an installation needs nothing else on disk
//! and the digests it records are build-time facts.

use std::path::{Path, PathBuf};

use kr_protocol::scalars::{Digest256, Nullable};
use kr_protocol::skill::{
    AgentTarget, AgentToolsInstallResult, AgentToolsParams, AgentToolsRemoveResult,
    AgentToolsStatusResult, ChangeManifest, ChangeOperation, InstalledFile, SERVER_NAME,
    SKILL_NAME,
};
use serde_json::{Map, Value, json};

use crate::error::{ControllerError, Result};

/// The skill instructions, compiled in.
pub const SKILL_MD: &str = include_str!("../../../skills/kalareach-contact/SKILL.md");

/// The tool reference, compiled in.
pub const TOOLS_MD: &str = include_str!("../../../skills/kalareach-contact/TOOLS.md");

/// The versioned installation manifest, compiled in.
pub const MANIFEST_JSON: &str = include_str!("../../../skills/kalareach-contact/manifest.json");

/// The version this build installs.
pub const SKILL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The arguments the tool server is launched with.
pub const ENTRY_ARGS: &[&str] = &["agent-tools", "--stdio"];

/// Where one agent keeps its skills and its tool-server configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Layout {
    /// The directory the skill package is written into.
    skills: PathBuf,
    /// The configuration document the server entry is added to, when there is one at this scope.
    configuration: Option<Configuration>,
}

/// One configuration document and how an entry is written into it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Configuration {
    path: PathBuf,
    format: Format,
    /// True when more than one agent reads this document.
    ///
    /// A project's `.mcp.json` is the shared case. Everything written into one has to be the same
    /// whichever agent's installation wrote it, because they are all reading one entry: an
    /// agent-specific field there would make the second installation rewrite the first's entry and
    /// leave its record describing something that is no longer in the file.
    shared: bool,
}

/// How one agent's configuration document is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    /// `[mcp_servers.<name>]` in a TOML document, edited in place.
    CodexToml,
    /// `mcpServers.<name>` with a command and its arguments.
    JsonCommandArgs,
    /// `mcp.<name>` with one command array and an enabled flag.
    JsonLocalCommandList,
}

impl Format {
    /// Returns the top-level key a JSON document holds servers under.
    const fn json_key(self) -> &'static str {
        match self {
            Self::JsonLocalCommandList => "mcp",
            Self::CodexToml | Self::JsonCommandArgs => "mcpServers",
        }
    }
}

/// Installs, inspects and removes the contact skill for one agent.
#[derive(Clone, Debug)]
pub struct Installer {
    /// The operating-system user's home directory, which every user-scope layout hangs off.
    home: PathBuf,
    /// Where this host records what it installed.
    records: PathBuf,
    /// The command an agent runs to reach the tools.
    executable: String,
}

impl Installer {
    /// Builds an installer for this host.
    #[must_use]
    pub fn new(home: PathBuf, records: PathBuf, executable: String) -> Self {
        Self {
            home,
            records,
            executable,
        }
    }

    /// Builds an installer from this process's own surroundings.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when this user has no home directory, which is
    /// where every agent keeps its configuration.
    pub fn discover(state_dir: &Path) -> Result<Self> {
        let home = home_directory().ok_or_else(|| {
            ControllerError::InvalidArgument(
                "this user has no home directory, so no agent configuration can be found"
                    .to_owned(),
            )
        })?;
        Ok(Self::new(
            home,
            state_dir.join("agent-tools"),
            entry_command(),
        ))
    }

    /// Installs the skill and registers the tool server.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the scope needs a project directory that
    /// was not given, and [`ControllerError::PermissionDenied`] when a server entry under this
    /// name exists and was not written by this host.
    pub fn install(&self, params: &AgentToolsParams) -> Result<AgentToolsInstallResult> {
        let layout = self.layout(params)?;
        self.check(params)?;
        if let Some(existing) = self.recorded(params)?
            && self.drift(&existing)?.is_empty()
        {
            return Ok(AgentToolsInstallResult {
                manifest: existing,
                already_installed: true,
            });
        }
        let root = layout.skills.clone();
        let mut operations = Vec::new();
        for directory in missing_ancestors(&root) {
            std::fs::create_dir_all(&directory).map_err(storage)?;
            operations.push(ChangeOperation::CreateDirectory {
                path: display(&directory),
            });
        }
        for (name, contents) in files() {
            let path = root.join(name);
            let replaced = read_digest(&path)?;
            write_atomically(&path, contents.as_bytes(), READABLE)?;
            operations.push(ChangeOperation::WriteFile {
                path: display(&path),
                digest: digest_of(contents.as_bytes()),
                replaced_digest: Nullable(replaced),
            });
        }
        if let Some(configuration) = layout.configuration.as_ref() {
            operations.push(self.write_entry(configuration, params.agent)?);
        }
        let manifest = ChangeManifest {
            skill_version: SKILL_VERSION.to_owned(),
            agent: params.agent,
            scope: params.scope,
            root: display(&root),
            entry_point: self.entry_point(),
            operations,
        };
        self.record(params, &manifest)?;
        Ok(AgentToolsInstallResult {
            manifest,
            already_installed: false,
        })
    }

    /// Reports what is installed, and what no longer matches what was written.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read.
    pub fn status(&self, params: &AgentToolsParams) -> Result<AgentToolsStatusResult> {
        let layout = self.layout(params)?;
        let Some(manifest) = self.recorded(params)? else {
            return Ok(AgentToolsStatusResult {
                agent: params.agent,
                scope: params.scope,
                root: display(&layout.skills),
                installed: false,
                skill_version: Nullable::null(),
                files: Vec::new(),
                drift: Vec::new(),
                removal: Vec::new(),
            });
        };
        let mut files = Vec::new();
        for operation in &manifest.operations {
            if let ChangeOperation::WriteFile { path, digest, .. } = operation {
                files.push(InstalledFile {
                    path: path.clone(),
                    expected_digest: *digest,
                    actual_digest: Nullable(read_digest(Path::new(path))?),
                });
            }
        }
        let drift = self.drift(&manifest)?;
        Ok(AgentToolsStatusResult {
            agent: params.agent,
            scope: params.scope,
            root: manifest.root.clone(),
            installed: true,
            skill_version: Nullable::some(manifest.skill_version.clone()),
            files,
            drift,
            removal: manifest.operations.iter().rev().cloned().collect(),
        })
    }

    /// Undoes exactly what an installation recorded.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read or a file cannot be removed.
    pub fn remove(&self, params: &AgentToolsParams) -> Result<AgentToolsRemoveResult> {
        let Some(manifest) = self.recorded(params)? else {
            return Ok(AgentToolsRemoveResult {
                agent: params.agent,
                scope: params.scope,
                removed: Vec::new(),
                retained: vec![format!(
                    "this host has no record of installing {SKILL_NAME} for {} at {} scope",
                    params.agent, params.scope
                )],
            });
        };
        let mut removed = Vec::new();
        let mut retained = Vec::new();
        for operation in manifest.operations.iter().rev() {
            match operation {
                ChangeOperation::WriteFile { path, digest, .. } => {
                    let present = read_digest(Path::new(path))?;
                    match present {
                        None => retained.push(format!("{path} is already gone")),
                        // Somebody edited it after this host wrote it. That edit is theirs, and a
                        // removal that deleted it would be deleting their work.
                        Some(found) if found != *digest => {
                            retained.push(format!("{path} has changed since it was installed"));
                        }
                        Some(_) => {
                            std::fs::remove_file(path).map_err(storage)?;
                            removed.push(operation.clone());
                        }
                    }
                }
                ChangeOperation::AddConfigurationEntry {
                    path,
                    entry,
                    digest,
                    created_document,
                } => {
                    let key = entry.rsplit_once('.').map_or("mcpServers", |(key, _)| key);
                    match self.remove_entry(
                        Path::new(path),
                        key,
                        *digest,
                        *created_document,
                        params,
                    )? {
                        Removal::Removed => removed.push(operation.clone()),
                        Removal::Kept(reason) => {
                            retained.push(format!("{entry} in {path}: {reason}"));
                        }
                    }
                }
                ChangeOperation::CreateDirectory { path } => {
                    // Only when it is empty. A directory that holds anything else holds somebody
                    // else's file.
                    match std::fs::remove_dir(path) {
                        Ok(()) => removed.push(operation.clone()),
                        Err(_) => retained.push(format!("{path} is not empty")),
                    }
                }
            }
        }
        let record = self.record_path(params);
        if record.exists() {
            std::fs::remove_file(&record).map_err(storage)?;
        }
        Ok(AgentToolsRemoveResult {
            agent: params.agent,
            scope: params.scope,
            removed,
            retained,
        })
    }

    /// Returns what no longer matches the record, in the words a person reads.
    fn drift(&self, manifest: &ChangeManifest) -> Result<Vec<String>> {
        let mut drift = Vec::new();
        for operation in &manifest.operations {
            match operation {
                ChangeOperation::WriteFile { path, digest, .. } => {
                    match read_digest(Path::new(path))? {
                        None => drift.push(format!("{path} is missing")),
                        Some(found) if found != *digest => {
                            drift.push(format!("{path} has changed since it was installed"));
                        }
                        Some(_) => {}
                    }
                }
                ChangeOperation::AddConfigurationEntry {
                    path,
                    entry,
                    digest,
                    ..
                } => match self.entry_digest(Path::new(path))? {
                    None => drift.push(format!("{entry} is missing from {path}")),
                    Some(found) if found != *digest => {
                        drift.push(format!("{entry} in {path} has changed"));
                    }
                    Some(_) => {}
                },
                ChangeOperation::CreateDirectory { path } => {
                    if !Path::new(path).is_dir() {
                        drift.push(format!("{path} is missing"));
                    }
                }
            }
        }
        if manifest.skill_version != SKILL_VERSION {
            drift.push(format!(
                "version {} is installed and this host carries {SKILL_VERSION}",
                manifest.skill_version
            ));
        }
        Ok(drift)
    }

    /// Returns the command an agent runs to reach the tools.
    fn entry_point(&self) -> Vec<String> {
        let mut entry = vec![self.executable.clone()];
        entry.extend(ENTRY_ARGS.iter().map(|argument| (*argument).to_owned()));
        entry
    }

    /// Adds the server entry to an agent's configuration, leaving its other settings alone.
    fn write_entry(
        &self,
        configuration: &Configuration,
        agent: AgentTarget,
    ) -> Result<ChangeOperation> {
        let created_document = !configuration.path.exists();
        if let Some(parent) = configuration.path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent).map_err(storage)?;
        }
        // A shared document gets the same entry whichever agent's installation writes it, so the
        // deadline an individual agent would declare is left out of one.
        let declaring = (!configuration.shared).then_some(agent);
        let digest = match configuration.format {
            Format::CodexToml => self.write_toml_entry(&configuration.path, declaring)?,
            format => self.write_json_entry(&configuration.path, format, declaring)?,
        };
        Ok(ChangeOperation::AddConfigurationEntry {
            path: display(&configuration.path),
            entry: format!("{}.{SERVER_NAME}", configuration.format.json_key()),
            digest,
            created_document,
        })
    }

    fn write_toml_entry(&self, path: &Path, agent: Option<AgentTarget>) -> Result<Digest256> {
        let text = read_to_string(path)?.unwrap_or_default();
        let mut document: toml_edit::DocumentMut = text.parse().map_err(|error| {
            ControllerError::InvalidArgument(format!("{}: {error}", display(path)))
        })?;
        let servers = document
            .entry("mcp_servers")
            .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
        let table = servers.as_table_mut().ok_or_else(|| {
            ControllerError::InvalidArgument(format!(
                "{} holds something other than a table of servers",
                display(path)
            ))
        })?;
        table.set_implicit(true);
        if table.contains_key(SERVER_NAME) {
            self.guard_existing(path, Format::CodexToml)?;
        }
        let mut entry = toml_edit::Table::new();
        entry["command"] = toml_edit::value(self.executable.clone());
        let mut args = toml_edit::Array::new();
        for argument in ENTRY_ARGS {
            args.push(*argument);
        }
        entry["args"] = toml_edit::value(args);
        if let Some((field, seconds)) = agent.and_then(deadline_field)
            && let Some(seconds) = seconds.as_i64()
        {
            entry[field] = toml_edit::value(seconds);
        }
        table.insert(SERVER_NAME, toml_edit::Item::Table(entry));
        write_atomically(path, document.to_string().as_bytes(), PRIVATE)?;
        self.entry_digest(path)?.ok_or_else(|| {
            ControllerError::InvalidArgument(format!("{} did not keep the entry", display(path)))
        })
    }

    fn write_json_entry(
        &self,
        path: &Path,
        format: Format,
        agent: Option<AgentTarget>,
    ) -> Result<Digest256> {
        let mut document = read_json(path)?;
        let key = format.json_key();
        let root = document.as_object_mut().ok_or_else(|| {
            ControllerError::InvalidArgument(format!("{} is not a JSON object", display(path)))
        })?;
        let servers = root
            .entry(key.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        let servers = servers.as_object_mut().ok_or_else(|| {
            ControllerError::InvalidArgument(format!(
                "{key} in {} is not an object of servers",
                display(path)
            ))
        })?;
        if servers.contains_key(SERVER_NAME) {
            self.guard_existing(path, format)?;
        }
        servers.insert(SERVER_NAME.to_owned(), self.entry_value(format, agent));
        let text = serde_json::to_string_pretty(&document)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        write_atomically(path, format!("{text}\n").as_bytes(), PRIVATE)?;
        self.entry_digest(path)?.ok_or_else(|| {
            ControllerError::InvalidArgument(format!("{} did not keep the entry", display(path)))
        })
    }

    /// Refuses an installation that would change anything this host did not write.
    ///
    /// Every check happens before the first write, so a refusal leaves the agent's tree exactly as
    /// it found it, and before the dispatch marker, so a refusal is never reported as an outcome
    /// that might have happened.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::PermissionDenied`] when a file or a server entry is already
    /// there and this host did not write it, and [`ControllerError::InvalidArgument`] when the
    /// scope needs a project directory that was not given.
    pub fn check(&self, params: &AgentToolsParams) -> Result<()> {
        let layout = self.layout(params)?;
        let root = layout.skills.clone();
        self.check_before_writing(params, &layout, &root)
    }

    fn check_before_writing(
        &self,
        params: &AgentToolsParams,
        layout: &Layout,
        root: &Path,
    ) -> Result<()> {
        let recorded = self.recorded(params)?;
        for (name, _) in files() {
            let path = root.join(name);
            let Some(present) = read_digest(&path)? else {
                continue;
            };
            let ours = recorded.as_ref().is_some_and(|manifest| {
                manifest.operations.iter().any(|operation| {
                    matches!(
                        operation,
                        ChangeOperation::WriteFile { path: recorded_path, digest, .. }
                            if recorded_path == &display(&path) && *digest == present
                    )
                })
            });
            if !ours {
                return Err(ControllerError::PermissionDenied {
                    detail: format!(
                        "{} is already there and this host did not write it; move it aside before \
                         installing",
                        display(&path)
                    ),
                });
            }
        }
        if let Some(configuration) = layout.configuration.as_ref() {
            self.guard_existing(&configuration.path, configuration.format)?;
        }
        Ok(())
    }

    /// Refuses to replace an entry this host did not write.
    fn guard_existing(&self, path: &Path, format: Format) -> Result<()> {
        let Some(present) = self.entry_digest(path)? else {
            return Ok(());
        };
        if self.records_hold(path, format.json_key(), &present) {
            return Ok(());
        }
        Err(ControllerError::PermissionDenied {
            detail: format!(
                "{} already has a server named {SERVER_NAME} that this host did not write; remove \
                 it or rename it before installing",
                display(path)
            ),
        })
    }

    /// Returns true when a record of this host wrote *this* entry, in *this* document.
    ///
    /// The digest alone is not enough. Several agents share one project `.mcp.json`, and an entry
    /// written for one of them has the same digest as the entry another would write; matching on
    /// the digest alone would let one installation claim, and later remove, another's entry.
    fn records_hold(&self, path: &Path, key: &str, digest: &Digest256) -> bool {
        self.holders(path, key, digest) > 0
    }

    /// Returns how many recorded installations claim this exact entry.
    fn holders(&self, path: &Path, key: &str, digest: &Digest256) -> usize {
        let entry_name = format!("{key}.{SERVER_NAME}");
        let wanted = display(path);
        let Ok(entries) = std::fs::read_dir(&self.records) else {
            return 0;
        };
        entries
            .flatten()
            .filter(|entry| {
                let Ok(text) = std::fs::read_to_string(entry.path()) else {
                    return false;
                };
                let Ok(manifest) = serde_json::from_str::<ChangeManifest>(&text) else {
                    return false;
                };
                manifest.operations.iter().any(|operation| {
                    matches!(
                        operation,
                        ChangeOperation::AddConfigurationEntry {
                            path: recorded_path,
                            entry: recorded_entry,
                            digest: recorded,
                            ..
                        } if recorded_path == &wanted
                            && recorded_entry == &entry_name
                            && recorded == digest
                    )
                })
            })
            .count()
    }

    /// Returns the digest of the server entry in a configuration document.
    ///
    /// The digest covers the entry alone, canonically rendered, so it does not change when
    /// something unrelated in the file does.
    fn entry_digest(&self, path: &Path) -> Result<Option<Digest256>> {
        let Some(text) = read_to_string(path)? else {
            return Ok(None);
        };
        if path
            .extension()
            .is_some_and(|extension| extension == "toml")
        {
            let document: toml_edit::DocumentMut = text.parse().map_err(|error| {
                ControllerError::InvalidArgument(format!("{}: {error}", display(path)))
            })?;
            let entry = document
                .get("mcp_servers")
                .and_then(|servers| servers.as_table())
                .and_then(|servers| servers.get(SERVER_NAME));
            return Ok(entry.map(|entry| digest_of(entry.to_string().trim().as_bytes())));
        }
        let document: Value = serde_json::from_str(&text).map_err(|error| {
            ControllerError::InvalidArgument(format!("{}: {error}", display(path)))
        })?;
        for key in ["mcpServers", "mcp"] {
            if let Some(entry) = document
                .get(key)
                .and_then(|servers| servers.get(SERVER_NAME))
            {
                return Ok(Some(digest_of(entry.to_string().as_bytes())));
            }
        }
        Ok(None)
    }

    /// Returns the digest of the server entry under one named key.
    fn entry_digest_under(&self, path: &Path, key: &str) -> Result<Option<Digest256>> {
        if path
            .extension()
            .is_some_and(|extension| extension == "toml")
        {
            return self.entry_digest(path);
        }
        let Some(text) = read_to_string(path)? else {
            return Ok(None);
        };
        let document: Value = serde_json::from_str(&text).map_err(|error| {
            ControllerError::InvalidArgument(format!("{}: {error}", display(path)))
        })?;
        Ok(document
            .get(key)
            .and_then(|servers| servers.get(SERVER_NAME))
            .map(|entry| digest_of(entry.to_string().as_bytes())))
    }

    /// Removes the server entry, when it is still the one that was written.
    fn remove_entry(
        &self,
        path: &Path,
        key: &str,
        digest: Digest256,
        created_document: bool,
        params: &AgentToolsParams,
    ) -> Result<Removal> {
        let Some(present) = self.entry_digest_under(path, key)? else {
            return Ok(Removal::Kept("it is already gone".to_owned()));
        };
        if present != digest {
            return Ok(Removal::Kept(
                "it has changed since it was installed".to_owned(),
            ));
        }
        // Several agents share one project `.mcp.json`. Removing one installation must not take
        // the server another installation is still using, so the entry goes only when this record
        // is the last one claiming it. This record is still on disk here, which is why one holder
        // means this one alone.
        if self.holders(path, key, &digest) > 1 {
            return Ok(Removal::Kept(format!(
                "another installation on this host still uses it; {} at {} scope was removed \
                 around it",
                params.agent, params.scope
            )));
        }
        if path
            .extension()
            .is_some_and(|extension| extension == "toml")
        {
            let text = read_to_string(path)?.unwrap_or_default();
            let mut document: toml_edit::DocumentMut = text.parse().map_err(|error| {
                ControllerError::InvalidArgument(format!("{}: {error}", display(path)))
            })?;
            if let Some(servers) = document
                .get_mut("mcp_servers")
                .and_then(|servers| servers.as_table_mut())
            {
                servers.remove(SERVER_NAME);
            }
            write_atomically(path, document.to_string().as_bytes(), PRIVATE)?;
        } else {
            let mut document = read_json(path)?;
            if let Some(root) = document.as_object_mut()
                && let Some(servers) = root.get_mut(key).and_then(Value::as_object_mut)
            {
                // Only the key the record names. A document that holds both shapes keeps whichever
                // this installation did not write.
                servers.remove(SERVER_NAME);
            }
            let empty = document
                .as_object()
                .is_some_and(|root| root.values().all(is_empty_object));
            if created_document && empty {
                // This host created the document and nothing else was ever added to it.
                std::fs::remove_file(path).map_err(storage)?;
                return Ok(Removal::Removed);
            }
            let text = serde_json::to_string_pretty(&document)
                .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
            write_atomically(path, format!("{text}\n").as_bytes(), PRIVATE)?;
        }
        Ok(Removal::Removed)
    }

    fn entry_value(&self, format: Format, agent: Option<AgentTarget>) -> Value {
        let arguments: Vec<&str> = ENTRY_ARGS.to_vec();
        match format {
            Format::JsonLocalCommandList => {
                let mut command = vec![self.executable.clone()];
                command.extend(arguments.iter().map(|argument| (*argument).to_owned()));
                json!({"type": "local", "command": command, "enabled": true})
            }
            Format::CodexToml | Format::JsonCommandArgs => {
                let mut entry = json!({
                    "type": "stdio",
                    "command": self.executable,
                    "args": arguments,
                });
                // Section 11 shortens a long poll to the installed client's qualified tool
                // deadline. Where an agent lets a server declare that deadline, the installation
                // declares one long enough for the host's own ceiling, so a wait returns the
                // durable question rather than being cut off by a default the agent chose for
                // ordinary tools.
                if let Some((field, value)) = agent.and_then(deadline_field)
                    && let Some(object) = entry.as_object_mut()
                {
                    object.insert(field.to_owned(), value);
                }
                entry
            }
        }
    }

    /// Returns where one agent keeps its skills and its configuration, at this scope.
    fn layout(&self, params: &AgentToolsParams) -> Result<Layout> {
        use kr_protocol::skill::InstallScope::{Project, User};

        let project = || -> Result<PathBuf> {
            params
                .project_dir
                .as_ref()
                .map(PathBuf::from)
                .ok_or_else(|| {
                    ControllerError::InvalidArgument(
                        "a project-scope installation needs the project directory".to_owned(),
                    )
                })
        };
        let home = &self.home;
        let layout = match (params.agent, params.scope) {
            // Codex reads repository and user skills from `.agents/skills`, and scopes servers to
            // a project with `.codex/config.toml`.
            (AgentTarget::Codex, User) => Layout {
                skills: home.join(".agents/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: home.join(".codex/config.toml"),
                    format: Format::CodexToml,
                    shared: false,
                }),
            },
            (AgentTarget::Codex, Project) => Layout {
                skills: project()?.join(".agents/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: project()?.join(".codex/config.toml"),
                    format: Format::CodexToml,
                    shared: false,
                }),
            },
            (AgentTarget::ClaudeCode, User) => Layout {
                skills: home.join(".claude/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: home.join(".claude.json"),
                    format: Format::JsonCommandArgs,
                    shared: false,
                }),
            },
            (AgentTarget::ClaudeCode, Project) => Layout {
                skills: project()?.join(".claude/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: project()?.join(".mcp.json"),
                    format: Format::JsonCommandArgs,
                    shared: true,
                }),
            },
            (AgentTarget::Opencode, User) => Layout {
                skills: home.join(".config/opencode/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: home.join(".config/opencode/opencode.json"),
                    format: Format::JsonLocalCommandList,
                    shared: false,
                }),
            },
            (AgentTarget::Opencode, Project) => Layout {
                skills: project()?.join(".opencode/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: project()?.join("opencode.json"),
                    format: Format::JsonLocalCommandList,
                    shared: false,
                }),
            },
            (AgentTarget::GeminiCli, User) => Layout {
                skills: home.join(".gemini/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: home.join(".gemini/settings.json"),
                    format: Format::JsonCommandArgs,
                    shared: false,
                }),
            },
            (AgentTarget::GeminiCli, Project) => Layout {
                skills: project()?.join(".gemini/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: project()?.join(".gemini/settings.json"),
                    format: Format::JsonCommandArgs,
                    shared: false,
                }),
            },
            (AgentTarget::KimiCodeCli, User) => Layout {
                skills: home.join(".kimi-code/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: home.join(".kimi-code/mcp.json"),
                    format: Format::JsonCommandArgs,
                    shared: false,
                }),
            },
            (AgentTarget::KimiCodeCli, Project) => Layout {
                skills: project()?.join(".kimi/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: project()?.join(".mcp.json"),
                    format: Format::JsonCommandArgs,
                    shared: true,
                }),
            },
            (AgentTarget::QoderCli, User) => Layout {
                skills: home.join(".qoder/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: home.join(".qoder/settings.json"),
                    format: Format::JsonCommandArgs,
                    shared: false,
                }),
            },
            (AgentTarget::QoderCli, Project) => Layout {
                skills: project()?.join(".qoder/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: project()?.join(".mcp.json"),
                    format: Format::JsonCommandArgs,
                    shared: true,
                }),
            },
        };
        Ok(layout)
    }

    fn record_path(&self, params: &AgentToolsParams) -> PathBuf {
        let scope = match params.project_dir.as_ref() {
            Some(directory) => format!(
                "{}-{}",
                params.scope,
                hex(&kr_cbor::sha256(directory.as_bytes())[..8])
            ),
            None => params.scope.to_string(),
        };
        self.records.join(format!("{}-{scope}.json", params.agent))
    }

    fn recorded(&self, params: &AgentToolsParams) -> Result<Option<ChangeManifest>> {
        let Some(text) = read_to_string(&self.record_path(params))? else {
            return Ok(None);
        };
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    fn record(&self, params: &AgentToolsParams, manifest: &ChangeManifest) -> Result<()> {
        std::fs::create_dir_all(&self.records).map_err(storage)?;
        let text = serde_json::to_string_pretty(manifest)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        write_atomically(
            &self.record_path(params),
            format!("{text}\n").as_bytes(),
            PRIVATE,
        )
    }
}

/// The durable record of one admitted installation action.
///
/// Section 9 makes a mutation's identity its action, not its parameters: the same action retried
/// returns what it produced the first time, the same identifier with a different payload is
/// `ID_CONFLICT`, and a dispatch marker without a recorded outcome is `unknown` rather than
/// something to do again. An installation changes files, so it needs all three.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ActionRecord {
    /// The digest of the mutation this action was admitted for.
    digest: String,
    /// `dispatching` until the effect finishes, then `applied`.
    state: String,
    /// What the effect produced, once it has: its canonical encoding, in hexadecimal.
    result: Option<String>,
}

impl Installer {
    /// Returns the answer a retained installation action is owed.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::IdConflict`] when the identifier carries a different payload,
    /// and [`ControllerError::Uncertain`] when a marker was written and no outcome was recorded:
    /// the files may have changed, and doing it again is exactly what section 9 forbids.
    pub fn retained(
        &self,
        actor_id: &kr_protocol::ids::ActorId,
        action_id: kr_protocol::ids::ActionId,
        digest: &Digest256,
    ) -> Result<Option<kr_protocol::envelope::ParamsValue>> {
        let Some(text) = read_to_string(&self.action_path(actor_id, action_id))? else {
            return Ok(None);
        };
        let record: ActionRecord = serde_json::from_str(&text)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        if record.digest != hex(digest.as_bytes()) {
            return Err(ControllerError::IdConflict {
                token: action_id.to_string(),
            });
        }
        match (record.state.as_str(), record.result) {
            ("applied", Some(result)) => Ok(Some(decode_result(&result)?)),
            _ => Err(ControllerError::Uncertain {
                detail: format!(
                    "installation action {action_id} was begun and its outcome was never \
                     recorded, so what it changed is not known; read the status before asking \
                     again"
                ),
            }),
        }
    }

    /// Commits the dispatch marker, before anything on disk changes.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when the marker cannot be written.
    pub fn mark_dispatching(
        &self,
        actor_id: &kr_protocol::ids::ActorId,
        action_id: kr_protocol::ids::ActionId,
        digest: &Digest256,
    ) -> Result<()> {
        self.write_action(
            actor_id,
            action_id,
            &ActionRecord {
                digest: hex(digest.as_bytes()),
                state: "dispatching".to_owned(),
                result: None,
            },
        )
    }

    /// Records what the effect produced.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when the record cannot be written.
    pub fn settle(
        &self,
        actor_id: &kr_protocol::ids::ActorId,
        action_id: kr_protocol::ids::ActionId,
        digest: &Digest256,
        result: &kr_protocol::envelope::ParamsValue,
    ) -> Result<()> {
        self.write_action(
            actor_id,
            action_id,
            &ActionRecord {
                digest: hex(digest.as_bytes()),
                state: "applied".to_owned(),
                result: Some(hex(&kr_cbor::encode(result.as_value()))),
            },
        )
    }

    fn write_action(
        &self,
        actor_id: &kr_protocol::ids::ActorId,
        action_id: kr_protocol::ids::ActionId,
        record: &ActionRecord,
    ) -> Result<()> {
        let path = self.action_path(actor_id, action_id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(storage)?;
        }
        let text = serde_json::to_string_pretty(record)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        write_atomically(&path, format!("{text}\n").as_bytes(), PRIVATE)
    }

    fn action_path(
        &self,
        actor_id: &kr_protocol::ids::ActorId,
        action_id: kr_protocol::ids::ActionId,
    ) -> PathBuf {
        self.records.join("actions").join(format!(
            "{}-{action_id}.json",
            hex(&kr_cbor::sha256(actor_id.as_str().as_bytes())[..8])
        ))
    }
}

/// Reads a retained result back from its hexadecimal encoding.
fn decode_result(text: &str) -> Result<kr_protocol::envelope::ParamsValue> {
    let bytes = unhex(text).ok_or_else(|| {
        ControllerError::InvalidArgument("a retained result is not readable".to_owned())
    })?;
    let value = kr_cbor::decode(&bytes, &kr_cbor::Limits::DEFAULT)
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
    Ok(kr_protocol::envelope::ParamsValue::new(value))
}

/// Reads hexadecimal back to bytes.
fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

/// What a removal did with one configuration entry.
enum Removal {
    /// It was the entry that was written, and it is gone.
    Removed,
    /// It was left alone, for the stated reason.
    Kept(String),
}

/// The longest a contact tool holds a call, in seconds, plus room to answer.
///
/// It is the host's long-poll ceiling with a margin, so a client that honours a declared deadline
/// never cuts off a wait the host would have finished.
const QUALIFIED_DEADLINE_SECONDS: i64 = 660;

/// The field one agent declares a server's tool deadline in, where it has one.
///
/// An agent without one is not given an invented field: its own default governs, and the tool
/// reference tells the agent to ask for a shorter wait than its client allows.
fn deadline_field(agent: AgentTarget) -> Option<(&'static str, Value)> {
    match agent {
        AgentTarget::Codex => Some(("tool_timeout_sec", json!(QUALIFIED_DEADLINE_SECONDS))),
        AgentTarget::KimiCodeCli => {
            Some(("toolTimeoutMs", json!(QUALIFIED_DEADLINE_SECONDS * 1_000)))
        }
        AgentTarget::QoderCli => Some(("timeout", json!(QUALIFIED_DEADLINE_SECONDS * 1_000))),
        AgentTarget::ClaudeCode | AgentTarget::Opencode | AgentTarget::GeminiCli => None,
    }
}

/// The files an installation writes, in the order it writes them.
fn files() -> [(&'static str, &'static str); 3] {
    [
        ("SKILL.md", SKILL_MD),
        ("TOOLS.md", TOOLS_MD),
        ("manifest.json", MANIFEST_JSON),
    ]
}

/// Returns the directories that have to be created for this path to exist, outermost first.
fn missing_ancestors(path: &Path) -> Vec<PathBuf> {
    let mut missing = Vec::new();
    let mut current = Some(path);
    while let Some(directory) = current {
        if directory.is_dir() {
            break;
        }
        missing.push(directory.to_path_buf());
        current = directory.parent();
    }
    missing.reverse();
    missing
}

fn read_to_string(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(storage(error)),
    }
}

fn read_json(path: &Path) -> Result<Value> {
    match read_to_string(path)? {
        None => Ok(Value::Object(Map::new())),
        Some(text) if text.trim().is_empty() => Ok(Value::Object(Map::new())),
        Some(text) => serde_json::from_str(&text).map_err(|error| {
            ControllerError::InvalidArgument(format!("{}: {error}", display(path)))
        }),
    }
}

fn read_digest(path: &Path) -> Result<Option<Digest256>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(digest_of(&bytes))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(storage(error)),
    }
}

fn digest_of(bytes: &[u8]) -> Digest256 {
    Digest256::from_bytes(kr_cbor::sha256(bytes))
}

/// The permissions a skill file is created with. It is documentation an agent reads.
const READABLE: u32 = 0o644;

/// The permissions a configuration document or a host record is created with.
///
/// An agent's configuration can hold a credential, so one this host creates is the owner's alone.
const PRIVATE: u32 = 0o600;

/// Writes a file so a failure part way through cannot truncate what was there.
///
/// The replacement carries the permissions of what it replaces: a document somebody kept private
/// must not become world-readable because this host rewrote it under its own umask. A file that
/// did not exist is created with `default_mode`.
fn write_atomically(path: &Path, bytes: &[u8], default_mode: u32) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let temporary = parent.join(format!(".{}.kalareach", file_name(path)));
    std::fs::write(&temporary, bytes).map_err(storage)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mode = std::fs::metadata(path)
            .ok()
            .map_or(default_mode, |existing| {
                existing.permissions().mode() & 0o777
            });
        let mut permissions = std::fs::metadata(&temporary)
            .map_err(storage)?
            .permissions();
        permissions.set_mode(mode);
        std::fs::set_permissions(&temporary, permissions).map_err(storage)?;
    }
    #[cfg(not(unix))]
    let _ = default_mode;
    std::fs::rename(&temporary, path).map_err(storage)
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_owned())
}

fn display(path: &Path) -> String {
    path.display().to_string()
}

fn is_empty_object(value: &Value) -> bool {
    value.as_object().is_some_and(Map::is_empty)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
        text
    })
}

fn storage(error: std::io::Error) -> ControllerError {
    ControllerError::Storage {
        operation: "change an agent's configuration",
        detail: error.to_string(),
    }
}

/// Returns this user's home directory.
fn home_directory() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
}

/// Returns the command an agent runs to reach the tools.
///
/// The `kr` beside this daemon when there is one, so an installation from a build that is not on
/// the path still reaches that build; otherwise the plain command name, which the person's path
/// resolves.
fn entry_command() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join(client_name())))
        .filter(|path| path.is_file())
        .map_or_else(|| "kr".to_owned(), |path| display(&path))
}

const fn client_name() -> &'static str {
    if cfg!(windows) { "kr.exe" } else { "kr" }
}

/// Returns the skill package's own files, for a check that they are what the manifest says.
#[must_use]
pub fn packaged_files() -> Vec<(&'static str, &'static str)> {
    files().to_vec()
}

#[cfg(test)]
mod tests {
    use kr_protocol::skill::InstallScope;

    use super::*;

    struct Tree {
        root: PathBuf,
    }

    impl Tree {
        fn create() -> Self {
            let root = std::env::temp_dir().join(format!("kr-skill-{}", kr_ipc::new_uuid()));
            std::fs::create_dir_all(root.join("home")).expect("a home");
            std::fs::create_dir_all(root.join("state")).expect("a state directory");
            Self { root }
        }

        fn installer(&self) -> Installer {
            Installer::new(
                self.root.join("home"),
                self.root.join("state/agent-tools"),
                "/opt/kalareach/kr".to_owned(),
            )
        }

        fn home(&self) -> PathBuf {
            self.root.join("home")
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn params(agent: AgentTarget, scope: InstallScope) -> AgentToolsParams {
        AgentToolsParams {
            agent,
            scope,
            project_dir: Nullable::null(),
        }
    }

    /// The digests the fixture records, and the digests the manifest carries.
    ///
    /// Both are checked against the files this binary carries. A skill package that changed
    /// without its manifest changing would install files whose hashes do not describe them, and a
    /// removal reads those hashes to decide what is safe to delete.
    #[test]
    fn the_packaged_files_match_the_manifest_and_the_fixture() {
        let manifest: Value = serde_json::from_str(MANIFEST_JSON).expect("the manifest is JSON");
        let fixture: Value =
            serde_json::from_str(include_str!("../../../fixtures/contact/skill-package.json"))
                .expect("the fixture is JSON");
        let recorded = |value: &Value, name: &str| -> Option<String> {
            value["files"].as_array()?.iter().find_map(|file| {
                (file["path"] == name)
                    .then(|| file["sha256"].as_str().unwrap_or_default().to_owned())
            })
        };
        for (name, contents) in files() {
            let digest = hex(digest_of(contents.as_bytes()).as_bytes());
            assert_eq!(
                recorded(&fixture, name).as_deref(),
                Some(digest.as_str()),
                "{name} matches the fixture"
            );
            if name != "manifest.json" {
                assert_eq!(
                    recorded(&manifest, name).as_deref(),
                    Some(digest.as_str()),
                    "{name} matches the manifest"
                );
            }
        }
        assert_eq!(manifest["version"], SKILL_VERSION);
        assert_eq!(manifest["entry_point"]["command"], "kr");
        assert_eq!(manifest["entry_point"]["args"][0], ENTRY_ARGS[0]);
        assert_eq!(manifest["entry_point"]["args"][1], ENTRY_ARGS[1]);
        for agent in AgentTarget::ALL {
            assert!(
                manifest["agents"]
                    .as_array()
                    .expect("agents")
                    .iter()
                    .any(|entry| entry["agent"] == agent.as_str()),
                "{agent} is in the manifest"
            );
        }
    }

    #[test]
    fn an_installation_writes_the_skill_and_registers_the_server() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::ClaudeCode, InstallScope::User);
        let result = installer.install(&params).expect("installs");
        assert!(!result.already_installed);
        assert!(
            tree.home()
                .join(".claude/skills/kalareach-contact/SKILL.md")
                .is_file()
        );
        assert!(
            tree.home()
                .join(".claude/skills/kalareach-contact/TOOLS.md")
                .is_file()
        );
        let configuration: Value = serde_json::from_str(
            &std::fs::read_to_string(tree.home().join(".claude.json")).expect("the file"),
        )
        .expect("json");
        assert_eq!(
            configuration["mcpServers"]["kalareach"]["command"],
            "/opt/kalareach/kr"
        );
        assert_eq!(
            configuration["mcpServers"]["kalareach"]["args"][0],
            "agent-tools"
        );
    }

    #[test]
    fn a_second_installation_is_the_same_installation() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::ClaudeCode, InstallScope::User);
        installer.install(&params).expect("installs");
        let again = installer.install(&params).expect("installs");
        assert!(again.already_installed);
    }

    #[test]
    fn status_reports_what_changed_since_the_installation() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::ClaudeCode, InstallScope::User);
        installer.install(&params).expect("installs");
        let status = installer.status(&params).expect("reads");
        assert!(status.installed);
        assert!(status.drift.is_empty());
        assert!(status.files.iter().all(InstalledFile::is_intact));

        std::fs::write(
            tree.home()
                .join(".claude/skills/kalareach-contact/SKILL.md"),
            "somebody edited this",
        )
        .expect("writes");
        let status = installer.status(&params).expect("reads");
        assert_eq!(status.drift.len(), 1);
        assert!(status.drift[0].contains("has changed"));
    }

    #[test]
    fn a_removal_undoes_its_own_changes_and_leaves_everything_else() {
        let tree = Tree::create();
        let installer = tree.installer();
        // Somebody else's configuration, which has to survive.
        std::fs::write(
            tree.home().join(".claude.json"),
            r#"{"mcpServers":{"theirs":{"command":"their-server"}},"theme":"dark"}"#,
        )
        .expect("writes");
        let params = params(AgentTarget::ClaudeCode, InstallScope::User);
        installer.install(&params).expect("installs");
        let removed = installer.remove(&params).expect("removes");
        assert!(!removed.removed.is_empty());
        let configuration: Value = serde_json::from_str(
            &std::fs::read_to_string(tree.home().join(".claude.json")).expect("the file"),
        )
        .expect("json");
        assert!(configuration["mcpServers"].get("kalareach").is_none());
        assert_eq!(
            configuration["mcpServers"]["theirs"]["command"],
            "their-server"
        );
        assert_eq!(configuration["theme"], "dark");
        assert!(
            !tree
                .home()
                .join(".claude/skills/kalareach-contact")
                .exists()
        );
        assert!(!installer.status(&params).expect("reads").installed);
    }

    #[test]
    fn a_removal_keeps_a_file_somebody_edited() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::ClaudeCode, InstallScope::User);
        installer.install(&params).expect("installs");
        let edited = tree
            .home()
            .join(".claude/skills/kalareach-contact/TOOLS.md");
        std::fs::write(&edited, "their notes").expect("writes");
        let removed = installer.remove(&params).expect("removes");
        assert!(edited.is_file());
        assert!(
            removed
                .retained
                .iter()
                .any(|note| note.contains("has changed"))
        );
    }

    #[test]
    fn an_entry_this_host_did_not_write_is_never_replaced() {
        let tree = Tree::create();
        let installer = tree.installer();
        std::fs::write(
            tree.home().join(".claude.json"),
            r#"{"mcpServers":{"kalareach":{"command":"somebody-elses-server"}}}"#,
        )
        .expect("writes");
        let error = installer
            .install(&params(AgentTarget::ClaudeCode, InstallScope::User))
            .expect_err("refuses");
        assert_eq!(
            error.to_protocol_error().code,
            kr_protocol::error::ErrorCode::PermissionDenied
        );
    }

    #[test]
    fn a_codex_installation_edits_the_toml_in_place() {
        let tree = Tree::create();
        let installer = tree.installer();
        std::fs::create_dir_all(tree.home().join(".codex")).expect("a directory");
        std::fs::write(
            tree.home().join(".codex/config.toml"),
            "# a comment somebody wrote\nmodel = \"something\"\n\n[mcp_servers.theirs]\ncommand = \"their-server\"\n",
        )
        .expect("writes");
        let params = params(AgentTarget::Codex, InstallScope::User);
        installer.install(&params).expect("installs");
        let text =
            std::fs::read_to_string(tree.home().join(".codex/config.toml")).expect("the file");
        assert!(text.contains("# a comment somebody wrote"));
        assert!(text.contains("[mcp_servers.theirs]"));
        assert!(text.contains("[mcp_servers.kalareach]"));
        assert!(text.contains("agent-tools"));

        installer.remove(&params).expect("removes");
        let text =
            std::fs::read_to_string(tree.home().join(".codex/config.toml")).expect("the file");
        assert!(text.contains("# a comment somebody wrote"));
        assert!(text.contains("[mcp_servers.theirs]"));
        assert!(!text.contains("[mcp_servers.kalareach]"));
    }

    #[test]
    fn a_file_this_host_did_not_write_stops_the_installation_before_anything_changes() {
        let tree = Tree::create();
        let installer = tree.installer();
        let skills = tree.home().join(".claude/skills/kalareach-contact");
        std::fs::create_dir_all(&skills).expect("a directory");
        std::fs::write(skills.join("SKILL.md"), "somebody's own notes").expect("writes");
        let error = installer
            .install(&params(AgentTarget::ClaudeCode, InstallScope::User))
            .expect_err("refuses");
        assert_eq!(
            error.to_protocol_error().code,
            kr_protocol::error::ErrorCode::PermissionDenied
        );
        assert_eq!(
            std::fs::read_to_string(skills.join("SKILL.md")).expect("still there"),
            "somebody's own notes"
        );
        assert!(!tree.home().join(".claude.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_private_configuration_stays_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let tree = Tree::create();
        let configuration = tree.home().join(".claude.json");
        std::fs::write(&configuration, "{}").expect("writes");
        std::fs::set_permissions(&configuration, std::fs::Permissions::from_mode(0o600))
            .expect("makes it private");
        tree.installer()
            .install(&params(AgentTarget::ClaudeCode, InstallScope::User))
            .expect("installs");
        let mode = std::fs::metadata(&configuration)
            .expect("the file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the configuration kept its permissions");
    }

    #[test]
    fn a_shared_project_entry_survives_one_installation_being_removed() {
        let tree = Tree::create();
        let installer = tree.installer();
        let project = tree.root.join("project");
        std::fs::create_dir_all(&project).expect("a project");
        let with_project = |agent| AgentToolsParams {
            agent,
            scope: InstallScope::Project,
            project_dir: Nullable::some(display(&project)),
        };
        installer
            .install(&with_project(AgentTarget::ClaudeCode))
            .expect("installs");
        installer
            .install(&with_project(AgentTarget::QoderCli))
            .expect("installs");
        let shared = project.join(".mcp.json");
        assert!(shared.is_file());

        let removed = installer
            .remove(&with_project(AgentTarget::ClaudeCode))
            .expect("removes");
        let configuration: Value =
            serde_json::from_str(&std::fs::read_to_string(&shared).expect("the file"))
                .expect("json");
        assert!(
            configuration["mcpServers"].get("kalareach").is_some(),
            "the other installation still has its server: {configuration}"
        );
        assert!(
            removed
                .retained
                .iter()
                .any(|note| note.contains("still uses it")),
            "the removal says why it kept it: {:?}",
            removed.retained
        );

        installer
            .remove(&with_project(AgentTarget::QoderCli))
            .expect("removes");
        let configuration: Value =
            serde_json::from_str(&std::fs::read_to_string(&shared).expect("the file"))
                .expect("json");
        assert!(configuration["mcpServers"].get("kalareach").is_none());
    }

    #[test]
    fn an_installation_action_is_answered_once_and_conflicts_on_a_changed_payload() {
        let tree = Tree::create();
        let installer = tree.installer();
        let actor = kr_protocol::ids::ActorId::new("local:501").expect("a principal");
        let action =
            kr_protocol::ids::ActionId::new(kr_protocol::scalars::Uuid::from_bytes([7; 16]));
        let digest = digest_of(b"one payload");
        let other = digest_of(b"another payload");

        assert!(
            installer
                .retained(&actor, action, &digest)
                .expect("reads")
                .is_none()
        );
        installer
            .mark_dispatching(&actor, action, &digest)
            .expect("marks");
        // A marker with no outcome is uncertain: the files may have changed, and repeating the
        // change is what section 9 forbids.
        let error = installer
            .retained(&actor, action, &digest)
            .expect_err("uncertain");
        assert_eq!(
            error.to_protocol_error().code,
            kr_protocol::error::ErrorCode::OutcomeUnknown
        );

        let result = kr_protocol::envelope::ParamsValue::from_typed(&AgentToolsRemoveResult {
            agent: AgentTarget::Codex,
            scope: InstallScope::User,
            removed: Vec::new(),
            retained: Vec::new(),
        })
        .expect("encodes");
        installer
            .settle(&actor, action, &digest, &result)
            .expect("settles");
        assert_eq!(
            installer.retained(&actor, action, &digest).expect("reads"),
            Some(result)
        );
        let error = installer
            .retained(&actor, action, &other)
            .expect_err("conflict");
        assert_eq!(
            error.to_protocol_error().code,
            kr_protocol::error::ErrorCode::IdConflict
        );
    }

    #[test]
    fn a_project_scope_installation_needs_the_project_directory() {
        let tree = Tree::create();
        let error = tree
            .installer()
            .install(&params(AgentTarget::ClaudeCode, InstallScope::Project))
            .expect_err("refuses");
        assert_eq!(
            error.to_protocol_error().code,
            kr_protocol::error::ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn every_agent_has_a_user_layout() {
        let tree = Tree::create();
        let installer = tree.installer();
        for agent in AgentTarget::ALL {
            installer
                .install(&params(*agent, InstallScope::User))
                .unwrap_or_else(|error| panic!("{agent} installs: {error}"));
            let status = installer
                .status(&params(*agent, InstallScope::User))
                .expect("reads");
            assert!(status.installed, "{agent} is installed");
            assert!(status.drift.is_empty(), "{agent} has no drift");
        }
    }
}
