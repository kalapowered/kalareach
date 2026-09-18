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
            write_atomically(&path, contents.as_bytes())?;
            operations.push(ChangeOperation::WriteFile {
                path: display(&path),
                digest: digest_of(contents.as_bytes()),
                replaced_digest: Nullable(replaced),
            });
        }
        if let Some(configuration) = layout.configuration.as_ref() {
            operations.push(self.write_entry(configuration)?);
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
                } => match self.remove_entry(Path::new(path), *digest, *created_document)? {
                    Removal::Removed => removed.push(operation.clone()),
                    Removal::Kept(reason) => retained.push(format!("{entry} in {path}: {reason}")),
                },
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
    fn write_entry(&self, configuration: &Configuration) -> Result<ChangeOperation> {
        let created_document = !configuration.path.exists();
        if let Some(parent) = configuration.path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent).map_err(storage)?;
        }
        let digest = match configuration.format {
            Format::CodexToml => self.write_toml_entry(&configuration.path)?,
            format => self.write_json_entry(&configuration.path, format)?,
        };
        Ok(ChangeOperation::AddConfigurationEntry {
            path: display(&configuration.path),
            entry: format!("{}.{SERVER_NAME}", configuration.format.json_key()),
            digest,
            created_document,
        })
    }

    fn write_toml_entry(&self, path: &Path) -> Result<Digest256> {
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
            self.guard_existing(path)?;
        }
        let mut entry = toml_edit::Table::new();
        entry["command"] = toml_edit::value(self.executable.clone());
        let mut args = toml_edit::Array::new();
        for argument in ENTRY_ARGS {
            args.push(*argument);
        }
        entry["args"] = toml_edit::value(args);
        table.insert(SERVER_NAME, toml_edit::Item::Table(entry));
        write_atomically(path, document.to_string().as_bytes())?;
        self.entry_digest(path)?.ok_or_else(|| {
            ControllerError::InvalidArgument(format!("{} did not keep the entry", display(path)))
        })
    }

    fn write_json_entry(&self, path: &Path, format: Format) -> Result<Digest256> {
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
            self.guard_existing(path)?;
        }
        servers.insert(SERVER_NAME.to_owned(), self.entry_value(format));
        let text = serde_json::to_string_pretty(&document)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        write_atomically(path, format!("{text}\n").as_bytes())?;
        self.entry_digest(path)?.ok_or_else(|| {
            ControllerError::InvalidArgument(format!("{} did not keep the entry", display(path)))
        })
    }

    /// Refuses to replace an entry this host did not write.
    fn guard_existing(&self, path: &Path) -> Result<()> {
        let present = self.entry_digest(path)?;
        let ours = self.records_hold(present.as_ref());
        if ours {
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

    /// Returns true when some record of this host wrote an entry with this digest.
    fn records_hold(&self, digest: Option<&Digest256>) -> bool {
        let Some(digest) = digest else {
            return false;
        };
        let Ok(entries) = std::fs::read_dir(&self.records) else {
            return false;
        };
        entries.flatten().any(|entry| {
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                return false;
            };
            let Ok(manifest) = serde_json::from_str::<ChangeManifest>(&text) else {
                return false;
            };
            manifest.operations.iter().any(|operation| {
                matches!(
                    operation,
                    ChangeOperation::AddConfigurationEntry { digest: recorded, .. }
                        if recorded == digest
                )
            })
        })
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

    /// Removes the server entry, when it is still the one that was written.
    fn remove_entry(
        &self,
        path: &Path,
        digest: Digest256,
        created_document: bool,
    ) -> Result<Removal> {
        let Some(present) = self.entry_digest(path)? else {
            return Ok(Removal::Kept("it is already gone".to_owned()));
        };
        if present != digest {
            return Ok(Removal::Kept(
                "it has changed since it was installed".to_owned(),
            ));
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
            write_atomically(path, document.to_string().as_bytes())?;
        } else {
            let mut document = read_json(path)?;
            if let Some(root) = document.as_object_mut() {
                for key in ["mcpServers", "mcp"] {
                    if let Some(servers) = root.get_mut(key).and_then(Value::as_object_mut) {
                        servers.remove(SERVER_NAME);
                    }
                }
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
            write_atomically(path, format!("{text}\n").as_bytes())?;
        }
        Ok(Removal::Removed)
    }

    fn entry_value(&self, format: Format) -> Value {
        let arguments: Vec<&str> = ENTRY_ARGS.to_vec();
        match format {
            Format::JsonLocalCommandList => {
                let mut command = vec![self.executable.clone()];
                command.extend(arguments.iter().map(|argument| (*argument).to_owned()));
                json!({"type": "local", "command": command, "enabled": true})
            }
            Format::CodexToml | Format::JsonCommandArgs => {
                json!({"type": "stdio", "command": self.executable, "args": arguments})
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
            (AgentTarget::Codex, User) => Layout {
                skills: home.join(".codex/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: home.join(".codex/config.toml"),
                    format: Format::CodexToml,
                }),
            },
            // Codex reads its servers from the user configuration alone, so a project-scope
            // installation places the skill in the project and says, by recording no entry, that
            // the server stays registered where the user configuration has it.
            (AgentTarget::Codex, Project) => Layout {
                skills: project()?.join(".codex/skills").join(SKILL_NAME),
                configuration: None,
            },
            (AgentTarget::ClaudeCode, User) => Layout {
                skills: home.join(".claude/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: home.join(".claude.json"),
                    format: Format::JsonCommandArgs,
                }),
            },
            (AgentTarget::ClaudeCode, Project) => Layout {
                skills: project()?.join(".claude/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: project()?.join(".mcp.json"),
                    format: Format::JsonCommandArgs,
                }),
            },
            (AgentTarget::Opencode, User) => Layout {
                skills: home.join(".config/opencode/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: home.join(".config/opencode/opencode.json"),
                    format: Format::JsonLocalCommandList,
                }),
            },
            (AgentTarget::Opencode, Project) => Layout {
                skills: project()?.join(".opencode/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: project()?.join("opencode.json"),
                    format: Format::JsonLocalCommandList,
                }),
            },
            (AgentTarget::GeminiCli, User) => Layout {
                skills: home.join(".gemini/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: home.join(".gemini/settings.json"),
                    format: Format::JsonCommandArgs,
                }),
            },
            (AgentTarget::GeminiCli, Project) => Layout {
                skills: project()?.join(".gemini/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: project()?.join(".gemini/settings.json"),
                    format: Format::JsonCommandArgs,
                }),
            },
            (AgentTarget::KimiCodeCli, User) => Layout {
                skills: home.join(".kimi-code/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: home.join(".kimi-code/mcp.json"),
                    format: Format::JsonCommandArgs,
                }),
            },
            (AgentTarget::KimiCodeCli, Project) => Layout {
                skills: project()?.join(".kimi/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: project()?.join(".mcp.json"),
                    format: Format::JsonCommandArgs,
                }),
            },
            (AgentTarget::QoderCli, User) => Layout {
                skills: home.join(".qoder/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: home.join(".qoder/settings.json"),
                    format: Format::JsonCommandArgs,
                }),
            },
            (AgentTarget::QoderCli, Project) => Layout {
                skills: project()?.join(".qoder/skills").join(SKILL_NAME),
                configuration: Some(Configuration {
                    path: project()?.join(".mcp.json"),
                    format: Format::JsonCommandArgs,
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
        write_atomically(&self.record_path(params), format!("{text}\n").as_bytes())
    }
}

/// What a removal did with one configuration entry.
enum Removal {
    /// It was the entry that was written, and it is gone.
    Removed,
    /// It was left alone, for the stated reason.
    Kept(String),
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

/// Writes a file so a failure part way through cannot truncate what was there.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let temporary = parent.join(format!(".{}.kalareach", file_name(path)));
    std::fs::write(&temporary, bytes).map_err(storage)?;
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
