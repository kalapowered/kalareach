//! Installing the contact skill, and undoing exactly what was installed.
//!
//! Section 11 asks for an installation recipe with exact files, hashes, version requirements and
//! removal operations, and for unrelated settings to be preserved. Three rules make that real
//! rather than hoped for.
//!
//! * **Every change is recorded with the digest of what it wrote.** The record is kept in this
//!   host's own state directory, not in the agent's, so an agent that rewrites its configuration
//!   cannot lose it. A removal undoes what the record owns, taking files and server entries before
//!   the directories that held them and a deeper directory before a shallower one, and stops at
//!   anything whose digest no longer matches, because a changed file is somebody's edit.
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

/// The variable an installation tells the tool server its client's deadline through.
///
/// The server cannot see a deadline the client never sends, and guessing one would either cut a
/// wait short or run past what the client allows. The installation knows: it is the side that
/// writes the deadline into the agent's configuration, so it writes the same number into the
/// environment the agent launches the server with.
pub const DEADLINE_VARIABLE: &str = "KR_TOOL_DEADLINE_MS";

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
    /// Returns the top-level key this document holds servers under, in its own spelling.
    const fn key(self) -> &'static str {
        match self {
            Self::CodexToml => "mcp_servers",
            Self::JsonLocalCommandList => "mcp",
            Self::JsonCommandArgs => "mcpServers",
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
        // A record an earlier build named differently is carried onto the name this one gives it,
        // here rather than in a read, so it happens once and under this mutation's own lock.
        self.migrate_records(params)?;
        let existing = self.recorded(params)?;
        if let Some(existing) = existing.as_ref()
            && existing.is_complete()
            && self.drift(&existing.manifest)?.is_empty()
        {
            return Ok(AgentToolsInstallResult {
                manifest: existing.manifest.clone(),
                already_installed: true,
                unresolved: Vec::new(),
            });
        }
        let root = layout.skills.clone();
        // What this host already did keeps its place. An installation that repairs one file must
        // not drop the claim it holds on the others or on its configuration entry, because a claim
        // it drops is a claim it will later refuse to replace and will not remove.
        let (previous, carried) = existing.map_or_else(
            || {
                (
                    ChangeManifest {
                        skill_version: SKILL_VERSION.to_owned(),
                        agent: params.agent,
                        scope: params.scope,
                        root: display(&root),
                        entry_point: self.entry_point(),
                        operations: Vec::new(),
                    },
                    Vec::new(),
                )
            },
            // Whatever an earlier attempt was in the middle of stays unresolved until something
            // resolves it. A repair that quietly dropped the note would leave a change nobody can
            // account for and a record that says everything is accounted for.
            |existing| (existing.manifest, existing.pending),
        );
        let mut record = InstallationRecord {
            version: InstallationRecord::VERSION,
            state: InstallationRecord::INSTALLING.to_owned(),
            manifest: previous,
            pending: carried,
        };
        record.manifest.skill_version = SKILL_VERSION.to_owned();
        record.manifest.root = display(&root);
        record.manifest.entry_point = self.entry_point();

        // Each change is noted before it happens and recorded after it. A crash between the two
        // leaves the note, which says the change may or may not have happened: a removal reports
        // it rather than undoing something this host may never have written.
        for directory in missing_ancestors(&root) {
            let operation = ChangeOperation::CreateDirectory {
                path: display(&directory),
            };
            self.begin(params, &mut record, operation.clone())?;
            self.settle_directory(params, &mut record, &directory, operation)?;
        }
        for (name, contents) in files() {
            let path = root.join(name);
            let operation = ChangeOperation::WriteFile {
                path: display(&path),
                digest: digest_of(contents.as_bytes()),
                replaced_digest: Nullable(read_digest(&path)?),
            };
            self.confirm_existing(params, &mut record, &operation)?;
            self.begin(params, &mut record, operation.clone())?;
            write_atomically(&path, contents.as_bytes(), READABLE)?;
            self.finish(params, &mut record, operation)?;
        }
        // A note about a directory this run did not create resolves to nothing: the directory is
        // either there, in which case something else made it and this host does not claim it, or
        // it is not, in which case there is nothing to claim. Either way a removal would leave it,
        // so the note says nothing a reader needs and is dropped rather than carried for ever.
        record
            .pending
            .retain(|noted| !matches!(noted, ChangeOperation::CreateDirectory { .. }));
        self.write(params, &record)?;
        if let Some(configuration) = layout.configuration.as_ref() {
            // The directory the document lives in is part of the installation when this host has
            // to create it, so it is recorded like any other change.
            if let Some(parent) = configuration.path.parent() {
                for directory in missing_ancestors(parent) {
                    let operation = ChangeOperation::CreateDirectory {
                        path: display(&directory),
                    };
                    self.begin(params, &mut record, operation.clone())?;
                    self.settle_directory(params, &mut record, &directory, operation)?;
                }
            }
            let planned = ChangeOperation::AddConfigurationEntry {
                path: display(&configuration.path),
                entry: format!("{}.{SERVER_NAME}", configuration.format.key()),
                digest: self.planned_entry_digest(configuration, params.agent),
                // Whether this host created the document is a fact about the first installation
                // that wrote it, not about this one. A repair keeps what was recorded.
                created_document: self.created_document(&record, &configuration.path)
                    || !configuration.path.exists(),
            };
            self.confirm_existing(params, &mut record, &planned)?;
            self.begin(params, &mut record, planned)?;
            let written = self.write_entry(configuration, params.agent)?;
            let written = self.keep_provenance(&record, written, &configuration.path);
            self.finish(params, &mut record, written)?;
        }
        // What this run could not account for. Every change it made resolved its own note, and a
        // note about a directory was dropped above, so anything still here belongs to an earlier
        // attempt and names something this installation no longer touches. It is reported, and the
        // record stays open, because claiming an installation finished while something it may have
        // written is unaccounted for is the claim this whole record exists to avoid.
        let unresolved: Vec<String> = record
            .pending
            .iter()
            .map(|operation| {
                format!(
                    "{} may or may not have been written by an earlier attempt; this host does \
                     not claim it, `kr skill remove` will not undo it, and it has to be looked at \
                     by hand",
                    operation.path()
                )
            })
            .collect();
        if unresolved.is_empty() {
            record.state = InstallationRecord::INSTALLED.to_owned();
        }
        self.write(params, &record)?;
        Ok(AgentToolsInstallResult {
            manifest: record.manifest,
            already_installed: false,
            unresolved,
        })
    }

    /// Records a directory this installation created, or forgets one it did not.
    ///
    /// A directory that was already there when the call ran belongs to whatever made it. Claiming
    /// it would let a later removal delete somebody else's, so the note is simply dropped.
    fn settle_directory(
        &self,
        params: &AgentToolsParams,
        record: &mut InstallationRecord,
        directory: &Path,
        operation: ChangeOperation,
    ) -> Result<()> {
        if create_directory_durably(directory)? {
            self.finish(params, record, operation)
        } else {
            record
                .pending
                .retain(|noted| !same_target(noted, &operation));
            self.write(params, record)
        }
    }

    /// Confirms what an earlier attempt left where this one is about to write.
    ///
    /// A note says this host was writing something to that place and could not confirm it. Where
    /// what is there is exactly what the note names, preflight has already decided it is this
    /// host's own unfinished work, and recording that is what keeps the claim: the note is about to
    /// be replaced by one for the new content, and the evidence for what is on disk now would go
    /// with it. Confirming first means a replacement that fails half way leaves a record that still
    /// accounts for what is there.
    fn confirm_existing(
        &self,
        params: &AgentToolsParams,
        record: &mut InstallationRecord,
        planned: &ChangeOperation,
    ) -> Result<()> {
        let Some(noted) = record
            .pending
            .iter()
            .find(|noted| same_target(noted, planned))
            .cloned()
        else {
            return Ok(());
        };
        let holds = match &noted {
            ChangeOperation::WriteFile { path, digest, .. } => {
                read_digest(Path::new(path))? == Some(*digest)
            }
            ChangeOperation::AddConfigurationEntry {
                path,
                entry,
                digest,
                ..
            } => {
                let key = entry
                    .rsplit_once('.')
                    .map_or(entry.as_str(), |(key, _)| key);
                self.entry_digest_under(Path::new(path), key)? == Some(*digest)
            }
            // A directory is claimed when this host creates it, and never afterwards.
            ChangeOperation::CreateDirectory { .. } => false,
        };
        if !holds {
            return Ok(());
        }
        record.pending.retain(|noted| !same_target(noted, planned));
        merge(&mut record.manifest.operations, noted);
        self.write(params, record)
    }

    /// Notes a change this installation is about to make.
    fn begin(
        &self,
        params: &AgentToolsParams,
        record: &mut InstallationRecord,
        operation: ChangeOperation,
    ) -> Result<()> {
        merge(&mut record.pending, operation);
        self.write(params, record)
    }

    /// Records a change this installation has made.
    fn finish(
        &self,
        params: &AgentToolsParams,
        record: &mut InstallationRecord,
        operation: ChangeOperation,
    ) -> Result<()> {
        // The note this change left is resolved, and only that one: a note some earlier attempt
        // left about a different target is still unresolved.
        record
            .pending
            .retain(|noted| !same_target(noted, &operation));
        merge(&mut record.manifest.operations, operation);
        self.write(params, record)
    }

    /// Returns whether a recorded entry says this host created the document it is in.
    fn created_document(&self, record: &InstallationRecord, path: &Path) -> bool {
        let wanted = display(path);
        record.manifest.operations.iter().any(|operation| {
            matches!(
                operation,
                ChangeOperation::AddConfigurationEntry {
                    path: recorded,
                    created_document: true,
                    ..
                } if *recorded == wanted
            )
        })
    }

    /// Keeps the first installation's record of whether this host created the document.
    fn keep_provenance(
        &self,
        record: &InstallationRecord,
        written: ChangeOperation,
        path: &Path,
    ) -> ChangeOperation {
        match written {
            ChangeOperation::AddConfigurationEntry {
                path: entry_path,
                entry,
                digest,
                created_document,
            } => ChangeOperation::AddConfigurationEntry {
                path: entry_path,
                entry,
                digest,
                created_document: created_document || self.created_document(record, path),
            },
            other => other,
        }
    }

    /// Returns the digest the configuration entry will have once it is written.
    ///
    /// The plan carries it so a removal after an interrupted installation can tell the entry this
    /// host wrote from one somebody else put there.
    fn planned_entry_digest(&self, configuration: &Configuration, agent: AgentTarget) -> Digest256 {
        let declaring = (!configuration.shared).then_some(agent);
        if configuration.format == Format::CodexToml {
            let mut entry = toml_edit::Table::new();
            entry["command"] = toml_edit::value(self.executable.clone());
            let mut args = toml_edit::Array::new();
            for argument in ENTRY_ARGS {
                args.push(*argument);
            }
            entry["args"] = toml_edit::value(args);
            if let Some((field, seconds)) = declaring.and_then(deadline_field)
                && let Some(seconds) = seconds.as_i64()
            {
                entry[field] = toml_edit::value(seconds);
            }
            if let Some(milliseconds) = declaring.and_then(deadline_milliseconds) {
                let mut environment = toml_edit::InlineTable::new();
                environment.insert(DEADLINE_VARIABLE, milliseconds.to_string().into());
                entry["env"] = toml_edit::value(environment);
            }
            return digest_of(toml_edit::Item::Table(entry).to_string().trim().as_bytes());
        }
        digest_of(
            self.entry_value(configuration.format, declaring)
                .to_string()
                .as_bytes(),
        )
    }

    /// Reports what is installed, and what no longer matches what was written.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read.
    pub fn status(&self, params: &AgentToolsParams) -> Result<AgentToolsStatusResult> {
        let layout = self.layout(params)?;
        let Some(record) = self.recorded(params)? else {
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
        let manifest = &record.manifest;
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
        let mut drift = self.drift(manifest)?;
        if !record.is_complete() {
            drift.push(format!(
                "an installation of {} at {} scope was begun and did not finish; `kr skill \
                 remove` undoes what it recorded",
                params.agent, params.scope
            ));
        }
        for operation in &record.pending {
            drift.push(format!(
                "{} may or may not have been written when that installation stopped; it is left \
                 alone",
                operation.path()
            ));
        }
        Ok(AgentToolsStatusResult {
            agent: params.agent,
            scope: params.scope,
            root: manifest.root.clone(),
            installed: record.is_complete(),
            skill_version: Nullable::some(manifest.skill_version.clone()),
            files,
            drift,
            // The order a removal would actually use, so what this reports is what would happen.
            removal: removal_order(&manifest.operations)
                .into_iter()
                .cloned()
                .collect(),
        })
    }

    /// Undoes exactly what an installation recorded.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read or a file cannot be removed.
    pub fn remove(&self, params: &AgentToolsParams) -> Result<AgentToolsRemoveResult> {
        // The record is read, and read as valid, before anything is moved: a record this build
        // does not understand must not change its name on the way to being refused.
        let read = self.removable(params)?;
        self.migrate_records(params)?;
        let Some(record) = read else {
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
        let mut retained: Vec<String> = record
            .pending
            .iter()
            .map(|operation| {
                format!(
                    "a change to {} may or may not have been written when the installation \
                     stopped; the change itself is left alone, though an earlier recorded write \
                     to the same place is still undone below",
                    operation.path()
                )
            })
            .collect();
        // What was recorded, in the order a removal can actually carry out: the files and the
        // configuration entries first, then the directories, deepest first. Record order is the
        // order the installation wrote things, and a repair can put a directory after the files
        // inside it, which reversed would try to remove a directory that is not empty yet.
        for operation in removal_order(&record.manifest.operations) {
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
                            if let Some(parent) = Path::new(path).parent() {
                                sync_directory(parent)?;
                            }
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
                        Ok(()) => {
                            if let Some(parent) = Path::new(path).parent() {
                                sync_directory(parent)?;
                            }
                            removed.push(operation.clone());
                        }
                        Err(_) => retained.push(format!("{path} is not empty")),
                    }
                }
            }
        }
        let record = self.record_path(params);
        if record.exists() {
            std::fs::remove_file(&record).map_err(storage)?;
            sync_directory(&self.records)?;
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
                } => match self.entry_digest_under(
                    Path::new(path),
                    entry.rsplit_once('.').map_or("mcpServers", |(key, _)| key),
                )? {
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
            entry: format!("{}.{SERVER_NAME}", configuration.format.key()),
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
        if let Some(milliseconds) = agent.and_then(deadline_milliseconds) {
            let mut environment = toml_edit::InlineTable::new();
            environment.insert(DEADLINE_VARIABLE, milliseconds.to_string().into());
            entry["env"] = toml_edit::value(environment);
        }
        table.insert(SERVER_NAME, toml_edit::Item::Table(entry));
        write_atomically(path, document.to_string().as_bytes(), PRIVATE)?;
        self.entry_digest_under(path, Format::CodexToml.key())?
            .ok_or_else(|| {
                ControllerError::InvalidArgument(format!(
                    "{} did not keep the entry",
                    display(path)
                ))
            })
    }

    fn write_json_entry(
        &self,
        path: &Path,
        format: Format,
        agent: Option<AgentTarget>,
    ) -> Result<Digest256> {
        let mut document = read_json(path)?;
        let key = format.key();
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
        self.entry_digest_under(path, key)?.ok_or_else(|| {
            ControllerError::InvalidArgument(format!("{} did not keep the entry", display(path)))
        })
    }

    /// Refuses a removal that cannot be carried out, without carrying any of it out.
    ///
    /// Everything here reads. It runs before the dispatch marker, so a removal this host will not
    /// do is refused rather than recorded as a change whose outcome nobody knows.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::PermissionDenied`] on a platform this host cannot change an
    /// installation on, or where a document it would rewrite is protected by an access-control
    /// list, and [`ControllerError::InvalidArgument`] when the scope needs a project directory
    /// that was not given, or the record cannot be read.
    pub fn check_removal(&self, params: &AgentToolsParams) -> Result<()> {
        self.removable(params).map(|_| ())
    }

    /// Reads what a removal would work from, refusing everything it cannot do.
    fn removable(&self, params: &AgentToolsParams) -> Result<Option<InstallationRecord>> {
        supported_platform()?;
        // A removal of something never installed still has to know where it would have been, or it
        // is not the removal of anything in particular.
        self.layout(params)?;
        let Some(record) = self.recorded(params)? else {
            return Ok(None);
        };
        // Every document this removal would rewrite. A removal that took the package and then
        // refused the document would leave the agent with an entry pointing at a skill that is no
        // longer there.
        for operation in &record.manifest.operations {
            if let ChangeOperation::AddConfigurationEntry { path, .. } = operation {
                guard_access_controls(Path::new(path))?;
            }
        }
        Ok(Some(record))
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
        supported_platform()?;
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
            let wanted = display(&path);
            // A file this host wrote, or one it was in the middle of writing when an installation
            // stopped, holding exactly the content that record names. The in-flight note counts
            // because the content is evidence for the note: this host was writing those bytes to
            // that path, so what is there is its own unfinished work, and refusing here would
            // leave an interrupted installation unrepairable. The content it names is not always
            // the content this build would write — an interrupted installation of an earlier
            // package version says so — and repairing then replaces this host's own file.
            // Anything else at that path is somebody's own file, and an installation does not
            // write over one.
            let ours = recorded.as_ref().is_some_and(|record| {
                record
                    .manifest
                    .operations
                    .iter()
                    .chain(record.pending.iter())
                    .any(|operation| {
                        matches!(
                            operation,
                            ChangeOperation::WriteFile { path: recorded_path, digest, .. }
                                if *recorded_path == wanted && *digest == present
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
            // The container the entry goes into, not only the entry. A document whose server
            // container is something other than a table is refused here rather than after the
            // skill files have been written.
            self.check_container(configuration)?;
            // The document's own protection, before anything is written. This host's own files
            // carry no such risk: they are its records and the package it wrote.
            guard_access_controls(&configuration.path)?;
        }
        Ok(())
    }

    /// Refuses a configuration document this installation could not finish writing.
    fn check_container(&self, configuration: &Configuration) -> Result<()> {
        let Some(text) = read_to_string(&configuration.path)? else {
            return Ok(());
        };
        let path = &configuration.path;
        let key = configuration.format.key();
        if configuration.format == Format::CodexToml {
            let document: toml_edit::DocumentMut = text.parse().map_err(|error| {
                ControllerError::InvalidArgument(format!("{}: {error}", display(path)))
            })?;
            if let Some(item) = document.get(key)
                && item.as_table().is_none()
            {
                return Err(ControllerError::InvalidArgument(format!(
                    "{key} in {} holds something other than a table of servers",
                    display(path)
                )));
            }
            return Ok(());
        }
        if text.trim().is_empty() {
            return Ok(());
        }
        let document: Value = serde_json::from_str(&text).map_err(|error| {
            ControllerError::InvalidArgument(format!("{}: {error}", display(path)))
        })?;
        if !document.is_object() {
            return Err(ControllerError::InvalidArgument(format!(
                "{} is not a JSON object",
                display(path)
            )));
        }
        if let Some(container) = document.get(key)
            && !container.is_object()
        {
            return Err(ControllerError::InvalidArgument(format!(
                "{key} in {} is not an object of servers",
                display(path)
            )));
        }
        Ok(())
    }

    /// Refuses to replace an entry this host did not write.
    fn guard_existing(&self, path: &Path, format: Format) -> Result<()> {
        let Some(present) = self.entry_digest_under(path, format.key())? else {
            return Ok(());
        };
        if self.records_hold(path, format.key(), &present)? {
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
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when a record cannot be read, because a record this
    /// host cannot read is a claim it cannot rule out.
    fn records_hold(&self, path: &Path, key: &str, digest: &Digest256) -> Result<bool> {
        Ok(!self.holders(path, key, digest, None)?.is_empty())
    }

    /// Returns the records that claim this exact entry, except the one named.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when the records directory or one of its files cannot
    /// be read.
    fn holders(
        &self,
        path: &Path,
        key: &str,
        digest: &Digest256,
        except: Option<&Path>,
    ) -> Result<Vec<PathBuf>> {
        let entry_name = format!("{key}.{SERVER_NAME}");
        let wanted = display(path);
        let listing = match std::fs::read_dir(&self.records) {
            Ok(listing) => listing,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(storage(error)),
        };
        let mut found = Vec::new();
        for entry in listing {
            let entry = entry.map_err(storage)?;
            // Only this host's own installation records, by the name it gives them. A temporary
            // file left by an interrupted write begins with a dot and is not one; the action
            // records live in a directory of their own.
            if !entry.path().is_file()
                || !is_record_name(&entry.file_name().to_string_lossy())
                || except.is_some_and(|skip| skip == entry.path())
            {
                continue;
            }
            let text = std::fs::read_to_string(entry.path()).map_err(storage)?;
            // A record this host cannot read is a claim it cannot rule out, and removing an entry
            // on the strength of that would take a server somebody else is using.
            let record = read_record(&text).map_err(|error| ControllerError::Storage {
                operation: "read an installation record",
                detail: format!("{}: {error}", display(&entry.path())),
            })?;
            // A claim this record made, or one it may have made and could not confirm. Both
            // count, in both directions: a removal must not take an entry another installation may
            // own, and a repair must be able to finish writing the entry it was interrupted
            // writing.
            let claims = record
                .manifest
                .operations
                .iter()
                .chain(record.pending.iter())
                .any(|operation| {
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
                });
            if claims {
                found.push(entry.path());
            }
        }
        Ok(found)
    }

    /// Returns the digest of the server entry under one named key.
    ///
    /// The digest covers the entry alone, canonically rendered, so it does not change when
    /// something unrelated in the file does. The key is always the one the record names: a
    /// document that happens to hold two server containers must not have one of them answer for
    /// the other.
    fn entry_digest_under(&self, path: &Path, key: &str) -> Result<Option<Digest256>> {
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
                .get(key)
                .and_then(|servers| servers.as_table())
                .and_then(|servers| servers.get(SERVER_NAME));
            return Ok(entry.map(|entry| digest_of(entry.to_string().trim().as_bytes())));
        }
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
        // the server another installation is still using, so the entry goes only when no *other*
        // record claims it. This record is excluded by name rather than by counting, because a
        // count cannot tell this record from somebody else's when its own file has already gone.
        let others = self.holders(path, key, &digest, Some(&self.record_path(params)))?;
        if !others.is_empty() {
            return Ok(Removal::Kept(format!(
                "{} other installation(s) on this host still use it; {} at {} scope was removed \
                 around it",
                others.len(),
                params.agent,
                params.scope
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
                .get_mut(key)
                .and_then(|servers| servers.as_table_mut())
            {
                servers.remove(SERVER_NAME);
            }
            // The document itself stays, even when this host created it and the entry was the
            // only thing in it. A format-preserving editor keeps comments and spacing that are
            // nobody's business but the author's, and an empty-looking table is not evidence the
            // file holds nothing of theirs. The JSON branch below can delete one because it
            // reparses the document and can see that it holds nothing at all.
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
                if let Some(parent) = path.parent() {
                    sync_directory(parent)?;
                }
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
                // The same number the entry declares, in the environment the agent launches the
                // server with, so the server bounds its own waits by what this client allows
                // instead of by a guess.
                if let Some(object) = entry.as_object_mut()
                    && let Some(milliseconds) = agent.and_then(deadline_milliseconds)
                {
                    object.insert(
                        "env".to_owned(),
                        json!({ DEADLINE_VARIABLE: milliseconds.to_string() }),
                    );
                }
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
        // A user installation is one per agent, whatever else the request carried. Naming it after
        // a project directory would give it a name the record reader does not recognise, and a
        // record nothing recognises is a claim nothing can honour.
        let scope = match (params.scope, params.project_dir.as_ref()) {
            (kr_protocol::skill::InstallScope::Project, Some(directory)) => format!(
                "{}-{}",
                params.scope,
                hex(&kr_cbor::sha256(directory.as_bytes())[..8])
            ),
            _ => params.scope.to_string(),
        };
        self.records.join(format!("{}-{scope}.json", params.agent))
    }

    /// Returns the records an earlier build wrote for this installation under a name this build
    /// does not give one.
    ///
    /// That build named a user record after a project directory the request happened to carry.
    /// An ordinary request carries none, so the name cannot be worked out again; it is recognised
    /// by its shape instead.
    fn legacy_records(&self, params: &AgentToolsParams) -> Result<Vec<PathBuf>> {
        if params.scope != kr_protocol::skill::InstallScope::User {
            return Ok(Vec::new());
        }
        let prefix = format!("{}-{}-", params.agent, params.scope);
        let listing = match std::fs::read_dir(&self.records) {
            Ok(listing) => listing,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(storage(error)),
        };
        let mut found = Vec::new();
        for entry in listing {
            let entry = entry.map_err(storage)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.path().is_file() && is_legacy_user_record(&name, &prefix) {
                found.push(entry.path());
            }
        }
        found.sort();
        Ok(found)
    }

    /// Returns the file this installation's record is in, whatever name it wears.
    fn record_source(&self, params: &AgentToolsParams) -> Result<Option<PathBuf>> {
        let path = self.record_path(params);
        if path.is_file() {
            return Ok(Some(path));
        }
        let legacy = self.legacy_records(params)?;
        match legacy.as_slice() {
            [] => Ok(None),
            [only] => Ok(Some(only.clone())),
            several => Err(ControllerError::InvalidArgument(format!(
                "an earlier build left {} records of installing {SKILL_NAME} for {} at {} scope \
                 ({}); only one of them describes this host, so keep that one and move the others \
                 aside",
                several.len(),
                params.agent,
                params.scope,
                several
                    .iter()
                    .map(|path| display(path))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }

    /// Moves a record an earlier build named after a project directory onto the name this build
    /// gives it.
    ///
    /// Nothing is overwritten. Where both names exist they are both left alone, and both keep
    /// counting towards the claims on a shared document. This runs with the installation it
    /// belongs to, under the same lock, and never during a read.
    fn migrate_records(&self, params: &AgentToolsParams) -> Result<()> {
        let path = self.record_path(params);
        if path.exists() {
            return Ok(());
        }
        let legacy = self.legacy_records(params)?;
        let [only] = legacy.as_slice() else {
            return Ok(());
        };
        std::fs::rename(only, &path).map_err(storage)?;
        sync_directory(&self.records)
    }

    fn recorded(&self, params: &AgentToolsParams) -> Result<Option<InstallationRecord>> {
        let Some(path) = self.record_source(params)? else {
            return Ok(None);
        };
        let Some(text) = read_to_string(&path)? else {
            return Ok(None);
        };
        read_record(&text).map(Some).map_err(|error| {
            ControllerError::InvalidArgument(format!("{}: {error}", display(&path)))
        })
    }

    fn write(&self, params: &AgentToolsParams, record: &InstallationRecord) -> Result<()> {
        create_directory_durably(&self.records)?;
        let text = serde_json::to_string_pretty(record)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        write_atomically(
            &self.record_path(params),
            format!("{text}\n").as_bytes(),
            PRIVATE,
        )
    }
}

/// What this host recorded about one installation.
///
/// It is a journal, not a plan. Each change is noted as pending before its effect and moved to the
/// manifest after it, and the state becomes `installed` once the last one has been made. An
/// installation interrupted part way through is therefore distinguishable from one that finished:
/// `kr skill status` reports it as unfinished, `kr skill remove` undoes what the manifest records
/// and reports what was pending rather than guessing at it, and a later installation does not
/// mistake it for complete.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct InstallationRecord {
    /// Which shape this record is written in.
    ///
    /// A record without one was written before the operations in it meant "this happened", so it
    /// is read as evidence of something uncertain rather than as ownership.
    #[serde(default)]
    version: u32,
    /// `installing` while the journal is being carried out, `installed` once it has been.
    state: String,
    /// What this installation has actually done, in the order it did it.
    ///
    /// Only these are undone. An operation reaches this list after its effect, so nothing here is
    /// a guess about what is on disk.
    manifest: ChangeManifest,
    /// What it was about to do when the record was last written.
    ///
    /// An operation is written here before its effect and moves to the manifest after it, so a
    /// crash leaves a note saying which change may or may not have happened. A removal does not
    /// act on one: a digest proves content, not who wrote it, and undoing something this host may
    /// never have written would delete somebody else's. It is reported instead.
    #[serde(default)]
    pending: Vec<ChangeOperation>,
}

impl InstallationRecord {
    /// The shape this build writes, in which a recorded operation is one that happened.
    const VERSION: u32 = 1;

    /// The state of a record whose journal has been carried out.
    const INSTALLED: &'static str = "installed";

    /// The state of a record that was begun and may not have been finished.
    const INSTALLING: &'static str = "installing";

    /// Returns true when the installation finished.
    fn is_complete(&self) -> bool {
        self.state == Self::INSTALLED && self.pending.is_empty()
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
            // Every missing ancestor, each one's own entry made durable in the directory above it,
            // before anything inside is claimed to be durable.
            create_directory_durably(parent)?;
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
    Ok(kr_protocol::envelope::ParamsValue::new(
        carry_result_forward(value)?,
    ))
}

/// Brings a result an earlier build recorded into the shape this one answers with.
///
/// An action is answered once: what it produced is replayed, never done again. A result that build
/// wrote has to be readable by a client of this one, and the only difference is the list of what an
/// installation could not account for, which that build had no way to leave behind. An empty list
/// is what it means.
fn carry_result_forward(value: kr_cbor::CanonicalValue) -> Result<kr_cbor::CanonicalValue> {
    let kr_cbor::CanonicalValue::Map(mut map) = value else {
        return Ok(value);
    };
    if map.get("manifest").is_some()
        && map.get("already_installed").is_some()
        && map.get("unresolved").is_none()
    {
        map.insert(
            "unresolved".to_owned(),
            kr_cbor::CanonicalValue::Array(Vec::new()),
        )
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
    }
    Ok(kr_cbor::CanonicalValue::Map(map))
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

/// Reads an installation record, accepting the shape an earlier build of this host wrote.
///
/// The earlier shape was the manifest alone, with no state beside it. Such a record describes what
/// was written but not whether the installation finished, so it is read as unfinished: repairing an
/// installation that was in fact complete writes the same files again, while claiming a completion
/// that may not have happened would leave a half-installed agent looking installed.
fn read_record(text: &str) -> std::result::Result<InstallationRecord, String> {
    let value: Value = serde_json::from_str(text).map_err(|error| error.to_string())?;
    let Some(version) = value.get("manifest").map(|_| {
        value
            .get("version")
            .and_then(Value::as_u64)
            .unwrap_or(UNVERSIONED)
    }) else {
        // The first shape: the manifest alone. That build recorded each change after making it, so
        // its operations are things that happened; what it does not say is whether the
        // installation finished, and a completion that may not have happened is never claimed.
        let manifest: ChangeManifest =
            serde_json::from_value(value).map_err(|error| error.to_string())?;
        return Ok(InstallationRecord {
            version: InstallationRecord::VERSION,
            state: InstallationRecord::INSTALLING.to_owned(),
            manifest,
            pending: Vec::new(),
        });
    };
    // An unversioned record is one of two shapes, and only the record itself can say which: the
    // journal wrote a `pending` list, the plan before it had no such thing. Serde's default would
    // erase that difference, so it is read from the document.
    let predicted = version == UNVERSIONED && value.get("pending").is_none();
    if version != UNVERSIONED && version != u64::from(InstallationRecord::VERSION) {
        return Err(format!(
            "this record was written in version {version}, which this build does not read; a \
             newer build wrote it and only that one should change it"
        ));
    }
    let mut record: InstallationRecord =
        serde_json::from_value(value).map_err(|error| error.to_string())?;
    record.version = InstallationRecord::VERSION;
    if predicted {
        // A record from the build that wrote its intentions rather than its effects. Those
        // operations may or may not have happened, so they become evidence of uncertainty: a
        // removal reports them and leaves them alone, because removing something this host may
        // never have written would delete somebody else's.
        record.pending = record
            .manifest
            .operations
            .drain(..)
            .chain(record.pending)
            .collect();
        record.state = InstallationRecord::INSTALLING.to_owned();
    }
    Ok(record)
}

/// The version an earlier build's record has, because it wrote none.
const UNVERSIONED: u64 = 0;

/// Returns the recorded operations in the order a removal undoes them.
///
/// Everything that lives inside a directory goes before the directory, and a deeper directory goes
/// before a shallower one, so nothing is asked to remove a directory something else still occupies.
fn removal_order(operations: &[ChangeOperation]) -> Vec<&ChangeOperation> {
    let mut ordered: Vec<&ChangeOperation> = operations.iter().collect();
    ordered.sort_by_key(|operation| {
        let directory = matches!(operation, ChangeOperation::CreateDirectory { .. });
        // Files and entries first, then directories; within each, the deepest path first.
        (
            u8::from(directory),
            std::cmp::Reverse(Path::new(operation.path()).components().count()),
        )
    });
    ordered
}

/// Creates a directory and makes the entry that names it durable.
fn create_directory_durably(path: &Path) -> Result<bool> {
    let mut created = false;
    for directory in missing_ancestors(path) {
        match std::fs::create_dir(&directory) {
            Ok(()) => created = true,
            // Something else made it between the look and the call. It is not this host's to
            // claim, and claiming it would let a later removal delete somebody else's directory.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(storage(error)),
        }
        // The parent's own entry for it, not the new directory's contents: what has to survive is
        // the name, because everything written inside it is reached through that name.
        if let Some(parent) = directory.parent() {
            sync_directory(parent)?;
        }
    }
    Ok(created)
}

/// Returns true when this file name is one a build of this host gives an installation record.
///
/// The name is `<agent>-<scope>.json`, or `<agent>-<scope>-<digest>.json` for a project. An
/// earlier build also gave a *user* record a digest, and those records still hold claims, so the
/// name it used is recognised here as well.
fn is_record_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".json") else {
        return false;
    };
    AgentTarget::ALL.iter().any(|agent| {
        stem.strip_prefix(agent.as_str())
            .and_then(|rest| rest.strip_prefix('-'))
            .is_some_and(|rest| {
                rest == "user"
                    || rest == "project"
                    || rest
                        .strip_prefix("project-")
                        .or_else(|| rest.strip_prefix("user-"))
                        .is_some_and(is_digest_name)
            })
    })
}

/// Returns true when this file name is the one an earlier build gave a user record.
fn is_legacy_user_record(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(".json"))
        .is_some_and(is_digest_name)
}

fn is_digest_name(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Refuses a change to an agent's installation on a platform this host cannot make one safely on.
///
/// Section 24 asks an effect to be durable before the record that accounts for it, and section 9
/// asks a dispatch marker to survive the crash it exists for. Both rest on making a directory's own
/// entries durable, which this host cannot do on Windows (see [`sync_directory`]). Rather than make
/// a change it cannot account for after a crash, it makes none: `kr skill status` still reports
/// what is there, and the agent's own command adds the server until the Windows qualification
/// supplies a durable barrier.
fn supported_platform() -> Result<()> {
    // A compile-time value rather than a conditional body, so both answers are checked on every
    // platform this crate builds for.
    if cfg!(windows) {
        return Err(ControllerError::PermissionDenied {
            detail: format!(
                "this host cannot yet install or remove {SKILL_NAME} on Windows, because it has no \
                 way to make the directory entries behind an installation durable; add the server \
                 with the agent's own command instead"
            ),
        });
    }
    Ok(())
}

/// Refuses to replace a document whose protection this host cannot carry across.
///
/// A replacement by rename gives the new file its own access control. The mode bits are carried
/// across; an access-control list is not, and reapplying one needs the platform's own calls. An
/// agent's configuration can hold a credential, and somebody who restricted it beyond the mode bits
/// meant it, so a document carrying one is refused before anything is written rather than quietly
/// weakened.
fn guard_access_controls(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if extended_access_controls(path)? {
        return Err(ControllerError::PermissionDenied {
            detail: format!(
                "{} is protected by an access-control list, and changing it here would not carry \
                 that across; add or remove the server with the agent's own command instead",
                display(path)
            ),
        });
    }
    // Changing it means writing a new file beside it and renaming that over it. A directory that
    // grants access to whatever is created in it would give that grant to the replacement, and the
    // document being replaced does not have it. The write itself checks the copy it made; this
    // check is here so the refusal comes before anything is installed rather than half way through.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if inheritable_access_controls(parent)? {
        return Err(ControllerError::PermissionDenied {
            detail: format!(
                "{} grants access to the files created in it, which {} does not have, and changing \
                 that document here would replace it with one that does; add or remove the server \
                 with the agent's own command instead",
                display(parent),
                display(path)
            ),
        });
    }
    Ok(())
}

/// Returns true when the file carries access controls its mode bits do not describe.
///
/// # Errors
///
/// Returns [`ControllerError::Storage`] when the file's access controls cannot be read, because a
/// protection this host cannot read is one it cannot promise to keep.
#[cfg(target_os = "macos")]
fn extended_access_controls(path: &Path) -> Result<bool> {
    // A file with no list of its own has an empty one here: this platform keeps no mode bits in it,
    // so anything in it is an extra grant or an extra restriction somebody added.
    exacl::getfacl(path, None)
        .map(|entries| !entries.is_empty())
        .map_err(storage)
}

#[cfg(target_os = "linux")]
fn extended_access_controls(path: &Path) -> Result<bool> {
    // This platform keeps a POSIX access-control list in one extended attribute, and a file without
    // that attribute is described by its mode bits alone.
    let mut probe = [0_u8; 1];
    interpret_probe(rustix::fs::getxattr(
        path,
        "system.posix_acl_access",
        &mut probe[..],
    ))
}

/// Turns the answer to an access-control probe into what it says about the file.
#[cfg(target_os = "linux")]
fn interpret_probe(answer: std::result::Result<usize, rustix::io::Errno>) -> Result<bool> {
    match answer {
        // There is a list. One byte of it is as much as this needs to know, so a list longer than
        // the byte offered for it answers the question as well as a shorter one would.
        Ok(_) | Err(rustix::io::Errno::RANGE) => Ok(true),
        Err(rustix::io::Errno::NODATA) => Ok(false),
        // Anything else is a failure to look, including a filesystem that does not answer this
        // question: a refusal to answer is not an answer of "none". An NFSv4 share keeps its list
        // somewhere else entirely and refuses this one, and a file protected there must not be
        // replaced on the strength of a probe that never saw its protection.
        Err(error) => Err(storage(std::io::Error::from(error))),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn extended_access_controls(path: &Path) -> Result<bool> {
    // Nothing here can read this platform's access controls, so nothing here can promise to keep
    // them. An existing document is refused rather than replaced.
    let _ = path;
    Ok(true)
}

/// Returns true when files created in this directory are given access controls by it.
///
/// # Errors
///
/// Returns [`ControllerError::Storage`] when the directory's access controls cannot be read.
#[cfg(target_os = "macos")]
fn inheritable_access_controls(directory: &Path) -> Result<bool> {
    exacl::getfacl(directory, None)
        .map(|entries| {
            entries
                .iter()
                .any(|entry| entry.flags.contains(exacl::Flag::FILE_INHERIT))
        })
        .map_err(storage)
}

#[cfg(target_os = "linux")]
fn inheritable_access_controls(directory: &Path) -> Result<bool> {
    // What a directory gives the files made in it is its default list, in an attribute of its own.
    let mut probe = [0_u8; 1];
    interpret_probe(rustix::fs::getxattr(
        directory,
        "system.posix_acl_default",
        &mut probe[..],
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn inheritable_access_controls(directory: &Path) -> Result<bool> {
    let _ = directory;
    Ok(true)
}

/// Makes a directory's own entries durable.
///
/// A rename or an unlink is not on disk until the directory holding it is. On Unix that is an
/// `fsync` of the directory itself; Windows offers no equivalent for a directory handle, and a
/// record written there is durable only as far as the platform's own ordering makes it.
fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let directory = std::fs::File::open(path).map_err(storage)?;
        directory.sync_all().map_err(storage)?;
    }
    // Windows has no equivalent this crate can reach: flushing a handle's buffers there needs
    // write access, and a directory handle cannot be opened for writing. An installation on
    // Windows is therefore as durable as the platform's own ordering makes it, which is a gap the
    // Windows qualification has to close rather than one this code can paper over. It is named
    // here and in the contact documentation instead of being claimed as durability it does not
    // have.
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Returns true when two operations are about the same thing.
fn same_target(left: &ChangeOperation, right: &ChangeOperation) -> bool {
    match (left, right) {
        (
            ChangeOperation::AddConfigurationEntry {
                path: left_path,
                entry: left_entry,
                ..
            },
            ChangeOperation::AddConfigurationEntry {
                path: right_path,
                entry: right_entry,
                ..
            },
        ) => left_path == right_path && left_entry == right_entry,
        (left, right) => {
            std::mem::discriminant(left) == std::mem::discriminant(right)
                && left.path() == right.path()
        }
    }
}

/// Adds an operation to a list, replacing any earlier one about the same thing.
fn merge(operations: &mut Vec<ChangeOperation>, operation: ChangeOperation) {
    if let Some(existing) = operations
        .iter_mut()
        .find(|existing| same_target(existing, &operation))
    {
        *existing = operation;
        return;
    }
    operations.push(operation);
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
/// Each spelling belongs to that agent's own configuration document. A document more than one
/// agent reads carries none of them: the three agents that share a project's `.mcp.json` do not
/// share a spelling, and the entry written for one of them is the entry the others read. Where no
/// deadline can be declared, the helper bounds its own default instead.
///
/// OpenCode is deliberately absent. What its configuration exposes is broader than one server, and
/// a setting that changes how every server behaves is not this installation's to write.
fn deadline_field(agent: AgentTarget) -> Option<(&'static str, Value)> {
    match agent {
        AgentTarget::Codex => Some(("tool_timeout_sec", json!(QUALIFIED_DEADLINE_SECONDS))),
        AgentTarget::KimiCodeCli => {
            Some(("toolTimeoutMs", json!(QUALIFIED_DEADLINE_SECONDS * 1_000)))
        }
        AgentTarget::ClaudeCode | AgentTarget::QoderCli | AgentTarget::GeminiCli => {
            Some(("timeout", json!(QUALIFIED_DEADLINE_SECONDS * 1_000)))
        }
        AgentTarget::Opencode => None,
    }
}

/// The deadline this installation can promise the tool server, in milliseconds.
///
/// It is the declared deadline where the agent takes one. An agent that takes none gets nothing
/// here either, and the server bounds its own waits conservatively instead of against a number
/// nobody agreed to.
fn deadline_milliseconds(agent: AgentTarget) -> Option<i64> {
    deadline_field(agent).map(|_| QUALIFIED_DEADLINE_SECONDS * 1_000)
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
    use std::io::Write as _;

    let parent = path.parent().unwrap_or(Path::new("."));
    // A distinct name per write. A fixed one is a collision between two callers writing the same
    // file, and each would see the other's half-written bytes.
    let temporary = parent.join(format!(
        ".{}.{}.kalareach",
        file_name(path),
        hex(&kr_cbor::sha256(kr_ipc::new_uuid().as_bytes())[..6])
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        // The permissions are set before the content exists. Writing first and narrowing after
        // would leave a readable copy of a private document for as long as the write takes, and
        // for good after a crash.
        let mode = std::fs::metadata(path)
            .ok()
            .map_or(default_mode, |existing| {
                existing.permissions().mode() & 0o777
            });
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = default_mode;
    let mut file = options.open(&temporary).map_err(storage)?;
    // The copy that is about to take an existing file's place, before anything is written into it.
    // A directory can give what is created in it access its own files do not have, and the rename
    // below would hand that to the document being replaced.
    if path.exists() && extended_access_controls(&temporary)? {
        drop(file);
        let _ = std::fs::remove_file(&temporary);
        return Err(ControllerError::PermissionDenied {
            detail: format!(
                "a new file in {} is given an access-control list by the directory itself, so \
                 replacing {} here would change who can read it",
                display(parent),
                display(path)
            ),
        });
    }
    file.write_all(bytes).map_err(storage)?;
    // The bytes reach the disk before the rename that publishes them, and the directory entry
    // reaches it before this call returns, so a record written before an effect is on disk before
    // the effect begins.
    file.sync_all().map_err(storage)?;
    drop(file);
    std::fs::rename(&temporary, path).map_err(storage)?;
    // The rename is not on disk until the directory holding it is. A failure here is reported
    // rather than swallowed: a record that claims durability it does not have is worse than one
    // that says it could not be written.
    sync_directory(parent)
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
    use std::collections::BTreeMap;

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

    /// One record's manifest, as a record from any build serialises it.
    fn manifest_value() -> Value {
        serde_json::json!({
            "skill_version": SKILL_VERSION,
            "agent": "codex",
            "scope": "user",
            "root": "/somewhere",
            "entry_point": ["kr"],
            "operations": [{
                "operation": "add_configuration_entry",
                "path": "/somewhere/config.toml",
                "entry": "mcp_servers.kalareach",
                "digest": serde_json::to_value(digest_of(b"an entry")).expect("a digest"),
                "created_document": false,
            }],
        })
    }

    /// The digests the fixture records, and the digests the manifest carries.
    ///
    /// Both are checked against the files this binary carries. A skill package that changed
    /// without its manifest changing would install files whose hashes do not describe them, and a
    /// removal reads those hashes to decide what is safe to delete.
    /// KR-REQ-23.33: the change manifest names every file with the hash of what is installed.
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

    /// Every file under `root`, with the digest of its contents.
    fn files_under(root: &Path) -> BTreeMap<PathBuf, Digest256> {
        let mut found = BTreeMap::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            let Ok(entries) = std::fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries {
                let path = entry.expect("an entry").path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    let contents = std::fs::read(&path).expect("a readable file");
                    found.insert(path, digest_of(&contents));
                }
            }
        }
        found
    }

    /// KR-REQ-23.33: an installation writes exactly its manifest for the target agent. The change
    /// manifest it returns names the agent, scope, root and entry point it was asked for; every
    /// file it records exists with the recorded digest and replaced nothing, the packaged files are
    /// all of them, every directory it records exists, its configuration entry names the document
    /// it created and the digest of the whole entry written there, and the home tree holds nothing
    /// the manifest does not name.
    #[test]
    fn an_installation_writes_the_skill_and_registers_the_server() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::ClaudeCode, InstallScope::User);
        let result = installer.install(&params).expect("installs");
        assert!(!result.already_installed);
        assert!(result.unresolved.is_empty());

        let manifest = &result.manifest;
        assert_eq!(manifest.agent, AgentTarget::ClaudeCode);
        assert_eq!(manifest.scope, InstallScope::User);
        assert_eq!(manifest.skill_version, SKILL_VERSION);
        let skill_root = tree.home().join(".claude/skills/kalareach-contact");
        assert_eq!(Path::new(&manifest.root), skill_root);
        assert_eq!(
            manifest.entry_point,
            vec![
                "/opt/kalareach/kr".to_owned(),
                ENTRY_ARGS[0].to_owned(),
                ENTRY_ARGS[1].to_owned()
            ]
        );
        let mut recorded = BTreeMap::new();
        let mut entries = Vec::new();
        for operation in &manifest.operations {
            match operation {
                ChangeOperation::CreateDirectory { path } => {
                    assert!(Path::new(path).is_dir(), "{path} was created");
                }
                ChangeOperation::WriteFile {
                    path,
                    digest,
                    replaced_digest,
                } => {
                    assert!(!replaced_digest.is_present(), "{path} replaced nothing");
                    recorded.insert(PathBuf::from(path), *digest);
                }
                ChangeOperation::AddConfigurationEntry {
                    path,
                    entry,
                    digest,
                    created_document,
                } => {
                    entries.push((
                        PathBuf::from(path),
                        entry.clone(),
                        *digest,
                        *created_document,
                    ));
                }
            }
        }
        let packaged: BTreeMap<PathBuf, Digest256> = files()
            .iter()
            .map(|(name, contents)| (skill_root.join(name), digest_of(contents.as_bytes())))
            .collect();
        assert_eq!(
            recorded, packaged,
            "the manifest records every packaged file"
        );

        // The configuration entry: the document it names did not exist and was created, the entry
        // written is the whole server entry this host declares for the agent, and the digest the
        // manifest records is the digest of exactly that entry.
        let document = tree.home().join(".claude.json");
        let written: Value =
            serde_json::from_str(&std::fs::read_to_string(&document).expect("the document"))
                .expect("json");
        let server = &written["mcpServers"]["kalareach"];
        assert_eq!(
            *server,
            installer.entry_value(Format::JsonCommandArgs, Some(AgentTarget::ClaudeCode))
        );
        assert_eq!(server["args"], json!(ENTRY_ARGS));
        assert_eq!(
            entries,
            vec![(
                document,
                "mcpServers.kalareach".to_owned(),
                digest_of(server.to_string().as_bytes()),
                true
            )]
        );
        let mut written = files_under(&tree.home());
        written
            .remove(&tree.home().join(".claude.json"))
            .expect("the configuration document");
        assert_eq!(
            written, recorded,
            "the home tree holds exactly the files the manifest names, with their digests"
        );
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

    /// KR-REQ-23.33: status reports the installation against its exact manifest.
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

    /// KR-REQ-23.33: a removal undoes exactly its own recorded changes.
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
                .any(|note| note.contains("still use it")),
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
    fn repairing_a_deleted_file_keeps_the_entry_this_host_already_claimed() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::ClaudeCode, InstallScope::User);
        installer.install(&params).expect("installs");
        std::fs::remove_file(
            tree.home()
                .join(".claude/skills/kalareach-contact/TOOLS.md"),
        )
        .expect("removes one file");
        // The entry is still this host's, so the repair replaces the file rather than refusing to
        // touch a server it would otherwise no longer recognise as its own.
        let repaired = installer.install(&params).expect("repairs");
        assert!(!repaired.already_installed);
        assert!(
            tree.home()
                .join(".claude/skills/kalareach-contact/TOOLS.md")
                .is_file()
        );
        assert!(installer.status(&params).expect("reads").drift.is_empty());
    }

    #[test]
    fn an_installation_that_did_not_finish_is_not_reported_as_installed() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::ClaudeCode, InstallScope::User);
        installer.install(&params).expect("installs");
        // What a crash between the plan and the last effect leaves behind.
        let path = installer.record_path(&params);
        let text = std::fs::read_to_string(&path).expect("the record");
        std::fs::write(&path, text.replace("\"installed\"", "\"installing\"")).expect("writes");

        let status = installer.status(&params).expect("reads");
        assert!(!status.installed);
        assert!(
            status
                .drift
                .iter()
                .any(|note| note.contains("did not finish"))
        );
        // And a second installation finishes the work rather than reporting it done.
        let again = installer.install(&params).expect("installs");
        assert!(!again.already_installed);
        assert!(installer.status(&params).expect("reads").installed);
    }

    #[test]
    fn a_change_that_may_not_have_happened_is_reported_and_left_alone() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::ClaudeCode, InstallScope::User);
        installer.install(&params).expect("installs");

        // What a crash between the note and the effect leaves: a record that says a file may or
        // may not have been written. Nothing knows whether this host wrote it, so nothing removes
        // it, and both surfaces say so.
        let path = installer.record_path(&params);
        let mut record =
            read_record(&std::fs::read_to_string(&path).expect("the record")).expect("reads");
        let interrupted = tree.home().join("somebody-elses-file.md");
        std::fs::write(&interrupted, "not this host's").expect("writes");
        record.state = InstallationRecord::INSTALLING.to_owned();
        record.pending = vec![ChangeOperation::WriteFile {
            path: display(&interrupted),
            digest: digest_of(b"not this host's"),
            replaced_digest: Nullable::null(),
        }];
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&record).expect("encodes"),
        )
        .expect("writes");

        let status = installer.status(&params).expect("reads");
        assert!(!status.installed);
        assert!(
            status
                .drift
                .iter()
                .any(|note| note.contains("may or may not have been written")),
            "{:?}",
            status.drift
        );
        let removed = installer.remove(&params).expect("removes");
        assert!(interrupted.is_file(), "it is left alone");
        assert!(
            removed
                .retained
                .iter()
                .any(|note| note.contains("may or may not have been written")),
            "{:?}",
            removed.retained
        );
    }

    #[test]
    fn a_file_left_in_flight_is_repaired_rather_than_refused() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::ClaudeCode, InstallScope::User);
        installer.install(&params).expect("installs");

        // What a crash between writing a skill file and recording it leaves: the file is on disk
        // holding what the note says, and the record does not claim it yet.
        let path = installer.record_path(&params);
        let mut record =
            read_record(&std::fs::read_to_string(&path).expect("the record")).expect("reads");
        let in_flight = record
            .manifest
            .operations
            .iter()
            .position(|operation| matches!(operation, ChangeOperation::WriteFile { .. }))
            .expect("a file was written");
        let operation = record.manifest.operations.remove(in_flight);
        let file = PathBuf::from(operation.path().to_owned());
        record.pending = vec![operation];
        record.state = InstallationRecord::INSTALLING.to_owned();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&record).expect("encodes"),
        )
        .expect("writes");

        installer.install(&params).expect("repairs");

        let repaired = installer
            .recorded(&params)
            .expect("reads")
            .expect("a record");
        assert!(repaired.is_complete(), "the repair finishes it");
        assert!(repaired.pending.is_empty(), "nothing is left uncertain");
        assert!(
            installer.status(&params).expect("reads").installed,
            "and it reads as installed"
        );

        // The same file holding somebody else's content is a different matter.
        std::fs::write(&file, "mine, actually").expect("writes");
        let refused = installer.install(&params).expect_err("refuses");
        assert!(
            matches!(refused, ControllerError::PermissionDenied { .. }),
            "{refused:?}"
        );
    }

    #[test]
    fn an_interrupted_configuration_entry_is_finished_by_installing_again() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::Codex, InstallScope::User);
        installer.install(&params).expect("installs");

        // What a crash between writing the entry and recording it leaves: the entry is in the
        // document, and the record only says it may be.
        let path = installer.record_path(&params);
        let mut record =
            read_record(&std::fs::read_to_string(&path).expect("the record")).expect("reads");
        let written = record
            .manifest
            .operations
            .iter()
            .position(|operation| {
                matches!(operation, ChangeOperation::AddConfigurationEntry { .. })
            })
            .expect("an entry was written");
        record.pending = vec![record.manifest.operations.remove(written)];
        record.state = InstallationRecord::INSTALLING.to_owned();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&record).expect("encodes"),
        )
        .expect("writes");

        let repaired = installer.install(&params).expect("repairs");

        assert!(repaired.unresolved.is_empty(), "{:?}", repaired.unresolved);
        let recorded = installer
            .recorded(&params)
            .expect("reads")
            .expect("a record");
        assert!(recorded.is_complete());
        assert!(recorded.pending.is_empty());
        assert!(
            recorded
                .manifest
                .operations
                .iter()
                .any(|operation| matches!(
                    operation,
                    ChangeOperation::AddConfigurationEntry { .. }
                )),
            "the entry is owned again"
        );
    }

    #[test]
    fn an_interrupted_entry_is_adopted_before_it_is_replaced() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::Codex, InstallScope::User);
        installer.install(&params).expect("installs");

        // Interrupted after the entry was written and before it was recorded.
        let path = installer.record_path(&params);
        let mut record =
            read_record(&std::fs::read_to_string(&path).expect("the record")).expect("reads");
        let written = record
            .manifest
            .operations
            .iter()
            .position(|operation| {
                matches!(operation, ChangeOperation::AddConfigurationEntry { .. })
            })
            .expect("an entry was written");
        record.pending = vec![record.manifest.operations.remove(written)];
        record.state = InstallationRecord::INSTALLING.to_owned();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&record).expect("encodes"),
        )
        .expect("writes");

        // The repair wants a different entry, because this host now reaches the tools by another
        // path. The note about the old one is the only evidence that the old one is this host's.
        let moved = Installer::new(
            tree.home(),
            installer.records.clone(),
            "/opt/elsewhere/kr".to_owned(),
        );
        let repaired = moved.install(&params).expect("repairs");

        assert!(repaired.unresolved.is_empty(), "{:?}", repaired.unresolved);
        let recorded = moved.recorded(&params).expect("reads").expect("a record");
        assert!(recorded.is_complete());
        assert!(recorded.pending.is_empty());
        assert_eq!(
            recorded.manifest.entry_point,
            vec![
                "/opt/elsewhere/kr".to_owned(),
                "agent-tools".to_owned(),
                "--stdio".to_owned()
            ],
            "and the entry it owns is the new one"
        );
        // Which it can undo, because it owns it.
        let removed = moved.remove(&params).expect("removes");
        assert!(
            removed.removed.iter().any(|operation| matches!(
                operation,
                ChangeOperation::AddConfigurationEntry { .. }
            )),
            "{:?}",
            removed.removed
        );
    }

    #[test]
    fn a_result_an_earlier_build_retained_is_still_readable() {
        let tree = Tree::create();
        let installer = tree.installer();
        let actor = kr_protocol::ids::ActorId::new("local:501").expect("a principal");
        let action =
            kr_protocol::ids::ActionId::new(kr_protocol::scalars::Uuid::from_bytes([9; 16]));
        let digest = digest_of(b"the payload");
        // The shape that build recorded: an installation result with no account of what it could
        // not resolve, because it had no such account to give.
        let manifest = ChangeManifest {
            skill_version: SKILL_VERSION.to_owned(),
            agent: params(AgentTarget::Codex, InstallScope::User).agent,
            scope: InstallScope::User,
            root: "/somewhere".to_owned(),
            entry_point: vec!["kr".to_owned()],
            operations: Vec::new(),
        };
        let stored = kr_cbor::CanonicalValue::Map(
            kr_cbor::CanonicalMap::from_entries([
                (
                    "manifest".to_owned(),
                    kr_cbor::to_canonical_value(&manifest).expect("encodes"),
                ),
                (
                    "already_installed".to_owned(),
                    kr_cbor::CanonicalValue::Bool(true),
                ),
            ])
            .expect("a map"),
        );
        installer
            .write_action(
                &actor,
                action,
                &ActionRecord {
                    digest: hex(digest.as_bytes()),
                    state: "applied".to_owned(),
                    result: Some(hex(&kr_cbor::encode(&stored))),
                },
            )
            .expect("writes the action record");

        let answer = installer
            .retained(&actor, action, &digest)
            .expect("reads")
            .expect("an answer");

        let result: AgentToolsInstallResult = answer.to_typed().expect("this build can read it");
        assert!(result.already_installed);
        assert!(result.unresolved.is_empty());
    }

    /// A directory that hands out access is not a place to replace a file.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_document_in_a_directory_that_grants_access_is_not_replaced() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::Codex, InstallScope::User);
        installer.install(&params).expect("installs");
        let document = tree.home().join(".codex/config.toml");
        // The document itself carries nothing; its directory gives what is made in it a grant the
        // document does not have.
        exacl::setfacl(
            &[document.parent().expect("a directory")],
            &[exacl::AclEntry::allow_group(
                "everyone",
                exacl::Perm::READ,
                Some(exacl::Flag::FILE_INHERIT),
            )],
            None,
        )
        .expect("grants access through the directory");

        let refused = installer
            .install(&params)
            .expect_err("refuses to replace it");
        assert!(
            matches!(refused, ControllerError::PermissionDenied { ref detail }
                if detail.contains("grants access to the files created in it")),
            "{refused:?}"
        );

        // And the write itself refuses, wherever it is reached from.
        let refused = write_atomically(&document, b"anything", PRIVATE).expect_err("refuses");
        assert!(
            matches!(refused, ControllerError::PermissionDenied { ref detail }
                if detail.contains("given an access-control list by the directory")),
            "{refused:?}"
        );
    }

    /// The Linux probe's answers, including the one that is not an answer.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_probe_that_cannot_answer_is_not_read_as_no_list() {
        assert!(interpret_probe(Ok(1)).expect("a list"));
        assert!(interpret_probe(Err(rustix::io::Errno::RANGE)).expect("a longer list"));
        assert!(!interpret_probe(Err(rustix::io::Errno::NODATA)).expect("no list"));
        // An NFSv4 share keeps its list somewhere this probe cannot see and refuses the question.
        // A refusal to answer is not an answer of "none".
        assert!(interpret_probe(Err(rustix::io::Errno::NOTSUP)).is_err());
    }

    #[test]
    fn an_unaccounted_change_keeps_an_installation_open() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::ClaudeCode, InstallScope::User);
        installer.install(&params).expect("installs");

        // A note about something this installation no longer touches. Nothing this run does can
        // resolve it, and nothing may claim it.
        let path = installer.record_path(&params);
        let mut record =
            read_record(&std::fs::read_to_string(&path).expect("the record")).expect("reads");
        let stranded = tree.home().join("something-else.md");
        std::fs::write(&stranded, "who wrote this?").expect("writes");
        record.pending = vec![ChangeOperation::WriteFile {
            path: display(&stranded),
            digest: digest_of(b"who wrote this?"),
            replaced_digest: Nullable::null(),
        }];
        record.state = InstallationRecord::INSTALLING.to_owned();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&record).expect("encodes"),
        )
        .expect("writes");

        let installed = installer.install(&params).expect("installs what it can");

        assert_eq!(installed.unresolved.len(), 1, "{:?}", installed.unresolved);
        assert!(installed.unresolved[0].contains("by hand"));
        let status = installer.status(&params).expect("reads");
        assert!(!status.installed, "it is not finished");
        assert!(
            status
                .drift
                .iter()
                .any(|note| note.contains("may or may not have been written")),
            "{:?}",
            status.drift
        );
        assert!(stranded.is_file(), "and it is left alone");
    }

    #[test]
    fn a_directory_an_earlier_attempt_was_unsure_of_does_not_hold_an_installation_open() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::ClaudeCode, InstallScope::User);
        installer.install(&params).expect("installs");

        let path = installer.record_path(&params);
        let mut record =
            read_record(&std::fs::read_to_string(&path).expect("the record")).expect("reads");
        // A directory that is there, which this host may or may not have made. Not claiming it and
        // forgetting the note come to the same thing: a removal leaves it either way.
        let directory = tree.home().join(".claude");
        record.pending = vec![ChangeOperation::CreateDirectory {
            path: display(&directory),
        }];
        record.state = InstallationRecord::INSTALLING.to_owned();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&record).expect("encodes"),
        )
        .expect("writes");

        let repaired = installer.install(&params).expect("repairs");

        assert!(repaired.unresolved.is_empty(), "{:?}", repaired.unresolved);
        let recorded = installer
            .recorded(&params)
            .expect("reads")
            .expect("a record");
        assert!(recorded.is_complete(), "it finished");
        assert!(recorded.pending.is_empty(), "and left nothing uncertain");
    }

    /// A document somebody restricted beyond its mode bits is not replaced.
    ///
    /// Only this platform can be tested here: it is the one whose access controls this build can
    /// read without the platform calls this crate does not make.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_configuration_protected_by_an_access_control_list_is_refused() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::Codex, InstallScope::User);
        installer.install(&params).expect("installs");
        let document = tree.home().join(".codex/config.toml");
        exacl::setfacl(
            &[&document],
            &[exacl::AclEntry::deny_group(
                "everyone",
                exacl::Perm::DELETE,
                None,
            )],
            None,
        )
        .expect("restricts the document");

        let refused = installer
            .install(&params)
            .expect_err("refuses to replace it");
        assert!(
            matches!(refused, ControllerError::PermissionDenied { ref detail }
                if detail.contains("access-control list")),
            "{refused:?}"
        );

        let refused = installer
            .remove(&params)
            .expect_err("refuses to rewrite it");
        assert!(
            matches!(refused, ControllerError::PermissionDenied { ref detail }
                if detail.contains("access-control list")),
            "{refused:?}"
        );
        assert!(
            tree.home()
                .join(".agents/skills/kalareach-contact/SKILL.md")
                .is_file(),
            "and nothing was taken before the refusal"
        );
    }

    #[test]
    fn a_predicted_record_from_an_earlier_build_becomes_uncertain_rather_than_owned() {
        // The shape that recorded what an installation *meant* to do. Those operations may or may
        // not have happened, so they become evidence of uncertainty instead of ownership.
        let text = serde_json::json!({
            "state": "installing",
            "manifest": manifest_value(),
        })
        .to_string();
        let record = read_record(&text).expect("reads the earlier shape");
        assert!(!record.is_complete());
        assert!(record.manifest.operations.is_empty(), "nothing is owned");
        assert_eq!(record.pending.len(), 1, "everything is uncertain");
    }

    #[test]
    fn a_user_record_an_earlier_build_named_after_a_project_is_still_found() {
        let tree = Tree::create();
        let installer = tree.installer();
        // An ordinary user request: no project directory, which is what the command line sends.
        let params = params(AgentTarget::Codex, InstallScope::User);
        installer.install(&params).expect("installs");
        let modern = installer.record_path(&params);
        // The name an earlier build gave it, after a project directory that request happened to
        // carry. Nothing in an ordinary request can work that name out again.
        let legacy =
            installer
                .records
                .join(format!("{}-user-{}.json", params.agent, hex(&[0xab, 0xcd])));
        std::fs::rename(&modern, &legacy).expect("wears the earlier name");

        let record = installer
            .recorded(&params)
            .expect("reads")
            .expect("a record");
        assert!(record.is_complete(), "the claim still counts");
        assert!(
            is_record_name(&legacy.file_name().expect("a name").to_string_lossy()),
            "and a shared document still sees it"
        );

        // A removal is a mutation, so it carries the record onto the name this build gives one.
        installer.remove(&params).expect("removes");
        assert!(!legacy.exists(), "the earlier name is gone");
        assert!(!modern.exists(), "and so is the record it became");
    }

    #[test]
    fn two_records_from_an_earlier_build_are_reported_rather_than_guessed_between() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::Codex, InstallScope::User);
        std::fs::create_dir_all(&installer.records).expect("a records directory");
        for hash in ["aa", "bb"] {
            std::fs::write(
                installer
                    .records
                    .join(format!("{}-user-{hash}.json", params.agent)),
                "{}",
            )
            .expect("writes");
        }

        let error = installer
            .recorded(&params)
            .expect_err("reports the ambiguity");

        assert!(
            matches!(error, ControllerError::InvalidArgument(ref detail) if detail.contains("move the others")),
            "{error:?}"
        );
    }

    #[test]
    fn a_record_from_a_newer_build_is_refused_rather_than_migrated() {
        let text = serde_json::json!({
            "version": 2,
            "state": "installed",
            "manifest": manifest_value(),
            "pending": [],
        })
        .to_string();

        let error = read_record(&text).expect_err("refuses");

        assert!(error.contains("version 2"), "{error}");
    }

    #[test]
    fn a_journal_from_an_earlier_build_keeps_what_it_confirmed() {
        // The shape before the version field: the same journal, without a version to name it.
        let text = serde_json::json!({
            "state": "installed",
            "manifest": manifest_value(),
            "pending": [],
        })
        .to_string();

        let record = read_record(&text).expect("reads the earlier journal");

        assert!(record.is_complete(), "it finished, and still says so");
        assert_eq!(
            record.manifest.operations.len(),
            1,
            "what it did is its own"
        );
        assert!(record.pending.is_empty());
    }

    #[test]
    fn a_directory_that_was_already_there_is_not_claimed() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::ClaudeCode, InstallScope::User);
        // Somebody else's directory, in the place this installation would have made one.
        let skills = tree.home().join(".claude/skills/kalareach-contact");
        std::fs::create_dir_all(&skills).expect("a directory");
        installer.install(&params).expect("installs");
        let recorded = installer
            .recorded(&params)
            .expect("reads")
            .expect("a record");
        assert!(
            !recorded
                .manifest
                .operations
                .iter()
                .any(|operation| matches!(operation, ChangeOperation::CreateDirectory { .. })),
            "no directory is claimed: {:?}",
            recorded.manifest.operations
        );
        installer.remove(&params).expect("removes");
        assert!(skills.is_dir(), "somebody else's directory is still there");
    }

    #[test]
    fn a_record_from_an_earlier_build_is_read_as_unfinished() {
        // The shape an earlier build of this host wrote: the manifest alone. It says what was
        // written and not whether the installation finished, so it is read as unfinished rather
        // than claimed as complete.
        let manifest = ChangeManifest {
            skill_version: SKILL_VERSION.to_owned(),
            agent: AgentTarget::Codex,
            scope: InstallScope::User,
            root: "/somewhere".to_owned(),
            entry_point: vec!["kr".to_owned()],
            operations: vec![ChangeOperation::CreateDirectory {
                path: "/somewhere".to_owned(),
            }],
        };
        let text = serde_json::to_string(&manifest).expect("encodes");
        let record = read_record(&text).expect("reads the earlier shape");
        assert!(!record.is_complete());
        assert_eq!(record.manifest.operations.len(), 1);
        assert!(record.pending.is_empty());
    }

    #[test]
    fn a_removal_takes_a_directory_after_what_is_inside_it() {
        // Record order is the order things were written, and a repair can append a directory after
        // the files inside it. Undoing in record order would leave the directory behind.
        let operations = vec![
            ChangeOperation::WriteFile {
                path: display(Path::new("/a/b/SKILL.md")),
                digest: digest_of(b""),
                replaced_digest: Nullable::null(),
            },
            ChangeOperation::CreateDirectory {
                path: display(Path::new("/a")),
            },
            ChangeOperation::CreateDirectory {
                path: display(Path::new("/a/b")),
            },
        ];
        let ordered: Vec<&str> = removal_order(&operations)
            .into_iter()
            .map(ChangeOperation::path)
            .collect();
        assert_eq!(ordered, vec!["/a/b/SKILL.md", "/a/b", "/a"]);
    }

    #[test]
    fn a_user_installation_is_recorded_under_its_own_name() {
        let tree = Tree::create();
        let installer = tree.installer();
        // A project directory on a user-scope request changes nothing about where the record goes,
        // so the record keeps a name the reader recognises.
        let named = AgentToolsParams {
            agent: AgentTarget::Codex,
            scope: InstallScope::User,
            project_dir: Nullable::some("/somewhere".to_owned()),
        };
        assert_eq!(
            installer.record_path(&named),
            installer.record_path(&params(AgentTarget::Codex, InstallScope::User))
        );
        assert!(is_record_name(
            &installer
                .record_path(&named)
                .file_name()
                .expect("a name")
                .to_string_lossy()
        ));
    }

    #[test]
    fn an_unreadable_installation_record_stops_a_shared_removal() {
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
        // Somebody's record is now unreadable. It still claims the shared entry, and a removal
        // that treated it as absent would take a server that installation is using.
        std::fs::write(
            installer.record_path(&with_project(AgentTarget::QoderCli)),
            "not a record",
        )
        .expect("writes");
        let error = installer
            .remove(&with_project(AgentTarget::ClaudeCode))
            .expect_err("refuses");
        assert_eq!(
            error.to_protocol_error().code,
            kr_protocol::error::ErrorCode::StorageUnavailable
        );
    }

    #[test]
    fn the_planned_entry_matches_the_entry_that_is_written() {
        // The plan is written before the entry exists, and a removal after an interrupted
        // installation compares that planned digest with what it finds. The two renderings have to
        // agree, for the JSON documents and for the TOML one.
        let tree = Tree::create();
        let installer = tree.installer();
        for agent in AgentTarget::ALL {
            let params = params(*agent, InstallScope::User);
            let layout = installer.layout(&params).expect("a layout");
            let Some(configuration) = layout.configuration.as_ref() else {
                continue;
            };
            let planned = installer.planned_entry_digest(configuration, *agent);
            installer.install(&params).expect("installs");
            let written = installer
                .entry_digest_under(&configuration.path, configuration.format.key())
                .expect("reads")
                .expect("the entry");
            assert_eq!(planned, written, "{agent}'s planned entry is what it wrote");
        }
    }

    /// KR-REQ-23.33: a project-scope change needs its project directory, and a refused one
    /// changes nothing: the home tree and the installation records are as they were.
    #[test]
    fn a_project_scope_installation_needs_the_project_directory() {
        let tree = Tree::create();
        tree.installer()
            .install(&params(AgentTarget::Codex, InstallScope::User))
            .expect("an earlier installation");
        let before = files_under(&tree.root);
        let error = tree
            .installer()
            .install(&params(AgentTarget::ClaudeCode, InstallScope::Project))
            .expect_err("refuses");
        assert_eq!(
            error.to_protocol_error().code,
            kr_protocol::error::ErrorCode::InvalidArgument
        );
        assert_eq!(files_under(&tree.root), before, "a refusal changes no file");
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
