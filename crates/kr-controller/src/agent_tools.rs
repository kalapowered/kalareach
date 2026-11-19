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
//! * **The agent's file keeps what is not this host's.** A TOML configuration is edited in place
//!   with a format-preserving editor, so ordering and comments survive. A JSON configuration is
//!   read with the place of every member, and the entry is spliced into it and out of it with every
//!   byte that was there kept ([`json`]). A JSON document that names a member twice in any object
//!   is refused before anything is written: which of the two a reader keeps is the reader's choice,
//!   and a rewrite would keep one of the person's settings and lose the other.
//!
//! The skill files are compiled into this binary, so an installation needs nothing else on disk
//! and the digests it records are build-time facts.

use std::path::{Path, PathBuf};

use kr_flush::NameKind;
use kr_protocol::scalars::{Digest256, Nullable};
use kr_protocol::skill::{
    AgentTarget, AgentToolsInstallResult, AgentToolsParams, AgentToolsRemoveResult,
    AgentToolsStatusResult, ChangeManifest, ChangeOperation, CompiledAgent, InstalledFile,
    SERVER_NAME, SKILL_NAME,
};
use serde_json::{Value, json};

use crate::catalogue::files::{
    PRIVATE, READABLE, create_directory_durably, create_private_directory_durably, digest_of,
    display, guard_access_controls, hex, home_directory, missing_ancestors, read_digest, storage,
    sync_directory, write_atomically,
};
use crate::catalogue::native_bridge::anchor;
use crate::catalogue::native_bridge::json;
pub(crate) mod declared;
use crate::error::{ControllerError, Result};
use crate::given::Recorded;

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

/// The refusal of a place inside a folder of this host's own.
const HOST_FOLDER: &str = "{place} is inside a folder this host keeps for its own files, so an installation does not \
     write there";

/// The refusal of a selected root that is not a folder where a write needs one.
const NOT_A_FOLDER_TO_WRITE: &str = "{path} is not a folder an installation can write into";

/// The refusal of a moved place. Its words are approved: the record, then where the place is now.
const MOVED_PLACE: &str = "the record of {word} at {scope} scope names {recorded place}, and {now} \
     {declared place}; run kr skill remove --agent {word} --scope {scope}, with --project-dir for a \
     project, and then install again";

/// Who says where the place is now, for a declared word and for a compiled one.
const NOW_DECLARED: &str = "the package now declares";
const NOW_COMPILED: &str = "this host now installs {word} at";

/// The refusal of an installation for a word that only a record of this host holds.
const ONLY_BY_RECORD: &str = "no package this host admits declares {word} now, so this host cannot \
     install it at {scope} scope; it can only remove what its own record of {word} names";

/// The refusal of a document that another word names in another format.
const DOCUMENT_FORMATS: &str = "{document} is named by {word} and by {other} at {scope} scope in \
     different formats, so this host will not install {word}";

/// The refusal of a document that the two words that name it do not both declare shared.
const DOCUMENT_NOT_SHARED: &str = "{document} is named by {word} and by {other} at {scope} scope, \
     and they do not both declare it shared, so this host will not install {word}";

/// The refusal of an entry that another record of this host claims with other contents.
const CLAIMED_DIFFERENTLY: &str = "{path} already holds a server named kalareach, written with \
     other contents by another installation this host made; remove that installation before \
     installing this one";

/// What a person does where this host will not rewrite an agent's configuration document.
const CONFIGURATION_BY_HAND: &str = "add or remove the server with the agent's own command instead";

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
    /// The deadline member this installation writes into the entry and the environment value that
    /// goes with it, where the agent takes one. A shared document carries none.
    deadline: Option<Deadline>,
}

/// The deadline an installation promises the tool server: the member of the entry that holds it,
/// and the number written there.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Deadline {
    /// The member of the entry.
    field: String,
    /// What the member holds, in the unit the agent reads it in.
    value: i64,
}

impl Deadline {
    /// The number the server is told through [`DEADLINE_VARIABLE`], in milliseconds. It is the same
    /// ceiling whatever unit the agent reads its own member in.
    const ENVIRONMENT_MILLISECONDS: i64 = QUALIFIED_DEADLINE_SECONDS * 1_000;
}

/// A claim a record of this host makes on a configuration entry.
struct Claim {
    /// The file of the record that makes it.
    record: PathBuf,
    /// The digest of the entry the record says it wrote.
    digest: Digest256,
    /// True when the record is for a word a package declares.
    declared: bool,
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

/// How an installation reaches the places a layout names.
///
/// The six compiled words go by path, as they always did. A word a package declares is reached
/// from one handle on the selected root, one component at a time and never through a link, so a
/// place that was swapped for a link after the check is refused rather than followed. A path
/// outside the selected root is refused by the walk.
#[derive(Clone, Debug)]
enum Fs {
    /// By path.
    Paths,
    /// From one handle on the selected root.
    Walk(std::sync::Arc<anchor::Anchor>),
    /// The selected root was not there when the request began: everything below it is absent, and
    /// nothing is written. No path is followed from here.
    Absent(PathBuf),
}

impl Fs {
    fn read_digest(&self, path: &Path) -> Result<Option<Digest256>> {
        match self {
            Self::Paths => read_digest(path),
            Self::Walk(walk) => walk.digest(path),
            Self::Absent(_) => Ok(None),
        }
    }

    fn read_text(&self, path: &Path) -> Result<Option<String>> {
        match self {
            Self::Paths => read_to_string(path),
            Self::Walk(walk) => walk.read_text(path),
            Self::Absent(_) => Ok(None),
        }
    }

    /// Writes `bytes` to the file at `path`. `replaces` is the digest of the file the caller
    /// checked there, or `None` where it found nothing; a declared word's walk replaces nothing
    /// else.
    fn write(
        &self,
        path: &Path,
        bytes: &[u8],
        default_mode: u32,
        replaces: Option<Digest256>,
    ) -> Result<()> {
        match self {
            Self::Paths => write_atomically(path, bytes, default_mode),
            Self::Walk(walk) => walk.write(path, bytes, default_mode, replaces),
            Self::Absent(root) => Err(no_folder_to_write(root)),
        }
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        match self {
            Self::Paths => {
                std::fs::remove_file(path).map_err(storage)?;
                if let Some(parent) = path.parent() {
                    sync_directory(parent, NameKind::File)?;
                }
                Ok(())
            }
            Self::Walk(walk) => walk.remove_file(path),
            Self::Absent(_) => Ok(()),
        }
    }

    /// Removes the folder at `path` when it is empty; false for one that could not be removed.
    fn remove_directory(&self, path: &Path) -> Result<bool> {
        match self {
            Self::Paths => match std::fs::remove_dir(path) {
                Ok(()) => {
                    if let Some(parent) = path.parent() {
                        sync_directory(parent, NameKind::Directory)?;
                    }
                    Ok(true)
                }
                Err(_) => Ok(false),
            },
            Self::Walk(walk) => Ok(walk.remove_directory(path).is_ok()),
            Self::Absent(_) => Ok(false),
        }
    }

    fn is_directory(&self, path: &Path) -> Result<bool> {
        match self {
            Self::Paths => Ok(path.is_dir()),
            Self::Walk(walk) => walk.is_directory(path),
            Self::Absent(_) => Ok(false),
        }
    }

    fn exists(&self, path: &Path) -> Result<bool> {
        match self {
            Self::Paths => Ok(path.exists()),
            Self::Walk(walk) => walk.exists(path),
            Self::Absent(_) => Ok(false),
        }
    }

    fn missing_ancestors(&self, path: &Path) -> Result<Vec<PathBuf>> {
        match self {
            Self::Paths => Ok(missing_ancestors(path)),
            Self::Walk(walk) => walk.missing_folders(path),
            Self::Absent(root) => Err(no_folder_to_write(root)),
        }
    }

    /// Makes the folder at `path`; true when it was made, false when it was already there.
    fn make_directory(&self, path: &Path) -> Result<bool> {
        match self {
            Self::Paths => create_directory_durably(path),
            // True only where this call made the folder: one that another process made first is
            // not the host's to claim, or to remove.
            Self::Walk(walk) => walk.make_folders(path),
            Self::Absent(root) => Err(no_folder_to_write(root)),
        }
    }

    /// Makes the folder at `path` and the ones missing before it.
    fn make_folders(&self, path: &Path) -> Result<()> {
        match self {
            Self::Paths => std::fs::create_dir_all(path).map_err(storage),
            Self::Walk(walk) => walk.make_folders(path).map(|_| ()),
            Self::Absent(root) => Err(no_folder_to_write(root)),
        }
    }
}

/// The refusal of a write below a root that is not there.
fn no_folder_to_write(root: &Path) -> ControllerError {
    ControllerError::InvalidArgument(NOT_A_FOLDER_TO_WRITE.replace("{path}", &display(root)))
}

/// Installs, inspects and removes the contact skill for one agent.
#[derive(Clone, Debug)]
pub struct Installer {
    /// The operating-system user's home directory, which every user-scope layout hangs off.
    home: PathBuf,
    /// Where this host records what it installed.
    records: PathBuf,
    /// The folders this host keeps for its own files, which a declared place may not be inside.
    host_folders: Vec<PathBuf>,
    /// The command an agent runs to reach the tools.
    executable: String,
    /// The skill target the one admitted package that names the requested word declares, which the
    /// service resolved for this request; none for one of the six compiled words.
    declared: Option<kr_plugin_sdk::skill_target::SkillTarget>,
    /// The words an admitted package declares or a record of this host holds, for the sentence that
    /// lists what the host knows.
    known: Vec<String>,
    /// Every skill target an admitted package declares, which the declared word's document is
    /// compared with.
    admitted: Vec<kr_plugin_sdk::skill_target::SkillTarget>,
    /// How this installer reaches the places a layout names: by path, or from one handle.
    fs: Fs,
}

impl Installer {
    /// Builds an installer for this host.
    #[must_use]
    pub fn new(home: PathBuf, records: PathBuf, executable: String) -> Self {
        Self {
            host_folders: declared::default_host_folders(&home, &records),
            home,
            records,
            executable,
            declared: None,
            known: Vec::new(),
            admitted: Vec::new(),
            fs: Fs::Paths,
        }
    }

    /// Returns this installer refusing the places inside `folders` besides the four the host
    /// keeps by default: its state, runtime, store and configuration folders as the host resolved
    /// them for this process, wherever a variable put them.
    #[must_use]
    pub fn with_host_folders(mut self, folders: impl IntoIterator<Item = PathBuf>) -> Self {
        self.host_folders.extend(folders);
        self
    }

    /// Returns this installer holding the declaration the service resolved for a request, and the
    /// words the host knows besides the six.
    #[must_use]
    pub fn with_declaration(
        mut self,
        declared: Option<kr_plugin_sdk::skill_target::SkillTarget>,
        known: Vec<String>,
    ) -> Self {
        self.declared = declared;
        self.known = known;
        self
    }

    /// Returns this installer comparing a declared word's document with the documents of every
    /// skill target the admitted packages declare, and with the six compiled layouts.
    #[must_use]
    pub fn with_admitted(
        mut self,
        admitted: Vec<kr_plugin_sdk::skill_target::SkillTarget>,
    ) -> Self {
        self.admitted = admitted;
        self
    }

    /// The words of the records this host holds, which it can still remove whether or not a package
    /// declares them.
    #[must_use]
    pub fn recorded_words(&self) -> Vec<String> {
        let Ok(listing) = std::fs::read_dir(&self.records) else {
            return Vec::new();
        };
        let mut words: Vec<String> = listing
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| entry.file_name().to_str().and_then(record_word))
            .collect();
        words.sort();
        words.dedup();
        words
    }

    /// Whether this host holds a record for the request's word and scope.
    ///
    /// # Errors
    ///
    /// Returns the error of reading the record.
    pub fn holds_record(&self, params: &AgentToolsParams) -> Result<bool> {
        Ok(self.recorded(params)?.is_some())
    }

    /// Whether a record of this host decides a removal alone: one declared word's removal, which
    /// needs no package where a record names what to undo.
    ///
    /// # Errors
    ///
    /// Returns [`Declined::ByARecord`] when the record cannot be read, because a record this host
    /// cannot read says that a record exists.
    pub(crate) fn removal_by_record(
        &self,
        params: &AgentToolsParams,
    ) -> std::result::Result<bool, Declined> {
        if params.agent.compiled().is_some() {
            return Ok(false);
        }
        self.holds_record(params)
            .map_err(|error| Declined::ByARecord(Recorded::read(error)))
    }

    /// This installer with its places reached the way the request's word needs: by path for one of
    /// the six compiled words, and from one handle on the selected root for a declared one. A root
    /// that is not there is no handle for a read or a removal, which then find every place gone,
    /// and a refusal for a write; no path is followed from it.
    fn on_handle(&self, params: &AgentToolsParams, writing: bool) -> Result<Self> {
        use kr_protocol::skill::InstallScope;

        if params.agent.compiled().is_some() {
            return Ok(self.clone());
        }
        if let Some(refusal) = declared::platform_refusal(cfg!(windows)) {
            return Err(ControllerError::InvalidArgument(refusal.to_owned()));
        }
        let root = match params.scope {
            InstallScope::User => self.home.clone(),
            InstallScope::Project => params
                .project_dir
                .as_ref()
                .map(|directory| PathBuf::from(directory.as_str()))
                .ok_or_else(|| {
                    ControllerError::InvalidArgument(
                        "a project-scope installation needs the project directory".to_owned(),
                    )
                })?,
        };
        let mut walking = self.clone();
        walking.fs = match anchor::Anchor::open(&root)? {
            Some(anchor) => Fs::Walk(std::sync::Arc::new(anchor)),
            None if writing => return Err(no_folder_to_write(&root)),
            None => Fs::Absent(root),
        };
        Ok(walking)
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
        self.on_handle(params, true)?.install_on(params)
    }

    fn install_on(&self, params: &AgentToolsParams) -> Result<AgentToolsInstallResult> {
        let layout = self.layout(params)?;
        let checked = self.check_on(params)?;
        // A record an earlier build named differently is carried onto the name this one gives it,
        // here rather than in a read, so it happens once and under this mutation's own lock.
        self.migrate_records(params)?;
        let existing = self.recorded(params)?;
        self.moved_place(params, &layout, existing.as_ref())?;
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
                        agent: params.agent.clone(),
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
            version: record_version(&params.agent),
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
        for directory in self.fs.missing_ancestors(&root)? {
            let operation = ChangeOperation::CreateDirectory {
                path: display(&directory),
            };
            self.begin(params, &mut record, operation.clone())?;
            self.settle_directory(params, &mut record, &directory, operation)?;
        }
        // What each file was when it was checked is what it is replaced over: a file made at a
        // name after the check, while the folders were made, is not read as the file that stood
        // there, and is not overwritten.
        for ((name, contents), replaced) in files().into_iter().zip(checked) {
            let path = root.join(name);
            let operation = ChangeOperation::WriteFile {
                path: display(&path),
                digest: digest_of(contents.as_bytes()),
                replaced_digest: Nullable(replaced),
            };
            self.confirm_existing(params, &mut record, &operation)?;
            self.begin(params, &mut record, operation.clone())?;
            self.fs
                .write(&path, contents.as_bytes(), READABLE, replaced)?;
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
                for directory in self.fs.missing_ancestors(parent)? {
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
                digest: self.planned_entry_digest(configuration),
                // Whether this host created the document is a fact about the first installation
                // that wrote it, not about this one. A repair keeps what was recorded.
                created_document: self.created_document(&record, &configuration.path)
                    || !self.fs.exists(&configuration.path)?,
            };
            self.confirm_existing(params, &mut record, &planned)?;
            self.begin(params, &mut record, planned)?;
            let written = self.write_entry(configuration)?;
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
        if self.fs.make_directory(directory)? {
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
                self.fs.read_digest(Path::new(path))? == Some(*digest)
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
        record.manifest.operations.iter().any(|operation| {
            matches!(
                operation,
                ChangeOperation::AddConfigurationEntry {
                    path: recorded,
                    created_document: true,
                    ..
                } if names_path(recorded, path)
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
    fn planned_entry_digest(&self, configuration: &Configuration) -> Digest256 {
        if configuration.format == Format::CodexToml {
            let mut entry = toml_edit::Table::new();
            entry["command"] = toml_edit::value(self.executable.clone());
            let mut args = toml_edit::Array::new();
            for argument in ENTRY_ARGS {
                args.push(*argument);
            }
            entry["args"] = toml_edit::value(args);
            if let Some(deadline) = configuration.deadline.as_ref() {
                entry[deadline.field.as_str()] = toml_edit::value(deadline.value);
                let mut environment = toml_edit::InlineTable::new();
                environment.insert(
                    DEADLINE_VARIABLE,
                    Deadline::ENVIRONMENT_MILLISECONDS.to_string().into(),
                );
                entry["env"] = toml_edit::value(environment);
            }
            return digest_of(toml_edit::Item::Table(entry).to_string().trim().as_bytes());
        }
        digest_of(
            self.entry_value(configuration.format, configuration.deadline.as_ref())
                .to_string()
                .as_bytes(),
        )
    }

    /// Refuses an installation whose recorded place is not the place now: the skills folder, the
    /// document, the entry's key and, for a declared word, the entry it wrote. One rule for every
    /// word. A compiled word's entry follows this host's own executable, so its digest is not part
    /// of its place. The two places are compared by their exact components: a spelling that
    /// differs only in case is another place, because the record names the files it wrote under
    /// one spelling, and a repair under the other would write files no record names.
    fn moved_place(
        &self,
        params: &AgentToolsParams,
        layout: &Layout,
        recorded: Option<&InstallationRecord>,
    ) -> Result<()> {
        match recorded.and_then(|record| self.moved_text(params, layout, record)) {
            Some(refusal) => Err(ControllerError::InvalidArgument(refusal)),
            None => Ok(()),
        }
    }

    /// The sentence that says the record's place is not the place now, or none where it is.
    fn moved_text(
        &self,
        params: &AgentToolsParams,
        layout: &Layout,
        record: &InstallationRecord,
    ) -> Option<String> {
        let declared_word = params.agent.compiled().is_none();
        let declared_root = display(&layout.skills);
        let declared_document = layout.configuration.as_ref().map(|document| {
            (
                display(&document.path),
                format!("{}.{SERVER_NAME}", document.format.key()),
                self.planned_entry_digest(document),
            )
        });
        // The entry the record wrote, or noted that it was writing when the installation stopped:
        // the entry may be in the document, so it is where the record's place is.
        let recorded_document = record
            .manifest
            .operations
            .iter()
            .chain(record.pending.iter())
            .find_map(|operation| {
                if let ChangeOperation::AddConfigurationEntry {
                    path,
                    entry,
                    digest,
                    ..
                } = operation
                {
                    Some((path.clone(), entry.clone(), *digest))
                } else {
                    None
                }
            });
        // An installation that stopped before it planned its entry noted no entry, and never wrote
        // one: that is an installation to finish, not a package whose declaration moved. A record
        // of an installation that finished with no entry is a different thing, and a declaration
        // that now names one moved.
        let before_its_entry =
            !record.is_complete() && recorded_document.is_none() && declared_document.is_some();
        let same_document = match (&declared_document, &recorded_document) {
            (None, None) => true,
            (Some(_), None) => before_its_entry,
            (None, Some(_)) => false,
            (Some(now), Some(then)) => {
                Path::new(&now.0) == Path::new(&then.0)
                    && now.1 == then.1
                    && (!declared_word || now.2 == then.2)
            }
        };
        if same_document && Path::new(&declared_root) == Path::new(&record.manifest.root) {
            return None;
        }
        let place = |root: &str, document: Option<&(String, String, Digest256)>| match document {
            Some((path, entry, _)) => format!("{root} and {path}, entry {entry}"),
            None => root.to_owned(),
        };
        let recorded_place = place(&record.manifest.root, recorded_document.as_ref());
        let mut declared_place = place(&declared_root, declared_document.as_ref());
        // Where the two read the same, the entry itself is what changed.
        if declared_place == recorded_place {
            declared_place.push_str(", with an entry of other contents");
        }
        let now = if declared_word {
            NOW_DECLARED.to_owned()
        } else {
            NOW_COMPILED.replace("{word}", params.agent.as_str())
        };
        Some(
            MOVED_PLACE
                .replace("{now}", &now)
                .replace("{word}", params.agent.as_str())
                .replace("{scope}", &params.scope.to_string())
                .replace("{recorded place}", &recorded_place)
                .replace("{declared place}", &declared_place),
        )
    }

    /// Refuses the places a package declared that this host must not write: a place inside the
    /// host's own folders, and, from the handle, a link or a file at any component below the
    /// selected root and a folder where a file is to be written. Every place is checked before the
    /// first write.
    fn check_declared_places(&self, params: &AgentToolsParams, layout: &Layout) -> Result<()> {
        if params.agent.compiled().is_some() {
            return Ok(());
        }
        let documents: Vec<&Path> = layout
            .configuration
            .iter()
            .map(|document| document.path.as_path())
            .collect();
        let files: Vec<PathBuf> = files()
            .iter()
            .map(|(name, _)| layout.skills.join(name))
            .collect();
        // The folders as they are written and as the file system reaches them, and each place as it
        // is written and as the selected root's actual location reaches it: a root or a folder
        // that is a link into one of the host's folders is one of them.
        let folders: Vec<PathBuf> = self
            .host_folders
            .iter()
            .flat_map(|folder| [folder.clone(), declared::resolved(folder)])
            .collect();
        for place in std::iter::once(layout.skills.as_path())
            .chain(files.iter().map(PathBuf::as_path))
            .chain(documents.iter().copied())
        {
            let reached = match &self.fs {
                Fs::Walk(walk) => walk.reached_by(place),
                Fs::Paths | Fs::Absent(_) => None,
            };
            if declared::inside_host_folders(&folders, place)
                || reached
                    .as_deref()
                    .is_some_and(|reached| declared::inside_host_folders(&folders, reached))
            {
                return Err(ControllerError::PermissionDenied {
                    detail: HOST_FOLDER.replace("{place}", &display(place)),
                });
            }
        }
        let Fs::Walk(walk) = &self.fs else {
            return Ok(());
        };
        walk.missing_folders(&layout.skills)?;
        walk.refuse_links(&layout.skills, anchor::Expect::Folder)?;
        for place in files
            .iter()
            .map(PathBuf::as_path)
            .chain(documents.iter().copied())
        {
            walk.refuse_links(place, anchor::Expect::File)?;
        }
        if let Some(parent) = layout
            .configuration
            .as_ref()
            .and_then(|document| document.path.parent())
        {
            walk.missing_folders(parent)?;
        }
        Ok(())
    }

    /// Reports what is installed, and what no longer matches what was written.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read.
    pub fn status(&self, params: &AgentToolsParams) -> Result<AgentToolsStatusResult> {
        self.on_handle(params, false)?.status_on(params)
    }

    fn status_on(&self, params: &AgentToolsParams) -> Result<AgentToolsStatusResult> {
        let Some(record) = self.recorded(params)? else {
            let layout = self.layout(params)?;
            return Ok(AgentToolsStatusResult {
                agent: params.agent.clone(),
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
                    actual_digest: Nullable(self.fs.read_digest(Path::new(path))?),
                });
            }
        }
        let mut drift = self.drift(manifest)?;
        // Where the record is no longer where this host would install now, by the layout it has
        // for this word: the package's declaration where the service resolved one, and the
        // compiled layout otherwise.
        if let Ok(layout) = self.layout(params)
            && let Some(moved) = self.moved_text(params, &layout, &record)
        {
            drift.push(moved);
        }
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
            agent: params.agent.clone(),
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
        self.on_handle(params, false)?.remove_on(params)
    }

    fn remove_on(&self, params: &AgentToolsParams) -> Result<AgentToolsRemoveResult> {
        // The record is read, and read as valid, before anything is moved: a record this build
        // does not understand must not change its name on the way to being refused.
        let read = self.removable(params)?;
        self.migrate_records(params)?;
        let Some(record) = read else {
            return Ok(AgentToolsRemoveResult {
                agent: params.agent.clone(),
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
                    let present = self.fs.read_digest(Path::new(path))?;
                    match present {
                        None => retained.push(format!("{path} is already gone")),
                        // Somebody edited it after this host wrote it. That edit is theirs, and a
                        // removal that deleted it would be deleting their work.
                        Some(found) if found != *digest => {
                            retained.push(format!("{path} has changed since it was installed"));
                        }
                        Some(_) => {
                            self.fs.remove_file(Path::new(path))?;
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
                    match self.remove_entry(
                        Path::new(path),
                        entry_key(entry),
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
                    if self.fs.remove_directory(Path::new(path))? {
                        removed.push(operation.clone());
                    } else {
                        retained.push(format!("{path} is not empty"));
                    }
                }
            }
        }
        let record = self.record_path(params);
        if record.exists() {
            std::fs::remove_file(&record).map_err(storage)?;
            sync_directory(&self.records, NameKind::File)?;
        }
        Ok(AgentToolsRemoveResult {
            agent: params.agent.clone(),
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
                    match self.fs.read_digest(Path::new(path))? {
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
                } => match self.entry_digest_under(Path::new(path), entry_key(entry))? {
                    None => drift.push(format!("{entry} is missing from {path}")),
                    Some(found) if found != *digest => {
                        drift.push(format!("{entry} in {path} has changed"));
                    }
                    Some(_) => {}
                },
                ChangeOperation::CreateDirectory { path } => {
                    if !self.fs.is_directory(Path::new(path))? {
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
        let created_document = !self.fs.exists(&configuration.path)?;
        if let Some(parent) = configuration.path.parent()
            && !self.fs.exists(parent)?
        {
            self.fs.make_folders(parent)?;
        }
        // A shared document gets the same entry whichever agent's installation writes it, so it
        // holds no deadline: the configuration of one carries none.
        let deadline = configuration.deadline.as_ref();
        let digest = match configuration.format {
            Format::CodexToml => self.write_toml_entry(&configuration.path, deadline)?,
            format => self.write_json_entry(&configuration.path, format, deadline)?,
        };
        Ok(ChangeOperation::AddConfigurationEntry {
            path: display(&configuration.path),
            entry: format!("{}.{SERVER_NAME}", configuration.format.key()),
            digest,
            created_document,
        })
    }

    fn write_toml_entry(&self, path: &Path, deadline: Option<&Deadline>) -> Result<Digest256> {
        let read = self.fs.read_text(path)?;
        let replaces = text_digest(read.as_deref());
        let text = read.unwrap_or_default();
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
        if let Some(deadline) = deadline {
            entry[deadline.field.as_str()] = toml_edit::value(deadline.value);
            let mut environment = toml_edit::InlineTable::new();
            environment.insert(
                DEADLINE_VARIABLE,
                Deadline::ENVIRONMENT_MILLISECONDS.to_string().into(),
            );
            entry["env"] = toml_edit::value(environment);
        }
        table.insert(SERVER_NAME, toml_edit::Item::Table(entry));
        self.fs
            .write(path, document.to_string().as_bytes(), PRIVATE, replaces)?;
        self.entry_digest_under(path, Format::CodexToml.key())?
            .ok_or_else(|| {
                ControllerError::InvalidArgument(format!(
                    "{} did not keep the entry",
                    display(path)
                ))
            })
    }

    /// Adds the server entry to a JSON document, one member spliced in and every other byte kept,
    /// and returns its digest.
    ///
    /// An entry this host wrote that is already there is replaced in its place, and left alone
    /// when it already says what this installation would write.
    fn write_json_entry(
        &self,
        path: &Path,
        format: Format,
        deadline: Option<&Deadline>,
    ) -> Result<Digest256> {
        let key = format.key();
        let members = [key, SERVER_NAME];
        let value = self.entry_value(format, deadline);
        let entry = value.to_string();
        let read = read_exact(&self.fs, path)?;
        let replaces = read.as_ref().map(|(text, _)| digest_of(text.as_bytes()));
        let edited = match read {
            // A document this host creates holds the entry and the container on the way to it.
            None => {
                let text = serde_json::to_string_pretty(&json!({ key: { SERVER_NAME: value } }))
                    .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
                Some(format!("{text}\n"))
            }
            Some((text, document)) => {
                let present = document
                    .value_at(&text, &members)
                    .map_err(|_| not_servers(key, path))?;
                match present {
                    None => Some(
                        json::insert(&text, &members, &entry)
                            .map_err(|reason| not_exact(path, &reason))?
                            .text,
                    ),
                    Some(present) => {
                        self.guard_existing(path, format)?;
                        let unchanged = serde_json::from_str::<Value>(present)
                            .is_ok_and(|present| present == value);
                        (!unchanged)
                            .then(|| json::replace(&text, &members, &entry))
                            .transpose()
                            .map_err(|reason| not_exact(path, &reason))?
                    }
                }
            }
        };
        if let Some(edited) = edited {
            self.fs.write(path, edited.as_bytes(), PRIVATE, replaces)?;
        }
        self.entry_digest_under(path, key)?.ok_or_else(|| {
            ControllerError::InvalidArgument(format!("{} did not keep the entry", display(path)))
        })
    }

    /// Reads what a removal would work from, refusing everything it cannot do.
    fn removable(&self, params: &AgentToolsParams) -> Result<Option<InstallationRecord>> {
        // A removal of something never installed still has to know where it would have been, or it
        // is not the removal of anything in particular.
        let recorded = self.recorded(params)?;
        if recorded.is_none() {
            self.layout(params)?;
        }
        self.removable_from(recorded)
    }

    /// Refuses what a removal that works from `recorded` cannot do, and gives back what it would
    /// work from. Everything here reads, and the record is read before it, by the caller.
    fn removable_from(
        &self,
        recorded: Option<InstallationRecord>,
    ) -> Result<Option<InstallationRecord>> {
        let Some(record) = recorded else {
            return Ok(None);
        };
        // Every document this removal would rewrite. A removal that took the package and then
        // refused the document would leave the agent with an entry pointing at a skill that is no
        // longer there.
        for operation in &record.manifest.operations {
            if let ChangeOperation::AddConfigurationEntry { path, entry, .. } = operation {
                // Read as the removal will read it, so a document it could not edit, one that
                // names a member twice among them, is refused here rather than half way through.
                self.entry_digest_under(Path::new(path), entry_key(entry))?;
                guard_access_controls(Path::new(path), CONFIGURATION_BY_HAND)?;
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
        self.on_handle(params, false)?.check_on(params).map(|_| ())
    }

    fn check_on(&self, params: &AgentToolsParams) -> Result<Checked> {
        let layout = self.layout(params)?;
        let recorded = self.recorded(params)?;
        self.check_before_writing(params, &layout, recorded.as_ref())
    }

    /// What an installation that `recorded` describes would not do to the agent's tree, read
    /// from the tree. It answers with what each skill file was when it was read: the digest of a
    /// file this host owns, or `None` for a name that was free. The installation replaces only
    /// that.
    fn check_before_writing(
        &self,
        params: &AgentToolsParams,
        layout: &Layout,
        recorded: Option<&InstallationRecord>,
    ) -> Result<Checked> {
        self.check_declared_places(params, layout)?;
        self.document_disagrees(params, layout)?;
        let root = layout.skills.as_path();
        let mut checked: Checked = [None; FILE_COUNT];
        for ((name, _), state) in files().into_iter().zip(checked.iter_mut()) {
            let path = root.join(name);
            let Some(present) = self.fs.read_digest(&path)? else {
                continue;
            };
            // A file this host wrote, or one it was in the middle of writing when an installation
            // stopped, holding exactly the content that record names. The in-flight note counts
            // because the content is evidence for the note: this host was writing those bytes to
            // that path, so what is there is its own unfinished work, and refusing here would
            // leave an interrupted installation unrepairable. The content it names is not always
            // the content this build would write — an interrupted installation of an earlier
            // package version says so — and repairing then replaces this host's own file.
            // Anything else at that path is somebody's own file, and an installation does not
            // write over one.
            let ours = recorded.is_some_and(|record| {
                record
                    .manifest
                    .operations
                    .iter()
                    .chain(record.pending.iter())
                    .any(|operation| {
                        matches!(
                            operation,
                            ChangeOperation::WriteFile { path: recorded_path, digest, .. }
                                if names_path(recorded_path, &path) && *digest == present
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
            *state = Some(present);
        }
        if let Some(configuration) = layout.configuration.as_ref() {
            self.guard_existing(&configuration.path, configuration.format)?;
            self.refuse_other_claims(params, configuration)?;
            // The container the entry goes into, not only the entry. A document whose server
            // container is something other than a table is refused here rather than after the
            // skill files have been written.
            self.check_container(configuration)?;
            // The document's own protection, before anything is written. This host's own files
            // carry no such risk: they are its records and the package it wrote.
            guard_access_controls(&configuration.path, CONFIGURATION_BY_HAND)?;
        }
        Ok(checked)
    }

    /// Refuses a declared word's document where another admitted word or a compiled word names the
    /// same document at this scope, ASCII case ignored, and the two do not agree on it: they name
    /// different formats, or they do not both declare it shared. Two words that write one entry
    /// name into one document agree only when each writes the entry the same way, and a document
    /// that is not shared holds one word's entry. This reads declarations only, so it runs before
    /// the marker, and a word whose scope the other does not declare is not compared at that scope.
    fn document_disagrees(&self, params: &AgentToolsParams, layout: &Layout) -> Result<()> {
        let Some(mine) = layout
            .configuration
            .as_ref()
            .filter(|_| params.agent.compiled().is_none())
        else {
            return Ok(());
        };
        let compiled = CompiledAgent::ALL
            .iter()
            .filter_map(|agent| AgentTarget::parse(agent.as_str()).ok())
            .map(|word| (word, None));
        let admitted = self
            .admitted
            .iter()
            .filter(|target| target.word != params.agent.as_str())
            .filter_map(|target| {
                AgentTarget::parse(&target.word)
                    .ok()
                    .map(|word| (word, Some(target.clone())))
            });
        for (word, declaration) in compiled.chain(admitted) {
            let other = Self {
                declared: declaration,
                ..self.clone()
            };
            let theirs = AgentToolsParams {
                agent: word.clone(),
                scope: params.scope,
                project_dir: params.project_dir.clone(),
            };
            // A word that declares nothing at this scope names no document there.
            let Some(theirs) = other
                .layout(&theirs)
                .ok()
                .and_then(|layout| layout.configuration)
            else {
                continue;
            };
            if !same_place(&mine.path, &theirs.path) {
                continue;
            }
            let text = if mine.format != theirs.format {
                DOCUMENT_FORMATS
            } else if !(mine.shared && theirs.shared) {
                DOCUMENT_NOT_SHARED
            } else {
                continue;
            };
            return Err(ControllerError::PermissionDenied {
                detail: text
                    .replace("{document}", &display(&mine.path))
                    .replace("{word}", params.agent.as_str())
                    .replace("{other}", word.as_str())
                    .replace("{scope}", &params.scope.to_string()),
            });
        }
        Ok(())
    }

    /// Refuses to write an entry over one that another record of this host claims with other
    /// contents, where either installation is for a declared word: the other record would then
    /// describe an entry that is no longer in the document. Two packages cannot be made to agree
    /// on one document, so the host compares what each record claims.
    fn refuse_other_claims(
        &self,
        params: &AgentToolsParams,
        configuration: &Configuration,
    ) -> Result<()> {
        let planned = self.planned_entry_digest(configuration);
        let own = self.record_path(params);
        let claims = self.claims_on(&configuration.path, configuration.format.key(), Some(&own))?;
        if claims.iter().any(|claim| {
            claim.digest != planned && (claim.declared || params.agent.compiled().is_none())
        }) {
            return Err(ControllerError::PermissionDenied {
                detail: CLAIMED_DIFFERENTLY.replace("{path}", &display(&configuration.path)),
            });
        }
        Ok(())
    }

    /// Refuses a configuration document this installation could not finish writing.
    fn check_container(&self, configuration: &Configuration) -> Result<()> {
        let Some(text) = self.fs.read_text(&configuration.path)? else {
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
        let document = json::Document::read(&text).map_err(|reason| not_exact(path, &reason))?;
        document
            .value_at(&text, &[key, SERVER_NAME])
            .map_err(|_| not_servers(key, path))?;
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
        Ok(self
            .claims_on(path, key, except)?
            .into_iter()
            .filter(|claim| claim.digest == *digest)
            .map(|claim| claim.record)
            .collect())
    }

    /// Every claim another record of this host makes on the entry under `key` in the document at
    /// `path`, whatever digest it names, except the record at `except`.
    fn claims_on(&self, path: &Path, key: &str, except: Option<&Path>) -> Result<Vec<Claim>> {
        let entry_name = format!("{key}.{SERVER_NAME}");
        let listing = match std::fs::read_dir(&self.records) {
            Ok(listing) => listing,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(storage(error)),
        };
        let mut found: Vec<Claim> = Vec::new();
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
            for operation in record
                .manifest
                .operations
                .iter()
                .chain(record.pending.iter())
            {
                if let ChangeOperation::AddConfigurationEntry {
                    path: recorded_path,
                    entry: recorded_entry,
                    digest,
                    ..
                } = operation
                    && names_path(recorded_path, path)
                    && recorded_entry == &entry_name
                {
                    found.push(Claim {
                        record: entry.path(),
                        digest: *digest,
                        declared: record.manifest.agent.compiled().is_none(),
                    });
                }
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
        let Some(text) = self.fs.read_text(path)? else {
            return Ok(None);
        };
        // The format is the one the recorded key names, whatever the document's file name says: a
        // declared document may be called anything.
        if key == Format::CodexToml.key() {
            let document: toml_edit::DocumentMut = text.parse().map_err(|error| {
                ControllerError::InvalidArgument(format!("{}: {error}", display(path)))
            })?;
            let entry = document
                .get(key)
                .and_then(|servers| servers.as_table())
                .and_then(|servers| servers.get(SERVER_NAME));
            return Ok(entry.map(|entry| digest_of(entry.to_string().trim().as_bytes())));
        }
        let document = json::Document::read(&text).map_err(|reason| not_exact(path, &reason))?;
        // A container that is not an object holds no entry of this host's.
        let Ok(Some(entry)) = document.value_at(&text, &[key, SERVER_NAME]) else {
            return Ok(None);
        };
        let entry: Value = serde_json::from_str(entry).map_err(|error| {
            ControllerError::InvalidArgument(format!("{}: {error}", display(path)))
        })?;
        Ok(Some(digest_of(entry.to_string().as_bytes())))
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
        if key == Format::CodexToml.key() {
            let read = self.fs.read_text(path)?;
            let replaces = text_digest(read.as_deref());
            let text = read.unwrap_or_default();
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
            // file holds nothing of theirs. The JSON branch below can delete one because it reads
            // the document exactly and can see that it holds nothing at all.
            self.fs
                .write(path, document.to_string().as_bytes(), PRIVATE, replaces)?;
        } else {
            let read = self.fs.read_text(path)?;
            let replaces = text_digest(read.as_deref());
            let text = read.unwrap_or_default();
            // Only the entry the record names, the one member it spliced in. In a document this
            // host created, whose container it made too, the container goes with the entry when
            // nothing else is left in it; in anybody else's the container stays, as the TOML table
            // does. A document that holds both shapes keeps whichever this installation did not
            // write.
            let members = [key, SERVER_NAME];
            let made = if created_document {
                members.len() - 1
            } else {
                0
            };
            let edited =
                json::remove(&text, &members, made).map_err(|reason| not_exact(path, &reason))?;
            let empty = json::Document::read(&edited).is_ok_and(|document| document.is_empty());
            if created_document && empty {
                // This host created the document and nothing else was ever added to it.
                self.fs.remove_file(path)?;
                return Ok(Removal::Removed);
            }
            self.fs.write(path, edited.as_bytes(), PRIVATE, replaces)?;
        }
        Ok(Removal::Removed)
    }

    fn entry_value(&self, format: Format, deadline: Option<&Deadline>) -> Value {
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
                    && deadline.is_some()
                {
                    object.insert(
                        "env".to_owned(),
                        json!({ DEADLINE_VARIABLE: Deadline::ENVIRONMENT_MILLISECONDS.to_string() }),
                    );
                }
                // Section 11 shortens a long poll to the installed client's qualified tool
                // deadline. Where an agent lets a server declare that deadline, the installation
                // declares one long enough for the host's own ceiling, so a wait returns the
                // durable question rather than being cut off by a default the agent chose for
                // ordinary tools.
                if let Some(deadline) = deadline
                    && let Some(object) = entry.as_object_mut()
                {
                    object.insert(deadline.field.clone(), json!(deadline.value));
                }
                entry
            }
        }
    }

    /// The layout a package declares for `params.agent`, from the declaration the service resolved
    /// for this request.
    fn declared_layout(
        &self,
        params: &AgentToolsParams,
        project: &dyn Fn() -> Result<PathBuf>,
    ) -> Result<Layout> {
        use kr_plugin_sdk::skill_target::{DeadlineUnit, DocumentFormat};
        use kr_protocol::skill::InstallScope;
        let Some(target) = self
            .declared
            .as_ref()
            .filter(|target| target.word == params.agent.as_str())
        else {
            // A word that only a record holds is known, and no package serves it now.
            if self.known.iter().any(|word| word == params.agent.as_str()) {
                return Err(ControllerError::InvalidArgument(
                    ONLY_BY_RECORD
                        .replace("{word}", params.agent.as_str())
                        .replace("{scope}", &params.scope.to_string()),
                ));
            }
            return Err(ControllerError::InvalidArgument(format!(
                "{} is not an agent this host knows; it knows {}",
                params.agent,
                known_words(&self.known)
            )));
        };
        let (root, location) = match params.scope {
            InstallScope::User => (self.home.clone(), target.user.as_ref()),
            InstallScope::Project => (project()?, target.project.as_ref()),
        };
        let Some(location) = location else {
            return Err(ControllerError::InvalidArgument(
                SCOPE_NOT_DECLARED
                    .replace("{word}", params.agent.as_str())
                    .replace("{scope}", &params.scope.to_string()),
            ));
        };
        let skills: Vec<&str> = location
            .skills
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(SKILL_NAME))
            .collect();
        let configuration = location.configuration.as_ref().map(|document| {
            let path: Vec<&str> = document.path.iter().map(String::as_str).collect();
            Configuration {
                path: under(&root, &path),
                format: match document.format {
                    DocumentFormat::CodexToml => Format::CodexToml,
                    DocumentFormat::JsonCommandArgs => Format::JsonCommandArgs,
                    DocumentFormat::JsonLocalCommandList => Format::JsonLocalCommandList,
                },
                shared: document.shared,
                deadline: document.deadline.as_ref().map(|deadline| Deadline {
                    field: deadline.field.clone(),
                    value: match deadline.unit {
                        DeadlineUnit::Seconds => QUALIFIED_DEADLINE_SECONDS,
                        DeadlineUnit::Milliseconds => QUALIFIED_DEADLINE_SECONDS * 1_000,
                    },
                }),
            }
        });
        Ok(Layout {
            skills: under(&root, &skills),
            configuration,
        })
    }

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
        let Some(compiled) = params.agent.compiled() else {
            return self.declared_layout(params, &project);
        };
        let layout = match (compiled, params.scope) {
            // Codex reads repository and user skills from `.agents/skills`, and scopes servers to
            // a project with `.codex/config.toml`.
            (CompiledAgent::Codex, User) => Layout {
                skills: under(home, &[".agents", "skills", SKILL_NAME]),
                configuration: Some(Configuration {
                    path: under(home, &[".codex", "config.toml"]),
                    format: Format::CodexToml,
                    shared: false,
                    deadline: None,
                }),
            },
            (CompiledAgent::Codex, Project) => Layout {
                skills: under(&project()?, &[".agents", "skills", SKILL_NAME]),
                configuration: Some(Configuration {
                    path: under(&project()?, &[".codex", "config.toml"]),
                    format: Format::CodexToml,
                    shared: false,
                    deadline: None,
                }),
            },
            (CompiledAgent::ClaudeCode, User) => Layout {
                skills: under(home, &[".claude", "skills", SKILL_NAME]),
                configuration: Some(Configuration {
                    path: under(home, &[".claude.json"]),
                    format: Format::JsonCommandArgs,
                    shared: false,
                    deadline: None,
                }),
            },
            (CompiledAgent::ClaudeCode, Project) => Layout {
                skills: under(&project()?, &[".claude", "skills", SKILL_NAME]),
                configuration: Some(Configuration {
                    path: under(&project()?, &[".mcp.json"]),
                    format: Format::JsonCommandArgs,
                    shared: true,
                    deadline: None,
                }),
            },
            (CompiledAgent::Opencode, User) => Layout {
                skills: under(home, &[".config", "opencode", "skills", SKILL_NAME]),
                configuration: Some(Configuration {
                    path: under(home, &[".config", "opencode", "opencode.json"]),
                    format: Format::JsonLocalCommandList,
                    shared: false,
                    deadline: None,
                }),
            },
            (CompiledAgent::Opencode, Project) => Layout {
                skills: under(&project()?, &[".opencode", "skills", SKILL_NAME]),
                configuration: Some(Configuration {
                    path: under(&project()?, &["opencode.json"]),
                    format: Format::JsonLocalCommandList,
                    shared: false,
                    deadline: None,
                }),
            },
            (CompiledAgent::GeminiCli, User) => Layout {
                skills: under(home, &[".gemini", "skills", SKILL_NAME]),
                configuration: Some(Configuration {
                    path: under(home, &[".gemini", "settings.json"]),
                    format: Format::JsonCommandArgs,
                    shared: false,
                    deadline: None,
                }),
            },
            (CompiledAgent::GeminiCli, Project) => Layout {
                skills: under(&project()?, &[".gemini", "skills", SKILL_NAME]),
                configuration: Some(Configuration {
                    path: under(&project()?, &[".gemini", "settings.json"]),
                    format: Format::JsonCommandArgs,
                    shared: false,
                    deadline: None,
                }),
            },
            (CompiledAgent::KimiCodeCli, User) => Layout {
                skills: under(home, &[".kimi-code", "skills", SKILL_NAME]),
                configuration: Some(Configuration {
                    path: under(home, &[".kimi-code", "mcp.json"]),
                    format: Format::JsonCommandArgs,
                    shared: false,
                    deadline: None,
                }),
            },
            (CompiledAgent::KimiCodeCli, Project) => Layout {
                skills: under(&project()?, &[".kimi", "skills", SKILL_NAME]),
                configuration: Some(Configuration {
                    path: under(&project()?, &[".mcp.json"]),
                    format: Format::JsonCommandArgs,
                    shared: true,
                    deadline: None,
                }),
            },
            (CompiledAgent::QoderCli, User) => Layout {
                skills: under(home, &[".qoder", "skills", SKILL_NAME]),
                configuration: Some(Configuration {
                    path: under(home, &[".qoder", "settings.json"]),
                    format: Format::JsonCommandArgs,
                    shared: false,
                    deadline: None,
                }),
            },
            (CompiledAgent::QoderCli, Project) => Layout {
                skills: under(&project()?, &[".qoder", "skills", SKILL_NAME]),
                configuration: Some(Configuration {
                    path: under(&project()?, &[".mcp.json"]),
                    format: Format::JsonCommandArgs,
                    shared: true,
                    deadline: None,
                }),
            },
        };
        // The deadline an agent takes is the compiled table's, and none is written into a document
        // that more than one agent reads.
        let layout = Layout {
            configuration: layout.configuration.map(|configuration| Configuration {
                deadline: (!configuration.shared)
                    .then(|| compiled_deadline(compiled))
                    .flatten(),
                ..configuration
            }),
            ..layout
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
    ///
    /// This serves the installation records such a build left in the records directory. A read
    /// accepts a record under that name where it finds it, and the move to the current name happens
    /// only with an install or an uninstall. Remove it, with `migrate_records`,
    /// `is_legacy_user_record` and the fallback to the earlier name in `record_source`, once no
    /// supported upgrade starts from a build that named a user record after a project directory.
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
    /// belongs to, under the same lock, and never during a read. On Windows another program can
    /// hold the record for a moment and the move is tried again while it does, so the new name is
    /// looked at again before every attempt: a record written there while the move waits is left
    /// alone like any other.
    ///
    /// Remove it under the condition `legacy_records` states.
    fn migrate_records(&self, params: &AgentToolsParams) -> Result<()> {
        let path = self.record_path(params);
        if path.exists() {
            return Ok(());
        }
        let legacy = self.legacy_records(params)?;
        let [only] = legacy.as_slice() else {
            return Ok(());
        };
        let mut taken = false;
        kr_flush::retry_while_held(|| {
            if path.exists() {
                taken = true;
                return Ok(());
            }
            std::fs::rename(only, &path)
        })
        .map_err(storage)?;
        if taken {
            return Ok(());
        }
        sync_directory(&self.records, NameKind::File)
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
        create_private_directory_durably(&self.records)?;
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

/// The highest format of the retained installation actions this build writes, recorded in each as
/// `version`. A record of an action for one of the six compiled agents is version 1, as every
/// earlier build wrote it, and one that names any other word is version 2 ([`record_version`]).
pub const ACTION_RECORD_VERSION: u32 = 2;

/// The format a record of an installation or of an action for `word` is written in: 1 for one of
/// the six compiled agents, which every earlier build reads, and 2 for any other word, which an
/// earlier build cannot read and so refuses a switch to itself while one is held.
#[must_use]
pub fn record_version(word: &AgentTarget) -> u32 {
    if word.compiled().is_some() { 1 } else { 2 }
}

/// The shape of the installation record this build writes, recorded in it as `version`. A record
/// that states none is one of two earlier shapes, which `read_record` converts.
pub const INSTALLATION_RECORD_VERSION: u32 = InstallationRecord::VERSION;

impl InstallationRecord {
    /// The highest shape this build writes, in which a recorded operation is one that happened.
    /// A record is written in [`record_version`] of its agent, so a host that uses only the six
    /// compiled agents still writes what an earlier build reads.
    const VERSION: u32 = 2;

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
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ActionRecord {
    /// The format of the record: [`ACTION_RECORD_VERSION`] in every record this build writes, `0`
    /// in one that states none, which an earlier build wrote.
    ///
    /// A record is stamped, and its result converted, when it is next asked for. Remove the
    /// default, and the conversion of such a record's result that [`carry_result_forward`] makes,
    /// once no supported upgrade starts from a record written before the format was recorded. A
    /// release that removes them reads no record at version 0, so its `migrates_from` for this
    /// record is 1 and a switch to it is refused while an unstamped record is left; a release before
    /// it therefore has the daemon stamp every record it finds.
    #[serde(default)]
    version: u32,
    /// The digest of the mutation this action was admitted for.
    digest: String,
    /// `dispatching` until the effect finishes, then `applied`.
    state: String,
    /// What the effect produced, once it has: its canonical encoding, in hexadecimal.
    result: Option<String>,
}

impl ActionRecord {
    /// This record in the shape this build writes: its result converted by
    /// [`carry_result_forward`] and re-encoded, and its format stated. `None` when the result
    /// cannot be read, which is left for the answer to refuse.
    fn carried_forward(&self) -> Option<Self> {
        let result = match self.result.as_deref() {
            None => None,
            Some(text) => {
                let value = kr_cbor::decode(&unhex(text)?, &kr_cbor::Limits::DEFAULT).ok()?;
                Some(hex(&kr_cbor::encode(&carry_result_forward(value).ok()?)))
            }
        };
        Some(Self {
            version: 1,
            digest: self.digest.clone(),
            state: self.state.clone(),
            result,
        })
    }
}

/// Why an installation or a removal is refused before anything is written.
#[derive(Debug)]
pub(crate) enum Declined {
    /// The request asks for something this host may not do.
    ByTheRequest(ControllerError),
    /// A record this host holds cannot be read, so it cannot rule out what the record may say.
    ByARecord(Recorded<ControllerError>),
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
    ) -> Recorded<Result<Option<kr_protocol::envelope::ParamsValue>>> {
        Recorded::read(self.action_on_record(actor_id, action_id, digest))
    }

    fn action_on_record(
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
        if record.version > ACTION_RECORD_VERSION {
            return Err(ControllerError::InvalidArgument(format!(
                "the retained installation action {action_id} is of format {}, and this build \
                 reads formats up to {ACTION_RECORD_VERSION}",
                record.version
            )));
        }
        if record.digest != hex(digest.as_bytes()) {
            return Err(ControllerError::IdConflict {
                token: action_id.to_string(),
            });
        }
        // A record written before the format was recorded is written again in this build's shape,
        // its result converted and its format stated, so that a stamped record is wholly current.
        // The answer is owed either way: a record that cannot be written stays as it was and is
        // written the next time it is asked for.
        if record.version == 0
            && let Some(current) = record.carried_forward()
        {
            let _ = self.write_action(actor_id, action_id, &current);
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

    /// What an installation or a removal is refused for before anything is written, with a refusal
    /// that a record this host cannot read causes kept apart from the ones about the request
    /// itself: the first says that a record exists, and the second, which includes a file or a
    /// document of the agent's own that cannot be read, does not.
    ///
    /// Everything here reads. It runs before the dispatch marker, so a change this host will not
    /// make is refused rather than recorded as a change whose outcome nobody knows.
    ///
    /// # Errors
    ///
    /// Returns [`Declined::ByTheRequest`] with [`ControllerError::PermissionDenied`] where a
    /// document it would rewrite has access controls a replacement could not carry or a file is
    /// there that this host did not write, [`ControllerError::Storage`] where they cannot be
    /// read, and [`ControllerError::InvalidArgument`] when the scope needs a project directory
    /// that was not given; and [`Declined::ByARecord`] when the record of the installation
    /// cannot be read or does not parse.
    pub(crate) fn declined_before_writing(
        &self,
        params: &AgentToolsParams,
        removal: bool,
    ) -> std::result::Result<(), Declined> {
        let this = self
            .on_handle(params, !removal)
            .map_err(Declined::ByTheRequest)?;
        let this = &this;
        let recorded = this
            .recorded(params)
            .map_err(|error| Declined::ByARecord(Recorded::read(error)))?;
        if removal {
            // A record decides alone: a package that is gone, disabled or no longer declares the
            // word blocks nothing.
            if recorded.is_none() {
                this.layout(params).map_err(Declined::ByTheRequest)?;
            }
            return this
                .removable_from(recorded)
                .map(|_| ())
                .map_err(Declined::ByTheRequest);
        }
        let layout = this.layout(params).map_err(Declined::ByTheRequest)?;
        this.moved_place(params, &layout, recorded.as_ref())
            .and_then(|()| this.check_before_writing(params, &layout, recorded.as_ref()))
            .map(|_| ())
            .map_err(Declined::ByTheRequest)
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
                // A marker names no word and no result, so every build reads it.
                version: 1,
                digest: hex(digest.as_bytes()),
                state: "dispatching".to_owned(),
                result: None,
            },
        )
    }

    /// Records what the effect produced, in the format of the agent's word.
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
        word: &AgentTarget,
    ) -> Result<()> {
        self.write_action(
            actor_id,
            action_id,
            &ActionRecord {
                version: record_version(word),
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
            // before anything inside is claimed to be durable. They are this host's own records, so
            // each is owner-only.
            create_private_directory_durably(parent)?;
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
        action_file(&self.records, actor_id, action_id)
    }
}

/// Where the record of one actor's installation or removal is kept, under the installer's records.
fn action_file(
    records: &Path,
    actor_id: &kr_protocol::ids::ActorId,
    action_id: kr_protocol::ids::ActionId,
) -> PathBuf {
    records.join("actions").join(format!(
        "{}-{action_id}.json",
        hex(&kr_cbor::sha256(actor_id.as_str().as_bytes())[..8])
    ))
}

/// Whether this environment holds a record of an installation or a removal under this actor's
/// action, whatever became of it.
///
/// The record is a file of its own, written whole, so it is looked for without the lock an
/// installation holds.
///
/// # Errors
///
/// Returns an error when the place the record would be cannot be looked at.
pub fn holds_installation_action(
    state_dir: &Path,
    actor_id: &kr_protocol::ids::ActorId,
    action_id: kr_protocol::ids::ActionId,
) -> Result<bool> {
    action_file(&state_dir.join("agent-tools"), actor_id, action_id)
        .try_exists()
        .map_err(storage)
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
            version: record_version(&manifest.agent),
            state: InstallationRecord::INSTALLING.to_owned(),
            manifest,
            pending: Vec::new(),
        });
    };
    // An unversioned record is one of two shapes, and only the record itself can say which: the
    // journal wrote a `pending` list, the plan before it had no such thing. Serde's default would
    // erase that difference, so it is read from the document.
    let predicted = version == UNVERSIONED && value.get("pending").is_none();
    if version > u64::from(InstallationRecord::VERSION) {
        return Err(format!(
            "this record was written in version {version}, which this build does not read; a \
             newer build wrote it and only that one should change it"
        ));
    }
    let mut record: InstallationRecord =
        serde_json::from_value(value).map_err(|error| error.to_string())?;
    record.version = record_version(&record.manifest.agent);
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

/// Returns true when this file name is one a build of this host gives an installation record.
///
/// The name is `<agent>-<scope>.json`, or `<agent>-<scope>-<digest>.json` for a project. An
/// earlier build also gave a *user* record a digest, and those records still hold claims, so the
/// name it used is recognised here as well.
fn is_record_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".json") else {
        return false;
    };
    let is_word = |word: &str| AgentTarget::problem(word).is_none();
    ["user", "project"].iter().any(|scope| {
        let ending = format!("-{scope}");
        stem.strip_suffix(ending.as_str()).is_some_and(is_word)
            || stem.rsplit_once('-').is_some_and(|(head, digest)| {
                is_digest_name(digest) && head.strip_suffix(ending.as_str()).is_some_and(is_word)
            })
    })
}

/// Returns true when this file name is the one an earlier build gave a user record.
///
/// Remove it under the condition `legacy_records` states.
fn is_legacy_user_record(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(".json"))
        .is_some_and(is_digest_name)
}

fn is_digest_name(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_hexdigit())
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
        ) => names_path(left_path, Path::new(right_path)) && left_entry == right_entry,
        (left, right) => {
            std::mem::discriminant(left) == std::mem::discriminant(right)
                && names_path(left.path(), Path::new(right.path()))
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

/// The deadline one compiled agent takes, where it has one.
///
/// Each spelling belongs to that agent's own configuration document. A document more than one
/// agent reads carries none of them: the three agents that share a project's `.mcp.json` do not
/// share a spelling, and the entry written for one of them is the entry the others read. Where no
/// deadline can be declared, the helper bounds its own default instead.
///
/// OpenCode is deliberately absent. What its configuration exposes is broader than one server, and
/// a setting that changes how every server behaves is not this installation's to write.
fn compiled_deadline(agent: CompiledAgent) -> Option<Deadline> {
    let (field, value) = match agent {
        CompiledAgent::Codex => ("tool_timeout_sec", QUALIFIED_DEADLINE_SECONDS),
        CompiledAgent::KimiCodeCli => ("toolTimeoutMs", QUALIFIED_DEADLINE_SECONDS * 1_000),
        CompiledAgent::ClaudeCode | CompiledAgent::QoderCli | CompiledAgent::GeminiCli => {
            ("timeout", QUALIFIED_DEADLINE_SECONDS * 1_000)
        }
        CompiledAgent::Opencode => return None,
    };
    Some(Deadline {
        field: field.to_owned(),
        value,
    })
}

/// The words of the agents this host knows, as a sentence part: the six it compiles in, and the
/// words an admitted package declares or a record of this host holds, where there are any.
fn known_words(declared: &[String]) -> String {
    let words: Vec<&str> = CompiledAgent::ALL
        .iter()
        .map(|agent| agent.as_str())
        .collect();
    let mut sentence = match words.split_last() {
        Some((last, first)) => format!("{} and {last}", first.join(", ")),
        None => String::new(),
    };
    if !declared.is_empty() {
        sentence.push_str(", and ");
        sentence.push_str(&declared.join(", "));
    }
    sentence
}

/// The word an installation record's file name belongs to, when the name is a record's.
fn record_word(name: &str) -> Option<String> {
    if !is_record_name(name) {
        return None;
    }
    let stem = name.strip_suffix(".json")?;
    let head = match stem.rsplit_once('-') {
        Some((head, digest)) if is_digest_name(digest) => head,
        _ => stem,
    };
    head.strip_suffix("-user")
        .or_else(|| head.strip_suffix("-project"))
        .map(str::to_owned)
}

/// The refusal of a scope the declaration has no place for.
const SCOPE_NOT_DECLARED: &str =
    "{word} declares no place at {scope} scope, so this host installs nothing there for it";

/// Returns `base` with `names` joined onto it one at a time.
///
/// A name that held a separator would keep it as written, and on Windows a path whose names were
/// joined two at a time would then be printed and recorded with both separators.
fn under(base: &Path, names: &[&str]) -> PathBuf {
    names
        .iter()
        .fold(base.to_path_buf(), |path, name| path.join(name))
}

/// Returns true when a recorded path names `path`.
///
/// Compared as paths, not as text: an earlier build joined two names at a time, so on Windows the
/// records it wrote spell some paths with both separators. ASCII case is ignored, because a file
/// system that does not tell `Mcp.json` from `mcp.json` holds one document under both spellings.
fn names_path(recorded: &str, path: &Path) -> bool {
    same_place(Path::new(recorded), path)
}

/// Whether two paths are one place for a claim: the same components, ASCII case ignored, for the
/// six compiled words and the declared ones alike. On a file system that tells `Mcp.json` from
/// `mcp.json` this takes two places for one, and the host then refuses more than it must: a
/// document another record holds under the other spelling is not written into. It decides
/// refusals only, never what is written or whose a file is: the move check compares places by
/// their exact components.
fn same_place(first: &Path, second: &Path) -> bool {
    let folded = |path: &Path| -> Vec<String> {
        path.components()
            .map(|component| component.as_os_str().to_string_lossy().to_ascii_lowercase())
            .collect()
    };
    folded(first) == folded(second)
}

/// How many files an installation writes.
const FILE_COUNT: usize = 3;

/// What each of the files was when the installation checked it, in the order it writes them: the
/// digest of a file this host owns, or `None` for a name that was free.
type Checked = [Option<Digest256>; FILE_COUNT];

/// The files an installation writes, in the order it writes them.
fn files() -> [(&'static str, &'static str); FILE_COUNT] {
    [
        ("SKILL.md", SKILL_MD),
        ("TOOLS.md", TOOLS_MD),
        ("manifest.json", MANIFEST_JSON),
    ]
}

fn read_to_string(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(storage(error)),
    }
}

/// Reads a JSON configuration document exactly, with the place of every member, or `None` when
/// there is none.
///
/// The document is somebody's, so it is edited one member at a time with every other byte kept.
/// A document this reader cannot read exactly is refused, naming it and why: one that names a
/// member twice in any object among them, because which of the two a reader keeps is the reader's
/// choice.
/// The digest of the text a read returned, or none where nothing was there.
fn text_digest(text: Option<&str>) -> Option<Digest256> {
    text.map(|text| digest_of(text.as_bytes()))
}

fn read_exact(fs: &Fs, path: &Path) -> Result<Option<(String, json::Document)>> {
    let Some(text) = fs.read_text(path)? else {
        return Ok(None);
    };
    let document = json::Document::read(&text).map_err(|reason| not_exact(path, &reason))?;
    Ok(Some((text, document)))
}

/// The refusal of a JSON document this host cannot edit exactly.
fn not_exact(path: &Path, reason: &str) -> ControllerError {
    ControllerError::InvalidArgument(format!(
        "{} is not a document this host can edit exactly: {reason}",
        display(path)
    ))
}

/// The refusal of a document whose server container is not an object.
fn not_servers(key: &str, path: &Path) -> ControllerError {
    ControllerError::InvalidArgument(format!(
        "{key} in {} is not an object of servers",
        display(path)
    ))
}

/// The key a recorded entry's servers are held under: `mcpServers` for `mcpServers.kalareach`.
fn entry_key(entry: &str) -> &str {
    entry.rsplit_once('.').map_or("mcpServers", |(key, _)| key)
}

/// Returns the command an agent runs to reach the tools.
///
/// The `kr` an update replaces when this daemon is of an installed release: the path through the
/// store's `current`, which an agent's configuration keeps naming across updates, so an agent that
/// starts after an update runs the new release's tools. Outside a store, the `kr` beside this
/// daemon when there is one, so an installation from a build that is not on the path still reaches
/// that build. Otherwise the plain command name, which the person's path resolves.
///
/// Whether the `kr` is there is asked of the release `current` names, read once, so a switch under
/// way cannot make the command fall back to the plain name in a configuration written for good.
fn entry_command() -> String {
    entry_command_of(kr_ipc::install::this_process().ok())
}

/// [`entry_command`] for the process `running`.
fn entry_command_of(running: Option<&kr_ipc::install::Running>) -> String {
    running
        .and_then(|running| running.stable_if_present(kr_ipc::install::Program::Kr))
        .map_or_else(|| "kr".to_owned(), |path| display(&path))
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
                self.root.join("state").join("agent-tools"),
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

    /// The command an agent runs is the `kr` through the store's `current` where the release
    /// `current` names carries one, and the plain name where it does not, or where `current` is
    /// not a link the store makes: that one is not asked, though the file is there through it.
    #[cfg(unix)]
    #[test]
    fn the_command_an_agent_runs_is_the_current_release_s_kr_where_a_switch_made_current() {
        use kr_ipc::install::{Program, Running, Store};
        use kr_protocol::update::ReleaseName;

        let host = kr_ipc::testing::TempHost::create();
        let store = Store::at(host.root().join("store"));
        store.create_directories().expect("the store's directories");
        std::fs::write(store.record(), b"{}\n").expect("the store's record");
        let release = ReleaseName::new("0.1.0+aaaaaaaaaaaa").expect("a release");
        std::fs::create_dir_all(store.release_directory(&release).join("bin"))
            .expect("the release's bin");
        std::fs::write(
            store.manifest(&release),
            serde_json::json!({
                "signed": {
                    "_type": "kalareach-release",
                    "release": release,
                    "sequence": "1",
                    "commit": "4254aa6e62e585478ff8dcff5518f23c7263f4ce",
                    "target": "aarch64-apple-darwin",
                    "os_floor": { "system": "macos", "version": "14.0" },
                    "protocol_version": { "major": 0, "minor": 48, "patch": 0 },
                    "public_majors": [1],
                    "retained_levels": ["0.48"],
                    "shells": [],
                    "agents": [],
                    "dependencies": {
                        "lock_sha256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "pinned": [],
                        "vectors": []
                    },
                    "stores": [{
                        "store": "registry",
                        "scope": "environment",
                        "path": "registry.sqlite",
                        "recording": { "kind": "sqlite_table", "table": "schema_version" },
                        "version": 7,
                        "migrates_from": 1,
                    }],
                    "files": [],
                },
                "signatures": [],
            })
            .to_string(),
        )
        .expect("a manifest");
        let kr = store.release_program(&release, Program::Kr);
        kr_ipc::testing::place_program(&std::env::current_exe().expect("a program"), &kr);
        let running = Running::of_image(&kr).expect("a release of the store");

        assert_eq!(
            entry_command_of(Some(&running)),
            "kr",
            "no release is current"
        );
        std::os::unix::fs::symlink(
            std::path::Path::new(kr_ipc::install::VERSIONS).join(release.as_str()),
            store.current_link(),
        )
        .expect("current names the release");
        assert_eq!(
            entry_command_of(Some(&running)),
            display(&store.stable(Program::Kr))
        );

        std::fs::remove_file(store.current_link()).expect("current goes");
        std::os::unix::fs::symlink(store.release_directory(&release), store.current_link())
            .expect("an absolute link");
        assert!(
            store.stable(Program::Kr).is_file(),
            "the file is there through the link"
        );
        assert_eq!(entry_command_of(Some(&running)), "kr");
    }

    /// A user record installed and then given the name an earlier build gave it, with the name
    /// this build gives it free.
    #[cfg(windows)]
    fn record_under_its_earlier_name(
        installer: &Installer,
        params: &AgentToolsParams,
    ) -> (PathBuf, PathBuf) {
        installer.install(params).expect("installs");
        let modern = installer.record_path(params);
        let legacy =
            installer
                .records
                .join(format!("{}-user-{}.json", params.agent, hex(&[0xab, 0xcd])));
        std::fs::rename(&modern, &legacy).expect("wears the earlier name");
        (modern, legacy)
    }

    /// On Windows a record from an earlier build that another program holds without sharing its
    /// deletion, as a scanner holds a file it reads, is moved onto the name this build gives it
    /// once that program lets go.
    #[cfg(windows)]
    #[test]
    fn a_held_record_from_an_earlier_build_is_moved_once_it_is_let_go() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::CODEX, InstallScope::User);
        let (modern, legacy) = record_under_its_earlier_name(&installer, &params);
        let kept = std::fs::read(&legacy).expect("the record");
        let (refusals, guard) = crate::catalogue::files::tests::at_the_first_refusal(
            crate::catalogue::files::tests::hold(&legacy),
            drop,
        );
        let moved = installer.migrate_records(&params);
        drop(guard);
        moved.expect("moved once it is let go");
        assert_eq!(refusals.get(), 1, "refused once while it was held");
        assert!(!legacy.exists(), "the earlier name is gone");
        assert_eq!(std::fs::read(&modern).expect("the record"), kept);
    }

    /// On Windows the check a move stands on, that the name this build gives the record is free,
    /// is made again before every attempt: a record another writer puts there while the held move
    /// waits is never replaced, and both names are left alone.
    #[cfg(windows)]
    #[test]
    fn a_record_written_under_the_new_name_while_the_move_waits_is_not_replaced() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::CODEX, InstallScope::User);
        let (modern, legacy) = record_under_its_earlier_name(&installer, &params);
        let kept = std::fs::read(&legacy).expect("the record");
        let written = modern.clone();
        let (refusals, guard) = crate::catalogue::files::tests::at_the_first_refusal(
            crate::catalogue::files::tests::hold(&legacy),
            move |holding| {
                std::fs::write(&written, b"another writer's record")
                    .expect("another writer takes the name meanwhile");
                drop(holding);
            },
        );
        let moved = installer.migrate_records(&params);
        drop(guard);
        moved.expect("both are left alone");
        assert_eq!(refusals.get(), 1);
        assert_eq!(std::fs::read(&legacy).expect("the earlier record"), kept);
        assert_eq!(
            std::fs::read(&modern).expect("the other writer's record"),
            b"another writer's record"
        );
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

    /// KR-REQ-24.26: the directories this host keeps its installation records in are owner-only
    /// whatever the mask of the process, because they are its own state: the one an installation's
    /// record is written in, and the one a retained action's record is written in below it. They
    /// are made by different writers, so a tree of its own holds each. A directory the agent reads
    /// its skill from is the agent's, and is made with the mode the mask gives it.
    #[cfg(unix)]
    #[test]
    fn the_directories_installation_records_are_kept_in_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let mode =
            |path: &Path| std::fs::metadata(path).expect("made").permissions().mode() & 0o777;
        let _login = kr_ipc::testing::LoginUmask::hold();

        // An installation writes its own record, in a state directory with no records yet.
        let tree = Tree::create();
        tree.installer()
            .install(&params(AgentTarget::CLAUDE_CODE, InstallScope::User))
            .expect("installs");
        let records = tree.root.join("state").join("agent-tools");
        assert_eq!(mode(&records), 0o700, "{}", records.display());
        // The control: a directory in the agent's own tree gets the mask's mode, which is the mode
        // the records' directory would have had.
        let skills = tree.home().join(".claude/skills");
        assert_eq!(mode(&skills), 0o755, "{}", skills.display());

        // A retained action's record is written first, in another tree with none.
        let other = Tree::create();
        let actor = kr_protocol::ids::ActorId::new("local:501").expect("a principal");
        let action =
            kr_protocol::ids::ActionId::new(kr_protocol::scalars::Uuid::from_bytes([8; 16]));
        other
            .installer()
            .mark_dispatching(&actor, action, &digest_of(b"the payload"))
            .expect("the marker is written");
        let records = other.root.join("state").join("agent-tools");
        for made in [records.clone(), records.join("actions")] {
            assert_eq!(mode(&made), 0o700, "{}", made.display());
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
        let params = params(AgentTarget::CLAUDE_CODE, InstallScope::User);
        let result = installer.install(&params).expect("installs");
        assert!(!result.already_installed);
        assert!(result.unresolved.is_empty());

        let manifest = &result.manifest;
        assert_eq!(manifest.agent, AgentTarget::CLAUDE_CODE);
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
            installer.entry_value(
                Format::JsonCommandArgs,
                compiled_deadline(CompiledAgent::ClaudeCode).as_ref()
            )
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
        let params = params(AgentTarget::CLAUDE_CODE, InstallScope::User);
        installer.install(&params).expect("installs");
        let again = installer.install(&params).expect("installs");
        assert!(again.already_installed);
    }

    /// KR-REQ-23.33: status reports the installation against its exact manifest.
    #[test]
    fn status_reports_what_changed_since_the_installation() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::CLAUDE_CODE, InstallScope::User);
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
        let params = params(AgentTarget::CLAUDE_CODE, InstallScope::User);
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
        let params = params(AgentTarget::CLAUDE_CODE, InstallScope::User);
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
            .install(&params(AgentTarget::CLAUDE_CODE, InstallScope::User))
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
        let params = params(AgentTarget::CODEX, InstallScope::User);
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
            .install(&params(AgentTarget::CLAUDE_CODE, InstallScope::User))
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
            .install(&params(AgentTarget::CLAUDE_CODE, InstallScope::User))
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
            .install(&with_project(AgentTarget::CLAUDE_CODE))
            .expect("installs");
        installer
            .install(&with_project(AgentTarget::QODER_CLI))
            .expect("installs");
        let shared = project.join(".mcp.json");
        assert!(shared.is_file());

        let removed = installer
            .remove(&with_project(AgentTarget::CLAUDE_CODE))
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
            .remove(&with_project(AgentTarget::QODER_CLI))
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
                .copied()
                .into_answer_for_test()
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
            .copied()
            .into_answer_for_test()
            .expect_err("uncertain");
        assert_eq!(
            error.to_protocol_error().code,
            kr_protocol::error::ErrorCode::OutcomeUnknown
        );

        let result = kr_protocol::envelope::ParamsValue::from_typed(&AgentToolsRemoveResult {
            agent: AgentTarget::CODEX,
            scope: InstallScope::User,
            removed: Vec::new(),
            retained: Vec::new(),
        })
        .expect("encodes");
        installer
            .settle(&actor, action, &digest, &result, &AgentTarget::CODEX)
            .expect("settles");
        assert_eq!(
            installer
                .retained(&actor, action, &digest)
                .copied()
                .into_answer_for_test()
                .expect("reads"),
            Some(result)
        );
        let error = installer
            .retained(&actor, action, &other)
            .copied()
            .into_answer_for_test()
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
        let params = params(AgentTarget::CLAUDE_CODE, InstallScope::User);
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
        let params = params(AgentTarget::CLAUDE_CODE, InstallScope::User);
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
        let params = params(AgentTarget::CLAUDE_CODE, InstallScope::User);
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
        let params = params(AgentTarget::CLAUDE_CODE, InstallScope::User);
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
        let params = params(AgentTarget::CODEX, InstallScope::User);
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
        let params = params(AgentTarget::CODEX, InstallScope::User);
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
            agent: params(AgentTarget::CODEX, InstallScope::User).agent,
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
                    // As an earlier build wrote it: no format stated.
                    version: 0,
                    digest: hex(digest.as_bytes()),
                    state: "applied".to_owned(),
                    result: Some(hex(&kr_cbor::encode(&stored))),
                },
            )
            .expect("writes the action record");

        let answer = installer
            .retained(&actor, action, &digest)
            .copied()
            .into_answer_for_test()
            .expect("reads")
            .expect("an answer");

        let result: AgentToolsInstallResult = answer.to_typed().expect("this build can read it");
        assert!(result.already_installed);
        assert!(result.unresolved.is_empty());

        // The record was written again: stamped, and holding the result in this build's shape, so
        // the conversion is no longer needed to read it.
        let text =
            std::fs::read_to_string(installer.action_path(&actor, action)).expect("a record");
        let record: ActionRecord = serde_json::from_str(&text).expect("a record");
        assert_eq!(
            record.version, 1,
            "a result of a compiled agent is written in version 1"
        );
        let kept = kr_cbor::decode(
            &unhex(&record.result.expect("a result")).expect("hexadecimal"),
            &kr_cbor::Limits::DEFAULT,
        )
        .expect("a value");
        let kr_cbor::CanonicalValue::Map(kept) = kept else {
            panic!("a result is a map");
        };
        assert!(kept.get("unresolved").is_some(), "the result is converted");
    }

    /// A record is written at the version an earlier build reads for one of the six compiled words
    /// and at the next version for any other word, in every writer of an action record: the
    /// dispatching marker names no word and is always version 1, a settled result takes its word's
    /// version, and a replay of a result that carried no version stamps version 1.
    #[test]
    fn a_record_carries_version_one_for_the_six_and_two_for_a_declared_word() {
        let declared = AgentTarget::parse("amp").expect("a word in the grammar");
        for word in AgentTarget::ALL {
            assert_eq!(record_version(word), 1, "{word} is one of the six");
        }
        assert_eq!(record_version(&declared), 2);
        assert_eq!(
            ACTION_RECORD_VERSION, 2,
            "the highest version this build writes"
        );
        assert_eq!(INSTALLATION_RECORD_VERSION, 2);

        let tree = Tree::create();
        let installer = tree.installer();
        let actor = kr_protocol::ids::ActorId::new("local:owner").expect("a principal");
        let digest = Digest256::from_bytes([9; 32]);
        let read = |path: &Path| -> Value {
            serde_json::from_slice(&std::fs::read(path).expect("the record")).expect("JSON")
        };
        let settled = |word: &AgentTarget| {
            let action = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
            installer
                .mark_dispatching(&actor, action, &digest)
                .expect("marks");
            let path = installer.action_path(&actor, action);
            assert_eq!(read(&path)["version"], 1, "a marker names no word");
            let result = kr_protocol::envelope::ParamsValue::from_typed(&AgentToolsRemoveResult {
                agent: word.clone(),
                scope: InstallScope::User,
                removed: Vec::new(),
                retained: Vec::new(),
            })
            .expect("encodes");
            installer
                .settle(&actor, action, &digest, &result, word)
                .expect("settles");
            let version = read(&path)["version"].clone();
            // Answering from the record again changes nothing: a replay never stamps 2 on a
            // result of one of the six.
            installer
                .retained(&actor, action, &digest)
                .copied()
                .into_answer_for_test()
                .expect("reads")
                .expect("an answer");
            assert_eq!(
                read(&path)["version"],
                version,
                "a replay keeps the version"
            );
            version
        };
        assert_eq!(
            settled(&AgentTarget::CODEX),
            1,
            "a result for one of the six"
        );
        assert_eq!(settled(&declared), 2, "a result for a declared word");
    }

    /// KR-REQ-11.01 (W4): the records a real installation writes carry the word's version through
    /// every writer: the installation record after an installation, after the repair of an
    /// interrupted one and after a removal, and the action record of each result this host settles,
    /// at version 1 for one of the six and 2 for a declared word.
    #[cfg(unix)]
    #[test]
    fn the_records_of_real_installations_carry_the_version_of_their_word() {
        let actor = kr_protocol::ids::ActorId::new("local:owner").expect("a principal");
        let digest = Digest256::from_bytes([7; 32]);
        let read = |path: &Path| -> Value {
            serde_json::from_slice(&std::fs::read(path).expect("the record")).expect("JSON")
        };
        let cases: [(
            AgentTarget,
            Option<kr_plugin_sdk::skill_target::SkillTarget>,
            u64,
        ); 2] = [
            (AgentTarget::CODEX, None, 1),
            (amp(), Some(declared(None, &[".amp", "skills"])), 2),
        ];
        for (word, declaration, version) in cases {
            let tree = Tree::create();
            let installer = tree.installer().with_declaration(declaration, Vec::new());
            let request = params(word.clone(), InstallScope::User);
            let settle = |result: kr_protocol::envelope::ParamsValue| {
                let action = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
                installer
                    .mark_dispatching(&actor, action, &digest)
                    .expect("marks");
                installer
                    .settle(&actor, action, &digest, &result, &word)
                    .expect("settles");
                read(&installer.action_path(&actor, action))["version"].clone()
            };

            // A completed installation.
            let installed = installer.install(&request).expect("installs");
            assert_eq!(
                read(&installer.record_path(&request))["version"],
                version,
                "{word}: the installation record after an installation"
            );
            assert_eq!(
                settle(
                    kr_protocol::envelope::ParamsValue::from_typed(&installed).expect("encodes")
                ),
                version,
                "{word}: the action record of an installation result"
            );

            // The repair of an installation that stopped: the record is open, a file is gone.
            let path = installer.record_path(&request);
            let mut record =
                read_record(&std::fs::read_to_string(&path).expect("the record")).expect("reads");
            record.state = InstallationRecord::INSTALLING.to_owned();
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&record).expect("encodes"),
            )
            .expect("writes");
            std::fs::remove_file(tree.home().join(match word.compiled() {
                Some(_) => ".agents/skills/kalareach-contact/TOOLS.md",
                None => ".amp/skills/kalareach-contact/TOOLS.md",
            }))
            .expect("a file goes missing");
            let repaired = installer.install(&request).expect("repairs");
            assert_eq!(
                read(&path)["version"],
                version,
                "{word}: the installation record after a repair"
            );
            assert_eq!(
                settle(kr_protocol::envelope::ParamsValue::from_typed(&repaired).expect("encodes")),
                version,
                "{word}: the action record of a repair result"
            );

            // A removal.
            let removed = installer.remove(&request).expect("removes");
            assert_eq!(
                settle(kr_protocol::envelope::ParamsValue::from_typed(&removed).expect("encodes")),
                version,
                "{word}: the action record of a removal result"
            );
        }
    }

    /// KR-REQ-11.01 (I15): a declaration with no configuration document installs the skill's three
    /// files and no entry, reports itself installed with no configuration entry in its record, and
    /// is removed whole.
    #[cfg(unix)]
    #[test]
    fn a_declaration_with_no_configuration_installs_the_skill_alone() {
        let tree = Tree::create();
        let installer = tree
            .installer()
            .with_declaration(Some(declared(None, &[".amp", "skills"])), Vec::new());
        let request = params(amp(), InstallScope::User);
        let result = installer.install(&request).expect("installs");
        let folder = tree.home().join(".amp/skills/kalareach-contact");
        for name in ["SKILL.md", "TOOLS.md", "manifest.json"] {
            assert!(folder.join(name).is_file(), "{name} is written");
        }
        assert!(
            result.unresolved.is_empty(),
            "nothing is left unaccounted for: {:?}",
            result.unresolved
        );
        let record = installer
            .recorded(&request)
            .expect("reads")
            .expect("a record");
        assert!(record.is_complete());
        assert!(
            !record.manifest.operations.iter().any(|operation| matches!(
                operation,
                ChangeOperation::AddConfigurationEntry { .. }
            )),
            "no entry was added"
        );
        let status = installer.status(&request).expect("reads");
        assert!(status.installed && status.drift.is_empty(), "{status:?}");
        installer.remove(&request).expect("removes");
        assert!(!folder.exists(), "the skill's folder is removed");
        assert!(
            !tree.home().join(".amp").exists(),
            "the folders this host made go with it"
        );
    }

    /// KR-REQ-11.01 (I16): a scope the declaration has no place for is refused by name before
    /// anything is written, and the scope it does declare installs.
    #[cfg(unix)]
    #[test]
    fn a_scope_the_declaration_does_not_name_is_refused_before_anything_is_written() {
        let tree = Tree::create();
        let project = tree.root.join("project");
        std::fs::create_dir_all(&project).expect("a project");
        let installer = tree
            .installer()
            .with_declaration(Some(declared(None, &[".amp", "skills"])), Vec::new());
        let refused = installer.install(&AgentToolsParams {
            agent: amp(),
            scope: InstallScope::Project,
            project_dir: Nullable::some(display(&project)),
        });
        assert_eq!(
            refused.as_ref().err().map(ToString::to_string),
            Some(
                "amp declares no place at project scope, so this host installs nothing there for it"
                    .to_owned()
            ),
            "{refused:?}"
        );
        assert!(
            std::fs::read_dir(&project).expect("reads").next().is_none(),
            "nothing was written"
        );
        let declared_scope = installer.install(&params(amp(), InstallScope::User));
        assert!(declared_scope.is_ok(), "{declared_scope:?}");
    }

    /// KR-REQ-11.01 (E15): one rule for every word. A record of a compiled word whose place is not
    /// the place this host installs it at now is a moved place, said in the words of a compiled word,
    /// and `status` shows the same sentence as drift; a compiled word's entry follows the host's own
    /// executable, so a changed command is not a moved place.
    #[cfg(unix)]
    #[test]
    fn a_compiled_word_whose_recorded_place_moved_is_refused_and_status_shows_it() {
        let tree = Tree::create();
        let installer = tree.installer();
        let request = params(AgentTarget::CODEX, InstallScope::User);
        installer.install(&request).expect("installs");
        let path = installer.record_path(&request);
        let mut record =
            read_record(&std::fs::read_to_string(&path).expect("the record")).expect("reads");
        let recorded_root = record.manifest.root.clone();
        let document = display(&tree.home().join(".codex").join("config.toml"));
        let before = installer.status(&request).expect("reads");
        assert!(before.drift.is_empty(), "{:?}", before.drift);

        // The host now installs it at another skills folder than the record names.
        record.manifest.root = display(&tree.home().join(".elsewhere").join("kalareach-contact"));
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&record).expect("encodes"),
        )
        .expect("writes");
        let expected = format!(
            "the record of codex at user scope names {} and {document}, entry mcp_servers.kalareach, \
             and this host now installs codex at {recorded_root} and {document}, entry \
             mcp_servers.kalareach; run kr skill remove --agent codex --scope user, with \
             --project-dir for a project, and then install again",
            record.manifest.root
        );
        let refused = installer
            .install(&request)
            .map(|_| ())
            .map_err(|e| e.to_string());
        assert_eq!(refused, Err(expected.clone()));
        let status = installer.status(&request).expect("reads");
        assert!(
            status.drift.contains(&expected),
            "status shows the drift: {:?}",
            status.drift
        );
    }

    /// KR-REQ-11.01 (E15): `status` of a declared word shows the same drift where the declaration
    /// the service resolved names another place than the record does.
    #[cfg(unix)]
    #[test]
    fn status_shows_the_drift_of_a_declared_word_whose_package_moved_its_place() {
        let tree = Tree::create();
        let configuration = |name: &str| {
            Some(json!({ "path": [".amp", name], "format": "json_command_args", "shared": false }))
        };
        let first = tree.installer().with_declaration(
            Some(declared(configuration("mcp.json"), &[".amp", "skills"])),
            Vec::new(),
        );
        let request = params(amp(), InstallScope::User);
        first.install(&request).expect("installs");
        assert!(first.status(&request).expect("reads").drift.is_empty());
        let moved = tree.installer().with_declaration(
            Some(declared(configuration("other.json"), &[".amp", "skills"])),
            Vec::new(),
        );
        let status = moved.status(&request).expect("reads");
        assert!(
            status.drift.iter().any(
                |said| said.contains("the record of amp at user scope names")
                    && said.contains("and the package now declares")
                    && said.contains("other.json, entry mcpServers.kalareach")
            ),
            "{:?}",
            status.drift
        );
    }

    /// KR-REQ-11.01: a declaration whose place differs from the record's only in ASCII case is a
    /// moved place, for the skills folder and for the document alike. The record names the files
    /// under one spelling, and a repair under the other, on a file system that tells the
    /// spellings apart, would write files no record names. The installation is refused by the
    /// moved-place sentence before it writes anything, and the files and the record stay as they
    /// were.
    #[cfg(unix)]
    #[test]
    fn a_declaration_that_changes_only_the_case_of_a_place_is_a_moved_place() {
        // Whether this file system tells `probe` from `PROBE`: where it does not, the other
        // spelling is the same folder, and that nothing is made under it cannot be asserted.
        let tells_case_apart = {
            let probe = Tree::create();
            std::fs::create_dir(probe.home().join("probe")).expect("a folder");
            !probe.home().join("PROBE").exists()
        };
        if !tells_case_apart {
            eprintln!(
                "this file system does not tell ASCII case apart: the case asserts the refusal, \
                 the files and the record, and not that the other spelling is left unmade"
            );
        }
        let request = params(amp(), InstallScope::User);
        for (what, folder, document, repairable) in [
            (
                "the skills folder, with a file to repair",
                ".AMP",
                "mcp.json",
                true,
            ),
            (
                "the skills folder, with nothing to repair",
                ".AMP",
                "mcp.json",
                false,
            ),
            ("the document", ".amp", "MCP.json", false),
        ] {
            let tree = Tree::create();
            let declaring = |folder: &str, document: &str| {
                tree.installer().with_declaration(
                    Some(declared(
                        Some(json!({
                            "path": [folder, document], "format": "json_command_args", "shared": false
                        })),
                        &[folder, "skills"],
                    )),
                    Vec::new(),
                )
            };
            declaring(".amp", "mcp.json")
                .install(&request)
                .expect("installs");
            if repairable {
                std::fs::remove_file(tree.home().join(".amp/skills/kalareach-contact/TOOLS.md"))
                    .expect("a file is missing");
            }
            let state = || {
                (
                    files_under(&tree.home()),
                    format!(
                        "{:?}",
                        declaring(".amp", "mcp.json")
                            .recorded(&request)
                            .expect("reads")
                    ),
                )
            };
            let before = state();
            let refused = declaring(folder, document)
                .install(&request)
                .expect_err(what);
            let ControllerError::InvalidArgument(said) = &refused else {
                panic!("{what}: a refusal by name: {refused}");
            };
            assert!(
                said.contains("the record of amp at user scope names")
                    && said.contains("and the package now declares"),
                "{what}: {said}"
            );
            assert!(state() == before, "{what}: the files and the record stay");
            if tells_case_apart && folder != ".amp" {
                assert!(
                    !tree.home().join(folder).exists(),
                    "{what}: nothing is made under the other spelling"
                );
            }
        }
    }

    /// A record of version 1 and one of version 2 are read through one reader, as the same shape.
    #[test]
    fn a_version_one_and_a_version_two_record_read_through_one_reader() {
        let record = |version: u32| {
            serde_json::json!({
                "version": version,
                "state": "installed",
                "manifest": manifest_value(),
                "pending": [],
            })
            .to_string()
        };
        let one = read_record(&record(1)).expect("version 1 is read");
        let two = read_record(&record(2)).expect("version 2 is read");
        assert_eq!(one.manifest, two.manifest);
        assert!(read_record(&record(INSTALLATION_RECORD_VERSION + 1)).is_err());
    }

    /// A skill target as a package declares it, for the cases of a declared word.
    #[cfg(unix)]
    fn declared(
        configuration: Option<Value>,
        skills: &[&str],
    ) -> kr_plugin_sdk::skill_target::SkillTarget {
        let mut user = json!({ "skills": skills });
        if let Some(configuration) = configuration {
            user["configuration"] = configuration;
        }
        serde_json::from_value(json!({ "word": "amp", "user": user })).expect("a target")
    }

    #[cfg(unix)]
    fn amp() -> AgentTarget {
        AgentTarget::parse("amp").expect("a word")
    }

    /// KR-REQ-11.01: an installation for a declared word writes the core's three files with the
    /// digests this binary carries and one entry whose command and arguments are the host's, in each
    /// of the three formats, whatever the package says.
    #[cfg(unix)]
    #[test]
    fn an_installation_for_a_declared_word_writes_the_cores_files_and_one_entry() {
        for (format, document, found) in [
            ("json_command_args", "mcp.json", "mcpServers"),
            ("json_local_command_list", "mcp.json", "mcp"),
            ("codex_toml", "config.toml", "mcp_servers"),
        ] {
            let tree = Tree::create();
            let target = declared(
                Some(json!({ "path": [".amp", document], "format": format, "shared": false })),
                &[".amp", "skills"],
            );
            let installer = tree
                .installer()
                .with_declaration(Some(target), vec!["amp".to_owned()]);
            let installed = installer
                .install(&params(amp(), InstallScope::User))
                .expect("a declared word installs");
            assert!(!installed.already_installed);
            let skill = tree.home().join(".amp/skills").join(SKILL_NAME);
            for (name, contents) in files() {
                assert_eq!(
                    std::fs::read(skill.join(name)).expect("a file"),
                    contents.as_bytes(),
                    "{format}: {name}"
                );
            }
            let text = std::fs::read_to_string(tree.home().join(".amp").join(document))
                .expect("the document");
            if format == "codex_toml" {
                let parsed: toml_edit::DocumentMut = text.parse().expect("TOML");
                let entry = &parsed[found][SERVER_NAME];
                assert_eq!(entry["command"].as_str(), Some("/opt/kalareach/kr"));
                let arguments: Vec<&str> = entry["args"]
                    .as_array()
                    .expect("arguments")
                    .iter()
                    .filter_map(toml_edit::Value::as_str)
                    .collect();
                assert_eq!(arguments, ["agent-tools", "--stdio"]);
            } else {
                let parsed: Value = serde_json::from_str(&text).expect("JSON");
                let entry = &parsed[found][SERVER_NAME];
                if format == "json_command_args" {
                    assert_eq!(entry["command"], "/opt/kalareach/kr");
                    assert_eq!(entry["args"], json!(["agent-tools", "--stdio"]));
                } else {
                    assert_eq!(
                        entry["command"],
                        json!(["/opt/kalareach/kr", "agent-tools", "--stdio"])
                    );
                }
            }
        }
    }

    /// KR-REQ-11.01: a declared deadline writes the field and the environment value, in either
    /// unit, and a configuration with none, a shared document and the command-list form write
    /// neither.
    #[cfg(unix)]
    #[test]
    fn a_declared_deadline_writes_the_field_and_the_environment_value_and_none_without_one() {
        let installed = |configuration: Value| -> String {
            let tree = Tree::create();
            let target = declared(Some(configuration), &[".amp", "skills"]);
            tree.installer()
                .with_declaration(Some(target), Vec::new())
                .install(&params(amp(), InstallScope::User))
                .expect("installs");
            std::fs::read_to_string(tree.home().join(".amp/mcp.json")).expect("the document")
        };
        let seconds = installed(json!({
            "path": [".amp", "mcp.json"], "format": "json_command_args", "shared": false,
            "deadline": { "field": "timeout", "unit": "seconds" }
        }));
        let parsed: Value = serde_json::from_str(&seconds).expect("JSON");
        assert_eq!(parsed["mcpServers"]["kalareach"]["timeout"], 660);
        assert_eq!(
            parsed["mcpServers"]["kalareach"]["env"][DEADLINE_VARIABLE],
            "660000"
        );
        let milliseconds = installed(json!({
            "path": [".amp", "mcp.json"], "format": "json_command_args", "shared": false,
            "deadline": { "field": "timeout", "unit": "milliseconds" }
        }));
        let parsed: Value = serde_json::from_str(&milliseconds).expect("JSON");
        assert_eq!(parsed["mcpServers"]["kalareach"]["timeout"], 660_000);
        let none = installed(json!({
            "path": [".amp", "mcp.json"], "format": "json_command_args", "shared": false
        }));
        assert!(
            !none.contains("timeout") && !none.contains(DEADLINE_VARIABLE),
            "{none}"
        );
        let shared = installed(json!({
            "path": [".amp", "mcp.json"], "format": "json_command_args", "shared": true
        }));
        assert!(
            !shared.contains("timeout") && !shared.contains(DEADLINE_VARIABLE),
            "{shared}"
        );
    }

    /// KR-REQ-11.01: status and a removal read the record, so a package that is gone or no longer
    /// declares the word blocks neither; an installation for a place the package no longer declares
    /// is refused by name, and the removal by the record still works.
    #[cfg(unix)]
    #[test]
    fn a_record_for_another_place_is_refused_by_name_and_removed_by_its_record() {
        let tree = Tree::create();
        let document =
            json!({ "path": [".amp", "mcp.json"], "format": "json_command_args", "shared": false });
        let first = declared(Some(document.clone()), &[".amp", "skills"]);
        tree.installer()
            .with_declaration(Some(first), Vec::new())
            .install(&params(amp(), InstallScope::User))
            .expect("installs");

        // No package declares the word any more: status and removal read the record.
        let gone = tree.installer();
        let status = gone
            .status(&params(amp(), InstallScope::User))
            .expect("status");
        assert!(status.installed, "the record answers with no package");

        // The package moved the place: an installation is refused, naming both places.
        let moved = declared(Some(document), &[".amp", "other"]);
        let refused = tree
            .installer()
            .with_declaration(Some(moved), Vec::new())
            .install(&params(amp(), InstallScope::User))
            .expect_err("a moved place is refused");
        let message = refused.to_string();
        assert!(
            message.contains("the record of amp at user scope names")
                && message.contains("and the package now declares")
                && message.contains("run kr skill remove --agent amp --scope user"),
            "{message}"
        );

        let removed = gone.remove(&params(amp(), InstallScope::User));
        assert!(
            removed
                .as_ref()
                .is_ok_and(|removed| !removed.removed.is_empty()),
            "the record is what the removal works from, with no package: {removed:?}"
        );
        assert!(!tree.home().join(".amp/skills").join(SKILL_NAME).exists());
    }

    /// KR-REQ-11.01: a word no package declares is refused with the words the host knows, which
    /// include a word a record holds; a declaration that names a compiled word is never served over
    /// the compiled layout, and two packages that declare one word serve neither.
    #[test]
    fn a_word_is_served_only_by_exactly_one_declaring_package() {
        use declared::{Declaration, Pick, pick};
        let declaration = |word: &str| Declaration {
            target: serde_json::from_value(json!({ "word": word, "user": { "skills": [".x"] } }))
                .expect("a target"),
        };
        let one = [declaration("amp")];
        assert!(matches!(pick("amp", &one), Pick::One(_)));
        assert!(matches!(pick("other", &one), Pick::Nobody));
        let two = [declaration("amp"), declaration("amp")];
        assert!(matches!(pick("amp", &two), Pick::Taken));
        assert_eq!(
            declared::served("amp", &two).expect_err("two packages"),
            "amp is named by more than one package this host admits, so it installs for none of them"
        );
        assert!(
            declared::served("amp", &one)
                .expect("one package")
                .is_some()
        );
        let compiled = [declaration("codex")];
        assert!(matches!(pick("codex", &compiled), Pick::Compiled));
    }

    /// KR-REQ-11.01: a word no package declares is refused with the words the host knows, which
    /// include a word a record holds.
    #[cfg(unix)]
    #[test]
    fn a_word_no_package_declares_is_refused_with_the_words_the_host_knows() {
        let tree = Tree::create();
        let refused = tree
            .installer()
            .with_declaration(None, vec!["amp".to_owned()])
            .install(&params(
                AgentTarget::parse("zed").expect("a word"),
                InstallScope::User,
            ))
            .expect_err("an unknown word");
        assert_eq!(
            refused.to_string(),
            "zed is not an agent this host knows; it knows codex, claude-code, opencode, gemini-cli, \
             kimi-code-cli and qoder-cli, and amp"
        );
    }

    /// KR-REQ-11.01: a word that only a record of this host holds is not called unknown: no
    /// package declares it now, so an installation or a status without a record at that scope says
    /// so, and the list of words the host knows is not shown for it.
    #[cfg(unix)]
    #[test]
    fn a_word_only_a_record_holds_is_refused_as_one_no_package_declares_now() {
        let tree = Tree::create();
        let installer = tree
            .installer()
            .with_declaration(None, vec!["amp".to_owned()]);
        let expected = "no package this host admits declares amp now, so this host cannot install it \
                        at user scope; it can only remove what its own record of amp names";
        let refused = installer
            .install(&params(amp(), InstallScope::User))
            .expect_err("no package declares it");
        assert_eq!(refused.to_string(), expected);
        let told = installer
            .status(&params(amp(), InstallScope::User))
            .expect_err("a status with no record names the same refusal");
        assert_eq!(told.to_string(), expected);
    }

    /// KR-REQ-11.01: a record decides a declared word's removal alone, and a record this host
    /// cannot read is declined as a record, not as a fresh refusal of the request.
    #[cfg(unix)]
    #[test]
    fn a_record_decides_a_declared_removal_and_an_unreadable_one_is_declined_as_a_record() {
        let tree = Tree::create();
        let declaring = tree
            .installer()
            .with_declaration(Some(declared(None, &[".amp", "skills"])), Vec::new());
        let request = params(amp(), InstallScope::User);
        assert!(
            matches!(declaring.removal_by_record(&request), Ok(false)),
            "no record yet"
        );
        declaring.install(&request).expect("installs");
        assert!(
            matches!(declaring.removal_by_record(&request), Ok(true)),
            "a record decides"
        );
        assert!(
            matches!(
                declaring.removal_by_record(&params(AgentTarget::CODEX, InstallScope::User)),
                Ok(false)
            ),
            "a compiled word has no record that decides"
        );
        std::fs::write(declaring.record_path(&request), "not a record").expect("writes");
        let declined = declaring.removal_by_record(&request);
        assert!(
            matches!(declined, Err(Declined::ByARecord(_))),
            "an unreadable record is declined as a record: {declined:?}"
        );
    }

    /// A target for `word` whose user location has a document, as the tests of the agreement of
    /// two words on one document name it.
    #[cfg(unix)]
    fn target_with_document(
        word: &str,
        path: &[&str],
        format: &str,
        shared: bool,
    ) -> kr_plugin_sdk::skill_target::SkillTarget {
        serde_json::from_value(json!({
            "word": word,
            "user": {
                "skills": [format!(".{word}"), "skills"],
                "configuration": { "path": path, "format": format, "shared": shared }
            }
        }))
        .expect("a target")
    }

    /// KR-REQ-11.01 (I6): a declared word is not installed where another admitted word names the same
    /// document in another format or without both declaring it shared, ASCII case ignored, and
    /// nothing is written for it; two words that both declare a document shared in one format agree.
    #[cfg(unix)]
    #[test]
    fn two_words_naming_one_document_agree_on_its_format_and_on_sharing_or_neither_installs() {
        let for_amp = |path: &[&str], format: &str, shared: bool| {
            target_with_document("amp", path, format, shared)
        };
        let for_bmp = |path: &[&str], format: &str, shared: bool| {
            target_with_document("bmp", path, format, shared)
        };
        // What installing amp does where bmp is admitted too: the refusal, if any, the document's
        // text, and whether anything of amp's was written.
        let attempt = |mine: kr_plugin_sdk::skill_target::SkillTarget,
                       other: kr_plugin_sdk::skill_target::SkillTarget| {
            let tree = Tree::create();
            let installer = tree
                .installer()
                .with_declaration(Some(mine.clone()), Vec::new())
                .with_admitted(vec![mine, other]);
            let outcome = installer
                .install(&params(amp(), InstallScope::User))
                .map(|_| ())
                .map_err(|error| error.to_string());
            let document = display(&tree.home().join(".shared").join("mcp.json"));
            (outcome, tree.home().join(".amp").exists(), document)
        };
        let formats = |document: &str| {
            format!(
                "{document} is named by amp and by bmp at user scope in different formats, so \
                 this host will not install amp"
            )
        };
        let sharing = |document: &str| {
            format!(
                "{document} is named by amp and by bmp at user scope, and they do not both \
                 declare it shared, so this host will not install amp"
            )
        };
        let shared = [".shared", "mcp.json"];

        // Another format: refused by name, nothing written.
        let (outcome, written, document) = attempt(
            for_amp(&shared, "json_command_args", true),
            for_bmp(&shared, "json_local_command_list", true),
        );
        assert_eq!(outcome, Err(formats(&document)));
        assert!(!written, "nothing was written for the refused word");

        // The same document spelled in another ASCII case is the same document.
        let (outcome, written, document) = attempt(
            for_amp(&shared, "json_command_args", true),
            for_bmp(&[".shared", "MCP.json"], "json_local_command_list", true),
        );
        assert_eq!(
            outcome,
            Err(formats(&document)),
            "the document's case is ignored"
        );
        assert!(!written);

        // The same format where one does not declare it shared, or neither does.
        for (mine, theirs) in [(false, true), (true, false), (false, false)] {
            let (outcome, written, document) = attempt(
                for_amp(&shared, "json_command_args", mine),
                for_bmp(&shared, "json_command_args", theirs),
            );
            assert_eq!(outcome, Err(sharing(&document)), "{mine} {theirs}");
            assert!(!written);
        }

        // Both declare it shared in one format: they agree and the word installs.
        let (outcome, written, _) = attempt(
            for_amp(&shared, "json_command_args", true),
            for_bmp(&shared, "json_command_args", true),
        );
        assert_eq!(outcome, Ok(()));
        assert!(written);

        // Another document is no disagreement, whatever its format.
        let (outcome, _, _) = attempt(
            for_amp(&shared, "json_command_args", false),
            for_bmp(&[".other", "mcp.json"], "json_local_command_list", false),
        );
        assert_eq!(outcome, Ok(()));
    }

    /// KR-REQ-11.01 (I6): a declared word's document is compared with the compiled layouts too: the
    /// project's `.mcp.json` that Claude Code writes is shared in the command-and-arguments form,
    /// so a declared word names it only in that form and shared.
    #[cfg(unix)]
    #[test]
    fn a_declared_word_naming_a_compiled_document_agrees_with_the_compiled_layout() {
        let project_of = |shared: bool, format: &str| {
            let tree = Tree::create();
            let project = tree.root.join("project");
            std::fs::create_dir_all(&project).expect("a project");
            let target: kr_plugin_sdk::skill_target::SkillTarget = serde_json::from_value(json!({
                "word": "amp",
                "project": {
                    "skills": [".amp", "skills"],
                    "configuration": { "path": [".mcp.json"], "format": format, "shared": shared }
                }
            }))
            .expect("a target");
            tree.installer()
                .with_declaration(Some(target.clone()), Vec::new())
                .with_admitted(vec![target])
                .install(&AgentToolsParams {
                    agent: amp(),
                    scope: InstallScope::Project,
                    project_dir: Nullable::some(display(&project)),
                })
                .map(|_| ())
                .map_err(|error| error.to_string())
        };
        assert_eq!(project_of(true, "json_command_args"), Ok(()));
        let not_shared = project_of(false, "json_command_args");
        assert!(
            not_shared.is_err(),
            "a document that is not shared is refused"
        );
        let sharing = not_shared.err().unwrap_or_default();
        assert!(
            sharing.contains("is named by amp and by claude-code at project scope"),
            "{sharing}"
        );
        assert!(
            sharing.contains("do not both declare it shared"),
            "{sharing}"
        );
        let another = project_of(true, "json_local_command_list");
        assert!(another.is_err(), "another format is refused");
        let formats = another.err().unwrap_or_default();
        assert!(formats.contains("in different formats"), "{formats}");
    }

    /// KR-REQ-11.01 (E15): an installation of a declared word that stopped before its entry was
    /// planned is finished by installing again, with the declaration it had; a declaration that
    /// names a document the finished record never had, and a skills folder that moved, are each a
    /// moved place.
    #[cfg(unix)]
    #[test]
    fn a_declared_installation_that_stopped_before_its_entry_was_planned_is_repaired() {
        let configuration = || {
            Some(
                json!({ "path": [".amp", "mcp.json"], "format": "json_command_args", "shared": false }),
            )
        };
        let tree = Tree::create();
        let installer = tree.installer().with_declaration(
            Some(declared(configuration(), &[".amp", "skills"])),
            Vec::new(),
        );
        let request = params(amp(), InstallScope::User);
        installer.install(&request).expect("installs");

        // Stopped after the files and before the entry was planned: no entry in the record, none
        // in the document, and the installation open.
        let path = installer.record_path(&request);
        let mut record =
            read_record(&std::fs::read_to_string(&path).expect("the record")).expect("reads");
        record.manifest.operations.retain(|operation| {
            !matches!(operation, ChangeOperation::AddConfigurationEntry { .. })
        });
        record.state = InstallationRecord::INSTALLING.to_owned();
        let write = |record: &InstallationRecord| {
            std::fs::write(
                &path,
                serde_json::to_string_pretty(record).expect("encodes"),
            )
            .expect("writes");
        };
        write(&record);
        std::fs::remove_file(tree.home().join(".amp").join("mcp.json")).expect("no document yet");

        // A skills folder that is not the recorded one is a moved place, interrupted or not.
        let elsewhere = tree.installer().with_declaration(
            Some(declared(configuration(), &[".amp", "other"])),
            Vec::new(),
        );
        let moved = elsewhere
            .install(&request)
            .map(|_| ())
            .map_err(|e| e.to_string());
        assert!(
            moved
                .as_ref()
                .is_err_and(|said| said.contains("run kr skill remove --agent amp")),
            "{moved:?}"
        );

        let repaired = installer
            .install(&request)
            .map(|_| ())
            .map_err(|e| e.to_string());
        assert_eq!(repaired, Ok(()), "the interrupted installation is finished");
        let finished = installer
            .recorded(&request)
            .expect("reads")
            .expect("a record");
        assert!(finished.is_complete());
        assert!(
            finished
                .manifest
                .operations
                .iter()
                .any(|operation| matches!(
                    operation,
                    ChangeOperation::AddConfigurationEntry { .. }
                )),
            "the entry is owned"
        );

        // A finished installation that had no entry, under a declaration that now names a document,
        // is not an interruption.
        let tree = Tree::create();
        let without = tree
            .installer()
            .with_declaration(Some(declared(None, &[".amp", "skills"])), Vec::new());
        without
            .install(&request)
            .expect("installs with no document");
        let with = tree.installer().with_declaration(
            Some(declared(configuration(), &[".amp", "skills"])),
            Vec::new(),
        );
        let moved = with
            .install(&request)
            .map(|_| ())
            .map_err(|e| e.to_string());
        assert!(
            moved
                .as_ref()
                .is_err_and(|said| said.contains("run kr skill remove --agent amp")),
            "{moved:?}"
        );
    }

    /// KR-REQ-11.01 (E15): an installation of a declared word that stopped while its entry was
    /// pending is finished by installing again with the declaration it had, and is a moved place
    /// under a declaration that names the entry elsewhere.
    #[cfg(unix)]
    #[test]
    fn a_declared_installation_that_stopped_while_its_entry_was_pending_is_repaired() {
        let configuration = |name: &str| {
            Some(json!({ "path": [".amp", name], "format": "json_command_args", "shared": false }))
        };
        let tree = Tree::create();
        let installer = tree.installer().with_declaration(
            Some(declared(configuration("mcp.json"), &[".amp", "skills"])),
            Vec::new(),
        );
        let request = params(amp(), InstallScope::User);
        installer.install(&request).expect("installs");

        // Stopped after the entry was written and before it was recorded: the note is pending.
        let path = installer.record_path(&request);
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

        let elsewhere = tree.installer().with_declaration(
            Some(declared(configuration("other.json"), &[".amp", "skills"])),
            Vec::new(),
        );
        let moved = elsewhere
            .install(&request)
            .map(|_| ())
            .map_err(|e| e.to_string());
        assert!(
            moved
                .as_ref()
                .is_err_and(|said| said.contains("run kr skill remove --agent amp")),
            "{moved:?}"
        );

        let repaired = installer
            .install(&request)
            .map(|_| ())
            .map_err(|e| e.to_string());
        assert_eq!(repaired, Ok(()), "the pending entry is finished");
        assert!(
            installer
                .recorded(&request)
                .expect("reads")
                .expect("a record")
                .is_complete()
        );
    }

    /// KR-REQ-11.01: a folder that another process makes after the host looked and before it made
    /// it is not the host's: the making says it did not make it, so no record claims it and no
    /// removal takes it. The control is a folder nothing else made.
    #[cfg(unix)]
    #[test]
    fn a_folder_made_between_the_look_and_the_making_is_not_claimed() {
        let tree = Tree::create();
        let walk = anchor::Anchor::open(&tree.home())
            .expect("opens")
            .expect("a root");
        let fs = Fs::Walk(std::sync::Arc::new(walk));
        anchor::make_pause::once(|path| {
            std::fs::create_dir_all(path).expect("another process makes the folder");
        });
        let first = fs.make_directory(&tree.home().join(".amp"));
        assert_eq!(
            first.as_ref().ok(),
            Some(&false),
            "a folder another process made first is not claimed: {first:?}"
        );
        let second = fs.make_directory(&tree.home().join(".bmp"));
        assert_eq!(second.as_ref().ok(), Some(&true), "{second:?}");
    }

    /// KR-REQ-11.01: an entry that another record of this host claims with other contents is not
    /// replaced, though the package that declared the other record's word is gone; nothing is
    /// written, and the document keeps the first installation's entry.
    #[cfg(unix)]
    #[test]
    fn an_entry_another_record_claims_differently_is_not_replaced_when_its_package_is_gone() {
        let tree = Tree::create();
        let document = |deadline: Option<Value>| {
            let mut found = json!({
                "path": [".shared", "mcp.json"], "format": "json_command_args", "shared": false
            });
            if let Some(deadline) = deadline {
                found["deadline"] = deadline;
            }
            found
        };
        tree.installer()
            .with_declaration(
                Some(declared(Some(document(None)), &[".amp", "skills"])),
                Vec::new(),
            )
            .install(&params(amp(), InstallScope::User))
            .expect("the first installs");
        let path = tree.home().join(".shared/mcp.json");
        let before = std::fs::read(&path).expect("the document");
        let mut other = declared(
            Some(document(Some(
                json!({ "field": "timeout", "unit": "seconds" }),
            ))),
            &[".bmp", "skills"],
        );
        other.word = "bmp".to_owned();
        let refused = tree
            .installer()
            .with_declaration(Some(other), Vec::new())
            .install(&params(
                AgentTarget::parse("bmp").expect("a word"),
                InstallScope::User,
            ))
            .expect_err("a different claim is refused");
        let ControllerError::PermissionDenied { detail } = refused else {
            panic!("a refusal by name: {refused}");
        };
        assert!(
            detail.contains("already holds a server named kalareach, written with other contents by another installation this host made"),
            "{detail}"
        );
        assert_eq!(
            std::fs::read(&path).expect("the document"),
            before,
            "the entry is kept"
        );
        assert!(
            !tree.home().join(".bmp").exists(),
            "nothing is written for the second word"
        );
    }

    /// KR-REQ-11.01: the entry is read back and removed by the key the record names, whatever the
    /// document's file name says, in each of the three formats.
    #[cfg(unix)]
    #[test]
    fn an_entry_is_read_back_by_its_recorded_key_whatever_the_file_name() {
        for (format, name) in [
            ("codex_toml", "servers.json"),
            ("json_command_args", "servers.toml"),
            ("json_local_command_list", "servers.toml"),
        ] {
            let tree = Tree::create();
            let target = declared(
                Some(json!({ "path": [".amp", name], "format": format, "shared": false })),
                &[".amp", "skills"],
            );
            let installer = tree.installer().with_declaration(Some(target), Vec::new());
            let request = params(amp(), InstallScope::User);
            let installed = installer.install(&request);
            assert!(
                installed.is_ok(),
                "{format} in {name}: the entry is written and read back by its key: {installed:?}"
            );
            let again = installer.install(&request);
            assert!(
                again.as_ref().is_ok_and(|again| again.already_installed),
                "{format} in {name}: the entry reads back as written: {again:?}"
            );
            let removed = installer.remove(&request);
            assert!(
                removed
                    .as_ref()
                    .is_ok_and(|removed| removed.removed.iter().any(|operation| matches!(
                        operation,
                        ChangeOperation::AddConfigurationEntry { .. }
                    ))),
                "{format} in {name}: the entry is removed by its key: {removed:?}"
            );
        }
    }

    /// KR-REQ-11.01: admissions that moved while the packages were read, or a revision that could
    /// not be read again, refuse the request before the dispatch marker; the same revision passes.
    #[test]
    fn a_changed_admission_revision_refuses_before_the_marker() {
        assert_eq!(declared::admissions_held(7, Some(7), 30), Ok(()));
        assert_eq!(
            declared::admissions_held(7, Some(8), 30),
            Err(
                "the packages this host admits changed while this request was read; ask again"
                    .to_owned()
            )
        );
        assert_eq!(
            declared::admissions_held(7, None, 30),
            Err(
                "this host could not check again within 30 seconds whether the packages it \
                 admits changed while this request was read; ask again"
                    .to_owned()
            ),
            "a read that did not come back is not a change"
        );
    }

    /// KR-REQ-11.01: the last read of the admissions, which comes after every check that reads the
    /// file system, refuses a request whose admissions changed while those checks ran, and a
    /// revision that cannot be read then; the same revision passes; and a word the host compiles in
    /// was read under none, so nothing is read for it.
    #[tokio::test]
    async fn admissions_that_change_during_the_file_system_checks_refuse_the_request() {
        let refusal =
            "the packages this host admits changed while this request was read; ask again"
                .to_owned();
        let unread = "this host could not check again within 30 seconds whether the packages it \
                      admits changed while this request was read; ask again"
            .to_owned();
        let live = std::cell::Cell::new(7_u64);
        let read_at = Some(live.get());
        // The checks that read the file system run, and the admissions change while they do.
        let checks = || live.set(8);
        checks();
        assert_eq!(
            declared::admissions_held_until_registration(read_at, 30, async { Some(live.get()) })
                .await,
            Err(refusal),
            "a revision that moved during the checks"
        );
        live.set(7);
        assert_eq!(
            declared::admissions_held_until_registration(read_at, 30, async { Some(live.get()) })
                .await,
            Ok(()),
            "admissions that stood still"
        );
        assert_eq!(
            declared::admissions_held_until_registration(read_at, 30, async { None }).await,
            Err(unread),
            "a revision that cannot be read in time"
        );
        assert_eq!(
            declared::admissions_held_until_registration(None, 30, async {
                panic!("a word read under no revision asks for none")
            })
            .await,
            Ok(())
        );
    }

    /// KR-REQ-11.01: the host reads the table of an admitted package for a declared word only where
    /// the package's current grants hold the capability: a package admitted without it, or with
    /// other capabilities only, is not read.
    #[test]
    fn a_package_whose_admission_does_not_hold_the_capability_declares_no_target_the_host_resolves()
    {
        let package = |name: &str, grants: &[&str]| -> kr_protocol::admission::AdmittedPackage {
            serde_json::from_value(serde_json::json!({
                "plugin_id": format!("kalareach/{name}"),
                "publisher_id": "kalareach",
                "version": "0.1.0",
                "package_digest": "A".repeat(43),
                "origin": { "repository_id": "official", "enrolment_key": "key" },
                "repository_generation": 1,
                "package_dir": format!("/packages/{name}"),
                "grants": grants,
                "bridge": null,
                "builds": [],
                "component": null
            }))
            .expect("an admitted package")
        };
        let packages = [
            package("holds", &["approval.respond", "skill_target.install"]),
            package("other", &["approval.respond", "native_bridge.install"]),
            package("none", &[]),
            package("also", &["skill_target.install"]),
        ];
        let held = declared::holding_the_capability(&packages);
        assert_eq!(
            held.iter().map(|(dir, _)| dir.as_str()).collect::<Vec<_>>(),
            ["/packages/holds", "/packages/also"]
        );
        assert!(
            held.iter()
                .all(|(_, digest)| *digest == packages[0].package_digest)
        );
        assert!(declared::holding_the_capability(&packages[1..3]).is_empty());
    }

    /// KR-REQ-11.01: a package that now declares another entry key or another entry for the same
    /// place moves the place, so the installation is refused by name and nothing is written.
    #[cfg(unix)]
    #[test]
    fn a_moved_entry_key_or_digest_is_a_moved_place() {
        let tree = Tree::create();
        let document = |format: &str, deadline: Option<Value>| {
            let mut found =
                json!({ "path": [".amp", "mcp.json"], "format": format, "shared": false });
            if let Some(deadline) = deadline {
                found["deadline"] = deadline;
            }
            found
        };
        tree.installer()
            .with_declaration(
                Some(declared(
                    Some(document("json_command_args", None)),
                    &[".amp", "skills"],
                )),
                Vec::new(),
            )
            .install(&params(amp(), InstallScope::User))
            .expect("installs");
        let before = std::fs::read(tree.home().join(".amp/mcp.json")).expect("the document");
        for (moved, shown) in [
            (
                document("json_local_command_list", None),
                [
                    "entry mcpServers.kalareach, and the package now declares ",
                    "entry mcp.kalareach; run kr skill remove",
                ],
            ),
            (
                document(
                    "json_command_args",
                    Some(json!({ "field": "timeout", "unit": "seconds" })),
                ),
                [
                    "entry mcpServers.kalareach, and the package now declares ",
                    ", entry mcpServers.kalareach, with an entry of other contents; run kr skill remove",
                ],
            ),
        ] {
            let refused = tree
                .installer()
                .with_declaration(Some(declared(Some(moved), &[".amp", "skills"])), Vec::new())
                .install(&params(amp(), InstallScope::User))
                .expect_err("a moved entry is refused");
            let message = refused.to_string();
            assert!(
                message.contains("the record of amp at user scope names")
                    && message.contains("run kr skill remove --agent amp --scope user"),
                "{message}"
            );
            for part in shown {
                assert!(message.contains(part), "{part}: {message}");
            }
        }
        assert_eq!(
            std::fs::read(tree.home().join(".amp/mcp.json")).expect("the document"),
            before
        );
    }

    #[cfg(unix)]
    fn project_params(word: AgentTarget, project: &Path) -> AgentToolsParams {
        AgentToolsParams {
            agent: word,
            scope: InstallScope::Project,
            project_dir: Nullable::some(project.display().to_string()),
        }
    }

    /// KR-REQ-11.01: the host refuses a declared word on Windows by name, in a pure function that
    /// takes the platform as a value.
    #[test]
    fn a_declared_word_is_refused_on_windows_by_name_and_not_elsewhere() {
        assert!(declared::platform_refusal(false).is_none());
        assert_eq!(
            declared::platform_refusal(true),
            Some(
                "this host installs the contact skill for an agent that a package names on macOS \
                 and Linux only; on Windows it installs it for codex, claude-code, opencode, \
                 gemini-cli, kimi-code-cli and qoder-cli"
            )
        );
    }

    /// KR-REQ-11.01: a place inside each of the four folders the host keeps for itself is refused
    /// by name, whatever the case of its letters, and nothing is written.
    #[cfg(unix)]
    #[test]
    fn a_declared_place_inside_each_of_the_hosts_own_folders_is_refused() {
        let home = Path::new("/home/someone");
        let records = Path::new("/home/someone/.local/state/kalareach/agent-tools");
        let folders = declared::default_host_folders(home, records);
        for inside in [
            "/home/someone/.local/state/kalareach/x",
            "/home/someone/.cache/kalareach/run",
            "/home/someone/.local/share/kalareach/host/x",
            "/home/someone/.config/kalareach/x",
            "/home/someone/.Config/KalaReach/x",
        ] {
            assert!(
                declared::inside_host_folders(&folders, Path::new(inside)),
                "{inside}"
            );
        }
        for outside in ["/home/someone/.config/other/x", "/home/someone/.amp/skills"] {
            assert!(
                !declared::inside_host_folders(&folders, Path::new(outside)),
                "{outside}"
            );
        }
        for folder in [
            [".local", "state", "kalareach"].as_slice(),
            [".cache", "kalareach", "run"].as_slice(),
            [".local", "share", "kalareach", "host"].as_slice(),
            [".config", "KalaReach"].as_slice(),
        ] {
            let tree = Tree::create();
            let refused = tree
                .installer()
                .with_declaration(Some(declared(None, folder)), Vec::new())
                .install(&params(amp(), InstallScope::User))
                .expect_err("a host folder");
            let ControllerError::PermissionDenied { detail } = refused else {
                panic!("a refusal by name: {refused}");
            };
            assert!(
                detail.contains("is inside a folder this host keeps for its own files, so an installation does not write there"),
                "{folder:?}: {detail}"
            );
            assert!(
                !tree.home().join(folder[0]).exists(),
                "{folder:?}: nothing is written"
            );
        }
    }

    /// KR-REQ-11.01: the folders the host resolved for itself are its own wherever a variable put
    /// them: a place inside its state, runtime, store or configuration folder is refused by name
    /// when the variable that chose it moved the folder from its default, and a place beside it is
    /// not.
    #[cfg(unix)]
    #[test]
    fn a_declared_place_inside_a_host_folder_that_a_variable_moved_is_refused() {
        // The folder each variable chose, under the home folder, and where a package might declare.
        for (variable, inside) in [
            ("XDG_STATE_HOME", [".kr-state", "kalareach"].as_slice()),
            (
                "XDG_RUNTIME_DIR",
                [".kr-run", "kalareach", "sockets"].as_slice(),
            ),
            (
                "XDG_DATA_HOME",
                [".kr-data", "kalareach", "host"].as_slice(),
            ),
            ("XDG_CONFIG_HOME", [".kr-config", "kalareach"].as_slice()),
        ] {
            let tree = Tree::create();
            let home = tree.home();
            let folders = declared::resolved_host_folders(
                &home.join(".kr-state/kalareach"),
                &home.join(".kr-run/kalareach"),
                Some(home.join(".kr-data/kalareach/host")),
                Some(home.join(".kr-config/kalareach")),
            );
            let installer = |place: &[&str]| {
                tree.installer()
                    .with_host_folders(folders.clone())
                    .with_declaration(Some(declared(None, place)), Vec::new())
            };
            let refused = installer(inside).install(&params(amp(), InstallScope::User));
            let Err(ControllerError::PermissionDenied { detail }) = refused else {
                panic!("{variable}: a refusal by name: {refused:?}");
            };
            assert!(
                detail.contains("is inside a folder this host keeps for its own files"),
                "{variable}: {detail}"
            );
            assert!(
                !home.join(inside[0]).exists(),
                "{variable}: nothing is written"
            );
            // The control: a folder beside the host's is the package's to name.
            let beside = [inside[0], "other"];
            let installed = installer(&beside).install(&params(amp(), InstallScope::User));
            assert!(
                installed.is_ok(),
                "{variable}: a place beside it installs: {installed:?}"
            );
        }
    }

    /// KR-REQ-11.01: a selected project root that is a link into one of the host's folders is one
    /// of them, so a place below it is refused although no component of its name says so, and
    /// nothing is written where the link leads.
    #[cfg(unix)]
    #[test]
    fn a_project_root_that_links_into_a_host_folder_is_refused() {
        use std::os::unix::fs::symlink;
        let tree = Tree::create();
        let host_folder = tree.home().join(".kr-state").join("kalareach");
        std::fs::create_dir_all(&host_folder).expect("the host's folder");
        let project = tree.root.join("project");
        symlink(&host_folder, &project).expect("a link");
        let mut target = declared(None, &[".amp", "skills"]);
        target.project = target.user.clone();
        let refused = tree
            .installer()
            .with_host_folders([host_folder.clone()])
            .with_declaration(Some(target), Vec::new())
            .install(&project_params(amp(), &project))
            .expect_err("a root inside a host folder");
        let ControllerError::PermissionDenied { detail } = refused else {
            panic!("a refusal by name: {refused}");
        };
        assert!(
            detail.contains("is inside a folder this host keeps for its own files"),
            "{detail}"
        );
        assert_eq!(
            std::fs::read_dir(&host_folder).expect("the folder").count(),
            0,
            "nothing is written where the link leads"
        );
    }

    /// KR-REQ-11.01: a link at any component of a declared place is refused before the first
    /// write, at either scope and at the last name, and nothing is written where the link leads.
    #[cfg(unix)]
    #[test]
    fn a_declared_place_with_a_link_at_any_component_is_refused_before_the_first_write() {
        use std::os::unix::fs::symlink;
        let document = || json!({ "path": [".amp", "mcp.json"], "format": "json_command_args", "shared": false });
        // The link is at the first component, at the skills folder's own name, and at the document.
        for (link_at, scope) in [
            (".amp", InstallScope::User),
            (".amp/skills", InstallScope::User),
            (".amp/mcp.json", InstallScope::User),
            (".amp", InstallScope::Project),
        ] {
            let tree = Tree::create();
            let elsewhere = tree.root.join("elsewhere");
            std::fs::create_dir_all(&elsewhere).expect("a folder");
            let project = tree.root.join("project");
            std::fs::create_dir_all(&project).expect("a project");
            let base = if scope == InstallScope::User {
                tree.home()
            } else {
                project.clone()
            };
            let link = base.join(link_at);
            if let Some(parent) = link.parent() {
                std::fs::create_dir_all(parent).expect("a parent");
            }
            symlink(&elsewhere, &link).expect("a link");
            let mut target = declared(Some(document()), &[".amp", "skills"]);
            target.project = target.user.clone();
            let installer = tree.installer().with_declaration(Some(target), Vec::new());
            let request = if scope == InstallScope::User {
                params(amp(), scope)
            } else {
                project_params(amp(), &project)
            };
            let refused = installer.install(&request).expect_err("a link is refused");
            assert!(
                matches!(refused, ControllerError::PermissionDenied { .. }),
                "{link_at}: {refused}"
            );
            assert_eq!(
                std::fs::read_dir(&elsewhere).expect("the folder").count(),
                0,
                "{link_at}: nothing is written where the link leads"
            );
            assert!(
                std::fs::read_dir(tree.root.join("state").join("agent-tools"))
                    .map_or(true, |mut records| records.next().is_none()),
                "{link_at}: the refusal comes before any record is written"
            );
        }
    }

    /// KR-REQ-11.01: a write or a removal through the handle follows no link that took a folder's
    /// name after the check, so the check by path is not the only protection.
    #[cfg(unix)]
    #[test]
    fn a_write_through_the_handle_follows_no_link_made_after_the_check() {
        use std::os::unix::fs::symlink;
        let tree = Tree::create();
        let walk = anchor::Anchor::open(&tree.home())
            .expect("opens")
            .expect("a root");
        let fs = Fs::Walk(std::sync::Arc::new(walk));
        let elsewhere = tree.root.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("a folder");
        symlink(&elsewhere, tree.home().join(".amp")).expect("a link");
        let refused = fs
            .write(&tree.home().join(".amp/mcp.json"), b"{}", PRIVATE, None)
            .expect_err("a link is not followed");
        assert!(
            matches!(refused, ControllerError::PermissionDenied { .. }),
            "{refused}"
        );
        assert_eq!(
            std::fs::read_dir(&elsewhere).expect("the folder").count(),
            0
        );
        std::fs::write(elsewhere.join("mcp.json"), b"x").expect("a file");
        fs.remove_file(&tree.home().join(".amp/mcp.json"))
            .expect_err("a link is not followed");
        assert!(
            elsewhere.join("mcp.json").exists(),
            "what the link leads to is left whole"
        );
    }

    /// KR-REQ-11.01: a removal follows no link either: a record whose place was replaced by a link
    /// after the installation is refused by name, and what the link leads to is left whole.
    #[cfg(unix)]
    #[test]
    fn a_removal_follows_no_link_either() {
        use std::os::unix::fs::symlink;
        let tree = Tree::create();
        let target = declared(
            Some(
                json!({ "path": [".amp", "mcp.json"], "format": "json_command_args", "shared": false }),
            ),
            &[".amp", "skills"],
        );
        let installer = tree.installer().with_declaration(Some(target), Vec::new());
        installer
            .install(&params(amp(), InstallScope::User))
            .expect("installs");
        let moved = tree.home().join(".amp-moved");
        std::fs::rename(tree.home().join(".amp"), &moved).expect("moves the folder");
        symlink(&moved, tree.home().join(".amp")).expect("a link");
        let refused = installer
            .remove(&params(amp(), InstallScope::User))
            .expect_err("a link is refused");
        assert!(
            matches!(refused, ControllerError::PermissionDenied { .. }),
            "{refused}"
        );
        assert!(
            moved
                .join("skills")
                .join(SKILL_NAME)
                .join("SKILL.md")
                .exists(),
            "what the link leads to is left whole"
        );
    }

    /// KR-REQ-11.01: the root a walk holds is the folder it opened, whatever its name leads to
    /// afterwards. A root moved away and replaced by a link is not followed for a place directly in
    /// it any more than for one below it: a read, a write and a removal all reach the folder that was
    /// opened, and what the link leads to is left whole.
    #[cfg(unix)]
    #[test]
    fn a_root_replaced_by_a_link_after_the_walk_opened_it_is_not_followed() {
        use std::os::unix::fs::symlink;
        let tree = Tree::create();
        let walk = anchor::Anchor::open(&tree.home())
            .expect("opens")
            .expect("a root");
        let fs = Fs::Walk(std::sync::Arc::new(walk));
        let moved = tree.root.join("home-moved");
        std::fs::rename(tree.home(), &moved).expect("moves the root");
        let elsewhere = tree.root.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("a folder");
        symlink(&elsewhere, tree.home()).expect("a link");
        std::fs::write(moved.join(".mcp.json"), b"held").expect("a file");
        std::fs::write(elsewhere.join(".mcp.json"), b"linked").expect("a file");
        let document = tree.home().join(".mcp.json");

        assert_eq!(
            fs.read_text(&document).expect("reads").as_deref(),
            Some("held"),
            "a read comes from the folder the walk holds"
        );
        fs.write(&document, b"{}", PRIVATE, Some(digest_of(b"held")))
            .expect("writes into the folder the walk holds");
        assert_eq!(
            std::fs::read(moved.join(".mcp.json")).expect("a file"),
            b"{}"
        );
        assert_eq!(
            std::fs::read(elsewhere.join(".mcp.json")).expect("a file"),
            b"linked",
            "what the link leads to is not written"
        );
        fs.write(&tree.home().join(".new.json"), b"{}", PRIVATE, None)
            .expect("a new file is made in the folder the walk holds");
        assert!(moved.join(".new.json").exists());
        assert!(
            !elsewhere.join(".new.json").exists(),
            "and not where the link leads"
        );
        fs.remove_file(&document)
            .expect("removes from the folder the walk holds");
        assert!(!moved.join(".mcp.json").exists());
        assert!(
            elsewhere.join(".mcp.json").exists(),
            "what the link leads to is left whole"
        );
    }

    /// KR-REQ-11.01: a root that was not there when a request began is followed by no path once
    /// something takes its name: a read or a removal below it finds nothing and touches nothing, and
    /// a write is refused.
    #[cfg(unix)]
    #[test]
    fn a_root_that_was_not_there_is_reached_by_no_path_once_something_takes_its_name() {
        use std::os::unix::fs::symlink;
        let tree = Tree::create();
        let project = tree.root.join("project");
        let target = declared(
            Some(
                json!({ "path": [".amp", "mcp.json"], "format": "json_command_args", "shared": false }),
            ),
            &[".amp", "skills"],
        );
        let installer = tree.installer().with_declaration(Some(target), Vec::new());
        let request = project_params(amp(), &project);
        installer
            .on_handle(&request, true)
            .expect_err("a write below a root that is not there is refused");
        let reading = installer
            .on_handle(&request, false)
            .expect("a read of a root that is not there");

        let elsewhere = tree.root.join("elsewhere");
        std::fs::create_dir_all(elsewhere.join(".amp")).expect("a folder");
        std::fs::write(elsewhere.join(".amp/mcp.json"), b"{}").expect("a file");
        symlink(&elsewhere, &project).expect("a link");
        let place = project.join(".amp/mcp.json");
        assert_eq!(reading.fs.read_text(&place).expect("reads"), None);
        assert_eq!(reading.fs.read_digest(&place).expect("reads"), None);
        assert!(!reading.fs.exists(&place).expect("looks"));
        assert!(
            !reading
                .fs
                .is_directory(&place.with_file_name("skills"))
                .expect("looks")
        );
        reading
            .fs
            .remove_file(&place)
            .expect("a name below a root that is not there is already gone");
        assert!(
            elsewhere.join(".amp/mcp.json").exists(),
            "what the link leads to is left whole"
        );
        reading
            .fs
            .write(&place, b"x", PRIVATE, None)
            .expect_err("nothing is written below a root that was not there");
        assert_eq!(
            std::fs::read(elsewhere.join(".amp/mcp.json")).expect("a file"),
            b"{}"
        );
    }

    /// KR-REQ-11.01: a file is published only over the one the caller checked. Where nothing stood
    /// it is published only if the name is still free, so a file another process made between the
    /// check and the publication is left as it is; where a file stood, only a file whose contents
    /// are still the checked ones is replaced.
    #[cfg(unix)]
    #[test]
    fn a_publication_replaces_only_the_file_that_was_checked() {
        let tree = Tree::create();
        let walk = anchor::Anchor::open(&tree.home())
            .expect("opens")
            .expect("a root");
        let place = tree.home().join("doc.json");
        let others = |expected: &str, what: &str| {
            assert_eq!(
                std::fs::read_to_string(&place).expect("a file"),
                expected,
                "{what}"
            );
            let left: Vec<String> = std::fs::read_dir(tree.home())
                .expect("the folder")
                .map(|entry| {
                    entry
                        .expect("an entry")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();
            assert_eq!(left, ["doc.json"], "{what}: no temporary file is left");
        };
        let refusal = |result: Result<()>, what: &str| {
            let refused = result.expect_err(what);
            assert!(
                matches!(&refused, ControllerError::PermissionDenied { detail }
                    if detail.contains("replaces only the file it checked")),
                "{what}: {refused}"
            );
        };

        // Nothing stood, and nothing is there: published, as a new file.
        walk.write(&place, b"one", 0o600, None).expect("a new file");
        others("one", "a new file");

        // Nothing stood, but a file is there: left as it is.
        refusal(
            walk.write(&place, b"two", 0o600, None),
            "a file where none stood",
        );
        others("one", "a file where none stood");

        // Nothing stood at the check, and a file is made before the publication.
        std::fs::remove_file(&place).expect("removes");
        let unowned = place.clone();
        anchor::publish_pause::once(move |_| {
            std::fs::write(&unowned, b"theirs").expect("another process writes it");
        });
        refusal(
            walk.write(&place, b"two", 0o600, None),
            "a file made between the check and the publication",
        );
        others(
            "theirs",
            "a file made between the check and the publication",
        );

        // A file stood, and its contents are the checked ones: replaced, keeping its mode.
        walk.write(&place, b"three", 0o600, Some(digest_of(b"theirs")))
            .expect("the checked file is replaced");
        others("three", "the checked file");

        // A file stood, and other contents are there at the check.
        refusal(
            walk.write(&place, b"four", 0o600, Some(digest_of(b"theirs"))),
            "other contents than the checked ones",
        );
        others("three", "other contents than the checked ones");

        // A file stood, and its contents change before the publication.
        let changed = place.clone();
        anchor::publish_pause::once(move |_| {
            std::fs::write(&changed, b"theirs again").expect("another process writes it");
        });
        refusal(
            walk.write(&place, b"four", 0o600, Some(digest_of(b"three"))),
            "contents changed between the check and the publication",
        );
        others(
            "theirs again",
            "contents changed between the check and the publication",
        );

        // A file stood, and it is gone before the publication.
        let gone = place.clone();
        anchor::publish_pause::once(move |_| {
            std::fs::remove_file(&gone).expect("another process removes it");
        });
        refusal(
            walk.write(&place, b"five", 0o600, Some(digest_of(b"theirs again"))),
            "a file removed between the check and the publication",
        );
        assert!(
            !place.exists(),
            "nothing is made where the checked file was"
        );
    }

    /// KR-REQ-11.01: an installation for a declared word does not replace a file another process
    /// made at one of its names between the check and the publication.
    #[cfg(unix)]
    #[test]
    fn an_installation_does_not_replace_a_file_made_between_its_check_and_its_publication() {
        let tree = Tree::create();
        let target = declared(
            Some(
                json!({ "path": [".amp", "mcp.json"], "format": "json_command_args", "shared": false }),
            ),
            &[".amp", "skills"],
        );
        let installer = tree.installer().with_declaration(Some(target), Vec::new());
        let made = std::rc::Rc::new(std::cell::RefCell::new(None::<PathBuf>));
        let writing = std::rc::Rc::clone(&made);
        anchor::publish_pause::once(move |path| {
            std::fs::write(path, b"not written by this host").expect("another process writes it");
            *writing.borrow_mut() = Some(path.to_path_buf());
        });
        let refused = installer
            .install(&params(amp(), InstallScope::User))
            .expect_err("a file that was not there at the check is not replaced");
        assert!(
            matches!(refused, ControllerError::PermissionDenied { .. }),
            "{refused}"
        );
        let made = made.borrow().clone().expect("a file was made");
        assert_eq!(
            std::fs::read(&made).expect("the file"),
            b"not written by this host",
            "{}",
            made.display()
        );
    }

    /// KR-REQ-11.01: a file another process makes at one of a declared word's names while the
    /// installation makes its folders is kept. The check found the name free, and what the check
    /// found is what the publication is held to, so no later read of the name stands in for it.
    #[cfg(unix)]
    #[test]
    fn an_installation_does_not_replace_a_file_made_while_it_makes_its_folders() {
        let tree = Tree::create();
        let target = declared(
            Some(
                json!({ "path": [".amp", "mcp.json"], "format": "json_command_args", "shared": false }),
            ),
            &[".amp", "skills"],
        );
        let installer = tree.installer().with_declaration(Some(target), Vec::new());
        let theirs = tree.home().join(".amp/skills/kalareach-contact/SKILL.md");
        let made = theirs.clone();
        anchor::make_pause::once(move |_| {
            std::fs::create_dir_all(made.parent().expect("a folder")).expect("the folder");
            std::fs::write(&made, b"not written by this host").expect("another process writes it");
        });
        let refused = installer
            .install(&params(amp(), InstallScope::User))
            .expect_err("a file that was not there at the check is not replaced");
        assert!(
            matches!(refused, ControllerError::PermissionDenied { .. }),
            "{refused}"
        );
        assert_eq!(
            std::fs::read(&theirs).expect("the file"),
            b"not written by this host",
            "the file another process made is kept"
        );
        assert!(
            !tree.home().join(".amp/mcp.json").exists(),
            "nothing else is written"
        );
    }

    /// KR-REQ-11.01: a file that stood at the check is replaced only if the file at its place when
    /// the two change places is the checked one. Whatever another process put there after the last
    /// read, a file under the same name, a link or a folder, is at its place again afterwards, the
    /// publication is refused, and no temporary file is left.
    #[cfg(unix)]
    #[test]
    fn a_replacement_put_in_the_place_after_the_last_read_is_kept() {
        use std::os::unix::fs::symlink;

        for kind in ["a file", "a link", "a folder"] {
            let tree = Tree::create();
            let walk = anchor::Anchor::open(&tree.home())
                .expect("opens")
                .expect("a root");
            let place = tree.home().join("doc.json");
            walk.write(&place, b"one", 0o600, None).expect("a new file");
            let (other, home) = (tree.home().join("elsewhere.json"), tree.home());
            let at = place.clone();
            let elsewhere = other.clone();
            anchor::publish_pause::once(move |_| {
                std::fs::remove_file(&at).expect("another process removes the file");
                match kind {
                    "a file" => {
                        std::fs::write(&elsewhere, b"theirs").expect("a file");
                        std::fs::rename(&elsewhere, &at).expect("put in its place");
                    }
                    "a link" => symlink(&elsewhere, &at).expect("a link"),
                    _ => std::fs::create_dir(&at).expect("a folder"),
                }
            });
            let refused = walk
                .write(&place, b"two", 0o600, Some(digest_of(b"one")))
                .expect_err(kind);
            assert!(
                matches!(&refused, ControllerError::PermissionDenied { detail }
                    if detail.contains("replaces only the file it checked")),
                "{kind}: {refused}"
            );
            match kind {
                "a file" => assert_eq!(std::fs::read(&place).expect("a file"), b"theirs", "{kind}"),
                "a link" => {
                    assert_eq!(std::fs::read_link(&place).expect("a link"), other, "{kind}")
                }
                _ => assert!(place.is_dir(), "{kind}: the folder is at its place"),
            }
            let mut left: Vec<String> = std::fs::read_dir(&home)
                .expect("the folder")
                .map(|entry| {
                    entry
                        .expect("an entry")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();
            left.sort();
            assert_eq!(left, ["doc.json"], "{kind}: nothing else is left");
        }
    }

    /// KR-REQ-11.01: a file where a folder is needed and a folder where a file is to be written
    /// stop the installation before anything is written, by the walk's approved words.
    #[cfg(unix)]
    #[test]
    fn a_file_and_a_directory_in_conflict_stop_the_installation_before_anything_is_written() {
        let document = || json!({ "path": [".amp", "mcp.json"], "format": "json_command_args", "shared": false });
        let target = || declared(Some(document()), &[".amp", "skills"]);
        // A file where the first folder goes.
        let tree = Tree::create();
        std::fs::write(tree.home().join(".amp"), b"a file").expect("a file");
        let refused = tree
            .installer()
            .with_declaration(Some(target()), Vec::new())
            .install(&params(amp(), InstallScope::User))
            .expect_err("a file where a folder goes");
        let ControllerError::PermissionDenied { detail } = refused else {
            panic!("a refusal by name: {refused}");
        };
        assert!(
            detail.contains("is a link or a file, and an installation follows no link and writes nothing below a file"),
            "{detail}"
        );
        // A folder where the document goes.
        let tree = Tree::create();
        std::fs::create_dir_all(tree.home().join(".amp/mcp.json")).expect("a folder");
        let refused = tree
            .installer()
            .with_declaration(Some(target()), Vec::new())
            .install(&params(amp(), InstallScope::User))
            .expect_err("a folder where a file goes");
        let ControllerError::PermissionDenied { detail } = refused else {
            panic!("a refusal by name: {refused}");
        };
        assert!(
            detail.contains("is not a regular file an installation can replace"),
            "{detail}"
        );
        assert!(
            !tree.home().join(".amp/skills").exists(),
            "nothing is written"
        );
    }

    /// KR-REQ-11.01: two spellings of one document that differ only in ASCII case are one document
    /// for the claims of the records, so a second installation does not replace the first's entry
    /// through the other spelling.
    #[cfg(unix)]
    #[test]
    fn a_document_spelled_in_another_case_is_the_same_document_for_the_claims() {
        let tree = Tree::create();
        let document = |path: [&str; 2], deadline: Option<Value>| {
            let mut found = json!({ "path": path, "format": "json_command_args", "shared": false });
            if let Some(deadline) = deadline {
                found["deadline"] = deadline;
            }
            found
        };
        tree.installer()
            .with_declaration(
                Some(declared(
                    Some(document([".shared", "mcp.json"], None)),
                    &[".amp", "skills"],
                )),
                Vec::new(),
            )
            .install(&params(amp(), InstallScope::User))
            .expect("the first installs");
        let first_document = tree.home().join(".shared").join("mcp.json");
        let before = std::fs::read(&first_document).expect("the first entry");
        let mut other = declared(
            Some(document(
                [".Shared", "MCP.json"],
                Some(json!({ "field": "timeout", "unit": "seconds" })),
            )),
            &[".bmp", "skills"],
        );
        other.word = "bmp".to_owned();
        let refused = tree
            .installer()
            .with_declaration(Some(other), Vec::new())
            .install(&params(
                AgentTarget::parse("bmp").expect("a word"),
                InstallScope::User,
            ))
            .expect_err("the same document under another spelling");
        // The refusal is the claim the first record holds on the document, whatever the file system
        // does with the spelling: no other refusal stands for it.
        match refused {
            ControllerError::PermissionDenied { detail } => assert_eq!(
                detail,
                CLAIMED_DIFFERENTLY.replace(
                    "{path}",
                    &display(&tree.home().join(".Shared").join("MCP.json"))
                )
            ),
            other => panic!("the claim on the document refuses: {other}"),
        }
        assert!(
            !tree.home().join(".bmp").exists(),
            "nothing was written for the refused word"
        );
        assert_eq!(
            std::fs::read(&first_document).expect("the first entry"),
            before,
            "the first entry is as it was"
        );
    }

    /// A retained installation action names the format it is written in, and one of a later format
    /// is refused rather than answered from.
    #[test]
    fn a_retained_action_names_its_format_and_a_later_one_is_refused() {
        let tree = Tree::create();
        let installer = tree.installer();
        let actor = kr_protocol::ids::ActorId::new("local:owner").expect("a principal");
        let action = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
        let digest = Digest256::from_bytes([7; 32]);
        installer
            .mark_dispatching(&actor, action, &digest)
            .expect("marks");
        let path = installer.action_path(&actor, action);
        let read = |path: &Path| -> Value {
            serde_json::from_slice(&std::fs::read(path).expect("the record")).expect("JSON")
        };
        assert_eq!(
            read(&path)["version"],
            1,
            "a dispatching marker names no word"
        );

        // A record written before the format was recorded is written again, stamped, when it is
        // read for an answer.
        let mut older = read(&path);
        older.as_object_mut().expect("an object").remove("version");
        std::fs::write(&path, older.to_string()).expect("rewritten");
        let answered = installer
            .retained(&actor, action, &digest)
            .copied()
            .into_answer_for_test()
            .expect_err("a marker with no outcome is uncertain");
        assert!(matches!(answered, ControllerError::Uncertain { .. }));
        assert_eq!(
            read(&path)["version"],
            1,
            "a replay stamps the version of a record that had none"
        );

        let mut later = read(&path);
        later["version"] = serde_json::json!(ACTION_RECORD_VERSION + 1);
        std::fs::write(&path, later.to_string()).expect("rewritten");
        assert!(
            matches!(
                installer
                    .retained(&actor, action, &digest)
                    .copied()
                    .into_answer_for_test(),
                Err(ControllerError::InvalidArgument(_))
            ),
            "a record of a later format is refused"
        );
    }

    /// A directory that hands out access is not a place to replace a file.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_document_in_a_directory_that_grants_access_is_not_replaced() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::CODEX, InstallScope::User);
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

    #[test]
    fn an_unaccounted_change_keeps_an_installation_open() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::CLAUDE_CODE, InstallScope::User);
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
        let params = params(AgentTarget::CLAUDE_CODE, InstallScope::User);
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
        let params = params(AgentTarget::CODEX, InstallScope::User);
        installer.install(&params).expect("installs");
        let document = tree.home().join(".codex/config.toml");
        // Declared after the tree, so it is dropped first however the test ends: a document this
        // account may not delete would keep the tree it is in from ever being removed.
        let restriction = Restriction(document.clone());
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

        // With the restriction lifted, the tree goes as every other test's does.
        let root = tree.root.clone();
        drop(restriction);
        drop(tree);
        assert!(
            !root.exists(),
            "the tree the restricted document was in is removed: {}",
            root.display()
        );
    }

    /// Runs one of this platform's own tools on a file this test made, and fails the test when it
    /// fails.
    #[cfg(windows)]
    fn run(program: &str, arguments: &[&std::ffi::OsStr]) {
        let output = std::process::Command::new(program)
            .args(arguments)
            .output()
            .unwrap_or_else(|error| panic!("{program} starts: {error}"));
        assert!(
            output.status.success(),
            "{program} failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Who can reach a file, as the installer reads it.
    #[cfg(windows)]
    fn access_of(path: &Path) -> kr_ipc::paths::FileAccess {
        kr_ipc::paths::FileAccess::of(path)
            .unwrap_or_else(|refusal| panic!("{} is read: {refusal:?}", path.display()))
    }

    /// KR-REQ-11.50: on Windows a configuration with an entry set on it is not replaced: an
    /// installation and a removal both refuse before anything is written, and the document keeps
    /// its bytes and who can read it.
    #[cfg(windows)]
    #[test]
    fn a_configuration_with_an_entry_set_on_it_is_refused_before_anything_is_written() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::CODEX, InstallScope::User);
        installer.install(&params).expect("installs");
        let document = tree.home().join(".codex/config.toml");
        run(
            "icacls.exe",
            &[
                document.as_os_str(),
                "/grant".as_ref(),
                "*S-1-1-0:(R)".as_ref(),
            ],
        );
        let bytes = std::fs::read(&document).expect("the document");
        let access = access_of(&document);
        let before = files_under(&tree.root);

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
        assert_eq!(
            files_under(&tree.root),
            before,
            "nothing was written or taken"
        );
        assert_eq!(std::fs::read(&document).expect("the document"), bytes);
        assert_eq!(access_of(&document), access);
    }

    /// KR-REQ-11.50: on Windows a configuration its directory made is replaced by one that reads
    /// back the same owner and lists, by an installation and again by a removal.
    #[cfg(windows)]
    #[test]
    fn a_configuration_its_directory_made_is_replaced_with_the_same_access() {
        let tree = Tree::create();
        let document = tree.home().join(".claude.json");
        std::fs::write(&document, r#"{"theme":"dark"}"#).expect("writes the configuration");
        let before = access_of(&document);
        let installer = tree.installer();
        let params = params(AgentTarget::CLAUDE_CODE, InstallScope::User);

        installer.install(&params).expect("installs");
        let written = std::fs::read_to_string(&document).expect("the document");
        assert!(written.contains(SERVER_NAME), "{written}");
        assert_eq!(
            access_of(&document),
            before,
            "the installation kept who can read it"
        );

        installer.remove(&params).expect("removes");
        let written = std::fs::read_to_string(&document).expect("the document");
        assert!(!written.contains(SERVER_NAME), "{written}");
        assert_eq!(access_of(&document), before, "and so did the removal");
    }

    /// On Windows a configuration moved in from a directory that gives its files more than this
    /// one does records nothing set on it, so it passes the check before the change; the write
    /// compares the copy it made with it, refuses, and leaves the document's bytes and access as
    /// they were. The installation that stopped there is reported as unfinished.
    #[cfg(windows)]
    #[test]
    fn a_configuration_moved_in_from_elsewhere_is_refused_where_it_would_be_replaced() {
        let tree = Tree::create();
        let elsewhere = tree.root.join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("another directory");
        run(
            "icacls.exe",
            &[
                elsewhere.as_os_str(),
                "/grant".as_ref(),
                "*S-1-1-0:(OI)(R)".as_ref(),
            ],
        );
        let made = elsewhere.join("settings.json");
        std::fs::write(&made, r#"{"theme":"dark"}"#).expect("writes the configuration");
        let document = tree.home().join(".claude.json");
        std::fs::rename(&made, &document).expect("moves it in, with what it was given there");
        let bytes = std::fs::read(&document).expect("the document");
        let access = access_of(&document);
        let installer = tree.installer();
        let params = params(AgentTarget::CLAUDE_CODE, InstallScope::User);

        installer
            .check(&params)
            .expect("nothing it records is set on it");
        let refused = installer
            .install(&params)
            .expect_err("refused where the copy would replace it");
        assert!(
            matches!(refused, ControllerError::PermissionDenied { ref detail }
                if detail.contains("another owner or access-control list")),
            "{refused:?}"
        );
        let refused = write_atomically(&document, b"anything", PRIVATE).expect_err("refuses");
        assert!(
            matches!(refused, ControllerError::PermissionDenied { .. }),
            "{refused:?}"
        );
        assert_eq!(std::fs::read(&document).expect("the document"), bytes);
        assert_eq!(access_of(&document), access);
        assert!(
            !installer.status(&params).expect("reads").installed,
            "the installation did not finish"
        );
    }

    /// On Windows an encrypted configuration is refused before anything is written: who can read
    /// it depends on keys, which a copy written beside it would not carry.
    #[cfg(windows)]
    #[test]
    fn an_encrypted_configuration_is_refused_before_anything_is_written() {
        let tree = Tree::create();
        let document = tree.home().join(".claude.json");
        std::fs::write(&document, "{}").expect("writes the configuration");
        run(
            "cipher.exe",
            &["/e".as_ref(), "/a".as_ref(), document.as_os_str()],
        );
        let before = files_under(&tree.root);
        let refused = tree
            .installer()
            .install(&params(AgentTarget::CLAUDE_CODE, InstallScope::User))
            .expect_err("refuses");
        assert!(
            matches!(refused, ControllerError::PermissionDenied { ref detail }
                if detail.contains("encrypted") && detail.ends_with(CONFIGURATION_BY_HAND)),
            "{refused:?}"
        );
        assert_eq!(files_under(&tree.root), before, "nothing was written");
    }

    /// The access-control list a test put on a document, taken off again when this is dropped.
    #[cfg(target_os = "macos")]
    struct Restriction(PathBuf);

    #[cfg(target_os = "macos")]
    impl Drop for Restriction {
        fn drop(&mut self) {
            // An empty list leaves the document with its mode bits alone.
            let _ = exacl::setfacl(&[&self.0], &[], None);
        }
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
        let params = params(AgentTarget::CODEX, InstallScope::User);
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
        let params = params(AgentTarget::CODEX, InstallScope::User);
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
            "version": INSTALLATION_RECORD_VERSION + 1,
            "state": "installed",
            "manifest": manifest_value(),
            "pending": [],
        })
        .to_string();

        let error = read_record(&text).expect_err("refuses");

        assert!(
            error.contains(&format!("version {}", INSTALLATION_RECORD_VERSION + 1)),
            "{error}"
        );
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
        let params = params(AgentTarget::CLAUDE_CODE, InstallScope::User);
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
            agent: AgentTarget::CODEX,
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
            agent: AgentTarget::CODEX,
            scope: InstallScope::User,
            project_dir: Nullable::some("/somewhere".to_owned()),
        };
        assert_eq!(
            installer.record_path(&named),
            installer.record_path(&params(AgentTarget::CODEX, InstallScope::User))
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
            .install(&with_project(AgentTarget::CLAUDE_CODE))
            .expect("installs");
        installer
            .install(&with_project(AgentTarget::QODER_CLI))
            .expect("installs");
        // Somebody's record is now unreadable. It still claims the shared entry, and a removal
        // that treated it as absent would take a server that installation is using.
        std::fs::write(
            installer.record_path(&with_project(AgentTarget::QODER_CLI)),
            "not a record",
        )
        .expect("writes");
        let error = installer
            .remove(&with_project(AgentTarget::CLAUDE_CODE))
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
            let params = params(agent.clone(), InstallScope::User);
            let layout = installer.layout(&params).expect("a layout");
            let Some(configuration) = layout.configuration.as_ref() else {
                continue;
            };
            let planned = installer.planned_entry_digest(configuration);
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
            .install(&params(AgentTarget::CODEX, InstallScope::User))
            .expect("an earlier installation");
        let before = files_under(&tree.root);
        let error = tree
            .installer()
            .install(&params(AgentTarget::CLAUDE_CODE, InstallScope::Project))
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
                .install(&params(agent.clone(), InstallScope::User))
                .unwrap_or_else(|error| panic!("{agent} installs: {error}"));
            let status = installer
                .status(&params(agent.clone(), InstallScope::User))
                .expect("reads");
            assert!(status.installed, "{agent} is installed");
            assert!(status.drift.is_empty(), "{agent} has no drift");
        }
    }

    /// KR-REQ-11.50: a configuration document that names a member twice, at its root and inside
    /// its servers, is refused before anything is written, naming the member and the document,
    /// and the document keeps every byte. Which of the two a reader keeps is the reader's choice,
    /// so a rewrite would keep one of the person's settings and lose the other.
    #[test]
    fn a_document_that_names_a_member_twice_is_refused_before_anything_is_written() {
        let tree = Tree::create();
        let installer = tree.installer();
        let document = tree.home().join(".claude.json");
        let text = "{\"theme\": \"dark\", \"theme\": \"light\", \"mcpServers\": {\"theirs\": \
                    {\"command\": \"a\"}, \"theirs\": {\"command\": \"b\"}}}\n";
        std::fs::write(&document, text).expect("writes");
        let before = files_under(&tree.root);
        let refused = match installer.install(&params(AgentTarget::CLAUDE_CODE, InstallScope::User))
        {
            Ok(_) => panic!(
                "installed, and the document is now {:?}",
                std::fs::read_to_string(&document).expect("reads")
            ),
            Err(refused) => refused,
        };
        let said = refused.to_string();
        assert!(
            said.contains("\"theme\"") && said.contains(&display(&document)),
            "names the member and the document: {said}"
        );
        assert_eq!(
            std::fs::read_to_string(&document).expect("reads"),
            text,
            "the document keeps every byte"
        );
        assert_eq!(files_under(&tree.root), before, "nothing is written");
    }

    /// KR-REQ-11.50: a removal whose document came to name a member twice after the installation
    /// is refused before anything is removed, so the agent is not left with an entry for a skill
    /// that is gone, and the document keeps every byte.
    #[test]
    fn a_removal_is_refused_before_anything_is_removed_when_its_document_names_a_member_twice() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::CLAUDE_CODE, InstallScope::User);
        installer.install(&params).expect("installs");
        let document = tree.home().join(".claude.json");
        let installed = std::fs::read_to_string(&document).expect("reads");
        let repeated = installed.replacen('{', "{\"theme\": \"dark\", \"theme\": \"light\", ", 1);
        std::fs::write(&document, &repeated).expect("writes");
        let before = files_under(&tree.root);
        let refused = installer.remove(&params).expect_err("refuses");
        assert!(
            refused.to_string().contains("\"theme\""),
            "names the member: {refused}"
        );
        assert_eq!(files_under(&tree.root), before, "nothing is removed");
    }

    /// KR-REQ-11.50, the control: a document in the person's own layout, indented with tabs and
    /// its members in their own order, keeps every byte of it through an installation, and is
    /// byte for byte what it was after the removal. Where it had no server container, the one the
    /// installation added stays behind, empty, and nothing else changes.
    #[test]
    fn a_document_in_the_persons_own_layout_survives_an_installation_and_its_removal() {
        for (original, removed) in [
            (
                "{\n\t\"theme\": \"dark\",\n\t\"mcpServers\": {\n\t\t\"theirs\": {\"command\": \
                 \"their-server\"}\n\t},\n\t\"autoUpdates\": false\n}\n",
                None,
            ),
            (
                "{\n\t\"theme\": \"dark\",\n\t\"autoUpdates\": false\n}\n",
                Some(
                    "{\n\t\"theme\": \"dark\",\n\t\"autoUpdates\": false,\n\t\"mcpServers\": {}\n}\n",
                ),
            ),
        ] {
            let tree = Tree::create();
            let installer = tree.installer();
            let params = params(AgentTarget::CLAUDE_CODE, InstallScope::User);
            let document = tree.home().join(".claude.json");
            std::fs::write(&document, original).expect("writes");
            installer.install(&params).expect("installs");
            let installed = std::fs::read_to_string(&document).expect("reads");
            for line in original.lines() {
                assert!(
                    installed.contains(line),
                    "{line:?} is still there: {installed}"
                );
            }
            let written: Value = serde_json::from_str(&installed).expect("json");
            assert_eq!(
                written["mcpServers"]["kalareach"],
                installer.entry_value(
                    Format::JsonCommandArgs,
                    compiled_deadline(CompiledAgent::ClaudeCode).as_ref()
                )
            );
            installer.remove(&params).expect("removes");
            assert_eq!(
                std::fs::read_to_string(&document).expect("reads"),
                removed.unwrap_or(original),
                "the document is byte for byte what it was, and an added container stays empty"
            );
        }
    }

    /// KR-REQ-11.50: a project's `.mcp.json` two installations share, in either removal order. The
    /// entry goes only with the last of them. A document this host created goes with it when the
    /// installation that created it is the last one removed; otherwise, as with a document that was
    /// somebody's to begin with, the server container stays behind, empty, and the person's own
    /// settings are byte for byte what they were.
    #[test]
    fn a_shared_document_ends_the_same_in_either_removal_order() {
        let with_project = |project: &Path, agent| AgentToolsParams {
            agent,
            scope: InstallScope::Project,
            project_dir: Nullable::some(display(project)),
        };
        for (original, first, last, expected) in [
            (
                Some("{\n  \"theirs\": true\n}\n"),
                AgentTarget::CLAUDE_CODE,
                AgentTarget::QODER_CLI,
                Some("{\n  \"theirs\": true,\n  \"mcpServers\": {}\n}\n"),
            ),
            (
                Some("{\n  \"theirs\": true\n}\n"),
                AgentTarget::QODER_CLI,
                AgentTarget::CLAUDE_CODE,
                Some("{\n  \"theirs\": true,\n  \"mcpServers\": {}\n}\n"),
            ),
            (None, AgentTarget::QODER_CLI, AgentTarget::CLAUDE_CODE, None),
            (
                None,
                AgentTarget::CLAUDE_CODE,
                AgentTarget::QODER_CLI,
                Some("{\n  \"mcpServers\": {\n  }\n}\n"),
            ),
        ] {
            let tree = Tree::create();
            let installer = tree.installer();
            let project = tree.root.join("project");
            std::fs::create_dir_all(&project).expect("a project");
            let shared = project.join(".mcp.json");
            if let Some(original) = original {
                std::fs::write(&shared, original).expect("writes");
            }
            // Claude Code's installation comes first, so it is the one that creates a document
            // that was not there.
            for agent in [AgentTarget::CLAUDE_CODE, AgentTarget::QODER_CLI] {
                installer
                    .install(&with_project(&project, agent))
                    .expect("installs");
            }
            installer
                .remove(&with_project(&project, first.clone()))
                .expect("removes");
            let kept: Value =
                serde_json::from_str(&std::fs::read_to_string(&shared).expect("the file"))
                    .expect("json");
            assert!(
                kept["mcpServers"].get("kalareach").is_some(),
                "{first} goes first and the entry stays"
            );
            installer
                .remove(&with_project(&project, last.clone()))
                .expect("removes");
            assert_eq!(
                std::fs::read_to_string(&shared).ok().as_deref(),
                expected,
                "{first} then {last}"
            );
        }
    }

    /// An entry this host wrote that another build of it would write differently, here because the
    /// command moved, is replaced in its place: the rest of the document keeps every byte, and the
    /// removal still leaves the document as it was before the first installation.
    #[test]
    fn an_entry_this_host_wrote_is_replaced_in_its_place() {
        let tree = Tree::create();
        let params = params(AgentTarget::CLAUDE_CODE, InstallScope::User);
        let document = tree.home().join(".claude.json");
        let original = "{\n\t\"mcpServers\": {\n\t\t\"theirs\": {\"command\": \"their-server\"}\n\t},\n\t\
                        \"theme\": \"dark\"\n}\n";
        std::fs::write(&document, original).expect("writes");
        tree.installer().install(&params).expect("installs");
        let first = std::fs::read_to_string(&document).expect("reads");
        let moved = Installer::new(
            tree.home(),
            tree.root.join("state").join("agent-tools"),
            "/usr/local/bin/kr".to_owned(),
        );
        // A file the first installation wrote goes missing, so the second one repairs rather than
        // finding everything in place.
        std::fs::remove_file(
            tree.home()
                .join(".claude")
                .join("skills")
                .join(SKILL_NAME)
                .join("TOOLS.md"),
        )
        .expect("removes one file");
        moved.install(&params).expect("repairs");
        let second = std::fs::read_to_string(&document).expect("reads");
        assert_eq!(
            second,
            first.replace("/opt/kalareach/kr", "/usr/local/bin/kr"),
            "only the entry changed"
        );
        moved.remove(&params).expect("removes");
        assert_eq!(
            std::fs::read_to_string(&document).expect("reads"),
            original,
            "the document is byte for byte what it was"
        );
    }

    /// KR-REQ-11.50: on macOS and Linux a configuration document whose group is not the one its
    /// replacement would get is refused before anything is written, naming both, and keeps its
    /// bytes and its group. The control is every other installation here: the person's own
    /// document is replaced as before.
    #[cfg(unix)]
    #[test]
    fn a_configuration_of_another_group_is_refused_before_anything_is_written() {
        use std::os::unix::fs::MetadataExt as _;

        let tree = Tree::create();
        let Some(group) = crate::catalogue::files::another_group(&tree.home()) else {
            println!(
                "this user belongs to one group only, so the group case runs as a decision here"
            );
            return;
        };
        let document = tree.home().join(".claude.json");
        std::fs::write(&document, "{\"theme\": \"dark\"}\n").expect("writes");
        std::os::unix::fs::chown(&document, None, Some(group))
            .expect("the document is given another group of this user's");
        let group_of = |path: &Path| std::fs::metadata(path).expect("reads").gid();
        let before = files_under(&tree.root);
        match tree
            .installer()
            .install(&params(AgentTarget::CLAUDE_CODE, InstallScope::User))
        {
            Ok(_) => panic!(
                "installed, and the document's group is now {} rather than {group}",
                group_of(&document)
            ),
            Err(refused) => assert!(
                matches!(refused, ControllerError::PermissionDenied { ref detail }
                    if detail.contains(&format!("group {group}"))),
                "{refused:?}"
            ),
        }
        assert_eq!(files_under(&tree.root), before, "nothing is written");
        assert_eq!(group_of(&document), group);
    }

    /// Where each agent's skills and configuration live under a user's home, name by name.
    fn user_layout(agent: AgentTarget) -> (&'static [&'static str], &'static [&'static str]) {
        match agent.compiled().expect("a compiled agent") {
            CompiledAgent::Codex => (&[".agents", "skills"], &[".codex", "config.toml"]),
            CompiledAgent::ClaudeCode => (&[".claude", "skills"], &[".claude.json"]),
            CompiledAgent::Opencode => (
                &[".config", "opencode", "skills"],
                &[".config", "opencode", "opencode.json"],
            ),
            CompiledAgent::GeminiCli => (&[".gemini", "skills"], &[".gemini", "settings.json"]),
            CompiledAgent::KimiCodeCli => (&[".kimi-code", "skills"], &[".kimi-code", "mcp.json"]),
            CompiledAgent::QoderCli => (&[".qoder", "skills"], &[".qoder", "settings.json"]),
        }
    }

    /// KR-REQ-11.50: every path an installation records, reports and prints is spelled with one
    /// separator, the platform's own, whichever agent it is for: the skill root, each file and
    /// directory it wrote, and the configuration document. On macOS and Linux that is the spelling
    /// it always had.
    #[test]
    fn every_path_an_installation_records_is_spelled_with_one_separator() {
        let tree = Tree::create();
        let installer = tree.installer();
        let foreign = if cfg!(windows) { '/' } else { '\\' };
        for agent in AgentTarget::ALL {
            let params = params(agent.clone(), InstallScope::User);
            let installed = installer.install(&params).expect("installs");
            let status = installer.status(&params).expect("reads");
            let (skills, configuration) = user_layout(agent.clone());
            let mut spelled = vec![installed.manifest.root.clone(), status.root.clone()];
            spelled.extend(
                installed
                    .manifest
                    .operations
                    .iter()
                    .chain(&status.removal)
                    .map(|operation| operation.path().to_owned()),
            );
            spelled.extend(status.files.iter().map(|file| file.path.clone()));
            let removed = installer.remove(&params).expect("removes");
            spelled.extend(
                removed
                    .removed
                    .iter()
                    .map(|operation| operation.path().to_owned()),
            );
            for path in &spelled {
                assert!(
                    !path.contains(foreign),
                    "{agent}: {path} is spelled with one separator"
                );
            }
            let configured = installed
                .manifest
                .operations
                .iter()
                .find_map(|operation| match operation {
                    ChangeOperation::AddConfigurationEntry { path, .. } => Some(path.clone()),
                    _ => None,
                })
                .expect("a configuration entry");
            if cfg!(unix) {
                // The spelling a path joined in one piece has here, which is the one it always had.
                let home = display(&tree.home());
                assert_eq!(
                    installed.manifest.root,
                    format!("{home}/{}/{SKILL_NAME}", skills.join("/")),
                    "{agent}"
                );
                assert_eq!(
                    configured,
                    format!("{home}/{}", configuration.join("/")),
                    "{agent}"
                );
            }
        }
    }

    /// Rewrites the paths in an installation's record the way an earlier build spelled them, which
    /// joined two names at a time: each path under `from` is spelled under `to` instead. On
    /// Windows that puts both separators into one path; elsewhere the two spellings are the same.
    fn spell_record_under(
        installer: &Installer,
        params: &AgentToolsParams,
        from: &Path,
        to: &Path,
    ) {
        fn respell(value: &mut Value, from: &str, to: &str) {
            match value {
                Value::String(text) => {
                    if let Some(rest) = text.strip_prefix(from) {
                        *text = format!("{to}{rest}");
                    }
                }
                Value::Array(items) => items.iter_mut().for_each(|item| respell(item, from, to)),
                Value::Object(members) => members
                    .values_mut()
                    .for_each(|member| respell(member, from, to)),
                _ => {}
            }
        }
        let path = installer.record_path(params);
        let mut record: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("the record"))
                .expect("a record");
        respell(&mut record, &display(from), &display(to));
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&record).expect("a record"),
        )
        .expect("rewrites the record");
    }

    /// A record an earlier build wrote, whose paths join two names at a time, is still this host's:
    /// an installation that repairs it claims what it names rather than refusing it, and records
    /// each path once, and a removal undoes everything it names. Paths are compared as paths.
    #[test]
    fn a_record_an_earlier_build_spelled_is_repaired_and_removed() {
        let tree = Tree::create();
        let installer = tree.installer();
        let params = params(AgentTarget::GEMINI_CLI, InstallScope::User);
        let gemini = tree.home().join(".gemini");
        let skill = gemini.join("skills").join(SKILL_NAME);
        let respelled = |installer: &Installer| {
            spell_record_under(
                installer,
                &params,
                &gemini.join("skills"),
                &tree.home().join(".gemini/skills"),
            );
            spell_record_under(
                installer,
                &params,
                &gemini.join("settings.json"),
                &tree.home().join(".gemini/settings.json"),
            );
        };

        // A repair over the earlier spelling: one file is gone, and the rest are this host's.
        installer.install(&params).expect("installs");
        respelled(&installer);
        std::fs::remove_file(skill.join("TOOLS.md")).expect("removes one file");
        let repaired = installer.install(&params).expect("repairs");
        assert!(repaired.unresolved.is_empty(), "{:?}", repaired.unresolved);
        assert!(skill.join("TOOLS.md").is_file());
        let recorded: Vec<PathBuf> = installer
            .recorded(&params)
            .expect("reads")
            .expect("a record")
            .manifest
            .operations
            .iter()
            .map(|operation| PathBuf::from(operation.path()))
            .collect();
        let mut distinct = recorded.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            recorded.len(),
            "each path once: {recorded:?}"
        );

        // A removal from the earlier spelling.
        respelled(&installer);
        let removed = installer.remove(&params).expect("removes");
        assert!(removed.retained.is_empty(), "{:?}", removed.retained);
        assert!(!skill.exists(), "the skill is removed");
        assert!(
            !gemini.join("settings.json").exists(),
            "the document this host created is removed with its entry"
        );
    }
}
