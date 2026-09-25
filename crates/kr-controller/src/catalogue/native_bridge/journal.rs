//! The journal of one package's native bridge: what was noted before each change, what the change
//! did, and what a removal had to leave.
//!
//! A change is noted before it happens and its outcome recorded after, each in a write of its own
//! that reaches the disk first. A file is noted with the temporary name it is about to be staged
//! under, then with the identity of the staged file, then as published under that identity. That
//! chain is what lets a later run settle a change an earlier one was in the middle of: the
//! temporary file still there was never published; the destination holding the staged identity is
//! the file this host published; anything else is not this host's.

use std::path::{Path, PathBuf};

use kr_protocol::ids::PluginId;
use kr_worker::broker::bridge::BridgeSurface;
use kr_worker::broker::connectors::BridgeFacts;

use super::tree::Identity;
use crate::catalogue::files;
use crate::error::{ControllerError, Result};

/// The shape this build writes.
pub(super) const VERSION: u32 = 1;

/// One package's native bridge, as this host recorded it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    /// The shape it is written in.
    pub(super) version: u32,
    /// The package.
    pub(super) plugin_id: String,
    /// Where it stands.
    pub(super) state: State,
    /// The release the changes belong to, while there is one.
    pub(super) release: Option<Release>,
    /// What the release changed or was about to change, in the order it did.
    pub(super) changes: Vec<Change>,
    /// Changes that may be this host's and cannot be shown to be. They are never taken and never
    /// claimed, and while there is one the bridge is not reported as applied.
    pub(super) unresolved: Vec<Kept>,
    /// What removals left in place, and why.
    pub(super) leftovers: Vec<Kept>,
    /// What the last removal could not finish, and why. Each reconciliation tries again.
    pub(super) blocked: Vec<Kept>,
    /// Why the last application was refused, when it was.
    pub(super) refusal: Option<String>,
}

/// Where a package's bridge stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum State {
    /// Being applied, and not yet complete.
    Applying,
    /// Applied, every change published.
    Applied,
    /// Being removed.
    Removing,
    /// Refused, with nothing of the release in place.
    Refused,
    /// Removed, with something left in place that the leftovers name.
    Removed,
}

/// The release a journal's changes belong to.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Release {
    /// The package hash.
    pub(super) package_digest: String,
    /// The application the recipe is for, as it names it.
    pub(super) application: String,
    /// The application's directory every path is under.
    pub(super) directory: PathBuf,
    /// That directory's identity when the release was applied. A directory at that path with
    /// another identity is not the one this host changed, and nothing in it is taken as its own.
    pub(super) directory_identity: Identity,
    /// What the registration says, once the release is applied.
    pub(super) facts: Option<RecordedFacts>,
    /// The recipe's removal operations, in the order they are applied.
    pub(super) removal: Vec<Removal>,
    /// The executables read for the recipe's version requirement, each with the version its
    /// signed record names.
    pub(super) versions: Vec<(PathBuf, String)>,
}

/// The facts a registration yields, as recorded.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordedFacts {
    /// The application name the registration invokes the forwarder for.
    pub(super) application: String,
    /// The registrations it makes.
    pub(super) surfaces: Vec<BridgeSurface>,
    /// The forwarder it is expected to start.
    pub(super) forwarder: PathBuf,
}

impl RecordedFacts {
    pub(super) fn facts(&self) -> BridgeFacts {
        BridgeFacts {
            application: self.application.clone(),
            surfaces: self.surfaces.iter().copied().collect(),
            forwarder: self.forwarder.clone(),
        }
    }
}

/// One removal operation of a recipe.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Removal {
    /// Take one key back out of a document.
    Key {
        /// The document, under the application's directory.
        file: String,
        /// The key, as dotted members.
        key: String,
    },
    /// Delete a file while it holds the bytes installed.
    File {
        /// The file, under the application's directory.
        path: String,
        /// The digest installed.
        digest: String,
    },
}

/// One change a release made or was about to make.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Change {
    /// A directory, made under a temporary name beside where it goes and renamed into place, so
    /// the one this host made is known by its identity.
    Directory {
        /// The directory, under the application's directory.
        path: String,
        /// The temporary name it is made under.
        temporary: String,
        /// How far its publication got.
        publication: Publication,
    },
    /// A file.
    File {
        /// The file, under the application's directory.
        path: String,
        /// The digest of its bytes.
        digest: String,
        /// The temporary name it is staged under, beside it.
        temporary: String,
        /// How far its publication got.
        publication: Publication,
    },
    /// One key in a document.
    Key {
        /// The document, under the application's directory.
        file: String,
        /// The key, as dotted members.
        key: String,
        /// The value written, as JSON text.
        value: String,
        /// How many members on the way to the key this host created.
        created_members: usize,
        /// True when this host created the document.
        created_document: bool,
        /// The temporary name the edited document is staged under.
        temporary: String,
        /// How far its publication got.
        publication: Publication,
        /// The edit that takes the key out, while one is being made.
        removing: Option<Staging>,
    },
}

/// An edit staged beside a document, before it takes the document's place.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Staging {
    /// The temporary name it is staged under.
    pub(super) temporary: String,
    /// The staged file's identity, once recorded.
    pub(super) identity: Option<Identity>,
}

/// How far a staged change got.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "stage", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Publication {
    /// Noted under its temporary name, and not yet known to be staged.
    Noted,
    /// Staged, with the staged file's identity.
    Staged {
        /// The staged file's identity.
        identity: Identity,
    },
    /// Published, with the identity it was published under.
    Published {
        /// The published file's identity.
        identity: Identity,
    },
}

/// Something a removal or a settlement left in place, and why.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Kept {
    /// The application's directory it is under.
    pub(super) directory: PathBuf,
    /// That directory's identity. Another directory at its path says nothing about what is in
    /// this one.
    pub(super) directory_identity: Identity,
    /// The file or directory, under that directory.
    pub(super) path: String,
    /// The key in that file, where it is a key.
    pub(super) key: Option<String>,
    /// Why it was left.
    pub(super) reason: String,
}

impl Kept {
    /// What was left and why, in words a person reads.
    pub(super) fn describe(&self) -> String {
        let place = self.directory.join(&self.path).display().to_string();
        match &self.key {
            Some(key) => format!("{key} in {place}: {}", self.reason),
            None => format!("{place}: {}", self.reason),
        }
    }
}

impl State {
    /// The state's name.
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Applying => "applying",
            Self::Applied => "applied",
            Self::Removing => "removing",
            Self::Refused => "refused",
            Self::Removed => "removed",
        }
    }
}

impl Journal {
    /// A journal with nothing in it yet.
    pub(super) fn new(plugin_id: &PluginId) -> Self {
        Self {
            version: VERSION,
            plugin_id: plugin_id.to_string(),
            state: State::Refused,
            release: None,
            changes: Vec::new(),
            unresolved: Vec::new(),
            leftovers: Vec::new(),
            blocked: Vec::new(),
            refusal: None,
        }
    }

    /// Returns the release's package hash, where there is a release.
    pub(super) fn digest(&self) -> Option<&str> {
        self.release
            .as_ref()
            .map(|release| release.package_digest.as_str())
    }

    /// Returns true when the release was refused and nothing this host placed is left: no change
    /// recorded, nothing that may be this host's, and nothing any removal or refusal had to leave
    /// because somebody changed it. Whichever run left it, and whether or not a run stopped while
    /// leaving it, it is in the journal until it is gone.
    pub(super) fn is_clean_refusal(&self) -> bool {
        self.state == State::Refused
            && self.changes.is_empty()
            && self.unresolved.is_empty()
            && self.leftovers.is_empty()
    }

    /// Returns true when the release is applied, every change is published and nothing is left
    /// that may be this host's and cannot be shown to be.
    pub(super) fn is_applied(&self) -> bool {
        self.state == State::Applied
            && self.unresolved.is_empty()
            && self.changes.iter().all(|change| match change {
                Change::Directory { publication, .. }
                | Change::File { publication, .. }
                | Change::Key { publication, .. } => {
                    matches!(publication, Publication::Published { .. })
                }
            })
    }
}

/// Where each package's journal is kept.
#[derive(Clone, Debug)]
pub(super) struct Journals {
    directory: PathBuf,
}

impl Journals {
    pub(super) fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    fn path(&self, plugin_id: &str) -> PathBuf {
        self.directory.join(format!(
            "{}.json",
            files::hex(&kr_cbor::sha256(plugin_id.as_bytes())[..8])
        ))
    }

    /// Reads one package's journal; `None` when there is none.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when it cannot be read, and
    /// [`ControllerError::InvalidArgument`] when it is not a journal this build reads.
    pub(super) fn load(&self, plugin_id: &str) -> Result<Option<Journal>> {
        let path = self.path(plugin_id);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(files::storage(error)),
        };
        let journal = read(&path, &text)?;
        if journal.plugin_id != plugin_id {
            return Err(ControllerError::InvalidArgument(format!(
                "{} is the journal of {}, not of {plugin_id}",
                path.display(),
                journal.plugin_id
            )));
        }
        Ok(Some(journal))
    }

    /// Reads every journal.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::load`] returns for any of them.
    pub(super) fn all(&self) -> Result<Vec<Journal>> {
        let listing = match std::fs::read_dir(&self.directory) {
            Ok(listing) => listing,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(files::storage(error)),
        };
        let mut journals = Vec::new();
        for entry in listing {
            let entry = entry.map_err(files::storage)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            // Only the names this host gives journals. A temporary file an interrupted write left
            // begins with a dot and is not one.
            let is_journal = name.strip_suffix(".json").is_some_and(|stem| {
                stem.len() == 16 && stem.bytes().all(|b| b.is_ascii_hexdigit())
            });
            if !is_journal {
                continue;
            }
            let path = entry.path();
            let text = std::fs::read_to_string(&path).map_err(files::storage)?;
            journals.push(read(&path, &text)?);
        }
        journals.sort_by(|left, right| left.plugin_id.cmp(&right.plugin_id));
        Ok(journals)
    }

    /// Writes a journal, durably, before anything it says is acted on.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when it cannot be written.
    pub(super) fn save(&self, journal: &Journal) -> Result<()> {
        files::create_directory_durably(&self.directory)?;
        let text = serde_json::to_string_pretty(journal)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        files::write_atomically(
            &self.path(&journal.plugin_id),
            format!("{text}\n").as_bytes(),
            files::PRIVATE,
        )
    }

    /// Deletes a journal that has nothing left to say.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when it cannot be deleted.
    pub(super) fn delete(&self, plugin_id: &str) -> Result<()> {
        match std::fs::remove_file(self.path(plugin_id)) {
            Ok(()) => files::sync_directory(&self.directory, kr_ipc::paths::NameKind::File),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(files::storage(error)),
        }
    }
}

fn read(path: &Path, text: &str) -> Result<Journal> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|error| {
        ControllerError::InvalidArgument(format!("{}: {error}", path.display()))
    })?;
    let version = value.get("version").and_then(serde_json::Value::as_u64);
    if version != Some(u64::from(VERSION)) {
        return Err(ControllerError::InvalidArgument(format!(
            "{} is written in a shape this build does not read; only the build that wrote it \
             should change it",
            path.display()
        )));
    }
    serde_json::from_value(value)
        .map_err(|error| ControllerError::InvalidArgument(format!("{}: {error}", path.display())))
}
