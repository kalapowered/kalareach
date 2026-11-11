//! The two records an installation keeps: the manifest of what it laid down, and the record of what
//! was there before it laid anything.
//!
//! Both live under `%ProgramData%\KalaReach\Boundary`, where only administrators and SYSTEM can
//! write, and both are read by the programs of this crate alone. Each is a new store at version 1:
//! a program that reads a version, a field or an object kind it does not know refuses the whole
//! record rather than guessing, since removal that guesses could take away something that is not
//! the installation's.
//!
//! The manifest is written first as `in-progress` and gains each object before the step that
//! makes it, so a failure at any point leaves a record that names everything that may exist. The
//! earlier-state record is written once, before the first change, and never rewritten: a repair
//! keeps the first baseline.

use std::fs::{self, File};
use std::io::{self, Write as _};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The version of both records.
pub const STORE_VERSION: u32 = 1;

/// A record that could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The record is not what this program reads.
    #[error("the installation record is not one this program reads: {0}")]
    Unreadable(String),
    /// The record could not be written.
    #[error("the installation record could not be written: {0}")]
    Io(#[from] io::Error),
}

/// How far an installation has got.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstallState {
    /// Some objects are laid down and the installation has not finished.
    InProgress,
    /// Every step finished and the enforcement was proved.
    Installed,
}

/// What kind of object the installation laid down.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectKind {
    /// A directory; the identifier is its path.
    Directory,
    /// A file; the identifier is its path and the detail its SHA-256 digest.
    File,
    /// A local account; the identifier is its name and the detail its identifier.
    Account,
    /// A user right granted to an account; the identifier is `account:right`.
    Right,
    /// A registry value; the identifier is its key and name.
    RegistryValue,
    /// The service; the identifier is its name.
    Service,
    /// A rule of the application-control policy; the identifier is its GUID.
    PolicyRule,
    /// The Application Identity service's start type; the detail is what the installation set.
    AppIdentity,
}

/// One object the installation laid down.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Object {
    /// What kind of object it is.
    pub kind: ObjectKind,
    /// Its name: a path, an account name, a GUID or a key.
    pub id: String,
    /// A digest or an identifier, by kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// One program of Git's installation as the installation found it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Image {
    /// The path of the program, relative to Git's installation.
    pub path: String,
    /// The program's SHA-256 digest, lower-case hexadecimal.
    pub sha256: String,
}

/// The Git installation the policy was written for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitSet {
    /// Where Git is installed.
    pub dir: String,
    /// The version `git --version` reported.
    pub version: String,
    /// Each program either account may start.
    pub images: Vec<Image>,
}

/// What the installation laid down.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// The record's version.
    pub store: u32,
    /// How far the installation has got.
    pub state: InstallState,
    /// Every object recorded, in the order it was recorded.
    pub objects: Vec<Object>,
    /// The identifiers of the people the broker serves.
    pub persons: Vec<String>,
    /// The Git installation the policy was written for, once it has been qualified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<GitSet>,
}

impl Manifest {
    /// A manifest for an installation that has laid nothing down.
    #[must_use]
    pub fn begin() -> Manifest {
        Manifest {
            store: STORE_VERSION,
            state: InstallState::InProgress,
            objects: Vec::new(),
            persons: Vec::new(),
            git: None,
        }
    }

    /// Adds an object, or updates the detail of one already recorded.
    pub fn record(&mut self, kind: ObjectKind, id: &str, detail: Option<&str>) {
        let detail = detail.map(str::to_owned);
        if let Some(object) = self
            .objects
            .iter_mut()
            .find(|object| object.kind == kind && object.id.eq_ignore_ascii_case(id))
        {
            object.detail = detail;
        } else {
            self.objects.push(Object {
                kind,
                id: id.to_owned(),
                detail,
            });
        }
    }

    /// The recorded object of a kind and name, if there is one.
    #[must_use]
    pub fn find(&self, kind: ObjectKind, id: &str) -> Option<&Object> {
        self.objects
            .iter()
            .find(|object| object.kind == kind && object.id.eq_ignore_ascii_case(id))
    }

    /// Every recorded object of a kind.
    pub fn of_kind(&self, kind: ObjectKind) -> impl Iterator<Item = &Object> {
        self.objects
            .iter()
            .filter(move |object| object.kind == kind)
    }

    /// Reads a manifest.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unreadable`] for text that is not a manifest, for a field or an object
    /// kind this version does not know and for another version.
    pub fn parse(bytes: &[u8]) -> Result<Manifest, StoreError> {
        let manifest: Manifest = serde_json::from_slice(bytes)
            .map_err(|error| StoreError::Unreadable(error.to_string()))?;
        if manifest.store != STORE_VERSION {
            return Err(StoreError::Unreadable(format!(
                "version {} of the manifest",
                manifest.store
            )));
        }
        Ok(manifest)
    }

    /// Writes the manifest, replacing the file whole.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] when the file cannot be written.
    pub fn save(&self, path: &Path) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| StoreError::Unreadable(error.to_string()))?;
        replace(path, &bytes)?;
        Ok(())
    }

    /// Reads the manifest at a path.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the file cannot be read or is not a manifest.
    pub fn load(path: &Path) -> Result<Manifest, StoreError> {
        Manifest::parse(&fs::read(path)?)
    }
}

/// What was there before the installation changed anything.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prior {
    /// The record's version.
    pub store: u32,
    /// The Application Identity service's start type before the installation.
    pub appid_start_type: u32,
    /// Whether the Application Identity service was running.
    pub appid_running: bool,
    /// The effective application-control policy the platform reported.
    pub policy_xml: String,
}

impl Prior {
    /// Writes the record unless one is already there, and says whether it wrote. A repair keeps
    /// the first baseline, so this never replaces a record.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] when the file cannot be written.
    pub fn write_once(&self, path: &Path) -> Result<bool, StoreError> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| StoreError::Unreadable(error.to_string()))?;
        match create(path, true) {
            Ok(mut file) => {
                file.write_all(&bytes)?;
                file.sync_all()?;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// Reads the record at a path.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the file cannot be read or is not a record of this version.
    pub fn load(path: &Path) -> Result<Prior, StoreError> {
        let prior: Prior = serde_json::from_slice(&fs::read(path)?)
            .map_err(|error| StoreError::Unreadable(error.to_string()))?;
        if prior.store != STORE_VERSION {
            return Err(StoreError::Unreadable(format!(
                "version {} of the earlier-state record",
                prior.store
            )));
        }
        Ok(prior)
    }
}

/// Opens a record for writing: new when `only_new` (the call fails when anything is at the name),
/// else emptied. On Windows the call that makes the file carries its whole descriptor, owner
/// included, so the record is the Administrators group's whoever runs the installation.
fn create(path: &Path, only_new: bool) -> io::Result<File> {
    #[cfg(windows)]
    {
        crate::win::fresh::record_file(path, only_new)
    }
    #[cfg(not(windows))]
    {
        if only_new {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
        } else {
            File::create(path)
        }
    }
}

/// Writes a file whole: to a sibling first, then over the name, so a reader sees the old record or
/// the new one and never half of either. The sibling has a name of its own that nothing could
/// have made before (the file's stem, a random name and `.new`) and is made new, so that the
/// record the broker reads by path is never one that was there before it was written.
fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let stem = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    let staging = path.with_file_name(format!("{stem}-{}.new", uuid::Uuid::new_v4().simple()));
    {
        let mut file: File = create(&staging, true)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&staging, path)
}
