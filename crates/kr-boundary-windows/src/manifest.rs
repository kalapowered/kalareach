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
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The version of both records.
pub const STORE_VERSION: u32 = 1;

/// What a record is written beside. On Windows it is the handle that the caller holds of the
/// directory that holds the record: the replacement is renamed to the record's name relative to that
/// handle, and the record is proved to be where it is read by opening its name relative to it. No
/// path names the directory. On other systems a rename by the record's path is all there is, and
/// nothing is held.
#[cfg(windows)]
pub type Beside = crate::win::ffi::Handle;
/// What a record is written beside: nothing is held on systems other than Windows.
#[cfg(not(windows))]
#[derive(Debug)]
pub struct Beside;

/// A record that could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The record is not what this program reads.
    // text: manifest-1
    #[error("the installation record is not one this program reads: {0}")]
    Unreadable(String),
    /// The record's file could not be read.
    // text: manifest-2
    #[error("the installation record could not be read: {0}")]
    Read(io::Error),
    /// The record could not be written.
    // text: manifest-3
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

/// The version Git reported, from what its `--version` run wrote and how it ended: the one line
/// `git version` and the number, and only when the run ended successfully. A run that failed, or one
/// that wrote anything else, reports no version, and a version that a failed run happened to print is
/// not taken for the Git that the policy was written for.
#[must_use]
pub fn git_version(success: bool, stdout: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(stdout);
    let line = text.trim();
    let number = line.strip_prefix("git version ")?;
    (success
        && !line.contains(['\r', '\n'])
        && number.starts_with(|first: char| first.is_ascii_digit()))
    .then(|| line.to_owned())
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

    /// Writes the manifest, replacing the file whole, beside `beside`: on Windows the held handle
    /// of the directory that holds the file. The installation writes its manifest this way.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] when the file cannot be written.
    pub fn save_beside(&self, path: &Path, beside: &Beside) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| StoreError::Unreadable(error.to_string()))?;
        replace(beside, path, &bytes)?;
        Ok(())
    }

    /// Writes the manifest, replacing the file whole, for a caller that holds no handle of the
    /// directory that holds it: the directory is opened by the file's path and held for the write.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] when the directory cannot be opened or the file cannot be written.
    pub fn save(&self, path: &Path) -> Result<(), StoreError> {
        self.save_beside(path, &beside_parent_of(path)?)
    }

    /// Reads the manifest at a path.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the file cannot be read or is not a manifest.
    pub fn load(path: &Path) -> Result<Manifest, StoreError> {
        Manifest::parse(&fs::read(path).map_err(StoreError::Read)?)
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
        let prior: Prior = serde_json::from_slice(&fs::read(path).map_err(StoreError::Read)?)
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

/// A failure that a case forces at a named step, once, in the test build only. The steps are
/// `"protect"` and `"record"` (the installation's first two steps after it made the data directory)
/// and `"replacement"` (inside the write of a record, after its replacement file was made).
#[cfg(feature = "testing")]
pub mod forced {
    use std::sync::{Mutex, PoisonError};

    static POINT: Mutex<Option<&'static str>> = Mutex::new(None);

    /// Makes the next arrival at the named step fail, once.
    pub fn fail_the_next(point: &'static str) {
        let mut held = match POINT.lock() {
            Ok(held) => held,
            Err(poisoned) => PoisonError::into_inner(poisoned),
        };
        *held = Some(point);
    }

    /// The failure of the step, where a case forced one there; it is forced once.
    ///
    /// # Errors
    ///
    /// Returns the words of the forced failure.
    pub fn failure_at(point: &str) -> Result<(), String> {
        let mut held = match POINT.lock() {
            Ok(held) => held,
            Err(poisoned) => PoisonError::into_inner(poisoned),
        };
        if *held == Some(point) {
            *held = None;
            return Err(format!("a failure forced for a case at the step {point}"));
        }
        Ok(())
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

/// What a record is written beside, where the caller holds no handle: the directory that holds the
/// record, opened by the record's path.
#[cfg(windows)]
fn beside_parent_of(path: &Path) -> io::Result<Beside> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("the record has no directory"))?;
    crate::win::fresh::hold_directory(parent)
}

/// What a record is written beside, where the caller holds no handle: nothing is held here.
#[cfg(not(windows))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the same call as on Windows, where opening the directory can fail"
)]
fn beside_parent_of(_path: &Path) -> io::Result<Beside> {
    Ok(Beside)
}

/// Writes a file whole: to a sibling first, then over the name, so a reader sees the old record or
/// the new one and never half of either. The sibling has a name of its own that nothing could
/// have made before (the file's stem, a random name and `.new`) and is made new, so that the
/// record the broker reads by path is never one that was there before it was written.
fn replace(beside: &Beside, path: &Path, bytes: &[u8]) -> io::Result<()> {
    replace_through(beside, path, &replacement_name(path), bytes)
}

/// The name a file's replacement is written under: the file's stem, 32 random hexadecimal digits
/// and `.new`, beside the file.
fn replacement_name(path: &Path) -> PathBuf {
    let stem = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!("{stem}-{}.new", uuid::Uuid::new_v4().simple()))
}

/// Writes the bytes to the replacement, which must not exist, and renames it over the file. Where
/// the write, the flush or the rename fails after this call made the replacement, the replacement is
/// removed again, so that a failed write leaves no file of its own; a removal that fails too is named
/// beside the first error. A replacement that this call did not make (the name was taken) is not
/// touched.
///
/// On Windows the replacement is written, renamed relative to the held directory handle, proved to
/// be at the record's name and, where a step fails, marked for removal through its one handle.
#[cfg(windows)]
fn replace_through(beside: &Beside, path: &Path, staging: &Path, bytes: &[u8]) -> io::Result<()> {
    crate::win::fresh::replace_whole(beside, path, staging, bytes)
}

/// [`replace_through`] for the other systems: they have no handle that renames or marks a file by
/// itself, so the replacement is removed by its name.
#[cfg(not(windows))]
fn replace_through(_beside: &Beside, path: &Path, staging: &Path, bytes: &[u8]) -> io::Result<()> {
    replace_by_name(path, staging, bytes)
}

/// The form of [`replace_through`] for systems other than Windows.
#[cfg(not(windows))]
fn replace_by_name(path: &Path, staging: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file: File = create(staging, true)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    let Err(failure) = written.and_then(|()| fs::rename(staging, path)) else {
        return Ok(());
    };
    match fs::remove_file(staging) {
        Ok(()) => Err(failure),
        // The rename may have moved it already: nothing is left to remove.
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(failure),
        Err(error) => Err(io::Error::new(
            failure.kind(),
            format!(
                "{failure}; the replacement {} could not be removed either: {error}",
                staging.display()
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a record in `dir` is written beside: on Windows the held handle of the directory, opened
    /// as a directory.
    #[cfg(windows)]
    fn beside(dir: &Path) -> Beside {
        crate::win::fresh::hold_directory(dir).unwrap()
    }

    #[cfg(not(windows))]
    fn beside(_dir: &Path) -> Beside {
        Beside
    }

    #[test]
    fn a_replacement_has_a_random_name_of_its_own_every_time() {
        let path = Path::new("data").join("manifest.json");
        let first = replacement_name(&path);
        let second = replacement_name(&path);
        assert_ne!(first, second, "no fixed name");
        assert_eq!(first.parent(), path.parent(), "beside the file");
        let name = first.file_name().unwrap().to_string_lossy().into_owned();
        let digits = name
            .strip_prefix("manifest-")
            .and_then(|rest| rest.strip_suffix(".new"))
            .unwrap_or_default();
        assert!(
            digits.len() == 32
                && digits
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{name}"
        );
    }

    /// A file that cannot be read is said to be unreadable, and one that cannot be written is said to
    /// be unwritable: the two errors have their own words.
    #[test]
    fn a_record_that_cannot_be_read_is_not_said_to_be_unwritable() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("manifest.json");
        for read in [
            Manifest::load(&missing).unwrap_err().to_string(),
            Prior::load(&missing).unwrap_err().to_string(),
        ] {
            assert!(
                read.starts_with("the installation record could not be read: "),
                "{read}"
            );
            assert!(!read.contains("written"), "{read}");
        }
        let into_a_directory_that_is_not_there = dir.path().join("none").join("manifest.json");
        let write = Manifest::begin()
            .save(&into_a_directory_that_is_not_there)
            .unwrap_err()
            .to_string();
        assert!(
            write.starts_with("the installation record could not be written: "),
            "{write}"
        );
    }

    /// A replacement that this call made and could not put over the file is removed again, so that a
    /// directory that holds only what the call made is empty after a first write that failed.
    #[test]
    fn a_replacement_that_could_not_be_put_over_the_file_is_removed_again() {
        let dir = tempfile::tempdir().unwrap();
        // A directory at the file's name: the rename fails after the replacement was written whole.
        let path = dir.path().join("manifest.json");
        fs::create_dir(&path).unwrap();
        let staging = dir.path().join("manifest-made.new");
        let failed =
            replace_through(&beside(dir.path()), &path, &staging, b"the record").unwrap_err();
        let look = fs::metadata(&staging).unwrap_err();
        assert_eq!(
            look.kind(),
            io::ErrorKind::NotFound,
            "the replacement is left: {failed}"
        );
        assert!(
            fs::metadata(&path).unwrap().is_dir(),
            "what was at the name is as it was"
        );
    }

    #[test]
    fn a_replacement_is_never_written_over_a_name_that_exists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        fs::write(&path, b"the record").unwrap();
        let taken = dir.path().join("manifest-taken.new");
        fs::write(&taken, b"another program's file").unwrap();
        let refused =
            replace_through(&beside(dir.path()), &path, &taken, b"the new record").unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::AlreadyExists, "{refused}");
        assert_eq!(fs::read(&taken).unwrap(), b"another program's file");
        assert_eq!(
            fs::read(&path).unwrap(),
            b"the record",
            "the record is as it was"
        );
    }
}
