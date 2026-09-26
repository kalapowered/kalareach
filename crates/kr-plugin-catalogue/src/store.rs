//! What an enrolment leaves on disk, and how it becomes current.
//!
//! One directory per enrolment, named by its [`EnrolmentKey`] rather than by the repository's name:
//!
//! ```text
//! <root>/repositories/<enrolment key>/
//!   datastore/            the client's own trusted metadata
//!   index/<digest>.json   each verified generation's index, whole and named by its own digest
//!   payloads/<digest>     cached payloads, by content hash
//!   packages/<digest>/    an activated package's files, under its manifest digest
//!   staging/              work in progress, and nothing a reader ever sees
//! ```
//!
//! What stays is budgeted. The trust checkpoint and the index documents of the generations a
//! repository keeps are its retained metadata; the cached payloads and the packages extracted
//! from them are its payload cache, and a package being staged is counted there at its largest
//! before it starts. Staging holds only the work of whoever holds the store's lock, so what is
//! left there when the lock is taken again is removed.
//!
//! Everything here is named by what it holds. Which generation is current, and which package is
//! installed where, are rows in the catalogue's database, and a file becomes something a reader
//! relies on only when a committed row names it. So the order is always the same: the object is
//! written whole and flushed, and then the row that names it commits.
//!
//! * **The index.** A generation's index is written whole and flushed under its digest, and only
//!   then does the repository's row move to name it. A reader sees one generation or the previous
//!   one, never a mixture, and an interrupted sync leaves the previous index exactly where it was.
//! * **A package.** Every payload is staged and verified in a directory of its own, and the
//!   directory is renamed into place once all of them verify. A package is therefore never half
//!   installed, and a package activation that fails leaves an installed package usable.
//!
//! Every write a reader could come to rely on takes a [`Permit`], so it happens inside the
//! admitting authority's commit. Staging does not: a staging directory is this attempt's own, and
//! nothing reads it.
//!
//! Everything the store writes, renames or removes goes through directory handles it opened
//! itself, each inside the one above it without following a link, from the catalogue's own
//! directory down. A directory that is a link is refused when it is opened, and one that becomes a
//! link afterwards redirects nothing, because the handle holds the directory rather than its name.
//!
//! Reclaiming space never takes a payload a live binding or a pinned generation still needs.
//! Section 11 is explicit that a sync does not evict those to finish, so [`Store::plan_reclaim`]
//! refuses rather than freeing the last thing that was keeping something working.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use kr_plugin_sdk::catalogue::CatalogueIndex;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::plugin::PluginManifest;

use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::fs::{Dir, OpenOptions};
use kr_flush::{NameKind, flush_held_directory};

use crate::authority::Permit;
use crate::budget::{BudgetLedger, Resource, ResourceLimit, Stage};
use crate::db::ActiveGeneration;
use crate::error::{CatalogueError, CatalogueResult};
use crate::repository::EnrolmentKey;

/// The directory every enrolment's own directory sits in.
const REPOSITORIES: &str = "repositories";

/// The document in which the client keeps the latest time it has known.
const TIME_CHECKPOINT: &str = "latest_known_time.json";

/// The documents of the accepted trust checkpoint the client reads back: the timestamp and the
/// snapshot a new one is compared with, and the latest time it has known.
///
/// Everything else it writes afresh on every load: the root it ends on, the top-level targets and
/// each delegated role's document, which under consistent snapshots it names by version. A working
/// copy holds only these, so a verified load publishes exactly one generation's documents, and one
/// generation's delegated documents do not pile up behind the next.
const CLIENT_READS: [&str; 3] = ["timestamp.json", "snapshot.json", TIME_CHECKPOINT];

/// The most the client's time document can hold: one quoted RFC 3339 instant with nanoseconds, and
/// room to spare.
///
/// The client writes the time it last saw on every load, and its length moves with the clock's
/// fraction of a second. A checkpoint is counted with this document at this size, so what the
/// retained metadata budget counts is never less than what is held and does not move from one load
/// to the next.
const TIME_CHECKPOINT_BOUND: u64 = 64;

/// Returns what a trust checkpoint in `directory` counts against the retained metadata budget:
/// every document it holds, the time document at [`TIME_CHECKPOINT_BOUND`] whether or not it is
/// there yet.
fn checkpoint_size(directory: &Path) -> CatalogueResult<u64> {
    let time = directory.join(TIME_CHECKPOINT);
    let held_time = match std::fs::symlink_metadata(&time) {
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Ok(_) => 0,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => 0,
        Err(source) => return Err(CatalogueError::storage(&time, &source)),
    };
    Ok(bytes_under(directory)?
        .saturating_sub(held_time)
        .saturating_add(TIME_CHECKPOINT_BOUND))
}

/// One repository's directory.
#[derive(Clone, Debug)]
pub struct Store {
    /// The catalogue's own directory, which every repository's directory sits under.
    catalogue: PathBuf,
    /// The enrolment's key, which names its directory under `repositories/`.
    key: String,
    root: PathBuf,
}

/// The file whose lock keeps a second process from writing into the same repository's store.
const LOCK_FILE: &str = ".lock";

/// One of the store's directories, held open.
///
/// What the store writes, renames or removes it reaches through this handle, and never through the
/// directory's name again: a name somebody points elsewhere afterwards redirects nothing, because
/// the handle holds the directory itself. The path is only what messages call it.
#[derive(Debug)]
struct Area {
    dir: Dir,
    path: PathBuf,
}

impl Area {
    /// Opens the directory `name` in this one, making it where it is missing ([`Self::make`]).
    fn child(&self, name: &str) -> CatalogueResult<Self> {
        self.make(Path::new(name))
    }

    /// Opens the directory `name` in this one without following a link, making it first where it
    /// is missing, and returns it once its name is confirmed in this one.
    ///
    /// A directory's name is an entry in the directory above it, so what the store writes into a
    /// directory it made survives a crash only once that entry has been flushed. The store confirms
    /// the name before anything can be written into the directory, and it marks the name as not yet
    /// confirmed until then: before it makes a directory it leaves a marker beside it, an empty
    /// directory named by [`marker_of`], and it takes the marker away only once this directory has
    /// been flushed. So nobody finds the directory under its name without the marker until the name
    /// is confirmed: a refused flush, a process that stops, and another process making the same
    /// directory at the same moment all leave the marker, and the next call that reaches the
    /// directory confirms the name before the directory is used. A directory with no marker beside
    /// it was confirmed when it was made, or was made before the store marked its directories, and
    /// is not flushed again. A marker that cannot be made stops the call before the directory is
    /// made.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the directory or its marker cannot be
    /// made, when what is at its name is a link or not a directory, and when its name cannot be
    /// confirmed; that failure names the directory and the one it is in.
    fn make(&self, name: &Path) -> CatalogueResult<Self> {
        let path = self.path.join(name);
        let marker = marker_of(name);
        let missing = match self.dir.symlink_metadata(name) {
            Ok(_) => false,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => true,
            Err(source) => return Err(CatalogueError::storage(&path, &source)),
        };
        if missing {
            self.mark_unconfirmed(&marker)?;
            match self.dir.create_dir(name) {
                Ok(()) => {}
                // Another process made it after the look above; the marker is beside it all the
                // same.
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(source) => return Err(CatalogueError::storage(&path, &source)),
            }
        }
        // Whatever is at the name now, made here or by another process meanwhile, is used only if
        // it is a directory and not a link.
        let made = open_child(&self.dir, &path, name)?;
        if !missing && !self.marked(&marker)? {
            return Ok(made);
        }
        flush_directory(self, NameKind::Directory).map_err(|error| {
            CatalogueError::StorageUnavailable {
                detail: format!(
                    "{} was made and its name is not confirmed in the directory it is in: {error}",
                    path.display()
                ),
            }
        })?;
        // Confirmed. A marker that stays only has the next call flush this directory again.
        let _ = self.dir.remove_dir(&marker);
        Ok(made)
    }

    /// Leaves the marker `marker` in this directory, an empty directory, whether or not another
    /// process or a call that stopped left it there already. Anything else at that name, a link
    /// among them, stops the call.
    fn mark_unconfirmed(&self, marker: &Path) -> CatalogueResult<()> {
        match self.dir.create_dir(marker) {
            Ok(()) => Ok(()),
            Err(source)
                if source.kind() == std::io::ErrorKind::AlreadyExists
                    && self
                        .dir
                        .symlink_metadata(marker)
                        .is_ok_and(|found| found.is_dir()) =>
            {
                Ok(())
            }
            Err(source) => Err(CatalogueError::storage(&self.path.join(marker), &source)),
        }
    }

    /// Whether anything is at the marker's name `marker` in this directory. Anything there counts,
    /// so a directory is never taken as confirmed while something stands at its marker's name.
    fn marked(&self, marker: &Path) -> CatalogueResult<bool> {
        match self.dir.symlink_metadata(marker) {
            Ok(_) => Ok(true),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(CatalogueError::storage(&self.path.join(marker), &source)),
        }
    }

    /// Opens every directory from this one down to the one `relative` names a file in, making
    /// each where it is missing when `create` says so ([`Self::make`]), and returns it with the
    /// file's name.
    fn parent_of(&self, relative: &Path, create: bool) -> CatalogueResult<(Self, OsString)> {
        let unnamed = || CatalogueError::StorageUnavailable {
            detail: format!(
                "{} is not a name below {}",
                relative.display(),
                self.path.display()
            ),
        };
        let name = relative.file_name().ok_or_else(unnamed)?.to_os_string();
        let mut directory = self.try_clone()?;
        for component in relative.parent().into_iter().flat_map(Path::components) {
            let std::path::Component::Normal(part) = component else {
                return Err(unnamed());
            };
            directory = if create {
                directory.make(Path::new(part))?
            } else {
                open_child(&directory.dir, &directory.path.join(part), Path::new(part))?
            };
        }
        Ok((directory, name))
    }

    fn try_clone(&self) -> CatalogueResult<Self> {
        Ok(Self {
            dir: self
                .dir
                .try_clone()
                .map_err(|source| CatalogueError::storage(&self.path, &source))?,
            path: self.path.clone(),
        })
    }
}

/// One store's directories, each opened without following a link, from the catalogue's own
/// directory down, when [`Store::layout`] took them.
#[derive(Debug)]
struct Layout {
    repository: Area,
    datastore: Area,
    index: Area,
    payloads: Area,
    packages: Area,
    staging: Area,
}

/// Returns `path` without the separators and `.` components that name the same place.
///
/// A trailing separator would have the platform resolve a last component that is a link before any
/// check could see it, and a trailing `.` would do the same.
pub(crate) fn normal(path: &Path) -> PathBuf {
    path.components().collect()
}

/// Checks that the catalogue's own directory is a directory and not a link.
///
/// # Errors
///
/// Returns [`CatalogueError::StorageUnavailable`] when it is a link, not a directory, names no
/// directory of its own, or cannot be opened.
pub(crate) fn check_own(path: &Path) -> CatalogueResult<()> {
    open_own(path).map(drop)
}

/// Opens the catalogue's own directory, refusing it where it is a link or not a directory.
///
/// The directories above it are the host's, and are opened as the host names them.
fn open_own(path: &Path) -> CatalogueResult<Area> {
    let path = normal(path);
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(CatalogueError::StorageUnavailable {
            detail: format!(
                "{} names no directory of its own for the catalogue",
                path.display()
            ),
        });
    };
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let above = Dir::open_ambient_dir(parent, cap_std::ambient_authority())
        .map_err(|source| CatalogueError::storage(parent, &source))?;
    open_child(&above, &path, Path::new(name))
}

/// The end of the name of the marker that stands beside a directory the store made, in the
/// directory it is in, until the directory's name is confirmed there ([`Area::make`]).
///
/// The marker's name is the directory's behind a dot and before this, and a `~` is in no name the
/// store gives a directory or a file otherwise: a package's paths are ASCII letters, digits, `.`,
/// `-` and `_`, and every other name is the store's own. It is an empty directory, so making it
/// asks of the directory it is in only the right to add a directory, which making the directory it
/// marks asks anyway.
const UNCONFIRMED: &str = "~unconfirmed";

/// The name of the marker of the directory `name`: `.<name>~unconfirmed`, in the same directory.
fn marker_of(name: &Path) -> PathBuf {
    let mut marker = OsString::from(".");
    marker.push(name.as_os_str());
    marker.push(UNCONFIRMED);
    PathBuf::from(marker)
}

/// Opens the directory `name` in `parent` without following a link.
///
/// A link, whether it was there before or put there while the directory was made, fails the open
/// itself, so there is no moment between a check and the open for it to redirect.
fn open_child(parent: &Dir, path: &Path, name: &Path) -> CatalogueResult<Area> {
    match parent.open_dir_nofollow(name) {
        Ok(dir) => Ok(Area {
            dir,
            path: path.to_path_buf(),
        }),
        Err(source) => Err(match parent.symlink_metadata(name) {
            Ok(metadata) if metadata.file_type().is_symlink() => not_own(path, "a link"),
            Ok(metadata) if !metadata.is_dir() => not_own(path, "not a directory"),
            _ => CatalogueError::storage(path, &source),
        }),
    }
}

fn not_own(path: &Path, what: &str) -> CatalogueError {
    CatalogueError::StorageUnavailable {
        detail: format!(
            "{} is {what}, and the catalogue writes only into directories of its own",
            path.display()
        ),
    }
}

/// Reads the file `relative` names below `area`, following no link on the way or at the end.
fn read_in(area: &Area, relative: &Path) -> std::io::Result<Vec<u8>> {
    let (directory, name) = area
        .parent_of(relative, false)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = directory.dir.open_with(&name, &options)?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes)?;
    Ok(bytes)
}

/// Creates the file `name` in `area`, which is not there yet, and writes and flushes `bytes`.
///
/// A name that is already there, a link among them, fails instead of being followed.
fn create_in(area: &Area, name: &Path, bytes: &[u8]) -> CatalogueResult<()> {
    let path = area.path.join(name);
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    let mut file = area
        .dir
        .open_with(name, &options)
        .map_err(|source| CatalogueError::storage(&path, &source))?;
    file.write_all(bytes)
        .map_err(|source| CatalogueError::storage(&path, &source))?;
    file.sync_all()
        .map_err(|source| CatalogueError::storage(&path, &source))
}

/// Returns every file below `area`, as paths relative to it, in a stable order, following no link.
fn files_in(area: &Area) -> CatalogueResult<BTreeSet<PathBuf>> {
    let mut files = BTreeSet::new();
    let mut pending = vec![(area.try_clone()?, PathBuf::new())];
    while let Some((directory, relative)) = pending.pop() {
        let entries = directory
            .dir
            .entries()
            .map_err(|source| CatalogueError::storage(&directory.path, &source))?;
        for entry in entries {
            let entry =
                entry.map_err(|source| CatalogueError::storage(&directory.path, &source))?;
            let name = entry.file_name();
            let kind = entry
                .file_type()
                .map_err(|source| CatalogueError::storage(&directory.path.join(&name), &source))?;
            if kind.is_dir() {
                let below = open_child(
                    &directory.dir,
                    &directory.path.join(&name),
                    Path::new(&name),
                )?;
                pending.push((below, relative.join(&name)));
            } else if kind.is_file() {
                files.insert(relative.join(&name));
            }
        }
    }
    Ok(files)
}

/// Returns the name an index document is kept under: its own digest.
fn index_name(digest: PayloadDigest) -> String {
    format!("{digest}.json")
}

/// Removes whatever an operation that stopped left in `staging`, which nothing names and no
/// budget counts.
fn clear_staging(staging: &Area) -> CatalogueResult<()> {
    let entries = staging
        .dir
        .entries()
        .map_err(|source| CatalogueError::storage(&staging.path, &source))?;
    for entry in entries {
        let entry = entry.map_err(|source| CatalogueError::storage(&staging.path, &source))?;
        let name = entry.file_name();
        let path = staging.path.join(&name);
        let kind = entry
            .file_type()
            .map_err(|source| CatalogueError::storage(&path, &source))?;
        let removed = if kind.is_dir() {
            staging.dir.remove_dir_all(&name)
        } else {
            staging.dir.remove_file(&name)
        };
        match removed {
            Ok(()) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(CatalogueError::StorageUnavailable {
                    detail: format!(
                        "{} was left in staging by an operation that stopped and cannot be \
                         removed, so the room it takes is not known to be free: {source}",
                        path.display()
                    ),
                });
            }
        }
    }
    Ok(())
}

/// What an activated package's directory holds, measured against its own manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackageCheck {
    /// The manifest and every file it declares are here, in the bytes declared.
    Complete(Box<ReadyPackage>),
    /// The package, or a file it declares, is not here.
    Missing {
        /// What is missing.
        detail: String,
    },
    /// A file is here and holds bytes other than the ones declared.
    Corrupt {
        /// Which file, and how it differs.
        detail: String,
    },
}

/// A private copy of a repository's accepted trust checkpoint, which one verification works in.
///
/// The client writes into its datastore as it goes: roots one after another, then each role's
/// metadata, each written in place. None of that reaches the accepted checkpoint until the load
/// has verified, when [`Store::publish_checkpoint`] moves it there under the admitting
/// authority's permit. A load that fails or is interrupted leaves only this copy, which is removed
/// with it.
///
/// The client reads and writes the copy by its name, which is the one place the store's files are
/// written by a name rather than through a directory this host holds open. What was verified is
/// read back through the copy's own handle.
#[derive(Debug)]
pub struct WorkingDatastore {
    /// The copy, held open. Declared before `_entry`, so it is closed before the copy is removed.
    dir: Area,
    /// Where the copy is in staging, held only to remove the copy once the verification it served
    /// is over.
    _entry: StagingEntry,
}

impl WorkingDatastore {
    /// Returns the directory the client works in.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.dir.path
    }
}

/// A directory an operation made in staging, removed again when this is dropped, through the
/// staging directory it was made in, unless it was renamed into place.
///
/// The directory is the operation's own and nothing reads it, so an operation that stops part way,
/// or whose work was refused, leaves nothing behind. A removal that fails leaves a directory no
/// reader ever looks at, under a name no later operation reuses. Whatever else holds the directory
/// open declares that handle before its entry, so the handle is closed before the removal: the
/// store opens a directory without sharing its deletion, and on Windows a directory held that way
/// can be neither removed nor renamed.
#[derive(Debug)]
struct StagingEntry {
    staging: Area,
    name: String,
    /// Whether dropping this removes the directory: it does until the directory has been renamed
    /// into place, after which nothing of the operation is left under the name.
    remove: bool,
}

impl StagingEntry {
    /// The directory `name`, just made in `staging`.
    fn made(staging: Area, name: String) -> Self {
        Self {
            staging,
            name,
            remove: true,
        }
    }

    /// Where the directory is.
    fn path(&self) -> PathBuf {
        self.staging.path.join(&self.name)
    }

    /// Opens the directory without following a link.
    fn open(&self) -> CatalogueResult<Area> {
        open_child(&self.staging.dir, &self.path(), Path::new(&self.name))
    }
}

impl Drop for StagingEntry {
    fn drop(&mut self) {
        if self.remove {
            let _ = self.staging.dir.remove_dir_all(&self.name);
        }
    }
}

/// Returns the bytes every file under `directory` holds, following no link.
fn bytes_under(directory: &Path) -> CatalogueResult<u64> {
    let mut total = 0u64;
    let mut pending = vec![directory.to_path_buf()];
    while let Some(current) = pending.pop() {
        let entries = match std::fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
            Err(source) => return Err(CatalogueError::storage(&current, &source)),
        };
        for entry in entries {
            let entry = entry.map_err(|source| CatalogueError::storage(&current, &source))?;
            let path = entry.path();
            let metadata = entry
                .metadata()
                .map_err(|source| CatalogueError::storage(&path, &source))?;
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            }
        }
    }
    Ok(total)
}

/// Returns every file under `directory`, as paths relative to it, in a stable order.
fn files_under(directory: &Path) -> CatalogueResult<BTreeSet<PathBuf>> {
    let mut files = BTreeSet::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(current) = pending.pop() {
        let entries = match std::fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
            Err(source) => return Err(CatalogueError::storage(&current, &source)),
        };
        for entry in entries {
            let entry = entry.map_err(|source| CatalogueError::storage(&current, &source))?;
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|source| CatalogueError::storage(&path, &source))?;
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file()
                && let Ok(relative) = path.strip_prefix(directory)
            {
                files.insert(relative.to_path_buf());
            }
        }
    }
    Ok(files)
}

/// What one store holds of a package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeldPackage {
    /// Nothing: neither an extracted copy nor its manifest in the cache. The package is another
    /// store's, and nothing here is its to lose.
    Absent,
    /// Its extracted copy, whose own manifest, under the package's hash, names these files.
    Named(Vec<PayloadDigest>),
    /// Its extracted copy or its cached manifest, and no manifest in an extracted copy here that
    /// can say what it consists of.
    Unnamed,
}

/// A package every file of which was checked, where it lies, against the manifest its digest names.
///
/// Only [`Store::check_package`] makes one. What an installation records about a package, and what
/// an enablement relies on, is read from this rather than from an index entry: the package hash
/// names this manifest and nothing else, so a later index that says something different about the
/// same hash changes nothing about what is installed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadyPackage {
    digest: PayloadDigest,
    manifest: PluginManifest,
}

impl ReadyPackage {
    /// Returns the package hash, which is the manifest's digest.
    #[must_use]
    pub const fn digest(&self) -> PayloadDigest {
        self.digest
    }

    /// Returns the manifest the package hash names, as it was read back and checked.
    #[must_use]
    pub const fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    /// A package the unit tests describe without a directory behind it.
    #[cfg(test)]
    pub(crate) const fn unchecked(digest: PayloadDigest, manifest: PluginManifest) -> Self {
        Self { digest, manifest }
    }
}

/// An exclusive cross-process lock on this repository's store, held across metadata synchronisation.
#[derive(Debug)]
pub struct StoreLock {
    _file: std::fs::File,
}

/// Takes the lock on one repository's store, in the lock file inside its own directory.
///
/// On Windows the same exclusion is the open itself, with no sharing.
fn acquire(repository: &Area) -> CatalogueResult<StoreLock> {
    let path = repository.path.join(LOCK_FILE);
    let mut options = OpenOptions::new();
    options
        .create(true)
        .truncate(false)
        .write(true)
        .follow(FollowSymlinks::No);
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        const NO_SHARING: u32 = 0;
        options.share_mode(NO_SHARING);
    }
    let file = repository
        .dir
        .open_with(LOCK_FILE, &options)
        .map_err(|source| CatalogueError::storage(&path, &source))?
        .into_std();
    #[cfg(unix)]
    {
        use rustix::fs::{FlockOperation, flock};
        flock(&file, FlockOperation::LockExclusive)
            .map_err(|source| CatalogueError::storage(&path, &std::io::Error::from(source)))?;
    }
    Ok(StoreLock { _file: file })
}

impl Store {
    /// Opens one repository's directory, creating what is missing.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when a directory cannot be created, or one of
    /// the store's directories is a link or not a directory.
    pub fn open(root: &Path, enrolment: &EnrolmentKey) -> CatalogueResult<Self> {
        let store = Self::at(root, enrolment);
        store.layout()?;
        Ok(store)
    }

    /// Names one enrolment's directory without creating anything, for a read.
    ///
    /// A read that found nothing there is an answer about what is held, so it creates nothing on
    /// the way.
    #[must_use]
    pub fn at(root: &Path, enrolment: &EnrolmentKey) -> Self {
        let catalogue = normal(root);
        Self {
            root: catalogue.join(REPOSITORIES).join(enrolment.as_str()),
            key: enrolment.as_str().to_owned(),
            catalogue,
        }
    }

    /// Opens every directory from the catalogue's own down to each of this store's, making the
    /// store's where they are missing, and returns them.
    ///
    /// Whatever the store writes, renames or removes, it does through these handles: each
    /// directory is opened in the one above it without following a link, so a directory that is a
    /// link, or not a directory, is refused, and one that becomes a link after it was opened
    /// redirects nothing, because the handle holds the directory itself. Every write opens them
    /// again just before it writes, so one put in place of a directory since is refused there. The
    /// directories above the catalogue's own are the host's, and are not the store's to judge.
    fn layout(&self) -> CatalogueResult<Layout> {
        let catalogue = open_own(&self.catalogue)?;
        let repository = catalogue.child(REPOSITORIES)?.child(&self.key)?;
        Ok(Layout {
            datastore: repository.child("datastore")?,
            index: repository.child("index")?,
            payloads: repository.child("payloads")?,
            packages: repository.child("packages")?,
            staging: repository.child("staging")?,
            repository,
        })
    }

    /// Acquires an exclusive cross-process lock on this repository's store.
    ///
    /// Staging holds only the work of whoever holds this lock, so whatever is there once it is
    /// taken was left by an operation that stopped before it could remove it. Nothing names it and
    /// no budget counts it, so it is removed. Something that cannot be removed stops the operation
    /// that took the lock: the room it takes would be outside every budget, and the budgets could
    /// not say what is free.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when one of the store's directories is a
    /// link or not a directory, the lock cannot be acquired, or staging cannot be cleared.
    pub fn lock(&self) -> CatalogueResult<StoreLock> {
        let layout = self.layout()?;
        #[cfg(all(test, unix))]
        lock_pause::run();
        let lock = acquire(&layout.repository)?;
        // Staging is cleared through the handle opened before any wait for the lock: a link put in
        // its place while this waited redirects nothing, because the handle holds the directory.
        clear_staging(&layout.staging)?;
        Ok(lock)
    }

    /// Returns the directory that holds this repository's accepted trust checkpoint.
    ///
    /// It holds the metadata the client last verified whole, which is what the next verification
    /// starts from. The client never writes here: it works in a [`WorkingDatastore`], and what it
    /// verified is moved here by [`Self::publish_checkpoint`].
    #[must_use]
    pub fn datastore(&self) -> PathBuf {
        self.root.join("datastore")
    }

    /// Copies the accepted trust checkpoint into a private working copy for one verification.
    ///
    /// Only the documents the client reads back are copied ([`CLIENT_READS`]); the rest it writes
    /// again as it verifies. `reset` drops the timestamp and snapshot documents from the copy. The client drops them
    /// itself when a load moves to a root whose timestamp or snapshot keys differ from the root it
    /// started from; a root advance kept by an earlier load that then failed is the root the next
    /// load starts from, so the next load would not see the change, and the reset is applied here
    /// instead.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the copy cannot be made.
    pub fn working_datastore(&self, reset: bool) -> CatalogueResult<WorkingDatastore> {
        let layout = self.layout()?;
        let mut attempt = 0u32;
        let name = loop {
            let candidate = format!("datastore-{}-{attempt}", std::process::id());
            match layout.staging.dir.create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                    attempt = attempt.saturating_add(1);
                    if attempt > 1024 {
                        return Err(CatalogueError::storage(
                            &layout.staging.path.join(&candidate),
                            &source,
                        ));
                    }
                }
                Err(source) => {
                    return Err(CatalogueError::storage(
                        &layout.staging.path.join(&candidate),
                        &source,
                    ));
                }
            }
        };
        // From here the copy is removed again when it is dropped, whatever happens next.
        let entry = StagingEntry::made(layout.staging, name);
        let working = WorkingDatastore {
            dir: entry.open()?,
            _entry: entry,
        };
        for name in CLIENT_READS {
            let bytes = match read_in(&layout.datastore, Path::new(name)) {
                Ok(bytes) => bytes,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(CatalogueError::storage(
                        &layout.datastore.path.join(name),
                        &source,
                    ));
                }
            };
            create_in(&working.dir, Path::new(name), &bytes)?;
        }
        if reset {
            for role in ["timestamp.json", "snapshot.json"] {
                match working.dir.dir.remove_file(role) {
                    Ok(()) => {}
                    Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                    Err(source) => {
                        return Err(CatalogueError::storage(
                            &working.dir.path.join(role),
                            &source,
                        ));
                    }
                }
            }
        }
        Ok(working)
    }

    /// Keeps the time checkpoint the client moved on while it fetched a verified generation's
    /// payloads.
    ///
    /// The client refuses a clock that stepped back behind the latest time it knows. It records
    /// that time in its working copy every time it reads a target, after the checkpoint was
    /// published, so what it saw last is written into the accepted checkpoint as well.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when nothing was written, and
    /// [`CatalogueError::PublicationUncertain`] when its directory did not confirm it.
    pub(crate) fn publish_time_checkpoint(
        &self,
        _permit: &Permit,
        working: &WorkingDatastore,
    ) -> CatalogueResult<()> {
        let bytes = match read_in(&working.dir, Path::new(TIME_CHECKPOINT)) {
            Ok(bytes) => bytes,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(CatalogueError::storage(
                    &working.dir.path.join(TIME_CHECKPOINT),
                    &source,
                ));
            }
        };
        // The client writes this document in place, so a write it did not finish leaves it empty
        // or cut short, and a document that does not read back is one the client ignores. Only a
        // time that reads back, and is no earlier than the time already kept, replaces it.
        let Ok(seen) = serde_json::from_slice::<jiff::Timestamp>(&bytes) else {
            return Ok(());
        };
        let layout = self.layout()?;
        match read_in(&layout.datastore, Path::new(TIME_CHECKPOINT)) {
            Ok(held) => {
                if serde_json::from_slice::<jiff::Timestamp>(&held).is_ok_and(|kept| kept >= seen) {
                    return Ok(());
                }
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(CatalogueError::storage(
                    &layout.datastore.path.join(TIME_CHECKPOINT),
                    &source,
                ));
            }
        }
        write_atomically(
            &layout.staging,
            &layout.datastore,
            Path::new(TIME_CHECKPOINT),
            &bytes,
        )
    }

    /// Makes a verified working copy the accepted trust checkpoint, one document at a time.
    ///
    /// What the working copy no longer holds goes first: the delegated documents of the generation
    /// before, which the client never reads back. Each document it holds is then written whole
    /// beside the accepted one and renamed over it, so a reader, or an interruption, finds every
    /// document whole: the one that was accepted or the one that verified. A checkpoint caught at
    /// any point therefore holds every floor, no older than before, and never one generation's
    /// delegated documents beside the next's, so it counts no more than [`Self::publication_peak`]
    /// says. The working copy is left as it was, because the client goes on reading and writing its
    /// time checkpoint there while the verified generation's payloads are fetched.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when nothing was changed, and
    /// [`CatalogueError::PublicationUncertain`] when part of the checkpoint was, or when its
    /// directory did not confirm it.
    pub(crate) fn publish_checkpoint(
        &self,
        _permit: &Permit,
        working: &WorkingDatastore,
    ) -> CatalogueResult<()> {
        let layout = self.layout()?;
        let (accepted, staging) = (layout.datastore, layout.staging);
        let verified = files_in(&working.dir)?;
        let held = files_in(&accepted)?;
        let mut changed = 0usize;
        let stopped = |changed: usize, error: CatalogueError| {
            if changed == 0 {
                error
            } else {
                CatalogueError::PublicationUncertain {
                    detail: format!(
                        "{changed} documents of the trust checkpoint were changed before this \
                         failed: {error}"
                    ),
                }
            }
        };
        #[cfg(test)]
        let made_to_stop = |changed: usize| {
            publish_fault::stops_at(changed).then(|| CatalogueError::StorageUnavailable {
                detail: "the publication was made to stop".to_owned(),
            })
        };
        for relative in held.iter().filter(|relative| !verified.contains(*relative)) {
            #[cfg(test)]
            if let Some(error) = made_to_stop(changed) {
                return Err(stopped(changed, error));
            }
            let path = accepted.path.join(relative);
            let (directory, name) = accepted
                .parent_of(relative, false)
                .map_err(|error| stopped(changed, error))?;
            match directory.dir.remove_file(&name) {
                Ok(()) => changed += 1,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(stopped(changed, CatalogueError::storage(&path, &source)));
                }
            }
        }
        for relative in &verified {
            #[cfg(test)]
            if let Some(error) = made_to_stop(changed) {
                return Err(stopped(changed, error));
            }
            let from = working.dir.path.join(relative);
            let bytes = read_in(&working.dir, relative)
                .map_err(|source| stopped(changed, CatalogueError::storage(&from, &source)))?;
            rename_into_place(&staging, &accepted, relative, &bytes)
                .map_err(|error| stopped(changed, error))?;
            changed += 1;
        }
        flushed_after_publication(&accepted, &accepted.path, NameKind::File)
    }

    /// Returns the most the accepted checkpoint counts at any moment while `working` is published
    /// over it, against the retained metadata budget.
    ///
    /// Each document the working copy holds counts at the larger of its accepted and verified
    /// sizes, since an interruption can leave either, and the time the client saw counts at the
    /// most its document can hold. A document the working copy no longer holds is removed before
    /// anything is written, so it never stands beside what replaces it and is not counted.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when either copy cannot be read.
    pub fn publication_peak(&self, working: &WorkingDatastore) -> CatalogueResult<u64> {
        let accepted = self.datastore();
        let size = |path: PathBuf| match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => Ok(metadata.len()),
            Ok(_) => Ok(0),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(source) => Err(CatalogueError::storage(&path, &source)),
        };
        let mut peak = TIME_CHECKPOINT_BOUND;
        for relative in files_under(working.path())? {
            if relative == Path::new(TIME_CHECKPOINT) {
                continue;
            }
            let larger = size(working.path().join(&relative))?.max(size(accepted.join(&relative))?);
            peak = peak.saturating_add(larger);
        }
        Ok(peak)
    }

    /// Returns what this repository's accepted trust checkpoint counts against the retained
    /// metadata budget: every document it holds, with the time the client last saw counted at the
    /// most that document can hold.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the checkpoint cannot be read.
    pub fn checkpoint_bytes(&self) -> CatalogueResult<u64> {
        checkpoint_size(&self.datastore())
    }

    /// Returns every index document here, by the digest it is named by, with the bytes it holds.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the directory cannot be read.
    pub fn index_documents(&self) -> CatalogueResult<BTreeMap<PayloadDigest, u64>> {
        let directory = self.root.join("index");
        let mut held = BTreeMap::new();
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(held),
            Err(source) => return Err(CatalogueError::storage(&directory, &source)),
        };
        for entry in entries {
            let entry = entry.map_err(|source| CatalogueError::storage(&directory, &source))?;
            let Some(digest) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_suffix(".json"))
                .and_then(|name| PayloadDigest::parse(name).ok())
            else {
                continue;
            };
            let metadata = entry
                .metadata()
                .map_err(|source| CatalogueError::storage(&entry.path(), &source))?;
            if metadata.is_file() {
                held.insert(digest, metadata.len());
            }
        }
        Ok(held)
    }

    /// Removes the index documents of generations this repository no longer keeps.
    ///
    /// Nothing names them any more: the records that did were removed first, so a reader never
    /// finds a generation whose index is gone. A document somebody else already removed counts as
    /// removed.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the first removal fails, and
    /// [`CatalogueError::PublicationUncertain`] when a later one does.
    pub(crate) fn remove_index_documents(
        &self,
        _permit: &Permit,
        digests: &[PayloadDigest],
    ) -> CatalogueResult<()> {
        let layout = self.layout()?;
        let mut removed = 0usize;
        for digest in digests {
            let name = index_name(*digest);
            let path = layout.index.path.join(&name);
            match layout.index.dir.remove_file(&name) {
                Ok(()) => removed += 1,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) if removed == 0 => return Err(CatalogueError::storage(&path, &source)),
                Err(source) => {
                    return Err(CatalogueError::PublicationUncertain {
                        detail: format!(
                            "{removed} of {} index documents no generation keeps were removed and \
                             {} could not be: {source}",
                            digests.len(),
                            path.display()
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    /// Returns every package extracted here, by its manifest digest, with the bytes its files hold.
    ///
    /// Only a directory counts as a package; an entry of any other kind under `packages` is not
    /// one, and nothing is followed through a link.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when a package cannot be read.
    pub fn package_trees(&self) -> CatalogueResult<BTreeMap<PayloadDigest, u64>> {
        let directory = self.root.join("packages");
        let mut held = BTreeMap::new();
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(held),
            Err(source) => return Err(CatalogueError::storage(&directory, &source)),
        };
        for entry in entries {
            let entry = entry.map_err(|source| CatalogueError::storage(&directory, &source))?;
            let Some(digest) = entry
                .file_name()
                .to_str()
                .and_then(|name| PayloadDigest::parse(name).ok())
            else {
                continue;
            };
            let kind = entry
                .file_type()
                .map_err(|source| CatalogueError::storage(&entry.path(), &source))?;
            if kind.is_dir() {
                held.insert(digest, bytes_under(&entry.path())?);
            }
        }
        Ok(held)
    }

    /// Returns the directory an activated package sits in.
    #[must_use]
    pub fn package_dir(&self, manifest_digest: PayloadDigest) -> PathBuf {
        self.root.join("packages").join(manifest_digest.to_string())
    }

    /// Returns the file one cached payload sits in.
    #[must_use]
    pub fn payload_path(&self, digest: PayloadDigest) -> PathBuf {
        self.root.join("payloads").join(digest.to_string())
    }

    /// Returns true when the payload cached here is the payload the digest names.
    ///
    /// A file of the right name is not the same thing as the right bytes: a truncated or altered
    /// object left by an interrupted write would otherwise pass for a fetch nobody has to make
    /// again, and a mirror would call itself complete while holding rubbish. The declared length
    /// is checked first, so an object of the wrong size costs one `stat`; an object of the right
    /// size is read and hashed, because nothing cheaper distinguishes the right bytes from bytes
    /// of the same length. A caller that has already verified an object in this pass does not ask
    /// again.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the file is there and cannot be read.
    pub fn holds_payload(&self, digest: PayloadDigest, length: u64) -> CatalogueResult<bool> {
        let path = self.payload_path(digest);
        match std::fs::metadata(&path) {
            Ok(metadata) if metadata.len() != length => return Ok(false),
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(source) => return Err(CatalogueError::storage(&path, &source)),
        }
        match std::fs::read(&path) {
            Ok(bytes) => Ok(PayloadDigest::of(&bytes) == digest),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(CatalogueError::storage(&path, &source)),
        }
    }

    /// Returns what this store holds of one package, and the files it consists of where its own
    /// manifest, in the package's extracted copy, can say.
    ///
    /// A manifest that is not the one the package's hash names, or does not read, says nothing
    /// about what the package consists of.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the manifest, the extracted copy or the
    /// cached manifest is there and cannot be read.
    pub(crate) fn package_payloads(
        &self,
        manifest_digest: PayloadDigest,
    ) -> CatalogueResult<HeldPackage> {
        let directory = self.package_dir(manifest_digest);
        let path = directory.join(kr_plugin_sdk::package::MANIFEST_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                // No manifest to read. What is held of the package is its extracted copy, or its
                // manifest in the cache; with neither here, it is another store's.
                for held in [directory, self.payload_path(manifest_digest)] {
                    match std::fs::symlink_metadata(&held) {
                        Ok(_) => return Ok(HeldPackage::Unnamed),
                        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                        Err(source) => return Err(CatalogueError::storage(&held, &source)),
                    }
                }
                return Ok(HeldPackage::Absent);
            }
            Err(source) => return Err(CatalogueError::storage(&path, &source)),
        };
        if PayloadDigest::of(&bytes) != manifest_digest {
            return Ok(HeldPackage::Unnamed);
        }
        Ok(serde_json::from_slice::<PluginManifest>(&bytes).map_or(
            HeldPackage::Unnamed,
            |manifest| {
                HeldPackage::Named(
                    manifest
                        .payloads
                        .iter()
                        .map(|payload| payload.digest)
                        .collect(),
                )
            },
        ))
    }

    /// Checks an activated package against the manifest its digest names, file by file.
    ///
    /// The directory alone says a package was activated here once. The package hash *is* the
    /// manifest's hash and the manifest names every other file with its length and digest, so the
    /// manifest is read back and hashed first and then every file it declares is. A file that is
    /// gone and a file that holds other bytes are answers about the package; a file this host
    /// cannot read is a failure of its own disk, and is returned as one rather than as a package
    /// that is not here.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when a file is there and cannot be read.
    pub fn check_package(&self, manifest_digest: PayloadDigest) -> CatalogueResult<PackageCheck> {
        let directory = self.package_dir(manifest_digest);
        let manifest_path = directory.join(kr_plugin_sdk::package::MANIFEST_FILE);
        let bytes = match std::fs::read(&manifest_path) {
            Ok(bytes) => bytes,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PackageCheck::Missing {
                    detail: format!("the package {manifest_digest} is not activated here"),
                });
            }
            Err(source) => return Err(CatalogueError::storage(&manifest_path, &source)),
        };
        if PayloadDigest::of(&bytes) != manifest_digest {
            return Ok(PackageCheck::Corrupt {
                detail: format!(
                    "{} is not the manifest {manifest_digest} names",
                    manifest_path.display()
                ),
            });
        }
        // The bytes are the ones the package hash names, and those were validated when the package
        // was activated. Bytes that hash correctly and do not parse cannot have passed that, so
        // they are reported as a package that is not what it was.
        let manifest: PluginManifest = match serde_json::from_slice(&bytes) {
            Ok(manifest) => manifest,
            Err(source) => {
                return Ok(PackageCheck::Corrupt {
                    detail: format!("{} does not parse: {source}", manifest_path.display()),
                });
            }
        };
        for payload in &manifest.payloads {
            let path = directory.join(payload.path.as_str());
            let expected = payload.size_bytes.get();
            match std::fs::symlink_metadata(&path) {
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(PackageCheck::Missing {
                        detail: format!(
                            "{} declares {} and it is not here",
                            manifest_digest,
                            payload.path.as_str()
                        ),
                    });
                }
                Err(source) => return Err(CatalogueError::storage(&path, &source)),
                Ok(metadata) if !metadata.is_file() || metadata.len() != expected => {
                    return Ok(PackageCheck::Corrupt {
                        detail: format!(
                            "{} is not the {expected}-byte file {manifest_digest} declares",
                            path.display()
                        ),
                    });
                }
                Ok(_) => {}
            }
            let bytes =
                std::fs::read(&path).map_err(|source| CatalogueError::storage(&path, &source))?;
            if PayloadDigest::of(&bytes) != payload.digest {
                return Ok(PackageCheck::Corrupt {
                    detail: format!(
                        "{} is not the bytes {manifest_digest} declares",
                        path.display()
                    ),
                });
            }
        }
        Ok(PackageCheck::Complete(Box::new(ReadyPackage {
            digest: manifest_digest,
            manifest,
        })))
    }

    /// Reads the index of one accepted generation.
    ///
    /// This is the offline read: it touches no network, no payload and no metadata, because the
    /// whole snapshot is already here. It is also what keeps working when a repository's metadata
    /// expires, which blocks new generations and leaves this one alone.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the document cannot be read, and
    /// [`CatalogueError::Integrity`] when it is not the one the generation was accepted with.
    pub fn index(&self, active: &ActiveGeneration) -> CatalogueResult<CatalogueIndex> {
        #[cfg(test)]
        index_pause::run();
        let path = self.index_path(active.index_digest);
        let bytes =
            std::fs::read(&path).map_err(|source| CatalogueError::storage(&path, &source))?;
        if PayloadDigest::of(&bytes) != active.index_digest {
            return Err(CatalogueError::Integrity {
                detail: format!(
                    "{} is not the index generation {} was accepted with",
                    path.display(),
                    active.generation
                ),
            });
        }
        serde_json::from_slice(&bytes).map_err(|source| CatalogueError::Integrity {
            detail: format!("{}: {source}", path.display()),
        })
    }

    /// Returns the file one index document sits in.
    ///
    /// The document is named by its own digest, so a generation republished with different bytes
    /// is a different file and the pointer can never end up naming content it did not verify.
    #[must_use]
    pub fn index_path(&self, digest: PayloadDigest) -> PathBuf {
        self.root.join("index").join(index_name(digest))
    }

    /// Writes one verified generation's index, in its canonical rendering, under its own digest.
    ///
    /// The document is written and flushed before anything names it, so a row that later makes it
    /// current never names a document that is not completely on disk. Nothing else changes: the
    /// packages already installed stay installed, on the hashes they were installed at.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the document cannot be written.
    pub(crate) fn write_index(
        &self,
        _permit: &Permit,
        rendered: &[u8],
    ) -> CatalogueResult<(PayloadDigest, u64)> {
        let digest = PayloadDigest::of(rendered);
        let layout = self.layout()?;
        write_atomically(
            &layout.staging,
            &layout.index,
            Path::new(&index_name(digest)),
            rendered,
        )?;
        Ok((digest, rendered.len() as u64))
    }

    /// Caches one verified payload under its content hash.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::Integrity`] when the bytes are not the ones the digest names,
    /// and [`CatalogueError::StorageUnavailable`] when they cannot be written.
    pub(crate) fn cache_payload(
        &self,
        _permit: &Permit,
        digest: PayloadDigest,
        bytes: &[u8],
    ) -> CatalogueResult<()> {
        if PayloadDigest::of(bytes) != digest {
            return Err(CatalogueError::Integrity {
                detail: format!("the bytes offered for {digest} are not the bytes it names"),
            });
        }
        let layout = self.layout()?;
        write_atomically(
            &layout.staging,
            &layout.payloads,
            Path::new(&digest.to_string()),
            bytes,
        )
    }

    /// Reads one cached payload, which has to be the `length` bytes its digest names.
    ///
    /// The length is checked before anything is read. A cached object of another length is not
    /// the payload a declaration of `length` describes, whatever it hashes to, and its bytes are
    /// not read, or staged, on that declaration's word.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::UnavailableOffline`] when the payload is not cached here, which
    /// is the answer section 11 asks for rather than a capability that is not really there, and
    /// [`CatalogueError::Integrity`] when what is cached is not `length` bytes that hash to
    /// `digest`.
    pub fn read_payload(&self, digest: PayloadDigest, length: u64) -> CatalogueResult<Vec<u8>> {
        let path = self.payload_path(digest);
        match std::fs::metadata(&path) {
            Ok(metadata) if metadata.len() != length => {
                return Err(CatalogueError::Integrity {
                    detail: format!(
                        "{} is {} bytes and {digest} is declared as {length}",
                        path.display(),
                        metadata.len()
                    ),
                });
            }
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(CatalogueError::storage(&path, &source)),
        }
        match std::fs::read(&path) {
            Ok(bytes) if PayloadDigest::of(&bytes) == digest => Ok(bytes),
            Ok(_) => Err(CatalogueError::Integrity {
                detail: format!("{} is not the payload {digest} names", path.display()),
            }),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                Err(CatalogueError::UnavailableOffline {
                    detail: format!(
                        "the payload {digest} is not cached here, and it is fetched by content \
                         hash on an explicit install or enable or an already-authorised matching \
                         activation"
                    ),
                })
            }
            Err(source) => Err(CatalogueError::storage(&path, &source)),
        }
    }

    /// Starts staging one package.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the staging directory cannot be made.
    pub fn stage_package(&self, manifest_digest: PayloadDigest) -> CatalogueResult<StagedPackage> {
        // Each attempt stages into a directory of its own, created rather than reused. A shared
        // one would let a second attempt's incomplete contents be renamed into place by the first
        // attempt's activation, and would make an interrupted run's leftovers part of a set
        // nobody verified as a set.
        let layout = self.layout()?;
        let mut attempt = 0u32;
        loop {
            let name = format!("package-{manifest_digest}-{}-{attempt}", std::process::id());
            let path = layout.staging.path.join(&name);
            match layout.staging.dir.create_dir(&name) {
                Ok(()) => {
                    // From here the directory is removed again unless it is activated, whatever
                    // happens next.
                    let entry = StagingEntry::made(layout.staging, name);
                    return Ok(StagedPackage {
                        store: self.clone(),
                        dir: entry.open()?,
                        entry,
                        digest: manifest_digest,
                        written: BTreeMap::new(),
                    });
                }
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                    attempt = attempt.saturating_add(1);
                    if attempt > 1024 {
                        return Err(CatalogueError::storage(&path, &source));
                    }
                }
                Err(source) => return Err(CatalogueError::storage(&path, &source)),
            }
        }
    }

    /// Returns every cached payload and its size.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the cache cannot be read.
    pub fn cached_payloads(&self) -> CatalogueResult<BTreeMap<PayloadDigest, u64>> {
        let directory = self.root.join("payloads");
        let mut held = BTreeMap::new();
        let entries = std::fs::read_dir(&directory)
            .map_err(|source| CatalogueError::storage(&directory, &source))?;
        for entry in entries {
            let entry = entry.map_err(|source| CatalogueError::storage(&directory, &source))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(digest) = PayloadDigest::parse(&name) else {
                continue;
            };
            let metadata = entry
                .metadata()
                .map_err(|source| CatalogueError::storage(&entry.path(), &source))?;
            if metadata.is_file() {
                held.insert(digest, metadata.len());
            }
        }
        Ok(held)
    }

    /// Decides which cached payloads and extracted packages to remove so that `needed` more bytes
    /// fit, without touching `protected`.
    ///
    /// `protected` names every package an installation, a live binding or a pinned generation
    /// holds, by its manifest digest, and every payload such a package consists of. Section 11 says
    /// a sync never evicts those to finish, so a reclaim that would have to is a reclaim that
    /// refuses and names the resource instead. An extracted package nothing protects goes before a
    /// cached payload: it is a second copy of payloads, and having it again costs an extraction.
    /// Nothing is removed here: the plan is carried out by [`Self::remove`], under the permit the
    /// admitting authority lends.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceLimit`] naming the payload cache when what nothing protects is not
    /// enough, and [`CatalogueError::StorageUnavailable`] when the cache cannot be read.
    pub(crate) fn plan_reclaim(
        &self,
        needed: u64,
        ledger: &BudgetLedger,
        protected: &BTreeSet<PayloadDigest>,
        subject: &str,
    ) -> CatalogueResult<ReclaimPlan> {
        let mut ledger = ledger.clone();
        let mut plan = ReclaimPlan::default();
        if ledger
            .check_payload_bytes(needed, Stage::Declared, subject)
            .is_ok()
        {
            return Ok(plan);
        }
        let limit = ledger.budgets().payload_cache_bytes.get();
        let packages = self.package_trees()?;
        let payloads = self.cached_payloads()?;
        let evictable: Vec<(bool, PayloadDigest, u64)> = packages
            .iter()
            .map(|(digest, size)| (true, *digest, *size))
            .chain(
                payloads
                    .iter()
                    .map(|(digest, size)| (false, *digest, *size)),
            )
            .filter(|(_, digest, _)| !protected.contains(digest))
            .collect();
        let freeable = evictable
            .iter()
            .fold(0u64, |total, (_, _, size)| total.saturating_add(*size));
        let requested = ledger.payload_bytes().saturating_add(needed);
        if requested.saturating_sub(freeable) > limit {
            return Err(ResourceLimit {
                resource: Resource::PayloadCacheBytes,
                limit,
                requested,
                stage: Stage::Declared,
                subject: format!(
                    "{subject}; {} bytes are held by installed, live or pinned packages and are \
                     never evicted to finish a sync",
                    ledger.payload_bytes().saturating_sub(freeable)
                ),
            }
            .into());
        }
        for (package, digest, size) in evictable {
            if ledger
                .check_payload_bytes(needed, Stage::Declared, subject)
                .is_ok()
            {
                break;
            }
            if package {
                plan.packages.push((digest, size));
            } else {
                plan.payloads.push((digest, size));
            }
            ledger.remove_payload_bytes(size);
        }
        ledger.check_payload_bytes(needed, Stage::Declared, subject)?;
        Ok(plan)
    }

    /// Removes the extracted packages and the cached payloads a reclaim plan names.
    ///
    /// An extracted package leaves `packages` in one rename, into staging, and is deleted from
    /// there: a package is therefore either all there or gone, never part of one. A copy set aside
    /// that cannot be deleted stops the reclaim as uncertain, because its room is not free; what is
    /// left of it is removed when the store's lock is next taken. A cached payload is one file,
    /// removed in one step. Something somebody else already removed counts as
    /// removed. A failure before anything was removed leaves the store as it was; one after is
    /// [`CatalogueError::PublicationUncertain`], because part of the plan has already happened and
    /// cannot be reported as nothing.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the first removal fails, and
    /// [`CatalogueError::PublicationUncertain`] when a later one does.
    pub(crate) fn remove(&self, _permit: &Permit, plan: &ReclaimPlan) -> CatalogueResult<()> {
        let mut removed = 0usize;
        let total = plan.packages.len() + plan.payloads.len();
        let stopped = |removed: usize, path: &Path, source: &std::io::Error| {
            if removed == 0 {
                CatalogueError::storage(path, source)
            } else {
                CatalogueError::PublicationUncertain {
                    detail: format!(
                        "{removed} of {total} objects were removed to make room and {} could not \
                         be: {source}",
                        path.display()
                    ),
                }
            }
        };
        let layout = self.layout()?;
        for (digest, _) in &plan.packages {
            let name = digest.to_string();
            let path = layout.packages.path.join(&name);
            let set_aside = format!("removed-{digest}");
            let aside = layout.staging.path.join(&set_aside);
            match layout
                .packages
                .dir
                .rename(&name, &layout.staging.dir, &set_aside)
            {
                Ok(()) => removed += 1,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => return Err(stopped(removed, &path, &source)),
            }
            // The package is gone from where readers look, and its bytes are not free until the
            // copy set aside is gone too. One that stays is room this reclaim did not make.
            if let Err(source) = layout.staging.dir.remove_dir_all(&set_aside) {
                return Err(CatalogueError::PublicationUncertain {
                    detail: format!(
                        "{digest} was moved aside to make room and {} could not be removed, so \
                         the room it takes is not free: {source}",
                        aside.display()
                    ),
                });
            }
        }
        for (digest, _) in &plan.payloads {
            let name = digest.to_string();
            let path = layout.payloads.path.join(&name);
            match layout.payloads.dir.remove_file(&name) {
                Ok(()) => removed += 1,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => return Err(stopped(removed, &path, &source)),
            }
        }
        Ok(())
    }
}

/// The extracted packages and cached payloads one reclaim removes, decided before any of them is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReclaimPlan {
    packages: Vec<(PayloadDigest, u64)>,
    payloads: Vec<(PayloadDigest, u64)>,
}

impl ReclaimPlan {
    /// Returns true when nothing has to be removed.
    pub(crate) fn is_empty(&self) -> bool {
        self.packages.is_empty() && self.payloads.is_empty()
    }

    /// Returns how many extracted packages the plan removes.
    pub(crate) fn packages(&self) -> u64 {
        self.packages.len() as u64
    }

    /// Returns how many payloads the plan removes.
    pub(crate) fn payloads(&self) -> u64 {
        self.payloads.len() as u64
    }

    /// Returns how many bytes those packages and payloads hold.
    pub(crate) fn bytes(&self) -> u64 {
        self.packages
            .iter()
            .chain(&self.payloads)
            .fold(0u64, |total, (_, size)| total.saturating_add(*size))
    }

    /// Returns true when the plan removes the payload `digest`.
    #[cfg(test)]
    pub(crate) fn removes(&self, digest: PayloadDigest) -> bool {
        self.payloads.iter().any(|(named, _)| *named == digest)
    }

    /// Returns true when the plan removes the extracted package `digest`.
    #[cfg(test)]
    pub(crate) fn removes_package(&self, digest: PayloadDigest) -> bool {
        self.packages.iter().any(|(named, _)| *named == digest)
    }
}

/// A package being staged, which becomes visible only when every payload has verified.
#[derive(Debug)]
pub struct StagedPackage {
    /// The store the package is staged in, whose directories are opened again before each write.
    store: Store,
    /// The directory the package is staged into, held open while it is staged. Declared before
    /// `entry`, so it is closed before the directory is removed.
    dir: Area,
    /// Where the directory is in staging, which removes it unless it is activated.
    entry: StagingEntry,
    /// The package's hash, which names its directory once it is activated.
    digest: PayloadDigest,
    written: BTreeMap<String, u64>,
}

impl StagedPackage {
    /// Writes one verified file into the staging directory.
    ///
    /// `relative` is a [`kr_plugin_sdk::paths::PackagePath`], which is the proof that the package
    /// path rules were applied to it: it cannot escape the directory, name a device or spell a
    /// name two filesystems disagree about. The file is created rather than opened, so an existing
    /// name, including a link somebody put there, fails instead of being followed. The store's
    /// directories are opened again first, so one that became a link since staging started is
    /// refused, and the file is written through the staged directory's own handle.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::UnsafePackage`] when the name is already staged, and
    /// [`CatalogueError::StorageUnavailable`] when a directory it would be written through is a
    /// link or not a directory, or the bytes cannot be written.
    pub fn write(
        &mut self,
        relative: &kr_plugin_sdk::paths::PackagePath,
        bytes: &[u8],
    ) -> CatalogueResult<()> {
        let relative = relative.as_str();
        if self.written.contains_key(relative) {
            return Err(CatalogueError::UnsafePackage {
                detail: format!("{relative} appears twice in the package"),
            });
        }
        self.store.layout()?;
        let (directory, name) = self.dir.parent_of(Path::new(relative), true)?;
        create_in(&directory, Path::new(&name), bytes)?;
        self.written.insert(relative.to_owned(), bytes.len() as u64);
        Ok(())
    }

    /// Returns the directory this attempt is staging into.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.dir.path
    }

    /// Returns how many bytes have been staged.
    #[must_use]
    pub fn staged_bytes(&self) -> u64 {
        self.written
            .values()
            .fold(0u64, |total, size| total.saturating_add(*size))
    }

    /// Returns how many files have been staged.
    #[must_use]
    pub fn staged_files(&self) -> u64 {
        self.written.len() as u64
    }

    /// Makes the staged package the activated one.
    ///
    /// The staged package was checked as a whole before this. Where nothing is at the destination
    /// yet, the whole directory is renamed into place, so the package appears complete or not at
    /// all, and what arrives there is confirmed to be the directory that was staged. Where a
    /// package is already there, it failed its own check, and it is repaired where it lies: each
    /// file that does not hold the checked bytes is replaced by a rename of its own. The directory
    /// never disappears, a reader holding a file open keeps reading it, and a reader that opens a
    /// file by name finds either the file that was there or the checked one. The name alone never
    /// counts as the package.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when nothing was changed, a directory put in
    /// the staged one's place among it, and [`CatalogueError::PublicationUncertain`] when part of
    /// the package was replaced and the rest could not be, or when a directory did not confirm a
    /// rename.
    pub(crate) fn activate(self, _permit: &Permit) -> CatalogueResult<PathBuf> {
        // The store's directories are opened again here, just before the package moves from
        // staging into packages: what was opened when staging started says nothing about a link
        // put in their place since.
        let layout = self.store.layout()?;
        flush_tree(&self.dir)?;
        let name = self.digest.to_string();
        let destination = layout.packages.path.join(&name);
        match layout.packages.dir.symlink_metadata(&name) {
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                self.move_into_place(&layout.packages, &name)?;
            }
            Err(source) => return Err(CatalogueError::storage(&destination, &source)),
            Ok(metadata) if metadata.is_dir() => self.repair_in_place(&layout.packages)?,
            Ok(_) => {
                return Err(CatalogueError::StorageUnavailable {
                    detail: format!(
                        "{} is not a directory, and a package is not repaired over it",
                        destination.display()
                    ),
                });
            }
        }
        Ok(destination)
    }

    /// Renames the staged directory into `packages` as `name`, and confirms that what arrived there
    /// is the directory that was staged and checked.
    ///
    /// The staged directory's own handle is closed first. The store opens a directory without
    /// sharing its deletion, which on Windows keeps anything, this store included, from renaming a
    /// directory held that way. The rename then reaches the directory by its name in staging rather
    /// than through a handle, so the directory that arrives in `packages` is compared with the one
    /// staged by what identifies a directory on its volume whatever its name. A second handle on
    /// the staged directory, which does not keep it from being renamed, stays open until that
    /// comparison is made, so its number on its volume cannot pass to another directory meanwhile
    /// (see [`Kept`]). Anything else is moved out of `packages` again, into staging, where taking
    /// the store's lock next removes it, and the activation is refused: a directory put in the
    /// staged one's place is never left where readers look.
    fn move_into_place(self, packages: &Area, name: &str) -> CatalogueResult<()> {
        // Taken while the package is whole, so that a failure here drops it as a whole, its
        // directory's handle before the entry that removes the directory.
        let (kept, staged) = Kept::open(&self.dir)?;
        let Self { dir, mut entry, .. } = self;
        let destination = packages.path.join(name);
        let staged_path = dir.path.clone();
        drop(dir);
        #[cfg(test)]
        rename_pause::run();
        // On Windows a scanner can hold a file in the staged directory for a moment, and the rename
        // of a directory is refused while anything below it is held; it is tried again for a
        // bounded time. `kept` stays open through every attempt and the comparison after them.
        kr_flush::retry_while_held(|| {
            #[cfg(test)]
            attempt_pause::run();
            entry.staging.dir.rename(&entry.name, &packages.dir, name)
        })
        .map_err(|source| CatalogueError::storage(&destination, &source))?;
        entry.remove = false;
        let arrived = open_child(&packages.dir, &destination, Path::new(name))
            .and_then(|arrived| identity(&arrived));
        let same = arrived.as_ref().is_ok_and(|arrived| *arrived == staged);
        drop(kept);
        if same {
            return flushed_after_publication(packages, &destination, NameKind::Directory);
        }
        let refused = format!("{}.refused", entry.name);
        if let Err(source) = packages.dir.rename(name, &entry.staging.dir, &refused) {
            return Err(CatalogueError::PublicationUncertain {
                detail: format!(
                    "{} is not the directory that was staged and checked, and it could not be \
                     moved out of place again: {source}",
                    destination.display()
                ),
            });
        }
        // Moved out, and flushed so that a crash does not put it back where readers look.
        flush_directory(packages, NameKind::Directory).map_err(|error| {
            CatalogueError::PublicationUncertain {
                detail: format!(
                    "{} was not the directory that was staged and checked and was moved out of \
                     place again, and its directory did not confirm that: {error}",
                    destination.display()
                ),
            }
        })?;
        let what = match arrived {
            Ok(_) => "another directory".to_owned(),
            Err(error) => error.to_string(),
        };
        Err(CatalogueError::StorageUnavailable {
            detail: format!(
                "{} was not the directory that was staged and checked when it was renamed into \
                 place ({what}), so it was moved out again and nothing was activated",
                staged_path.display()
            ),
        })
    }

    /// Replaces, one rename at a time, every file of the package already in `packages` that does
    /// not hold the checked bytes.
    fn repair_in_place(&self, packages: &Area) -> CatalogueResult<()> {
        let name = self.digest.to_string();
        let package = open_child(&packages.dir, &packages.path.join(&name), Path::new(&name))?;
        // Every directory between the package and a file it declares has to be a directory, not a
        // link: a rename through a linked directory would write outside the package. The whole
        // package is checked before anything is replaced, so a refusal changes nothing. How many of
        // those directories are there already is kept: the rest are made by this repair.
        let mut present: BTreeMap<&str, usize> = BTreeMap::new();
        for relative in self.written.keys() {
            let mut directory = package.try_clone()?;
            let mut depth = 0;
            for component in Path::new(relative)
                .parent()
                .into_iter()
                .flat_map(Path::components)
            {
                let std::path::Component::Normal(part) = component else {
                    break;
                };
                match directory.dir.symlink_metadata(part) {
                    Err(source) if source.kind() == std::io::ErrorKind::NotFound => break,
                    Err(source) => {
                        return Err(CatalogueError::storage(&directory.path.join(part), &source));
                    }
                    Ok(_) => {
                        directory = open_child(
                            &directory.dir,
                            &directory.path.join(part),
                            Path::new(part),
                        )?;
                        depth += 1;
                    }
                }
            }
            present.insert(relative.as_str(), depth);
        }
        let mut replaced: Vec<PathBuf> = Vec::new();
        let stopped = |replaced: &[PathBuf], error: CatalogueError| {
            if replaced.is_empty() {
                error
            } else {
                CatalogueError::PublicationUncertain {
                    detail: format!(
                        "{} of the package's files were replaced before this failed: {error}",
                        replaced.len()
                    ),
                }
            }
        };
        // Every directory from a replaced file up to the package's own is flushed, each for the
        // kind of name it gained: a file's for the directory a file was renamed into, whatever else
        // it gained, and a directory's for one this repair made a directory in. A directory above
        // the file that gained nothing, because what is below it was there already, is flushed on
        // Unix as it always was, since a flush there asks nothing of the directory. On Windows a
        // flush opens the directory with the right to add to it, which such a directory may not
        // grant and which this repair did not use, so it is left alone.
        let mut touched: BTreeMap<PathBuf, (Area, Option<NameKind>)> = BTreeMap::new();
        for (relative, depth_present) in &present {
            let relative = Path::new(relative);
            let staged = self.dir.path.join(relative);
            let target = package.path.join(relative);
            let checked = read_in(&self.dir, relative)
                .map_err(|source| stopped(&replaced, CatalogueError::storage(&staged, &source)))?;
            // A file that holds the checked bytes is left where it is, so whoever is reading it is
            // not disturbed. A file that is missing, different or unreadable is replaced, and the
            // replacement is what reports whether that can be done.
            if read_in(&package, relative).is_ok_and(|held| held == checked) {
                continue;
            }
            let (from, file) = self
                .dir
                .parent_of(relative, false)
                .map_err(|error| stopped(&replaced, error))?;
            let (into, _) = package
                .parent_of(relative, true)
                .map_err(|error| stopped(&replaced, error))?;
            if let Err(source) =
                kr_flush::retry_while_held(|| from.dir.rename(&file, &into.dir, &file))
            {
                return Err(stopped(
                    &replaced,
                    CatalogueError::storage(&target, &source),
                ));
            }
            replaced.push(target);
            let mut directory = package
                .try_clone()
                .map_err(|error| stopped(&replaced, error))?;
            for (depth, component) in relative
                .parent()
                .into_iter()
                .flat_map(Path::components)
                .enumerate()
            {
                let next = open_child(
                    &directory.dir,
                    &directory.path.join(component),
                    Path::new(component.as_os_str()),
                )
                .map_err(|error| stopped(&replaced, error))?;
                let made_here = depth >= *depth_present;
                let (_, gained) = touched
                    .entry(directory.path.clone())
                    .or_insert((directory, None));
                if made_here && gained.is_none() {
                    *gained = Some(NameKind::Directory);
                }
                directory = next;
            }
            touched.insert(directory.path.clone(), (directory, Some(NameKind::File)));
        }
        for (directory, gained) in touched.values() {
            match gained {
                Some(kind) => flushed_after_publication(directory, &package.path, *kind)?,
                None if cfg!(unix) => {
                    flushed_after_publication(directory, &package.path, NameKind::Directory)?;
                }
                None => {}
            }
        }
        Ok(())
    }

    /// Discards the staged package.
    ///
    /// An interrupted package activation leaves the installed package usable, which is what this
    /// is for: nothing outside the staging directory was ever touched.
    pub fn abandon(self) {
        drop(self);
    }
}

/// What identifies a directory on its volume whatever its name: the volume's number and the
/// directory's own number on it, as the operating system reports them for the handle.
///
/// On Windows the directory's number is the 64-bit file index. NTFS gives every file its own;
/// ReFS numbers files with 128 bits and does not promise that the 64 reported here are unique, so
/// on a ReFS volume two directories could compare equal where they are not the same.
fn identity(directory: &Area) -> CatalogueResult<(u64, u64)> {
    use cap_fs_ext::MetadataExt as _;

    let metadata = directory
        .dir
        .dir_metadata()
        .map_err(|source| CatalogueError::storage(&directory.path, &source))?;
    Ok((metadata.dev(), metadata.ino()))
}

/// A second handle on a staged directory that keeps the directory's number on its volume its own
/// while the directory is renamed into place, and does not keep the rename from happening.
///
/// While a directory is open it cannot be removed for good, so no other directory is given its
/// number. On Unix this is a copy of the store's own handle, which a rename does not mind. On
/// Windows the store's handle shares no deletion and would refuse the rename, so this is a handle of
/// its own that shares everything and may only read the directory's attributes; it is opened by
/// the directory's name while the store's handle still holds the directory there, and checked to
/// be on the same directory.
#[derive(Debug)]
struct Kept {
    #[cfg(unix)]
    _dir: Dir,
    #[cfg(windows)]
    _file: cap_std::fs::File,
}

impl Kept {
    /// Opens the second handle on `directory` and returns it with what identifies the directory.
    fn open(directory: &Area) -> CatalogueResult<(Self, (u64, u64))> {
        #[cfg(test)]
        if kept_fault::fails() {
            return Err(CatalogueError::StorageUnavailable {
                detail: format!(
                    "{}: the second handle was made to fail",
                    directory.path.display()
                ),
            });
        }
        let staged = identity(directory)?;
        #[cfg(unix)]
        {
            let dir = directory
                .dir
                .try_clone()
                .map_err(|source| CatalogueError::storage(&directory.path, &source))?;
            Ok((Self { _dir: dir }, staged))
        }
        #[cfg(windows)]
        {
            use cap_fs_ext::MetadataExt as _;
            use std::os::windows::fs::OpenOptionsExt as _;

            /// The right to read a file's attributes, which is all this handle holds.
            const FILE_READ_ATTRIBUTES: u32 = 0x0080;
            /// Reading, writing and deleting are all shared with other handles.
            const FILE_SHARE_ALL: u32 = 0x0001 | 0x0002 | 0x0004;
            /// What lets a program open a directory at all.
            const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
            /// A link under the name is opened as the link rather than followed.
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

            let file = std::fs::OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_ALL)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&directory.path)
                .map_err(|source| CatalogueError::storage(&directory.path, &source))?;
            let file = cap_std::fs::File::from_std(file);
            let metadata = file
                .metadata()
                .map_err(|source| CatalogueError::storage(&directory.path, &source))?;
            if (metadata.dev(), metadata.ino()) != staged {
                return Err(CatalogueError::StorageUnavailable {
                    detail: format!(
                        "{} is not the directory the store holds under that name",
                        directory.path.display()
                    ),
                });
            }
            Ok((Self { _file: file }, staged))
        }
    }
}

/// Writes a document and requires its rename to be durable before it returns.
///
/// A failure before the rename leaves nothing changed. A flush that fails after it is
/// [`CatalogueError::PublicationUncertain`]: the new document is already what every reader sees,
/// and only whether its directory entry survives a power loss is in question.
fn write_atomically(
    staging: &Area,
    area: &Area,
    relative: &Path,
    bytes: &[u8],
) -> CatalogueResult<()> {
    let directory = rename_into_place(staging, area, relative, bytes)?;
    flushed_after_publication(&directory, &area.path.join(relative), NameKind::File)
}

/// Flushes the directory a publication renamed something into, for the kind of name it renamed.
///
/// The rename has happened by then, so a flush that fails does not undo anything: it leaves the
/// publication in place and its durability unconfirmed, which is an uncertain outcome rather than
/// a failure that changed nothing.
fn flushed_after_publication(
    directory: &Area,
    published: &Path,
    kind: NameKind,
) -> CatalogueResult<()> {
    flush_directory(directory, kind).map_err(|error| CatalogueError::PublicationUncertain {
        detail: format!(
            "{} is in place and its directory did not confirm it: {error}",
            published.display()
        ),
    })
}

/// Writes `bytes` into a temporary file in `staging` and renames it over the file `relative` names
/// below `area`, without flushing the directory, and returns the directory it renamed into.
///
/// Every directory between `area` and the file is opened without following a link, and made
/// where it is missing, so the document lands where it is named.
fn rename_into_place(
    staging: &Area,
    area: &Area,
    relative: &Path,
    bytes: &[u8],
) -> CatalogueResult<Area> {
    let (directory, name) = area.parent_of(relative, true)?;
    let label = name.to_str().unwrap_or("document").to_owned();
    // The temporary name is this writer's alone and is created rather than opened, so a name
    // another writer is using, or a link somebody left, fails instead of being written through.
    let mut attempt = 0u32;
    let (temporary, mut file) = loop {
        let candidate = format!("{label}.{}.{attempt}.writing", std::process::id());
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        match staging.dir.open_with(&candidate, &options) {
            Ok(file) => break (candidate, file),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                attempt = attempt.saturating_add(1);
                if attempt > 1024 {
                    return Err(CatalogueError::storage(
                        &staging.path.join(&candidate),
                        &source,
                    ));
                }
            }
            Err(source) => {
                return Err(CatalogueError::storage(
                    &staging.path.join(&candidate),
                    &source,
                ));
            }
        }
    };
    let written = staging.path.join(&temporary);
    file.write_all(bytes)
        .map_err(|source| CatalogueError::storage(&written, &source))?;
    file.sync_all()
        .map_err(|source| CatalogueError::storage(&written, &source))?;
    drop(file);
    kr_flush::retry_while_held(|| staging.dir.rename(&temporary, &directory.dir, &name)).map_err(
        |source| {
            let _ = staging.dir.remove_file(&temporary);
            CatalogueError::storage(&directory.path.join(&name), &source)
        },
    )?;
    Ok(directory)
}

/// Flushes a directory the store holds, so the names changed in it survive a power loss.
///
/// The directory is flushed through a second handle opened from the one held, never through its
/// name, so it is the directory the store holds whatever that name reaches by now. `kind` is the
/// name that changed in it, a file's or a directory's, which is the right that handle asks for on
/// Windows.
fn flush_directory(directory: &Area, kind: NameKind) -> CatalogueResult<()> {
    #[cfg(test)]
    if flush_fault::fails(&directory.path) {
        return Err(CatalogueError::StorageUnavailable {
            detail: format!("{}: the flush was made to fail", directory.path.display()),
        });
    }
    flush_held_directory(&directory.dir, kind)
        .map_err(|source| CatalogueError::storage(&directory.path, &source))
}

/// Where the unit tests make a checkpoint publication stop: after a number of documents were
/// replaced, or at the commit that records the reset it carries as settled.
#[cfg(test)]
pub(crate) mod publish_fault {
    use std::cell::Cell;

    thread_local! {
        static AFTER: Cell<Option<usize>> = const { Cell::new(None) };
        static RESET: Cell<bool> = const { Cell::new(false) };
    }

    /// Makes the next publications on this thread stop once `documents` documents were replaced.
    pub(crate) fn stop_after(documents: usize) {
        AFTER.with(|after| after.set(Some(documents)));
    }

    /// Makes the commit that settles a published checkpoint's reset fail on this thread.
    pub(crate) fn fail_reset() {
        RESET.with(|reset| reset.set(true));
    }

    /// Lets every publication go through again.
    pub(crate) fn clear() {
        AFTER.with(|after| after.set(None));
        RESET.with(|reset| reset.set(false));
    }

    pub(crate) fn stops_at(replaced: usize) -> bool {
        AFTER.with(|after| after.get() == Some(replaced))
    }

    pub(crate) fn reset_fails() -> bool {
        RESET.with(Cell::get)
    }
}

/// What the unit tests run just before an index document is opened, to reach a reader whose records
/// were read before a sync removed the document they name.
#[cfg(test)]
pub(crate) mod index_pause {
    use std::cell::RefCell;

    type Then = Box<dyn FnOnce()>;

    thread_local! {
        static BEFORE: RefCell<Option<Then>> = const { RefCell::new(None) };
    }

    /// Runs `then` once, the next time an index document is about to be opened on this thread.
    pub(crate) fn once(then: impl FnOnce() + 'static) {
        BEFORE.with(|before| *before.borrow_mut() = Some(Box::new(then)));
    }

    pub(crate) fn run() {
        if let Some(then) = BEFORE.with(|before| before.borrow_mut().take()) {
            then();
        }
    }
}

/// A staged package whose second handle the unit tests make fail, to reach an activation that
/// stops before anything is renamed.
#[cfg(test)]
pub(crate) mod kept_fault {
    use std::cell::Cell;

    thread_local! {
        static FAILING: Cell<bool> = const { Cell::new(false) };
    }

    /// Makes the next second handle on this thread fail.
    pub(crate) fn fail() {
        FAILING.with(|failing| failing.set(true));
    }

    pub(crate) fn fails() -> bool {
        FAILING.with(|failing| failing.replace(false))
    }
}

/// What the unit tests run before each attempt to rename a staged directory into place, given
/// the attempt's number from one, to act while the rename waits for a held file.
#[cfg(test)]
pub(crate) mod attempt_pause {
    use std::cell::{Cell, RefCell};

    type Then = Box<dyn FnMut(usize)>;

    thread_local! {
        static EACH: RefCell<Option<Then>> = const { RefCell::new(None) };
        static COUNT: Cell<usize> = const { Cell::new(0) };
    }

    /// Runs `then` before each attempt on this thread from now on, until [`clear`] is called.
    #[cfg(windows)]
    pub(crate) fn each(then: impl FnMut(usize) + 'static) {
        COUNT.with(|count| count.set(0));
        EACH.with(|each| *each.borrow_mut() = Some(Box::new(then)));
    }

    /// Stops running what [`each`] was given.
    #[cfg(windows)]
    pub(crate) fn clear() {
        EACH.with(|each| *each.borrow_mut() = None);
    }

    pub(crate) fn run() {
        let attempt = COUNT.with(|count| {
            count.set(count.get() + 1);
            count.get()
        });
        EACH.with(|each| {
            if let Some(then) = each.borrow_mut().as_mut() {
                then(attempt);
            }
        });
    }
}

/// What the unit tests run after a staged package closed its directory's handle and before it
/// renames the directory into place, to put another directory in the staged one's place.
#[cfg(test)]
pub(crate) mod rename_pause {
    use std::cell::RefCell;

    type Then = Box<dyn FnOnce()>;

    thread_local! {
        static BEFORE: RefCell<Option<Then>> = const { RefCell::new(None) };
    }

    /// Runs `then` once, the next time a staged package on this thread is about to be renamed
    /// into place.
    pub(crate) fn once(then: impl FnOnce() + 'static) {
        BEFORE.with(|before| *before.borrow_mut() = Some(Box::new(then)));
    }

    pub(crate) fn run() {
        if let Some(then) = BEFORE.with(|before| before.borrow_mut().take()) {
            then();
        }
    }
}

/// What the unit tests run after an operation opened the store and before it waits for the lock,
/// to reach a directory replaced while the operation waits. Only the Unix tests replace one, with
/// a symbolic link, so the hook exists only where they run.
#[cfg(all(test, unix))]
pub(crate) mod lock_pause {
    use std::cell::RefCell;

    type Then = Box<dyn FnOnce()>;

    thread_local! {
        static BEFORE: RefCell<Option<Then>> = const { RefCell::new(None) };
    }

    /// Runs `then` once, the next time an operation on this thread is about to wait for the lock.
    pub(crate) fn once(then: impl FnOnce() + 'static) {
        BEFORE.with(|before| *before.borrow_mut() = Some(Box::new(then)));
    }

    pub(crate) fn run() {
        if let Some(then) = BEFORE.with(|before| before.borrow_mut().take()) {
            then();
        }
    }
}

/// A directory whose flush the unit tests make fail, to reach what follows a rename that happened.
#[cfg(test)]
pub(crate) mod flush_fault {
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};

    thread_local! {
        static FAILING: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    }

    /// Makes every flush of `directory` on this thread fail until [`clear`] is called.
    pub(crate) fn fail(directory: &Path) {
        FAILING.with(|failing| *failing.borrow_mut() = Some(directory.to_path_buf()));
    }

    /// Lets every flush succeed again.
    pub(crate) fn clear() {
        FAILING.with(|failing| *failing.borrow_mut() = None);
    }

    pub(crate) fn fails(directory: &Path) -> bool {
        FAILING.with(|failing| failing.borrow().as_deref() == Some(directory))
    }
}

/// Flushes every directory in a directory tree, deepest first, following no link.
///
/// Each directory is flushed for the names made in it: a file's where it holds a file, and a
/// directory's where it holds directories alone.
fn flush_tree(directory: &Area) -> CatalogueResult<()> {
    let entries = directory
        .dir
        .entries()
        .map_err(|source| CatalogueError::storage(&directory.path, &source))?;
    let mut holds_file = false;
    for entry in entries {
        let entry = entry.map_err(|source| CatalogueError::storage(&directory.path, &source))?;
        let name = entry.file_name();
        let kind = entry
            .file_type()
            .map_err(|source| CatalogueError::storage(&directory.path.join(&name), &source))?;
        if kind.is_dir() {
            flush_tree(&open_child(
                &directory.dir,
                &directory.path.join(&name),
                Path::new(&name),
            )?)?;
        } else {
            holds_file = true;
        }
    }
    flush_directory(
        directory,
        if holds_file {
            NameKind::File
        } else {
            NameKind::Directory
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{Effect, Owner, committed};
    use kr_plugin_sdk::limits::RepositoryBudgets;
    use kr_protocol::ids::RepositoryGeneration;
    use kr_protocol::scalars::{TimestampMs, U64};

    fn store() -> (tempfile::TempDir, Store) {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let store = Store::open(directory.path(), &EnrolmentKey::generate().expect("a key"))
            .expect("an openable store");
        (directory, store)
    }

    /// Runs one write under the owner's own commit, which is the only way to hold a permit.
    fn owned<T>(write: impl FnOnce(&Permit) -> CatalogueResult<T>) -> CatalogueResult<T> {
        committed(&Owner::acting(), &Effect::Records, write)
    }

    fn accepted(
        generation: u64,
        (index_digest, index_bytes): (PayloadDigest, u64),
    ) -> ActiveGeneration {
        ActiveGeneration {
            generation,
            index_digest,
            index_bytes,
            entries: 0,
            versions: crate::trust::MetadataVersions::default(),
        }
    }

    fn path(text: &str) -> kr_plugin_sdk::paths::PackagePath {
        kr_plugin_sdk::paths::PackagePath::new(text).expect("a safe path")
    }

    fn index(generation: u64) -> CatalogueIndex {
        CatalogueIndex {
            index_version: kr_plugin_sdk::catalogue::INDEX_VERSION,
            generation: RepositoryGeneration::new(generation),
            produced_at: TimestampMs::new(1_760_000_000_000),
            publishers: Vec::new(),
            entries: Vec::new(),
        }
    }

    fn rendered(index: &CatalogueIndex) -> Vec<u8> {
        index
            .canonical_json()
            .expect("a renderable index")
            .into_bytes()
    }

    #[test]
    fn an_index_is_read_back_only_as_the_generation_it_was_accepted_with() {
        let (_directory, store) = store();
        let first = accepted(
            1,
            owned(|permit| store.write_index(permit, &rendered(&index(1)))).expect("written"),
        );
        assert_eq!(store.index(&first).expect("readable").generation.get(), 1);

        // A second generation's document beside it changes nothing about the first.
        let second = accepted(
            2,
            owned(|permit| store.write_index(permit, &rendered(&index(2)))).expect("written"),
        );
        assert_eq!(store.index(&first).expect("readable").generation.get(), 1);
        assert_eq!(store.index(&second).expect("readable").generation.get(), 2);

        // A document altered under its name is not the generation its digest names.
        std::fs::write(store.index_path(first.index_digest), b"{}").expect("writable");
        assert!(matches!(
            store.index(&first),
            Err(CatalogueError::Integrity { .. })
        ));
    }

    #[test]
    fn an_index_document_is_named_by_its_own_digest() {
        let (_directory, store) = store();
        let (first, _) =
            owned(|permit| store.write_index(permit, &rendered(&index(1)))).expect("written");
        // A second generation with different bytes is a different file, so a row can never end
        // up naming content this store did not verify.
        let mut changed = index(1);
        changed.produced_at = TimestampMs::new(1_760_000_100_000);
        let (second, _) =
            owned(|permit| store.write_index(permit, &rendered(&changed))).expect("written");
        assert_ne!(first, second);
        assert!(store.index_path(first).is_file());
        assert!(store.index_path(second).is_file());
    }

    #[test]
    fn a_package_becomes_visible_only_when_every_payload_verified() {
        let (_directory, store) = store();
        let digest = PayloadDigest::of(b"manifest");
        let mut staged = store.stage_package(digest).expect("a staging directory");
        staged
            .write(&path("plugin.json"), b"manifest")
            .expect("written");
        assert!(!store.package_dir(digest).exists());
        staged.abandon();
        assert!(!store.package_dir(digest).exists());

        let mut staged = store.stage_package(digest).expect("a staging directory");
        staged
            .write(&path("plugin.json"), b"manifest")
            .expect("written");
        staged
            .write(&path("presentation.json"), b"presentation")
            .expect("written");
        assert_eq!(staged.staged_files(), 2);
        let activated = owned(|permit| staged.activate(permit)).expect("activated");
        assert!(store.package_dir(digest).is_dir());
        assert_eq!(activated, store.package_dir(digest));
        assert_eq!(
            std::fs::read(activated.join("plugin.json")).expect("readable"),
            b"manifest"
        );
    }

    /// KR-REQ-11.06: a staged package's activation renames its directory by its name in staging,
    /// having closed the directory's own handle, so what arrives in `packages` is compared with the
    /// directory that was staged and checked. A directory put in the staged one's place in that
    /// moment, holding the very same file, is refused and moved out again: nothing is left where
    /// readers look, the staged directory is left as it was, and taking the store's lock clears
    /// what was moved out.
    #[test]
    fn a_directory_put_in_the_staged_ones_place_is_refused_and_not_left_in_place() {
        let (directory, store) = store();
        let digest = PayloadDigest::of(b"manifest");
        let mut staged = store.stage_package(digest).expect("a staging directory");
        staged
            .write(&path("plugin.json"), b"manifest")
            .expect("written");
        let (name, moved) = (staged.path().to_path_buf(), directory.path().join("moved"));
        let elsewhere = moved.clone();
        rename_pause::once(move || {
            std::fs::rename(&name, &elsewhere).expect("the staged directory is not held");
            std::fs::create_dir(&name).expect("another directory of the same name");
            std::fs::write(name.join("plugin.json"), b"manifest").expect("with the same file");
        });

        let refused = owned(|permit| staged.activate(permit))
            .expect_err("not the directory that was staged and checked");
        assert!(
            matches!(&refused, CatalogueError::StorageUnavailable { detail }
                if detail.contains("was not the directory that was staged and checked")),
            "{refused:?}"
        );
        assert!(
            !store.package_dir(digest).exists(),
            "nothing is left where readers look"
        );
        assert_eq!(
            std::fs::read(moved.join("plugin.json")).expect("readable"),
            b"manifest",
            "the staged directory is as it was"
        );
        let _lock = store.lock().expect("the store's lock");
        assert_eq!(
            std::fs::read_dir(store.root.join("staging"))
                .expect("readable")
                .count(),
            0,
            "what was moved out is cleared with the lock"
        );
    }

    /// An activation that stops before its rename, here because the second handle that keeps the
    /// staged directory's number is made to fail, drops the staged package whole: the directory's
    /// handle is closed before the directory is removed, which on Windows a directory held open
    /// refuses, so nothing is activated and nothing is left in staging.
    #[test]
    fn an_activation_that_stops_before_its_rename_leaves_nothing_in_staging() {
        let (_directory, store) = store();
        let digest = PayloadDigest::of(b"manifest");
        let mut staged = store.stage_package(digest).expect("a staging directory");
        staged
            .write(&path("plugin.json"), b"manifest")
            .expect("written");
        kept_fault::fail();
        let refused =
            owned(|permit| staged.activate(permit)).expect_err("stopped before its rename");
        assert!(
            matches!(refused, CatalogueError::StorageUnavailable { .. }),
            "{refused:?}"
        );
        assert!(!store.package_dir(digest).exists(), "nothing is activated");
        assert_eq!(
            std::fs::read_dir(store.root.join("staging"))
                .expect("readable")
                .count(),
            0,
            "nothing is left in staging"
        );
    }

    /// A working copy dropped once its verification is over, and a staged package abandoned, each
    /// leave nothing in staging: each closes its handle on its directory before the directory is
    /// removed, which on Windows a directory held open refuses.
    #[test]
    fn a_working_copy_or_an_abandoned_package_leaves_nothing_in_staging() {
        let (_directory, store) = store();
        let working = store.working_datastore(false).expect("a working copy");
        std::fs::write(working.path().join("root.json"), b"{}").expect("the client writes in it");
        drop(working);
        let mut staged = store
            .stage_package(PayloadDigest::of(b"abandoned"))
            .expect("a staging directory");
        staged
            .write(&path("plugin.json"), b"manifest")
            .expect("written");
        staged.abandon();
        assert_eq!(
            std::fs::read_dir(store.root.join("staging"))
                .expect("readable")
                .count(),
            0,
            "nothing is left in staging"
        );
    }

    /// Activates the example package, whose manifest declares one presentation file.
    fn activated_example(store: &Store) -> (PayloadDigest, PathBuf) {
        let (digest, activated) = activate_example(store);
        (digest, activated.expect("activated"))
    }

    /// Stages the example package and asks for it to be activated.
    fn activate_example(store: &Store) -> (PayloadDigest, CatalogueResult<PathBuf>) {
        let presentation = kr_plugin_sdk::example::example_presentation_json();
        let manifest = kr_plugin_sdk::example::example_manifest_for(presentation.as_bytes());
        let manifest_bytes = serde_json::to_vec(&manifest).expect("serialisable");
        let digest = PayloadDigest::of(&manifest_bytes);
        let mut staged = store.stage_package(digest).expect("a staging directory");
        staged
            .write(
                &path(kr_plugin_sdk::package::MANIFEST_FILE),
                &manifest_bytes,
            )
            .expect("written");
        staged
            .write(
                &path(kr_plugin_sdk::package::PRESENTATION_FILE),
                presentation.as_bytes(),
            )
            .expect("written");
        (digest, owned(|permit| staged.activate(permit)))
    }

    #[test]
    fn a_package_check_tells_absence_corruption_and_a_complete_package_apart() {
        let (_directory, store) = store();
        let (digest, directory) = activated_example(&store);
        let PackageCheck::Complete(ready) = store.check_package(digest).expect("readable") else {
            panic!("the activated package is complete");
        };
        assert_eq!(ready.digest(), digest);
        assert_eq!(
            serde_json::to_vec(ready.manifest()).expect("serialisable"),
            std::fs::read(directory.join(kr_plugin_sdk::package::MANIFEST_FILE)).expect("readable"),
            "the manifest it carries is the one the package hash names"
        );
        assert!(matches!(
            store
                .check_package(PayloadDigest::of(b"never activated"))
                .expect("readable"),
            PackageCheck::Missing { .. }
        ));

        let presentation = directory.join(kr_plugin_sdk::package::PRESENTATION_FILE);
        let original = std::fs::read(&presentation).expect("readable");
        std::fs::remove_file(&presentation).expect("removable");
        assert!(matches!(
            store.check_package(digest).expect("readable"),
            PackageCheck::Missing { .. }
        ));

        let mut altered = original.clone();
        altered[0] ^= 0x01;
        std::fs::write(&presentation, &altered).expect("writable");
        assert!(matches!(
            store.check_package(digest).expect("readable"),
            PackageCheck::Corrupt { .. }
        ));

        std::fs::write(&presentation, &original[..original.len() - 1]).expect("writable");
        assert!(matches!(
            store.check_package(digest).expect("readable"),
            PackageCheck::Corrupt { .. }
        ));

        std::fs::write(&presentation, &original).expect("writable");
        std::fs::write(directory.join(kr_plugin_sdk::package::MANIFEST_FILE), b"{}")
            .expect("writable");
        assert!(matches!(
            store.check_package(digest).expect("readable"),
            PackageCheck::Corrupt { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_package_file_this_host_cannot_read_is_a_storage_failure() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_directory, store) = store();
        let (digest, directory) = activated_example(&store);
        let presentation = directory.join(kr_plugin_sdk::package::PRESENTATION_FILE);
        std::fs::set_permissions(&presentation, std::fs::Permissions::from_mode(0o000))
            .expect("the file can be made unreadable");
        let outcome = store.check_package(digest);
        std::fs::set_permissions(&presentation, std::fs::Permissions::from_mode(0o600))
            .expect("readable again");
        assert!(
            matches!(outcome, Err(CatalogueError::StorageUnavailable { .. })),
            "{outcome:?}"
        );
    }

    /// A directory the layout makes is confirmed in the directory above it before anything is
    /// written into it. A refused confirmation fails the open and names that directory, and the
    /// directory it made stays unconfirmed, so the next open confirms it before it is used.
    #[test]
    fn a_directory_the_layout_makes_is_confirmed_in_its_parent_before_it_is_used() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let key = EnrolmentKey::generate().expect("a key");
        let store = Store::at(directory.path(), &key);

        // The layout makes the repository's own directory and then five directories in it.
        flush_fault::fail(&store.root);
        let refused = Store::open(directory.path(), &key);
        flush_fault::clear();
        let refused = refused.expect_err("an open whose new directories are not confirmed");
        assert!(
            matches!(refused, CatalogueError::StorageUnavailable { .. }),
            "{refused:?}"
        );
        assert!(
            refused
                .to_string()
                .contains(&store.root.display().to_string()),
            "names the directory: {refused}"
        );

        flush_fault::fail(&store.root);
        let again = Store::open(directory.path(), &key);
        flush_fault::clear();
        assert!(
            again.is_err(),
            "a directory whose confirmation was refused was used without being confirmed"
        );
        Store::open(directory.path(), &key).expect("confirmed by the next open");
    }

    /// Opening a layout already confirmed flushes nothing: every directory the layout's directories
    /// are in may refuse a flush, and the layout still opens.
    #[test]
    fn a_layout_already_confirmed_is_opened_without_a_flush() {
        let (directory, store) = store();
        let catalogue = normal(directory.path());
        for above in [
            catalogue.clone(),
            catalogue.join(REPOSITORIES),
            store.root.clone(),
        ] {
            flush_fault::fail(&above);
            let opened = store.layout();
            flush_fault::clear();
            opened.unwrap_or_else(|error| panic!("{}: {error}", above.display()));
        }
    }

    /// A directory a write makes below the directory it writes into is confirmed there before the
    /// write goes on, and a refused confirmation refuses the write.
    #[test]
    fn a_directory_a_write_makes_is_confirmed_in_its_parent_first() {
        let (_directory, store) = store();
        let mut staged = store
            .stage_package(PayloadDigest::of(b"nested"))
            .expect("a staging directory");
        let staging = staged.path().to_path_buf();
        flush_fault::fail(&staging);
        let refused = staged.write(&path("assets/icon.bin"), b"icon");
        flush_fault::clear();
        let refused = refused.expect_err("a write whose new directory is not confirmed");
        assert!(
            refused.to_string().contains(&staging.display().to_string()),
            "names the directory: {refused}"
        );
        staged
            .write(&path("assets/icon.bin"), b"icon")
            .expect("written once its directory is confirmed");
        assert_eq!(
            std::fs::read(staging.join("assets/icon.bin")).expect("written"),
            b"icon"
        );
    }

    #[test]
    fn a_publication_whose_directory_does_not_flush_is_uncertain_and_in_place() {
        let (_directory, store) = store();

        // A cached payload: renamed into place, then its directory does not flush.
        let digest = PayloadDigest::of(b"component");
        flush_fault::fail(&store.root.join("payloads"));
        let outcome = owned(|permit| store.cache_payload(permit, digest, b"component"));
        flush_fault::clear();
        assert!(
            matches!(outcome, Err(CatalogueError::PublicationUncertain { .. })),
            "{outcome:?}"
        );
        assert!(
            store.holds_payload(digest, 9).expect("readable"),
            "the renamed object is what readers see"
        );

        // An index document, the same way.
        flush_fault::fail(&store.root.join("index"));
        let outcome = owned(|permit| store.write_index(permit, &rendered(&index(1))));
        flush_fault::clear();
        assert!(
            matches!(outcome, Err(CatalogueError::PublicationUncertain { .. })),
            "{outcome:?}"
        );

        // A package moved into place, the same way.
        let presentation = kr_plugin_sdk::example::example_presentation_json();
        let manifest = kr_plugin_sdk::example::example_manifest_for(presentation.as_bytes());
        let manifest_bytes = serde_json::to_vec(&manifest).expect("serialisable");
        let package = PayloadDigest::of(&manifest_bytes);
        let mut staged = store.stage_package(package).expect("a staging directory");
        staged
            .write(
                &path(kr_plugin_sdk::package::MANIFEST_FILE),
                &manifest_bytes,
            )
            .expect("written");
        staged
            .write(
                &path(kr_plugin_sdk::package::PRESENTATION_FILE),
                presentation.as_bytes(),
            )
            .expect("written");
        flush_fault::fail(&store.root.join("packages"));
        let outcome = owned(|permit| staged.activate(permit));
        flush_fault::clear();
        assert!(
            matches!(outcome, Err(CatalogueError::PublicationUncertain { .. })),
            "{outcome:?}"
        );
        assert!(
            matches!(
                store.check_package(package).expect("readable"),
                PackageCheck::Complete(_)
            ),
            "the package is in place"
        );
    }

    #[test]
    fn a_write_that_fails_before_its_rename_publishes_nothing_and_is_a_storage_failure() {
        let (_directory, store) = store();
        let staging = store.root.join("staging");
        std::fs::remove_dir_all(&staging).expect("removable");
        std::fs::write(&staging, b"a file in the way").expect("writable");
        let digest = PayloadDigest::of(b"component");
        let outcome = owned(|permit| store.cache_payload(permit, digest, b"component"));
        assert!(
            matches!(outcome, Err(CatalogueError::StorageUnavailable { .. })),
            "{outcome:?}"
        );
        assert!(!store.holds_payload(digest, 9).expect("readable"));
    }

    #[test]
    fn an_activation_replaces_a_package_that_failed_its_check() {
        let (_directory, store) = store();
        let (digest, directory) = activated_example(&store);
        let presentation = directory.join(kr_plugin_sdk::package::PRESENTATION_FILE);
        std::fs::write(&presentation, b"altered").expect("writable");
        assert!(matches!(
            store.check_package(digest).expect("readable"),
            PackageCheck::Corrupt { .. }
        ));

        // The same package, staged and checked again, takes the place of the altered one rather
        // than being discarded because a directory of that name exists.
        let (again, _) = activated_example(&store);
        assert_eq!(again, digest);
        assert!(matches!(
            store.check_package(digest).expect("readable"),
            PackageCheck::Complete(_)
        ));
        let staging = store.root.join("staging");
        assert_eq!(
            std::fs::read_dir(&staging).expect("readable").count(),
            0,
            "nothing of either attempt is left in staging"
        );
    }

    #[test]
    fn a_repair_leaves_intact_files_and_their_readers_alone() {
        use std::io::Read as _;

        let (_directory, store) = store();
        let (digest, directory) = activated_example(&store);
        let manifest = directory.join(kr_plugin_sdk::package::MANIFEST_FILE);
        let expected = std::fs::read(&manifest).expect("readable");
        let mut reader = std::fs::File::open(&manifest).expect("a reader holds the manifest open");
        #[cfg(unix)]
        let before =
            std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&manifest).expect("readable"));
        std::fs::write(
            directory.join(kr_plugin_sdk::package::PRESENTATION_FILE),
            b"altered",
        )
        .expect("writable");

        let (again, repaired) = activated_example(&store);
        assert_eq!((again, &repaired), (digest, &directory));
        assert!(matches!(
            store.check_package(digest).expect("readable"),
            PackageCheck::Complete(_)
        ));
        #[cfg(unix)]
        assert_eq!(
            std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&manifest).expect("readable")),
            before,
            "the intact manifest is the same file it was"
        );
        let mut read = Vec::new();
        reader
            .read_to_end(&mut read)
            .expect("the open file still reads");
        assert_eq!(read, expected);
    }

    #[test]
    fn a_repair_that_cannot_replace_a_file_says_what_it_changed_and_is_tried_again() {
        let (_directory, store) = store();
        let (digest, directory) = activated_example(&store);
        let presentation = directory.join(kr_plugin_sdk::package::PRESENTATION_FILE);
        let manifest = directory.join(kr_plugin_sdk::package::MANIFEST_FILE);
        // A name no file rename replaces: a directory with something in it.
        std::fs::remove_file(&presentation).expect("removable");
        std::fs::create_dir_all(presentation.join("in the way")).expect("a directory");

        // Only the presentation needs replacing and it cannot be, so nothing changed.
        let (_, outcome) = activate_example(&store);
        assert!(
            matches!(outcome, Err(CatalogueError::StorageUnavailable { .. })),
            "{outcome:?}"
        );
        assert!(
            directory.is_dir(),
            "the package directory stays where it is"
        );

        // With the manifest altered too, the manifest is replaced first and the presentation still
        // cannot be: part of the repair happened, and the answer says so.
        std::fs::write(&manifest, b"altered").expect("writable");
        let (_, outcome) = activate_example(&store);
        assert!(
            matches!(outcome, Err(CatalogueError::PublicationUncertain { .. })),
            "{outcome:?}"
        );
        assert_ne!(std::fs::read(&manifest).expect("readable"), b"altered");

        // Once the obstruction is gone, the same repair completes in the same process.
        std::fs::remove_dir_all(&presentation).expect("removable");
        let (_, outcome) = activate_example(&store);
        outcome.expect("repaired");
        assert!(matches!(
            store.check_package(digest).expect("readable"),
            PackageCheck::Complete(_)
        ));
        assert_eq!(
            std::fs::read_dir(store.root.join("staging"))
                .expect("readable")
                .count(),
            0,
            "no attempt left anything in staging"
        );
    }

    /// Stages the example package with its presentation file in a nested directory too.
    fn stage_nested(store: &Store, digest: PayloadDigest) -> StagedPackage {
        let mut staged = store.stage_package(digest).expect("a staging directory");
        staged
            .write(&path(kr_plugin_sdk::package::MANIFEST_FILE), b"manifest")
            .expect("written");
        staged
            .write(&path("assets/icons/icon.bin"), b"icon")
            .expect("written");
        staged
    }

    #[cfg(unix)]
    #[test]
    fn a_repair_through_a_linked_directory_is_refused_and_changes_nothing() {
        let (directory, store) = store();
        let digest = PayloadDigest::of(b"nested");
        let staged = stage_nested(&store, digest);
        let package = owned(|permit| staged.activate(permit)).expect("activated");

        // The package's assets directory is replaced by a link to somewhere else.
        let elsewhere = directory.path().join("elsewhere");
        std::fs::create_dir_all(elsewhere.join("icons")).expect("a directory");
        std::fs::write(elsewhere.join("icons/icon.bin"), b"not the package's").expect("writable");
        std::fs::remove_dir_all(package.join("assets")).expect("removable");
        std::os::unix::fs::symlink(&elsewhere, package.join("assets")).expect("a link");

        let staged = stage_nested(&store, digest);
        let outcome = owned(|permit| staged.activate(permit));
        assert!(
            matches!(outcome, Err(CatalogueError::StorageUnavailable { .. })),
            "{outcome:?}"
        );
        assert_eq!(
            std::fs::read(elsewhere.join("icons/icon.bin")).expect("readable"),
            b"not the package's",
            "nothing outside the package was written"
        );
    }

    /// A staging directory replaced by a link while an operation waits for the lock is not cleared
    /// through the link. The operation clears the staging directory it opened before it waited,
    /// through that directory's own handle, and its next write refuses the link.
    #[cfg(unix)]
    #[test]
    fn a_staging_directory_linked_while_the_lock_is_awaited_is_not_cleared_through_it() {
        let (directory, store) = store();
        let staging = store.root.join("staging");
        let elsewhere = directory.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("a directory");
        std::fs::write(elsewhere.join("sentinel"), b"not the catalogue's").expect("writable");

        let held = store.lock().expect("the lock");
        // Left while the lock is held, after taking it cleared staging, so only the operation
        // that waits for the lock can clear it.
        std::fs::write(staging.join("left behind"), b"an operation stopped").expect("writable");
        let (reached, waiting) = std::sync::mpsc::channel();
        let other = store.clone();
        let waiter = std::thread::spawn(move || {
            lock_pause::once(move || reached.send(()).expect("told"));
            other.lock().map(drop)
        });
        waiting
            .recv()
            .expect("the other operation opened the store and waits for the lock");
        let aside = directory.path().join("aside");
        std::fs::rename(&staging, &aside).expect("moved aside");
        std::os::unix::fs::symlink(&elsewhere, &staging).expect("a link");
        assert!(
            aside.join("left behind").is_file(),
            "what was left is still there while the lock is held"
        );
        drop(held);
        waiter
            .join()
            .expect("joined")
            .expect("the lock, and the staging it opened cleared");

        assert!(
            elsewhere.join("sentinel").is_file(),
            "nothing was cleared through the link"
        );
        assert!(
            !aside.join("left behind").exists(),
            "the staging directory it opened was cleared"
        );
        let refusal = owned(|permit| store.write_index(permit, b"{}"))
            .expect_err("a link in place of staging");
        assert!(
            matches!(&refusal, CatalogueError::StorageUnavailable { detail }
                if detail.contains("is a link")),
            "{refusal:?}"
        );
    }

    /// A working copy or a staged package that goes away is removed from the staging directory it
    /// was made in, through that directory's handle, and never through a link put in its place.
    #[cfg(unix)]
    #[test]
    fn a_working_copy_or_a_staged_package_is_removed_only_from_the_staging_it_was_made_in() {
        for staged in [false, true] {
            let (directory, store) = store();
            let made: Box<dyn std::fmt::Debug> = if staged {
                let mut package = store
                    .stage_package(PayloadDigest::of(b"going"))
                    .expect("a staging directory");
                package
                    .write(&path(kr_plugin_sdk::package::MANIFEST_FILE), b"manifest")
                    .expect("written");
                Box::new(package)
            } else {
                Box::new(store.working_datastore(false).expect("a copy"))
            };
            // Elsewhere holds a directory of every name staging holds, as a link's target would
            // have to for a removal through it to reach anything.
            let staging = store.root.join("staging");
            let elsewhere = directory.path().join("elsewhere");
            for entry in std::fs::read_dir(&staging).expect("readable").flatten() {
                let same = elsewhere.join(entry.file_name());
                std::fs::create_dir_all(&same).expect("a directory");
                std::fs::write(same.join("sentinel"), b"not the catalogue's").expect("writable");
            }
            let before: Vec<_> = std::fs::read_dir(&elsewhere)
                .expect("readable")
                .flatten()
                .map(|entry| entry.path().join("sentinel"))
                .collect();
            assert_eq!(before.len(), 1, "staged: {staged}");
            let aside = directory.path().join("aside");
            std::fs::rename(&staging, &aside).expect("moved aside");
            std::os::unix::fs::symlink(&elsewhere, &staging).expect("a link");

            drop(made);

            for sentinel in &before {
                assert!(
                    sentinel.is_file(),
                    "staged: {staged}: removed through the link"
                );
            }
            assert_eq!(
                std::fs::read_dir(&aside).expect("readable").count(),
                0,
                "staged: {staged}: removed from the staging it was made in"
            );
        }
    }

    #[test]
    fn a_repaired_subtree_is_flushed_up_to_the_package() {
        let (_directory, store) = store();
        let digest = PayloadDigest::of(b"nested");
        let staged = stage_nested(&store, digest);
        let package = owned(|permit| staged.activate(permit)).expect("activated");

        // Every directory from the recreated file up to the package's own holds a new entry. A
        // directory the repair makes is confirmed in the one it is in before anything is renamed
        // into it, so a flush refused there refuses the repair before it replaces anything. The
        // file's own directory is flushed once the file is in it, so a flush refused there leaves
        // the file in place and whether it survives a crash unknown.
        for (failing, placed) in [
            (package.join("assets/icons"), true),
            (package.join("assets"), false),
            (package.clone(), false),
        ] {
            std::fs::remove_dir_all(package.join("assets")).expect("removable");
            let staged = stage_nested(&store, digest);
            flush_fault::fail(&failing);
            let outcome = owned(|permit| staged.activate(permit));
            flush_fault::clear();
            if placed {
                assert!(
                    matches!(outcome, Err(CatalogueError::PublicationUncertain { .. })),
                    "{}: {outcome:?}",
                    failing.display()
                );
                assert_eq!(
                    std::fs::read(package.join("assets/icons/icon.bin")).expect("in place"),
                    b"icon"
                );
            } else {
                assert!(
                    matches!(outcome, Err(CatalogueError::StorageUnavailable { .. })),
                    "{}: {outcome:?}",
                    failing.display()
                );
                assert!(
                    !package.join("assets/icons/icon.bin").exists(),
                    "{}: nothing was replaced",
                    failing.display()
                );
            }
        }

        // The next repair confirms what the refused one left unconfirmed, and places the file.
        let staged = stage_nested(&store, digest);
        owned(|permit| staged.activate(permit)).expect("repaired");
        assert_eq!(
            std::fs::read(package.join("assets/icons/icon.bin")).expect("in place"),
            b"icon"
        );
        for directory in [package.clone(), package.join("assets")] {
            let markers: Vec<_> = std::fs::read_dir(&directory)
                .expect("readable")
                .flatten()
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(UNCONFIRMED))
                .collect();
            assert!(markers.is_empty(), "{}: {markers:?}", directory.display());
        }
    }

    #[test]
    fn a_staged_file_that_cannot_be_read_after_a_replacement_is_uncertain() {
        let (_directory, store) = store();
        let (digest, directory) = activated_example(&store);
        let manifest = directory.join(kr_plugin_sdk::package::MANIFEST_FILE);
        std::fs::write(&manifest, b"altered").expect("writable");
        std::fs::write(
            directory.join(kr_plugin_sdk::package::PRESENTATION_FILE),
            b"altered",
        )
        .expect("writable");

        // The same package staged again, and its presentation lost from staging before the
        // repair reaches it: the manifest is replaced first, so part of the repair happened.
        let presentation = kr_plugin_sdk::example::example_presentation_json();
        let manifest_bytes = serde_json::to_vec(&kr_plugin_sdk::example::example_manifest_for(
            presentation.as_bytes(),
        ))
        .expect("serialisable");
        let mut staged = store.stage_package(digest).expect("a staging directory");
        staged
            .write(
                &path(kr_plugin_sdk::package::MANIFEST_FILE),
                &manifest_bytes,
            )
            .expect("written");
        staged
            .write(
                &path(kr_plugin_sdk::package::PRESENTATION_FILE),
                presentation.as_bytes(),
            )
            .expect("written");
        std::fs::remove_file(
            staged
                .path()
                .join(kr_plugin_sdk::package::PRESENTATION_FILE),
        )
        .expect("removable");
        let outcome = owned(|permit| staged.activate(permit));
        assert!(
            matches!(outcome, Err(CatalogueError::PublicationUncertain { .. })),
            "{outcome:?}"
        );
        assert_eq!(std::fs::read(&manifest).expect("readable"), manifest_bytes);
    }

    #[test]
    fn only_a_time_that_reads_back_and_is_later_replaces_the_kept_one() {
        let (_directory, store) = store();
        let kept = store.datastore().join(TIME_CHECKPOINT);
        let earlier = jiff::Timestamp::from_second(1_760_000_000).expect("a time");
        let later = jiff::Timestamp::from_second(1_760_000_600).expect("a time");
        let json = |time: jiff::Timestamp| serde_json::to_vec(&time).expect("serialisable");
        std::fs::write(&kept, json(later)).expect("writable");

        for (seen, replaces) in [
            (Vec::new(), false),
            (json(later)[..5].to_vec(), false),
            (json(earlier), false),
            (json(later), false),
            (
                json(jiff::Timestamp::from_second(1_760_001_200).expect("a time")),
                true,
            ),
        ] {
            let before = std::fs::read(&kept).expect("readable");
            let working = store.working_datastore(false).expect("a copy");
            std::fs::write(working.path().join(TIME_CHECKPOINT), &seen).expect("writable");
            owned(|permit| store.publish_time_checkpoint(permit, &working)).expect("kept");
            let after = std::fs::read(&kept).expect("readable");
            if replaces {
                assert_eq!(after, seen);
            } else {
                assert_eq!(after, before, "{:?}", String::from_utf8_lossy(&seen));
            }
        }
    }

    #[test]
    fn a_package_names_its_files_only_from_a_manifest_under_its_own_hash() {
        let (_directory, store) = store();
        let (digest, directory) = activated_example(&store);
        let presentation = kr_plugin_sdk::example::example_presentation_json();
        assert_eq!(
            store.package_payloads(digest).expect("readable"),
            HeldPackage::Named(vec![PayloadDigest::of(presentation.as_bytes())])
        );
        assert_eq!(
            store
                .package_payloads(PayloadDigest::of(b"never activated"))
                .expect("readable"),
            HeldPackage::Absent
        );
        // A manifest that reads, and names other files, but is not the one the hash names: another
        // release of the same package, written where this one's manifest was.
        let mut foreign = kr_plugin_sdk::example::example_manifest_for(presentation.as_bytes());
        foreign.version =
            kr_plugin_sdk::version::PackageVersion::parse("9.9.9").expect("a version");
        foreign.payloads[0].digest = PayloadDigest::of(b"another component");
        let foreign = serde_json::to_vec(&foreign).expect("serialisable");
        assert!(serde_json::from_slice::<PluginManifest>(&foreign).is_ok());
        assert_ne!(PayloadDigest::of(&foreign), digest);
        std::fs::write(
            directory.join(kr_plugin_sdk::package::MANIFEST_FILE),
            &foreign,
        )
        .expect("writable");
        assert_eq!(
            store.package_payloads(digest).expect("readable"),
            HeldPackage::Unnamed,
            "a manifest that is not the one its hash names says nothing, however well it reads"
        );
        std::fs::write(
            directory.join(kr_plugin_sdk::package::MANIFEST_FILE),
            b"altered",
        )
        .expect("writable");
        assert_eq!(
            store.package_payloads(digest).expect("readable"),
            HeldPackage::Unnamed,
            "a manifest that is not the one its hash names says nothing"
        );
        // An extracted copy without its manifest, and a manifest only in the cache, are both held
        // here, and neither says what the package consists of.
        std::fs::remove_file(directory.join(kr_plugin_sdk::package::MANIFEST_FILE))
            .expect("removable");
        assert_eq!(
            store.package_payloads(digest).expect("readable"),
            HeldPackage::Unnamed
        );
        std::fs::remove_dir_all(&directory).expect("removable");
        assert_eq!(
            store.package_payloads(digest).expect("readable"),
            HeldPackage::Absent
        );
        let manifest = kr_plugin_sdk::example::example_manifest_for(presentation.as_bytes());
        let manifest = serde_json::to_vec(&manifest).expect("serialisable");
        let cached = PayloadDigest::of(&manifest);
        std::fs::write(store.payload_path(cached), &manifest).expect("writable");
        assert_eq!(
            store.package_payloads(cached).expect("readable"),
            HeldPackage::Unnamed
        );
    }

    #[test]
    fn a_staged_name_is_created_and_never_followed() {
        let (_directory, store) = store();
        let digest = PayloadDigest::of(b"twice");
        let mut staged = store.stage_package(digest).expect("a staging directory");
        staged.write(&path("plugin.json"), b"one").expect("written");
        let refusal = staged
            .write(&path("plugin.json"), b"two")
            .expect_err("the same name twice");
        assert!(matches!(refusal, CatalogueError::UnsafePackage { .. }));
    }

    #[test]
    fn an_uncached_payload_is_unavailable_offline_and_not_a_pretend_capability() {
        let (_directory, store) = store();
        let digest = PayloadDigest::of(b"component");
        let refusal = store.read_payload(digest, 9).expect_err("not cached");
        assert_eq!(
            refusal.code(),
            kr_protocol::error::ErrorCode::PackageUnavailableOffline
        );
        owned(|permit| store.cache_payload(permit, digest, b"component")).expect("cacheable");
        assert_eq!(store.read_payload(digest, 9).expect("cached"), b"component");
        // The same bytes asked for at another length are not the payload that length describes.
        for length in [8, 10] {
            assert!(matches!(
                store.read_payload(digest, length),
                Err(CatalogueError::Integrity { .. })
            ));
        }
    }

    #[test]
    fn caching_bytes_that_are_not_the_digest_is_refused() {
        let (_directory, store) = store();
        let refusal =
            owned(|permit| store.cache_payload(permit, PayloadDigest::of(b"one"), b"two"))
                .expect_err("a mismatched digest");
        assert!(matches!(refusal, CatalogueError::Integrity { .. }));
    }

    #[test]
    fn reclaiming_never_evicts_a_live_bound_or_pinned_payload() {
        let (_directory, store) = store();
        let mut budgets = RepositoryBudgets::defaults();
        budgets.payload_cache_bytes = U64::new(32);
        let mut ledger = BudgetLedger::new(budgets);

        let live = PayloadDigest::of(b"live");
        let spare = PayloadDigest::of(b"spare");
        owned(|permit| store.cache_payload(permit, live, b"live")).expect("cacheable");
        owned(|permit| store.cache_payload(permit, spare, b"spare")).expect("cacheable");
        ledger.add_payload_bytes(9);

        let mut protected = BTreeSet::new();
        protected.insert(live);

        // Five bytes of spare payload are enough to make room for twenty-four more.
        let plan = store
            .plan_reclaim(24, &ledger, &protected, "component.wasm")
            .expect("room can be made");
        assert!(plan.removes(spare) && !plan.removes(live), "{plan:?}");
        assert!(
            store.holds_payload(spare, 5).expect("a readable store"),
            "a plan removes nothing by itself"
        );
        owned(|permit| store.remove(permit, &plan)).expect("the spare payload is evicted");
        assert!(
            store.holds_payload(live, 4).expect("a readable store"),
            "a live-bound payload is kept"
        );
        assert!(!store.holds_payload(spare, 5).expect("a readable store"));

        // Nothing unprotected is left, so the refusal names the resource rather than taking the
        // live-bound payload.
        let mut ledger = BudgetLedger::new(ledger.budgets());
        ledger.add_payload_bytes(4 + 24);
        let refusal = store
            .plan_reclaim(24, &ledger, &protected, "component.wasm")
            .expect_err("nothing else may be evicted");
        let message = refusal.to_string();
        assert!(message.contains("payload_cache_bytes"), "{message}");
        assert!(message.contains("never evicted"), "{message}");
        assert!(store.holds_payload(live, 4).expect("a readable store"));
    }

    #[test]
    fn an_extracted_package_counts_and_goes_before_a_cached_payload_when_nothing_holds_it() {
        let (_directory, store) = store();
        let (kept, kept_dir) = activated_example(&store);
        let kept_bytes = *store
            .package_trees()
            .expect("a readable store")
            .get(&kept)
            .expect("the package is here");
        assert!(kept_bytes > 0);
        // A second extracted package nothing holds, and one cached payload nothing holds.
        let spare = PayloadDigest::of(b"a package nobody holds");
        let spare_dir = store.package_dir(spare);
        std::fs::create_dir_all(spare_dir.join("assets")).expect("a directory");
        std::fs::write(spare_dir.join("assets").join("icon.bin"), [0u8; 20]).expect("writable");
        let cached = PayloadDigest::of(b"cached");
        owned(|permit| store.cache_payload(permit, cached, b"cached")).expect("cacheable");
        // Something at `packages` that is not a directory is not a package.
        std::fs::write(
            store.package_dir(PayloadDigest::of(b"not a package")),
            b"a file",
        )
        .expect("writable");
        let trees = store.package_trees().expect("a readable store");
        assert_eq!(trees.get(&spare), Some(&20));
        assert_eq!(trees.len(), 2, "{trees:?}");

        let held = kept_bytes + 20 + 6;
        let mut budgets = RepositoryBudgets::defaults();
        budgets.payload_cache_bytes = U64::new(held);
        let mut ledger = BudgetLedger::new(budgets);
        ledger.add_payload_bytes(held);
        let protected: BTreeSet<PayloadDigest> = [kept].into_iter().collect();

        // Room for twenty bytes takes the package nobody holds and leaves the cached payload.
        let plan = store
            .plan_reclaim(20, &ledger, &protected, "a package")
            .expect("room can be made");
        assert!(
            plan.removes_package(spare) && !plan.removes(cached),
            "{plan:?}"
        );
        assert!(!plan.removes_package(kept), "{plan:?}");
        owned(|permit| store.remove(permit, &plan)).expect("removed");
        assert!(!spare_dir.exists());
        assert!(
            kept_dir
                .join(kr_plugin_sdk::package::MANIFEST_FILE)
                .is_file()
        );

        // Room for one byte more than both unprotected objects hold names the resource and
        // removes nothing a package that is held needs.
        let refusal = store
            .plan_reclaim(27, &ledger, &protected, "a package")
            .expect_err("the held package is never evicted");
        assert!(refusal.to_string().contains("never evicted"), "{refusal}");
    }

    #[test]
    fn an_index_document_nothing_keeps_is_removed_and_only_named_documents_count() {
        let (_directory, store) = store();
        let (first, first_bytes) =
            owned(|permit| store.write_index(permit, &rendered(&index(1)))).expect("written");
        let (second, _) =
            owned(|permit| store.write_index(permit, &rendered(&index(2)))).expect("written");
        std::fs::write(store.root.join("index").join("notes.txt"), b"not an index")
            .expect("writable");
        let held = store.index_documents().expect("a readable store");
        assert_eq!(held.len(), 2, "{held:?}");
        assert_eq!(held.get(&first), Some(&first_bytes));
        owned(|permit| store.remove_index_documents(permit, &[first, first]))
            .expect("a document removed twice is removed");
        let held = store.index_documents().expect("a readable store");
        assert!(!held.contains_key(&first) && held.contains_key(&second));
    }

    /// Leaves a staged package as an operation that stopped leaves it: its directory stays in
    /// staging, since nothing ran to remove it, and every handle it held is closed, as the
    /// operating system closes a stopped process's handles.
    fn stopped(staged: StagedPackage) {
        let StagedPackage { dir, mut entry, .. } = staged;
        drop(dir);
        entry.remove = false;
    }

    #[test]
    fn taking_the_lock_clears_what_an_operation_that_stopped_left_in_staging() {
        let (_directory, store) = store();
        let staged = store
            .stage_package(PayloadDigest::of(b"left behind"))
            .expect("staged");
        let left = staged.path().to_path_buf();
        stopped(staged);
        let temporary = store.root.join("staging").join("index.json.partial");
        std::fs::write(&temporary, b"half a document").expect("writable");
        assert!(left.is_dir() && temporary.is_file());
        let lock = store.lock().expect("the store's lock");
        assert!(!left.exists() && !temporary.exists());
        // What the holder stages afterwards is its own and stays until it is done with it.
        let mine = store
            .stage_package(PayloadDigest::of(b"mine"))
            .expect("staged");
        assert!(mine.path().is_dir());
        drop(lock);
    }

    #[cfg(unix)]
    #[test]
    fn staging_that_cannot_be_cleared_stops_the_operation_that_took_the_lock() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_directory, store) = store();
        let staged = store
            .stage_package(PayloadDigest::of(b"left behind"))
            .expect("staged");
        let held = staged.path().join("assets");
        stopped(staged);
        std::fs::create_dir_all(&held).expect("a directory");
        std::fs::write(held.join("icon.bin"), [0u8; 8]).expect("writable");
        std::fs::set_permissions(&held, std::fs::Permissions::from_mode(0o555)).expect("read-only");
        let refusal = store.lock().expect_err("staging cannot be cleared");
        std::fs::set_permissions(&held, std::fs::Permissions::from_mode(0o755))
            .expect("writable again");
        assert!(
            matches!(&refusal, CatalogueError::StorageUnavailable { detail } if detail.contains("left in staging")),
            "{refusal:?}"
        );
        let _lock = store.lock().expect("staging clears once it can");
        assert_eq!(
            std::fs::read_dir(store.root.join("staging"))
                .expect("readable")
                .count(),
            0
        );
    }

    #[test]
    fn the_checkpoint_counts_every_document_and_the_time_at_its_most() {
        let (_directory, store) = store();
        assert_eq!(
            store.checkpoint_bytes().expect("a readable store"),
            TIME_CHECKPOINT_BOUND
        );
        std::fs::write(store.datastore().join("root.json"), [0u8; 40]).expect("writable");
        std::fs::create_dir_all(store.datastore().join("roles")).expect("a directory");
        std::fs::write(
            store.datastore().join("roles").join("vendor.json"),
            [0u8; 2],
        )
        .expect("writable");
        assert_eq!(
            store.checkpoint_bytes().expect("a readable store"),
            42 + TIME_CHECKPOINT_BOUND
        );
        // However long the time the client wrote, it counts the same.
        for time in [
            "\"2026-09-24T10:06:12Z\"",
            "\"2026-09-24T10:06:12.123456789Z\"",
        ] {
            std::fs::write(store.datastore().join(TIME_CHECKPOINT), time).expect("writable");
            assert_eq!(
                store.checkpoint_bytes().expect("a readable store"),
                42 + TIME_CHECKPOINT_BOUND
            );
        }
    }

    #[test]
    fn a_reclaim_that_fails_part_way_is_uncertain_and_one_that_fails_first_removed_nothing() {
        let (_directory, store) = store();
        let first = PayloadDigest::of(b"first");
        let second = PayloadDigest::of(b"second");
        owned(|permit| store.cache_payload(permit, first, b"first")).expect("cacheable");
        // A name no file removal takes away: a directory where the payload would be.
        std::fs::create_dir_all(store.payload_path(second).join("inside")).expect("a directory");

        let plan = ReclaimPlan {
            packages: Vec::new(),
            payloads: vec![(first, 5), (second, 6)],
        };
        let outcome = owned(|permit| store.remove(permit, &plan));
        assert!(
            matches!(outcome, Err(CatalogueError::PublicationUncertain { .. })),
            "part of the plan happened: {outcome:?}"
        );
        assert!(!store.holds_payload(first, 5).expect("a readable store"));

        let plan = ReclaimPlan {
            packages: Vec::new(),
            payloads: vec![(second, 6)],
        };
        let outcome = owned(|permit| store.remove(permit, &plan));
        assert!(
            matches!(outcome, Err(CatalogueError::StorageUnavailable { .. })),
            "nothing of the plan happened: {outcome:?}"
        );
    }

    #[test]
    fn an_extracted_package_is_removed_whole_or_not_at_all() {
        let (_directory, store) = store();
        let tree = |name: &[u8]| {
            let digest = PayloadDigest::of(name);
            let directory = store.package_dir(digest);
            std::fs::create_dir_all(directory.join("assets")).expect("a directory");
            std::fs::write(directory.join("plugin.json"), b"{}").expect("writable");
            std::fs::write(directory.join("assets").join("icon.bin"), [0u8; 8]).expect("writable");
            digest
        };
        let whole = |digest: PayloadDigest| {
            let directory = store.package_dir(digest);
            directory.join("plugin.json").is_file()
                && directory.join("assets").join("icon.bin").is_file()
        };
        let (first, second) = (tree(b"first"), tree(b"second"));
        // A name the second package cannot be renamed to: a directory with something in it.
        let blocked = store.root.join("staging").join(format!("removed-{second}"));
        std::fs::create_dir_all(blocked.join("left")).expect("a directory");
        let plan = |packages: &[PayloadDigest]| ReclaimPlan {
            packages: packages.iter().map(|digest| (*digest, 10)).collect(),
            payloads: Vec::new(),
        };

        let outcome = owned(|permit| store.remove(permit, &plan(&[second])));
        assert!(
            matches!(outcome, Err(CatalogueError::StorageUnavailable { .. })),
            "nothing of the plan happened: {outcome:?}"
        );
        assert!(whole(second));

        let outcome = owned(|permit| store.remove(permit, &plan(&[first, second])));
        assert!(
            matches!(outcome, Err(CatalogueError::PublicationUncertain { .. })),
            "part of the plan happened: {outcome:?}"
        );
        assert!(!store.package_dir(first).exists(), "the first went whole");
        assert!(
            !store
                .root
                .join("staging")
                .join(format!("removed-{first}"))
                .exists(),
            "and nothing of it is left aside"
        );
        assert!(whole(second), "the second is still whole");
    }

    #[test]
    fn a_cached_object_that_lost_its_bytes_is_not_held() {
        let (_directory, store) = store();
        let digest = PayloadDigest::of(b"component");
        owned(|permit| store.cache_payload(permit, digest, b"component")).expect("cacheable");
        assert!(
            store
                .holds_payload(digest, 9)
                .expect("a readable store, and the bytes it named"),
        );

        // The same name, the wrong length: an interrupted write leaves exactly this.
        std::fs::write(store.payload_path(digest), b"compon").expect("a truncated object");
        assert!(!store.holds_payload(digest, 9).expect("a readable store"));

        // The right length and the wrong bytes costs a hash to catch, and is caught.
        std::fs::write(store.payload_path(digest), b"comPonent").expect("an altered object");
        assert!(!store.holds_payload(digest, 9).expect("a readable store"));
    }

    #[test]
    fn exclusive_lock_contention_refuses_concurrent_lock() {
        let (_directory, store) = store();
        let _lock1 = store.lock().expect("first lock");
        // On Unix the lock is an advisory `flock`, which a second `lock` would wait on, so the
        // contention is asked without waiting.
        #[cfg(unix)]
        {
            use rustix::fs::{FlockOperation, flock};
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(store.root.join(".lock"))
                .expect("open lockfile");
            let err = flock(&file, FlockOperation::NonBlockingLockExclusive).unwrap_err();
            assert_eq!(err, rustix::io::Errno::WOULDBLOCK);
        }
        // On Windows the lock is the open itself, shared with nobody, so a second `lock` is
        // refused at once with a sharing violation.
        #[cfg(windows)]
        {
            const ERROR_SHARING_VIOLATION: i32 = 32;
            match store.lock() {
                Err(CatalogueError::StorageUnavailable { detail }) => assert!(
                    detail.ends_with(&format!("(os error {ERROR_SHARING_VIOLATION})")),
                    "refused for another reason: {detail}"
                ),
                Err(other) => panic!("refused for another reason: {other:?}"),
                Ok(_) => panic!("a second lock was granted while the first was held"),
            }
        }
    }

    /// Holds a directory through a handle that shares no writing with any other.
    ///
    /// A name can still be created or removed in the directory while it is held, since that opens
    /// the name rather than the directory, but nothing can open the directory itself with a right
    /// to add to it, which is what a flush of it has to do on Windows.
    #[cfg(windows)]
    fn hold_without_shared_writing(directory: &Path) -> std::fs::File {
        use std::os::windows::fs::OpenOptionsExt as _;

        /// The right to list a directory, which is all the handle holds.
        const FILE_LIST_DIRECTORY: u32 = 0x0001;
        /// Reading is shared with other handles.
        const FILE_SHARE_READ: u32 = 0x0001;
        /// Deleting is shared; writing is not.
        const FILE_SHARE_DELETE: u32 = 0x0004;
        /// What lets a program open a directory at all.
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

        std::fs::OpenOptions::new()
            .access_mode(FILE_LIST_DIRECTORY)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(directory)
            .expect("the directory is held")
    }

    /// KR-REQ-11.06: a staged package is flushed, every directory of its tree, before it is renamed
    /// into place, each through a second handle opened from the one the store holds. While a
    /// handle that shares no writing holds one of those directories, the activation is refused by
    /// that directory's flush, before the rename, and nothing is activated; once that handle is let
    /// go, every directory of a staged tree is flushed.
    #[cfg(windows)]
    #[test]
    fn a_package_whose_staged_tree_cannot_be_flushed_is_not_activated() {
        let (_directory, store) = store();
        let digest = PayloadDigest::of(b"manifest");
        let stage = || {
            let mut staged = store.stage_package(digest).expect("a staging directory");
            staged
                .write(&path("plugin.json"), b"manifest")
                .expect("written");
            staged
                .write(&path("assets/icon.txt"), b"icon")
                .expect("written");
            staged
        };

        let staged = stage();
        let assets = staged.dir.path.join("assets");
        let held = hold_without_shared_writing(&assets);
        let refused = owned(|permit| staged.activate(permit));
        drop(held);
        // The flush's own refusal names the directory it could not flush. A refusal naming the
        // destination instead would come from the rename, which a flush that did nothing reaches.
        match refused {
            Err(CatalogueError::StorageUnavailable { detail }) => assert!(
                detail.starts_with(&assets.display().to_string()),
                "refused for another reason: {detail}"
            ),
            other => panic!("activated, or refused for another reason: {other:?}"),
        }
        assert!(!store.package_dir(digest).exists(), "nothing was activated");

        let staged = stage();
        flush_tree(&staged.dir).expect("with nothing holding it, the staged tree is flushed");
        staged.abandon();
    }

    /// KR-REQ-11.06: on Windows a directory held open through the store cannot be renamed, since
    /// the store opens its directories without sharing their deletion and a rename deletes the old
    /// name. A staged package holds its own directory while it is staged, so nothing renames it
    /// then, while a directory beside it that no staged package holds is renamed with every one of
    /// the store's own directories held. The package's activation lets go of its handle and renames
    /// the directory into place.
    #[cfg(windows)]
    #[test]
    fn a_staged_package_holds_its_directory_until_its_activation_lets_it_go() {
        /// Another handle on the directory does not share what the rename's open asks for.
        const ERROR_SHARING_VIOLATION: i32 = 32;

        let (_directory, store) = store();
        let layout = store.layout().expect("the store's directories");
        let digest = PayloadDigest::of(b"manifest");
        let mut staged = store.stage_package(digest).expect("a staging directory");
        staged
            .write(&path("plugin.json"), b"manifest")
            .expect("written");

        let aside = layout.staging.path.join("aside");
        let refused = std::fs::rename(staged.path(), &aside)
            .expect_err("the staged package holds its directory");
        assert_eq!(
            refused.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION),
            "{refused}"
        );
        let unheld = layout.staging.path.join("unheld");
        std::fs::create_dir(&unheld).expect("a directory beside it");
        std::fs::rename(&unheld, &aside)
            .expect("a directory no handle holds is renamed while the store's own are held");
        std::fs::remove_dir(&aside).expect("removable");

        let activated = owned(|permit| staged.activate(permit))
            .expect("the staged directory is let go of and renamed into place");
        assert_eq!(activated, store.package_dir(digest));
        assert_eq!(
            std::fs::read(activated.join("plugin.json")).expect("readable"),
            b"manifest"
        );
    }

    /// Holds `file` with a handle that shares reading and writing but not its deletion, as a scanner
    /// holds a file it has just seen written.
    #[cfg(windows)]
    fn hold_file_without_shared_deletion(file: &Path) -> std::fs::File {
        use std::os::windows::fs::OpenOptionsExt as _;

        /// Reading is shared with other handles.
        const FILE_SHARE_READ: u32 = 0x0001;
        /// Writing is shared; deleting is not.
        const FILE_SHARE_WRITE: u32 = 0x0002;

        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(file)
            .expect("the file is held")
    }

    /// KR-REQ-11.06: on Windows a staged directory cannot be renamed while a file in it is held
    /// without its deletion shared, as a scanner holds a file it has just seen written. The
    /// activation tries the rename again, and places the package once the file is let go.
    #[cfg(windows)]
    #[test]
    fn a_package_whose_file_is_held_for_a_moment_is_placed_once_it_is_let_go() {
        let (_directory, store) = store();
        let digest = PayloadDigest::of(b"manifest");
        let mut staged = store.stage_package(digest).expect("a staging directory");
        staged
            .write(&path("plugin.json"), b"manifest")
            .expect("written");
        let holding = hold_file_without_shared_deletion(&staged.path().join("plugin.json"));
        let letting_go = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            drop(holding);
        });
        let attempts = std::rc::Rc::new(std::cell::Cell::new(0));
        let counted = std::rc::Rc::clone(&attempts);
        attempt_pause::each(move |attempt| counted.set(attempt));
        let activated = owned(|permit| staged.activate(permit));
        attempt_pause::clear();
        letting_go.join().expect("let go");
        let activated = activated.expect("placed once the file is let go");
        assert!(
            attempts.get() > 1,
            "refused while the file was held: {}",
            attempts.get()
        );
        assert_eq!(activated, store.package_dir(digest));
        assert_eq!(
            std::fs::read(activated.join("plugin.json")).expect("readable"),
            b"manifest"
        );
    }

    /// KR-REQ-11.06: a staged package with a file held past the bound the rename is tried again for
    /// is not placed: the activation reports the refusal once the bound has passed, and nothing is
    /// in `packages`.
    #[cfg(windows)]
    #[test]
    fn a_package_whose_file_is_held_past_the_bound_is_not_placed() {
        let (_directory, store) = store();
        let digest = PayloadDigest::of(b"manifest");
        let mut staged = store.stage_package(digest).expect("a staging directory");
        staged
            .write(&path("plugin.json"), b"manifest")
            .expect("written");
        let holding = hold_file_without_shared_deletion(&staged.path().join("plugin.json"));
        let started = std::time::Instant::now();
        let refused = owned(|permit| staged.activate(permit)).expect_err("not placed while held");
        let took = started.elapsed();
        drop(holding);
        assert!(
            matches!(&refused, CatalogueError::StorageUnavailable { detail }
                if detail.ends_with("(os error 5)")),
            "{refused:?}"
        );
        assert!(took >= kr_flush::HELD_RENAME_BOUND, "tried again: {took:?}");
        assert!(!store.package_dir(digest).exists(), "nothing is placed");
    }

    /// KR-REQ-11.06: a directory put in the staged one's place while its rename waits for a held
    /// file is refused and moved out again, as one put there before the first attempt is: the
    /// directory that arrives is compared with the staged one, whose second handle stays open
    /// through every attempt.
    #[cfg(windows)]
    #[test]
    fn a_directory_put_in_the_staged_ones_place_while_its_rename_waits_is_refused() {
        let (directory, store) = store();
        let digest = PayloadDigest::of(b"manifest");
        let mut staged = store.stage_package(digest).expect("a staging directory");
        staged
            .write(&path("plugin.json"), b"manifest")
            .expect("written");
        let name = staged.path().to_path_buf();
        let moved = directory.path().join("moved");
        let elsewhere = moved.clone();
        let mut holding = Some(hold_file_without_shared_deletion(&name.join("plugin.json")));
        attempt_pause::each(move |attempt| {
            // Refused once while the file is held; before the second attempt the file is let go,
            // the staged directory moved away and another of the same name put in its place.
            if attempt == 2 {
                drop(holding.take());
                std::fs::rename(&name, &elsewhere).expect("the staged directory moved away");
                std::fs::create_dir(&name).expect("another directory of the same name");
                std::fs::write(name.join("plugin.json"), b"manifest").expect("with the same file");
            }
        });
        let refused = owned(|permit| staged.activate(permit));
        attempt_pause::clear();
        let refused = refused.expect_err("not the directory that was staged and checked");
        assert!(
            matches!(&refused, CatalogueError::StorageUnavailable { detail }
                if detail.contains("was not the directory that was staged and checked")),
            "{refused:?}"
        );
        assert!(
            !store.package_dir(digest).exists(),
            "nothing is left where readers look"
        );
        assert_eq!(
            std::fs::read(moved.join("plugin.json")).expect("readable"),
            b"manifest",
            "the staged directory is as it was"
        );
    }

    /// Runs a program and returns what it printed, failing the test when it fails.
    #[cfg(windows)]
    fn run_program(program: &str, arguments: &[&std::ffi::OsStr]) -> String {
        let output = std::process::Command::new(program)
            .args(arguments)
            .output()
            .unwrap_or_else(|error| panic!("{program} starts: {error}"));
        let printed = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success(),
            "{program} failed: {printed}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        printed
    }

    /// Refuses this account the right to add one kind of name to one directory, and nothing else,
    /// until it is dropped.
    #[cfg(windows)]
    struct AddingRefused {
        directory: PathBuf,
        account: String,
    }

    #[cfg(windows)]
    impl AddingRefused {
        fn on(directory: &Path, kind: NameKind) -> Self {
            use std::os::windows::fs::OpenOptionsExt as _;

            /// The right to add a file to a directory.
            const FILE_ADD_FILE: u32 = 0x0002;
            /// The right to add a directory to one.
            const FILE_ADD_SUBDIRECTORY: u32 = 0x0004;
            /// What lets a program open a directory at all.
            const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

            // The right refused, as the list names it, and as a handle asks for it; then the
            // right left alone.
            let (entry, refused_right, kept_right) = match kind {
                NameKind::File => ("WD", FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY),
                NameKind::Directory => ("AD", FILE_ADD_SUBDIRECTORY, FILE_ADD_FILE),
            };
            let printed = run_program(
                "whoami.exe",
                &[
                    "/user".as_ref(),
                    "/fo".as_ref(),
                    "csv".as_ref(),
                    "/nh".as_ref(),
                ],
            );
            let account = printed
                .trim()
                .rsplit(',')
                .next()
                .unwrap_or_default()
                .trim_matches('"')
                .to_owned();
            assert!(
                account.starts_with("S-1-"),
                "this account's identifier: {printed}"
            );
            // An entry for this directory alone, which nothing created inside it inherits.
            run_program(
                "icacls.exe",
                &[
                    directory.as_os_str(),
                    "/deny".as_ref(),
                    format!("*{account}:({entry})").as_ref(),
                ],
            );
            let refused = Self {
                directory: directory.to_path_buf(),
                account,
            };
            let open = |right: u32| {
                std::fs::OpenOptions::new()
                    .access_mode(right)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                    .open(directory)
            };
            // The list is what refuses it: an account holding a privilege that overrides lists
            // would be let through, and for it this arrangement cannot be made.
            assert_eq!(
                open(refused_right)
                    .expect_err("the right is refused")
                    .kind(),
                std::io::ErrorKind::PermissionDenied,
                "{kind:?}"
            );
            open(kept_right).expect("and the other right is not");
            refused
        }
    }

    #[cfg(windows)]
    impl Drop for AddingRefused {
        fn drop(&mut self) {
            let _ = std::process::Command::new("icacls.exe")
                .arg(&self.directory)
                .arg("/remove:d")
                .arg(format!("*{}", self.account))
                .output();
        }
    }

    /// KR-REQ-11.06: a package repaired in place has each directory it changed flushed for the
    /// kind of name that directory gained. Here the package's own directory may gain a directory
    /// and not a file: the repair makes `assets` in it and renames the missing file into `assets`,
    /// so the package's directory is flushed with the right to add a directory and `assets` with
    /// the right to add a file, and the repair reports success.
    #[cfg(windows)]
    #[test]
    fn a_repair_flushes_each_directory_for_the_kind_of_name_it_gained() {
        let (_directory, store) = store();
        let digest = PayloadDigest::of(b"manifest");
        let package = store.package_dir(digest);
        std::fs::create_dir_all(&package).expect("a package directory already in place");
        std::fs::write(package.join("plugin.json"), b"manifest").expect("its manifest, intact");
        let mut staged = store.stage_package(digest).expect("a staging directory");
        staged
            .write(&path("plugin.json"), b"manifest")
            .expect("written");
        staged
            .write(&path("assets/icon.txt"), b"icon")
            .expect("written");

        let refused = AddingRefused::on(&package, NameKind::File);
        let repaired = owned(|permit| staged.activate(permit));
        drop(refused);
        assert_eq!(repaired.expect("the repair is made and flushed"), package);
        assert_eq!(
            std::fs::read(package.join("assets").join("icon.txt")).expect("the repaired file"),
            b"icon"
        );
    }

    /// KR-REQ-11.06: a directory a repair passes through without changing is not asked for a
    /// right the repair did not use. Here `assets` is already in place and the package's own
    /// directory may gain a file and not a directory: the repair renames the missing file into
    /// `assets`, flushes `assets` with the right to add a file, leaves the package's directory,
    /// which gained nothing, unflushed, and reports success.
    #[cfg(windows)]
    #[test]
    fn a_repair_asks_nothing_of_a_directory_it_did_not_change() {
        let (_directory, store) = store();
        let digest = PayloadDigest::of(b"manifest");
        let package = store.package_dir(digest);
        std::fs::create_dir_all(package.join("assets")).expect("a package already in place");
        std::fs::write(package.join("plugin.json"), b"manifest").expect("its manifest, intact");
        let mut staged = store.stage_package(digest).expect("a staging directory");
        staged
            .write(&path("plugin.json"), b"manifest")
            .expect("written");
        staged
            .write(&path("assets/icon.txt"), b"icon")
            .expect("written");

        let refused = AddingRefused::on(&package, NameKind::Directory);
        let repaired = owned(|permit| staged.activate(permit));
        drop(refused);
        assert_eq!(repaired.expect("the repair is made and flushed"), package);
        assert_eq!(
            std::fs::read(package.join("assets").join("icon.txt")).expect("the repaired file"),
            b"icon"
        );
    }

    /// A directory the store holds is flushed through a second handle opened from the one held,
    /// for either kind of name, so a handle that shares no writing stops the flush and the flush is
    /// made once that handle is let go.
    #[cfg(windows)]
    #[test]
    fn a_store_directory_is_flushed_through_the_handle_the_store_holds() {
        let (_directory, store) = store();
        let layout = store.layout().expect("the store's directories");
        for kind in [NameKind::File, NameKind::Directory] {
            let held = hold_without_shared_writing(&layout.index.path);
            let refused = flush_directory(&layout.index, kind);
            drop(held);
            assert!(
                matches!(refused, Err(CatalogueError::StorageUnavailable { .. })),
                "{kind:?}: {refused:?}"
            );
            flush_directory(&layout.index, kind).expect("flushed once nothing holds it");
        }
    }
}
