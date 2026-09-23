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
//! Reclaiming space never takes a payload a live binding or a pinned generation still needs.
//! Section 11 is explicit that a sync does not evict those to finish, so [`Store::plan_reclaim`]
//! refuses rather than freeing the last thing that was keeping something working.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use kr_plugin_sdk::catalogue::CatalogueIndex;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::plugin::PluginManifest;

use crate::catalogue::authority::Permit;
use crate::catalogue::budget::{BudgetLedger, Resource, ResourceLimit, Stage};
use crate::catalogue::db::ActiveGeneration;
use crate::catalogue::error::{CatalogueError, CatalogueResult};
use crate::catalogue::repository::EnrolmentKey;

/// The directory every enrolment's own directory sits in.
const REPOSITORIES: &str = "repositories";

/// The document in which the client keeps the latest time it has known.
const TIME_CHECKPOINT: &str = "latest_known_time.json";

/// One repository's directory.
#[derive(Clone, Debug)]
pub struct Store {
    root: PathBuf,
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
#[derive(Debug)]
pub struct WorkingDatastore {
    path: PathBuf,
}

impl WorkingDatastore {
    /// Returns the directory the client works in.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for WorkingDatastore {
    /// Removes the working copy once the verification it served is over. A removal that fails
    /// leaves a directory nothing reads.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
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

impl Store {
    /// Opens one repository's directory, creating what is missing.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when a directory cannot be created.
    pub fn open(root: &Path, enrolment: &EnrolmentKey) -> CatalogueResult<Self> {
        let root = root.join(REPOSITORIES).join(enrolment.as_str());
        for directory in ["datastore", "index", "payloads", "packages", "staging"] {
            let path = root.join(directory);
            std::fs::create_dir_all(&path)
                .map_err(|source| CatalogueError::storage(&path, &source))?;
        }
        Ok(Self { root })
    }

    /// Names one enrolment's directory without creating anything, for a read.
    ///
    /// A read that found nothing there is an answer about what is held, so it creates nothing on
    /// the way.
    #[must_use]
    pub fn at(root: &Path, enrolment: &EnrolmentKey) -> Self {
        Self {
            root: root.join(REPOSITORIES).join(enrolment.as_str()),
        }
    }

    /// Acquires an exclusive cross-process lock on this repository's store.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the lock cannot be acquired.
    pub fn lock(&self) -> CatalogueResult<StoreLock> {
        let path = self.root.join(".lock");
        #[cfg(unix)]
        {
            use rustix::fs::{FlockOperation, flock};
            let file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&path)
                .map_err(|source| CatalogueError::storage(&path, &source))?;
            flock(&file, FlockOperation::LockExclusive)
                .map_err(|source| CatalogueError::storage(&path, &std::io::Error::from(source)))?;
            Ok(StoreLock { _file: file })
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            const NO_SHARING: u32 = 0;
            let file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .share_mode(NO_SHARING)
                .open(&path)
                .map_err(|source| CatalogueError::storage(&path, &source))?;
            Ok(StoreLock { _file: file })
        }
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
    /// `reset` drops the timestamp and snapshot documents from the copy. The client drops them
    /// itself when a load moves to a root whose timestamp or snapshot keys differ from the root it
    /// started from; a root advance kept by an earlier load that then failed is the root the next
    /// load starts from, so the next load would not see the change, and the reset is applied here
    /// instead.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the copy cannot be made.
    pub fn working_datastore(&self, reset: bool) -> CatalogueResult<WorkingDatastore> {
        let staging = self.root.join("staging");
        std::fs::create_dir_all(&staging)
            .map_err(|source| CatalogueError::storage(&staging, &source))?;
        let mut attempt = 0u32;
        let path = loop {
            let candidate = staging.join(format!("datastore-{}-{attempt}", std::process::id()));
            match std::fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                    attempt = attempt.saturating_add(1);
                    if attempt > 1024 {
                        return Err(CatalogueError::storage(&candidate, &source));
                    }
                }
                Err(source) => return Err(CatalogueError::storage(&candidate, &source)),
            }
        };
        let working = WorkingDatastore { path };
        let accepted = self.datastore();
        for relative in files_under(&accepted)? {
            let from = accepted.join(&relative);
            let to = working.path.join(&relative);
            if let Some(parent) = to.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|source| CatalogueError::storage(parent, &source))?;
            }
            std::fs::copy(&from, &to).map_err(|source| CatalogueError::storage(&from, &source))?;
        }
        if reset {
            for role in ["timestamp.json", "snapshot.json"] {
                let path = working.path.join(role);
                match std::fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                    Err(source) => return Err(CatalogueError::storage(&path, &source)),
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
        let from = working.path.join(TIME_CHECKPOINT);
        let bytes = match std::fs::read(&from) {
            Ok(bytes) => bytes,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => return Err(CatalogueError::storage(&from, &source)),
        };
        // The client writes this document in place, so a write it did not finish leaves it empty
        // or cut short, and a document that does not read back is one the client ignores. Only a
        // time that reads back, and is no earlier than the time already kept, replaces it.
        let Ok(seen) = serde_json::from_slice::<jiff::Timestamp>(&bytes) else {
            return Ok(());
        };
        let to = self.datastore().join(TIME_CHECKPOINT);
        match std::fs::read(&to) {
            Ok(held) => {
                if serde_json::from_slice::<jiff::Timestamp>(&held).is_ok_and(|kept| kept >= seen) {
                    return Ok(());
                }
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(CatalogueError::storage(&to, &source)),
        }
        write_atomically(&self.root.join("staging"), &to, &bytes)
    }

    /// Makes a verified working copy the accepted trust checkpoint, one document at a time.
    ///
    /// Each document is written whole beside the accepted one and renamed over it, so a reader, or
    /// an interruption, finds every document whole: the one that was accepted or the one that
    /// verified. The working copy is left as it was, because the client goes on reading and
    /// writing its time checkpoint there while the verified generation's payloads are fetched. A
    /// document the working copy no longer holds is removed. The client verified each new document as no older
    /// than the one it replaces, so a checkpoint caught part way between the two is still a set of
    /// floors the next verification can start from.
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
        let accepted = self.datastore();
        let verified = files_under(&working.path)?;
        let held = files_under(&accepted)?;
        let staging = self.root.join("staging");
        let mut changed = 0usize;
        let stopped = |changed: usize, error: CatalogueError| {
            if changed == 0 {
                error
            } else {
                CatalogueError::PublicationUncertain {
                    detail: format!(
                        "{changed} documents of the trust checkpoint were replaced before this \
                         failed: {error}"
                    ),
                }
            }
        };
        for relative in &verified {
            let from = working.path.join(relative);
            let bytes = std::fs::read(&from)
                .map_err(|source| stopped(changed, CatalogueError::storage(&from, &source)))?;
            rename_into_place(&staging, &accepted.join(relative), &bytes)
                .map_err(|error| stopped(changed, error))?;
            changed += 1;
        }
        for relative in held.iter().filter(|relative| !verified.contains(*relative)) {
            let path = accepted.join(relative);
            match std::fs::remove_file(&path) {
                Ok(()) => changed += 1,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(stopped(changed, CatalogueError::storage(&path, &source)));
                }
            }
        }
        flushed_after_publication(&accepted, &accepted)
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

    /// Returns the files a package activated here consists of, read from its own manifest.
    ///
    /// `None` is a package that is not here, or whose manifest is not the one its hash names or does
    /// not read: nothing about what it consists of can be said from it.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the manifest is there and cannot be read.
    pub(crate) fn package_payloads(
        &self,
        manifest_digest: PayloadDigest,
    ) -> CatalogueResult<Option<Vec<PayloadDigest>>> {
        let path = self
            .package_dir(manifest_digest)
            .join(kr_plugin_sdk::package::MANIFEST_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(CatalogueError::storage(&path, &source)),
        };
        if PayloadDigest::of(&bytes) != manifest_digest {
            return Ok(None);
        }
        Ok(serde_json::from_slice::<PluginManifest>(&bytes)
            .ok()
            .map(|manifest| {
                manifest
                    .payloads
                    .iter()
                    .map(|payload| payload.digest)
                    .collect()
            }))
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
        self.root.join("index").join(format!("{digest}.json"))
    }

    /// Writes one verified generation's index under its own digest.
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
        index: &CatalogueIndex,
    ) -> CatalogueResult<(PayloadDigest, u64)> {
        let rendered = index
            .canonical_json()
            .map_err(|source| CatalogueError::Integrity {
                detail: format!("the index could not be rendered: {source}"),
            })?;
        let bytes = rendered.into_bytes();
        let digest = PayloadDigest::of(&bytes);
        write_atomically(&self.root.join("staging"), &self.index_path(digest), &bytes)?;
        Ok((digest, bytes.len() as u64))
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
        write_atomically(
            &self.root.join("staging"),
            &self.payload_path(digest),
            bytes,
        )
    }

    /// Reads one cached payload.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::UnavailableOffline`] when the payload is not cached here, which
    /// is the answer section 11 asks for rather than a capability that is not really there.
    pub fn read_payload(&self, digest: PayloadDigest) -> CatalogueResult<Vec<u8>> {
        let path = self.payload_path(digest);
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
        let staging = self.root.join("staging");
        std::fs::create_dir_all(&staging)
            .map_err(|source| CatalogueError::storage(&staging, &source))?;
        let mut attempt = 0u32;
        loop {
            let path = staging.join(format!(
                "package-{manifest_digest}-{}-{attempt}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    return Ok(StagedPackage {
                        destination: self.package_dir(manifest_digest),
                        path,
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

    /// Decides which cached payloads to remove so that `needed` more bytes fit, without touching
    /// `protected`.
    ///
    /// `protected` is every payload a live binding or a pinned generation still needs. Section 11
    /// says a sync never evicts those to finish, so a reclaim that would have to is a reclaim that
    /// refuses and names the resource instead. Nothing is removed here: the plan is carried out by
    /// [`Self::remove`], under the permit the admitting authority lends.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceLimit`] naming the payload cache when the unprotected payloads are not
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
        let held = self.cached_payloads()?;
        let evictable: u64 = held
            .iter()
            .filter(|(digest, _)| !protected.contains(*digest))
            .map(|(_, size)| *size)
            .sum();
        let requested = ledger.payload_bytes().saturating_add(needed);
        if requested.saturating_sub(evictable) > limit {
            return Err(ResourceLimit {
                resource: Resource::PayloadCacheBytes,
                limit,
                requested,
                stage: Stage::Declared,
                subject: format!(
                    "{subject}; {} bytes are held by live bindings or pinned generations and are \
                     never evicted to finish a sync",
                    requested.saturating_sub(evictable).min(requested)
                ),
            }
            .into());
        }
        for (digest, size) in held {
            if ledger
                .check_payload_bytes(needed, Stage::Declared, subject)
                .is_ok()
            {
                break;
            }
            if protected.contains(&digest) {
                continue;
            }
            plan.payloads.push((digest, size));
            ledger.remove_payload_bytes(size);
        }
        ledger.check_payload_bytes(needed, Stage::Declared, subject)?;
        Ok(plan)
    }

    /// Removes the payloads a reclaim plan names.
    ///
    /// A payload somebody else already removed counts as removed. A failure before anything was
    /// removed leaves the cache as it was; one after is [`CatalogueError::PublicationUncertain`],
    /// because part of the plan has already happened and cannot be reported as nothing.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the first removal fails, and
    /// [`CatalogueError::PublicationUncertain`] when a later one does.
    pub(crate) fn remove(&self, _permit: &Permit, plan: &ReclaimPlan) -> CatalogueResult<()> {
        let mut removed = 0usize;
        for (digest, _) in &plan.payloads {
            let path = self.payload_path(*digest);
            match std::fs::remove_file(&path) {
                Ok(()) => removed += 1,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) if removed == 0 => return Err(CatalogueError::storage(&path, &source)),
                Err(source) => {
                    return Err(CatalogueError::PublicationUncertain {
                        detail: format!(
                            "{removed} of {} payloads were removed to make room and {} could not \
                             be: {source}",
                            plan.payloads.len(),
                            path.display()
                        ),
                    });
                }
            }
        }
        Ok(())
    }
}

/// The cached payloads one reclaim removes, decided before any of them is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReclaimPlan {
    payloads: Vec<(PayloadDigest, u64)>,
}

impl ReclaimPlan {
    /// Returns true when nothing has to be removed.
    pub(crate) fn is_empty(&self) -> bool {
        self.payloads.is_empty()
    }

    /// Returns how many payloads the plan removes.
    pub(crate) fn payloads(&self) -> u64 {
        self.payloads.len() as u64
    }

    /// Returns how many bytes those payloads hold.
    pub(crate) fn bytes(&self) -> u64 {
        self.payloads
            .iter()
            .fold(0u64, |total, (_, size)| total.saturating_add(*size))
    }

    /// Returns true when the plan removes `digest`.
    #[cfg(test)]
    pub(crate) fn removes(&self, digest: PayloadDigest) -> bool {
        self.payloads.iter().any(|(named, _)| *named == digest)
    }
}

/// A package being staged, which becomes visible only when every payload has verified.
#[derive(Debug)]
pub struct StagedPackage {
    path: PathBuf,
    destination: PathBuf,
    written: BTreeMap<String, u64>,
}

impl StagedPackage {
    /// Writes one verified file into the staging directory.
    ///
    /// `relative` is a [`kr_plugin_sdk::paths::PackagePath`], which is the proof that the package
    /// path rules were applied to it: it cannot escape the directory, name a device or spell a
    /// name two filesystems disagree about. The file is created rather than opened, so an existing
    /// name, including a link somebody put there, fails instead of being followed.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::UnsafePackage`] when the name is already staged, and
    /// [`CatalogueError::StorageUnavailable`] when the bytes cannot be written.
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
        let path = self.path.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|source| CatalogueError::storage(parent, &source))?;
        }
        let mut file = std::fs::File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|source| CatalogueError::storage(&path, &source))?;
        file.write_all(bytes)
            .map_err(|source| CatalogueError::storage(&path, &source))?;
        file.sync_all()
            .map_err(|source| CatalogueError::storage(&path, &source))?;
        self.written.insert(relative.to_owned(), bytes.len() as u64);
        Ok(())
    }

    /// Returns the directory this attempt is staging into.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
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
    /// all. Where a package is already there, it failed its own check, and it is repaired where it
    /// lies: each file that does not hold the checked bytes is replaced by a rename of its own. The
    /// directory never disappears, a reader holding a file open keeps reading it, and a reader that
    /// opens a file by name finds either the file that was there or the checked one. The name
    /// alone never counts as the package.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when nothing was changed, and
    /// [`CatalogueError::PublicationUncertain`] when part of the package was replaced and the rest
    /// could not be, or when a directory did not confirm a rename.
    pub(crate) fn activate(self, _permit: &Permit) -> CatalogueResult<PathBuf> {
        if let Some(parent) = self.destination.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|source| CatalogueError::storage(parent, &source))?;
        }
        flush_tree(&self.path)?;
        match std::fs::symlink_metadata(&self.destination) {
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                std::fs::rename(&self.path, &self.destination)
                    .map_err(|source| CatalogueError::storage(&self.destination, &source))?;
                if let Some(parent) = self.destination.parent() {
                    flushed_after_publication(parent, &self.destination)?;
                }
            }
            Err(source) => return Err(CatalogueError::storage(&self.destination, &source)),
            Ok(metadata) if metadata.is_dir() => self.repair_in_place()?,
            Ok(_) => {
                return Err(CatalogueError::StorageUnavailable {
                    detail: format!(
                        "{} is not a directory, and a package is not repaired over it",
                        self.destination.display()
                    ),
                });
            }
        }
        Ok(self.destination.clone())
    }

    /// Replaces, one rename at a time, every file of the package already at the destination that
    /// does not hold the checked bytes.
    fn repair_in_place(&self) -> CatalogueResult<()> {
        // Every directory between the package and a file it declares has to be a directory, not a
        // link: a rename through a linked directory would write outside the package. The whole
        // package is checked before anything is replaced, so a refusal changes nothing.
        for relative in self.written.keys() {
            let mut directory = self.destination.clone();
            for component in Path::new(relative)
                .parent()
                .into_iter()
                .flat_map(Path::components)
            {
                directory.push(component);
                match std::fs::symlink_metadata(&directory) {
                    Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                        return Err(CatalogueError::StorageUnavailable {
                            detail: format!(
                                "{} is not a directory of the package, and a package is not \
                                 repaired through it",
                                directory.display()
                            ),
                        });
                    }
                    Ok(_) => {}
                    Err(source) if source.kind() == std::io::ErrorKind::NotFound => break,
                    Err(source) => return Err(CatalogueError::storage(&directory, &source)),
                }
            }
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
        for relative in self.written.keys() {
            let staged = self.path.join(relative);
            let target = self.destination.join(relative);
            let checked = std::fs::read(&staged)
                .map_err(|source| stopped(&replaced, CatalogueError::storage(&staged, &source)))?;
            // A file that holds the checked bytes is left where it is, so whoever is reading it is
            // not disturbed. A file that is missing, different or unreadable is replaced, and the
            // replacement is what reports whether that can be done.
            if std::fs::read(&target).is_ok_and(|held| held == checked) {
                continue;
            }
            let outcome = target
                .parent()
                .map_or(Ok(()), std::fs::create_dir_all)
                .and_then(|()| std::fs::rename(&staged, &target));
            if let Err(source) = outcome {
                return Err(stopped(
                    &replaced,
                    CatalogueError::storage(&target, &source),
                ));
            }
            replaced.push(target);
        }
        // Every directory from a replaced file up to the package's own holds a new entry, a
        // replaced file or a directory created for one, so each of them is flushed.
        let mut directories: BTreeSet<PathBuf> = BTreeSet::new();
        for path in &replaced {
            let mut directory = path.parent();
            while let Some(current) = directory {
                directories.insert(current.to_path_buf());
                if current == self.destination {
                    break;
                }
                directory = current.parent();
            }
        }
        for directory in &directories {
            flushed_after_publication(directory, &self.destination)?;
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

impl Drop for StagedPackage {
    /// Removes a staging directory nothing will activate.
    ///
    /// The directory is this attempt's own and nothing reads it, so an attempt that stops part way,
    /// or whose activation was refused, leaves nothing behind. After an activation it has been
    /// renamed into place and there is nothing here to remove. A removal that fails leaves a
    /// directory no reader ever looks at, under a name no later attempt reuses.
    fn drop(&mut self) {
        if self.path.exists() {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Writes a document and requires its rename to be durable before it returns.
///
/// A failure before the rename leaves nothing changed. A flush that fails after it is
/// [`CatalogueError::PublicationUncertain`]: the new document is already what every reader sees,
/// and only whether its directory entry survives a power loss is in question.
fn write_atomically(staging: &Path, path: &Path, bytes: &[u8]) -> CatalogueResult<()> {
    rename_into_place(staging, path, bytes)?;
    if let Some(parent) = path.parent() {
        flushed_after_publication(parent, path)?;
    }
    Ok(())
}

/// Flushes the directory a publication renamed something into.
///
/// The rename has happened by then, so a flush that fails does not undo anything: it leaves the
/// publication in place and its durability unconfirmed, which is an uncertain outcome rather than
/// a failure that changed nothing.
fn flushed_after_publication(directory: &Path, published: &Path) -> CatalogueResult<()> {
    flush_directory(directory).map_err(|error| CatalogueError::PublicationUncertain {
        detail: format!(
            "{} is in place and its directory did not confirm it: {error}",
            published.display()
        ),
    })
}

/// Writes `bytes` into a temporary file and renames it over `path`, without flushing the directory.
fn rename_into_place(staging: &Path, path: &Path, bytes: &[u8]) -> CatalogueResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|source| CatalogueError::storage(parent, &source))?;
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("document");
    std::fs::create_dir_all(staging).map_err(|source| CatalogueError::storage(staging, &source))?;
    // The temporary name is this writer's alone and is created rather than opened, so a name
    // another writer is using, or a link somebody left, fails instead of being written through.
    let mut attempt = 0u32;
    let (temporary, mut file) = loop {
        let candidate = staging.join(format!("{name}.{}.{attempt}.writing", std::process::id()));
        match std::fs::File::options()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => break (candidate, file),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                attempt = attempt.saturating_add(1);
                if attempt > 1024 {
                    return Err(CatalogueError::storage(&candidate, &source));
                }
            }
            Err(source) => return Err(CatalogueError::storage(&candidate, &source)),
        }
    };
    file.write_all(bytes)
        .map_err(|source| CatalogueError::storage(&temporary, &source))?;
    file.sync_all()
        .map_err(|source| CatalogueError::storage(&temporary, &source))?;
    drop(file);
    std::fs::rename(&temporary, path).map_err(|source| {
        let _ = std::fs::remove_file(&temporary);
        CatalogueError::storage(path, &source)
    })?;
    Ok(())
}

/// Flushes a directory entry so a rename survives a power loss, where the platform offers it.
///
/// Unix can open a directory and flush it. Windows cannot, and its own rename durability is the
/// filesystem's; the comment above a rename says what the platform gives rather than claiming one
/// guarantee everywhere.
fn flush_directory(path: &Path) -> CatalogueResult<()> {
    #[cfg(test)]
    if flush_fault::fails(path) {
        return Err(CatalogueError::StorageUnavailable {
            detail: format!("{}: the flush was made to fail", path.display()),
        });
    }
    #[cfg(unix)]
    {
        let directory =
            std::fs::File::open(path).map_err(|source| CatalogueError::storage(path, &source))?;
        directory
            .sync_all()
            .map_err(|source| CatalogueError::storage(path, &source))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
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

/// Flushes every directory in a directory tree recursively.
fn flush_tree(path: &Path) -> CatalogueResult<()> {
    #[cfg(unix)]
    {
        if path.is_dir() {
            for entry in
                std::fs::read_dir(path).map_err(|source| CatalogueError::storage(path, &source))?
            {
                let entry = entry.map_err(|source| CatalogueError::storage(path, &source))?;
                let entry_path = entry.path();
                if entry_path.is_dir() {
                    flush_tree(&entry_path)?;
                }
            }
            flush_directory(path)?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalogue::authority::{Effect, Owner, committed};
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
            versions: crate::catalogue::trust::MetadataVersions::default(),
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

    #[test]
    fn an_index_is_read_back_only_as_the_generation_it_was_accepted_with() {
        let (_directory, store) = store();
        let first = accepted(
            1,
            owned(|permit| store.write_index(permit, &index(1))).expect("written"),
        );
        assert_eq!(store.index(&first).expect("readable").generation.get(), 1);

        // A second generation's document beside it changes nothing about the first.
        let second = accepted(
            2,
            owned(|permit| store.write_index(permit, &index(2))).expect("written"),
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
        let (first, _) = owned(|permit| store.write_index(permit, &index(1))).expect("written");
        // A second generation with different bytes is a different file, so a row can never end
        // up naming content this store did not verify.
        let mut changed = index(1);
        changed.produced_at = TimestampMs::new(1_760_000_100_000);
        let (second, _) = owned(|permit| store.write_index(permit, &changed)).expect("written");
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
        let outcome = owned(|permit| store.write_index(permit, &index(1)));
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

    #[test]
    fn a_repaired_subtree_is_flushed_up_to_the_package() {
        let (_directory, store) = store();
        let digest = PayloadDigest::of(b"nested");
        let staged = stage_nested(&store, digest);
        let package = owned(|permit| staged.activate(permit)).expect("activated");

        // Every directory from the recreated file up to the package's own holds a new entry.
        for failing in [
            package.join("assets/icons"),
            package.join("assets"),
            package.clone(),
        ] {
            std::fs::remove_dir_all(package.join("assets")).expect("removable");
            let staged = stage_nested(&store, digest);
            flush_fault::fail(&failing);
            let outcome = owned(|permit| staged.activate(permit));
            flush_fault::clear();
            assert!(
                matches!(outcome, Err(CatalogueError::PublicationUncertain { .. })),
                "{}: {outcome:?}",
                failing.display()
            );
            assert_eq!(
                std::fs::read(package.join("assets/icons/icon.bin")).expect("in place"),
                b"icon"
            );
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
        let refusal = store.read_payload(digest).expect_err("not cached");
        assert_eq!(
            refusal.code(),
            kr_protocol::error::ErrorCode::PackageUnavailableOffline
        );
        owned(|permit| store.cache_payload(permit, digest, b"component")).expect("cacheable");
        assert_eq!(store.read_payload(digest).expect("cached"), b"component");
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
    fn a_reclaim_that_fails_part_way_is_uncertain_and_one_that_fails_first_removed_nothing() {
        let (_directory, store) = store();
        let first = PayloadDigest::of(b"first");
        let second = PayloadDigest::of(b"second");
        owned(|permit| store.cache_payload(permit, first, b"first")).expect("cacheable");
        // A name no file removal takes away: a directory where the payload would be.
        std::fs::create_dir_all(store.payload_path(second).join("inside")).expect("a directory");

        let plan = ReclaimPlan {
            payloads: vec![(first, 5), (second, 6)],
        };
        let outcome = owned(|permit| store.remove(permit, &plan));
        assert!(
            matches!(outcome, Err(CatalogueError::PublicationUncertain { .. })),
            "part of the plan happened: {outcome:?}"
        );
        assert!(!store.holds_payload(first, 5).expect("a readable store"));

        let plan = ReclaimPlan {
            payloads: vec![(second, 6)],
        };
        let outcome = owned(|permit| store.remove(permit, &plan));
        assert!(
            matches!(outcome, Err(CatalogueError::StorageUnavailable { .. })),
            "nothing of the plan happened: {outcome:?}"
        );
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
        let path = store.root.join(".lock");
        #[cfg(unix)]
        {
            use rustix::fs::{FlockOperation, flock};
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open lockfile");
            let err = flock(&file, FlockOperation::NonBlockingLockExclusive).unwrap_err();
            assert_eq!(err, rustix::io::Errno::WOULDBLOCK);
        }
    }
}
