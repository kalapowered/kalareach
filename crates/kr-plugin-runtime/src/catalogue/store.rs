//! What a repository leaves on disk, and how it becomes current.
//!
//! One directory per enrolled repository:
//!
//! ```text
//! <root>/<repository>/
//!   datastore/            the client's own trusted metadata
//!   index/<digest>.json   each verified generation's index, whole and named by its own digest
//!   index/active.json     which generation is current
//!   payloads/<digest>     cached payloads, by content hash
//!   packages/<digest>/    an activated package's files, under its manifest digest
//!   staging/              work in progress, and nothing a reader ever sees
//! ```
//!
//! Two activations, each atomic on its own:
//!
//! * **The index.** A generation's index is written whole and flushed, and only then does
//!   `active.json` move to name it. A reader sees one generation or the previous one, never a
//!   mixture, and an interrupted sync leaves the previous index exactly where it was.
//! * **A package.** Every payload is staged and verified in a directory of its own, and the
//!   directory is renamed into place once all of them verify. A package is therefore never half
//!   installed, and a package activation that fails leaves an installed package usable.
//!
//! Reclaiming space never takes a payload a live binding or a pinned generation still needs.
//! Section 11 is explicit that a sync does not evict those to finish, so [`Store::reclaim`]
//! refuses rather than freeing the last thing that was keeping something working.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use kr_plugin_sdk::catalogue::CatalogueIndex;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_protocol::ids::RepositoryGeneration;

use crate::catalogue::budget::{BudgetLedger, Resource, ResourceLimit, Stage};
use crate::catalogue::error::{CatalogueError, CatalogueResult};
use crate::catalogue::repository::RepositoryId;

/// The file that names the current generation.
const ACTIVE_FILE: &str = "active.json";

/// One repository's directory.
#[derive(Clone, Debug)]
pub struct Store {
    root: PathBuf,
}

/// An exclusive cross-process lock on this repository's store, held across metadata synchronisation.
#[derive(Debug)]
pub struct StoreLock {
    _file: std::fs::File,
}

/// Which generation is current, and what it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActiveGeneration {
    /// The generation number.
    pub generation: u64,
    /// The digest of the index's canonical rendering.
    ///
    /// A generation number names one immutable index. Holding the digest beside the number is what
    /// lets a later sync refuse different bytes under a number this host already accepted.
    pub index_digest: PayloadDigest,
    /// The exact length of the index document held.
    pub index_bytes: u64,
    /// The metadata versions this generation was accepted at.
    #[serde(default)]
    pub versions: crate::catalogue::trust::MetadataVersions,
}

impl Store {
    /// Opens one repository's directory, creating what is missing.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when a directory cannot be created.
    pub fn open(root: &Path, repository: &RepositoryId) -> CatalogueResult<Self> {
        let root = root.join(repository.as_str());
        for directory in ["datastore", "index", "payloads", "packages", "staging"] {
            let path = root.join(directory);
            std::fs::create_dir_all(&path)
                .map_err(|source| CatalogueError::storage(&path, &source))?;
        }
        Ok(Self { root })
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

    /// Returns the file this repository's active generation pointer sits in.
    #[must_use]
    pub fn active_path(&self) -> PathBuf {
        self.root.join("index").join(ACTIVE_FILE)
    }

    /// Resets trust for this repository by clearing the datastore cache, removing any
    /// active index, and writing the newly adopted trust root.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] if writing the root fails or clearing fails.
    pub fn reset_trust(&self, new_root: &[u8]) -> CatalogueResult<()> {
        let datastore = self.datastore();
        if datastore.exists() {
            std::fs::remove_dir_all(&datastore)
                .map_err(|source| CatalogueError::storage(&datastore, &source))?;
        }
        std::fs::create_dir_all(&datastore)
            .map_err(|source| CatalogueError::storage(&datastore, &source))?;
        let active = self.active_path();
        if active.exists() {
            std::fs::remove_file(&active)
                .map_err(|source| CatalogueError::storage(&active, &source))?;
        }
        self.write_root(new_root)
    }

    /// Returns the file this repository's adopted trust root sits in.
    #[must_use]
    pub fn root_path(&self) -> PathBuf {
        self.root.join("root.json")
    }

    /// Writes this repository's adopted trust root.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when it cannot be written.
    pub fn write_root(&self, bytes: &[u8]) -> CatalogueResult<()> {
        write_atomically(&self.root.join("staging"), &self.root_path(), bytes)
    }

    /// Reads this repository's adopted trust root.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::Untrusted`] when there is none, because a repository with no
    /// adopted root is a repository nothing verifies against.
    pub fn read_root(&self) -> CatalogueResult<Vec<u8>> {
        let path = self.root_path();
        match std::fs::read(&path) {
            Ok(bytes) => Ok(bytes),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                Err(CatalogueError::Untrusted {
                    detail: format!(
                        "{} holds no adopted trust root, so nothing verifies its metadata",
                        path.display()
                    ),
                })
            }
            Err(source) => Err(CatalogueError::storage(&path, &source)),
        }
    }

    /// Returns the directory the client keeps this repository's trusted metadata in.
    #[must_use]
    pub fn datastore(&self) -> PathBuf {
        self.root.join("datastore")
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
    /// is checked first, so the common case costs one `stat`, and the bytes are hashed only when
    /// that length matches.
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

    /// Returns true when the package is already activated here.
    #[must_use]
    pub fn has_package(&self, manifest_digest: PayloadDigest) -> bool {
        self.package_dir(manifest_digest).is_dir()
    }

    /// Reads which generation is current.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the pointer exists and cannot be read.
    pub fn active(&self) -> CatalogueResult<Option<ActiveGeneration>> {
        let path = self.active_path();
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|source| {
                CatalogueError::StorageUnavailable {
                    detail: format!("{}: {source}", path.display()),
                }
            }),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(CatalogueError::storage(&path, &source)),
        }
    }

    /// Reads the index of the current generation.
    ///
    /// This is the offline read: it touches no network, no payload and no metadata, because the
    /// whole snapshot is already here. It is also what keeps working when a repository's metadata
    /// expires, which blocks new generations and leaves this one alone.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when no generation is active, and
    /// [`CatalogueError::Integrity`] when the held document is not the one the pointer names.
    pub fn active_index(&self) -> CatalogueResult<CatalogueIndex> {
        let active = self.active()?.ok_or_else(|| CatalogueError::NotFound {
            detail: "this repository has no activated generation yet".to_owned(),
        })?;
        let path = self.index_path(active.index_digest);
        let bytes =
            std::fs::read(&path).map_err(|source| CatalogueError::storage(&path, &source))?;
        if PayloadDigest::of(&bytes) != active.index_digest {
            return Err(CatalogueError::Integrity {
                detail: format!(
                    "{} is not the index generation {} was activated with",
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

    /// Makes one verified generation current.
    ///
    /// The index document is written and flushed first, and the pointer moves after it, so the
    /// pointer never names a document that is not completely on disk. Nothing else changes: the
    /// packages already installed stay installed, on the hashes they were installed at.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the document or the pointer cannot be
    /// written.
    pub fn activate_index(
        &self,
        generation: RepositoryGeneration,
        index: &CatalogueIndex,
        versions: crate::catalogue::trust::MetadataVersions,
    ) -> CatalogueResult<ActiveGeneration> {
        let rendered = index
            .canonical_json()
            .map_err(|source| CatalogueError::Integrity {
                detail: format!("the index could not be rendered: {source}"),
            })?;
        let bytes = rendered.into_bytes();
        let digest = PayloadDigest::of(&bytes);
        let path = self.index_path(digest);
        write_atomically(&self.root.join("staging"), &path, &bytes)?;

        let active = ActiveGeneration {
            generation: generation.get(),
            index_digest: digest,
            index_bytes: bytes.len() as u64,
            versions,
        };
        let pointer =
            serde_json::to_vec(&active).map_err(|source| CatalogueError::StorageUnavailable {
                detail: format!("the active generation could not be recorded: {source}"),
            })?;
        write_atomically(&self.root.join("staging"), &self.active_path(), &pointer)?;
        Ok(active)
    }

    /// Caches one verified payload under its content hash.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::Integrity`] when the bytes are not the ones the digest names,
    /// and [`CatalogueError::StorageUnavailable`] when they cannot be written.
    pub fn cache_payload(&self, digest: PayloadDigest, bytes: &[u8]) -> CatalogueResult<()> {
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

    /// Removes an activated package.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the directory cannot be removed.
    pub fn remove_package(&self, manifest_digest: PayloadDigest) -> CatalogueResult<()> {
        let path = self.package_dir(manifest_digest);
        match std::fs::remove_dir_all(&path) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(CatalogueError::storage(&path, &source)),
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

    /// Frees cached payload bytes until `needed` more would fit, without touching `protected`.
    ///
    /// `protected` is every payload a live binding or a pinned generation still needs. Section 11
    /// says a sync never evicts those to finish, so a reclaim that would have to is a reclaim that
    /// refuses and names the resource instead.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceLimit`] naming the payload cache when the unprotected payloads are not
    /// enough, and [`CatalogueError::StorageUnavailable`] when a file cannot be removed.
    pub fn reclaim(
        &self,
        needed: u64,
        ledger: &mut BudgetLedger,
        protected: &BTreeSet<PayloadDigest>,
        subject: &str,
    ) -> CatalogueResult<()> {
        if ledger
            .check_payload_bytes(needed, Stage::Declared, subject)
            .is_ok()
        {
            return Ok(());
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
            let path = self.payload_path(digest);
            match std::fs::remove_file(&path) {
                Ok(()) => ledger.remove_payload_bytes(size),
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                    ledger.remove_payload_bytes(size);
                }
                Err(source) => return Err(CatalogueError::storage(&path, &source)),
            }
        }
        ledger.check_payload_bytes(needed, Stage::Declared, subject)?;
        Ok(())
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
    /// A package already at the destination is the same package: the directory is named by the
    /// manifest digest, which covers every other file by transitivity. The staging directory is
    /// discarded in that case rather than replacing bytes that are already the right bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the directory cannot be moved.
    pub fn activate(self) -> CatalogueResult<PathBuf> {
        if self.destination.is_dir() {
            std::fs::remove_dir_all(&self.path)
                .map_err(|source| CatalogueError::storage(&self.path, &source))?;
            return Ok(self.destination);
        }
        if let Some(parent) = self.destination.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|source| CatalogueError::storage(parent, &source))?;
        }
        flush_tree(&self.path)?;
        match std::fs::rename(&self.path, &self.destination) {
            Ok(()) => {}
            // Another writer activated the same package between the check and the rename. The
            // directory is named by the manifest digest, which covers every other file, so what
            // is there is the same package: this attempt's copy is discarded.
            Err(_) if self.destination.is_dir() => {
                let _ = std::fs::remove_dir_all(&self.path);
                return Ok(self.destination);
            }
            Err(source) => return Err(CatalogueError::storage(&self.destination, &source)),
        }
        if let Some(parent) = self.destination.parent() {
            flush_directory(parent)?;
        }
        Ok(self.destination)
    }

    /// Discards the staged package.
    ///
    /// An interrupted package activation leaves the installed package usable, which is what this
    /// is for: nothing outside the staging directory was ever touched.
    pub fn abandon(self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Writes `bytes` to `path` by writing a temporary file beside it and renaming.
///
/// The rename is what makes the change atomic for a reader: it sees the old contents or the new
/// ones, on every platform this ships on. The flush before it is what makes the new contents
/// complete, and the directory flush after it is what makes the rename itself survive a power
/// loss where the platform offers one.
pub(crate) fn write_document(root: &Path, path: &Path, bytes: &[u8]) -> CatalogueResult<()> {
    let staging = root.join("staging");
    std::fs::create_dir_all(&staging)
        .map_err(|source| CatalogueError::storage(&staging, &source))?;
    write_atomically(&staging, path, bytes)
}

fn write_atomically(staging: &Path, path: &Path, bytes: &[u8]) -> CatalogueResult<()> {
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
    if let Some(parent) = path.parent() {
        flush_directory(parent)?;
    }
    Ok(())
}

/// Flushes a directory entry so a rename survives a power loss, where the platform offers it.
///
/// Unix can open a directory and flush it. Windows cannot, and its own rename durability is the
/// filesystem's; the comment above a rename says what the platform gives rather than claiming one
/// guarantee everywhere.
fn flush_directory(path: &Path) -> CatalogueResult<()> {
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
    use kr_plugin_sdk::limits::RepositoryBudgets;
    use kr_protocol::scalars::{TimestampMs, U64};

    fn store() -> (tempfile::TempDir, Store) {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let store = Store::open(
            directory.path(),
            &RepositoryId::new("official").expect("a valid identifier"),
        )
        .expect("an openable store");
        (directory, store)
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

    fn versions(number: u64) -> crate::catalogue::trust::MetadataVersions {
        crate::catalogue::trust::MetadataVersions {
            root: 1,
            timestamp: number,
            snapshot: number,
            targets: number,
        }
    }

    #[test]
    fn an_interrupted_index_fetch_leaves_the_previous_index_usable() {
        let (_directory, store) = store();
        store
            .activate_index(RepositoryGeneration::new(1), &index(1), versions(1))
            .expect("the first generation activates");
        assert_eq!(store.active_index().expect("readable").generation.get(), 1);

        // A sync that wrote the next generation's document and stopped before the pointer moved.
        let rendered = index(2).canonical_json().expect("renderable");
        let path = store.index_path(PayloadDigest::of(rendered.as_bytes()));
        write_atomically(&store.root.join("staging"), &path, rendered.as_bytes())
            .expect("the document is written");
        assert!(path.is_file());
        assert_eq!(
            store.active_index().expect("readable").generation.get(),
            1,
            "the previous index stays current until the pointer moves"
        );

        store
            .activate_index(RepositoryGeneration::new(2), &index(2), versions(2))
            .expect("the second generation activates");
        assert_eq!(store.active_index().expect("readable").generation.get(), 2);
        assert_eq!(
            store.active().expect("readable").expect("active").versions,
            versions(2),
            "the metadata versions are held beside the generation they were accepted at"
        );
    }

    #[test]
    fn an_index_document_is_named_by_its_own_digest() {
        let (_directory, store) = store();
        let first = store
            .activate_index(RepositoryGeneration::new(1), &index(1), versions(1))
            .expect("activated");
        // A second generation with different bytes is a different file, so a pointer can never
        // end up naming content this store did not verify.
        let mut changed = index(1);
        changed.produced_at = TimestampMs::new(1_760_000_100_000);
        let second = store
            .activate_index(RepositoryGeneration::new(1), &changed, versions(1))
            .expect("activated");
        assert_ne!(first.index_digest, second.index_digest);
        assert!(store.index_path(first.index_digest).is_file());
        assert!(store.index_path(second.index_digest).is_file());
    }

    #[test]
    fn a_package_becomes_visible_only_when_every_payload_verified() {
        let (_directory, store) = store();
        let digest = PayloadDigest::of(b"manifest");
        let mut staged = store.stage_package(digest).expect("a staging directory");
        staged
            .write(&path("plugin.json"), b"manifest")
            .expect("written");
        assert!(!store.has_package(digest));
        staged.abandon();
        assert!(!store.has_package(digest));

        let mut staged = store.stage_package(digest).expect("a staging directory");
        staged
            .write(&path("plugin.json"), b"manifest")
            .expect("written");
        staged
            .write(&path("presentation.json"), b"presentation")
            .expect("written");
        assert_eq!(staged.staged_files(), 2);
        let activated = staged.activate().expect("activated");
        assert!(store.has_package(digest));
        assert_eq!(activated, store.package_dir(digest));
        assert_eq!(
            std::fs::read(activated.join("plugin.json")).expect("readable"),
            b"manifest"
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
        let refusal = store.read_payload(digest).expect_err("not cached");
        assert_eq!(
            refusal.code(),
            kr_protocol::error::ErrorCode::PackageUnavailableOffline
        );
        store
            .cache_payload(digest, b"component")
            .expect("cacheable");
        assert_eq!(store.read_payload(digest).expect("cached"), b"component");
    }

    #[test]
    fn caching_bytes_that_are_not_the_digest_is_refused() {
        let (_directory, store) = store();
        let refusal = store
            .cache_payload(PayloadDigest::of(b"one"), b"two")
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
        store.cache_payload(live, b"live").expect("cacheable");
        store.cache_payload(spare, b"spare").expect("cacheable");
        ledger.add_payload_bytes(9);

        let mut protected = BTreeSet::new();
        protected.insert(live);

        // Five bytes of spare payload are enough to make room for twenty-four more.
        store
            .reclaim(24, &mut ledger, &protected, "component.wasm")
            .expect("the spare payload is evicted");
        assert!(
            store.holds_payload(live, 4).expect("a readable store"),
            "a live-bound payload is kept"
        );
        assert!(!store.holds_payload(spare, 5).expect("a readable store"));

        // Nothing unprotected is left, so the refusal names the resource rather than taking the
        // live-bound payload.
        ledger.add_payload_bytes(24);
        let refusal = store
            .reclaim(24, &mut ledger, &protected, "component.wasm")
            .expect_err("nothing else may be evicted");
        let message = refusal.to_string();
        assert!(message.contains("payload_cache_bytes"), "{message}");
        assert!(message.contains("never evicted"), "{message}");
        assert!(store.holds_payload(live, 4).expect("a readable store"));
    }

    #[test]
    fn a_cached_object_that_lost_its_bytes_is_not_held() {
        let (_directory, store) = store();
        let digest = PayloadDigest::of(b"component");
        store
            .cache_payload(digest, b"component")
            .expect("cacheable");
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
