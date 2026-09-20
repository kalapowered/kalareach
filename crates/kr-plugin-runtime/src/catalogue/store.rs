//! What a repository leaves on disk, and how it becomes current.
//!
//! One directory per enrolled repository:
//!
//! ```text
//! <root>/<repository>/
//!   datastore/            the client's own trusted metadata
//!   index/<n>.json        each verified generation's index, whole
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

/// Which generation is current, and what it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActiveGeneration {
    /// The generation number.
    pub generation: u64,
    /// The digest of the index's canonical rendering.
    pub index_digest: PayloadDigest,
    /// The exact length of the index document held.
    pub index_bytes: u64,
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

    /// Returns true when the payload is already cached here.
    #[must_use]
    pub fn has_payload(&self, digest: PayloadDigest) -> bool {
        self.payload_path(digest).is_file()
    }

    /// Returns the directory one package is staged in.
    #[must_use]
    pub fn stage_path(&self, manifest_digest: PayloadDigest) -> PathBuf {
        self.root
            .join("staging")
            .join(format!("package-{manifest_digest}"))
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
        let path = self.root.join("index").join(ACTIVE_FILE);
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
        let path = self.index_path(active.generation);
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

    fn index_path(&self, generation: u64) -> PathBuf {
        self.root.join("index").join(format!("{generation}.json"))
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
    ) -> CatalogueResult<ActiveGeneration> {
        let rendered = index
            .canonical_json()
            .map_err(|source| CatalogueError::Integrity {
                detail: format!("the index could not be rendered: {source}"),
            })?;
        let bytes = rendered.into_bytes();
        let path = self.index_path(generation.get());
        write_atomically(&self.root.join("staging"), &path, &bytes)?;

        let active = ActiveGeneration {
            generation: generation.get(),
            index_digest: PayloadDigest::of(&bytes),
            index_bytes: bytes.len() as u64,
        };
        let pointer =
            serde_json::to_vec(&active).map_err(|source| CatalogueError::StorageUnavailable {
                detail: format!("the active generation could not be recorded: {source}"),
            })?;
        write_atomically(
            &self.root.join("staging"),
            &self.root.join("index").join(ACTIVE_FILE),
            &pointer,
        )?;
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
        let path = self.stage_path(manifest_digest);
        // A directory left by an interrupted run is removed rather than reused: its contents were
        // never verified as a set, and adding to it would activate a mixture of two attempts.
        if path.exists() {
            std::fs::remove_dir_all(&path)
                .map_err(|source| CatalogueError::storage(&path, &source))?;
        }
        std::fs::create_dir_all(&path).map_err(|source| CatalogueError::storage(&path, &source))?;
        Ok(StagedPackage {
            destination: self.package_dir(manifest_digest),
            path,
            written: BTreeMap::new(),
        })
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
    /// `relative` has already been through the package path rules, so it cannot escape the
    /// directory, name a device or collide with a sibling. The file is created rather than opened,
    /// so an existing name, including a link somebody put there, fails instead of being followed.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::UnsafePackage`] when the name is already staged, and
    /// [`CatalogueError::StorageUnavailable`] when the bytes cannot be written.
    pub fn write(&mut self, relative: &str, bytes: &[u8]) -> CatalogueResult<()> {
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
        std::fs::rename(&self.path, &self.destination)
            .map_err(|source| CatalogueError::storage(&self.destination, &source))?;
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
/// ones. The flush before it is what makes the new contents complete, so a machine that loses
/// power between the two finds the old file rather than a truncated new one.
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
    let temporary = staging.join(format!("{name}.{}.writing", std::process::id()));
    {
        let mut file = std::fs::File::create(&temporary)
            .map_err(|source| CatalogueError::storage(&temporary, &source))?;
        file.write_all(bytes)
            .map_err(|source| CatalogueError::storage(&temporary, &source))?;
        file.sync_all()
            .map_err(|source| CatalogueError::storage(&temporary, &source))?;
    }
    std::fs::rename(&temporary, path).map_err(|source| {
        let _ = std::fs::remove_file(&temporary);
        CatalogueError::storage(path, &source)
    })
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
    fn an_interrupted_index_fetch_leaves_the_previous_index_usable() {
        let (_directory, store) = store();
        store
            .activate_index(RepositoryGeneration::new(1), &index(1))
            .expect("the first generation activates");
        assert_eq!(store.active_index().expect("readable").generation.get(), 1);

        // A sync that wrote the next generation's document and stopped before the pointer moved.
        let path = store.index_path(2);
        write_atomically(
            &store.root.join("staging"),
            &path,
            index(2).canonical_json().expect("renderable").as_bytes(),
        )
        .expect("the document is written");
        assert!(path.is_file());
        assert_eq!(
            store.active_index().expect("readable").generation.get(),
            1,
            "the previous index stays current until the pointer moves"
        );

        store
            .activate_index(RepositoryGeneration::new(2), &index(2))
            .expect("the second generation activates");
        assert_eq!(store.active_index().expect("readable").generation.get(), 2);
    }

    #[test]
    fn a_package_becomes_visible_only_when_every_payload_verified() {
        let (_directory, store) = store();
        let digest = PayloadDigest::of(b"manifest");
        let mut staged = store.stage_package(digest).expect("a staging directory");
        staged.write("plugin.json", b"manifest").expect("written");
        assert!(!store.has_package(digest));
        staged.abandon();
        assert!(!store.has_package(digest));

        let mut staged = store.stage_package(digest).expect("a staging directory");
        staged.write("plugin.json", b"manifest").expect("written");
        staged
            .write("presentation.json", b"presentation")
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
        staged.write("plugin.json", b"one").expect("written");
        let refusal = staged
            .write("plugin.json", b"two")
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
        assert!(store.has_payload(live), "a live-bound payload is kept");
        assert!(!store.has_payload(spare));

        // Nothing unprotected is left, so the refusal names the resource rather than taking the
        // live-bound payload.
        ledger.add_payload_bytes(24);
        let refusal = store
            .reclaim(24, &mut ledger, &protected, "component.wasm")
            .expect_err("nothing else may be evicted");
        let message = refusal.to_string();
        assert!(message.contains("payload_cache_bytes"), "{message}");
        assert!(message.contains("never evicted"), "{message}");
        assert!(store.has_payload(live));
    }
}
