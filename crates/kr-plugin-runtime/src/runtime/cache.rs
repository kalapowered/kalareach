//! The compiled-code cache: what it keys on, and what it refuses.
//!
//! Compiling a component takes long enough that doing it once per binding would be visible, and
//! short enough that caching it is uninteresting unless the cache is safe. This module is the
//! safety.
//!
//! # The key
//!
//! Three things, all three necessary:
//!
//! | Part | Why |
//! | --- | --- |
//! | the Wasm digest | different code compiles to different machine code |
//! | the engine version | a different engine produces and expects a different artefact format |
//! | the target features | machine code for one instruction set is not machine code for another |
//!
//! The engine version and the target features come together from the engine's own compatibility
//! hash, so an engine that changes anything about how it compiles misses the cache rather than
//! loading something it cannot run.
//!
//! # What is never deserialised
//!
//! A serialised component is machine code. Deserialising one is equivalent to loading a shared
//! library: it is not validated Wasm, and nothing this host does to it makes it validated Wasm. So
//! there are two separate questions, and it is worth being exact about which one the manifest
//! answers.
//!
//! **Which artefact is this?** The manifest answers that, and the answers are checked:
//!
//! * it names the Wasm digest the caller is asking for, so an artefact filed under one component
//!   cannot be served for another;
//! * it names the engine's compatibility hash and the target, so an artefact another engine or
//!   another instruction set produced is refused rather than loaded and trusted;
//! * it names the artefact's own digest and length, which are checked against the bytes this host
//!   then hands to the engine: the same bytes, read once, not the file reopened afterwards;
//! * it carries a marker saying a local compilation produced it, so an artefact that arrived any
//!   other way is a miss rather than a load.
//!
//! **Could somebody put machine code here on purpose?** The manifest does not answer that, and no
//! manifest could: every field in it is one a writer of this directory could produce. What answers
//! it is the directory, which is the owner's own and nobody else's. A process that can write here
//! runs as this user and can replace the plugin host's own executable, so the cache is not where
//! that boundary is drawn and this module does not pretend otherwise.
//!
//! What the checks above do buy, on top of the directory, is that a *downloaded* artefact cannot
//! become a cache entry by accident or by being dropped in: a payload fetched from a catalogue has
//! no manifest, and one filed under a digest the caller did not verify is refused by name. Section
//! 11's rule is that a downloaded native-code cache is never deserialised as validated Wasm, and
//! that is the rule these checks keep.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use kr_plugin_sdk::digest::PayloadDigest;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::runtime::error::{RuntimeError, RuntimeResult};

/// The marker a manifest carries to say what produced the artefact beside it.
pub const PRODUCED_BY: &str = "compiled in process from validated wasm";

/// The manifest format version.
pub const MANIFEST_VERSION: u32 = 1;

/// The file extension of a compiled artefact.
pub const ARTEFACT_EXTENSION: &str = "cwasm";

/// The file extension of an artefact's manifest.
pub const MANIFEST_EXTENSION: &str = "json";

/// The largest manifest this host will read.
const MAX_MANIFEST_BYTES: u64 = 8 * 1024;

/// The largest compiled artefact this host will read.
///
/// Machine code for a component is a few times the size of its Wasm, and the Wasm itself is bounded
/// at [`crate::runtime::compile::MAX_COMPONENT_BYTES`]. A file past this bound is not something
/// this cache wrote.
const MAX_ARTEFACT_BYTES: u64 = 256 * 1024 * 1024;

/// How many compiled components this cache keeps in memory.
///
/// A component this process compiled or loaded once is kept, so a second binding of the same
/// package neither compiles nor reads a file: the one in memory is the one this process produced,
/// and no question of provenance arises for it at all. Past this many, later components are served
/// from disk; the bound is what keeps the convenience from becoming an unbounded cache of machine
/// code.
const MAX_RESIDENT: usize = 32;

/// What a cache entry records about itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CacheManifest {
    /// The manifest format version.
    pub manifest_version: u32,
    /// The digest of the Wasm this artefact was compiled from.
    pub wasm_digest: PayloadDigest,
    /// The length of that Wasm.
    pub wasm_bytes: u64,
    /// The engine's compatibility hash: its version and its compilation settings together.
    pub engine_compatibility: String,
    /// The engine version, for a person reading the directory.
    pub engine_version: String,
    /// The target triple the artefact holds machine code for.
    pub target: String,
    /// The digest of the artefact beside this manifest.
    pub artefact_digest: PayloadDigest,
    /// The length of that artefact.
    pub artefact_bytes: u64,
    /// What produced the artefact.
    pub produced_by: String,
}

impl CacheManifest {
    /// Returns true when this manifest describes an artefact this host may read back.
    #[must_use]
    pub fn describes_local_compilation(&self) -> bool {
        self.manifest_version == MANIFEST_VERSION && self.produced_by == PRODUCED_BY
    }
}

/// The identity of one cache entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheKey {
    /// The digest of the validated Wasm.
    pub wasm_digest: PayloadDigest,
    /// The length of that Wasm.
    pub wasm_bytes: u64,
    /// The engine's compatibility hash.
    pub engine_compatibility: String,
    /// The engine version.
    pub engine_version: String,
    /// The target triple.
    pub target: String,
}

impl CacheKey {
    /// Returns the directory name the engine's identity maps to.
    ///
    /// Entries for different engines live in different directories rather than side by side, so a
    /// host that has run two engine versions can be inspected and pruned by directory.
    #[must_use]
    pub fn engine_directory(&self) -> String {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.engine_compatibility.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.target.as_bytes());
        let digest = hasher.finalize();
        format!("{}-{}", self.engine_version, hex_of(&digest[..8]))
    }

    /// Returns the base file name of this entry, without an extension.
    #[must_use]
    pub fn entry_name(&self) -> String {
        self.wasm_digest.to_string()
    }
}

fn hex_of(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// The cache of compiled components: the ones in this process's memory, and the ones on disk.
/// One compiled component this process is holding, and what it was made from.
#[derive(Clone, Debug)]
struct Resident {
    component: wasmtime::component::Component,
    artefact_bytes: u64,
}

/// The compiled-code cache: a directory of artefacts, and what this process is holding from it.
#[derive(Clone, Debug)]
pub struct CompiledCache {
    root: PathBuf,
    /// Each entry's component and the artefact bytes it was made from. Shared by every clone,
    /// because every clone is the same cache. The bytes are what lets a host report what its
    /// compiled cache is costing rather than only how many entries it holds: section 5 asks for
    /// resource accounting that includes compiled caches, and a count of entries is not that.
    resident: Arc<Mutex<HashMap<String, Resident>>>,
}

impl CompiledCache {
    /// Opens the cache under `root`, creating the owner-only directory if it is absent.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::CacheUnusable`] when the directory cannot be created or is not the
    /// owner's own private directory.
    pub fn open(root: impl Into<PathBuf>) -> RuntimeResult<Self> {
        let root = root.into();
        kr_ipc::paths::create_private_directory(&root).map_err(|error| {
            RuntimeError::CacheUnusable {
                path: root.display().to_string(),
                detail: error.to_string(),
            }
        })?;
        Ok(Self {
            root,
            resident: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Returns how many compiled components this process is holding in memory.
    #[must_use]
    pub fn resident(&self) -> usize {
        self.resident.lock().map_or(0, |resident| resident.len())
    }

    /// Returns how many compiled bytes this process is holding in memory.
    ///
    /// The artefacts those components were made from, which is what this host can measure: what the
    /// engine then holds for one is the engine's own and is not reported as though it were known.
    #[must_use]
    pub fn resident_bytes(&self) -> u64 {
        self.resident.lock().map_or(0, |resident| {
            resident.values().map(|held| held.artefact_bytes).sum()
        })
    }

    /// Returns the name an entry is held under in memory.
    fn resident_name(key: &CacheKey) -> String {
        format!("{}/{}", key.engine_directory(), key.entry_name())
    }

    /// Returns the component for a key if this process already has it in memory.
    #[must_use]
    pub fn resident_component(&self, key: &CacheKey) -> Option<wasmtime::component::Component> {
        self.resident.lock().ok().and_then(|resident| {
            resident
                .get(&Self::resident_name(key))
                .map(|held| held.component.clone())
        })
    }

    /// Keeps a component in memory, up to the resident bound.
    fn keep(&self, key: &CacheKey, component: &wasmtime::component::Component, bytes: u64) {
        if let Ok(mut resident) = self.resident.lock()
            && resident.len() < MAX_RESIDENT
        {
            resident.insert(
                Self::resident_name(key),
                Resident {
                    component: component.clone(),
                    artefact_bytes: bytes,
                },
            );
        }
    }

    /// Returns the root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the directory entries for a key are stored in.
    #[must_use]
    pub fn directory_for(&self, key: &CacheKey) -> PathBuf {
        self.root.join(key.engine_directory())
    }

    /// Returns the artefact path for a key.
    #[must_use]
    pub fn artefact_path(&self, key: &CacheKey) -> PathBuf {
        self.directory_for(key)
            .join(format!("{}.{ARTEFACT_EXTENSION}", key.entry_name()))
    }

    /// Returns the manifest path for a key.
    #[must_use]
    pub fn manifest_path(&self, key: &CacheKey) -> PathBuf {
        self.directory_for(key)
            .join(format!("{}.{MANIFEST_EXTENSION}", key.entry_name()))
    }

    /// Reads an entry's manifest and its artefact, checking them against the key.
    ///
    /// Returns the manifest and the artefact bytes together, because the bytes that were checked
    /// and the bytes that are loaded have to be the same bytes: reopening the file afterwards
    /// would check one thing and load another.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::CacheRefused`] when a manifest exists and does not match the key,
    /// the engine or the artefact on disk. A missing manifest is not a refusal; it is a miss.
    pub fn verify(&self, key: &CacheKey) -> RuntimeResult<Option<(CacheManifest, Vec<u8>)>> {
        let manifest_path = self.manifest_path(key);
        let Some(bytes) = kr_ipc::paths::read_owner_only_file(&manifest_path, MAX_MANIFEST_BYTES)
            .map_err(|error| RuntimeError::CacheRefused {
            detail: format!("{}: {error}", manifest_path.display()),
        })?
        else {
            return Ok(None);
        };
        let manifest: CacheManifest = serde_json::from_slice(&bytes).map_err(|error| {
            RuntimeError::cache_refused(format!("unreadable manifest: {error}"))
        })?;

        if !manifest.describes_local_compilation() {
            return Err(RuntimeError::cache_refused(format!(
                "the entry says it was produced by {:?}, and only an artefact this host compiled from validated wasm is read back",
                manifest.produced_by
            )));
        }
        if manifest.wasm_digest != key.wasm_digest {
            return Err(RuntimeError::cache_refused(
                "the entry was compiled from different wasm than the caller verified",
            ));
        }
        if manifest.wasm_bytes != key.wasm_bytes {
            return Err(RuntimeError::cache_refused(
                "the entry was compiled from wasm of a different length",
            ));
        }
        if manifest.engine_compatibility != key.engine_compatibility {
            return Err(RuntimeError::cache_refused(format!(
                "the entry was produced by an engine with compatibility {}, and this one is {}",
                manifest.engine_compatibility, key.engine_compatibility
            )));
        }
        if manifest.target != key.target {
            return Err(RuntimeError::cache_refused(format!(
                "the entry holds machine code for {}, and this host is {}",
                manifest.target, key.target
            )));
        }

        let artefact_path = self.artefact_path(key);
        let Some(artefact) =
            kr_ipc::paths::read_owner_only_file(&artefact_path, MAX_ARTEFACT_BYTES).map_err(
                |error| RuntimeError::CacheRefused {
                    detail: format!("{}: {error}", artefact_path.display()),
                },
            )?
        else {
            return Err(RuntimeError::cache_refused(
                "the entry's manifest is there and its artefact is not",
            ));
        };
        if artefact.len() as u64 != manifest.artefact_bytes {
            return Err(RuntimeError::cache_refused(
                "the artefact is not the length its manifest records",
            ));
        }
        if PayloadDigest::of(&artefact) != manifest.artefact_digest {
            return Err(RuntimeError::cache_refused(
                "the artefact is not the bytes its manifest records",
            ));
        }
        Ok(Some((manifest, artefact)))
    }

    /// Loads a cached component, or says there is none.
    ///
    /// The `unsafe` block is this crate's only one, and it is handed the very bytes
    /// [`Self::verify`] checked rather than a path to read again. `deserialize_file` would be the
    /// obvious call here and is the wrong one twice over: it reopens the file, so the bytes it
    /// loads need not be the bytes that were checked, and it maps the file for the component's
    /// whole life, so a file that changed afterwards would change what is running.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::CacheRefused`] when an entry exists and fails any of the checks, or
    /// when the engine will not load bytes that passed them.
    pub fn load(
        &self,
        engine: &wasmtime::Engine,
        key: &CacheKey,
    ) -> RuntimeResult<Option<wasmtime::component::Component>> {
        // What this process compiled or loaded already. Serving it from here is not only quicker:
        // it is a component whose provenance is this process's own, with no file in the question.
        if let Some(component) = self.resident_component(key) {
            return Ok(Some(component));
        }
        let Some((_manifest, artefact)) = self.verify(key)? else {
            return Ok(None);
        };
        // SAFETY: these are the bytes `verify` has just checked, in memory, not a path reopened
        // afterwards. It established that the manifest beside them records this engine's
        // compatibility hash, this host's target, the digest of the Wasm the caller verified, and
        // the digest and length of these bytes; and that it carries the marker only a local
        // compilation writes. The directory they came from is the owner's own. That is the
        // condition section 11 puts on reading a serialised artefact back rather than validating
        // Wasm.
        #[allow(unsafe_code)]
        let component = unsafe { wasmtime::component::Component::deserialize(engine, &artefact) }
            .map_err(|error| {
            RuntimeError::cache_refused(format!("{}: {error}", self.artefact_path(key).display()))
        })?;
        self.keep(key, &component, artefact.len() as u64);
        Ok(Some(component))
    }

    /// Files a freshly compiled component under a key.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::CacheUnusable`] when the entry cannot be written.
    pub fn store(
        &self,
        key: &CacheKey,
        component: &wasmtime::component::Component,
    ) -> RuntimeResult<()> {
        let directory = self.directory_for(key);
        kr_ipc::paths::create_private_directory(&directory).map_err(|error| {
            RuntimeError::CacheUnusable {
                path: directory.display().to_string(),
                detail: error.to_string(),
            }
        })?;
        let artefact = component
            .serialize()
            .map_err(|error| RuntimeError::CacheUnusable {
                path: directory.display().to_string(),
                detail: format!("the engine would not serialise the component: {error}"),
            })?;
        let manifest = CacheManifest {
            manifest_version: MANIFEST_VERSION,
            wasm_digest: key.wasm_digest,
            wasm_bytes: key.wasm_bytes,
            engine_compatibility: key.engine_compatibility.clone(),
            engine_version: key.engine_version.clone(),
            target: key.target.clone(),
            artefact_digest: PayloadDigest::of(&artefact),
            artefact_bytes: artefact.len() as u64,
            produced_by: PRODUCED_BY.to_owned(),
        };
        let document =
            serde_json::to_vec(&manifest).map_err(|error| RuntimeError::CacheUnusable {
                path: directory.display().to_string(),
                detail: format!("the manifest could not be written: {error}"),
            })?;

        // The artefact first, then the manifest. A manifest is what makes an artefact loadable, so
        // writing it last means an interrupted store leaves an unreferenced artefact rather than a
        // manifest that points at an incomplete file.
        let artefact_path = self.artefact_path(key);
        kr_ipc::paths::write_owner_only_file(&artefact_path, &artefact).map_err(|error| {
            RuntimeError::CacheUnusable {
                path: artefact_path.display().to_string(),
                detail: error.to_string(),
            }
        })?;
        let manifest_path = self.manifest_path(key);
        kr_ipc::paths::write_owner_only_file(&manifest_path, &document).map_err(|error| {
            RuntimeError::CacheUnusable {
                path: manifest_path.display().to_string(),
                detail: error.to_string(),
            }
        })?;
        self.keep(key, component, artefact.len() as u64);
        Ok(())
    }

    /// Removes an entry: the one in memory, and the artefact and manifest together.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::CacheUnusable`] when a present entry cannot be removed.
    pub fn remove(&self, key: &CacheKey) -> RuntimeResult<()> {
        if let Ok(mut resident) = self.resident.lock() {
            resident.remove(&Self::resident_name(key));
        }
        for path in [self.manifest_path(key), self.artefact_path(key)] {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(RuntimeError::CacheUnusable {
                        path: path.display().to_string(),
                        detail: error.to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> CacheKey {
        CacheKey {
            wasm_digest: PayloadDigest::of(b"a component"),
            wasm_bytes: 11,
            engine_compatibility: "engine-abc".to_owned(),
            engine_version: "48.0.2".to_owned(),
            target: "aarch64-apple-darwin".to_owned(),
        }
    }

    fn cache() -> (tempfile::TempDir, CompiledCache) {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let cache = CompiledCache::open(directory.path().join("plugin-cache")).expect("a cache");
        (directory, cache)
    }

    fn write_manifest(cache: &CompiledCache, key: &CacheKey, manifest: &CacheManifest) {
        let directory = cache.directory_for(key);
        kr_ipc::paths::create_private_directory(&directory).expect("the entry directory");
        kr_ipc::paths::write_owner_only_file(
            &cache.manifest_path(key),
            &serde_json::to_vec(manifest).expect("a manifest"),
        )
        .expect("the manifest");
    }

    fn manifest_for(key: &CacheKey, artefact: &[u8]) -> CacheManifest {
        CacheManifest {
            manifest_version: MANIFEST_VERSION,
            wasm_digest: key.wasm_digest,
            wasm_bytes: key.wasm_bytes,
            engine_compatibility: key.engine_compatibility.clone(),
            engine_version: key.engine_version.clone(),
            target: key.target.clone(),
            artefact_digest: PayloadDigest::of(artefact),
            artefact_bytes: artefact.len() as u64,
            produced_by: PRODUCED_BY.to_owned(),
        }
    }

    #[test]
    fn an_empty_cache_is_a_miss_rather_than_a_refusal() {
        let (_directory, cache) = cache();
        assert!(cache.verify(&key()).expect("a lookup").is_none());
    }

    #[test]
    fn a_verified_entry_returns_the_bytes_that_were_checked() {
        let (_directory, cache) = cache();
        let key = key();
        let artefact = b"machine code".to_vec();
        write_manifest(&cache, &key, &manifest_for(&key, &artefact));
        kr_ipc::paths::write_owner_only_file(&cache.artefact_path(&key), &artefact)
            .expect("the artefact");

        let (manifest, checked) = cache
            .verify(&key)
            .expect("a lookup")
            .expect("the entry is there");
        assert_eq!(manifest.wasm_digest, key.wasm_digest);
        // The same bytes, so what is loaded cannot be something the file became afterwards.
        assert_eq!(checked, artefact);
    }

    #[test]
    fn the_engine_identity_decides_which_directory_an_entry_lives_in() {
        let mut first = key();
        let mut second = key();
        second.engine_compatibility = "engine-def".to_owned();
        assert_ne!(first.engine_directory(), second.engine_directory());

        first.target = "x86_64-unknown-linux-gnu".to_owned();
        assert_ne!(first.engine_directory(), key().engine_directory());
    }

    #[test]
    fn the_wasm_digest_names_the_entry_so_two_components_never_share_one() {
        let first = key();
        let mut second = key();
        second.wasm_digest = PayloadDigest::of(b"another component");
        assert_ne!(first.entry_name(), second.entry_name());
    }

    #[test]
    fn an_entry_compiled_from_different_wasm_is_refused() {
        let (_directory, cache) = cache();
        let key = key();
        let artefact = b"machine code".to_vec();
        let mut manifest = manifest_for(&key, &artefact);
        manifest.wasm_digest = PayloadDigest::of(b"something else");
        write_manifest(&cache, &key, &manifest);
        kr_ipc::paths::write_owner_only_file(&cache.artefact_path(&key), &artefact)
            .expect("the artefact");

        let error = cache.verify(&key).expect_err("the entry is refused");
        assert!(error.to_string().contains("different wasm"));
    }

    #[test]
    fn an_entry_from_another_engine_is_refused() {
        let (_directory, cache) = cache();
        let key = key();
        let artefact = b"machine code".to_vec();
        let mut manifest = manifest_for(&key, &artefact);
        manifest.engine_compatibility = "engine-from-last-year".to_owned();
        write_manifest(&cache, &key, &manifest);
        kr_ipc::paths::write_owner_only_file(&cache.artefact_path(&key), &artefact)
            .expect("the artefact");

        let error = cache.verify(&key).expect_err("the entry is refused");
        assert!(error.to_string().contains("engine-from-last-year"));
    }

    #[test]
    fn an_entry_for_another_target_is_refused() {
        let (_directory, cache) = cache();
        let key = key();
        let artefact = b"machine code".to_vec();
        let mut manifest = manifest_for(&key, &artefact);
        manifest.target = "riscv64gc-unknown-linux-gnu".to_owned();
        write_manifest(&cache, &key, &manifest);
        kr_ipc::paths::write_owner_only_file(&cache.artefact_path(&key), &artefact)
            .expect("the artefact");

        let error = cache.verify(&key).expect_err("the entry is refused");
        assert!(error.to_string().contains("riscv64gc-unknown-linux-gnu"));
    }

    #[test]
    fn a_downloaded_artefact_has_no_manifest_and_is_never_loaded() {
        let (_directory, cache) = cache();
        let key = key();
        let directory = cache.directory_for(&key);
        kr_ipc::paths::create_private_directory(&directory).expect("the entry directory");
        // A native-code artefact placed in the cache by anything other than a local compilation.
        kr_ipc::paths::write_owner_only_file(
            &cache.artefact_path(&key),
            b"downloaded machine code",
        )
        .expect("the artefact");

        assert!(
            cache.verify(&key).expect("a lookup").is_none(),
            "an artefact with no manifest must be a miss, not a load"
        );
    }

    #[test]
    fn an_artefact_claimed_by_a_manifest_it_does_not_match_is_refused() {
        let (_directory, cache) = cache();
        let key = key();
        let manifest = manifest_for(&key, b"the artefact that was compiled");
        write_manifest(&cache, &key, &manifest);
        kr_ipc::paths::write_owner_only_file(
            &cache.artefact_path(&key),
            b"the artefact that is there now",
        )
        .expect("the artefact");

        let error = cache.verify(&key).expect_err("the entry is refused");
        assert!(error.to_string().contains("not the bytes"));
    }

    #[test]
    fn a_manifest_that_does_not_claim_a_local_compilation_is_refused() {
        let (_directory, cache) = cache();
        let key = key();
        let artefact = b"machine code".to_vec();
        let mut manifest = manifest_for(&key, &artefact);
        manifest.produced_by = "downloaded from the catalogue".to_owned();
        write_manifest(&cache, &key, &manifest);
        kr_ipc::paths::write_owner_only_file(&cache.artefact_path(&key), &artefact)
            .expect("the artefact");

        let error = cache.verify(&key).expect_err("the entry is refused");
        assert!(error.to_string().contains("downloaded from the catalogue"));
    }

    #[test]
    fn a_manifest_with_no_artefact_is_refused_rather_than_treated_as_a_miss() {
        let (_directory, cache) = cache();
        let key = key();
        write_manifest(&cache, &key, &manifest_for(&key, b"machine code"));
        let error = cache.verify(&key).expect_err("the entry is refused");
        assert!(error.to_string().contains("artefact is not"));
    }

    #[test]
    fn removing_an_entry_removes_both_files_and_a_second_removal_is_quiet() {
        let (_directory, cache) = cache();
        let key = key();
        let artefact = b"machine code".to_vec();
        write_manifest(&cache, &key, &manifest_for(&key, &artefact));
        kr_ipc::paths::write_owner_only_file(&cache.artefact_path(&key), &artefact)
            .expect("the artefact");

        cache.remove(&key).expect("the entry is removed");
        assert!(!cache.manifest_path(&key).exists());
        assert!(!cache.artefact_path(&key).exists());
        cache.remove(&key).expect("a second removal is quiet");
    }

    #[test]
    fn an_unreadable_manifest_is_refused_with_a_reason() {
        let (_directory, cache) = cache();
        let key = key();
        let directory = cache.directory_for(&key);
        kr_ipc::paths::create_private_directory(&directory).expect("the entry directory");
        kr_ipc::paths::write_owner_only_file(&cache.manifest_path(&key), b"not json")
            .expect("the manifest");
        let error = cache.verify(&key).expect_err("the entry is refused");
        assert!(error.to_string().contains("unreadable manifest"));
    }
}
