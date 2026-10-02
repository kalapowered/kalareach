//! Seeding the catalogue from the generation compiled into the host.
//!
//! A fresh installation has no repository and may have no network, and it still has to match,
//! present and activate the adapters' packages. So the host carries a signed catalogue generation:
//! the metadata that verifies it, its index and the packages of the adapters. The seed enrols the
//! official repository against the highest root that generation ships, activates the generation
//! through the ordinary update client over an in-memory transport, and installs each bundled
//! package once, enabled and with an empty grant, so that admission has something to admit.
//!
//! What the seed never does: grant anything (every capability past the default ceiling stays the
//! owner's decision, shown the publisher's own words when the owner makes it); replace an
//! installation that is already there; undo an owner's removal, uninstall or disable; touch an
//! enrolment it did not make; or trust a root this build does not name. A release build names no
//! root until the production root exists, so it refuses every bundle and reports why; a build with
//! debug assertions also names the development lineage's root keys, which anybody can sign with.

use std::collections::BTreeMap;
use std::sync::Arc;

use kr_plugin_sdk::bundle::{BundleLock, BundledFile, BundledPackage};
use kr_plugin_sdk::catalogue::CatalogueIndex;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::ids::PluginId;
use kr_plugin_sdk::limits::RepositoryBudgets;
use kr_protocol::ids::{EnvironmentId, RepositoryGeneration};
use tough::schema::{RoleType, Root, Signed};

use crate::authority::Authority;
use crate::ceiling::InstallationGrant;
use crate::error::{CatalogueError, CatalogueResult};
use crate::install::Installation;
use crate::repository::{CapabilityCeiling, Enrolment, EnrolmentKey, RepositoryId, RepositoryKind};
use crate::{Catalogue, Change, Transition, Via, committing, extract};

/// What the host calls the repository the seed enrols.
pub const OFFICIAL: &str = "official";

/// The prefix of the record that names the enrolment the seed made.
pub const SEEDED: &str = "seeded:";

/// The prefix of the record that says the owner removed the enrolment the seed made.
pub const REMOVED: &str = "removed:";

/// The prefix of the record that says the seed found the owner's own enrolment of this root.
pub const DECLINED: &str = "declined:";

/// The prefix of the record that says what the seed did with one bundled package.
pub const SEED_INSTALLED: &str = "seed_installed:";

/// The prefix of the record that says where the seeded generation came from.
pub const PROVENANCE: &str = "seed_provenance:";

/// What a root's keys have to be for a build to trust it without the owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permitted {
    /// Every key is one the production set names, and the root meets the production threshold.
    Production,
    /// Every key is one of the development lineage's, and this build admits those.
    Development,
}

/// Why a build does not trust a root.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The root declares no key for its own role.
    #[error("the root declares no key for the root role")]
    NoKeys,
    /// A release trusts no bundled root yet.
    #[error(
        "this build trusts no bundled root: the production root keys are not yet committed, and a \
         release does not trust the development lineage"
    )]
    NoProductionRoot,
    /// A key is in no set this build names.
    #[error("the root names the key {0}, which this build does not trust")]
    UnknownKey(String),
    /// Every key is trusted, and not by one set: the root has a production key and a development
    /// one.
    #[error("the root names production keys and development keys together")]
    Mixed,
    /// The root is the production root's keys with fewer signatures than the production root needs.
    #[error("the root requires {have} root signature(s) and a production root requires {need}")]
    BelowThreshold {
        /// The threshold the root carries.
        have: u64,
        /// The threshold a production root has to carry.
        need: u64,
    },
}

/// Decides whether a build trusts a root, from the key identifiers of its root role alone.
///
/// Nothing a root says about itself is read: a marker in signed data would be a claim by whoever
/// signed it. A root is trusted as a production root only when the production set is not empty,
/// every key is in it and the root meets its threshold; and as a development root only where
/// `development` is `Some` (a build with debug assertions) and every key is in it. A root with one
/// key of each, with no key, or with a key of neither is refused.
///
/// # Errors
///
/// Returns why the root is not trusted.
pub fn permitted(
    root_key_ids: &[&str],
    threshold: u64,
    production: &[&str],
    production_threshold: u64,
    development: Option<&[&str]>,
) -> Result<Permitted, Refusal> {
    if root_key_ids.is_empty() {
        return Err(Refusal::NoKeys);
    }
    if !production.is_empty() && root_key_ids.iter().all(|key| production.contains(key)) {
        return if threshold >= production_threshold {
            Ok(Permitted::Production)
        } else {
            Err(Refusal::BelowThreshold {
                have: threshold,
                need: production_threshold,
            })
        };
    }
    if let Some(development) = development
        && root_key_ids.iter().all(|key| development.contains(key))
    {
        return Ok(Permitted::Development);
    }
    if production.is_empty() && development.is_none() {
        return Err(Refusal::NoProductionRoot);
    }
    match root_key_ids.iter().find(|key| {
        !production.contains(key) && !development.is_some_and(|keys| keys.contains(key))
    }) {
        Some(unknown) => Err(Refusal::UnknownKey((*unknown).to_owned())),
        None => Err(Refusal::Mixed),
    }
}

/// What a build trusts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedTrust {
    production: Vec<String>,
    production_threshold: u64,
    development: Option<Vec<String>>,
}

impl SeedTrust {
    /// The trust this build commits: the production keys, and the development lineage's where
    /// this build has debug assertions.
    #[must_use]
    pub fn compiled() -> Self {
        Self {
            production: crate::seed_trust::PRODUCTION_ROOT_KEYS
                .iter()
                .map(|key| (*key).to_owned())
                .collect(),
            production_threshold: crate::seed_trust::PRODUCTION_ROOT_THRESHOLD,
            development: cfg!(debug_assertions).then(|| {
                crate::seed_trust::DEVELOPMENT_ROOT_KEYS
                    .iter()
                    .map(|key| (*key).to_owned())
                    .collect()
            }),
        }
    }

    /// A trust a test names: production keys, their threshold and the development keys.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn named(
        production: Vec<String>,
        production_threshold: u64,
        development: Option<Vec<String>>,
    ) -> Self {
        Self {
            production,
            production_threshold,
            development,
        }
    }

    /// The trust of a test that admits the development set, naming the key identifiers of
    /// `root`'s own role.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::Untrusted`] when the root cannot be read.
    #[cfg(any(test, feature = "testing"))]
    pub fn trusting_root_of(root: &[u8]) -> CatalogueResult<Self> {
        let (keys, _) = root_role(root)?;
        Ok(Self::named(Vec::new(), 1, Some(keys)))
    }

    /// Decides whether this trust names the root, from its own bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::Untrusted`] when the root cannot be read or is not trusted.
    pub fn permit(&self, root: &[u8]) -> CatalogueResult<Permitted> {
        let (keys, threshold) = root_role(root)?;
        let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
        let production: Vec<&str> = self.production.iter().map(String::as_str).collect();
        let development: Option<Vec<&str>> = self
            .development
            .as_ref()
            .map(|keys| keys.iter().map(String::as_str).collect());
        permitted(
            &keys,
            threshold,
            &production,
            self.production_threshold,
            development.as_deref(),
        )
        .map_err(|refusal| CatalogueError::Untrusted {
            detail: refusal.to_string(),
        })
    }
}

/// The key identifiers of a root's own role and the signatures it needs, as the client reads them.
pub(crate) fn root_role(root: &[u8]) -> CatalogueResult<(Vec<String>, u64)> {
    let signed: Signed<Root> =
        serde_json::from_slice(root).map_err(|source| CatalogueError::Untrusted {
            detail: format!("a bundled root could not be read: {source}"),
        })?;
    let role =
        signed
            .signed
            .roles
            .get(&RoleType::Root)
            .ok_or_else(|| CatalogueError::Untrusted {
                detail: Refusal::NoKeys.to_string(),
            })?;
    let mut keys: Vec<String> = role.keyids.iter().map(|key| hex_of(key.as_ref())).collect();
    keys.sort();
    Ok((keys, role.threshold.get()))
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The generation compiled into the host, with what it needs to be verified and served.
#[derive(Clone, Debug)]
pub struct SeedBundle {
    lock: BundleLock,
    files: Arc<BTreeMap<String, Vec<u8>>>,
    by_digest: Arc<BTreeMap<PayloadDigest, String>>,
    trust: SeedTrust,
    roots: BTreeMap<u64, String>,
}

impl SeedBundle {
    /// The bundle compiled into this build.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::Integrity`] when what is compiled in is not what its lock names,
    /// which a build made from this repository's own bundle never is.
    pub fn embedded() -> CatalogueResult<Self> {
        let files = crate::bundled_files::FILES
            .iter()
            .map(|(path, bytes)| ((*path).to_owned(), bytes.to_vec()))
            .collect();
        Self::assemble(crate::bundled_files::LOCK, files, SeedTrust::compiled())
    }

    /// A bundle made of files a test supplies, trusting what the test names.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::embedded`] returns for the files given.
    #[cfg(any(test, feature = "testing"))]
    pub fn from_files(
        lock: &[u8],
        files: BTreeMap<String, Vec<u8>>,
        trust: SeedTrust,
    ) -> CatalogueResult<Self> {
        Self::assemble(lock, files, trust)
    }

    /// A bundle made of a generation published in a directory (`metadata/` and `targets/`), with a
    /// lock written for every package its index lists whose files are there, trusting `trust`.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::embedded`] returns for the files found.
    #[cfg(any(test, feature = "testing"))]
    pub fn from_directory(directory: &std::path::Path, trust: SeedTrust) -> CatalogueResult<Self> {
        let unreadable = |error: std::io::Error| CatalogueError::StorageUnavailable {
            detail: format!("{} cannot be read: {error}", directory.display()),
        };
        let mut files = BTreeMap::new();
        let mut pending = vec![directory.to_path_buf()];
        while let Some(current) = pending.pop() {
            for entry in std::fs::read_dir(&current).map_err(unreadable)? {
                let path = entry.map_err(unreadable)?.path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                let relative = path
                    .strip_prefix(directory)
                    .map_or_else(|_| path.clone(), std::path::Path::to_path_buf)
                    .to_string_lossy()
                    .replace('\\', "/");
                if relative.starts_with("metadata/") || relative.starts_with("targets/") {
                    files.insert(relative, std::fs::read(&path).map_err(unreadable)?);
                }
            }
        }
        let integrity = |detail: String| CatalogueError::Integrity { detail };
        let index: CatalogueIndex = serde_json::from_slice(
            files
                .get("targets/index.json")
                .ok_or_else(|| integrity("the directory carries no index".to_owned()))?,
        )
        .map_err(|source| integrity(format!("its index cannot be read: {source}")))?;
        let highest = files
            .keys()
            .filter_map(|path| {
                path.strip_prefix("metadata/")?
                    .strip_suffix(".root.json")?
                    .parse::<u64>()
                    .ok()
            })
            .max()
            .ok_or_else(|| integrity("the directory ships no numbered root".to_owned()))?;
        let root_bytes = files[&format!("metadata/{highest}.root.json")].clone();
        let root: serde_json::Value = serde_json::from_slice(&root_bytes)
            .map_err(|source| integrity(format!("its root cannot be read: {source}")))?;
        let describe = |path: &str| {
            let bytes = &files[path];
            serde_json::json!({
                "path": path,
                "digest": PayloadDigest::of(bytes).to_string(),
                "size_bytes": bytes.len().to_string(),
            })
        };
        let mut metadata: Vec<serde_json::Value> = files
            .keys()
            .filter(|path| path.starts_with("metadata/") || path.as_str() == "targets/index.json")
            .map(|path| describe(path))
            .collect();
        metadata.sort_by_key(|entry| entry["path"].as_str().map(str::to_owned));
        let mut packages = Vec::new();
        let mut kept: Vec<String> = Vec::new();
        for entry in &index.entries {
            let prefix = format!(
                "targets/packages/{}/{}/{}",
                entry.publisher_id, entry.plugin_name, entry.version
            );
            let names: Vec<String> = std::iter::once("plugin.json".to_owned())
                .chain(
                    entry
                        .payloads
                        .iter()
                        .map(|payload| payload.path.to_string()),
                )
                .collect();
            if names
                .iter()
                .any(|name| !files.contains_key(&format!("{prefix}/{name}")))
            {
                continue;
            }
            kept.extend(names.iter().map(|name| format!("{prefix}/{name}")));
            let payloads: Vec<serde_json::Value> = entry
                .payloads
                .iter()
                .map(|payload| {
                    serde_json::json!({
                        "role": serde_json::to_value(payload.role).unwrap_or_default(),
                        "path": payload.path.as_str(),
                        "digest": payload.digest.to_string(),
                        "size_bytes": payload.size_bytes.get().to_string(),
                    })
                })
                .collect();
            packages.push(serde_json::json!({
                "directory": prefix,
                "plugin_id": entry.plugin_id.to_string(),
                "publisher_id": entry.publisher_id.to_string(),
                "plugin_name": entry.plugin_name.to_string(),
                "version": entry.version.to_string(),
                "sdk_range": entry.sdk_range.to_string(),
                "wit_range": entry.wit_range.to_string(),
                "manifest": {
                    "path": "plugin.json",
                    "digest": entry.manifest_digest.to_string(),
                    "size_bytes": entry.manifest_size_bytes.get().to_string(),
                },
                "payloads": payloads,
                "total_size_bytes": entry.total_size_bytes.get().to_string(),
            }));
        }
        files.retain(|path, _| {
            path.starts_with("metadata/")
                || path == "targets/index.json"
                || kept.iter().any(|name| name == path)
        });
        let lock = serde_json::json!({
            "lock_version": 2,
            "source": {
                "repository": "https://example.invalid/plugins",
                "commit": "0123456789abcdef0123456789abcdef01234567",
                "generation_path": "snapshots/test",
                "tree_url": "https://example.invalid/tree",
                "generation": index.generation.get().to_string(),
                "produced_at": index.produced_at.get().to_string(),
            },
            "trust_root": {
                "digest": PayloadDigest::of(&root_bytes).to_string(),
                "version": highest,
                "expires": root["signed"]["expires"],
                "key_ids": root["signed"]["roles"]["root"]["keyids"],
            },
            "metadata": metadata,
            "packages": packages,
        });
        Self::assemble(lock.to_string().as_bytes(), files, trust)
    }

    fn assemble(
        lock_bytes: &[u8],
        files: BTreeMap<String, Vec<u8>>,
        trust: SeedTrust,
    ) -> CatalogueResult<Self> {
        let integrity = |detail: String| CatalogueError::Integrity { detail };
        let lock = BundleLock::from_slice(lock_bytes, "the bundled lock")
            .map_err(|error| integrity(error.to_string()))?;

        // Every file the lock names is there with the digest and length it names, and nothing is
        // there that it does not.
        let mut declared: BTreeMap<String, (PayloadDigest, u64)> = BTreeMap::new();
        for entry in &lock.metadata {
            declared.insert(entry.path.clone(), (entry.digest, entry.size_bytes.get()));
        }
        for package in &lock.packages {
            for file in package_files(package) {
                declared.insert(
                    format!("{}/{}", package.directory, file.path),
                    (file.digest, file.size_bytes.get()),
                );
            }
        }
        for (path, (digest, size)) in &declared {
            let bytes = files
                .get(path)
                .ok_or_else(|| integrity(format!("the bundle does not carry {path}")))?;
            if bytes.len() as u64 != *size || PayloadDigest::of(bytes) != *digest {
                return Err(integrity(format!(
                    "{path} is not what the bundled lock names"
                )));
            }
        }
        if let Some(extra) = files.keys().find(|path| !declared.contains_key(*path)) {
            return Err(integrity(format!(
                "the bundle carries {extra}, which its lock does not name"
            )));
        }

        // The roots run from 1 to the highest, which is the one the lock names and the one
        // `root.json` is.
        let mut roots = BTreeMap::new();
        for path in files.keys() {
            if let Some(version) = path
                .strip_prefix("metadata/")
                .and_then(|name| name.strip_suffix(".root.json"))
                .and_then(|number| number.parse::<u64>().ok())
            {
                roots.insert(version, path.clone());
            }
        }
        let highest = roots.keys().next_back().copied().unwrap_or(0);
        if highest == 0 || (1..=highest).any(|version| !roots.contains_key(&version)) {
            return Err(integrity(
                "the bundled roots do not run from version 1 without a gap".to_owned(),
            ));
        }
        let top = &files[&roots[&highest]];
        if files.get("metadata/root.json") != Some(top) {
            return Err(integrity(
                "metadata/root.json is not the highest numbered root".to_owned(),
            ));
        }
        if u64::from(lock.trust_root.version) != highest
            || lock.trust_root.digest != PayloadDigest::of(top)
        {
            return Err(integrity(
                "the lock does not name the highest root the bundle ships".to_owned(),
            ));
        }

        // A package's manifest is the document its payloads' names come from, so the lock and the
        // manifest have to say the same about it.
        for package in &lock.packages {
            let path = format!("{}/{}", package.directory, package.manifest.path);
            let manifest: kr_plugin_sdk::plugin::PluginManifest =
                serde_json::from_slice(&files[&path])
                    .map_err(|source| integrity(format!("{path} is not a manifest: {source}")))?;
            let disagreements = package.disagreements(&manifest);
            if !disagreements.is_empty() {
                return Err(integrity(format!(
                    "the lock and the manifest of {} disagree: {}",
                    package.plugin_id,
                    disagreements.join("; ")
                )));
            }
        }

        // The index is held to the default metadata budget, and carries each package at the
        // digest the lock names.
        let index_bytes = files
            .get("targets/index.json")
            .ok_or_else(|| integrity("the bundle carries no index".to_owned()))?;
        let budgets = RepositoryBudgets::defaults();
        if index_bytes.len() as u64 > budgets.metadata_bytes.get() {
            return Err(integrity(
                "the bundled index is over the default metadata budget".to_owned(),
            ));
        }
        let index: CatalogueIndex = serde_json::from_slice(index_bytes)
            .map_err(|source| integrity(format!("the bundled index cannot be read: {source}")))?;
        if index.entries.len() as u64 > budgets.metadata_entries.get() {
            return Err(integrity(
                "the bundled index is over the default entry budget".to_owned(),
            ));
        }
        // The generation the lock names is the one the seed compares with what a store holds, so
        // it has to be the index's own.
        if index.generation != lock.source.generation
            || index.produced_at != lock.source.produced_at
        {
            return Err(integrity(format!(
                "the bundled index is generation {} built at {}, and the lock names generation {} \
                 built at {}",
                index.generation,
                index.produced_at.get(),
                lock.source.generation,
                lock.source.produced_at.get()
            )));
        }
        for package in &lock.packages {
            let entry = index.find(&package.plugin_id, &package.version);
            if entry.is_none_or(|entry| entry.manifest_digest != package.manifest.digest) {
                return Err(integrity(format!(
                    "the bundled index does not carry {} {} at the digest the lock names",
                    package.plugin_id, package.version
                )));
            }
        }

        let mut by_digest = BTreeMap::new();
        for (path, bytes) in &files {
            by_digest
                .entry(PayloadDigest::of(bytes))
                .or_insert_with(|| path.clone());
        }
        Ok(Self {
            lock,
            files: Arc::new(files),
            by_digest: Arc::new(by_digest),
            trust,
            roots,
        })
    }

    /// The generation the bundle carries.
    #[must_use]
    pub fn generation(&self) -> RepositoryGeneration {
        self.lock.source.generation
    }

    /// The highest root the bundle ships, which a new enrolment adopts.
    #[must_use]
    pub fn highest_root(&self) -> &[u8] {
        let highest = self.roots.keys().next_back().copied().unwrap_or_default();
        &self.files[&self.roots[&highest]]
    }

    /// Every root the bundle ships, by version.
    pub fn roots(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.roots
            .iter()
            .map(|(version, path)| (*version, self.files[path].as_slice()))
    }

    /// The packages the bundle carries, in the order its lock gives.
    #[must_use]
    pub fn packages(&self) -> &[BundledPackage] {
        &self.lock.packages
    }

    /// What the bundle says about where it came from.
    #[must_use]
    pub fn lock(&self) -> &BundleLock {
        &self.lock
    }

    /// The files of the bundle, by path, shared with the transport that serves them.
    pub(crate) fn shared_files(&self) -> Arc<BTreeMap<String, Vec<u8>>> {
        Arc::clone(&self.files)
    }

    /// The bytes of one file of the bundle, by its path relative to the bundle directory.
    #[must_use]
    pub fn file(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }

    /// The bytes that hash to `digest`, when they are one file of the bundle and have exactly
    /// `length`.
    #[must_use]
    pub fn payload(&self, digest: PayloadDigest, length: u64) -> Option<&[u8]> {
        let bytes = self.files.get(self.by_digest.get(&digest)?)?;
        (bytes.len() as u64 == length && PayloadDigest::of(bytes) == digest)
            .then_some(bytes.as_slice())
    }

    /// What this bundle's build trusts.
    #[must_use]
    pub const fn trust(&self) -> &SeedTrust {
        &self.trust
    }

    /// The earliest time one of the bundled metadata documents expires, as each states it: the
    /// highest root, the timestamp, the snapshot and the targets. The update client waives the
    /// root's expiry along with the others for the bundled generation, so this reports it too.
    #[must_use]
    pub fn earliest_expiry(&self) -> Option<jiff::Timestamp> {
        [
            "root.json",
            "timestamp.json",
            "snapshot.json",
            "targets.json",
        ]
        .into_iter()
        .filter_map(|name| {
            let bytes = self.files.get(&format!("metadata/{name}"))?;
            let document: serde_json::Value = serde_json::from_slice(bytes).ok()?;
            document["signed"]["expires"].as_str()?.parse().ok()
        })
        .min()
    }
}

/// A package's manifest and payloads as one list.
fn package_files(package: &BundledPackage) -> Vec<BundledFile> {
    package.files()
}

/// A point in a seeding a test stops it at, as an interruption would.
#[cfg(any(test, feature = "testing"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedPoint {
    /// After the enrolment commits and before the generation is activated.
    AfterEnrolment,
    /// After the generation is activated and before any package is installed.
    AfterActivation,
}

/// What one seeding did, for the daemon to report.
#[derive(Clone, Debug, Default)]
pub struct SeedOutcome {
    /// Whether this run enrolled the repository.
    pub enrolled: bool,
    /// The generation this run activated, where it did.
    pub activated: Option<RepositoryGeneration>,
    /// The packages this run installed.
    pub installed: Vec<PluginId>,
    /// The packages this run left as they were, because an installation was already there.
    pub left: Vec<PluginId>,
    /// The packages this run could not install, and why; nothing is recorded for them, so the
    /// next start tries them again.
    pub skipped: Vec<(PluginId, String)>,
    /// Why the seed did less than a full run for a reason the host should report: a bundle this
    /// build does not trust, or a seeded repository it will not move.
    pub notes: Vec<String>,
    /// What the owner's own choices left alone: a pin that holds back a newer bundle, a removed
    /// seeded repository, a repository of the owner's that holds the bundled root. These are
    /// supported choices and no warning.
    pub choices: Vec<String>,
    /// The time the bundled metadata expired, where it had.
    pub expired: Option<String>,
    /// What stopped the run, where something did.
    pub failure: Option<CatalogueError>,
    /// Whether the run committed anything to the catalogue's records.
    pub committed: bool,
}

impl SeedOutcome {
    /// One line for a log or a diagnostic.
    #[must_use]
    pub fn report(&self) -> String {
        let mut parts = Vec::new();
        if self.enrolled {
            parts.push("enrolled the official repository".to_owned());
        }
        if let Some(generation) = self.activated {
            parts.push(format!("activated generation {generation}"));
        }
        if !self.installed.is_empty() {
            parts.push(format!("installed {} package(s)", self.installed.len()));
        }
        if !self.left.is_empty() {
            parts.push(format!(
                "left {} installation(s) as they were",
                self.left.len()
            ));
        }
        for (plugin, reason) in &self.skipped {
            parts.push(format!("did not install {plugin}: {reason}"));
        }
        parts.extend(self.notes.iter().cloned());
        parts.extend(self.choices.iter().cloned());
        if let Some(expired) = &self.expired {
            parts.push(format!("the bundled metadata expired at {expired}"));
        }
        if let Some(failure) = &self.failure {
            parts.push(format!("stopped: {failure}"));
        }
        if parts.is_empty() {
            "nothing to seed".to_owned()
        } else {
            parts.join("; ")
        }
    }
}

/// The authority a seed runs under: its own, with no admission window to lapse and no owner's
/// confirmation, so nothing it commits can be one the owner confirmed.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SeedAuthority;

impl Authority for SeedAuthority {
    fn check(&self) -> CatalogueResult<()> {
        Ok(())
    }

    fn commit(
        &self,
        _effect: &crate::authority::Effect,
        commit: &mut dyn FnMut() -> CatalogueResult<()>,
    ) -> CatalogueResult<()> {
        commit()
    }

    fn owner_confirmed(&self) -> bool {
        false
    }
}

/// What seeding one package came to.
enum Seeded {
    /// Installed, enabled, with an empty grant.
    Installed,
    /// An installation was there, and is as it was.
    Left,
    /// Already settled by an earlier run.
    Settled,
    /// Not installed this run, for a reason that may pass.
    Skipped(String),
}

/// Where the generation a bundle activates came from: the repository, commit and generation the
/// copy was made from, and the root it was verified against.
pub(crate) fn provenance_of(bundle: &SeedBundle) -> String {
    let source = &bundle.lock().source;
    serde_json::json!({
        "repository": source.repository,
        "commit": source.commit,
        "generation": source.generation.get(),
        "root": bundle.lock().trust_root.digest.to_string(),
    })
    .to_string()
}

/// The digest that names a root's key set, which a decline is recorded under.
fn key_set_digest(keys: &[String]) -> String {
    PayloadDigest::of(keys.join(",").as_bytes()).to_string()
}

impl Catalogue {
    /// Seeds this catalogue from `bundle`, in `environment_id`, enrolling with `budgets`.
    ///
    /// Always keeps the bundle for the payloads it carries: a payload an accepted generation pins
    /// by digest is served from the bundle's bytes when it is not cached, whatever the bundle's
    /// root, because those bytes are checked against the digest and length that generation signed.
    ///
    /// The run never fails the caller: what it did, what it left and what stopped it are in the
    /// outcome. A run that is not permitted by this build, that finds an enrolment of the owner's,
    /// or that finds the seed already made does nothing durable beyond the one record each kind of
    /// decline keeps.
    pub async fn seed(
        &mut self,
        bundle: &SeedBundle,
        environment_id: EnvironmentId,
        budgets: RepositoryBudgets,
    ) -> SeedOutcome {
        self.embedded = Some(bundle.clone());
        let mut outcome = SeedOutcome::default();
        if let Err(error) = self
            .seed_run(bundle, environment_id, budgets, &mut outcome)
            .await
        {
            outcome.failure = Some(error);
        }
        outcome
    }

    async fn seed_run(
        &mut self,
        bundle: &SeedBundle,
        environment_id: EnvironmentId,
        budgets: RepositoryBudgets,
        outcome: &mut SeedOutcome,
    ) -> CatalogueResult<()> {
        // A bundle this build does not trust is not seeded, and nothing is written for it: a
        // later build, or the release made after the production root exists, can still seed.
        if let Err(error) = bundle.trust.permit(bundle.highest_root()) {
            outcome.notes.push(format!("did not seed: {error}"));
            return Ok(());
        }
        let (bundle_keys, _) = root_role(bundle.highest_root())?;
        let seeded = self
            .db
            .read(|records| records.settings_with_prefix(SEEDED))?;
        let enrolled = if let Some((name, _)) = seeded.first() {
            // The seed made an enrolment, once. It resumes that one and nothing else.
            let key = EnrolmentKey::parse(&name[SEEDED.len()..])?;
            let Some(enrolled) = self.db.read(|records| records.enrolment_by_key(&key))? else {
                outcome
                    .choices
                    .push("the repository the seed enrolled is no longer enrolled".to_owned());
                return Ok(());
            };
            // The root the enrolment trusts now has to be one this build trusts too, or the seed
            // does nothing to it: a build never moves a seeded enrolment under a root it does not
            // name.
            if let Err(error) = bundle.trust.permit(&enrolled.enrolment.root) {
                outcome.notes.push(format!(
                    "did not resume the seeded repository: its current root is not one this \
                     build trusts: {error}"
                ));
                return Ok(());
            }
            enrolled
        } else {
            let declined = format!("{DECLINED}{}", key_set_digest(&bundle_keys));
            if self
                .db
                .read(|records| records.setting(&declined))?
                .is_some()
            {
                outcome
                    .choices
                    .push("the seed found the owner's own enrolment of this root".to_owned());
                return Ok(());
            }
            if let Some(reason) = self.owners_enrolment(bundle)? {
                let reason = reason.clone();
                committing(
                    &mut self.db,
                    &*self.broker,
                    &mut Change::new(&SeedAuthority),
                    |changes| {
                        changes.put_setting(&declined, &reason)?;
                        Ok(((), Transition::SeedRecorded))
                    },
                )?;
                outcome.committed = true;
                outcome.choices.push(format!("did not seed: {reason}"));
                return Ok(());
            }
            let enrolled = self.enrol_seed(bundle, budgets, outcome)?;
            #[cfg(any(test, feature = "testing"))]
            self.stop_if(SeedPoint::AfterEnrolment)?;
            enrolled
        };

        let id = enrolled.enrolment.id.clone();

        // Only the sync is skipped by a pin, and by a generation that is already as high: the
        // packages the bundle carries are still installed against whatever is active.
        let active = enrolled.active.map(|active| active.generation);
        if let Some(pinned) = enrolled.enrolment.pinned_generation {
            if pinned < bundle.generation() {
                outcome.choices.push(format!(
                    "the seeded repository is pinned to generation {pinned}, so the bundled \
                     generation {} was not activated",
                    bundle.generation()
                ));
            }
        } else if active.is_some_and(|active| active >= bundle.generation().get()) {
            // Nothing to activate: the generation in use is the bundle's or a later one.
        } else {
            let mut change = Change::new(&SeedAuthority);
            let synced = self
                .sync_from(&id, &mut change, Via::Bundle(bundle))
                .await?;
            outcome.activated = Some(synced.generation);
            outcome.committed = true;
        }

        #[cfg(any(test, feature = "testing"))]
        self.stop_if(SeedPoint::AfterActivation)?;
        let enrolled = self.enrolled(&id)?;
        let Some(in_use) = enrolled.active else {
            return Ok(());
        };
        // The bundled metadata's expiry is the host's to report only while the bundled generation
        // is the one in use: once a synchronisation has moved the store past it, what the bundle
        // says about itself no longer says anything about what the host runs.
        if in_use.generation == bundle.generation().get()
            && let Some(expired) = bundle
                .earliest_expiry()
                .filter(|at| *at <= jiff::Timestamp::now())
        {
            outcome.expired = Some(expired.to_string());
        }
        let packages: Vec<BundledPackage> = bundle.packages().to_vec();
        for package in &packages {
            match self
                .seed_package(&enrolled, environment_id, package, bundle)
                .await
            {
                Ok(Seeded::Installed) => {
                    outcome.committed = true;
                    outcome.installed.push(package.plugin_id.clone());
                }
                Ok(Seeded::Left) => {
                    outcome.committed = true;
                    outcome.left.push(package.plugin_id.clone());
                }
                Ok(Seeded::Settled) => {}
                Ok(Seeded::Skipped(reason)) => {
                    outcome.skipped.push((package.plugin_id.clone(), reason));
                }
                Err(
                    error @ (CatalogueError::StorageUnavailable { .. }
                    | CatalogueError::PublicationUncertain { .. }),
                ) => return Err(error),
                Err(error) => outcome
                    .skipped
                    .push((package.plugin_id.clone(), error.to_string())),
            }
        }
        Ok(())
    }

    /// Stops the run here when a test asked it to.
    #[cfg(any(test, feature = "testing"))]
    fn stop_if(&self, point: SeedPoint) -> CatalogueResult<()> {
        if self.seed_stop == Some(point) {
            return Err(CatalogueError::InvalidArgument {
                detail: format!("the seed was stopped {point:?}"),
            });
        }
        Ok(())
    }

    /// Makes the next seed stop at `point`, as an interruption would, or none.
    #[cfg(any(test, feature = "testing"))]
    pub fn stop_seed_at(&mut self, point: Option<SeedPoint>) {
        self.seed_stop = point;
    }

    /// Says why this root is the owner's, where an enrolment of theirs holds it.
    fn owners_enrolment(&self, bundle: &SeedBundle) -> CatalogueResult<Option<String>> {
        let bundled: Vec<Vec<String>> = bundle
            .roots()
            .map(|(_, root)| root_role(root).map(|(keys, _)| keys))
            .collect::<CatalogueResult<_>>()?;
        for held in self.repositories()? {
            if let Ok(keys) = held.root_key_ids().map(|mut keys| {
                keys.sort();
                keys
            }) && bundled.contains(&keys)
            {
                return Ok(Some(format!(
                    "{} already trusts a root of the bundled lineage",
                    held.id
                )));
            }
            if held.id.as_str() == OFFICIAL {
                return Ok(Some(format!(
                    "a repository named {OFFICIAL} is already enrolled with other keys"
                )));
            }
        }
        Ok(None)
    }

    /// Enrols the official repository against the bundle's highest root, and records that the
    /// seed did.
    fn enrol_seed(
        &mut self,
        bundle: &SeedBundle,
        budgets: RepositoryBudgets,
        outcome: &mut SeedOutcome,
    ) -> CatalogueResult<crate::db::Enrolled> {
        let root = bundle.highest_root().to_vec();
        // The root's own signatures are checked as the client checks them when it loads one, so a
        // root that could never start a load leaves no record that holds the store.
        let signed: Signed<Root> =
            serde_json::from_slice(&root).map_err(|source| CatalogueError::Untrusted {
                detail: format!("the bundled root could not be read: {source}"),
            })?;
        signed
            .signed
            .verify_role(&signed)
            .map_err(|source| CatalogueError::Untrusted {
                detail: format!("the bundled root does not verify against itself: {source}"),
            })?;
        let id = RepositoryId::new(OFFICIAL)?;
        let parse = |text: &str| {
            url::Url::parse(text).map_err(|source| CatalogueError::InvalidArgument {
                detail: format!("{text} is not an address: {source}"),
            })
        };
        let mut budgets = budgets;
        budgets.full_offline_mirror = false;
        let enrolment = Enrolment::new(
            id.clone(),
            RepositoryKind::Official,
            parse(crate::seed_trust::OFFICIAL_METADATA_URL)?,
            parse(crate::seed_trust::OFFICIAL_TARGETS_URL)?,
            root,
            budgets,
            CapabilityCeiling::default_ceiling(),
        )?;
        let key = EnrolmentKey::generate()?;
        crate::Store::open(&self.root, &key)?;
        committing(
            &mut self.db,
            &*self.broker,
            &mut Change::new(&SeedAuthority),
            |changes| {
                changes.enrol(&key, &enrolment)?;
                changes.put_setting(&format!("{SEEDED}{key}"), "1")?;
                let view = crate::RepositoryView {
                    enrolment: enrolment.clone(),
                    active: None,
                };
                Ok(((), Transition::Enrolled(view)))
            },
        )?;
        outcome.enrolled = true;
        outcome.committed = true;
        self.enrolled(&id)
    }

    /// Installs one bundled package once: enabled, with an empty grant, and only where this
    /// environment has no installation of the plugin and no record of an earlier decision.
    async fn seed_package(
        &mut self,
        enrolled: &crate::db::Enrolled,
        environment_id: EnvironmentId,
        package: &BundledPackage,
        bundle: &SeedBundle,
    ) -> CatalogueResult<Seeded> {
        let plugin_id = &package.plugin_id;
        let record = format!("{SEED_INSTALLED}{plugin_id}");
        let (existing, recorded) = self.db.read(|records| {
            Ok((
                records.installation(environment_id, plugin_id)?,
                records.setting(&record)?,
            ))
        })?;
        if recorded.is_some() {
            return Ok(Seeded::Settled);
        }
        if existing.is_some() {
            self.record_left(&record)?;
            return Ok(Seeded::Left);
        }
        let (store, _lock, enrolled) = self.locked(enrolled)?;
        let Some(active) = enrolled.active else {
            return Ok(Seeded::Skipped(
                "the repository has no active generation".to_owned(),
            ));
        };
        let index = store.index(&active)?;
        let Some(entry) = index.find(plugin_id, &package.version).cloned() else {
            return Ok(Seeded::Skipped(format!(
                "the active generation does not list {} {}",
                plugin_id, package.version
            )));
        };
        if entry.manifest_digest != package.manifest.digest {
            return Ok(Seeded::Skipped(format!(
                "the active generation lists {} {} at another digest than the bundle's",
                plugin_id, package.version
            )));
        }
        if entry.revocation.0.is_some() {
            return Ok(Seeded::Skipped(format!(
                "{} {} is revoked in the active generation",
                plugin_id, package.version
            )));
        }
        crate::check_seeded_installation(&entry, &enrolled.enrolment.ceiling)?;
        let ready = self
            .activate_locked(
                &enrolled,
                &store,
                Some(environment_id),
                plugin_id,
                &package.version,
                Some(entry.manifest_digest),
                crate::Why::Seed(bundle),
                &SeedAuthority,
            )
            .await?;
        extract::reconcile(
            &entry,
            ready.manifest(),
            &format!("{plugin_id} {}", package.version),
        )?;
        let root = self.root.clone();
        let key = enrolled.key.clone();
        let id = enrolled.enrolment.id.clone();
        let ceiling = enrolled.enrolment.ceiling.clone();
        committing(
            &mut self.db,
            &*self.broker,
            &mut Change::new(&SeedAuthority),
            |changes| {
                // Read again, inside the commit: what an owner did meanwhile decides.
                changes
                    .enrolment_by_key(&key)?
                    .ok_or_else(|| CatalogueError::NotFound {
                        detail: format!("{id} was removed while the seed installed {plugin_id}"),
                    })?;
                if changes.setting(&record)?.is_some() {
                    return Ok((Seeded::Settled, Transition::SeedRecorded));
                }
                if let Some(existing) = changes.installation(environment_id, plugin_id)? {
                    changes.put_setting(&record, "left")?;
                    let view = crate::installation_view(&root, changes, existing)?;
                    return Ok((Seeded::Left, Transition::Changed(view)));
                }
                let mut installation = Installation::from_package(
                    &ready,
                    key.clone(),
                    id.clone(),
                    environment_id,
                    InstallationGrant::none(),
                    ceiling.clone(),
                );
                installation.enabled = true;
                changes.forget_retired(
                    environment_id,
                    plugin_id,
                    installation.package_digest,
                    &crate::admission::ReleaseOrigin::of(&installation),
                )?;
                changes.install(&installation)?;
                changes.put_setting(&record, "installed")?;
                let view = crate::installation_view(&root, changes, installation)?;
                Ok((Seeded::Installed, Transition::Installed(view)))
            },
        )
    }

    /// Whether the seed made this enrolment, from its permanent record: true from the enrolment on,
    /// whether or not a generation was ever activated.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the records cannot be read.
    pub fn was_seeded(&self, id: &RepositoryId) -> CatalogueResult<bool> {
        let Some(enrolled) = self.db.read(|records| records.enrolment(id))? else {
            return Ok(false);
        };
        let name = format!("{SEEDED}{}", enrolled.key);
        Ok(self.db.read(|records| records.setting(&name))?.is_some())
    }

    /// Records that the seed found an installation of this plugin and left it.
    fn record_left(&mut self, record: &str) -> CatalogueResult<()> {
        committing(
            &mut self.db,
            &*self.broker,
            &mut Change::new(&SeedAuthority),
            |changes| {
                if changes.setting(record)?.is_none() {
                    changes.put_setting(record, "left")?;
                }
                Ok(((), Transition::SeedRecorded))
            },
        )
    }

    /// Where the generation the seed activated for `id` came from, as the seed recorded it, where
    /// the seed made that enrolment and its owner has not removed it: the repository and commit
    /// the bundle was copied at, the generation, and the root it was verified against.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the records cannot be read.
    pub fn seed_provenance(&self, id: &RepositoryId) -> CatalogueResult<Option<serde_json::Value>> {
        let Some(enrolled) = self.db.read(|records| records.enrolment(id))? else {
            return Ok(None);
        };
        let name = format!("{PROVENANCE}{}", enrolled.key);
        Ok(self
            .db
            .read(|records| records.setting(&name))?
            .and_then(|text| serde_json::from_str(&text).ok()))
    }

    /// What the seed has recorded, by record name: which enrolment it made, where the generation
    /// came from, and what it did with each package.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the records cannot be read.
    pub fn seed_records(&self) -> CatalogueResult<Vec<(String, String)>> {
        self.db.read(|records| {
            let mut found = Vec::new();
            for prefix in [SEEDED, REMOVED, DECLINED, SEED_INSTALLED, PROVENANCE] {
                found.extend(records.settings_with_prefix(prefix)?);
            }
            Ok(found)
        })
    }
}
