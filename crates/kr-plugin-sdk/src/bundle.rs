//! The packages that ship with the host, and the lock that names them.
//!
//! A fresh installation has no repository yet. It has to be able to recognise an application,
//! present it and activate a package before anything is reachable, so KalaReach carries a signed
//! catalogue generation with it: the metadata that verifies it and the packages it names, compiled
//! into the host. Section 11 states the promise plainly: bundled, installed, pinned and live-bound
//! payloads remain available offline, and a payload that is not there answers
//! `PACKAGE_UNAVAILABLE_OFFLINE` rather than a capability nobody can perform.
//!
//! # What the lock is for
//!
//! The bundled bytes sit in a directory. A directory is not evidence, so the lock beside it says
//! what those bytes are meant to be: every metadata file and every package, with the digest and
//! exact length of each file, the SDK and WIT ranges each manifest declares, the trust root the
//! chain was verified against, and the generation and commit the copy came from. Making the copy
//! is where the signatures are checked, once, by the script that owns the bundle; the host then
//! verifies the same generation again, against the root it adopts, when it seeds its catalogue.
//!
//! # What it is not
//!
//! It is not catalogue synchronisation, and it is not a substitute for one. The lock names one
//! generation, frozen at the commit it was copied from. Nothing here fetches, updates, or decides
//! that a newer generation exists.

use std::path::Path;

use kr_protocol::scalars::TimestampMs;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::digest::{ByteSize, PayloadDigest};
use crate::ids::{PluginId, PluginName, PublisherId, RepositoryGeneration};
use crate::paths::PackagePath;
use crate::plugin::{PayloadRole, PluginManifest};
use crate::version::{PackageVersion, VersionRange};

/// The directory the bundled packages live in, relative to the repository or installation root.
pub const BUNDLE_DIR: &str = "bundled-plugins";

/// The file that names them.
pub const LOCK_FILE: &str = "bundled-plugins.lock";

/// The lock format version this crate reads and writes.
pub const LOCK_VERSION: u32 = 2;

/// Where a bundled copy came from.
///
/// A generation is published as a directory of metadata and targets in a repository, so "where"
/// is a repository, a commit and a path inside it. Together they are an address a person can
/// resolve and a later copy can be compared against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct BundleSource {
    /// The repository the generation is published from.
    pub repository: String,
    /// The exact commit the copy was made at.
    pub commit: String,
    /// Where the generation is inside that commit.
    pub generation_path: String,
    /// The address of that path at that commit.
    pub tree_url: String,
    /// The generation the copy came from.
    pub generation: RepositoryGeneration,
    /// When that generation's index was built.
    pub produced_at: TimestampMs,
}

/// The trust root the chain was verified against when the copy was made.
///
/// A host activating a bundled package does not re-run the chain: it has no repository and no
/// current metadata. This says which root the check was made against, so a bundle verified against
/// one root cannot be mistaken for a bundle verified against another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TrustRoot {
    /// The digest of the root document.
    pub digest: PayloadDigest,
    /// The root metadata version.
    pub version: u32,
    /// When the root expires, as its own metadata spells it.
    pub expires: String,
    /// The key identifiers the root role is signed by.
    pub key_ids: Vec<String>,
}

/// One file of a bundled package, by path, digest and exact length.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct BundledFile {
    /// Where it lives inside the package directory.
    pub path: PackagePath,
    /// Its SHA-256 digest.
    pub digest: PayloadDigest,
    /// Its exact length in bytes.
    pub size_bytes: ByteSize,
}

/// One payload of a bundled package, with the role its manifest gives it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct BundledPayload {
    /// What the payload is.
    pub role: PayloadRole,
    /// Where it lives inside the package directory.
    pub path: PackagePath,
    /// Its SHA-256 digest.
    pub digest: PayloadDigest,
    /// Its exact length in bytes.
    pub size_bytes: ByteSize,
}

/// One file of the bundled generation's metadata, or its index, by path, digest and exact length.
///
/// The path is relative to the bundle directory: `metadata/<name>` for the metadata and
/// `targets/index.json` for the index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct BundledMetadata {
    /// Where it lives, relative to the bundle directory.
    pub path: String,
    /// Its SHA-256 digest.
    pub digest: PayloadDigest,
    /// Its exact length in bytes.
    pub size_bytes: ByteSize,
}

/// One bundled package, as the lock names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct BundledPackage {
    /// The directory it occupies, relative to the bundle directory: where the generation's targets
    /// place it, `targets/packages/<publisher>/<name>/<version>`.
    pub directory: PackagePath,
    /// The wire plugin identifier.
    pub plugin_id: PluginId,
    /// The publisher.
    pub publisher_id: PublisherId,
    /// The plugin name under that publisher.
    pub plugin_name: PluginName,
    /// The exact version.
    pub version: PackageVersion,
    /// The SDK versions its manifest declares.
    pub sdk_range: VersionRange,
    /// The WIT package versions its manifest declares.
    pub wit_range: VersionRange,
    /// The manifest, which declares every other file and not itself.
    pub manifest: BundledFile,
    /// Every other file.
    pub payloads: Vec<BundledPayload>,
    /// The manifest and every payload added together.
    pub total_size_bytes: ByteSize,
}

/// The lock beside the bundle directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct BundleLock {
    /// The lock format version.
    pub lock_version: u32,
    /// Where the copy came from.
    pub source: BundleSource,
    /// The highest root the generation ships, which a new enrolment adopts.
    pub trust_root: TrustRoot,
    /// Every metadata file the generation ships, and its index.
    pub metadata: Vec<BundledMetadata>,
    /// The packages the bundle carries.
    pub packages: Vec<BundledPackage>,
}

/// Why a lock cannot be read.
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    /// The file could not be opened or read.
    #[error("{path} cannot be read: {source}")]
    Unreadable {
        /// The path that was tried.
        path: String,
        /// What the filesystem said.
        source: std::io::Error,
    },
    /// The document did not parse against the closed schema.
    #[error("{path} is not a bundle lock: {source}")]
    Unparsable {
        /// The path that was tried.
        path: String,
        /// What the parser said.
        source: serde_json::Error,
    },
    /// The document is a version this build does not read.
    #[error("{path} is lock version {found}, and this build reads {LOCK_VERSION}")]
    Version {
        /// The path that was tried.
        path: String,
        /// The version the document declared.
        found: u32,
    },
}

impl BundleLock {
    /// Parses a lock from its bytes.
    ///
    /// # Errors
    ///
    /// Returns [`LockError`] when the document does not parse or declares another version.
    pub fn from_slice(bytes: &[u8], path: &str) -> Result<Self, LockError> {
        let lock: Self = serde_json::from_slice(bytes).map_err(|source| LockError::Unparsable {
            path: path.to_owned(),
            source,
        })?;
        if lock.lock_version != LOCK_VERSION {
            return Err(LockError::Version {
                path: path.to_owned(),
                found: lock.lock_version,
            });
        }
        Ok(lock)
    }

    /// Reads the lock at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`LockError`] when the file cannot be read, does not parse, or declares another
    /// version.
    pub fn read(path: &Path) -> Result<Self, LockError> {
        let display = path.display().to_string();
        let bytes = std::fs::read(path).map_err(|source| LockError::Unreadable {
            path: display.clone(),
            source,
        })?;
        Self::from_slice(&bytes, &display)
    }

    /// Returns the package the lock carries under `plugin_id`.
    #[must_use]
    pub fn package(&self, plugin_id: &PluginId) -> Option<&BundledPackage> {
        self.packages
            .iter()
            .find(|package| &package.plugin_id == plugin_id)
    }
}

impl BundledPackage {
    /// Returns the payload the lock gives `role`, where the package has one.
    #[must_use]
    pub fn payload(&self, role: PayloadRole) -> Option<&BundledPayload> {
        self.payloads.iter().find(|payload| payload.role == role)
    }

    /// The manifest and every payload, as one list.
    #[must_use]
    pub fn files(&self) -> Vec<BundledFile> {
        let mut files = vec![self.manifest.clone()];
        files.extend(self.payloads.iter().map(|payload| BundledFile {
            path: payload.path.clone(),
            digest: payload.digest,
            size_bytes: payload.size_bytes,
        }));
        files
    }

    /// Says where a package's manifest and the lock's account of it differ: the lock and the
    /// manifest are two documents about one package, and a host that trusted the lock's identity
    /// without opening the manifest would bind a plugin identifier to bytes that never claimed it.
    #[must_use]
    pub fn disagreements(&self, manifest: &PluginManifest) -> Vec<String> {
        let mut disagreements = Vec::new();
        if manifest.plugin_id() != self.plugin_id {
            disagreements.push(format!("its manifest says {}", manifest.plugin_id()));
        }
        if manifest.publisher_id != self.publisher_id {
            disagreements.push(format!("its publisher is {}", manifest.publisher_id));
        }
        if manifest.plugin_name != self.plugin_name {
            disagreements.push(format!("its plugin name is {}", manifest.plugin_name));
        }
        if manifest.version != self.version {
            disagreements.push(format!("its version is {}", manifest.version));
        }
        if manifest.sdk_range != self.sdk_range {
            disagreements.push(format!("its SDK range is {}", manifest.sdk_range));
        }
        if manifest.wit_range != self.wit_range {
            disagreements.push(format!("its WIT range is {}", manifest.wit_range));
        }
        for payload in &manifest.payloads {
            match self
                .payloads
                .iter()
                .find(|bundled| bundled.path == payload.path)
            {
                Some(bundled)
                    if bundled.digest == payload.digest
                        && bundled.size_bytes == payload.size_bytes
                        && bundled.role == payload.role => {}
                Some(_) => disagreements.push(format!(
                    "the lock and the manifest disagree about {}",
                    payload.path
                )),
                None => disagreements.push(format!(
                    "the manifest declares {}, which the lock does not name",
                    payload.path
                )),
            }
        }
        for bundled in &self.payloads {
            if !manifest
                .payloads
                .iter()
                .any(|payload| payload.path == bundled.path)
            {
                disagreements.push(format!(
                    "the lock names {}, which the manifest does not declare",
                    bundled.path
                ));
            }
        }
        disagreements
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock_text() -> &'static str {
        r#"{
  "lock_version": 2,
  "metadata": [
    {
      "digest": "874233c78ea4a6db808b3967fe6b750c6419084edf2007d2c4fc2e5486d1ed8e",
      "path": "metadata/1.root.json",
      "size_bytes": "1500"
    }
  ],
  "packages": [
    {
      "directory": "targets/packages/kalareach/example-declarative/0.1.0",
      "manifest": {
        "digest": "f8434aef081de78d9b63e34d1172b9a64399182a7420bb4f0b3352762a5aeccb",
        "path": "plugin.json",
        "size_bytes": "2953"
      },
      "payloads": [],
      "plugin_id": "kalareach/example-declarative",
      "plugin_name": "example-declarative",
      "publisher_id": "kalareach",
      "sdk_range": ">=0.1.0, <0.2.0",
      "total_size_bytes": "2953",
      "version": "0.1.0",
      "wit_range": ">=0.1.0, <0.2.0"
    }
  ],
  "source": {
    "commit": "44084fc058106bca25bfb4f2118cc349187419df",
    "generation": "2",
    "generation_path": "snapshots/development",
    "produced_at": "1760000000000",
    "repository": "https://github.com/kalapowered/kalareach-plugins",
    "tree_url": "https://example.invalid/tree"
  },
  "trust_root": {
    "digest": "874233c78ea4a6db808b3967fe6b750c6419084edf2007d2c4fc2e5486d1ed8e",
    "expires": "2046-10-01T00:00:00Z",
    "key_ids": ["22a99bda605726730776823e26da03b178524617baccaee1a75ad8a67fb41eca"],
    "version": 1
  }
}"#
    }

    #[test]
    fn the_lock_reads_with_the_sdk_types() {
        let lock = BundleLock::from_slice(lock_text().as_bytes(), "lock").expect("a lock");
        assert_eq!(lock.lock_version, LOCK_VERSION);
        assert_eq!(lock.source.generation, RepositoryGeneration::new(2));
        assert_eq!(lock.source.produced_at, TimestampMs::new(1_760_000_000_000));
        assert_eq!(lock.metadata[0].path, "metadata/1.root.json");
        let id = PluginId::new("kalareach/example-declarative").expect("an identifier");
        let package = lock.package(&id).expect("the bundled package");
        assert_eq!(
            package.directory.as_str(),
            "targets/packages/kalareach/example-declarative/0.1.0"
        );
        assert_eq!(package.manifest.size_bytes.get(), 2953);
    }

    #[test]
    fn a_lock_of_another_version_is_refused_by_version() {
        for other in [1, 3] {
            let text =
                lock_text().replace("\"lock_version\": 2", &format!("\"lock_version\": {other}"));
            assert!(matches!(
                BundleLock::from_slice(text.as_bytes(), "lock"),
                Err(LockError::Version { found, .. }) if found == other
            ));
        }
    }

    #[test]
    fn a_path_that_leaves_the_package_is_refused_before_anything_opens() {
        let text = lock_text().replace("\"path\": \"plugin.json\"", "\"path\": \"../plugin.json\"");
        assert!(matches!(
            BundleLock::from_slice(text.as_bytes(), "lock"),
            Err(LockError::Unparsable { .. })
        ));
    }

    #[test]
    fn a_lock_without_its_metadata_is_not_a_lock() {
        let text = lock_text().replace("\"metadata\"", "\"files\"");
        assert!(matches!(
            BundleLock::from_slice(text.as_bytes(), "lock"),
            Err(LockError::Unparsable { .. })
        ));
    }
}
