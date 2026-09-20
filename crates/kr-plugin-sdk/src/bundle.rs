//! The packages that ship with the host, and the lock that names them.
//!
//! A fresh installation has no repository yet. It has to be able to recognise an application,
//! present it and activate a package before anything is reachable, so KalaReach carries one
//! package with it. Section 11 states the promise plainly: bundled, installed, pinned and
//! live-bound payloads remain available offline, and a payload that is not there answers
//! `PACKAGE_UNAVAILABLE_OFFLINE` rather than a capability nobody can perform.
//!
//! # What the lock is for
//!
//! The bundled bytes sit in a directory. A directory is not evidence, so the lock beside it says
//! what those bytes are meant to be: the package, its version, the digest and exact length of
//! every file, the SDK and WIT ranges its manifest declares, the trust root the chain was verified
//! against, and the generation and commit the copy came from. Making the copy is where the
//! signatures are checked, once, by the tool that owns the catalogue; using the copy is where the
//! digests are checked, every time, by this module.
//!
//! That split is deliberate. A host reading a bundled package has no repository to re-run a TUF
//! chain against: the metadata, the mirror and the delegations are all behind the network it has
//! not got. What it can do, and what [`BundledPackage::activate`] does, is recompute the digest of
//! every byte it is about to use and refuse anything that is not what the lock names.
//!
//! # What activating a bundled package is
//!
//! Every payload is read, measured and digested before any of them is parsed, and the package
//! becomes usable in one step or not at all. Section 11 asks for exactly that: package activation
//! is independently atomic after all its payloads verify. A payload that has been edited, replaced
//! by a link, truncated, grown or removed leaves the package unactivated, with nothing half-read
//! in the caller's hands.
//!
//! # What it is not
//!
//! It is not catalogue synchronisation, and it is not a substitute for one. The lock names one
//! generation, frozen at the commit it was copied from. Nothing here fetches, updates, or decides
//! that a newer generation exists.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Path;

use cap_std::fs::{Dir, OpenOptions};
use kr_protocol::error::ErrorCode;
use kr_protocol::scalars::TimestampMs;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::digest::{ByteSize, PayloadDigest};
use crate::identity::PluginIdentity;
use crate::ids::{PluginId, PluginName, PublisherId, RepositoryGeneration};
use crate::package::{MAX_PACKAGE_BYTES, PRESENTATION_FILE};
use crate::paths::{PackagePath, find_collisions};
use crate::plugin::{PayloadRole, PluginManifest};
use crate::presentation::PresentationManifest;
use crate::version::{PackageVersion, VersionRange};

/// The directory the bundled packages live in, relative to the repository or installation root.
pub const BUNDLE_DIR: &str = "bundled-plugins";

/// The file that names them.
pub const LOCK_FILE: &str = "bundled-plugins.lock";

/// The lock format version this crate reads and writes.
pub const LOCK_VERSION: u32 = 1;

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

/// One bundled package, as the lock names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct BundledPackage {
    /// The directory it occupies, relative to the bundle directory.
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
    /// The root the chain was verified against when it was made.
    pub trust_root: TrustRoot,
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

/// Why a bundled package cannot be activated.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BundleError {
    /// The lock does not name this package or this payload.
    #[error("the bundle does not carry {what}")]
    NotBundled {
        /// What was asked for.
        what: String,
    },
    /// A file the lock names is not in the bundle.
    #[error("{path} is named by the lock and is not in the bundle")]
    Absent {
        /// The file the lock named.
        path: PackagePath,
    },
    /// A file the lock names could not be read for want of a local resource.
    #[error("{path} cannot be read here: {detail}")]
    Resource {
        /// The file the lock named.
        path: PackagePath,
        /// What the system said.
        detail: String,
    },
    /// The lock declares more than one package may hold.
    #[error("{path} declares {declared} bytes, over the {limit} byte package limit")]
    Oversized {
        /// The file the lock named.
        path: PackagePath,
        /// What the lock declared.
        declared: u64,
        /// What a package may hold.
        limit: u64,
    },
    /// The lock names one file twice, or two names that are one file.
    #[error("the lock names {first} and {second}, which are one file")]
    Collision {
        /// The path seen first.
        first: PackagePath,
        /// The path that collides with it.
        second: PackagePath,
    },
    /// A file the lock names is there and cannot be read as itself.
    #[error("{path} cannot be read: {detail}")]
    Unreadable {
        /// The file the lock named.
        path: PackagePath,
        /// What the filesystem said.
        detail: String,
    },
    /// A file the lock names is not a regular file.
    #[error("{path} is not a regular file, and a bundled payload is")]
    NotAFile {
        /// The file the lock named.
        path: PackagePath,
    },
    /// A file is not the length the lock declares.
    #[error("{path} is {actual} bytes and the lock declares {declared}")]
    Size {
        /// The file the lock named.
        path: PackagePath,
        /// What the lock declared.
        declared: u64,
        /// What the file is.
        actual: u64,
    },
    /// A file is not the payload the lock names.
    #[error("{path} is not the payload the lock names")]
    Digest {
        /// The file the lock named.
        path: PackagePath,
    },
    /// The package holds more bytes than the lock declares.
    #[error("the package holds {actual} bytes and the lock declares {declared}")]
    Expansion {
        /// What the lock declared.
        declared: u64,
        /// What the files add up to.
        actual: u64,
    },
    /// The manifest did not parse, or is not the package the lock names.
    #[error("the bundled manifest is not {expected}: {detail}")]
    Manifest {
        /// The package the lock names.
        expected: String,
        /// What was wrong with it.
        detail: String,
    },
}

impl BundleError {
    /// The error code a caller reports for this.
    ///
    /// A payload that is not there at all is the offline case: there is no repository to fetch it
    /// from, and the answer is that the package is unavailable rather than a capability that would
    /// fail the moment somebody used it. Anything else means something is there and is not what the
    /// lock names, which is a trust answer rather than a fetch answer: a link in place of a file, a
    /// length that does not match, or bytes that are not the payload. A read this installation could
    /// not make for want of a descriptor or memory is neither: it is a local resource that may be
    /// there on the next attempt, and reporting it as untrusted would send a person looking for
    /// tampering that never happened.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::NotBundled { .. } | Self::Absent { .. } => ErrorCode::PackageUnavailableOffline,
            Self::Resource { .. } => ErrorCode::ResourceUnavailable,
            Self::Unreadable { .. }
            | Self::NotAFile { .. }
            | Self::Size { .. }
            | Self::Digest { .. }
            | Self::Expansion { .. }
            | Self::Oversized { .. }
            | Self::Collision { .. }
            | Self::Manifest { .. } => ErrorCode::RepositoryUntrusted,
        }
    }
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

    /// Activates the bundled package `plugin_id` out of the bundle directory.
    ///
    /// `bundle` is a handle on the bundle directory itself. Every file is opened relative to it,
    /// so a package cannot reach outside the directory the caller opened.
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::NotBundled`] when the lock does not carry that package, which is the
    /// offline answer rather than a capability nothing could perform, and anything
    /// [`BundledPackage::activate`] returns otherwise.
    pub fn activate(
        &self,
        bundle: &Dir,
        plugin_id: &PluginId,
    ) -> Result<ActivatedPackage, BundleError> {
        let package = self
            .package(plugin_id)
            .ok_or_else(|| BundleError::NotBundled {
                what: plugin_id.to_string(),
            })?;
        package.activate(bundle, self.source.generation)
    }
}

impl BundledPackage {
    /// Returns the payload the lock gives `role`, where the package has one.
    #[must_use]
    pub fn payload(&self, role: PayloadRole) -> Option<&BundledPayload> {
        self.payloads.iter().find(|payload| payload.role == role)
    }

    /// Reads and verifies every file, then returns the activated package.
    ///
    /// Nothing is parsed until everything is verified, and nothing partial is returned: a package
    /// whose files do not all match the lock is a package that did not activate. That is section
    /// 11's independently atomic package activation, and it is also what makes the digest check
    /// happen before anything reads a byte as a document.
    ///
    /// # Errors
    ///
    /// Returns [`BundleError`] naming the first file that is absent, is not a regular file, is not
    /// the declared length, or is not the declared payload; the package whose files add up to more
    /// than the lock declares; or the manifest that does not parse or is not this package.
    pub fn activate(
        &self,
        bundle: &Dir,
        generation: RepositoryGeneration,
    ) -> Result<ActivatedPackage, BundleError> {
        // What the lock says, checked before anything is opened. A lock is the one input here that
        // no digest covers, so its own claims are bounded first: no name twice, no two names that
        // are one file on a case-folding volume, no file over what a package may hold, and a total
        // that is the sum of the files it lists.
        let declared = self.files();

        // The names first, because what they are is what everything after this counts. Two entries
        // that are one file would otherwise be verified against one file's bytes and counted twice
        // towards a total, and the complaint that came out would be about arithmetic rather than
        // about the two names that caused it.
        let paths: Vec<PackagePath> = declared.iter().map(|file| file.path.clone()).collect();
        if let Some(collision) = first_collision(&paths) {
            return Err(collision);
        }

        // What the files add up to, from the files themselves rather than from the total beside
        // them. A lock that declared several payloads of a package's whole size and a total of one
        // of them would otherwise be read in full before the totals were compared, which is a way
        // to make this hold as much memory as the lock liked.
        let mut declared_total: u64 = 0;
        for file in &declared {
            if file.size_bytes.get() > MAX_PACKAGE_BYTES {
                return Err(BundleError::Oversized {
                    path: file.path.clone(),
                    declared: file.size_bytes.get(),
                    limit: MAX_PACKAGE_BYTES,
                });
            }
            declared_total = declared_total
                .checked_add(file.size_bytes.get())
                .ok_or_else(|| BundleError::Oversized {
                    path: file.path.clone(),
                    declared: u64::MAX,
                    limit: MAX_PACKAGE_BYTES,
                })?;
        }
        if declared_total > MAX_PACKAGE_BYTES {
            return Err(BundleError::Oversized {
                path: self.directory.clone(),
                declared: declared_total,
                limit: MAX_PACKAGE_BYTES,
            });
        }
        if declared_total != self.total_size_bytes.get() {
            return Err(BundleError::Expansion {
                declared: self.total_size_bytes.get(),
                actual: declared_total,
            });
        }

        let directory = self.open_directory(bundle)?;

        let mut files: BTreeMap<PackagePath, Vec<u8>> = BTreeMap::new();
        let mut total: u64 = 0;
        for file in &declared {
            let bytes = read_verified(&directory, file)?;
            total = total.saturating_add(bytes.len() as u64);
            files.insert(file.path.clone(), bytes);
        }
        if total != self.total_size_bytes.get() {
            return Err(BundleError::Expansion {
                declared: self.total_size_bytes.get(),
                actual: total,
            });
        }

        // Only now, with every byte verified, is anything read as a document.
        let manifest = self.parse_manifest(&files)?;

        Ok(ActivatedPackage {
            identity: PluginIdentity::new(
                self.plugin_id.clone(),
                self.version.clone(),
                self.manifest.digest,
                generation,
            ),
            manifest,
            files,
        })
    }

    /// The manifest and every payload, as one list.
    fn files(&self) -> Vec<BundledFile> {
        let mut files = vec![self.manifest.clone()];
        files.extend(self.payloads.iter().map(|payload| BundledFile {
            path: payload.path.clone(),
            digest: payload.digest,
            size_bytes: payload.size_bytes,
        }));
        files
    }

    /// Opens the package's own directory, refusing a link anywhere on the way to it.
    fn open_directory(&self, bundle: &Dir) -> Result<Dir, BundleError> {
        descend(bundle, self.directory.segments(), &self.directory)
    }

    fn parse_manifest(
        &self,
        files: &BTreeMap<PackagePath, Vec<u8>>,
    ) -> Result<PluginManifest, BundleError> {
        let expected = format!("{} {}", self.plugin_id, self.version);
        let bytes = files
            .get(&self.manifest.path)
            .ok_or_else(|| BundleError::Manifest {
                expected: expected.clone(),
                detail: format!("the lock's manifest is {}", self.manifest.path),
            })?;
        let manifest: PluginManifest =
            serde_json::from_slice(bytes).map_err(|error| BundleError::Manifest {
                expected: expected.clone(),
                detail: error.to_string(),
            })?;

        // The lock and the manifest are two documents about one package, and a host that trusted
        // the lock's identity without opening the manifest would bind a plugin identifier to bytes
        // that never claimed it.
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
        if !disagreements.is_empty() {
            return Err(BundleError::Manifest {
                expected,
                detail: disagreements.join("; "),
            });
        }
        Ok(manifest)
    }
}

/// A bundled package whose every file has been read and verified.
#[derive(Clone, Debug)]
pub struct ActivatedPackage {
    identity: PluginIdentity,
    manifest: PluginManifest,
    files: BTreeMap<PackagePath, Vec<u8>>,
}

impl ActivatedPackage {
    /// The identity a binding to this package pins.
    ///
    /// The package hash is the manifest's digest, because the manifest is the document that names
    /// every other byte, and the generation is the one the lock says the copy was made from. A
    /// binding pinned to this identity is pinned to those bytes and that generation, so a later
    /// generation that withdraws the package has something to match against.
    #[must_use]
    pub const fn identity(&self) -> &PluginIdentity {
        &self.identity
    }

    /// The package's manifest.
    #[must_use]
    pub const fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    /// The bytes of one verified file.
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::NotBundled`], whose code is `PACKAGE_UNAVAILABLE_OFFLINE`, when the
    /// lock does not name that path. There is no repository to fetch it from, so the honest answer
    /// is that the package does not carry it.
    pub fn file(&self, path: &PackagePath) -> Result<&[u8], BundleError> {
        self.files
            .get(path)
            .map(Vec::as_slice)
            .ok_or_else(|| BundleError::NotBundled {
                what: path.as_str().to_owned(),
            })
    }

    /// The package's presentation document.
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::NotBundled`] when the package carries none, and
    /// [`BundleError::Manifest`] when the verified bytes do not parse as one.
    pub fn presentation(&self) -> Result<PresentationManifest, BundleError> {
        let path = PackagePath::new(PRESENTATION_FILE).map_err(|error| BundleError::Manifest {
            expected: PRESENTATION_FILE.to_owned(),
            detail: error.to_string(),
        })?;
        let bytes = self.file(&path)?;
        serde_json::from_slice(bytes).map_err(|error| BundleError::Manifest {
            expected: PRESENTATION_FILE.to_owned(),
            detail: error.to_string(),
        })
    }

    /// Every path the package carries, in order.
    pub fn paths(&self) -> impl Iterator<Item = &PackagePath> {
        self.files.keys()
    }
}

/// Reads one file through the bundle's directory handle and checks it against the lock.
///
/// Every component is opened relative to the one before it with links refused, so a link anywhere
/// on the way to a payload stops the read rather than redirecting it. `cap_std` already keeps the
/// resolution inside the handle it started from; this adds the second half of section 11's rule,
/// which is that a package holds files and not links to them.
///
/// The file's own open does not wait: without `O_NONBLOCK` a name replaced by a named pipe would
/// hold the read open until somebody wrote to it, which no declared length bounds. The handle's
/// metadata then decides, and the read stops one byte past the declared length rather than
/// trusting the length reported before it started.
fn read_verified(directory: &Dir, file: &BundledFile) -> Result<Vec<u8>, BundleError> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};

    let mut segments: Vec<&str> = file.path.segments().collect();
    let name = segments.pop().expect("a package path has a last segment");
    let parent = descend(directory, segments.into_iter(), &file.path)?;

    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut handle = parent
        .open_with(name, &options)
        .map_err(|error| absence(&file.path, &error))?;
    let metadata = handle
        .metadata()
        .map_err(|error| absence(&file.path, &error))?;
    if !metadata.is_file() {
        return Err(BundleError::NotAFile {
            path: file.path.clone(),
        });
    }
    let declared = file.size_bytes.get();
    if metadata.len() != declared {
        return Err(BundleError::Size {
            path: file.path.clone(),
            declared,
            actual: metadata.len(),
        });
    }

    // Reserved against what the lock declared and what one package may hold, whichever is smaller,
    // so a lock that declares a size nothing on disk could satisfy cannot make this allocate it.
    let reserve = usize::try_from(declared.min(MAX_PACKAGE_BYTES)).unwrap_or(0);
    let mut bytes = Vec::with_capacity(reserve);
    handle
        .by_ref()
        .take(declared.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| absence(&file.path, &error))?;
    if bytes.len() as u64 != declared {
        return Err(BundleError::Size {
            path: file.path.clone(),
            declared,
            actual: bytes.len() as u64,
        });
    }
    if PayloadDigest::of(&bytes) != file.digest {
        return Err(BundleError::Digest {
            path: file.path.clone(),
        });
    }
    Ok(bytes)
}

/// Opens each directory segment beneath `from`, refusing a link at any of them.
fn descend<'a>(
    from: &Dir,
    segments: impl Iterator<Item = &'a str>,
    path: &PackagePath,
) -> Result<Dir, BundleError> {
    use cap_fs_ext::DirExt as _;

    let mut here = from.try_clone().map_err(|error| absence(path, &error))?;
    for segment in segments {
        here = here
            .open_dir_nofollow(segment)
            .map_err(|error| absence(path, &error))?;
    }
    Ok(here)
}

/// Turns a failed open into the right answer about it.
///
/// A name that is not there is the offline case. A descriptor or a page the system could not spare
/// is a local shortage, which may be gone by the next attempt. Everything else is something that is
/// there and is not the payload: a link in place of a file, a directory where a file belongs, or a
/// permission this installation has not got.
fn absence(path: &PackagePath, error: &std::io::Error) -> BundleError {
    if error.kind() == std::io::ErrorKind::NotFound {
        return BundleError::Absent { path: path.clone() };
    }
    if is_resource_shortage(error) {
        return BundleError::Resource {
            path: path.clone(),
            detail: error.to_string(),
        };
    }
    BundleError::Unreadable {
        path: path.clone(),
        detail: error.to_string(),
    }
}

/// Returns true when the system refused for want of something it may have again.
///
/// A descriptor table that is full and a page it could not spare are this installation's problem
/// for the moment, not the bundle's. They are the reason the answer is not simply "absent or
/// untrusted": a person sent to look for tampering that never happened has been told the wrong
/// thing.
fn is_resource_shortage(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::OutOfMemory {
        return true;
    }
    #[cfg(unix)]
    if let Some(raw) = error.raw_os_error() {
        return matches!(raw, libc::EMFILE | libc::ENFILE | libc::ENOMEM);
    }
    false
}

/// Returns the first pair of paths that cannot both exist, including two directory spellings.
///
/// [`find_collisions`] compares whole file paths, which catches `a/b` against `A/B` and a file that
/// is another path's directory. It does not catch `Assets/a` beside `assets/b`: two paths that
/// differ everywhere except in a directory's spelling, which a case-folding volume makes one
/// directory and a case-sensitive one makes two. A package that means one thing on macOS and
/// another on Linux is not a package a digest can speak for, so both are refused here.
fn first_collision(paths: &[PackagePath]) -> Option<BundleError> {
    if let Some(collision) = find_collisions(paths).into_iter().next() {
        return Some(BundleError::Collision {
            first: collision.first,
            second: collision.second,
        });
    }

    let mut folded: BTreeMap<String, PackagePath> = BTreeMap::new();
    for path in paths {
        let segments: Vec<&str> = path.segments().collect();
        for depth in 1..segments.len() {
            let prefix = segments[..depth].join("/");
            let key = segments[..depth]
                .iter()
                .map(|segment| segment.to_lowercase())
                .collect::<Vec<_>>()
                .join("/");
            match folded.get(&key) {
                Some(seen) if seen.as_str() != prefix => {
                    return Some(BundleError::Collision {
                        first: seen.clone(),
                        second: PackagePath::new(prefix).ok()?,
                    });
                }
                Some(_) => {}
                None => {
                    folded.insert(key, PackagePath::new(prefix).ok()?);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock_text() -> &'static str {
        r#"{
  "lock_version": 1,
  "packages": [
    {
      "directory": "fixture",
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
    "generation": "1",
    "generation_path": "snapshots/development",
    "produced_at": "1760000000000",
    "repository": "https://github.com/kalapowered/kalareach-plugins",
    "tree_url": "https://example.invalid/tree"
  },
  "trust_root": {
    "digest": "874233c78ea4a6db808b3967fe6b750c6419084edf2007d2c4fc2e5486d1ed8e",
    "expires": "2036-09-12T13:27:01.481482Z",
    "key_ids": ["f14e4ac91420a6515eb9ae321fcba909420d2cd09cf8c5fd42244af8f0e5fdf2"],
    "version": 1
  }
}"#
    }

    #[test]
    fn the_lock_reads_with_the_sdk_types() {
        let lock = BundleLock::from_slice(lock_text().as_bytes(), "lock").expect("a lock");
        assert_eq!(lock.lock_version, LOCK_VERSION);
        assert_eq!(lock.source.generation, RepositoryGeneration::new(1));
        assert_eq!(lock.source.produced_at, TimestampMs::new(1_760_000_000_000));
        let id = PluginId::new("kalareach/example-declarative").expect("an identifier");
        let package = lock.package(&id).expect("the bundled package");
        assert_eq!(package.directory.as_str(), "fixture");
        assert_eq!(package.manifest.size_bytes.get(), 2953);
    }

    #[test]
    fn a_lock_of_another_version_is_refused_by_version() {
        let text = lock_text().replace("\"lock_version\": 1", "\"lock_version\": 2");
        assert!(matches!(
            BundleLock::from_slice(text.as_bytes(), "lock"),
            Err(LockError::Version { found: 2, .. })
        ));
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
    fn a_local_shortage_is_not_an_untrusted_repository() {
        let path = PackagePath::new("README.md").expect("a package path");
        let shortage = std::io::Error::from(std::io::ErrorKind::OutOfMemory);
        assert_eq!(
            absence(&path, &shortage).code(),
            ErrorCode::ResourceUnavailable
        );

        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert_eq!(
            absence(&path, &missing).code(),
            ErrorCode::PackageUnavailableOffline
        );

        let refused = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            absence(&path, &refused).code(),
            ErrorCode::RepositoryUntrusted
        );
    }

    #[test]
    fn two_spellings_of_one_directory_are_one_name() {
        let paths = ["Assets/a.json", "assets/b.json"]
            .into_iter()
            .map(|value| PackagePath::new(value).expect("a package path"))
            .collect::<Vec<_>>();
        assert!(
            first_collision(&paths).is_some(),
            "two spellings of one directory cannot both exist"
        );

        let apart = ["assets/a.json", "fixtures/b.json"]
            .into_iter()
            .map(|value| PackagePath::new(value).expect("a package path"))
            .collect::<Vec<_>>();
        assert!(first_collision(&apart).is_none());
    }

    #[test]
    fn an_absent_package_is_unavailable_offline() {
        let lock = BundleLock::from_slice(lock_text().as_bytes(), "lock").expect("a lock");
        let directory = tempfile::tempdir().expect("a directory");
        let bundle = Dir::open_ambient_dir(directory.path(), cap_std::ambient_authority())
            .expect("a handle");
        let absent = PluginId::new("kalareach/absent").expect("an identifier");
        let error = lock
            .activate(&bundle, &absent)
            .expect_err("the lock does not carry it");
        assert_eq!(error.code(), ErrorCode::PackageUnavailableOffline);
    }
}
