//! The catalogue index.
//!
//! The host synchronises the complete signed metadata snapshot: compact descriptions, declarative
//! match rules, capability declarations and immutable payload hashes and sizes. Offline search
//! covers the whole index, so the index has to be small enough that a host can hold all of it and
//! complete enough that search never needs the network.
//!
//! That shapes [`IndexEntry`]. It carries what a host needs to search, match and decide, and
//! nothing a host would only need after it decided to install. Documentation, assets and the
//! component itself stay behind their content hashes until an explicit install, an enable, or an
//! already-authorised matching activation asks for them.
//!
//! The index is also a build output that has to be reproducible. [`CatalogueIndex::canonical_json`]
//! renders it with sorted entries and stable key order, so the same inputs produce the same bytes
//! and a signature over those bytes means something.

use kr_protocol::ids::RepositoryGeneration;
use kr_protocol::scalars::{Nullable, TimestampMs};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::capability::{CapabilityRequest, CapabilityState, EvidenceSource};
use crate::digest::{ByteSize, PayloadDigest};
use crate::ids::CapabilityId;
use crate::ids::{PluginId, PluginName, PublisherId};
use crate::matching::{Architecture, MatchRule, OperatingSystem, PlatformSupport};
use crate::plugin::{PayloadRef, PayloadRole, PluginManifest, SourcePin};
use crate::text::{CompactDescription, Label, Summary};
use crate::version::{PackageVersion, VersionRange};

/// The index format version this crate reads and writes.
pub const INDEX_VERSION: u32 = 1;

/// A publisher record.
///
/// Publishers are named in the index so a person can see who signed a package before installing
/// it, and so a delegation can be scoped to one publisher's path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PublisherRecord {
    /// The publisher identifier.
    pub id: PublisherId,
    /// The name a person reads.
    pub display_name: Label,
    /// Where the publisher's own source and contact details live.
    pub homepage: String,
    /// Whether this publisher ships with KalaReach.
    pub first_party: bool,
}

/// Why a package stops receiving new bindings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// The publisher withdrew this release.
    Withdrawn,
    /// The release has a security defect.
    Vulnerable,
    /// The signing key was compromised.
    KeyCompromise,
    /// A later release supersedes it and this one should not be installed again.
    Superseded,
}

/// A revocation record.
///
/// A revoked package stops new bindings. An active binding receives a warning and follows the
/// administrator's explicit disable policy; it does not change under a live request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RevocationRecord {
    /// Why it was revoked.
    pub reason: RevocationReason,
    /// When the revocation was published.
    pub revoked_at: TimestampMs,
    /// What a person reads about it.
    pub statement: Summary,
}

/// One compatibility result the catalogue carries about a package.
///
/// Section 25 stores compatibility results beside the manifests and hashes. Section 11 ships that
/// qualification data as signed, immutable catalogue artefacts, separately from host binaries, so
/// updating it cannot create new primitive effects, raise a grant or turn an old live binding into
/// a different version.
///
/// A result says how a version behaved where it was tested. It is not permission, and it is not a
/// live binding: a host still probes, still checks its grant and still rechecks the capability
/// revision on every action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct QualificationResult {
    /// The versioned capability the result is about.
    pub capability_id: CapabilityId,
    /// The capability version.
    pub capability_version: PackageVersion,
    /// What the publisher qualified the package against.
    pub subject: Label,
    /// What the result is.
    ///
    /// A catalogue result can report that a version was qualified or that it is incompatible. It
    /// cannot report that a capability is available on a host it has never seen.
    pub state: CapabilityState,
    /// Where the result came from.
    pub source: EvidenceSource,
    /// The digest of the signed profile the result came from.
    pub profile_digest: PayloadDigest,
    /// What a person reads about it.
    pub statement: Summary,
}

/// Why a qualification result may not appear in a catalogue index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum QualificationError {
    /// The result claimed a host outcome the catalogue cannot know.
    #[error("a catalogue result cannot claim that a capability is available on a host")]
    ClaimsHostAvailability,
    /// The result came from a source the catalogue does not carry.
    #[error("a catalogue result comes from a signed record, not from {claimed:?}")]
    WrongSource {
        /// The source that was claimed.
        claimed: EvidenceSource,
    },
}

impl QualificationResult {
    /// Checks the rules a catalogue qualification result must satisfy.
    ///
    /// # Errors
    ///
    /// Returns [`QualificationError`] when the result claims a host outcome or a source the
    /// catalogue cannot carry.
    pub fn validate(&self) -> Result<(), QualificationError> {
        if self.state.is_usable() {
            return Err(QualificationError::ClaimsHostAvailability);
        }
        if self.source != EvidenceSource::SignedRecord {
            return Err(QualificationError::WrongSource {
                claimed: self.source,
            });
        }
        Ok(())
    }
}

/// The most executable builds one index entry names.
///
/// A host hands each release it admits to its workers with the builds for its own platform, one
/// whole record at a time, so what one entry can name is bounded: a release is qualified against a
/// few builds per platform, not against thousands.
pub const MAX_QUALIFIED_BUILDS: usize = 256;

/// One executable build of the application a release is qualified against, as the signed index
/// names it: which application it is, where it was distributed from, the upstream version it is,
/// the platform it runs on, and the digest of the executable itself.
///
/// It is signed with the index and kept apart from the package's bytes, so a generation can add or
/// withdraw a build for a release without a new package. A host takes an executable's version from
/// here and nowhere else: a record that names the digest of the exact bytes says what those bytes
/// are. Like a qualification result, it is not permission, and a later record cannot change the
/// version a live binding was bound with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct QualifiedBuild {
    /// The application the build is.
    pub application: Label,
    /// Where the build was distributed from: a registry and its package, or the vendor's archive.
    pub distribution: Label,
    /// The upstream version the build is.
    pub version: PackageVersion,
    /// The operating system it runs on.
    pub os: OperatingSystem,
    /// The architecture it runs on.
    pub architecture: Architecture,
    /// The SHA-256 digest of the executable.
    pub executable_digest: PayloadDigest,
}

/// Why an entry's builds may not appear in a catalogue index.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BuildsError {
    /// The entry names more builds than one entry may.
    #[error("the entry names {count} builds, and one entry names at most {MAX_QUALIFIED_BUILDS}")]
    TooMany {
        /// How many it names.
        count: usize,
    },
    /// A build runs on a platform the release does not support.
    #[error(
        "a build runs on {} {}, which the entry does not list among its platforms",
        os.as_str(),
        architecture.as_str()
    )]
    UnlistedPlatform {
        /// The build's operating system.
        os: OperatingSystem,
        /// The build's architecture.
        architecture: Architecture,
    },
    /// One executable is named as two versions.
    #[error("the executable {digest} is named as version {first} and as version {second}")]
    TwoVersions {
        /// The executable's digest.
        digest: PayloadDigest,
        /// The version it was named as first.
        first: PackageVersion,
        /// The other version it was named as.
        second: PackageVersion,
    },
}

/// One entry in the catalogue index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct IndexEntry {
    /// The wire plugin identifier.
    pub plugin_id: PluginId,
    /// The publisher.
    pub publisher_id: PublisherId,
    /// The plugin name under that publisher.
    pub plugin_name: PluginName,
    /// This release's version.
    pub version: PackageVersion,
    /// The name a person reads.
    pub display_name: Label,
    /// The one-line description offline search reads.
    pub description: CompactDescription,
    /// The SDK versions the package is written against.
    pub sdk_range: VersionRange,
    /// The WIT package versions its component targets.
    pub wit_range: VersionRange,
    /// Where the source came from.
    pub source: SourcePin,
    /// The applications the package recognises.
    pub match_rules: Vec<MatchRule>,
    /// The platforms it supports.
    pub platforms: Vec<PlatformSupport>,
    /// What it asks to be permitted.
    pub capabilities: Vec<CapabilityRequest>,
    /// Every payload, by hash and exact size.
    pub payloads: Vec<PayloadRef>,
    /// The digest of the manifest itself, which names every other payload.
    pub manifest_digest: PayloadDigest,
    /// The exact length of the manifest.
    ///
    /// The manifest does not declare itself, so its length is here. A host checks a declared size
    /// before it downloads, and the manifest is the first thing it downloads.
    pub manifest_size_bytes: ByteSize,
    /// The sum of every payload size and the manifest's own length.
    pub total_size_bytes: ByteSize,
    /// What the publisher qualified this release against.
    pub qualification: Vec<QualificationResult>,
    /// The executable builds of the application this release is qualified against, each with the
    /// digest of its executable and the version it is.
    ///
    /// Absent from the document when there are none, so every index written before the member
    /// existed reads, verifies and is written again exactly as it was: none has to be signed again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub builds: Vec<QualifiedBuild>,
    /// Whether the package ships a Wasm component.
    pub has_component: bool,
    /// The revocation record, where this release has one.
    pub revocation: Nullable<RevocationRecord>,
}

impl IndexEntry {
    /// Builds an entry from a validated manifest, its digest and its exact length.
    #[must_use]
    pub fn from_manifest(
        manifest: &PluginManifest,
        manifest_digest: PayloadDigest,
        manifest_size_bytes: u64,
    ) -> Self {
        Self {
            plugin_id: manifest.plugin_id(),
            publisher_id: manifest.publisher_id.clone(),
            plugin_name: manifest.plugin_name.clone(),
            version: manifest.version.clone(),
            display_name: manifest.display_name.clone(),
            description: manifest.description.clone(),
            sdk_range: manifest.sdk_range.clone(),
            wit_range: manifest.wit_range.clone(),
            source: manifest.source.clone(),
            match_rules: manifest.match_rules.clone(),
            platforms: manifest.platforms.clone(),
            capabilities: manifest.capabilities.clone(),
            payloads: manifest.payloads.clone(),
            manifest_digest,
            manifest_size_bytes: ByteSize::new(manifest_size_bytes),
            total_size_bytes: ByteSize::new(
                manifest
                    .declared_size_bytes()
                    .saturating_add(manifest_size_bytes),
            ),
            has_component: manifest.has_component(),
            qualification: Vec::new(),
            builds: Vec::new(),
            revocation: Nullable(None),
        }
    }

    /// Returns true when this release still accepts new bindings.
    #[must_use]
    pub fn accepts_new_bindings(&self) -> bool {
        self.revocation.0.is_none()
    }

    /// Checks what an index may say about this release's builds: no more than
    /// [`MAX_QUALIFIED_BUILDS`], each on a platform the release supports, and one version for each
    /// executable.
    ///
    /// # Errors
    ///
    /// Returns the first [`BuildsError`] the builds break.
    pub fn check_builds(&self) -> Result<(), BuildsError> {
        if self.builds.len() > MAX_QUALIFIED_BUILDS {
            return Err(BuildsError::TooMany {
                count: self.builds.len(),
            });
        }
        let mut versions: std::collections::BTreeMap<PayloadDigest, &PackageVersion> =
            std::collections::BTreeMap::new();
        for build in &self.builds {
            let listed = self.platforms.iter().any(|platform| {
                platform.os == build.os && platform.architectures.contains(&build.architecture)
            });
            if !listed {
                return Err(BuildsError::UnlistedPlatform {
                    os: build.os,
                    architecture: build.architecture,
                });
            }
            match versions.get(&build.executable_digest) {
                Some(first) if **first != build.version => {
                    return Err(BuildsError::TwoVersions {
                        digest: build.executable_digest,
                        first: (*first).clone(),
                        second: build.version.clone(),
                    });
                }
                Some(_) => {}
                None => {
                    versions.insert(build.executable_digest, &build.version);
                }
            }
        }
        Ok(())
    }

    /// Returns the builds that run on one operating system and architecture.
    pub fn builds_for(
        &self,
        os: OperatingSystem,
        architecture: Architecture,
    ) -> impl Iterator<Item = &QualifiedBuild> {
        self.builds
            .iter()
            .filter(move |build| build.os == os && build.architecture == architecture)
    }

    /// Returns the payload with the given role, where the package has one.
    #[must_use]
    pub fn payload(&self, role: PayloadRole) -> Option<&PayloadRef> {
        self.payloads.iter().find(|payload| payload.role == role)
    }

    /// The key entries are ordered by, so an index built twice is byte-identical.
    #[must_use]
    pub fn sort_key(&self) -> (String, String, String) {
        (
            self.publisher_id.to_string(),
            self.plugin_name.to_string(),
            self.version.to_string(),
        )
    }
}

/// The complete signed metadata snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CatalogueIndex {
    /// The index format version.
    pub index_version: u32,
    /// The generation this snapshot is.
    ///
    /// A generation is what a host pins. Index activation is atomic after metadata verification,
    /// so a host is always on one whole generation and never on a mixture of two.
    pub generation: RepositoryGeneration,
    /// When the snapshot was built.
    pub produced_at: TimestampMs,
    /// The publishers whose packages appear in it.
    pub publishers: Vec<PublisherRecord>,
    /// The entries, ordered by publisher, plugin name and version.
    pub entries: Vec<IndexEntry>,
}

impl CatalogueIndex {
    /// Sorts publishers and entries into the canonical order.
    pub fn sort(&mut self) {
        self.publishers
            .sort_by(|left, right| left.id.cmp(&right.id));
        self.entries.sort_by_key(IndexEntry::sort_key);
    }

    /// Renders the index as canonical JSON.
    ///
    /// Entries and publishers are sorted, object keys are sorted and the output carries no
    /// insignificant whitespace, so the same inputs produce the same bytes. That is what makes a
    /// signature over an index mean "these packages" rather than "this run of the builder".
    ///
    /// The rendering is compact because the index is measured against a byte budget: a host holds
    /// the whole thing so that catalogue search works offline, and indentation would spend roughly
    /// half that budget on whitespace nobody reads.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] when the index cannot be serialised.
    pub fn canonical_json(&self) -> Result<String, serde_json::Error> {
        let mut sorted = self.clone();
        sorted.sort();
        let value = serde_json::to_value(&sorted)?;
        let mut text = serde_json::to_string(&sort_keys(value))?;
        text.push('\n');
        Ok(text)
    }

    /// Returns the digest of the canonical rendering.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] when the index cannot be serialised.
    pub fn digest(&self) -> Result<PayloadDigest, serde_json::Error> {
        Ok(PayloadDigest::of(self.canonical_json()?.as_bytes()))
    }

    /// Returns the entry for one plugin identifier at one version.
    #[must_use]
    pub fn find(&self, plugin_id: &PluginId, version: &PackageVersion) -> Option<&IndexEntry> {
        self.entries
            .iter()
            .find(|entry| &entry.plugin_id == plugin_id && &entry.version == version)
    }

    /// Returns every entry whose match rules recognise an executable at `path`.
    ///
    /// This is the offline lookup: it reads the synchronised index and touches no network and no
    /// payload. A host uses it to decide which packages are relevant before it instantiates any
    /// of them.
    #[must_use]
    pub fn matching_executable(&self, path: &str) -> Vec<&IndexEntry> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.accepts_new_bindings()
                    && entry
                        .match_rules
                        .iter()
                        .any(|rule| rule.executable.matches_path(path))
            })
            .collect()
    }
}

/// Recursively sorts every object key.
fn sort_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: Map<String, Value> = map
                .into_iter()
                .map(|(key, value)| (key, sort_keys(value)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect();
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sort_keys).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::example::example_manifest;

    fn index() -> CatalogueIndex {
        let manifest = example_manifest();
        let digest = PayloadDigest::of(b"manifest");
        let size = 4_096;
        CatalogueIndex {
            index_version: INDEX_VERSION,
            generation: RepositoryGeneration::new(3),
            produced_at: TimestampMs::new(1_760_000_000_000),
            publishers: vec![PublisherRecord {
                id: manifest.publisher_id.clone(),
                display_name: Label::new("KalaReach").expect("valid label"),
                homepage: "https://reach.kala.to".to_owned(),
                first_party: true,
            }],
            entries: vec![IndexEntry::from_manifest(&manifest, digest, size)],
        }
    }

    #[test]
    fn the_canonical_rendering_is_stable() {
        let index = index();
        let first = index.canonical_json().expect("serialisable");
        let second = index.canonical_json().expect("serialisable");
        assert_eq!(first, second);
        assert_eq!(
            index.digest().expect("serialisable"),
            PayloadDigest::of(first.as_bytes())
        );
    }

    #[test]
    fn entry_order_does_not_change_the_bytes() {
        let mut one = index();
        let manifest = example_manifest();
        let mut second_entry =
            IndexEntry::from_manifest(&manifest, PayloadDigest::of(b"other"), 4_096);
        second_entry.version = PackageVersion::parse("0.2.0").expect("valid version");
        one.entries.push(second_entry.clone());

        let mut two = index();
        two.entries.insert(0, second_entry);

        assert_eq!(
            one.canonical_json().expect("serialisable"),
            two.canonical_json().expect("serialisable")
        );
    }

    #[test]
    fn offline_lookup_reads_the_index_alone() {
        let index = index();
        assert_eq!(
            index
                .matching_executable("/usr/local/bin/example-agent")
                .len(),
            1
        );
        assert!(
            index
                .matching_executable("/usr/local/bin/unrelated")
                .is_empty()
        );
    }

    #[test]
    fn a_catalogue_result_cannot_claim_a_host_outcome() {
        let result = QualificationResult {
            capability_id: CapabilityId::new("agent.approval.respond/1").expect("valid id"),
            capability_version: PackageVersion::parse("1.0.0").expect("valid version"),
            subject: Label::new("Codex 1.4").expect("valid label"),
            state: CapabilityState::VersionQualified,
            source: EvidenceSource::SignedRecord,
            profile_digest: PayloadDigest::of(b"profile"),
            statement: Summary::new("Qualified against Codex 1.4").expect("valid statement"),
        };
        assert_eq!(result.validate(), Ok(()));

        let mut claiming = result.clone();
        claiming.state = CapabilityState::QualifiedAvailable;
        assert_eq!(
            claiming.validate(),
            Err(QualificationError::ClaimsHostAvailability)
        );

        let mut declared = result;
        declared.source = EvidenceSource::PackageDeclaration;
        assert!(matches!(
            declared.validate(),
            Err(QualificationError::WrongSource { .. })
        ));
    }

    fn build(version: &str, os: OperatingSystem, architecture: Architecture) -> QualifiedBuild {
        QualifiedBuild {
            application: Label::new("example-agent").expect("valid label"),
            distribution: Label::new("npm @example/agent").expect("valid label"),
            version: PackageVersion::parse(version).expect("valid version"),
            os,
            architecture,
            executable_digest: PayloadDigest::of(version.as_bytes()),
        }
    }

    /// An entry with no builds is written exactly as an entry was before the member existed, so
    /// no index already signed has to be signed again, and one written without the member reads
    /// with none; an entry with builds writes and reads them.
    #[test]
    fn builds_are_absent_from_an_entry_that_has_none() {
        let mut index = index();
        let rendered = index.canonical_json().expect("serialisable");
        assert!(!rendered.contains("builds"), "{rendered}");
        let read: CatalogueIndex = serde_json::from_str(&rendered).expect("readable");
        assert!(read.entries[0].builds.is_empty());
        assert_eq!(read.canonical_json().expect("serialisable"), rendered);

        index.entries[0].builds = vec![build(
            "1.4.0",
            OperatingSystem::Linux,
            Architecture::X86_64,
        )];
        let rendered = index.canonical_json().expect("serialisable");
        assert!(rendered.contains("\"builds\""), "{rendered}");
        let read: CatalogueIndex = serde_json::from_str(&rendered).expect("readable");
        assert_eq!(read.entries[0].builds, index.entries[0].builds);
    }

    /// An index names a build only on a platform the release lists, one version for each
    /// executable, and no more than the bound; and a host asks for the builds of its own platform.
    #[test]
    fn builds_stay_on_listed_platforms_with_one_version_each_within_the_bound() {
        let mut entry = index().entries.remove(0);
        entry.platforms = vec![PlatformSupport {
            os: OperatingSystem::Linux,
            architectures: vec![Architecture::X86_64, Architecture::Aarch64],
        }];
        entry.builds = vec![
            build("1.4.0", OperatingSystem::Linux, Architecture::X86_64),
            build("1.4.0", OperatingSystem::Linux, Architecture::Aarch64),
        ];
        assert_eq!(entry.check_builds(), Ok(()));
        assert_eq!(
            entry
                .builds_for(OperatingSystem::Linux, Architecture::Aarch64)
                .count(),
            1
        );
        assert_eq!(
            entry
                .builds_for(OperatingSystem::MacOs, Architecture::Aarch64)
                .count(),
            0
        );

        let mut unlisted = entry.clone();
        unlisted
            .builds
            .push(build("1.4.1", OperatingSystem::MacOs, Architecture::Aarch64));
        assert_eq!(
            unlisted.check_builds(),
            Err(BuildsError::UnlistedPlatform {
                os: OperatingSystem::MacOs,
                architecture: Architecture::Aarch64,
            })
        );

        let mut two_versions = entry.clone();
        let mut again = build("1.4.0", OperatingSystem::Linux, Architecture::X86_64);
        again.version = PackageVersion::parse("1.5.0").expect("valid version");
        two_versions.builds.push(again);
        assert!(matches!(
            two_versions.check_builds(),
            Err(BuildsError::TwoVersions { .. })
        ));

        let mut at_bound = entry.clone();
        at_bound.builds = (0..MAX_QUALIFIED_BUILDS)
            .map(|n| {
                let mut one = build("1.4.0", OperatingSystem::Linux, Architecture::X86_64);
                one.executable_digest = PayloadDigest::of(&n.to_le_bytes());
                one
            })
            .collect();
        assert_eq!(at_bound.check_builds(), Ok(()));
        at_bound
            .builds
            .push(build("1.4.0", OperatingSystem::Linux, Architecture::X86_64));
        assert_eq!(
            at_bound.check_builds(),
            Err(BuildsError::TooMany {
                count: MAX_QUALIFIED_BUILDS + 1
            })
        );
    }

    #[test]
    fn a_revoked_entry_stops_matching_for_new_bindings() {
        let mut index = index();
        index.entries[0].revocation = Nullable(Some(RevocationRecord {
            reason: RevocationReason::Vulnerable,
            revoked_at: TimestampMs::new(1_760_000_100_000),
            statement: Summary::new("Replaced by 0.1.1").expect("valid statement"),
        }));
        assert!(!index.entries[0].accepts_new_bindings());
        assert!(
            index
                .matching_executable("/usr/local/bin/example-agent")
                .is_empty()
        );
    }
}
