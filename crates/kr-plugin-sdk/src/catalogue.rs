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

use crate::capability::CapabilityRequest;
use crate::digest::{ByteSize, PayloadDigest};
use crate::ids::{PluginId, PluginName, PublisherId};
use crate::matching::{MatchRule, PlatformSupport};
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
    /// The sum of every payload size.
    pub total_size_bytes: ByteSize,
    /// Whether the package ships a Wasm component.
    pub has_component: bool,
    /// The revocation record, where this release has one.
    pub revocation: Nullable<RevocationRecord>,
}

impl IndexEntry {
    /// Builds an entry from a validated manifest and its digest.
    #[must_use]
    pub fn from_manifest(manifest: &PluginManifest, manifest_digest: PayloadDigest) -> Self {
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
            total_size_bytes: ByteSize::new(manifest.declared_size_bytes()),
            has_component: manifest.has_component(),
            revocation: Nullable(None),
        }
    }

    /// Returns true when this release still accepts new bindings.
    #[must_use]
    pub fn accepts_new_bindings(&self) -> bool {
        self.revocation.0.is_none()
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
    /// Entries and publishers are sorted, object keys are sorted and the indentation is fixed, so
    /// the same inputs produce the same bytes. That is what makes a signature over an index mean
    /// "these packages", rather than "this run of the builder".
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] when the index cannot be serialised.
    pub fn canonical_json(&self) -> Result<String, serde_json::Error> {
        let mut sorted = self.clone();
        sorted.sort();
        let value = serde_json::to_value(&sorted)?;
        let mut text = serde_json::to_string_pretty(&sort_keys(value))?;
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
            entries: vec![IndexEntry::from_manifest(&manifest, digest)],
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
        let mut second_entry = IndexEntry::from_manifest(&manifest, PayloadDigest::of(b"other"));
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
