//! Building signed catalogue generations inside a test.
//!
//! Every generation the suite verifies is built here, with four Ed25519 keys made in memory: one
//! per role, exactly as a real trust root separates them. Nothing is written to a key file and
//! nothing is read from one, so there is no signing key in this repository to leak or rotate.
//!
//! The generations are written with the same `tough` editor the publishing pipeline signs with,
//! which is what makes the suite a qualification of that client's actual behaviour rather than of
//! a reimplementation that agrees with the code under test by construction.

#![allow(dead_code)]

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::Ed25519KeyPair;
use kr_plugin_sdk::capability::{CapabilityRequest, PluginCapability};
use kr_plugin_sdk::catalogue::{CatalogueIndex, INDEX_VERSION, IndexEntry, PublisherRecord};
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::ids::{PluginName, PublisherId};
use kr_plugin_sdk::plugin::PluginManifest;
use kr_plugin_sdk::text::{Label, Summary};
use kr_plugin_sdk::version::PackageVersion;
use kr_protocol::ids::RepositoryGeneration;
use kr_protocol::scalars::TimestampMs;
use tough::editor::RepositoryEditor;
use tough::editor::signed::SignedRole;
use tough::key_source::KeySource;
use tough::schema::key::Key;
use tough::schema::{KeyHolder, PathPattern, PathSet, RoleKeys, RoleType, Root, Target};
use tough::sign::Sign;

/// One signing key, held as its PKCS#8 bytes and never written anywhere.
#[derive(Clone, Debug)]
pub struct TestKey {
    pkcs8: Vec<u8>,
}

impl TestKey {
    /// Generates a fresh Ed25519 key.
    #[must_use]
    pub fn generate() -> Self {
        let rng = SystemRandom::new();
        let document = Ed25519KeyPair::generate_pkcs8(&rng).expect("a generated key");
        Self {
            pkcs8: document.as_ref().to_vec(),
        }
    }

    fn pair(&self) -> Ed25519KeyPair {
        Ed25519KeyPair::from_pkcs8(&self.pkcs8).expect("a readable key")
    }

    /// Returns the public key as the trust root names it.
    #[must_use]
    pub fn tuf_key(&self) -> Key {
        Sign::tuf_key(&self.pair())
    }
}

#[tough::async_trait]
impl KeySource for TestKey {
    async fn as_sign(
        &self,
    ) -> Result<Box<dyn Sign>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(Box::new(self.pair()))
    }

    async fn write(
        &self,
        _value: &str,
        _key_id_hex: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        // A test key is never written. Writing one would be putting a signing key on disk beside
        // the repository it signs for, which is the thing the pipeline refuses to do.
        Ok(())
    }
}

/// The four role keys of one trust root.
#[derive(Clone, Debug)]
pub struct KeySet {
    pub root: TestKey,
    pub targets: TestKey,
    pub snapshot: TestKey,
    pub timestamp: TestKey,
}

impl KeySet {
    /// Generates one key per role.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            root: TestKey::generate(),
            targets: TestKey::generate(),
            snapshot: TestKey::generate(),
            timestamp: TestKey::generate(),
        }
    }

    fn sources(&self) -> Vec<Box<dyn KeySource>> {
        vec![
            Box::new(self.root.clone()),
            Box::new(self.targets.clone()),
            Box::new(self.snapshot.clone()),
            Box::new(self.timestamp.clone()),
        ]
    }

    fn root_document(&self, expires: jiff::Timestamp, consistent_snapshot: bool) -> Root {
        self.root_document_with_version(
            NonZeroU64::new(1).expect("one is not zero"),
            expires,
            consistent_snapshot,
        )
    }

    fn root_document_with_version(
        &self,
        version: NonZeroU64,
        expires: jiff::Timestamp,
        consistent_snapshot: bool,
    ) -> Root {
        let mut keys = HashMap::new();
        let mut roles = HashMap::new();
        for (role, key) in [
            (RoleType::Root, &self.root),
            (RoleType::Targets, &self.targets),
            (RoleType::Snapshot, &self.snapshot),
            (RoleType::Timestamp, &self.timestamp),
        ] {
            let tuf_key = key.tuf_key();
            let key_id = tuf_key.key_id().expect("a key identifier");
            keys.insert(key_id.clone(), tuf_key);
            roles.insert(
                role,
                RoleKeys {
                    keyids: vec![key_id],
                    threshold: NonZeroU64::new(1).expect("one is not zero"),
                    _extra: HashMap::new(),
                },
            );
        }
        Root {
            spec_version: "1.0.0".to_owned(),
            consistent_snapshot,
            version,
            expires,
            keys,
            roles,
            _extra: HashMap::new(),
        }
    }
}

/// Returns a fresh key set.
#[must_use]
pub fn key_set() -> KeySet {
    KeySet::generate()
}

/// What one generation is made of.
#[derive(Clone, Debug)]
pub struct GenerationSpec {
    /// The generation number, which is also every role's metadata version.
    pub generation: u64,
    /// The package directory to publish, or the example package when absent.
    pub package: Option<PathBuf>,
    /// The version the published package carries.
    pub package_version: String,
    /// The capabilities the published package requests.
    pub capabilities: Vec<PluginCapability>,
    /// Vendor delegations, as name, path pattern and whether the role terminates the search.
    pub delegations: Vec<(String, String, bool)>,
    /// A payload file to delete after the generation is signed, leaving the metadata pinning it.
    pub drop_payload: Option<String>,
    /// The keys to sign with, or a fresh set when absent.
    pub keys: Option<KeySet>,
    /// Whether the metadata expires in the past.
    pub expired: bool,
    /// Whether to build a nested two-level delegation (top -> vendor -> vendor-leaf).
    pub nested_delegation: bool,
    /// How deep a chain of delegations to build (top -> level-1 -> ... -> level-n), each role
    /// delegating to the next and the last signing the package's targets. None where zero.
    pub delegation_chain: usize,
    /// Whether the leaf role carries no package targets (for terminating-miss test).
    pub empty_leaf: bool,
    /// Whether the root publishes consistent snapshots: every metadata document but the timestamp
    /// named with its version in front, and every target with its SHA-256.
    pub consistent_snapshot: bool,
    /// The version of the root this generation is signed under.
    pub root_version: u64,
    /// The keys of the root this one replaces, which sign it as well, as a rotation is signed.
    pub previous_keys: Option<KeySet>,
    /// Fields the root carries beyond the ones the client knows, signed with the rest.
    pub root_extra: Vec<(String, serde_json::Value)>,
    /// Whether the package carries the presentation's bytes a second time, as an asset at
    /// `assets/presentation-copy.json`: two paths that share one digest.
    pub asset_copy: bool,
    /// A length the index and the targets metadata both declare for every file that holds the
    /// presentation's bytes, in place of its real one: two signed statements that agree with each
    /// other and not with the bytes.
    pub understated_presentation: Option<u64>,
    /// A change made to the package's index entry after it is derived from the manifest, before
    /// the index is signed: an index that says something the manifest does not.
    pub edit_entry: Option<fn(&mut IndexEntry)>,
}

impl Default for GenerationSpec {
    fn default() -> Self {
        Self {
            generation: 1,
            package: None,
            package_version: "0.1.0".to_owned(),
            capabilities: Vec::new(),
            delegations: Vec::new(),
            drop_payload: None,
            keys: None,
            expired: false,
            nested_delegation: false,
            delegation_chain: 0,
            empty_leaf: false,
            consistent_snapshot: false,
            root_version: 1,
            previous_keys: None,
            root_extra: Vec::new(),
            asset_copy: false,
            understated_presentation: None,
            edit_entry: None,
        }
    }
}

/// One built generation on disk.
#[derive(Debug)]
pub struct Generation {
    directory: PathBuf,
    keys: KeySet,
    manifest_digest: PayloadDigest,
    spec: GenerationSpec,
}

impl Generation {
    /// Builds and signs one generation under `home`.
    pub async fn build(home: &Path, spec: GenerationSpec) -> Self {
        let directory = home.join("generation");
        let keys = spec.keys.clone().unwrap_or_else(KeySet::generate);
        let manifest_digest = write_generation(&directory, &keys, &spec).await;
        Self {
            directory,
            keys,
            manifest_digest,
            spec,
        }
    }

    /// Returns the keys this generation was signed with.
    #[must_use]
    pub fn keys(&self) -> KeySet {
        self.keys.clone()
    }

    /// Returns the digest of the published package's manifest, which is its package hash.
    #[must_use]
    pub const fn manifest_digest(&self) -> PayloadDigest {
        self.manifest_digest
    }

    /// Returns the directory the generation is published in, metadata and targets.
    #[must_use]
    pub fn directory(&self) -> PathBuf {
        self.directory.clone()
    }

    /// Returns the adopted trust root's bytes.
    #[must_use]
    pub fn root_bytes(&self) -> Vec<u8> {
        std::fs::read(self.directory.join("root.json")).expect("a trust root")
    }

    /// Returns the metadata location.
    #[must_use]
    pub fn metadata_url(&self) -> url::Url {
        directory_url(&self.directory.join("metadata"))
    }

    /// Returns the metadata directory.
    #[must_use]
    pub fn metadata_dir(&self) -> PathBuf {
        self.directory.join("metadata")
    }

    /// Returns the targets location.
    #[must_use]
    pub fn targets_url(&self) -> url::Url {
        directory_url(&self.directory.join("targets"))
    }

    /// Returns the targets directory.
    #[must_use]
    pub fn targets_dir(&self) -> PathBuf {
        self.directory.join("targets")
    }

    /// Publishes `spec` at this location under a new root that this generation's root signs as
    /// well, beside what is already here, so a client that trusts this generation's root moves to
    /// the new one. The new root is signed with fresh keys unless `spec` names some.
    pub async fn rotate_to(&self, spec: GenerationSpec) {
        let keys = spec.keys.clone().unwrap_or_else(KeySet::generate);
        let spec = GenerationSpec {
            keys: Some(keys.clone()),
            previous_keys: Some(self.keys.clone()),
            ..spec
        };
        write_generation(&self.directory, &keys, &spec).await;
    }

    /// Rebuilds this generation in place at another generation number.
    pub async fn rewrite_as(&self, generation: u64) {
        let spec = GenerationSpec {
            generation,
            keys: Some(self.keys.clone()),
            ..self.spec.clone()
        };
        std::fs::remove_dir_all(&self.directory).expect("removable");
        write_generation(&self.directory, &self.keys, &spec).await;
    }

    /// Rebuilds this generation in place with metadata that has already expired.
    pub async fn rewrite_expired(&self, generation: u64) {
        let spec = GenerationSpec {
            generation,
            expired: true,
            keys: Some(self.keys.clone()),
            ..self.spec.clone()
        };
        std::fs::remove_dir_all(&self.directory).expect("removable");
        write_generation(&self.directory, &self.keys, &spec).await;
    }

    /// Replaces what is at this location with another generation's contents.
    pub fn replace_with(&self, other: &Self) {
        std::fs::remove_dir_all(&self.directory).expect("removable");
        copy_tree(&other.directory, &self.directory);
    }

    /// Moves the whole repository out of reach, as an offline host would find it.
    pub fn take_offline(&self) {
        let aside = self.directory.with_extension("offline");
        if aside.exists() {
            std::fs::remove_dir_all(&aside).expect("removable");
        }
        std::fs::rename(&self.directory, &aside).expect("movable");
    }

    /// Rotates the root to version 2 using `new_keys`, cross-signing with the old root key,
    /// writing `2.root.json` and signing metadata at generation 2.
    pub async fn rotate_root_to_v2(&self, new_keys: &KeySet) -> Vec<u8> {
        self.rotate_root_to_v2_publishing(new_keys, 2).await
    }

    /// Rotates the root as [`Self::rotate_root_to_v2`] does, with every role's metadata signed at
    /// version 2 and the index published as `index_generation`.
    pub async fn rotate_root_to_v2_publishing(
        &self,
        new_keys: &KeySet,
        index_generation: u64,
    ) -> Vec<u8> {
        let metadata = self.directory.join("metadata");
        let targets = self.directory.join("targets");
        let root_expires: jiff::Timestamp =
            "2036-01-01T00:00:00Z".parse().expect("a literal instant");
        let expires = root_expires;

        let consistent_snapshot = self.spec.consistent_snapshot;
        let root_v2 = new_keys.root_document_with_version(
            NonZeroU64::new(2).expect("two is not zero"),
            root_expires,
            consistent_snapshot,
        );

        let old_root_doc = self.keys.root_document(root_expires, consistent_snapshot);
        let old_signed = SignedRole::new(
            root_v2.clone(),
            &KeyHolder::Root(old_root_doc),
            &self.keys.sources(),
            &SystemRandom::new(),
        )
        .await
        .expect("signed with old root");
        let old_signatures = old_signed.signed().signatures.clone();

        let signed_root_v2 = SignedRole::new(
            root_v2.clone(),
            &KeyHolder::Root(root_v2),
            &new_keys.sources(),
            &SystemRandom::new(),
        )
        .await
        .expect("signed root v2");

        let cross_signed = signed_root_v2
            .add_old_signatures(old_signatures)
            .expect("cross signed");
        let root_v2_bytes = cross_signed.buffer().clone();

        std::fs::write(self.directory.join("root.json"), &root_v2_bytes).expect("writable");
        std::fs::write(metadata.join("root.json"), &root_v2_bytes).expect("writable");
        std::fs::write(metadata.join("2.root.json"), &root_v2_bytes).expect("writable");

        // Now resign the repository metadata using new_keys at version 2
        let version = NonZeroU64::new(2).expect("two is not zero");
        let mut editor = RepositoryEditor::new(self.directory.join("root.json"))
            .await
            .expect("editor");
        editor
            .targets_version(version)
            .expect("version")
            .targets_expires(expires)
            .expect("expiry")
            .snapshot_version(version)
            .snapshot_expires(expires)
            .timestamp_version(version)
            .timestamp_expires(expires);

        let (manifest, files) = package_files(&self.spec);
        let manifest_bytes = files
            .iter()
            .find(|(name, _)| name == kr_plugin_sdk::package::MANIFEST_FILE)
            .map(|(_, bytes)| bytes.clone())
            .expect("a manifest");
        let manifest_digest = PayloadDigest::of(&manifest_bytes);
        let entry =
            IndexEntry::from_manifest(&manifest, manifest_digest, manifest_bytes.len() as u64);
        let index = CatalogueIndex {
            index_version: INDEX_VERSION,
            generation: RepositoryGeneration::new(index_generation),
            produced_at: TimestampMs::new(1_760_000_000_000),
            publishers: vec![PublisherRecord {
                id: manifest.publisher_id.clone(),
                display_name: Label::new("KalaReach").expect("a literal label"),
                homepage: "https://reach.kala.to".to_owned(),
                first_party: true,
            }],
            entries: vec![entry],
        };
        let index_bytes = index.canonical_json().expect("serialisable").into_bytes();
        std::fs::write(targets.join("index.json"), &index_bytes).expect("writable");

        let prefix = format!(
            "packages/{}/{}/{}",
            manifest.publisher_id, manifest.plugin_name, manifest.version
        );

        let mut names: Vec<(String, PathBuf)> =
            vec![("index.json".to_owned(), targets.join("index.json"))];
        for (name, _) in &files {
            names.push((format!("{prefix}/{name}"), targets.join(&prefix).join(name)));
        }
        names.sort();
        for (name, path) in &names {
            let target = Target::from_path(path).await.expect("a target");
            editor.add_target(name.as_str(), target).expect("added");
        }

        let signed = editor.sign(&new_keys.sources()).await.expect("signed");
        signed.write(&metadata).await.expect("written");
        if consistent_snapshot {
            publish_consistent(&targets, names.iter().map(|(name, _)| name.as_str()));
        }
        std::fs::write(metadata.join("root.json"), &root_v2_bytes).expect("writable");

        root_v2_bytes
    }

    /// Withholds root v2 by replacing `metadata/root.json` with root v1 and removing `2.root.json`.
    pub fn withhold_root_v2(&self) {
        let metadata = self.directory.join("metadata");
        let _ = std::fs::remove_file(metadata.join("2.root.json"));
        let root_v1 = std::fs::read(metadata.join("1.root.json")).expect("root 1");
        std::fs::write(metadata.join("root.json"), &root_v1).expect("writable");
    }

    /// Restores root v2 metadata.
    pub fn restore_root_v2(&self, root_v2_bytes: &[u8]) {
        let metadata = self.directory.join("metadata");
        std::fs::write(self.directory.join("root.json"), root_v2_bytes).expect("writable");
        std::fs::write(metadata.join("root.json"), root_v2_bytes).expect("writable");
        std::fs::write(metadata.join("2.root.json"), root_v2_bytes).expect("writable");
    }
}

async fn write_generation(directory: &Path, keys: &KeySet, spec: &GenerationSpec) -> PayloadDigest {
    let metadata = directory.join("metadata");
    let targets = directory.join("targets");
    std::fs::create_dir_all(&metadata).expect("a metadata directory");
    std::fs::create_dir_all(&targets).expect("a targets directory");

    let expires: jiff::Timestamp = if spec.expired {
        "2020-01-01T00:00:00Z".parse().expect("a literal instant")
    } else {
        "2036-01-01T00:00:00Z".parse().expect("a literal instant")
    };
    // The root itself never expires inside a test: expiry is exercised on the roles a repository
    // republishes, which is what section 11's rule is about.
    let root_expires: jiff::Timestamp = "2036-01-01T00:00:00Z".parse().expect("a literal instant");

    let root_version = NonZeroU64::new(spec.root_version).expect("a root version starts at one");
    let mut root =
        keys.root_document_with_version(root_version, root_expires, spec.consistent_snapshot);
    root._extra.extend(spec.root_extra.iter().cloned());
    let signed_root = SignedRole::new(
        root.clone(),
        &KeyHolder::Root(root.clone()),
        &keys.sources(),
        &SystemRandom::new(),
    )
    .await
    .expect("a signed root");
    // A root after the first is signed by the root it replaces as well, which is what lets a
    // client that trusts that one move to it.
    let signed_root = match &spec.previous_keys {
        Some(previous) => {
            let old = SignedRole::new(
                root.clone(),
                &KeyHolder::Root(previous.root_document(root_expires, false)),
                &previous.sources(),
                &SystemRandom::new(),
            )
            .await
            .expect("signed by the previous root");
            signed_root
                .add_old_signatures(old.signed().signatures.clone())
                .expect("cross signed")
        }
        None => signed_root,
    };
    let root_bytes = signed_root.buffer().clone();
    let versioned_root = format!("{}.root.json", spec.root_version);
    std::fs::write(directory.join("root.json"), &root_bytes).expect("writable");
    std::fs::write(metadata.join("root.json"), &root_bytes).expect("writable");
    std::fs::write(metadata.join(&versioned_root), &root_bytes).expect("writable");

    // The package, then the index that describes it.
    let (manifest, files) = package_files(spec);
    let manifest_bytes = files
        .iter()
        .find(|(name, _)| name == kr_plugin_sdk::package::MANIFEST_FILE)
        .map(|(_, bytes)| bytes.clone())
        .expect("a manifest");
    let manifest_digest = PayloadDigest::of(&manifest_bytes);

    let prefix = format!(
        "packages/{}/{}/{}",
        manifest.publisher_id, manifest.plugin_name, manifest.version
    );
    for (name, bytes) in &files {
        let path = targets.join(&prefix).join(name);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("writable");
        std::fs::write(&path, bytes).expect("writable");
    }

    let mut entry =
        IndexEntry::from_manifest(&manifest, manifest_digest, manifest_bytes.len() as u64);
    if let Some(edit) = spec.edit_entry {
        edit(&mut entry);
    }
    // The names of the files that hold the presentation's bytes, and the length both signed
    // statements declare for them where it is understated.
    let presentation_digest = files
        .iter()
        .find(|(name, _)| name == kr_plugin_sdk::package::PRESENTATION_FILE)
        .map(|(_, bytes)| PayloadDigest::of(bytes))
        .expect("a presentation");
    let understated: std::collections::BTreeSet<String> = files
        .iter()
        .filter(|(_, bytes)| PayloadDigest::of(bytes) == presentation_digest)
        .map(|(name, _)| {
            format!(
                "packages/{}/{}/{}/{name}",
                manifest.publisher_id, manifest.plugin_name, manifest.version
            )
        })
        .collect();
    if let Some(length) = spec.understated_presentation {
        let mut total = entry.total_size_bytes.get();
        for payload in &mut entry.payloads {
            if payload.digest == presentation_digest {
                total = total - payload.size_bytes.get() + length;
                payload.size_bytes = kr_protocol::scalars::U64::new(length);
            }
        }
        entry.total_size_bytes = kr_protocol::scalars::U64::new(total);
    }
    let declared = |name: &str, mut target: Target| {
        if let Some(length) = spec.understated_presentation
            && understated.contains(name)
        {
            target.length = length;
        }
        target
    };
    let index = CatalogueIndex {
        index_version: INDEX_VERSION,
        generation: RepositoryGeneration::new(spec.generation),
        produced_at: TimestampMs::new(1_760_000_000_000),
        publishers: vec![PublisherRecord {
            id: manifest.publisher_id.clone(),
            display_name: Label::new("KalaReach").expect("a literal label"),
            homepage: "https://reach.kala.to".to_owned(),
            first_party: true,
        }],
        entries: vec![entry],
    };
    let index_bytes = index.canonical_json().expect("serialisable").into_bytes();
    std::fs::write(targets.join("index.json"), &index_bytes).expect("writable");

    let version = NonZeroU64::new(spec.generation).expect("a generation starts at one");
    let mut editor = RepositoryEditor::new(directory.join("root.json"))
        .await
        .expect("an editor over the root");
    editor
        .targets_version(version)
        .expect("a version")
        .targets_expires(expires)
        .expect("an expiry")
        .snapshot_version(version)
        .snapshot_expires(expires)
        .timestamp_version(version)
        .timestamp_expires(expires);

    // A chain of delegations: each role delegates the publisher's packages to the next, and the
    // last one signs the package's targets. The index stays with the top-level targets role.
    let chain: Vec<(String, bool)> = if spec.nested_delegation {
        vec![
            ("vendor".to_owned(), false),
            ("vendor-leaf".to_owned(), true),
        ]
    } else {
        (1..=spec.delegation_chain)
            .map(|level| (format!("level-{level}"), false))
            .collect()
    };
    if !chain.is_empty() {
        let index_target = Target::from_path(targets.join("index.json"))
            .await
            .expect("an index target");
        editor
            .add_target("index.json", index_target)
            .expect("added");

        // Whoever signs the role being edited: the top-level targets key, then each delegate.
        let mut signer: Option<TestKey> = None;
        for (role, terminating) in &chain {
            let delegate = TestKey::generate();
            let sources: Vec<Box<dyn KeySource>> = vec![Box::new(delegate.clone())];
            editor
                .delegate_role(
                    role,
                    &sources,
                    PathSet::Paths(vec![
                        PathPattern::new(format!("packages/{}/*/*/*", manifest.publisher_id))
                            .expect("a parsable pattern"),
                    ]),
                    *terminating,
                    NonZeroU64::new(1).expect("one is not zero"),
                    expires,
                    version,
                )
                .await
                .expect("a delegated role");
            let signing: Vec<Box<dyn KeySource>> = match &signer {
                None => keys.sources(),
                Some(key) => vec![Box::new(key.clone())],
            };
            editor
                .sign_targets_editor(&signing)
                .await
                .expect("the delegating role signed");
            editor
                .change_delegated_targets(role)
                .expect("the delegated role is editable");
            editor
                .targets_version(version)
                .expect("version")
                .targets_expires(expires)
                .expect("expiry");
            signer = Some(delegate);
        }
        let leaf_sources: Vec<Box<dyn KeySource>> =
            vec![Box::new(signer.expect("a chain has a last role"))];

        if !spec.empty_leaf {
            for (name, _) in &files {
                let target_name = format!("{prefix}/{name}");
                let target_path = targets.join(&prefix).join(name);
                let target = declared(
                    &target_name,
                    Target::from_path(&target_path).await.expect("a target"),
                );
                editor
                    .add_target(target_name.as_str(), target)
                    .expect("added");
            }
        }

        editor
            .sign_targets_editor(&leaf_sources)
            .await
            .expect("the last role signed");
    } else {
        let mut names: Vec<(String, PathBuf)> =
            vec![("index.json".to_owned(), targets.join("index.json"))];
        for (name, _) in &files {
            names.push((format!("{prefix}/{name}"), targets.join(&prefix).join(name)));
        }
        names.sort();
        for (name, path) in &names {
            let target = declared(name, Target::from_path(path).await.expect("a target"));
            editor.add_target(name.as_str(), target).expect("added");
        }

        for (role, pattern, terminating) in &spec.delegations {
            let delegated = TestKey::generate();
            let sources: Vec<Box<dyn KeySource>> = vec![Box::new(delegated)];
            editor
                .delegate_role(
                    role,
                    &sources,
                    PathSet::Paths(vec![
                        PathPattern::new(pattern.clone()).expect("a parsable pattern"),
                    ]),
                    *terminating,
                    NonZeroU64::new(1).expect("one is not zero"),
                    expires,
                    version,
                )
                .await
                .expect("a delegated role");
        }
    }

    let signed = editor
        .sign(&keys.sources())
        .await
        .expect("a signed repository");
    signed.write(&metadata).await.expect("written");
    std::fs::write(metadata.join("root.json"), &root_bytes).expect("writable");
    std::fs::write(metadata.join(&versioned_root), &root_bytes).expect("writable");
    if spec.consistent_snapshot {
        let mut names = vec!["index.json".to_owned()];
        names.extend(files.iter().map(|(name, _)| format!("{prefix}/{name}")));
        publish_consistent(&targets, names.iter().map(String::as_str));
    }

    if let Some(dropped) = &spec.drop_payload {
        // The metadata still pins it. The bytes are gone, which is what a host finds when a
        // repository loses a payload between publishing and being asked for it.
        let path = targets.join(&prefix).join(dropped);
        std::fs::remove_file(&path).expect("removable");
    }

    manifest_digest
}

/// Publishes every named target a second time under the name a consistent snapshot fetches it by:
/// its SHA-256 in hexadecimal, a dot, then the whole target name.
fn publish_consistent<'a>(targets: &Path, names: impl Iterator<Item = &'a str>) {
    for name in names {
        let bytes = std::fs::read(targets.join(name)).expect("a published target");
        let digest: String = PayloadDigest::of(&bytes)
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let path = targets.join(format!("{digest}.{name}"));
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("writable");
        std::fs::write(&path, &bytes).expect("writable");
    }
}

/// Returns the manifest and the files of the package a generation publishes.
fn package_files(spec: &GenerationSpec) -> (PluginManifest, Vec<(String, Vec<u8>)>) {
    if let Some(directory) = &spec.package {
        let mut files = Vec::new();
        for path in read_tree(directory) {
            let relative = path
                .strip_prefix(directory)
                .expect("inside the package")
                .to_string_lossy()
                .replace('\\', "/");
            files.push((relative, std::fs::read(&path).expect("readable")));
        }
        files.sort();
        let manifest_bytes = files
            .iter()
            .find(|(name, _)| name == kr_plugin_sdk::package::MANIFEST_FILE)
            .map(|(_, bytes)| bytes.clone())
            .expect("a manifest");
        let manifest: PluginManifest =
            serde_json::from_slice(&manifest_bytes).expect("a readable manifest");
        return (manifest, files);
    }

    let presentation = kr_plugin_sdk::example::example_presentation_json();
    let mut manifest = kr_plugin_sdk::example::example_manifest_for(presentation.as_bytes());
    manifest.version = PackageVersion::parse(&spec.package_version).expect("a valid version");
    if !spec.capabilities.is_empty() {
        manifest.capabilities = spec
            .capabilities
            .iter()
            .map(|capability| CapabilityRequest {
                capability: *capability,
                reason: Summary::new("the example package asks for it").expect("a literal summary"),
            })
            .collect();
    }
    let copy = "assets/presentation-copy.json";
    if spec.asset_copy {
        let mut asset = manifest
            .payloads
            .iter()
            .find(|payload| payload.path.as_str() == kr_plugin_sdk::package::PRESENTATION_FILE)
            .expect("the presentation is a payload")
            .clone();
        asset.role = kr_plugin_sdk::plugin::PayloadRole::Asset;
        asset.path = kr_plugin_sdk::paths::PackagePath::new(copy).expect("a package path");
        manifest.payloads.push(asset);
    }
    let mut manifest_json =
        serde_json::to_string_pretty(&manifest).expect("the manifest is serialisable");
    manifest_json.push('\n');
    let mut files = vec![
        (
            kr_plugin_sdk::package::MANIFEST_FILE.to_owned(),
            manifest_json.into_bytes(),
        ),
        (
            kr_plugin_sdk::package::PRESENTATION_FILE.to_owned(),
            presentation.clone().into_bytes(),
        ),
    ];
    if spec.asset_copy {
        files.push((copy.to_owned(), presentation.into_bytes()));
    }
    (manifest, files)
}

/// Returns the example package as its files.
#[must_use]
pub fn example_package() -> Vec<(String, Vec<u8>)> {
    package_files(&GenerationSpec::default()).1
}

/// Returns an index entry for the example package.
#[must_use]
pub fn example_entry() -> IndexEntry {
    let presentation = kr_plugin_sdk::example::example_presentation_json();
    let manifest = kr_plugin_sdk::example::example_manifest_for(presentation.as_bytes());
    let mut manifest_json =
        serde_json::to_string_pretty(&manifest).expect("the manifest is serialisable");
    manifest_json.push('\n');
    IndexEntry::from_manifest(
        &manifest,
        PayloadDigest::of(manifest_json.as_bytes()),
        manifest_json.len() as u64,
    )
}

/// Returns an index of `count` small definitions, each recognising its own executable.
#[must_use]
pub fn synthetic_index(count: usize) -> CatalogueIndex {
    let presentation = kr_plugin_sdk::example::example_presentation_json();
    let template = kr_plugin_sdk::example::example_manifest_for(presentation.as_bytes());
    let mut entries = Vec::with_capacity(count);
    for ordinal in 0..count {
        let mut manifest = template.clone();
        let name = format!("agent-{ordinal}");
        manifest.plugin_name = PluginName::new(&name).expect("a valid plugin name");
        manifest.display_name = Label::new(format!("Agent {ordinal}")).expect("a valid label");
        manifest.match_rules[0].executable.file_stem = name.clone();
        manifest.match_rules[0].distribution = kr_protocol::scalars::Nullable(None);
        entries.push(IndexEntry::from_manifest(
            &manifest,
            PayloadDigest::of(name.as_bytes()),
            4_096,
        ));
    }
    CatalogueIndex {
        index_version: INDEX_VERSION,
        generation: RepositoryGeneration::new(1),
        produced_at: TimestampMs::new(1_760_000_000_000),
        publishers: vec![PublisherRecord {
            id: PublisherId::new("kalareach").expect("a literal publisher"),
            display_name: Label::new("KalaReach").expect("a literal label"),
            homepage: "https://reach.kala.to".to_owned(),
            first_party: true,
        }],
        entries,
    }
}

/// Returns an index where two packages recognise one executable exactly.
#[must_use]
pub fn conflicting_index() -> CatalogueIndex {
    let mut index = synthetic_index(2);
    for entry in &mut index.entries {
        entry.match_rules[0].executable.file_stem = "agent".to_owned();
    }
    index
}

/// Returns how many entries an offline search finds.
#[must_use]
pub fn search_len(index: &CatalogueIndex, query: &str) -> usize {
    kr_plugin_catalogue::search::search(index, query, usize::MAX).len()
}

/// Returns the directory URL the client reads a local repository through.
#[must_use]
pub fn directory_url(path: &Path) -> url::Url {
    let absolute = std::fs::canonicalize(path).expect("an existing directory");
    url::Url::from_directory_path(absolute).expect("an absolute path")
}

/// Copies one directory tree to another.
pub fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a destination");
    for path in read_tree(from) {
        let relative = path.strip_prefix(from).expect("inside the tree");
        let destination = to.join(relative);
        std::fs::create_dir_all(destination.parent().expect("a parent")).expect("writable");
        std::fs::copy(&path, &destination).expect("copyable");
    }
}

fn read_tree(directory: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![directory.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}
