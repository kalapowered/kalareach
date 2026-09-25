//! A plugin catalogue, enrolled the way the product enrols one.
//!
//! Adopting a repository's trust root is the owner's decision, so the device asks the host for a
//! challenge about that exact enrolment, answers it in its own ceremony, and sends the proof with
//! `catalogue.add` over its paired connection. The host then synchronises the generation and
//! installs from it, which is what `kr plugin repo sync` and `kr plugin install` ask of it.
//!
//! The trust root is never fetched from the place it is meant to verify. It is the development
//! root this repository commits, taken only when its digest is the one `bundled-plugins.lock`
//! pins, which is the root the bundled copy was verified against.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use kr_controller::sharing::CatalogueTrustPlan;
use kr_plugin_catalogue::{CapabilityCeiling, Enrolment, RepositoryId, RepositoryKind};
use kr_protocol::catalogue as wire;
use kr_protocol::method::Method;
use kr_protocol::pairing::SensitiveAction;
use kr_protocol::scalars::CanonicalSet;

use crate::device::Remote;

/// The package the lock bundles and the legs install.
pub const PLUGIN: &str = "kalareach/example-declarative";

/// The workspace this crate was built from.
#[must_use]
pub fn workspace() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    std::fs::canonicalize(&root).unwrap_or(root)
}

/// What `bundled-plugins.lock` pins about the bundled package and the root it was verified
/// against.
#[derive(Clone, Debug)]
pub struct BundledLock {
    /// The release the bundle carries.
    pub version: String,
    /// The manifest digest, which is the package's hash.
    pub manifest_digest: String,
    /// The digest of the trust root the bundle was verified against.
    pub root_digest: String,
}

impl BundledLock {
    /// Reads the lock this repository commits.
    ///
    /// # Panics
    ///
    /// Panics when the lock is missing, unreadable or does not bundle [`PLUGIN`].
    #[must_use]
    pub fn read() -> Self {
        let path = workspace().join("bundled-plugins.lock");
        let lock: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display())),
        )
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let package = lock["packages"]
            .as_array()
            .and_then(|packages| {
                packages
                    .iter()
                    .find(|package| package["plugin_id"] == PLUGIN)
            })
            .unwrap_or_else(|| panic!("the bundled lock carries {PLUGIN}"));
        let text = |value: &serde_json::Value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("the bundled lock names {value}"))
                .to_owned()
        };
        Self {
            version: text(&package["version"]),
            manifest_digest: text(&package["manifest"]["digest"]),
            root_digest: text(&lock["trust_root"]["digest"]),
        }
    }
}

/// The committed development generation, a copy of what the plugin repository published.
#[must_use]
pub fn development_generation() -> PathBuf {
    workspace().join("fixtures/plugins/catalogue/development")
}

/// The development trust root, taken only when its digest is the one the lock pins.
///
/// # Panics
///
/// Panics when the committed root is not the root the lock pins.
#[must_use]
pub fn pinned_root(lock: &BundledLock) -> Vec<u8> {
    let path = development_generation().join("root.json");
    let root = std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let digest = kr_plugin_sdk::digest::PayloadDigest::of(&root).to_string();
    assert_eq!(
        digest, lock.root_digest,
        "the committed development root is the root the bundled lock pins"
    );
    root
}

/// Enrols a repository on the host through `remote`, with the owner device's confirmation of that
/// exact enrolment: this identifier, this root, its key identifiers, and no ceiling beyond the
/// default.
///
/// # Errors
///
/// Returns the host's refusal of the challenge or of the enrolment.
pub async fn enrol(
    remote: &Remote,
    catalogue_id: &str,
    kind: wire::CatalogueKind,
    metadata_url: &str,
    targets_url: &str,
    root: &[u8],
) -> Result<wire::CatalogueAddResult, String> {
    let repository_kind = match kind {
        wire::CatalogueKind::Official => RepositoryKind::Official,
        wire::CatalogueKind::Vendor => RepositoryKind::Vendor,
        wire::CatalogueKind::Community => RepositoryKind::Community,
        wire::CatalogueKind::Local => RepositoryKind::Local,
        wire::CatalogueKind::Mirror => RepositoryKind::Mirror,
    };
    let root_key_ids = Enrolment::new(
        RepositoryId::new(catalogue_id).map_err(|error| error.to_string())?,
        repository_kind,
        url::Url::parse(metadata_url).map_err(|error| error.to_string())?,
        url::Url::parse(targets_url).map_err(|error| error.to_string())?,
        root.to_vec(),
        kr_plugin_sdk::limits::RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .map_err(|error| format!("the enrolment: {error}"))?
    .root_key_ids()
    .map_err(|error| format!("the root's key identifiers: {error}"))?
    .into_iter()
    .collect();
    let digest = CatalogueTrustPlan {
        environment_id: remote.environment_id(),
        catalogue_id: catalogue_id.to_owned(),
        root_digest: kr_plugin_sdk::digest::PayloadDigest::of(root).to_string(),
        root_key_ids,
        ceiling: CanonicalSet::new(),
    }
    .action_digest()
    .map_err(|error| format!("the enrolment's digest: {error}"))?;
    let proof = remote
        .confirm_described(SensitiveAction::TrustRepositoryRoot, digest)
        .await?;
    let defaults = kr_plugin_sdk::limits::RepositoryBudgets::defaults();
    remote
        .mutate_environment(
            Method::CatalogueAdd,
            &wire::CatalogueAddParams {
                environment_id: remote.environment_id(),
                catalogue_id: catalogue_id.to_owned(),
                kind,
                metadata_url: metadata_url.to_owned(),
                targets_url: targets_url.to_owned(),
                root: base64::engine::general_purpose::STANDARD.encode(root),
                budgets: wire::CatalogueBudgets {
                    metadata_bytes: defaults.metadata_bytes,
                    metadata_entries: defaults.metadata_entries,
                    retained_generations: defaults.retained_generations,
                    retained_metadata_bytes: defaults.retained_metadata_bytes,
                    payload_cache_bytes: defaults.payload_cache_bytes,
                    full_offline_mirror: false,
                },
                ceiling: Vec::new(),
                owner_confirmation: proof,
            },
        )
        .await
        .map_err(|error| format!("catalogue.add: {error}"))
}

/// Copies a directory tree, for a generation served from the internal disk.
///
/// # Panics
///
/// Panics when anything cannot be read or written.
pub fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a destination");
    let mut stack = vec![from.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path).expect("readable").flatten() {
            let source = entry.path();
            if source.is_dir() {
                stack.push(source);
                continue;
            }
            let relative = source.strip_prefix(from).expect("inside the tree");
            let destination = to.join(relative);
            std::fs::create_dir_all(destination.parent().expect("a parent")).expect("writable");
            std::fs::copy(&source, &destination).expect("copyable");
        }
    }
}

/// The `file:` address of a directory, as a local repository names its metadata and targets.
///
/// # Panics
///
/// Panics when the directory does not exist.
#[must_use]
pub fn directory_url(path: &Path) -> String {
    let absolute = std::fs::canonicalize(path).expect("an existing directory");
    url::Url::from_directory_path(absolute)
        .expect("an absolute path")
        .to_string()
}
