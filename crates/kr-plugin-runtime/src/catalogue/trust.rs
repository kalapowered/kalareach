//! Verifying a catalogue generation with The Update Framework.
//!
//! Section 11 asks for root, timestamp, snapshot and targets metadata through an exact qualified
//! maintained Rust client. That client is [`tough`], pinned to the same release the publishing
//! pipeline signs with, so the end that writes a generation and the end that reads one run the
//! same code and cannot drift into two readings of the same metadata.
//!
//! What this module adds on top of the client is what the client cannot know:
//!
//! * **Publisher and path scope.** TUF lets a delegated role claim any path pattern. A vendor
//!   delegation in a KalaReach catalogue may sign that vendor's packages and nothing else, so
//!   every delegation is checked against `packages/<publisher>/` before the generation is used.
//!   A role that claims the index, another publisher's prefix or a bare wildcard is refused.
//! * **Bounded depth.** A delegation tree can be arbitrarily deep, and each level is more
//!   metadata to verify and more places a target can come from. The depth is bounded, and the
//!   bound is stated rather than discovered when a sync stops answering.
//! * **Rollback across generations.** The client refuses metadata older than what it already
//!   trusts. The catalogue index carries a generation of its own, and a snapshot that renumbered
//!   its metadata would otherwise replay an old index under a new version, so the index's
//!   generation is compared with the one already accepted as well.
//! * **Expiry as section 11 means it.** Expired metadata blocks a new generation. It does not
//!   reach into what is installed: a pinned package stays usable offline under the grants it
//!   already has, which is why the refusal is raised here and never turned into an uninstall.
//!
//! Terminating-role semantics and the delegation traversal itself are the client's, and the suite
//! qualifies the selected release's actual behaviour rather than trusting a crate overview.

use std::collections::BTreeMap;
use std::path::Path;

use kr_plugin_sdk::catalogue::CatalogueIndex;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_protocol::ids::RepositoryGeneration;
use tough::schema::{PathSet, Targets};
use tough::{ExpirationEnforcement, IntoVec as _, Repository, RepositoryLoader, TargetName};

use crate::catalogue::budget::{BudgetLedger, Stage};
use crate::catalogue::error::{CatalogueError, CatalogueResult};
use crate::catalogue::repository::Enrolment;

/// The target name of the catalogue index.
pub const INDEX_TARGET: &str = "index.json";

/// The target-name prefix every package payload sits under.
pub const PACKAGE_PREFIX: &str = "packages/";

/// Every character the path matcher gives a meaning other than itself.
///
/// A delegation's publisher segment is compared as a name, so any of these in it means the segment
/// is a pattern and the role claims more than one publisher.
const GLOB_METACHARACTERS: &str = "*?[]{}!\\,";

/// How deep a delegation chain may go beneath the top-level targets role.
///
/// Three levels is a vendor, a product line inside that vendor and a release channel inside that
/// product line. Anything deeper is an organisation modelling itself in a trust graph, and each
/// level costs a host another signed document to fetch and verify on every sync.
pub const MAX_DELEGATION_DEPTH: usize = 3;

/// The versions of the roles one load trusted.
///
/// The client keeps its own trusted metadata in a datastore and refuses a version lower than the
/// one it holds. That protection is only as durable as the datastore: a document it cannot parse
/// after an interrupted write is a document it skips rather than one it refuses on. These are the
/// same numbers held beside the activated generation, so rollback protection survives a datastore
/// this host can no longer read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MetadataVersions {
    /// The root metadata version.
    pub root: u64,
    /// The timestamp metadata version.
    pub timestamp: u64,
    /// The snapshot metadata version.
    pub snapshot: u64,
    /// The targets metadata version.
    pub targets: u64,
}

impl MetadataVersions {
    /// Returns the role whose version went backwards, where one did.
    #[must_use]
    pub fn rollback_from(&self, accepted: Self) -> Option<&'static str> {
        for (role, mine, theirs) in [
            ("root", self.root, accepted.root),
            ("timestamp", self.timestamp, accepted.timestamp),
            ("snapshot", self.snapshot, accepted.snapshot),
            ("targets", self.targets, accepted.targets),
        ] {
            if mine < theirs {
                return Some(role);
            }
        }
        None
    }
}

/// One delegated role, as this host understands its scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationScope {
    /// The role's name.
    pub role: String,
    /// The publisher whose packages it may sign.
    pub publisher: String,
    /// How deep beneath the top-level targets role it sits.
    pub depth: usize,
    /// Whether the role ends the search for a target it does not carry.
    pub terminating: bool,
}

/// One target the generation's metadata pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetRecord {
    /// The digest the metadata pins.
    pub digest: PayloadDigest,
    /// The exact length the metadata pins.
    pub length: u64,
}

/// One target of an accepted generation, kept with that generation.
///
/// The client resolved it through the generation's signed metadata when the generation was
/// accepted. Kept with the generation, it is what lets the exact bytes it names be fetched from
/// where they were accepted after the repository publishes something newer, without reading the
/// newer metadata and without letting the newer metadata stand in for the accepted one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedTarget {
    /// The target name.
    pub name: String,
    /// What the generation's metadata pinned it at.
    pub record: TargetRecord,
    /// Where its bytes are fetched from, by the client's own location rule.
    pub location: url::Url,
}

/// A generation whose metadata verified.
#[derive(Debug)]
pub struct VerifiedGeneration {
    /// The generation number the index carries.
    pub generation: RepositoryGeneration,
    /// The index itself.
    pub index: CatalogueIndex,
    /// The exact bytes the index was read from, for the metadata budget.
    pub index_bytes: u64,
    /// Every target the metadata pins, by target name.
    pub targets: BTreeMap<String, TargetRecord>,
    /// The delegations beneath the top-level targets role.
    pub delegations: Vec<DelegationScope>,
    /// The versions of the roles this load trusted.
    pub versions: MetadataVersions,
    /// The trusted root this load ended on, which is what the next load starts from.
    ///
    /// A root rotation is signed by the root it replaces, so the root a host should carry forward
    /// is the one verification arrived at rather than the one it started with. Starting from the
    /// original root again would let a repository restore old trust by withholding the newer root.
    pub root: Vec<u8>,
    /// The loaded client, for reading payloads out of this same generation.
    repository: Repository,
}

impl VerifiedGeneration {
    /// Returns every target this generation pins, each with the location it is fetched from.
    ///
    /// The location follows the client's own rule for this repository's root: the targets location
    /// with a trailing slash, joined with the target's name, which is prefixed by its SHA-256 where
    /// the root publishes consistent snapshots. A name that would leave the targets location is
    /// refused, as the client refuses it.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::Untrusted`] for a name the client would not fetch.
    pub fn accepted_targets(&self, targets_url: &url::Url) -> CatalogueResult<Vec<AcceptedTarget>> {
        let base = if targets_url.as_str().ends_with('/') {
            targets_url.clone()
        } else {
            url::Url::parse(&format!("{targets_url}/")).map_err(|source| {
                CatalogueError::Untrusted {
                    detail: format!("{targets_url} is not a targets location: {source}"),
                }
            })?
        };
        let consistent = self.repository.root().signed.consistent_snapshot;
        self.targets
            .iter()
            .map(|(name, record)| {
                let target =
                    TargetName::new(name.as_str()).map_err(|source| CatalogueError::Untrusted {
                        detail: format!("{name} is not a target name the client fetches: {source}"),
                    })?;
                let file = if consistent {
                    let digest: String = record
                        .digest
                        .as_bytes()
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect();
                    format!("{digest}.{}", target.resolved())
                } else {
                    target.resolved().to_owned()
                };
                let location = base
                    .join(&file)
                    .ok()
                    .filter(|location| location.as_str().starts_with(base.as_str()))
                    .ok_or_else(|| CatalogueError::Untrusted {
                        detail: format!("{name} does not name a file inside {base}"),
                    })?;
                Ok(AcceptedTarget {
                    name: name.clone(),
                    record: *record,
                    location,
                })
            })
            .collect()
    }

    /// Returns the record the metadata pins for one target name.
    #[must_use]
    pub fn target(&self, name: &str) -> Option<TargetRecord> {
        self.targets.get(name).copied()
    }

    /// Reads one target through the client, checking it against what the index declares.
    ///
    /// The client checks the digest and the length the metadata pins as the bytes stream. This
    /// checks the same bytes against the index as well, because the metadata says "these are the
    /// bytes under this name" and the index says "this package consists of these bytes"; only
    /// both together make a target name mean one package's file.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::ResourceLimit`] when the pinned length is past the budget,
    /// [`CatalogueError::NotFound`] when the metadata does not pin the name, and
    /// [`CatalogueError::Integrity`] when the bytes are not the ones the index declares.
    pub async fn read_target(
        &self,
        name: &str,
        declared: TargetRecord,
        ledger: &BudgetLedger,
    ) -> CatalogueResult<Vec<u8>> {
        let pinned = self.target(name).ok_or_else(|| CatalogueError::NotFound {
            detail: format!("the generation's metadata does not pin {name}"),
        })?;
        // The declared size decides whether the fetch starts. A payload the index declares as one
        // size and the metadata pins as another is already a disagreement, and reading it to find
        // out which is right is reading bytes this host said it would not hold.
        if pinned.length != declared.length || pinned.digest != declared.digest {
            return Err(CatalogueError::Integrity {
                detail: format!(
                    "{name} is pinned at {} bytes and declared at {} bytes",
                    pinned.length, declared.length
                ),
            });
        }
        ledger.check_payload_bytes(pinned.length, Stage::Declared, name)?;

        let target = TargetName::new(name).map_err(|source| CatalogueError::InvalidArgument {
            detail: format!("{name} is not a target name: {source}"),
        })?;
        // A target the metadata pins and the repository cannot supply is an absence, not a failure
        // of trust: the signature over the name is fine and the bytes are not there. That is the
        // `None` below. An error is something else, and it keeps the class it had: a datastore
        // this host cannot read is a storage failure, a hash that does not match is an integrity
        // failure, and reporting either as "offline" would tell somebody to check their network
        // about a disk or about a repository that answered and lied.
        let stream = self
            .repository
            .read_target(&target)
            .await
            .map_err(|source| classify(&source))?
            .ok_or_else(|| CatalogueError::UnavailableOffline {
                detail: format!("the repository does not carry {name}"),
            })?;
        // The stream is bounded by the length the signed metadata pins and its digest is checked
        // as it arrives. What went wrong on the way is read out of the error's own cause: a link
        // that dropped is an availability failure, and more bytes than the signed length or a
        // digest that does not match is an integrity failure about this repository's bytes.
        let bytes = stream
            .into_vec()
            .await
            .map_err(|source| classify(&source))?;
        let actual = bytes.len() as u64;
        if actual != declared.length || PayloadDigest::of(&bytes) != declared.digest {
            return Err(CatalogueError::Integrity {
                detail: format!(
                    "{name} arrived as {actual} bytes and is not the payload the index declares"
                ),
            });
        }
        ledger.check_payload_bytes(actual, Stage::Actual, name)?;
        Ok(bytes)
    }
}

/// Fetches one target of an accepted generation from where it was accepted, reading no metadata.
///
/// The generation's signed metadata was verified when it was accepted, and this target's digest
/// and length are what it pinned then. The bytes are bounded by that length as they arrive and have
/// to hash to that digest, so what this returns is exactly what the accepted generation named,
/// whatever the repository has published since.
///
/// # Errors
///
/// Returns [`CatalogueError::ResourceLimit`] when the pinned length is past the payload budget,
/// [`CatalogueError::UnavailableOffline`] when the bytes cannot be fetched, and
/// [`CatalogueError::Integrity`] when what arrived is not what the generation pinned.
pub async fn fetch_accepted(
    transport: &std::sync::Arc<dyn tough::Transport + Send + Sync>,
    target: &AcceptedTarget,
    ledger: &BudgetLedger,
) -> CatalogueResult<Vec<u8>> {
    use futures::StreamExt as _;

    let name = target.name.as_str();
    let length = target.record.length;
    ledger.check_payload_bytes(length, Stage::Declared, name)?;
    let unavailable = |error: &tough::TransportError| CatalogueError::UnavailableOffline {
        detail: match error.kind() {
            tough::TransportErrorKind::FileNotFound => {
                format!("the repository no longer carries {name}")
            }
            _ => format!("{name} could not be fetched: {error}"),
        },
    };
    let mut stream = transport
        .fetch(target.location.clone())
        .await
        .map_err(|error| unavailable(&error))?;
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| unavailable(&error))?;
        if (bytes.len() as u64).saturating_add(chunk.len() as u64) > length {
            return Err(CatalogueError::Integrity {
                detail: format!("{name} is longer than the {length} bytes its generation pinned"),
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    let actual = bytes.len() as u64;
    if actual != length || PayloadDigest::of(&bytes) != target.record.digest {
        return Err(CatalogueError::Integrity {
            detail: format!(
                "{name} arrived as {actual} bytes and is not the payload its generation pinned"
            ),
        });
    }
    ledger.check_payload_bytes(actual, Stage::Actual, name)?;
    Ok(bytes)
}

/// Verifies one generation of a repository.
///
/// `datastore` is a directory the client keeps its trusted metadata in. It belongs to this
/// repository and to no other: the roots are separate, so the state derived from them is too.
///
/// # Errors
///
/// Returns [`CatalogueError::Untrusted`] when the metadata does not verify against the enrolled
/// root or a delegation is outside its publisher's scope,
/// [`CatalogueError::MetadataExpired`] when a role's metadata has expired,
/// [`CatalogueError::ResourceLimit`] when the index is larger than the metadata budget, and
/// [`CatalogueError::Integrity`] when the index is not the document the metadata pins.
pub async fn verify(
    enrolment: &Enrolment,
    datastore: &Path,
    ledger: &BudgetLedger,
    transport: &std::sync::Arc<dyn tough::Transport + Send + Sync>,
    on_root_rotated: &mut (dyn FnMut(Vec<u8>) -> CatalogueResult<()> + Send),
) -> CatalogueResult<VerifiedGeneration> {
    std::fs::create_dir_all(datastore)
        .map_err(|source| CatalogueError::storage(datastore, &source))?;
    // The client's own per-document ceilings are ignored wherever the snapshot declares a length,
    // so the budget is enforced on the bytes instead: every metadata fetch this load makes is
    // counted against the repository's approved metadata budget, whatever the metadata says about
    // its own size.
    let budgeted = BudgetedTransport::new(
        std::sync::Arc::clone(transport),
        &enrolment.metadata_url,
        enrolment.budgets.metadata_bytes.get(),
    );
    let loader = RepositoryLoader::new(
        &enrolment.root,
        enrolment.metadata_url.clone(),
        enrolment.targets_url.clone(),
    )
    .datastore(datastore.to_path_buf())
    .expiration_enforcement(ExpirationEnforcement::Safe)
    .transport(budgeted.clone())
    .limits(tough::Limits {
        max_root_size: enrolment.budgets.metadata_bytes.get(),
        max_targets_size: enrolment.budgets.metadata_bytes.get(),
        max_timestamp_size: enrolment.budgets.metadata_bytes.get(),
        max_snapshot_size: enrolment.budgets.metadata_bytes.get(),
        ..tough::Limits::default()
    });
    let repository = match loader.load().await {
        Ok(repository) => repository,
        // A load the budget stopped is a budget refusal, not a repository this host cannot reach.
        // The transport carries the refusal as its error's cause, and the classification reads it
        // from there.
        Err(source) => {
            let datastore_root = datastore.join("root.json");
            if let Ok(bytes) = std::fs::read(&datastore_root)
                && !bytes.is_empty()
                && bytes != enrolment.root
                && let Ok(new_signed) =
                    serde_json::from_slice::<tough::schema::Signed<tough::schema::Root>>(&bytes)
                && let Ok(old_signed) = serde_json::from_slice::<
                    tough::schema::Signed<tough::schema::Root>,
                >(&enrolment.root)
                && new_signed.signed.version > old_signed.signed.version
            {
                on_root_rotated(bytes)?;
            }
            return Err(classify(&source));
        }
    };
    let versions = MetadataVersions {
        root: repository.root().signed.version.get(),
        timestamp: repository.timestamp().signed.version.get(),
        snapshot: repository.snapshot().signed.version.get(),
        targets: repository.targets().signed.version.get(),
    };
    // A rotation is a root of a higher version, reached through a chain the client verified. The
    // bytes are not compared: the client's root holds its keys and roles in unordered maps, so the
    // same root can serialise differently from one load to the next, and keeping it again would be
    // a change that never happened.
    let accepted =
        serde_json::from_slice::<tough::schema::Signed<tough::schema::Root>>(&enrolment.root)
            .map_err(|source| CatalogueError::Untrusted {
                detail: format!("the enrolled root could not be read: {source}"),
            })?;
    let root =
        serde_json::to_vec(repository.root()).map_err(|source| CatalogueError::Untrusted {
            detail: format!("the trusted root could not be recorded: {source}"),
        })?;
    if repository.root().signed.version > accepted.signed.version {
        on_root_rotated(root.clone())?;
    }

    let delegations = scope_delegations(&repository.targets().signed)?;

    let index_record =
        resolve_target(&repository, INDEX_TARGET)?.ok_or_else(|| CatalogueError::Untrusted {
            detail: format!("the generation's metadata does not pin {INDEX_TARGET}"),
        })?;
    let mut targets = BTreeMap::new();
    targets.insert(INDEX_TARGET.to_owned(), index_record);

    // The index is held whole, because it is parsed and searched offline. Its signed length is
    // checked against the metadata budget before it is read, so what is held is what this host
    // said it was willing to hold.
    ledger.check_metadata_bytes(index_record.length, Stage::Declared, INDEX_TARGET)?;
    let index_name =
        TargetName::new(INDEX_TARGET).map_err(|source| CatalogueError::InvalidArgument {
            detail: format!("{INDEX_TARGET} is not a target name: {source}"),
        })?;
    let bytes = repository
        .read_target(&index_name)
        .await
        .map_err(|source| classify(&source))?
        .ok_or_else(|| CatalogueError::UnavailableOffline {
            detail: format!("the generation does not carry {INDEX_TARGET}"),
        })?
        .into_vec()
        .await
        .map_err(|source| classify(&source))?;
    let index_bytes = bytes.len() as u64;
    ledger.check_metadata_bytes(index_bytes, Stage::Actual, INDEX_TARGET)?;
    let index: CatalogueIndex =
        serde_json::from_slice(&bytes).map_err(|source| CatalogueError::Integrity {
            detail: format!("{INDEX_TARGET} is not a catalogue index: {source}"),
        })?;
    ledger.check_metadata_entries(index.entries.len() as u64, Stage::Actual, INDEX_TARGET)?;
    if index.index_version != kr_plugin_sdk::catalogue::INDEX_VERSION {
        return Err(CatalogueError::Untrusted {
            detail: format!(
                "the index is format version {} and this build reads version {}",
                index.index_version,
                kr_plugin_sdk::catalogue::INDEX_VERSION
            ),
        });
    }
    if index.generation.get() == 0 {
        return Err(CatalogueError::Untrusted {
            detail: "a catalogue generation starts at one".to_owned(),
        });
    }
    // What each entry declares is checked before the index and the metadata are compared. A
    // package whose declared layout is unsafe is refused for that, rather than for whichever of
    // its consequences the comparison happens to notice first.
    for entry in &index.entries {
        crate::catalogue::extract::check_declared(entry, ledger)?;
    }
    for name in declared_target_names(&index) {
        let record =
            resolve_target(&repository, &name)?.ok_or_else(|| CatalogueError::Untrusted {
                detail: format!("target {name} could not be resolved through delegation"),
            })?;
        targets.insert(name, record);
    }
    check_index_against_targets(&index, &targets)?;

    let total_spent = budgeted.spent.load(std::sync::atomic::Ordering::Relaxed);
    ledger.check_metadata_bytes(total_spent, Stage::Actual, "metadata")?;

    Ok(VerifiedGeneration {
        generation: index.generation,
        index,
        index_bytes,
        targets,
        delegations,
        versions,
        root,
        repository,
    })
}

/// Refuses a generation older than the one already accepted, and one the owner did not pin.
///
/// # Errors
///
/// Returns [`CatalogueError::Untrusted`] for a replayed generation, and
/// [`CatalogueError::InvalidArgument`] when a pin names another generation.
pub fn check_generation(
    candidate: RepositoryGeneration,
    candidate_digest: PayloadDigest,
    accepted: Option<(RepositoryGeneration, PayloadDigest)>,
    pinned: Option<RepositoryGeneration>,
) -> CatalogueResult<()> {
    if let Some((accepted, accepted_digest)) = accepted {
        if candidate.get() < accepted.get() {
            return Err(CatalogueError::Untrusted {
                detail: format!(
                    "generation {} is older than the accepted generation {}; a generation \
                     replayed after a later one is a rollback",
                    candidate.get(),
                    accepted.get()
                ),
            });
        }
        // A generation number names one immutable index. Accepting different bytes under a number
        // this host has already accepted would let a repository change what a pin means.
        if candidate.get() == accepted.get() && candidate_digest != accepted_digest {
            return Err(CatalogueError::Untrusted {
                detail: format!(
                    "generation {} is already accepted as {accepted_digest} and this one is \
                     {candidate_digest}; a generation is written once",
                    candidate.get()
                ),
            });
        }
    }
    if let Some(pinned) = pinned
        && candidate.get() != pinned.get()
    {
        return Err(CatalogueError::InvalidArgument {
            detail: format!(
                "this repository is pinned to generation {}, so generation {} is not activated; \
                 the pinned generation stays usable",
                pinned.get(),
                candidate.get()
            ),
        });
    }
    Ok(())
}

/// Returns every target name the index declares, in a stable order.
fn declared_target_names(index: &CatalogueIndex) -> Vec<String> {
    let mut names = Vec::new();
    for entry in &index.entries {
        let prefix = format!(
            "{PACKAGE_PREFIX}{}/{}/{}",
            entry.publisher_id, entry.plugin_name, entry.version
        );
        names.push(format!(
            "{prefix}/{}",
            kr_plugin_sdk::package::MANIFEST_FILE
        ));
        for payload in &entry.payloads {
            names.push(format!("{prefix}/{}", payload.path.as_str()));
        }
    }
    names.sort();
    names.dedup();
    names
}

/// Resolves one target name through the client's own delegation search.
fn resolve_target(repository: &Repository, name: &str) -> CatalogueResult<Option<TargetRecord>> {
    let target_name = TargetName::new(name).map_err(|source| CatalogueError::Untrusted {
        detail: format!("{name} is not a target name the client will resolve: {source}"),
    })?;
    let Ok(target) = repository.targets().signed.find_target(&target_name, false) else {
        return Ok(None);
    };
    let digest: [u8; 32] =
        target
            .hashes
            .sha256
            .as_ref()
            .try_into()
            .map_err(|_| CatalogueError::Untrusted {
                detail: format!("{name} is pinned without a SHA-256 digest"),
            })?;
    Ok(Some(TargetRecord {
        digest: PayloadDigest::from_bytes(digest),
        length: target.length,
    }))
}

/// Checks every delegation's publisher and path scope, and the tree's depth.
fn scope_delegations(targets: &Targets) -> CatalogueResult<Vec<DelegationScope>> {
    let mut scopes = Vec::new();
    walk_delegations(targets, 1, &mut scopes)?;
    Ok(scopes)
}

fn walk_delegations(
    targets: &Targets,
    depth: usize,
    scopes: &mut Vec<DelegationScope>,
) -> CatalogueResult<()> {
    let Some(delegations) = targets.delegations.as_ref() else {
        return Ok(());
    };
    if delegations.roles.is_empty() {
        // A role that delegates to nobody adds no level. Counting it would refuse a chain of the
        // permitted depth whose last role simply carries an empty delegations object.
        return Ok(());
    }
    if depth > MAX_DELEGATION_DEPTH {
        return Err(CatalogueError::Untrusted {
            detail: format!(
                "the delegation chain is deeper than {MAX_DELEGATION_DEPTH} roles; each level is \
                 another signed document every sync must fetch and verify"
            ),
        });
    }
    for role in &delegations.roles {
        let publisher = delegated_publisher(&role.name, &role.paths)?;
        scopes.push(DelegationScope {
            role: role.name.clone(),
            publisher,
            depth,
            terminating: role.terminating,
        });
        if let Some(signed) = role.targets.as_ref() {
            walk_delegations(&signed.signed, depth + 1, scopes)?;
        }
    }
    Ok(())
}

/// Returns the one publisher a delegated role may sign for.
///
/// A KalaReach catalogue names every package target `packages/<publisher>/<name>/<version>/<file>`,
/// so a vendor delegation is expressible as that vendor's prefix and nothing else. A role that
/// claims two publishers, a bare wildcard, the index or a hash-prefix bin is refused: the first
/// three are wider than a vendor delegation ever needs to be, and the last cannot be checked
/// against a publisher at all.
fn delegated_publisher(role: &str, paths: &PathSet) -> CatalogueResult<String> {
    let patterns = match paths {
        PathSet::Paths(patterns) => patterns,
        PathSet::PathHashPrefixes(_) => {
            return Err(CatalogueError::Untrusted {
                detail: format!(
                    "the delegation {role} is scoped by path hash prefix, which names no \
                     publisher; a vendor delegation is scoped to {PACKAGE_PREFIX}<publisher>/"
                ),
            });
        }
    };
    if patterns.is_empty() {
        return Err(CatalogueError::Untrusted {
            detail: format!("the delegation {role} claims no paths"),
        });
    }
    let mut publisher: Option<String> = None;
    for pattern in patterns {
        let value = pattern.value();
        let Some(rest) = value.strip_prefix(PACKAGE_PREFIX) else {
            return Err(CatalogueError::Untrusted {
                detail: format!(
                    "the delegation {role} claims {value}, which is outside \
                     {PACKAGE_PREFIX}<publisher>/"
                ),
            });
        };
        let Some((name, _)) = rest.split_once('/') else {
            return Err(CatalogueError::Untrusted {
                detail: format!(
                    "the delegation {role} claims {value}, which is a publisher and not that \
                     publisher's packages"
                ),
            });
        };
        // The publisher segment is read as a literal name, not as a pattern that happens to look
        // like one. The matcher understands wildcards, character classes, brace alternatives and
        // escapes, so `packages/{acme,other}/*` is two publishers written as one segment, and a
        // segment that is not a publisher identifier this build would accept is refused outright.
        if name.is_empty() || name.contains(|c| GLOB_METACHARACTERS.contains(c)) {
            return Err(CatalogueError::Untrusted {
                detail: format!(
                    "the delegation {role} claims {value}, whose publisher segment is a pattern \
                     rather than a name; a vendor delegation names one publisher"
                ),
            });
        }
        if kr_plugin_sdk::ids::PublisherId::new(name).is_err() {
            return Err(CatalogueError::Untrusted {
                detail: format!(
                    "the delegation {role} claims {value}, whose publisher segment is not a \
                     publisher identifier"
                ),
            });
        }
        match &publisher {
            None => publisher = Some(name.to_owned()),
            Some(first) if first == name => {}
            Some(first) => {
                return Err(CatalogueError::Untrusted {
                    detail: format!(
                        "the delegation {role} claims both {first} and {name}; a vendor \
                         delegation is scoped to one publisher"
                    ),
                });
            }
        }
    }
    publisher.ok_or_else(|| CatalogueError::Untrusted {
        detail: format!("the delegation {role} claims no publisher"),
    })
}

/// Checks that the metadata and the index describe the same generation.
fn check_index_against_targets(
    index: &CatalogueIndex,
    targets: &BTreeMap<String, TargetRecord>,
) -> CatalogueResult<()> {
    for entry in &index.entries {
        let prefix = format!(
            "{PACKAGE_PREFIX}{}/{}/{}",
            entry.publisher_id, entry.plugin_name, entry.version
        );
        let manifest = format!("{prefix}/{}", kr_plugin_sdk::package::MANIFEST_FILE);
        let pinned = targets
            .get(&manifest)
            .ok_or_else(|| CatalogueError::Integrity {
                detail: format!("the index declares {manifest} and the metadata does not pin it"),
            })?;
        if pinned.digest != entry.manifest_digest
            || pinned.length != entry.manifest_size_bytes.get()
        {
            return Err(CatalogueError::Integrity {
                detail: format!("{manifest} is not the manifest the index declares"),
            });
        }
        for payload in &entry.payloads {
            let name = format!("{prefix}/{}", payload.path.as_str());
            let pinned = targets
                .get(&name)
                .ok_or_else(|| CatalogueError::Integrity {
                    detail: format!("the index declares {name} and the metadata does not pin it"),
                })?;
            if pinned.digest != payload.digest || pinned.length != payload.size_bytes.get() {
                return Err(CatalogueError::Integrity {
                    detail: format!("{name} is not the payload the index declares"),
                });
            }
        }
    }
    Ok(())
}

/// Turns a client failure into the refusal a person acts on, keeping its class.
///
/// Expiry is the one that has to be told apart from trust: section 11 says expired metadata blocks
/// a new generation while installed pinned packages stay usable, and a host that reported it as
/// "the root is not trusted" would send somebody to re-adopt a root that is fine.
///
/// The client reports what went wrong while a document streamed as a transport error with the real
/// failure as its cause, so the class is read from that cause rather than from where the error
/// surfaced. A link that dropped part way is an availability failure. More bytes than the signed
/// metadata allows, and bytes whose digest is not the signed one, are integrity failures about
/// what this repository sent. A document past this host's own budget is that budget.
pub(crate) fn classify(error: &tough::error::Error) -> CatalogueError {
    match error {
        tough::error::Error::ExpiredMetadata { role, .. } => CatalogueError::MetadataExpired {
            role: role.to_string(),
            expired_at: "the time the metadata states".to_owned(),
        },
        tough::error::Error::Transport { source, .. } => classify_transport(source),
        tough::error::Error::HashMismatch {
            context,
            calculated,
            expected,
            ..
        } => CatalogueError::Integrity {
            detail: format!(
                "hash mismatch for {context}: calculated {calculated}, expected {expected}"
            ),
        },
        tough::error::Error::MaxSizeExceeded {
            max_size,
            specifier,
            ..
        } => past_a_length(*max_size, specifier),
        tough::error::Error::DatastoreInit { .. }
        | tough::error::Error::DatastoreCreate { .. }
        | tough::error::Error::DatastoreOpen { .. }
        | tough::error::Error::DatastoreRemove { .. }
        | tough::error::Error::DatastoreSerialize { .. }
        | tough::error::Error::DirCreate { .. }
        | tough::error::Error::FileOpen { .. }
        | tough::error::Error::FileRead { .. }
        | tough::error::Error::FileWrite { .. }
        | tough::error::Error::CacheFileRead { .. }
        | tough::error::Error::CacheFileWrite { .. }
        | tough::error::Error::CacheDirectoryCreate { .. }
        | tough::error::Error::CacheTargetWrite { .. } => CatalogueError::StorageUnavailable {
            detail: error.to_string(),
        },
        // A bad signature, a rollback, a malformed document and a delegation out of scope are
        // refusals of trust. Reporting them as "offline" would tell somebody to check their
        // network about a repository that answered and lied.
        other => CatalogueError::Untrusted {
            detail: other.to_string(),
        },
    }
}

/// Classifies a transport failure by what caused it.
fn classify_transport(error: &tough::TransportError) -> CatalogueError {
    if let Some(cause) = std::error::Error::source(error) {
        // The client's own stream checks travel as the cause: the length and digest the signed
        // metadata pins.
        if let Some(inner) = cause.downcast_ref::<tough::error::Error>() {
            return classify(inner);
        }
        // This host's own metadata budget, which the budgeted transport stops a stream with.
        if let Some(exceeded) = cause.downcast_ref::<BudgetExceeded>() {
            return CatalogueError::ResourceLimit(exceeded.0.clone());
        }
    }
    match error.kind() {
        tough::TransportErrorKind::FileNotFound => CatalogueError::UnavailableOffline {
            detail: format!("the repository does not carry {}", error.url()),
        },
        // What is left is the link itself: a repository that could not be reached, or a
        // connection that dropped while a document was arriving.
        _ => CatalogueError::UnavailableOffline {
            detail: error.to_string(),
        },
    }
}

/// Classifies a document that ran past a length.
///
/// The client names where the length came from. A length this host set is its budget; a length
/// the signed metadata set is a statement by the repository, and more bytes than that is the
/// repository sending what it did not sign.
fn past_a_length(max_size: u64, specifier: &str) -> CatalogueError {
    if specifier.ends_with(" argument") || specifier.ends_with(" parameter") {
        return CatalogueError::ResourceLimit(crate::catalogue::budget::ResourceLimit {
            resource: crate::catalogue::budget::Resource::MetadataBytes,
            limit: max_size,
            requested: max_size.saturating_add(1),
            stage: Stage::Actual,
            subject: "one metadata document".to_owned(),
        });
    }
    CatalogueError::Integrity {
        detail: format!(
            "the repository sent more than the {max_size} bytes {specifier} pins for this document"
        ),
    }
}

/// The budget refusal the budgeted transport stops a stream with, carried as the error's cause.
#[derive(Debug)]
struct BudgetExceeded(crate::catalogue::budget::ResourceLimit);

impl core::fmt::Display for BudgetExceeded {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for BudgetExceeded {}

/// A transport that holds one load's metadata inside the repository's byte budget.
///
/// The client's own per-document ceilings apply only where the metadata does not declare a length.
/// Where it does, the declared length wins, so a snapshot inside the budget can name a targets
/// document of any size. Counting the bytes as they arrive is the only place that can be refused
/// before they are held.
#[derive(Clone, Debug)]
struct BudgetedTransport {
    inner: std::sync::Arc<dyn tough::Transport + Send + Sync>,
    metadata_base: String,
    budget: u64,
    spent: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl BudgetedTransport {
    fn new(
        inner: std::sync::Arc<dyn tough::Transport + Send + Sync>,
        metadata_base: &url::Url,
        budget: u64,
    ) -> Self {
        Self {
            inner,
            metadata_base: metadata_base.as_str().to_owned(),
            budget,
            spent: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Returns true when a fetch is metadata rather than a target.
    ///
    /// Metadata is everything under the repository's metadata location. A target comes from the
    /// targets location and is bounded by the length its own signed metadata pins.
    fn is_metadata(&self, url: &url::Url) -> bool {
        url.as_str().starts_with(&self.metadata_base)
    }
}

#[tough::async_trait]
impl tough::Transport for BudgetedTransport {
    async fn fetch(&self, url: url::Url) -> Result<tough::TransportStream, tough::TransportError> {
        use futures::StreamExt as _;

        let counted = self.is_metadata(&url);
        let stream = self.inner.fetch(url.clone()).await?;
        let budget = self.budget;
        let spent = std::sync::Arc::clone(&self.spent);
        let named = url;
        Ok(Box::pin(stream.map(move |chunk| {
            let chunk = chunk?;
            if counted {
                let total = spent
                    .fetch_add(chunk.len() as u64, std::sync::atomic::Ordering::Relaxed)
                    .saturating_add(chunk.len() as u64);
                if total > budget {
                    // The refusal is the error's cause, so whoever classifies the failure reads
                    // the resource it names rather than a transport failure.
                    return Err(tough::TransportError::new_with_cause(
                        tough::TransportErrorKind::Other,
                        named.clone(),
                        BudgetExceeded(crate::catalogue::budget::ResourceLimit {
                            resource: crate::catalogue::budget::Resource::MetadataBytes,
                            limit: budget,
                            requested: total,
                            stage: Stage::Actual,
                            subject: "this repository's metadata".to_owned(),
                        }),
                    ));
                }
            }
            Ok(chunk)
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tough::schema::PathPattern;

    fn paths(patterns: &[&str]) -> PathSet {
        PathSet::Paths(
            patterns
                .iter()
                .map(|pattern| PathPattern::new(*pattern).expect("a parsable pattern"))
                .collect(),
        )
    }

    #[test]
    fn a_delegation_is_scoped_to_one_publisher() {
        assert_eq!(
            delegated_publisher("vendor", &paths(&["packages/acme/*/*/*"])).expect("in scope"),
            "acme"
        );
        assert_eq!(
            delegated_publisher(
                "vendor",
                &paths(&["packages/acme/tool/*/*", "packages/acme/other/*/*"])
            )
            .expect("in scope"),
            "acme"
        );
    }

    #[test]
    fn a_delegation_outside_its_publisher_is_refused() {
        for pattern in [
            "*",
            "index.json",
            "packages/*",
            "packages/*/*/*/*",
            "../packages/acme/tool/1.0.0/plugin.json",
            "targets/packages/acme/tool/1.0.0/plugin.json",
        ] {
            let refusal =
                delegated_publisher("vendor", &paths(&[pattern])).expect_err("out of scope");
            assert!(
                matches!(refusal, CatalogueError::Untrusted { .. }),
                "{pattern}: {refusal}"
            );
        }
        let two = delegated_publisher(
            "vendor",
            &paths(&["packages/acme/tool/*/*", "packages/other/tool/*/*"]),
        )
        .expect_err("two publishers");
        assert!(two.to_string().contains("one publisher"), "{two}");
    }

    #[test]
    fn a_hash_prefix_delegation_names_no_publisher() {
        let refusal = delegated_publisher(
            "bin",
            &PathSet::PathHashPrefixes(vec![
                tough::schema::PathHashPrefix::new("ab").expect("a valid prefix"),
            ]),
        )
        .expect_err("no publisher");
        assert!(
            refusal.to_string().contains("names no publisher"),
            "{refusal}"
        );
    }

    #[test]
    fn a_replayed_generation_is_a_rollback() {
        let three = RepositoryGeneration::new(3);
        let two = RepositoryGeneration::new(2);
        let digest = PayloadDigest::of(b"index");
        assert!(check_generation(three, digest, Some((two, digest)), None).is_ok());
        assert!(check_generation(three, digest, Some((three, digest)), None).is_ok());
        let refusal =
            check_generation(two, digest, Some((three, digest)), None).expect_err("a rollback");
        assert!(refusal.to_string().contains("rollback"), "{refusal}");
    }

    #[test]
    fn one_generation_number_names_one_index() {
        let three = RepositoryGeneration::new(3);
        let accepted = PayloadDigest::of(b"the index this host accepted");
        let changed = PayloadDigest::of(b"different bytes under the same number");
        let refusal = check_generation(three, changed, Some((three, accepted)), None)
            .expect_err("a generation rewritten in place");
        assert!(refusal.to_string().contains("written once"), "{refusal}");
    }

    #[test]
    fn a_pin_holds_the_repository_on_its_generation() {
        let three = RepositoryGeneration::new(3);
        let four = RepositoryGeneration::new(4);
        let digest = PayloadDigest::of(b"index");
        assert!(check_generation(three, digest, Some((three, digest)), Some(three)).is_ok());
        let refusal =
            check_generation(four, digest, Some((three, digest)), Some(three)).expect_err("pinned");
        assert!(
            refusal
                .to_string()
                .contains("pinned generation stays usable"),
            "{refusal}"
        );
    }

    #[test]
    fn a_rollback_is_seen_in_any_role() {
        let accepted = MetadataVersions {
            root: 1,
            timestamp: 7,
            snapshot: 7,
            targets: 7,
        };
        assert!(accepted.rollback_from(accepted).is_none());
        for (role, older) in [
            (
                "root",
                MetadataVersions {
                    root: 0,
                    ..accepted
                },
            ),
            (
                "timestamp",
                MetadataVersions {
                    timestamp: 6,
                    ..accepted
                },
            ),
            (
                "snapshot",
                MetadataVersions {
                    snapshot: 6,
                    ..accepted
                },
            ),
            (
                "targets",
                MetadataVersions {
                    targets: 6,
                    ..accepted
                },
            ),
        ] {
            assert_eq!(older.rollback_from(accepted), Some(role));
        }
    }

    #[test]
    fn a_publisher_segment_that_is_a_pattern_is_refused() {
        // The matcher understands brace alternatives, so one segment can name two publishers.
        for pattern in [
            "packages/{acme,other}/*/*/*",
            "packages/acme,other/*/*/*",
            "packages/ac[me]/*/*/*",
            "packages/acme\\x2f/*/*/*",
        ] {
            let refusal = delegated_publisher("vendor", &paths(&[pattern])).expect_err("a pattern");
            assert!(
                matches!(refusal, CatalogueError::Untrusted { .. }),
                "{pattern}: {refusal}"
            );
        }
    }

    fn role(name: &str, pattern: &str, child: Option<Targets>) -> tough::schema::DelegatedRole {
        tough::schema::DelegatedRole {
            name: name.to_owned(),
            keyids: Vec::new(),
            threshold: std::num::NonZeroU64::new(1).expect("one is not zero"),
            paths: paths(&[pattern]),
            terminating: false,
            targets: child.map(|targets| tough::schema::Signed {
                signed: targets,
                signatures: Vec::new(),
            }),
        }
    }

    fn targets_with(delegations: Option<tough::schema::Delegations>) -> Targets {
        let mut targets = Targets::new(
            "1.0.0".to_owned(),
            std::num::NonZeroU64::new(1).expect("one is not zero"),
            "2036-01-01T00:00:00Z".parse().expect("a literal instant"),
        );
        targets.delegations = delegations;
        targets
    }

    fn chain(depth: usize) -> Targets {
        let mut current = targets_with(None);
        for level in (0..depth).rev() {
            current = targets_with(Some(tough::schema::Delegations {
                keys: std::collections::HashMap::new(),
                roles: vec![role(
                    &format!("level-{level}"),
                    "packages/acme/*/*/*",
                    Some(current),
                )],
            }));
        }
        current
    }

    #[test]
    fn a_delegation_chain_is_bounded() {
        let permitted = scope_delegations(&chain(MAX_DELEGATION_DEPTH)).expect("inside the bound");
        assert_eq!(permitted.len(), MAX_DELEGATION_DEPTH);
        assert_eq!(permitted[0].depth, 1);
        assert_eq!(
            permitted[MAX_DELEGATION_DEPTH - 1].depth,
            MAX_DELEGATION_DEPTH
        );

        let refusal =
            scope_delegations(&chain(MAX_DELEGATION_DEPTH + 1)).expect_err("past the bound");
        assert!(
            refusal.to_string().contains("deeper than 3 roles"),
            "{refusal}"
        );
    }

    #[test]
    fn a_role_that_delegates_to_nobody_adds_no_level() {
        // A deepest role carrying an empty delegations object is a chain of the permitted depth,
        // not one past it.
        let mut deepest = chain(MAX_DELEGATION_DEPTH);
        let mut role_at = &mut deepest;
        for _ in 0..MAX_DELEGATION_DEPTH {
            let delegations = role_at.delegations.as_mut().expect("a level");
            role_at = &mut delegations.roles[0]
                .targets
                .as_mut()
                .expect("a child")
                .signed;
        }
        role_at.delegations = Some(tough::schema::Delegations {
            keys: std::collections::HashMap::new(),
            roles: Vec::new(),
        });
        assert!(scope_delegations(&deepest).is_ok());
    }
}
