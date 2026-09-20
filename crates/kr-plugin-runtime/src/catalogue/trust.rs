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

/// How deep a delegation chain may go beneath the top-level targets role.
///
/// Three levels is a vendor, a product line inside that vendor and a release channel inside that
/// product line. Anything deeper is an organisation modelling itself in a trust graph, and each
/// level costs a host another signed document to fetch and verify on every sync.
pub const MAX_DELEGATION_DEPTH: usize = 3;

/// How a host treats metadata expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpiryPolicy {
    /// Expired metadata refuses the generation. This is what a sync uses.
    Enforce,
    /// Expiry is not checked.
    ///
    /// This reads a generation this host already verified and activated, so that an installed,
    /// pinned package stays usable offline after its repository's metadata expires. It never
    /// admits a generation the host has not already accepted.
    AlreadyAccepted,
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
    /// The loaded client, for reading payloads out of this same generation.
    repository: Repository,
}

impl VerifiedGeneration {
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
        // A target the metadata pins and the repository cannot supply is an absence, not a
        // failure of trust: the signature over the name is fine and the bytes are not there.
        let stream = self
            .repository
            .read_target(&target)
            .await
            .map_err(|source| match source {
                tough::error::Error::ExpiredMetadata { .. } => classify(&source),
                other => CatalogueError::UnavailableOffline {
                    detail: format!("{name} is not cached here and could not be read: {other}"),
                },
            })?
            .ok_or_else(|| CatalogueError::UnavailableOffline {
                detail: format!("the repository does not carry {name}"),
            })?;
        // The stream is bounded by the length the signed metadata pins and its digest is checked
        // as it arrives, so what comes back is at most that many bytes or an error.
        let bytes = stream
            .into_vec()
            .await
            .map_err(|source| CatalogueError::Integrity {
                detail: format!("{name} did not verify against the metadata: {source}"),
            })?;
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
    expiry: ExpiryPolicy,
    transport: Option<&std::sync::Arc<dyn tough::Transport + Send + Sync>>,
) -> CatalogueResult<VerifiedGeneration> {
    std::fs::create_dir_all(datastore)
        .map_err(|source| CatalogueError::storage(datastore, &source))?;
    let mut loader = RepositoryLoader::new(
        &enrolment.root,
        enrolment.metadata_url.clone(),
        enrolment.targets_url.clone(),
    )
    .datastore(datastore.to_path_buf())
    .expiration_enforcement(match expiry {
        ExpiryPolicy::Enforce => ExpirationEnforcement::Safe,
        ExpiryPolicy::AlreadyAccepted => ExpirationEnforcement::Unsafe,
    })
    .limits(tough::Limits {
        // The whole snapshot is held so that offline search works, so the client's own ceiling on
        // each metadata document is the enrolment's metadata budget rather than the crate default.
        max_root_size: enrolment.budgets.metadata_bytes.get(),
        max_targets_size: enrolment.budgets.metadata_bytes.get(),
        max_timestamp_size: enrolment.budgets.metadata_bytes.get(),
        max_snapshot_size: enrolment.budgets.metadata_bytes.get(),
        ..tough::Limits::default()
    });
    if let Some(transport) = transport {
        loader = loader.transport(SharedTransport(std::sync::Arc::clone(transport)));
    }
    let repository = loader.load().await.map_err(|source| classify(&source))?;

    let delegations = scope_delegations(&repository.targets().signed)?;

    let mut targets = BTreeMap::new();
    for (name, target) in repository.all_targets() {
        let digest: [u8; 32] =
            target
                .hashes
                .sha256
                .as_ref()
                .try_into()
                .map_err(|_| CatalogueError::Untrusted {
                    detail: format!("{} is pinned without a SHA-256 digest", name.raw()),
                })?;
        targets.insert(
            name.raw().to_owned(),
            TargetRecord {
                digest: PayloadDigest::from_bytes(digest),
                length: target.length,
            },
        );
    }

    let index_record =
        targets
            .get(INDEX_TARGET)
            .copied()
            .ok_or_else(|| CatalogueError::Untrusted {
                detail: format!("the generation's metadata does not pin {INDEX_TARGET}"),
            })?;
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
        .map_err(|source| CatalogueError::Integrity {
            detail: format!("{INDEX_TARGET} did not verify against the metadata: {source}"),
        })?;
    let index_bytes = bytes.len() as u64;
    ledger.check_metadata_bytes(index_bytes, Stage::Actual, INDEX_TARGET)?;
    let index: CatalogueIndex =
        serde_json::from_slice(&bytes).map_err(|source| CatalogueError::Integrity {
            detail: format!("{INDEX_TARGET} is not a catalogue index: {source}"),
        })?;
    ledger.check_metadata_entries(index.entries.len() as u64, Stage::Actual, INDEX_TARGET)?;
    // What each entry declares is checked before the index and the metadata are compared. A
    // package whose declared layout is unsafe is refused for that, rather than for whichever of
    // its consequences the comparison happens to notice first.
    for entry in &index.entries {
        crate::catalogue::extract::check_declared(entry, ledger)?;
    }
    check_index_against_targets(&index, &targets)?;

    Ok(VerifiedGeneration {
        generation: index.generation,
        index,
        index_bytes,
        targets,
        delegations,
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
    accepted: Option<RepositoryGeneration>,
    pinned: Option<RepositoryGeneration>,
) -> CatalogueResult<()> {
    if let Some(accepted) = accepted
        && candidate.get() < accepted.get()
    {
        return Err(CatalogueError::Untrusted {
            detail: format!(
                "generation {} is older than the accepted generation {}; a generation replayed \
                 after a later one is a rollback",
                candidate.get(),
                accepted.get()
            ),
        });
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
        if name.is_empty() || name.contains(['*', '?', '[', ']']) {
            return Err(CatalogueError::Untrusted {
                detail: format!(
                    "the delegation {role} claims {value}, whose publisher is a wildcard; a \
                     vendor delegation names its publisher"
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

/// Turns a client failure into the refusal a person acts on.
///
/// Expiry is the one that has to be told apart: section 11 says expired metadata blocks a new
/// generation while installed pinned packages stay usable, and a host that reported it as "the
/// root is not trusted" would send somebody to re-adopt a root that is fine.
fn classify(error: &tough::error::Error) -> CatalogueError {
    match error {
        tough::error::Error::ExpiredMetadata { role, .. } => CatalogueError::MetadataExpired {
            role: role.to_string(),
            expired_at: "the time the metadata states".to_owned(),
        },
        other => CatalogueError::Untrusted {
            detail: other.to_string(),
        },
    }
}

/// Carries a shared transport into the client, which wants an owned implementation.
#[derive(Clone, Debug)]
struct SharedTransport(std::sync::Arc<dyn tough::Transport + Send + Sync>);

#[tough::async_trait]
impl tough::Transport for SharedTransport {
    async fn fetch(&self, url: url::Url) -> Result<tough::TransportStream, tough::TransportError> {
        self.0.fetch(url).await
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
        assert!(check_generation(three, Some(two), None).is_ok());
        assert!(check_generation(three, Some(three), None).is_ok());
        let refusal = check_generation(two, Some(three), None).expect_err("a rollback");
        assert!(refusal.to_string().contains("rollback"), "{refusal}");
    }

    #[test]
    fn a_pin_holds_the_repository_on_its_generation() {
        let three = RepositoryGeneration::new(3);
        let four = RepositoryGeneration::new(4);
        assert!(check_generation(three, Some(three), Some(three)).is_ok());
        let refusal = check_generation(four, Some(three), Some(three)).expect_err("pinned");
        assert!(
            refusal
                .to_string()
                .contains("pinned generation stays usable"),
            "{refusal}"
        );
    }
}
