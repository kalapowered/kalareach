//! Repository sync, the catalogue and what a host installs from it.
//!
//! The host synchronises the **complete signed catalogue metadata snapshot**: compact
//! descriptions, declarative match rules, capability declarations and immutable payload hashes and
//! sizes. Everything a person searches, everything a rule matches against and everything a
//! decision needs is in that snapshot, so catalogue search works with no network at all. Payloads
//! stay behind their content hashes until something explicitly asks for them.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`repository`] | Enrolment: the adopted root, the budgets, the ceiling and what needs the owner's confirmation |
//! | [`trust`] | The Update Framework client, delegation scope and depth, rollback and expiry |
//! | [`budget`] | The declared and actual accounting, and the refusal that names its resource |
//! | [`store`] | The directory, the atomic index activation and the independently atomic package activation |
//! | [`extract`] | What a package may contain, checked before a fetch and again before an activation |
//! | [`ceiling`] | Which decision each capability needs, and what an upgrade may not widen |
//! | [`search`] | Offline search and the match index activation reads |
//! | [`install`] | Installed packages, live bindings and what revocation does to them |
//! | [`evidence`] | The capability evidence a catalogue contributes, and what a qualification may not do |
//! | [`broker`] | What the catalogue needs from the trusted broker, as a trait |
//! | [`state`] | The enrolments and installations that survive a restart |
//!
//! # When a payload is fetched
//!
//! Three reasons, and no others: an explicit install, an explicit enable, and an activation for a
//! package that is already installed and enabled here. Anything else reading an uncached payload
//! gets `PACKAGE_UNAVAILABLE_OFFLINE`, which is the answer section 11 asks for. A host that
//! invented an enabled capability instead would be telling somebody an action will work when the
//! bytes that would perform it are not here.
//!
//! The full-offline-mirror setting is the one way to fetch everything: it is explicit, it runs
//! inside the repository's approved budget, and it replaces unconditional executable and asset
//! download as a sync strategy rather than replacing the complete-catalogue rule.
//!
//! # What survives an interruption
//!
//! Index activation is atomic after the metadata verifies, and each package's activation is
//! atomic after all of its payloads verify, independently of the index. An interrupted index or
//! payload fetch therefore leaves the previous valid index and the installed package usable.

pub mod broker;
pub mod budget;
pub mod ceiling;
pub mod error;
pub mod evidence;
pub mod extract;
pub mod install;
pub mod repository;
pub mod search;
pub mod state;
pub mod store;
pub mod trust;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::catalogue::{CatalogueIndex, IndexEntry};
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::ids::PluginId;
use kr_plugin_sdk::package::MANIFEST_FILE;
use kr_plugin_sdk::version::PackageVersion;
use kr_protocol::ids::{EnvironmentId, RepositoryGeneration};

pub use crate::catalogue::broker::{BrokerBridge, UnboundBroker};
pub use crate::catalogue::budget::{BudgetLedger, Resource, ResourceLimit, Stage};
pub use crate::catalogue::ceiling::{CapabilityDecision, GrantRequirement, InstallationGrant};
pub use crate::catalogue::error::{CatalogueError, CatalogueResult};
pub use crate::catalogue::install::{
    Binding, BindingId, DisablePolicy, Installation, Installations, RevocationNotice,
};
pub use crate::catalogue::repository::{
    CapabilityCeiling, Enrolment, RepositoryId, RepositoryKind,
};
pub use crate::catalogue::search::{Candidate, MatchIndex, Observation, Resolution};
pub use crate::catalogue::state::{CatalogueState, capability_from_str};
pub use crate::catalogue::store::{ActiveGeneration, Store};
pub use crate::catalogue::trust::{ExpiryPolicy, VerifiedGeneration};

use crate::catalogue::trust::{PACKAGE_PREFIX, TargetRecord};

/// Why a payload is being fetched.
///
/// Section 11 names the three reasons that fetch a payload by content hash. They are an
/// enumeration rather than a boolean because the refusal has to say which one was missing: a
/// caller that asked for an activation of something not installed here is told that, not told the
/// repository is unreachable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchReason {
    /// The owner asked for this package to be installed.
    ExplicitInstall,
    /// The owner asked for an installed package to be enabled.
    ExplicitEnable,
    /// A matching application started and the package is already installed and enabled here.
    AuthorisedActivation,
    /// The repository's full-offline-mirror setting is on.
    FullOfflineMirror,
}

impl FetchReason {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitInstall => "explicit_install",
            Self::ExplicitEnable => "explicit_enable",
            Self::AuthorisedActivation => "authorised_activation",
            Self::FullOfflineMirror => "full_offline_mirror",
        }
    }
}

/// What one sync did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncOutcome {
    /// The generation now active.
    pub generation: RepositoryGeneration,
    /// How many entries its index carries.
    pub entries: usize,
    /// How many bytes the index is.
    pub index_bytes: u64,
    /// How many payloads a full mirror fetched, where the setting is on.
    pub mirrored_payloads: usize,
    /// The delegations the generation carries, by role and publisher.
    pub delegations: Vec<(String, String)>,
}

/// One enrolled repository, as this host holds it.
#[derive(Debug)]
struct RepositoryState {
    enrolment: Enrolment,
    store: Store,
    ledger: BudgetLedger,
}

/// The host's catalogue.
#[derive(Debug)]
pub struct Catalogue {
    root: PathBuf,
    repositories: BTreeMap<RepositoryId, RepositoryState>,
    installations: Installations,
    broker: Arc<dyn BrokerBridge>,
    transport: Option<Arc<dyn tough::Transport + Send + Sync>>,
}

impl Catalogue {
    /// Opens the catalogue under `root`, with no broker bound.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the directory cannot be created.
    pub fn open(root: &Path) -> CatalogueResult<Self> {
        Self::with_broker(root, Arc::new(UnboundBroker))
    }

    /// Opens the catalogue under `root`, against one broker.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the directory cannot be created.
    pub fn with_broker(root: &Path, broker: Arc<dyn BrokerBridge>) -> CatalogueResult<Self> {
        std::fs::create_dir_all(root).map_err(|source| CatalogueError::storage(root, &source))?;
        let mut catalogue = Self {
            root: root.to_path_buf(),
            repositories: BTreeMap::new(),
            installations: Installations::new(),
            broker,
            transport: Some(Arc::new(tough::FilesystemTransport)),
        };
        // What an earlier daemon enrolled and installed is still enrolled and installed. Reading
        // it back is what stops a restart from asking the owner to adopt every root again, and
        // from reporting nothing installed while the packages are on disk.
        let state = CatalogueState::read(root)?;
        for enrolment in state.enrolments(root)? {
            catalogue.attach(enrolment)?;
        }
        for installation in state.installed()? {
            catalogue.installations.insert(installation);
        }
        catalogue.installations.set_policy(state.disable_policy());
        Ok(catalogue)
    }

    /// Writes the enrolments and installations that survive a restart.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the state cannot be written.
    pub fn persist(&self) -> CatalogueResult<()> {
        CatalogueState::of(
            &self.repositories(),
            &self.installations.all(),
            self.installations.policy(),
        )
        .write(&self.root)
    }

    /// Attaches one enrolment's store and budget ledger without writing anything new.
    fn attach(&mut self, enrolment: Enrolment) -> CatalogueResult<()> {
        let store = Store::open(&self.root, &enrolment.id)?;
        let mut ledger = BudgetLedger::new(enrolment.budgets);
        for size in store.cached_payloads()?.values() {
            ledger.add_payload_bytes(*size);
        }
        if let Some(active) = store.active()? {
            ledger.accept_metadata(active.index_bytes, 0);
        }
        self.repositories.insert(
            enrolment.id.clone(),
            RepositoryState {
                enrolment,
                store,
                ledger,
            },
        );
        Ok(())
    }

    /// Replaces the transport repositories are fetched through.
    pub fn set_transport(&mut self, transport: Arc<dyn tough::Transport + Send + Sync>) {
        self.transport = Some(transport);
    }

    /// Returns the installations and bindings this host holds.
    #[must_use]
    pub const fn installations(&self) -> &Installations {
        &self.installations
    }

    /// Returns the installations and bindings this host holds, for changing.
    pub const fn installations_mut(&mut self) -> &mut Installations {
        &mut self.installations
    }

    /// Returns every enrolled repository, in a stable order.
    #[must_use]
    pub fn repositories(&self) -> Vec<&Enrolment> {
        self.repositories
            .values()
            .map(|state| &state.enrolment)
            .collect()
    }

    /// Returns one enrolled repository.
    #[must_use]
    pub fn repository(&self, id: &RepositoryId) -> Option<&Enrolment> {
        self.repositories.get(id).map(|state| &state.enrolment)
    }

    /// Returns which generation one repository is on, where it has one.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the repository is not enrolled.
    pub fn active(&self, id: &RepositoryId) -> CatalogueResult<Option<ActiveGeneration>> {
        self.state(id)?.store.active()
    }

    /// Enrols a repository.
    ///
    /// A new root is always the owner's decision, so enrolment takes the confirmation rather than
    /// inferring one from the caller's rights.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::OwnerConfirmationRequired`] when the owner has not confirmed the
    /// root, [`CatalogueError::InvalidArgument`] when the repository is already enrolled, and
    /// [`CatalogueError::StorageUnavailable`] when its directory cannot be made.
    pub fn enrol(&mut self, enrolment: Enrolment, confirmed: bool) -> CatalogueResult<()> {
        if self.repositories.contains_key(&enrolment.id) {
            return Err(CatalogueError::InvalidArgument {
                detail: format!("{} is already enrolled", enrolment.id),
            });
        }
        if !confirmed {
            return Err(CatalogueError::OwnerConfirmationRequired {
                detail: format!(
                    "{} would be trusted against a root this host has not accepted before; \
                     adopting a root is the owner's decision",
                    enrolment.id
                ),
            });
        }
        // The adopted root is written into the repository's own directory, which is where a
        // generation carries one and where the client reads it from.
        Store::open(&self.root, &enrolment.id)?.write_root(&enrolment.root)?;
        self.attach(enrolment)?;
        self.persist()
    }

    /// Changes an enrolment, asking the owner for a new root or wider trust.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the repository is not enrolled and
    /// [`CatalogueError::OwnerConfirmationRequired`] when the change needs confirming.
    pub fn update_enrolment(
        &mut self,
        proposed: Enrolment,
        confirmed: bool,
    ) -> CatalogueResult<()> {
        let state =
            self.repositories
                .get_mut(&proposed.id)
                .ok_or_else(|| CatalogueError::NotFound {
                    detail: format!("{} is not enrolled", proposed.id),
                })?;
        state.enrolment.check_change(&proposed, confirmed)?;
        state.ledger = {
            let mut ledger = BudgetLedger::new(proposed.budgets);
            ledger.accept_metadata(
                state.ledger.metadata_bytes(),
                state.ledger.metadata_entries(),
            );
            ledger.add_payload_bytes(state.ledger.payload_bytes());
            ledger
        };
        state.enrolment = proposed;
        self.persist()
    }

    /// Pins a repository to one generation, or removes its pin.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the repository is not enrolled, and
    /// [`CatalogueError::InvalidArgument`] when the pin names a generation this host has not
    /// activated.
    pub fn pin(
        &mut self,
        id: &RepositoryId,
        generation: Option<RepositoryGeneration>,
    ) -> CatalogueResult<()> {
        let state = self
            .repositories
            .get_mut(id)
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!("{id} is not enrolled"),
            })?;
        if let Some(generation) = generation {
            let active = state
                .store
                .active()?
                .ok_or_else(|| CatalogueError::InvalidArgument {
                    detail: format!("{id} has no activated generation to pin"),
                })?;
            if active.generation != generation.get() {
                return Err(CatalogueError::InvalidArgument {
                    detail: format!(
                        "{id} is on generation {} and the pin names {}; pinning operates on the \
                         generation that is active",
                        active.generation,
                        generation.get()
                    ),
                });
            }
        }
        state.enrolment.pinned_generation = generation;
        self.persist()
    }

    /// Removes a repository and stops trusting its root.
    ///
    /// The directory is left where it is. A package installed from it is still installed, on the
    /// hash it was installed at, and removing those is `plugin.remove`'s decision rather than
    /// something that happens to somebody while they are removing a repository.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the repository is not enrolled.
    pub fn remove_repository(&mut self, id: &RepositoryId) -> CatalogueResult<Enrolment> {
        let enrolment = self
            .repositories
            .remove(id)
            .map(|state| state.enrolment)
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!("{id} is not enrolled"),
            })?;
        self.persist()?;
        Ok(enrolment)
    }

    /// Synchronises one repository's complete signed metadata snapshot.
    ///
    /// # Errors
    ///
    /// Returns the refusal verification, the budgets or the generation check decided. Nothing is
    /// activated when it does, so the previous generation stays usable.
    pub async fn sync(&mut self, id: &RepositoryId) -> CatalogueResult<SyncOutcome> {
        let (enrolment, datastore, ledger, accepted) = {
            let state = self.state(id)?;
            (
                state.enrolment.clone(),
                state.store.datastore(),
                state.ledger.clone(),
                state.store.active()?.map(|active| active.generation),
            )
        };

        let verified = trust::verify(
            &enrolment,
            &datastore,
            &ledger,
            ExpiryPolicy::Enforce,
            self.transport.as_ref(),
        )
        .await?;
        trust::check_generation(
            verified.generation,
            accepted.map(RepositoryGeneration::new),
            enrolment.pinned_generation,
        )?;
        // The index is activated before any payload is fetched. A full mirror that runs out of
        // budget half way therefore leaves the host on the generation it just verified, with the
        // payloads it managed to cache, rather than on the previous one with none of them.
        let active = {
            let state = self.state_mut(id)?;
            let active = state
                .store
                .activate_index(verified.generation, &verified.index)?;
            state
                .ledger
                .accept_metadata(verified.index_bytes, verified.index.entries.len() as u64);
            active
        };

        let mut mirrored = 0usize;
        if enrolment.budgets.full_offline_mirror {
            mirrored = self.mirror(id, &verified).await?;
        }

        Ok(SyncOutcome {
            generation: RepositoryGeneration::new(active.generation),
            entries: verified.index.entries.len(),
            index_bytes: verified.index_bytes,
            mirrored_payloads: mirrored,
            delegations: verified
                .delegations
                .iter()
                .map(|scope| (scope.role.clone(), scope.publisher.clone()))
                .collect(),
        })
    }

    /// Reads one repository's active index, offline.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the repository is not enrolled or has no
    /// activated generation.
    pub fn index(&self, id: &RepositoryId) -> CatalogueResult<CatalogueIndex> {
        self.state(id)?.store.active_index()
    }

    /// Searches one repository's active index, offline.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the repository is not enrolled or has no
    /// activated generation.
    pub fn search(
        &self,
        id: &RepositoryId,
        query: &str,
        limit: usize,
    ) -> CatalogueResult<Vec<IndexEntry>> {
        let index = self.index(id)?;
        Ok(search::search(&index, query, limit)
            .into_iter()
            .cloned()
            .collect())
    }

    /// Reads one payload, and never fetches for a reason section 11 does not name.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::UnavailableOffline`] when the payload is not cached and the
    /// reason does not permit fetching it.
    pub async fn payload(
        &mut self,
        id: &RepositoryId,
        digest: PayloadDigest,
        target: &str,
        reason: FetchReason,
    ) -> CatalogueResult<Vec<u8>> {
        if let Ok(bytes) = self.state(id)?.store.read_payload(digest) {
            return Ok(bytes);
        }
        let declared = {
            let state = self.state(id)?;
            state
                .store
                .active()?
                .ok_or_else(|| CatalogueError::UnavailableOffline {
                    detail: format!(
                        "{id} has no activated generation, so {target} cannot be fetched by \
                         content hash"
                    ),
                })?
        };
        let _ = declared;
        let bytes = self.fetch(id, target, digest, reason).await?;
        Ok(bytes)
    }

    /// Activates one package: fetches every payload, verifies all of them, then makes it visible.
    ///
    /// Package activation is independent of index activation, and atomic on its own. A package
    /// whose payloads do not all verify is not activated, and whatever was installed before stays
    /// installed and usable.
    ///
    /// # Errors
    ///
    /// Returns the refusal verification, the budgets or the package rules decided.
    pub async fn activate_package(
        &mut self,
        id: &RepositoryId,
        plugin_id: &PluginId,
        version: &PackageVersion,
        reason: FetchReason,
    ) -> CatalogueResult<PayloadDigest> {
        let index = self.index(id)?;
        let entry =
            index
                .find(plugin_id, version)
                .cloned()
                .ok_or_else(|| CatalogueError::NotFound {
                    detail: format!("{plugin_id} {version} is not in this repository's index"),
                })?;
        if self.state(id)?.store.has_package(entry.manifest_digest) {
            return Ok(entry.manifest_digest);
        }
        extract::check_declared(&entry, &self.state(id)?.ledger)?;

        let prefix = format!(
            "{PACKAGE_PREFIX}{}/{}/{}",
            entry.publisher_id, entry.plugin_name, entry.version
        );
        let subject = format!("{} {}", entry.plugin_id, entry.version);

        let mut staged = self.state(id)?.store.stage_package(entry.manifest_digest)?;
        let manifest = self
            .fetch(
                id,
                &format!("{prefix}/{MANIFEST_FILE}"),
                entry.manifest_digest,
                reason,
            )
            .await;
        let manifest = match manifest {
            Ok(bytes) => bytes,
            Err(error) => {
                staged.abandon();
                return Err(error);
            }
        };
        if let Err(error) = staged.write(MANIFEST_FILE, &manifest) {
            staged.abandon();
            return Err(error);
        }
        for payload in &entry.payloads {
            let target = format!("{prefix}/{}", payload.path.as_str());
            let relative = match extract::relative_target(&prefix, &target) {
                Ok(relative) => relative,
                Err(error) => {
                    staged.abandon();
                    return Err(error);
                }
            };
            match self.fetch(id, &target, payload.digest, reason).await {
                Ok(bytes) => {
                    if let Err(error) = staged.write(relative.as_str(), &bytes) {
                        staged.abandon();
                        return Err(error);
                    }
                }
                Err(error) => {
                    staged.abandon();
                    return Err(error);
                }
            }
        }

        let staged_bytes = staged.staged_bytes();
        let staged_files = staged.staged_files();
        let directory = self.state(id)?.store.stage_path(entry.manifest_digest);
        let checked = extract::check_staged(&directory, &subject).and_then(|manifest| {
            extract::check_actual(
                &entry,
                &manifest,
                staged_bytes,
                staged_files,
                &self.state(id)?.ledger,
            )
        });
        if let Err(error) = checked {
            staged.abandon();
            return Err(error);
        }
        staged.activate()?;
        Ok(entry.manifest_digest)
    }

    /// Fetches every payload the index references, inside the approved budget.
    async fn mirror(
        &mut self,
        id: &RepositoryId,
        verified: &VerifiedGeneration,
    ) -> CatalogueResult<usize> {
        let mut fetched = 0usize;
        for entry in &verified.index.entries {
            let prefix = format!(
                "{PACKAGE_PREFIX}{}/{}/{}",
                entry.publisher_id, entry.plugin_name, entry.version
            );
            let mut wanted: Vec<(String, PayloadDigest, u64)> = vec![(
                format!("{prefix}/{MANIFEST_FILE}"),
                entry.manifest_digest,
                entry.manifest_size_bytes.get(),
            )];
            for payload in &entry.payloads {
                wanted.push((
                    format!("{prefix}/{}", payload.path.as_str()),
                    payload.digest,
                    payload.size_bytes.get(),
                ));
            }
            for (target, digest, length) in wanted {
                if self.state(id)?.store.has_payload(digest) {
                    continue;
                }
                self.reclaim_for(id, length, &target)?;
                let bytes = verified
                    .read_target(
                        &target,
                        TargetRecord { digest, length },
                        &self.state(id)?.ledger,
                    )
                    .await?;
                let state = self.state_mut(id)?;
                state.store.cache_payload(digest, &bytes)?;
                state.ledger.add_payload_bytes(bytes.len() as u64);
                fetched += 1;
            }
        }
        Ok(fetched)
    }

    /// Fetches one payload by content hash, for a reason section 11 names.
    async fn fetch(
        &mut self,
        id: &RepositoryId,
        target: &str,
        digest: PayloadDigest,
        reason: FetchReason,
    ) -> CatalogueResult<Vec<u8>> {
        if let Ok(bytes) = self.state(id)?.store.read_payload(digest) {
            return Ok(bytes);
        }
        let (enrolment, datastore, ledger) = {
            let state = self.state(id)?;
            (
                state.enrolment.clone(),
                state.store.datastore(),
                state.ledger.clone(),
            )
        };
        // The metadata is read again rather than kept from the sync: a payload fetched now is
        // fetched against the metadata that is current now, and expired metadata blocks it.
        let verified = trust::verify(
            &enrolment,
            &datastore,
            &ledger,
            ExpiryPolicy::Enforce,
            self.transport.as_ref(),
        )
        .await
        .map_err(|error| match error {
            CatalogueError::Untrusted { detail } => CatalogueError::UnavailableOffline {
                detail: format!(
                    "{target} is not cached here and {id} could not be reached to fetch it for \
                     an {}: {detail}",
                    reason.as_str()
                ),
            },
            other => other,
        })?;
        let declared = verified
            .target(target)
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!("{target} is not in {id}'s current generation"),
            })?;
        if declared.digest != digest {
            return Err(CatalogueError::Integrity {
                detail: format!(
                    "{target} is pinned at {} and was asked for by {digest}; a payload is fetched \
                     by content hash",
                    declared.digest
                ),
            });
        }
        self.reclaim_for(id, declared.length, target)?;
        let bytes = verified
            .read_target(target, declared, &self.state(id)?.ledger)
            .await?;
        let state = self.state_mut(id)?;
        state.store.cache_payload(digest, &bytes)?;
        state.ledger.add_payload_bytes(bytes.len() as u64);
        Ok(bytes)
    }

    /// Makes room for `length` more bytes, without touching a live-bound or pinned payload.
    fn reclaim_for(
        &mut self,
        id: &RepositoryId,
        length: u64,
        subject: &str,
    ) -> CatalogueResult<()> {
        let mut protected: BTreeSet<PayloadDigest> = self
            .installations
            .protected_packages()
            .into_iter()
            .collect();
        protected.extend(self.broker.live_packages());
        let state = self
            .repositories
            .get_mut(id)
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!("{id} is not enrolled"),
            })?;
        state
            .store
            .reclaim(length, &mut state.ledger, &protected, subject)
    }

    /// Installs one verified package into one environment.
    ///
    /// The package's payloads are fetched by content hash, verified as a set and activated
    /// atomically before anything is recorded as installed, so a failed installation leaves
    /// whatever was installed before exactly as it was.
    ///
    /// # Errors
    ///
    /// Returns the refusal verification, the budgets, the package rules or the ceiling decided.
    pub async fn install(
        &mut self,
        id: &RepositoryId,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
        version: &PackageVersion,
        expected_digest: PayloadDigest,
        grant: InstallationGrant,
    ) -> CatalogueResult<Installation> {
        let index = self.index(id)?;
        let entry =
            index
                .find(plugin_id, version)
                .cloned()
                .ok_or_else(|| CatalogueError::NotFound {
                    detail: format!("{plugin_id} {version} is not in this repository's index"),
                })?;
        // Pinning and rollback operate on immutable hashes, so the caller states the hash it read
        // and a repository that published something else in between is a refusal, not a surprise.
        if entry.manifest_digest != expected_digest {
            return Err(CatalogueError::Integrity {
                detail: format!(
                    "{plugin_id} {version} is {} in this generation and the request names {}",
                    entry.manifest_digest, expected_digest
                ),
            });
        }
        if let Some(record) = entry.revocation.0.as_ref() {
            return Err(CatalogueError::Untrusted {
                detail: format!(
                    "{plugin_id} {version} is revoked ({:?}): {}",
                    record.reason,
                    record.statement.as_str()
                ),
            });
        }
        ceiling::check_installable(
            &entry.capabilities,
            &self.state(id)?.enrolment.ceiling,
            &grant,
        )?;
        if let Some(previous) = self.installations.get(environment_id, plugin_id) {
            ceiling::check_upgrade(&previous.grant, &grant, false)?;
        }

        self.activate_package(id, plugin_id, version, FetchReason::ExplicitInstall)
            .await?;

        let mut installation = Installation::from_entry(&entry, id.clone(), environment_id, grant);
        if let Some(previous) = self.installations.get(environment_id, plugin_id) {
            installation.enabled = previous.enabled;
        }
        self.installations.insert(installation.clone());
        self.persist()?;
        Ok(installation)
    }

    /// Enables or disables an installed package.
    ///
    /// Enabling fetches the package's payloads where they are not cached, which is one of the
    /// three reasons section 11 names. Disabling fetches nothing.
    ///
    /// # Errors
    ///
    /// Returns the refusal the installation or the fetch decided.
    pub async fn set_enabled(
        &mut self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
        enabled: bool,
    ) -> CatalogueResult<Installation> {
        let installation = self
            .installations
            .get(environment_id, plugin_id)
            .cloned()
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!("{plugin_id} is not installed in this environment"),
            })?;
        if enabled {
            let repository = installation.repository.clone();
            let version = installation.version.clone();
            self.activate_package(
                &repository,
                plugin_id,
                &version,
                FetchReason::ExplicitEnable,
            )
            .await?;
        }
        self.installations
            .set_enabled(environment_id, plugin_id, enabled)?;
        self.persist()?;
        self.installations
            .get(environment_id, plugin_id)
            .cloned()
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!("{plugin_id} is not installed in this environment"),
            })
    }

    /// Replaces one installation's grant.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the package is not installed here, and
    /// [`CatalogueError::GrantRequired`] when the new set is outside what this host will permit.
    pub fn set_grant(
        &mut self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
        grant: InstallationGrant,
    ) -> CatalogueResult<Installation> {
        let installation = self
            .installations
            .get(environment_id, plugin_id)
            .cloned()
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!("{plugin_id} is not installed in this environment"),
            })?;
        let index = self.index(&installation.repository)?;
        let entry = index
            .find(plugin_id, &installation.version)
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!(
                    "{plugin_id} {} is not in this repository's index",
                    installation.version
                ),
            })?;
        ceiling::check_installable(
            &entry.capabilities,
            &self.state(&installation.repository)?.enrolment.ceiling,
            &grant,
        )?;
        let mut updated = installation;
        updated.grant = grant;
        self.installations.insert(updated.clone());
        self.persist()?;
        Ok(updated)
    }

    /// Removes an installation and closes every binding that held it.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the package is not installed here.
    pub fn uninstall(
        &mut self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
    ) -> CatalogueResult<usize> {
        let closed = self
            .installations
            .bindings()
            .iter()
            .filter(|binding| {
                binding.environment_id == environment_id && &binding.plugin_id == plugin_id
            })
            .count();
        self.installations.remove(environment_id, plugin_id)?;
        self.persist()?;
        Ok(closed)
    }

    /// Pins or unpins an installation to the exact hash it holds.
    ///
    /// # Errors
    ///
    /// Returns what [`Installations::set_pinned`] returns.
    pub fn pin_package(
        &mut self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
        package_digest: Option<PayloadDigest>,
    ) -> CatalogueResult<Installation> {
        self.installations
            .set_pinned(environment_id, plugin_id, package_digest)?;
        self.persist()?;
        self.installations
            .get(environment_id, plugin_id)
            .cloned()
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!("{plugin_id} is not installed in this environment"),
            })
    }

    /// Returns what one installed package may currently do.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the repository, the package or the installation
    /// is not here.
    pub fn capabilities(
        &self,
        id: &RepositoryId,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
    ) -> CatalogueResult<Vec<CapabilityDecision>> {
        let installation = self
            .installations
            .get(environment_id, plugin_id)
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!("{plugin_id} is not installed in this environment"),
            })?;
        let index = self.index(id)?;
        let entry = index
            .find(plugin_id, &installation.version)
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!(
                    "{plugin_id} {} is not in this repository's index",
                    installation.version
                ),
            })?;
        Ok(ceiling::decide(
            &entry.capabilities,
            &self.state(id)?.enrolment.ceiling,
            &installation.grant,
        ))
    }

    /// Returns the capabilities one installed package may actually use.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::capabilities`] returns.
    pub fn effective_capabilities(
        &self,
        id: &RepositoryId,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
    ) -> CatalogueResult<BTreeSet<PluginCapability>> {
        Ok(self
            .capabilities(id, environment_id, plugin_id)?
            .into_iter()
            .filter(|decision| decision.permitted)
            .map(|decision| decision.capability)
            .collect())
    }

    fn state(&self, id: &RepositoryId) -> CatalogueResult<&RepositoryState> {
        self.repositories
            .get(id)
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!("{id} is not enrolled"),
            })
    }

    fn state_mut(&mut self, id: &RepositoryId) -> CatalogueResult<&mut RepositoryState> {
        self.repositories
            .get_mut(id)
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!("{id} is not enrolled"),
            })
    }
}
