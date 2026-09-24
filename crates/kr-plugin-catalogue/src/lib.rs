//! Repository sync, the catalogue and what a host installs from it.
//!
//! The host synchronises the **complete signed catalogue metadata snapshot**: compact
//! descriptions, declarative match rules, capability declarations and immutable payload hashes and
//! sizes. Everything a person searches, everything a rule matches against and everything a
//! decision needs is in that snapshot, so catalogue search works with no network at all. Payloads
//! stay behind their content hashes until something explicitly asks for them.
//!
//! This crate verifies, stores and fetches, and it hosts no component. The control daemon links it
//! to serve the catalogue and plugin methods, and neither the daemon nor a session's worker links a
//! Wasm engine, so a component runs only in the plugin runtime's own process.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`repository`] | Enrolment: the adopted root, the budgets, the ceiling and what needs the owner's confirmation |
//! | [`trust`] | The Update Framework client, delegation scope and depth, rollback and expiry |
//! | [`budget`] | The declared and actual accounting, and the refusal that names its resource |
//! | [`db`] | The catalogue's records and receipts, and the one place they change |
//! | [`authority`] | The admission a change runs under, asked again where the change becomes durable |
//! | [`store`] | The files: indexes, payloads and packages, each named by what it holds |
//! | [`extract`] | What a package may contain, checked before a fetch and again before an activation |
//! | [`ceiling`] | Which decision each capability needs, and what an upgrade may not widen |
//! | [`search`] | Offline search and the match index activation reads |
//! | [`install`] | Installed packages, live bindings and what revocation does to them |
//! | [`evidence`] | The capability evidence a catalogue contributes, and what a qualification may not do |
//! | [`broker`] | What the catalogue needs from the trusted broker, as a trait |
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
//! # How a change becomes durable
//!
//! Every change is one transaction of the catalogue's database, and it reads what it changes inside
//! that transaction, so two catalogues on one directory, or two requests on one catalogue, never
//! overwrite each other's work. The transaction runs inside the admitting [`Authority`]'s commit,
//! so the admission is standing at the moment the change becomes durable rather than only when the
//! request arrived. Where the caller keeps a receipt for the action, the same transaction records
//! the result the action answered with.
//!
//! # What survives an interruption
//!
//! Index activation is atomic after the metadata verifies, and each package's activation is
//! atomic after all of its payloads verify, independently of the index. An interrupted index or
//! payload fetch therefore leaves the previous valid index and the installed package usable.

pub mod authority;
pub mod broker;
pub mod budget;
pub mod ceiling;
pub mod db;
pub mod error;
pub mod evidence;
pub mod extract;
pub mod install;
pub mod repository;
pub mod search;
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

pub use crate::authority::{Authority, Committed, Effect, Failure, Owner, Recording};
pub use crate::broker::{BrokerBridge, UnboundBroker};
pub use crate::budget::{BudgetLedger, Resource, ResourceLimit, Retained, Stage};
pub use crate::ceiling::{
    CapabilityDecision, GrantRequirement, InstallationGrant, capability_from_str,
};
pub use crate::db::{
    ActiveGeneration, Claimed, Durability, Enrolled, KeptGeneration, ReceiptClaim, ReceiptKey,
    ReceiptRecord,
};
pub use crate::error::{CatalogueError, CatalogueResult};
pub use crate::install::{
    Binding, BindingId, Bindings, DisablePolicy, Installation, RevocationNotice,
};
pub use crate::repository::{
    CapabilityCeiling, Enrolment, EnrolmentKey, RepositoryId, RepositoryKind,
};
pub use crate::search::{Candidate, MatchIndex, Observation, Resolution};
pub use crate::store::{PackageCheck, ReadyPackage, Store};
pub use crate::trust::{MetadataVersions, VerifiedGeneration};

use crate::authority::committed;

/// The suite's own generations, signed in memory, for the tests that reach inside a publication.
#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;

/// The suite names this crate by its name, as every other user of it does.
#[cfg(test)]
extern crate self as kr_plugin_catalogue;
use crate::db::{Changes, Db, Records};
use crate::store::StoreLock;
use crate::trust::{PACKAGE_PREFIX, TargetRecord};

/// How many times a read that met a sync is made before its failure is the answer.
const READ_ATTEMPTS: u32 = 4;

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

/// One enrolled repository, as a caller is told about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryView {
    /// What was enrolled.
    pub enrolment: Enrolment,
    /// Which generation it is on, where it has one.
    pub active: Option<ActiveGeneration>,
}

/// One installed package, as a caller is told about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallationView {
    /// What the catalogue holds for it.
    pub installation: Installation,
    /// Whether the release it is on is revoked in its repository's current generation.
    pub revoked: bool,
    /// How many live bindings hold it.
    pub live_bindings: u64,
    /// What each capability it asks for needs, and whether it has it.
    pub decisions: Vec<CapabilityDecision>,
}

/// What one change did, handed to the caller's settlement inside the change's own transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transition {
    /// A repository was enrolled.
    Enrolled(RepositoryView),
    /// An enrolment's settings changed.
    Updated(RepositoryView),
    /// A repository verified and activated a generation.
    Synced {
        /// The repository as it now is.
        repository: RepositoryView,
        /// What the sync did.
        outcome: SyncOutcome,
    },
    /// A repository was pinned to a generation, or unpinned.
    Pinned(RepositoryView),
    /// A repository was removed.
    Removed {
        /// The repository that was removed.
        enrolment: Enrolment,
        /// The packages installed from it, which stay installed.
        installed: Vec<PluginId>,
    },
    /// A package was installed.
    Installed(InstallationView),
    /// An installation was enabled, disabled, pinned, unpinned or granted.
    Changed(InstallationView),
    /// An installation was removed.
    Uninstalled {
        /// The package.
        plugin_id: PluginId,
        /// How many live bindings closed with it.
        closed_bindings: u64,
    },
    /// The administrator's disable policy changed.
    PolicyChanged(DisablePolicy),
}

/// How a caller that keeps a receipt settles it in the change's own transaction.
pub struct Settlement<'a> {
    key: ReceiptKey,
    now_ms: u64,
    render: &'a mut (dyn FnMut(&Transition) -> CatalogueResult<Vec<u8>> + Send),
}

/// What one catalogue change carries: the admission it runs under and, where the caller keeps
/// one, the receipt it settles.
pub struct Change<'a> {
    authority: &'a dyn Authority,
    settlement: Option<Settlement<'a>>,
}

impl<'a> Change<'a> {
    /// A change under `authority`, with no receipt to settle.
    #[must_use]
    pub fn new(authority: &'a dyn Authority) -> Self {
        Self {
            authority,
            settlement: None,
        }
    }

    /// A change under `authority` that settles the claimed receipt `key` as applied, with the
    /// result `render` makes from what the change did.
    ///
    /// The result is made inside the change's transaction and recorded there, so the effect and
    /// the answer it gave commit together or not at all.
    #[must_use]
    pub fn settling(
        authority: &'a dyn Authority,
        key: ReceiptKey,
        now_ms: u64,
        render: &'a mut (dyn FnMut(&Transition) -> CatalogueResult<Vec<u8>> + Send),
    ) -> Self {
        Self {
            authority,
            settlement: Some(Settlement {
                key,
                now_ms,
                render,
            }),
        }
    }

    /// Returns the authority this change runs under.
    #[must_use]
    pub fn authority(&self) -> &'a dyn Authority {
        self.authority
    }
}

/// The host's catalogue.
#[derive(Debug)]
pub struct Catalogue {
    root: PathBuf,
    db: Db,
    bindings: Bindings,
    fetches_network: bool,
    broker: Arc<dyn BrokerBridge>,
    transport: Arc<dyn tough::Transport + Send + Sync>,
}

impl Catalogue {
    /// Opens the catalogue under `root`, with no broker bound.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the directory or its database cannot be
    /// opened.
    pub fn open(root: &Path) -> CatalogueResult<Self> {
        Self::with_broker(root, Arc::new(UnboundBroker))
    }

    /// Opens the catalogue under `root`, against one broker.
    ///
    /// What an earlier daemon enrolled and installed is still enrolled and installed: it is in the
    /// database, which is read where it is needed rather than copied into memory here.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the directory or its database cannot be
    /// opened.
    pub fn with_broker(root: &Path, broker: Arc<dyn BrokerBridge>) -> CatalogueResult<Self> {
        std::fs::create_dir_all(root).map_err(|source| CatalogueError::storage(root, &source))?;
        Ok(Self {
            root: root.to_path_buf(),
            db: Db::open(root)?,
            bindings: Bindings::new(),
            fetches_network: true,
            broker,
            // The client's default transport, which reads a local directory mirror or fetches
            // over HTTP/HTTPS using tough's HTTP feature with rustls-platform-verifier.
            transport: Arc::new(tough::DefaultTransport::new()),
        })
    }

    /// Replaces the transport repositories are fetched through.
    pub fn set_transport(&mut self, transport: Arc<dyn tough::Transport + Send + Sync>) {
        self.transport = transport;
        self.fetches_network = true;
    }

    /// Sets whether this host may fetch a repository over the network.
    pub fn set_fetches_network(&mut self, fetches_network: bool) {
        self.fetches_network = fetches_network;
    }

    /// Returns true when this host can fetch a repository over the network.
    #[must_use]
    pub const fn fetches_network(&self) -> bool {
        self.fetches_network
    }

    /// Returns this host's root directory for the catalogue.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the durability the catalogue's records are written with.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the settings cannot be read.
    pub fn durability(&self) -> CatalogueResult<Durability> {
        self.db.durability()
    }

    /// Refuses a repository this host's transport cannot fetch.
    fn check_reachable(&self, enrolment: &Enrolment) -> CatalogueResult<()> {
        let scheme = enrolment.metadata_url.scheme();
        if scheme == "file" {
            return Ok(());
        }
        if self.fetches_network && (scheme == "http" || scheme == "https") {
            return Ok(());
        }
        Err(CatalogueError::UnavailableOffline {
            detail: format!(
                "{} is at {}, and this host has no network transport for a repository; enrol a \
                 local mirror of it instead",
                enrolment.id, enrolment.metadata_url
            ),
        })
    }

    // -----------------------------------------------------------------------------------------
    // Reads
    // -----------------------------------------------------------------------------------------

    /// Returns one enrolled repository with its identity and generation.
    fn enrolled(&self, id: &RepositoryId) -> CatalogueResult<Enrolled> {
        self.db
            .read(|records| records.enrolment(id))?
            .ok_or_else(|| not_enrolled(id))
    }

    /// Takes one enrolment's store lock, then reads the enrolment again under it.
    ///
    /// An enrolment read before the wait can be out of date once the lock is held: a sync in
    /// another process may have moved the repository on to a generation that no longer keeps the
    /// one read before, or removed it. What an operation relies on is read as it is once the lock
    /// is held.
    fn locked(&self, enrolled: &Enrolled) -> CatalogueResult<(Store, StoreLock, Enrolled)> {
        let store = Store::open(&self.root, &enrolled.key)?;
        let lock = store.lock()?;
        let current = self
            .db
            .read(|records| records.enrolment_by_key(&enrolled.key))?
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!(
                    "{} was removed while this waited for it",
                    enrolled.enrolment.id
                ),
            })?;
        Ok((store, lock, current))
    }

    /// Returns every enrolled repository, in a stable order.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the records cannot be read.
    pub fn repositories(&self) -> CatalogueResult<Vec<Enrolment>> {
        Ok(self
            .db
            .read(|records| records.enrolments())?
            .into_iter()
            .map(|enrolled| enrolled.enrolment)
            .collect())
    }

    /// Returns every enrolled repository with the generation it is on.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the records cannot be read.
    pub fn repository_views(&self) -> CatalogueResult<Vec<RepositoryView>> {
        Ok(self
            .db
            .read(|records| records.enrolments())?
            .into_iter()
            .map(repository_view)
            .collect())
    }

    /// Returns one enrolled repository, where it is enrolled.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the record cannot be read.
    pub fn repository(&self, id: &RepositoryId) -> CatalogueResult<Option<Enrolment>> {
        Ok(self
            .db
            .read(|records| records.enrolment(id))?
            .map(|enrolled| enrolled.enrolment))
    }

    /// Returns which generation one repository is on, where it has one.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the repository is not enrolled, and
    /// [`CatalogueError::StorageUnavailable`] when the record cannot be read.
    pub fn active(&self, id: &RepositoryId) -> CatalogueResult<Option<ActiveGeneration>> {
        Ok(self.enrolled(id)?.active)
    }

    /// Returns the directory of one enrolled repository.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the repository is not enrolled.
    pub fn store(&self, id: &RepositoryId) -> CatalogueResult<Store> {
        Ok(Store::at(&self.root, &self.enrolled(id)?.key))
    }

    /// Returns the directory an installed package's files live in, enrolled or not.
    #[must_use]
    pub fn store_of(&self, installation: &Installation) -> Store {
        Store::at(&self.root, &installation.enrolment)
    }

    /// Reads one repository's active index, offline.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the repository is not enrolled or has no
    /// activated generation.
    pub fn index(&self, id: &RepositoryId) -> CatalogueResult<CatalogueIndex> {
        self.current_index(id)?
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!("{id} has no activated generation yet"),
            })
    }

    /// Reads one repository's active index where it has one, offline.
    ///
    /// `None` is an answer: the repository is not enrolled, or it has no activated generation
    /// yet. A record or an index this host cannot read is not that answer, and is returned as
    /// the failure it is, so nobody concludes from a disk error that a catalogue is empty.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when a record or the index cannot be read,
    /// and [`CatalogueError::Integrity`] when the index is not the one its generation names.
    pub fn current_index(&self, id: &RepositoryId) -> CatalogueResult<Option<CatalogueIndex>> {
        self.read_kept(|records| {
            let Some(enrolled) = records.enrolment(id)? else {
                return Ok(None);
            };
            let Some(active) = enrolled.active else {
                return Ok(None);
            };
            Store::at(&self.root, &enrolled.key)
                .index(&active)
                .map(Some)
        })
    }

    /// Reads what depends on the index documents repositories keep, and reads again where the read
    /// failed while a repository stopped keeping a generation.
    ///
    /// A sync removes an index document only after the commit that stops naming it, and a read
    /// takes its records from one moment: records read just before that commit can name a document
    /// the sync then removes before the read opens it. The records read again name what is kept
    /// now. A read that fails while nothing it could have named was removed fails as it is, and one
    /// that keeps meeting syncs gives up after a few attempts rather than chasing them.
    fn read_kept<T>(
        &self,
        read: impl Fn(&Records<'_>) -> CatalogueResult<T>,
    ) -> CatalogueResult<T> {
        let mut attempts = 0;
        loop {
            let before = self.db.read(|records| records.kept_everywhere())?;
            match self.db.read(&read) {
                Ok(value) => return Ok(value),
                Err(error) => {
                    attempts += 1;
                    if attempts >= READ_ATTEMPTS
                        || self.db.read(|records| records.kept_everywhere())? == before
                    {
                        return Err(error);
                    }
                }
            }
        }
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

    /// Returns every installation, in a stable order.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the records cannot be read.
    pub fn installations(&self) -> CatalogueResult<Vec<Installation>> {
        self.db.read(|records| records.installations())
    }

    /// Returns one package's installation in one environment.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the record cannot be read.
    pub fn installation(
        &self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
    ) -> CatalogueResult<Option<Installation>> {
        self.db
            .read(|records| records.installation(environment_id, plugin_id))
    }

    /// Returns every installation in one environment, as a caller is told about it.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when a record or an index cannot be read.
    pub fn installation_views(
        &self,
        environment_id: EnvironmentId,
    ) -> CatalogueResult<Vec<InstallationView>> {
        self.read_kept(|records| {
            records
                .installations()?
                .into_iter()
                .filter(|installation| installation.environment_id == environment_id)
                .map(|installation| {
                    installation_view(&self.root, records, &self.bindings, installation)
                })
                .collect()
        })
    }

    /// Returns one installed package, as a caller is told about it.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the package is not installed here.
    pub fn installation_view(
        &self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
    ) -> CatalogueResult<InstallationView> {
        self.read_kept(|records| {
            let installation = records
                .installation(environment_id, plugin_id)?
                .ok_or_else(|| not_installed(plugin_id))?;
            installation_view(&self.root, records, &self.bindings, installation)
        })
    }

    /// Returns what one installed package may currently do.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the package is not installed here.
    pub fn capabilities(
        &self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
    ) -> CatalogueResult<Vec<CapabilityDecision>> {
        let installation = self
            .installation(environment_id, plugin_id)?
            .ok_or_else(|| not_installed(plugin_id))?;
        // The ceiling is the one the package was installed under, taken from the installation
        // rather than from the caller. A caller that could name the repository could name a wider
        // one and be told this package may do what that other repository permits.
        //
        // What the installed package asks for was recorded when it was installed. Reading the
        // current index instead would make an answer about an installed package depend on a
        // generation that may no longer carry it, which is the opposite of usable offline.
        Ok(ceiling::decide(
            &installation.requested,
            &installation.ceiling,
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
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
    ) -> CatalogueResult<BTreeSet<PluginCapability>> {
        Ok(self
            .capabilities(environment_id, plugin_id)?
            .into_iter()
            .filter(|decision| decision.permitted)
            .map(|decision| decision.capability)
            .collect())
    }

    /// Returns the administrator's disable policy.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the setting cannot be read.
    pub fn disable_policy(&self) -> CatalogueResult<DisablePolicy> {
        self.db.read(|records| records.disable_policy())
    }

    // -----------------------------------------------------------------------------------------
    // Live bindings
    // -----------------------------------------------------------------------------------------

    /// Returns every live binding, in the order they were made.
    #[must_use]
    pub fn bindings(&self) -> &[Binding] {
        self.bindings.all()
    }

    /// Opens a binding against what the catalogue holds for the entry's package.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the package is not installed here, and the
    /// refusal [`Bindings::bind`] decided.
    pub fn bind(
        &mut self,
        environment_id: EnvironmentId,
        entry: &IndexEntry,
        executable_path: &str,
    ) -> CatalogueResult<Binding> {
        let installation = self
            .installation(environment_id, &entry.plugin_id)?
            .ok_or_else(|| not_installed(&entry.plugin_id))?;
        self.bindings.bind(&installation, entry, executable_path)
    }

    /// Closes one binding.
    pub fn unbind(&mut self, binding_id: BindingId) {
        self.bindings.unbind(binding_id);
    }

    /// Returns what a revocation means for every live binding of that release.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the policy cannot be read.
    pub fn revocation_notices(&self, entry: &IndexEntry) -> CatalogueResult<Vec<RevocationNotice>> {
        Ok(self
            .bindings
            .revocation_notices(entry, self.disable_policy()?))
    }

    // -----------------------------------------------------------------------------------------
    // Receipts
    // -----------------------------------------------------------------------------------------

    /// Claims an action before it is performed, or returns the receipt it already has.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the claim cannot be recorded, in which
    /// case nothing may be performed under it.
    pub fn claim(&mut self, claim: &ReceiptClaim, now_ms: u64) -> CatalogueResult<Claimed> {
        self.db.receipts(|receipts| receipts.claim(claim, now_ms))
    }

    /// Settles a claimed action that stopped, as its [`Failure`] says.
    ///
    /// A failure is made only by [`Recording::failure`], from what the action committed before it
    /// stopped, so an action that left anything behind is never recorded as refused.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when it cannot be recorded.
    pub fn settle_failure(
        &mut self,
        key: &ReceiptKey,
        failure: &Failure,
        now_ms: u64,
    ) -> CatalogueResult<()> {
        self.db
            .receipts(|receipts| receipts.settle_failure(key, failure, now_ms))
    }

    /// Returns one action's receipt.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the record cannot be read.
    pub fn receipt(&self, key: &ReceiptKey) -> CatalogueResult<Option<ReceiptRecord>> {
        self.db.read(|records| records.receipt(key))
    }

    /// Settles as unknown every action a previous daemon left mid-dispatch.
    ///
    /// Called once when the daemon that owns this catalogue opens it, before it serves anything.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when it cannot be recorded.
    pub fn recover_interrupted(&mut self, now_ms: u64) -> CatalogueResult<usize> {
        self.db
            .receipts(|receipts| receipts.recover_interrupted(now_ms))
    }

    // -----------------------------------------------------------------------------------------
    // Repository changes
    // -----------------------------------------------------------------------------------------

    /// Enrols a repository, as the owner acting directly.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::enrol_with`] returns.
    pub fn enrol(&mut self, enrolment: Enrolment, confirmed: bool) -> CatalogueResult<()> {
        let owner = if confirmed {
            Owner::confirming()
        } else {
            Owner::acting()
        };
        self.enrol_with(enrolment, &mut Change::new(&owner))
            .map(|_| ())
    }

    /// Enrols a repository.
    ///
    /// A new root is always the owner's decision, so enrolment asks the change's authority whether
    /// it carries the owner's confirmation rather than inferring one from the caller's rights.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::OwnerConfirmationRequired`] when the owner has not confirmed the
    /// root, [`CatalogueError::InvalidArgument`] when the repository is already enrolled, and
    /// [`CatalogueError::StorageUnavailable`] when its directory cannot be made.
    pub fn enrol_with(
        &mut self,
        enrolment: Enrolment,
        change: &mut Change<'_>,
    ) -> CatalogueResult<RepositoryView> {
        change.authority.check()?;
        if !change.authority.owner_confirmed() {
            return Err(CatalogueError::OwnerConfirmationRequired {
                detail: format!(
                    "{} would be trusted against a root this host has not accepted before; \
                     adopting a root is the owner's decision",
                    enrolment.id
                ),
            });
        }
        // A fresh identity for this enrolment, whatever it is called. Its directory is made
        // before the row that names it, so a row never names a directory that is not there.
        let key = EnrolmentKey::generate()?;
        Store::open(&self.root, &key)?;
        committing(&mut self.db, change, |changes| {
            changes.enrol(&key, &enrolment)?;
            let view = RepositoryView {
                enrolment,
                active: None,
            };
            Ok((view.clone(), Transition::Enrolled(view)))
        })
    }

    /// Changes an enrolment, as the owner acting directly.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::update_enrolment_with`] returns.
    pub fn update_enrolment(
        &mut self,
        proposed: Enrolment,
        confirmed: bool,
    ) -> CatalogueResult<()> {
        let owner = if confirmed {
            Owner::confirming()
        } else {
            Owner::acting()
        };
        self.update_enrolment_with(proposed, &mut Change::new(&owner))
            .map(|_| ())
    }

    /// Changes an enrolment's budgets or ceiling, asking the owner for wider trust.
    ///
    /// A different root is refused rather than adopted here: replacing a root is two deliberate
    /// acts, removing the repository and enrolling it again, so a root never changes underneath a
    /// repository somebody is using.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the repository is not enrolled,
    /// [`CatalogueError::OwnerConfirmationRequired`] when the change needs confirming, and
    /// [`CatalogueError::InvalidArgument`] for a different root.
    pub fn update_enrolment_with(
        &mut self,
        proposed: Enrolment,
        change: &mut Change<'_>,
    ) -> CatalogueResult<RepositoryView> {
        change.authority.check()?;
        let confirmed = change.authority.owner_confirmed();
        committing(&mut self.db, change, |changes| {
            let current = changes
                .enrolment(&proposed.id)?
                .ok_or_else(|| not_enrolled(&proposed.id))?;
            current.enrolment.check_change(&proposed, confirmed)?;
            if current.enrolment.root != proposed.root {
                return Err(CatalogueError::InvalidArgument {
                    detail: format!(
                        "{} is enrolled against another root; remove it and enrol it again \
                             to adopt a different one",
                        proposed.id
                    ),
                });
            }
            let mut enrolment = proposed;
            // The pin is the pin's own decision, made through `pin`.
            enrolment.pinned_generation = current.enrolment.pinned_generation;
            changes.update_enrolment(&current.key, &enrolment)?;
            let view = RepositoryView {
                enrolment,
                active: current.active,
            };
            Ok((view.clone(), Transition::Updated(view)))
        })
    }

    /// Pins a repository to one generation, or removes its pin, as the owner acting directly.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::pin_with`] returns.
    pub fn pin(
        &mut self,
        id: &RepositoryId,
        generation: Option<RepositoryGeneration>,
    ) -> CatalogueResult<()> {
        self.pin_with(id, generation, &mut Change::new(&Owner::acting()))
            .map(|_| ())
    }

    /// Pins a repository to one generation, or removes its pin.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the repository is not enrolled, and
    /// [`CatalogueError::InvalidArgument`] when the pin names a generation that is not the one
    /// this repository is on.
    pub fn pin_with(
        &mut self,
        id: &RepositoryId,
        generation: Option<RepositoryGeneration>,
        change: &mut Change<'_>,
    ) -> CatalogueResult<RepositoryView> {
        change.authority.check()?;
        committing(&mut self.db, change, |changes| {
            let current = changes.enrolment(id)?.ok_or_else(|| not_enrolled(id))?;
            if let Some(generation) = generation {
                let active = current
                    .active
                    .ok_or_else(|| CatalogueError::InvalidArgument {
                        detail: format!("{id} has no activated generation to pin"),
                    })?;
                if active.generation != generation.get() {
                    return Err(CatalogueError::InvalidArgument {
                        detail: format!(
                            "{id} is on generation {} and the pin names {}; pinning operates \
                                 on the generation that is active",
                            active.generation,
                            generation.get()
                        ),
                    });
                }
            }
            let mut enrolment = current.enrolment;
            enrolment.pinned_generation = generation;
            changes.update_enrolment(&current.key, &enrolment)?;
            let view = RepositoryView {
                enrolment,
                active: current.active,
            };
            Ok((view.clone(), Transition::Pinned(view)))
        })
    }

    /// Removes a repository and stops trusting its root, as the owner acting directly.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::remove_repository_with`] returns.
    pub fn remove_repository(&mut self, id: &RepositoryId) -> CatalogueResult<Enrolment> {
        self.remove_repository_with(id, &mut Change::new(&Owner::acting()))
            .map(|(enrolment, _)| enrolment)
    }

    /// Removes a repository and stops trusting its root.
    ///
    /// Its directory is left where it is. A package installed from it is still installed, on the
    /// hash it was installed at, and removing those is `plugin.remove`'s decision rather than
    /// something that happens to somebody while they are removing a repository.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the repository is not enrolled.
    pub fn remove_repository_with(
        &mut self,
        id: &RepositoryId,
        change: &mut Change<'_>,
    ) -> CatalogueResult<(Enrolment, Vec<PluginId>)> {
        change.authority.check()?;
        committing(&mut self.db, change, |changes| {
            let current = changes.enrolment(id)?.ok_or_else(|| not_enrolled(id))?;
            let installed: Vec<PluginId> = changes
                .installations()?
                .into_iter()
                .filter(|installation| installation.enrolment == current.key)
                .map(|installation| installation.plugin_id)
                .collect();
            changes.remove_enrolment(&current.key)?;
            Ok((
                (current.enrolment.clone(), installed.clone()),
                Transition::Removed {
                    enrolment: current.enrolment,
                    installed,
                },
            ))
        })
    }

    /// Records the administrator's disable policy, as the owner acting directly.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when it cannot be recorded.
    pub fn set_disable_policy(&mut self, policy: DisablePolicy) -> CatalogueResult<()> {
        committing(
            &mut self.db,
            &mut Change::new(&Owner::acting()),
            |changes| {
                changes.set_disable_policy(policy)?;
                Ok(((), Transition::PolicyChanged(policy)))
            },
        )
    }

    // -----------------------------------------------------------------------------------------
    // Sync
    // -----------------------------------------------------------------------------------------

    /// Synchronises one repository's complete signed metadata snapshot, as the owner acting
    /// directly.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::sync_with`] returns.
    pub async fn sync(&mut self, id: &RepositoryId) -> CatalogueResult<SyncOutcome> {
        self.sync_with(id, &mut Change::new(&Owner::acting())).await
    }

    /// Synchronises one repository's complete signed metadata snapshot.
    ///
    /// # Errors
    ///
    /// Returns the refusal verification, the budgets, the admission or the generation check
    /// decided. Nothing is activated when it does, so the previous generation stays usable.
    pub async fn sync_with(
        &mut self,
        id: &RepositoryId,
        change: &mut Change<'_>,
    ) -> CatalogueResult<SyncOutcome> {
        let authority = change.authority;
        authority.check()?;
        let enrolled = self.enrolled(id)?;
        let store = Store::open(&self.root, &enrolled.key)?;
        let _lock = store.lock()?;
        self.check_reachable(&enrolled.enrolment)?;
        let ledger = ledger_of(&store, &enrolled)?;

        let transport = Arc::clone(&self.transport);
        // The client works in a private copy of the accepted trust checkpoint, never in the
        // checkpoint itself: a load that fails, is interrupted or is refused at its commit leaves
        // the accepted checkpoint exactly as it was. A reset a kept root advance still owes is
        // applied to the copy. The copy lives until this sync is over, because the client keeps
        // its time checkpoint there while it fetches the generation's payloads.
        let reset = self.db.read(|records| records.trust_reset(&enrolled.key))?;
        let working = store.working_datastore(reset)?;
        let verified = {
            let db = &mut self.db;
            let key = &enrolled.key;
            let accepted_root = &enrolled.enrolment.root;
            let rotated = Effect::Root(id.clone());
            trust::verify(
                &enrolled.enrolment,
                working.path(),
                &ledger,
                &transport,
                &mut |new_root| {
                    // A rotation is kept the moment verification arrives at it, before anything
                    // that follows can fail: a host that went back to the old root could have old
                    // trust restored by a repository that withheld the new one. Whether it resets
                    // the timestamp and snapshot floors is kept with it, so the next load applies
                    // the reset even though it starts from the new root.
                    let reset = trust::resets_floors(accepted_root, &new_root)?;
                    let pending = db.begin()?;
                    committed(authority, &rotated, move |permit| {
                        pending.run(permit, |changes| changes.set_root(key, &new_root, reset))
                    })
                },
            )
            .await?
        };
        authority.check()?;

        // The index is kept in its canonical rendering, named by that rendering's digest, which is
        // also what one generation number is compared by.
        let rendered = verified
            .index
            .canonical_json()
            .map_err(|source| CatalogueError::Integrity {
                detail: format!("the index could not be rendered: {source}"),
            })?
            .into_bytes();
        let index_digest = PayloadDigest::of(&rendered);
        let arriving = Retained {
            generation: verified.generation.get(),
            index_bytes: rendered.len() as u64,
        };

        // What the repository keeps is decided before anything this sync verified is kept. The
        // checkpoint, at the most it counts while it is published, has to fit beside the new
        // generation, which is what stays if the sync succeeds, and beside the generation in use,
        // which is what stays if it goes no further; generations it is not on make room for the
        // second first. A sync that cannot fit either way is refused here, with the accepted
        // checkpoint and the generation in use as they were.
        let checkpoint = store.publication_peak(&working)?;
        self.retain_before_publication(&store, &enrolled.key, id, checkpoint, arriving, authority)?;

        // The metadata verified, so it becomes the accepted checkpoint now, in a commit of its
        // own: trust progress is kept whatever the generation checks, the mirror or the index
        // activation that follow decide, and the reset the checkpoint carries is no longer owed.
        {
            let key = &enrolled.key;
            let pending = self.db.begin()?;
            committed(authority, &Effect::Checkpoint(id.clone()), |permit| {
                store.publish_checkpoint(permit, &working)?;
                pending
                    .run(permit, |changes| {
                        #[cfg(test)]
                        if crate::store::publish_fault::reset_fails() {
                            return Err(CatalogueError::StorageUnavailable {
                                detail: "the reset was made not to settle".to_owned(),
                            });
                        }
                        changes.clear_trust_reset(key)
                    })
                    .map_err(|error| match error {
                        uncertain @ CatalogueError::PublicationUncertain { .. } => uncertain,
                        other => CatalogueError::PublicationUncertain {
                            detail: format!(
                                "the trust checkpoint was published and its reset could not be \
                                 cleared: {other}"
                            ),
                        },
                    })
            })?;
        }

        trust::check_generation(
            verified.generation,
            index_digest,
            accepted_of(enrolled.active),
            enrolled.enrolment.pinned_generation,
        )?;

        // A full mirror runs before the index is activated. Section 11 asks for the whole
        // generation inside the approved budget, so a mirror that cannot be completed leaves the
        // previous generation in place rather than activating a new index it has no payloads for.
        let mut mirrored = 0usize;
        if enrolled.enrolment.budgets.full_offline_mirror {
            let fetched = self.mirror(&enrolled, &store, &verified, authority).await;
            // The client moved its time checkpoint on while it fetched. That is kept whatever the
            // mirror did, so a clock later set back to a time in between is refused.
            let kept = committed(authority, &Effect::Checkpoint(id.clone()), |permit| {
                store.publish_time_checkpoint(permit, &working)
            });
            mirrored = fetched?;
            kept?;
            authority.check()?;
        }

        let outcome = SyncOutcome {
            generation: verified.generation,
            entries: verified.index.entries.len(),
            index_bytes: verified.index_bytes,
            mirrored_payloads: mirrored,
            delegations: verified
                .delegations
                .iter()
                .map(|scope| (scope.role.clone(), scope.publisher.clone()))
                .collect(),
        };
        let entries = verified.index.entries.len() as u64;
        let versions = verified.versions;
        let key = enrolled.key.clone();
        let accepted_targets = verified.accepted_targets(&enrolled.enrolment.targets_url)?;
        // The index is written whole and flushed before the row that names it commits, in a
        // commit of its own: a document nothing names yet is what a later failure leaves behind,
        // and the receipt says so.
        let (digest, bytes) = committed(authority, &Effect::Index(id.clone()), |permit| {
            store.write_index(permit, &rendered)
        })?;
        let checkpoint = store.checkpoint_bytes()?;
        let synced = committing(&mut self.db, change, |changes| {
            // Read again: the repository may have been removed, enrolled again or moved to
            // another generation while this sync fetched. Only the enrolment this sync
            // verified is changed, and only forward from the generation it holds now.
            let current =
                changes
                    .enrolment_by_key(&key)?
                    .ok_or_else(|| CatalogueError::NotFound {
                        detail: format!("{id} was removed while it synchronised"),
                    })?;
            trust::check_generation(
                verified.generation,
                digest,
                accepted_of(current.active),
                current.enrolment.pinned_generation,
            )?;
            let active = ActiveGeneration {
                generation: verified.generation.get(),
                index_digest: digest,
                index_bytes: bytes,
                entries,
                versions,
            };
            changes.activate(&key, &active, &accepted_targets)?;
            // The generations it no longer keeps go in the same commit that moves it on, the
            // oldest first, decided from the records and the budgets as they are now.
            let forgotten = BudgetLedger::new(current.enrolment.budgets).plan_retention(
                checkpoint,
                &retained(&changes.kept_generations(&key)?),
                Some(Retained {
                    generation: active.generation,
                    index_bytes: active.index_bytes,
                }),
            )?;
            for generation in forgotten {
                changes.forget_generation(&key, generation)?;
            }
            let repository = RepositoryView {
                enrolment: current.enrolment,
                active: Some(active),
            };
            Ok((
                outcome.clone(),
                Transition::Synced {
                    repository,
                    outcome,
                },
            ))
        })?;
        // Best effort: the sync has happened whatever this does. A document it cannot remove is
        // removed by the next sync before it keeps anything, or stops that sync.
        let _ = self.remove_unnamed_indexes(&store, &enrolled.key, id, authority);
        Ok(synced)
    }

    /// Checks what a repository keeps before a sync publishes the checkpoint it verified, and makes
    /// room for it beside the generation in use.
    ///
    /// Both outcomes are decided from the records as they are under the store's lock: the
    /// checkpoint beside the new generation, and the checkpoint beside the generation in use, which
    /// is what stays if the sync goes no further. The generations the second needs gone are
    /// removed in a commit of their own, decided again inside it, and their index documents after
    /// it, before the checkpoint is published into the room they held. Nothing is written when
    /// nothing has to go.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::ResourceLimit`] naming the retained metadata when either outcome
    /// is past the budget, and [`CatalogueError::NotFound`] when the repository was removed.
    fn retain_before_publication(
        &mut self,
        store: &Store,
        key: &EnrolmentKey,
        id: &RepositoryId,
        checkpoint: u64,
        arriving: Retained,
        authority: &dyn Authority,
    ) -> CatalogueResult<()> {
        let removed = || CatalogueError::NotFound {
            detail: format!("{id} was removed while it synchronised"),
        };
        let in_use = |current: &Enrolled| {
            current.active.map(|active| Retained {
                generation: active.generation,
                index_bytes: active.index_bytes,
            })
        };
        // An index document no kept generation names, left by a sync that stopped, is removed
        // before anything is decided. The records no longer count it, so one that cannot be removed
        // stops this sync rather than holding room the budget cannot see.
        self.remove_unnamed_indexes(store, key, id, authority)?;
        let forget = self.db.read(|records| {
            let current = records.enrolment_by_key(key)?.ok_or_else(removed)?;
            let kept = retained(&records.kept_generations(key)?);
            let ledger = BudgetLedger::new(current.enrolment.budgets);
            ledger.plan_retention(checkpoint, &kept, Some(arriving))?;
            Ok(ledger.plan_retention(checkpoint, &kept, in_use(&current))?)
        })?;
        if forget.is_empty() {
            return Ok(());
        }
        let pending = self.db.begin()?;
        committed(authority, &Effect::Records, |permit| {
            pending.run(permit, |changes| {
                let current = changes.enrolment_by_key(key)?.ok_or_else(removed)?;
                let kept = retained(&changes.kept_generations(key)?);
                let forget = BudgetLedger::new(current.enrolment.budgets).plan_retention(
                    checkpoint,
                    &kept,
                    in_use(&current),
                )?;
                for generation in forget {
                    changes.forget_generation(key, generation)?;
                }
                Ok(())
            })
        })?;
        // The room those generations held is what the checkpoint is published into, so their
        // documents have to be gone before it is.
        self.remove_unnamed_indexes(store, key, id, authority)
    }

    /// Removes every index document no generation this repository keeps names.
    ///
    /// The records that named a generation it stopped keeping are already gone, so no reader is
    /// left holding a generation whose index has disappeared, and a document a sync wrote before
    /// it stopped is removed the same way.
    ///
    /// # Errors
    ///
    /// Returns what reading the records or the directory, or removing a document, returns.
    fn remove_unnamed_indexes(
        &self,
        store: &Store,
        key: &EnrolmentKey,
        id: &RepositoryId,
        authority: &dyn Authority,
    ) -> CatalogueResult<()> {
        let kept = self.db.read(|records| records.kept_generations(key))?;
        let unnamed: Vec<PayloadDigest> = store
            .index_documents()?
            .into_keys()
            .filter(|digest| !kept.iter().any(|kept| kept.index_digest == *digest))
            .collect();
        if unnamed.is_empty() {
            return Ok(());
        }
        committed(authority, &Effect::Forgotten(id.clone()), |permit| {
            store.remove_index_documents(permit, &unnamed)
        })
    }

    /// Fetches every payload the index references, inside the approved budget.
    ///
    /// The whole set is measured first. Fetching one object at a time and making room for each in
    /// turn would evict the ones already fetched, and the loop could finish "successfully" with
    /// part of a generation cached, which is not a mirror.
    async fn mirror(
        &mut self,
        enrolled: &Enrolled,
        store: &Store,
        verified: &VerifiedGeneration,
        authority: &dyn Authority,
    ) -> CatalogueResult<usize> {
        let mut wanted: BTreeMap<PayloadDigest, (String, u64)> = BTreeMap::new();
        for entry in &verified.index.entries {
            let prefix = format!(
                "{PACKAGE_PREFIX}{}/{}/{}",
                entry.publisher_id, entry.plugin_name, entry.version
            );
            wanted.insert(
                entry.manifest_digest,
                (
                    format!("{prefix}/{MANIFEST_FILE}"),
                    entry.manifest_size_bytes.get(),
                ),
            );
            for payload in &entry.payloads {
                wanted.insert(
                    payload.digest,
                    (
                        format!("{prefix}/{}", payload.path.as_str()),
                        payload.size_bytes.get(),
                    ),
                );
            }
        }

        // Everything the mirror will hold, including what it already holds, against the budget.
        let held = store.cached_payloads()?;
        let needed: u64 = wanted
            .iter()
            .filter(|(digest, _)| !held.contains_key(*digest))
            .fold(0u64, |total, (_, (_, size))| total.saturating_add(*size));
        let mirror_set: BTreeSet<PayloadDigest> = wanted.keys().copied().collect();
        reclaim(
            &mut self.db,
            authority,
            &self.bindings,
            &*self.broker,
            &enrolled.key,
            store,
            needed,
            "the full offline mirror",
            &mirror_set,
        )?;

        // What this pass has seen with its own eyes, either verified where it lay or written
        // here. Hashing each object once a sync is the cost of the guarantee; hashing it twice is
        // not, and the store is locked for the whole pass.
        let mut verified_here: BTreeSet<PayloadDigest> = BTreeSet::new();
        let mut fetched = 0usize;
        for (digest, (target, length)) in &wanted {
            if store.holds_payload(*digest, *length)? {
                verified_here.insert(*digest);
                continue;
            }
            let ledger = ledger_of(store, enrolled)?;
            let bytes = verified
                .read_target(
                    target,
                    TargetRecord {
                        digest: *digest,
                        length: *length,
                    },
                    &ledger,
                )
                .await?;
            committed(authority, &Effect::Payload(*digest), |permit| {
                store.cache_payload(permit, *digest, &bytes)
            })?;
            verified_here.insert(*digest);
            fetched += 1;
        }

        // A mirror reports success only when the whole set is here, in the bytes the generation
        // names. An object whose contents no longer hash to its name is a gap in the mirror, not
        // a payload, so it is reported the same way a missing one is.
        for (digest, (_, length)) in &wanted {
            if !verified_here.contains(digest) && !store.holds_payload(*digest, *length)? {
                return Err(CatalogueError::UnavailableOffline {
                    detail: format!(
                        "the full offline mirror is missing {digest}; the previous generation \
                         stays usable"
                    ),
                });
            }
        }
        Ok(fetched)
    }

    // -----------------------------------------------------------------------------------------
    // Packages
    // -----------------------------------------------------------------------------------------

    /// Fetches and verifies every payload of one package in one repository, as the owner acting
    /// directly.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::activate_package_scoped_with`] returns.
    pub async fn activate_package(
        &mut self,
        id: &RepositoryId,
        plugin_id: &PluginId,
        version: &PackageVersion,
        reason: FetchReason,
    ) -> CatalogueResult<PayloadDigest> {
        self.activate_package_scoped_with(
            id,
            None,
            plugin_id,
            version,
            None,
            reason,
            &Owner::acting(),
        )
        .await
    }

    /// Fetches and verifies every payload of one package, scoped to an installation, as the owner
    /// acting directly.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::activate_package_scoped_with`] returns.
    pub async fn activate_package_scoped(
        &mut self,
        id: &RepositoryId,
        environment_id: Option<EnvironmentId>,
        plugin_id: &PluginId,
        version: &PackageVersion,
        package_hash: Option<PayloadDigest>,
        reason: FetchReason,
    ) -> CatalogueResult<PayloadDigest> {
        self.activate_package_scoped_with(
            id,
            environment_id,
            plugin_id,
            version,
            package_hash,
            reason,
            &Owner::acting(),
        )
        .await
    }

    /// Activates one package: fetches every payload, verifies all of them, then makes it visible.
    ///
    /// Package activation is independent of index activation, and atomic on its own. A package
    /// whose payloads do not all verify is not activated, and whatever was installed before stays
    /// installed and usable.
    ///
    /// # Errors
    ///
    /// Returns the refusal verification, the budgets, the admission or the package rules decided.
    // Every argument names one part of the identity an activation is authorised against, and
    // folding them into a struct would hide which of them a caller left unset.
    #[allow(clippy::too_many_arguments)]
    pub async fn activate_package_scoped_with(
        &mut self,
        id: &RepositoryId,
        environment_id: Option<EnvironmentId>,
        plugin_id: &PluginId,
        version: &PackageVersion,
        package_hash: Option<PayloadDigest>,
        reason: FetchReason,
        authority: &dyn Authority,
    ) -> CatalogueResult<PayloadDigest> {
        authority.check()?;
        let (store, _lock, enrolled) = self.locked(&self.enrolled(id)?)?;
        self.activate_locked(
            &enrolled,
            &store,
            environment_id,
            plugin_id,
            version,
            package_hash,
            reason,
            authority,
        )
        .await
        .map(|package| package.digest())
    }

    #[allow(clippy::too_many_arguments)]
    async fn activate_locked(
        &mut self,
        enrolled: &Enrolled,
        store: &Store,
        environment_id: Option<EnvironmentId>,
        plugin_id: &PluginId,
        version: &PackageVersion,
        package_hash: Option<PayloadDigest>,
        reason: FetchReason,
        authority: &dyn Authority,
    ) -> CatalogueResult<ReadyPackage> {
        authority.check()?;
        // Which of the three reasons section 11 names this is, and whether it holds. A package is
        // not fetched because something matched; it is fetched because somebody installed it,
        // enabled it, or already did both and an application it recognises started.
        self.check_reason(
            enrolled,
            environment_id,
            plugin_id,
            version,
            package_hash,
            reason,
        )?;
        // A package already here is used only after every file its manifest declares is checked
        // where it lies. Its name is not the package: one that is incomplete or altered is fetched
        // again and replaced, and one this host cannot read is its disk's failure.
        if let Some(hash) = package_hash
            && let PackageCheck::Complete(package) = store.check_package(hash)?
        {
            return Ok(*package);
        }
        let active = enrolled.active.ok_or_else(|| CatalogueError::NotFound {
            detail: format!("{} has no activated generation yet", enrolled.enrolment.id),
        })?;
        let index = store.index(&active)?;
        let entry =
            index
                .find(plugin_id, version)
                .cloned()
                .ok_or_else(|| CatalogueError::NotFound {
                    detail: format!("{plugin_id} {version} is not in this repository's index"),
                })?;
        if let Some(expected_hash) = package_hash
            && entry.manifest_digest != expected_hash
        {
            return Err(CatalogueError::UnavailableOffline {
                detail: format!(
                    "the requested package hash {expected_hash} does not match {plugin_id} \
                     {version} ({}) in the active catalogue generation",
                    entry.manifest_digest
                ),
            });
        }
        let subject = format!("{} {}", entry.plugin_id, entry.version);
        // The same package reached through the entry: the entry is a signed statement about this
        // hash, and it has to agree with the manifest the hash names before anything relies on it.
        if let PackageCheck::Complete(package) = store.check_package(entry.manifest_digest)? {
            extract::reconcile(&entry, package.manifest(), &subject)?;
            return Ok(*package);
        }
        extract::check_declared(&entry, &ledger_of(store, enrolled)?)?;

        // The package is staged whole, beside everything the cache and the packages already here
        // hold, and what it still has to fetch is cached on the way. Room for both is made before
        // anything is fetched, so the staging is counted at its largest rather than discovered
        // part way, and nothing this package consists of is what is removed to make it.
        let package: BTreeSet<PayloadDigest> = std::iter::once(entry.manifest_digest)
            .chain(entry.payloads.iter().map(|payload| payload.digest))
            .collect();
        let cached = store.cached_payloads()?;
        let mut fetching: BTreeSet<PayloadDigest> = BTreeSet::new();
        let (mut staging, mut fetched) = (0u64, 0u64);
        for (digest, size) in std::iter::once((entry.manifest_digest, entry.manifest_size_bytes))
            .chain(
                entry
                    .payloads
                    .iter()
                    .map(|payload| (payload.digest, payload.size_bytes)),
            )
        {
            staging = staging.saturating_add(size.get());
            if cached.get(&digest) != Some(&size.get()) && fetching.insert(digest) {
                fetched = fetched.saturating_add(size.get());
            }
        }
        reclaim(
            &mut self.db,
            authority,
            &self.bindings,
            &*self.broker,
            &enrolled.key,
            store,
            staging.saturating_add(fetched),
            &subject,
            &package,
        )?;

        let prefix = format!(
            "{PACKAGE_PREFIX}{}/{}/{}",
            entry.publisher_id, entry.plugin_name, entry.version
        );

        // The staging directory is this attempt's own; dropping it on any early return removes it.
        let mut staged = store.stage_package(entry.manifest_digest)?;
        let manifest = self
            .fetch(
                enrolled,
                store,
                &format!("{prefix}/{MANIFEST_FILE}"),
                entry.manifest_digest,
                entry.manifest_size_bytes.get(),
                &package,
                reason,
                authority,
            )
            .await?;
        let manifest_path =
            kr_plugin_sdk::paths::PackagePath::new(MANIFEST_FILE).map_err(|source| {
                CatalogueError::UnsafePackage {
                    detail: format!("{MANIFEST_FILE} is not a package path: {source}"),
                }
            })?;
        staged.write(&manifest_path, &manifest)?;
        for payload in &entry.payloads {
            let target = format!("{prefix}/{}", payload.path.as_str());
            let relative = extract::relative_target(&prefix, &target)?;
            let bytes = self
                .fetch(
                    enrolled,
                    store,
                    &target,
                    payload.digest,
                    payload.size_bytes.get(),
                    &package,
                    reason,
                    authority,
                )
                .await?;
            staged.write(&relative, &bytes)?;
        }

        let staged_bytes = staged.staged_bytes();
        let staged_files = staged.staged_files();
        let checked = extract::check_staged(staged.path(), &subject)?;
        extract::check_actual(
            &entry,
            &checked,
            staged_bytes,
            staged_files,
            &ledger_of(store, enrolled)?,
        )?;
        committed(
            authority,
            &Effect::Package(entry.manifest_digest),
            move |permit| staged.activate(permit),
        )?;
        // What was moved into place is read back and checked like any package already here, so
        // the only way to a ready package is through that check.
        match store.check_package(entry.manifest_digest)? {
            PackageCheck::Complete(package) => Ok(*package),
            PackageCheck::Missing { detail } | PackageCheck::Corrupt { detail } => {
                Err(CatalogueError::PublicationUncertain {
                    detail: format!(
                        "{subject} was moved into place and does not read back whole: {detail}"
                    ),
                })
            }
        }
    }

    /// Fetches one payload by content hash, out of the generation this host accepted.
    ///
    /// `package` is everything the package being staged consists of, which room is never made by
    /// removing.
    #[allow(clippy::too_many_arguments)]
    async fn fetch(
        &mut self,
        enrolled: &Enrolled,
        store: &Store,
        target: &str,
        digest: PayloadDigest,
        length: u64,
        package: &BTreeSet<PayloadDigest>,
        reason: FetchReason,
        authority: &dyn Authority,
    ) -> CatalogueResult<Vec<u8>> {
        // A cached object that is not cached, or is not the length declared for it, or whose bytes
        // no longer hash to its name, is fetched again, bounded by the declared length. A store
        // that cannot be read is neither: it is a failure of this host's own disk, and reporting
        // it as an absent payload would send a person looking at their repository instead of
        // their filesystem.
        match store.read_payload(digest, length) {
            Ok(bytes) => return Ok(bytes),
            Err(CatalogueError::UnavailableOffline { .. } | CatalogueError::Integrity { .. }) => {}
            Err(other) => return Err(other),
        }
        let id = &enrolled.enrolment.id;
        let accepted = enrolled
            .active
            .ok_or_else(|| CatalogueError::UnavailableOffline {
                detail: format!(
                    "{target} is not cached here and {id} has no activated generation to fetch it \
                     from for an {}",
                    reason.as_str()
                ),
            })?;
        self.check_reachable(&enrolled.enrolment)?;

        // The payload is fetched as the accepted generation named it, from where that generation
        // said it is, and nothing the repository has published since is read. A generation this
        // host accepted, or pinned, stays installable while its bytes are there, and a newer one
        // never stands in for it: the newer generation is a sync's to verify and accept.
        let accepted_target = self
            .db
            .read(|records| records.accepted_target(&enrolled.key, accepted.generation, target))?
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!("{target} is not in {id}'s accepted generation"),
            })?;
        if accepted_target.record.digest != digest {
            return Err(CatalogueError::Integrity {
                detail: format!(
                    "{target} is pinned at {} and was asked for by {digest}; a payload is fetched \
                     by content hash",
                    accepted_target.record.digest
                ),
            });
        }
        reclaim(
            &mut self.db,
            authority,
            &self.bindings,
            &*self.broker,
            &enrolled.key,
            store,
            accepted_target.record.length,
            target,
            package,
        )?;
        let bytes = trust::fetch_accepted(
            &self.transport,
            &accepted_target,
            &ledger_of(store, enrolled)?,
        )
        .await?;
        committed(authority, &Effect::Payload(digest), |permit| {
            store.cache_payload(permit, digest, &bytes)
        })?;
        Ok(bytes)
    }

    /// Checks that a fetch has one of the three reasons section 11 names, and that it holds.
    fn check_reason(
        &self,
        enrolled: &Enrolled,
        environment_id: Option<EnvironmentId>,
        plugin_id: &PluginId,
        version: &PackageVersion,
        package_hash: Option<PayloadDigest>,
        reason: FetchReason,
    ) -> CatalogueResult<()> {
        let id = &enrolled.enrolment.id;
        match reason {
            // The owner asked for it. Whether they may is the ceiling's and the grant's decision,
            // which `install` makes before it gets here.
            FetchReason::ExplicitInstall | FetchReason::ExplicitEnable => Ok(()),
            FetchReason::FullOfflineMirror => {
                if enrolled.enrolment.budgets.full_offline_mirror {
                    Ok(())
                } else {
                    Err(CatalogueError::UnavailableOffline {
                        detail: format!(
                            "{id} does not keep a full offline mirror, so a payload is fetched on \
                             an explicit install or enable or an already-authorised activation"
                        ),
                    })
                }
            }
            // An activation fetches only what this environment already installed and enabled.
            // Anything else would make a matching application enough to pull bytes nobody asked
            // this host to hold.
            FetchReason::AuthorisedActivation => {
                // An unnamed environment or package hash would make this reason its own authority:
                // any enabled installation of the plugin anywhere would answer for the one the
                // caller has. The activation names the exact installation it claims, or it is not
                // an authorised activation at all.
                let (Some(environment), Some(hash)) = (environment_id, package_hash) else {
                    return Err(CatalogueError::InvalidArgument {
                        detail: format!(
                            "an already-authorised activation of {plugin_id} {version} names the \
                             environment and the exact package hash it was authorised for"
                        ),
                    });
                };
                let authorised =
                    self.installation(environment, plugin_id)?
                        .is_some_and(|installation| {
                            installation.enrolment == enrolled.key
                                && installation.version == *version
                                && installation.enabled
                                && installation.package_digest == hash
                        });
                if authorised {
                    Ok(())
                } else {
                    Err(CatalogueError::UnavailableOffline {
                        detail: format!(
                            "{plugin_id} {version} is not installed and enabled for {id} in the \
                             requested environment on this package hash, so a matching application \
                             does not authorise fetching its payloads"
                        ),
                    })
                }
            }
        }
    }

    /// Installs one verified package into one environment, as the owner acting directly.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::install_with`] returns.
    pub async fn install(
        &mut self,
        id: &RepositoryId,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
        version: &PackageVersion,
        expected_digest: PayloadDigest,
        grant: InstallationGrant,
    ) -> CatalogueResult<Installation> {
        self.install_with(
            id,
            environment_id,
            plugin_id,
            version,
            expected_digest,
            grant,
            &mut Change::new(&Owner::acting()),
        )
        .await
        .map(|view| view.installation)
    }

    /// Installs one verified package into one environment.
    ///
    /// The package's payloads are fetched by content hash, verified as a set and activated
    /// atomically before anything is recorded as installed, so a failed installation leaves
    /// whatever was installed before exactly as it was.
    ///
    /// # Errors
    ///
    /// Returns the refusal verification, the budgets, the admission, the package rules or the
    /// ceiling decided.
    // The package identity, the environment, the grant and the change each have to be named
    // separately here, because an installation is authorised against all four.
    #[allow(clippy::too_many_arguments)]
    pub async fn install_with(
        &mut self,
        id: &RepositoryId,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
        version: &PackageVersion,
        expected_digest: PayloadDigest,
        grant: InstallationGrant,
        change: &mut Change<'_>,
    ) -> CatalogueResult<InstallationView> {
        let authority = change.authority;
        authority.check()?;
        let (store, _lock, enrolled) = self.locked(&self.enrolled(id)?)?;
        let active = enrolled.active.ok_or_else(|| CatalogueError::NotFound {
            detail: format!("{id} has no activated generation yet"),
        })?;
        let index = store.index(&active)?;
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
        let previous = self.installation(environment_id, plugin_id)?;
        check_installation(
            &entry,
            &enrolled.enrolment.ceiling,
            &grant,
            previous.as_ref(),
        )?;

        let package = self
            .activate_locked(
                &enrolled,
                &store,
                Some(environment_id),
                plugin_id,
                version,
                Some(entry.manifest_digest),
                FetchReason::ExplicitInstall,
                authority,
            )
            .await?;
        // The entry decided what to fetch. What is installed is what the package's own manifest
        // says, and the two have to agree, whether the package was fetched now or was already here.
        extract::reconcile(
            &entry,
            package.manifest(),
            &format!("{plugin_id} {version}"),
        )?;

        let root = self.root.clone();
        let bindings = &self.bindings;
        let key = enrolled.key.clone();
        committing(&mut self.db, change, |changes| {
            // Read again, inside the commit. The enrolment may have changed while the package
            // was fetched, and the installation it replaces may have been pinned or granted
            // in the meantime: the decision is made against what is there now.
            let current =
                changes
                    .enrolment_by_key(&key)?
                    .ok_or_else(|| CatalogueError::NotFound {
                        detail: format!("{id} was removed while {plugin_id} was installed"),
                    })?;
            let previous = changes.installation(environment_id, plugin_id)?;
            check_installation(
                &entry,
                &current.enrolment.ceiling,
                &grant,
                previous.as_ref(),
            )?;
            // The ceiling travels with the installation. What this package may do was decided
            // against the repository's ceiling as it stood now, and that answer must not move
            // when the repository's enrolment changes or is removed.
            let mut installation = Installation::from_package(
                &package,
                key.clone(),
                id.clone(),
                environment_id,
                grant.clone(),
                current.enrolment.ceiling.clone(),
            );
            if let Some(previous) = &previous {
                installation.enabled = previous.enabled;
                installation.pinned =
                    previous.pinned && previous.package_digest == entry.manifest_digest;
            }
            changes.install(&installation)?;
            let view = installation_view(&root, changes, bindings, installation)?;
            Ok((view.clone(), Transition::Installed(view)))
        })
    }

    /// Enables or disables an installed package, as the owner acting directly.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::set_enabled_with`] returns.
    pub async fn set_enabled(
        &mut self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
        enabled: bool,
    ) -> CatalogueResult<Installation> {
        self.set_enabled_with(
            environment_id,
            plugin_id,
            enabled,
            &mut Change::new(&Owner::acting()),
        )
        .await
        .map(|view| view.installation)
    }

    /// Enables or disables an installed package.
    ///
    /// Enabling fetches the package's payloads where they are not cached, which is one of the
    /// three reasons section 11 names. Disabling fetches nothing.
    ///
    /// # Errors
    ///
    /// Returns the refusal the installation, the admission, or the fetch decided.
    pub async fn set_enabled_with(
        &mut self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
        enabled: bool,
        change: &mut Change<'_>,
    ) -> CatalogueResult<InstallationView> {
        let authority = change.authority;
        authority.check()?;
        let installation = self
            .installation(environment_id, plugin_id)?
            .ok_or_else(|| not_installed(plugin_id))?;
        if enabled {
            let enrolled = self
                .db
                .read(|records| records.enrolment_by_key(&installation.enrolment))?;
            match enrolled {
                Some(enrolled) => {
                    let (store, _lock, enrolled) = self.locked(&enrolled)?;
                    self.activate_locked(
                        &enrolled,
                        &store,
                        Some(environment_id),
                        plugin_id,
                        &installation.version,
                        Some(installation.package_digest),
                        FetchReason::ExplicitEnable,
                        authority,
                    )
                    .await?;
                }
                None => {
                    // The repository was removed. The package is still installed on the hash it
                    // was installed at, and its files are in the directory that enrolment left
                    // behind. There is nothing to fetch and no root to verify a fetch against, so
                    // every file the package declares is checked where it lies: one that is gone
                    // or altered is section 11's own answer, because nothing can fetch it again,
                    // and one this host cannot read is its disk's failure.
                    let store = self.store_of(&installation);
                    let _lock = store.lock()?;
                    match store.check_package(installation.package_digest)? {
                        PackageCheck::Complete(_) => {}
                        PackageCheck::Missing { detail } | PackageCheck::Corrupt { detail } => {
                            return Err(CatalogueError::UnavailableOffline {
                                detail: format!(
                                    "{plugin_id} {} is installed from {}, which is no longer \
                                     enrolled, and the package held here is not complete: {detail}",
                                    installation.version, installation.repository
                                ),
                            });
                        }
                    }
                }
            }
        }
        let root = self.root.clone();
        let bindings = &self.bindings;
        let digest = installation.package_digest;
        committing(&mut self.db, change, |changes| {
            let mut current = changes
                .installation(environment_id, plugin_id)?
                .ok_or_else(|| not_installed(plugin_id))?;
            // What was checked above is this hash. An installation that moved to another one
            // while it was checked is a different decision.
            if current.package_digest != digest {
                return Err(CatalogueError::InvalidArgument {
                    detail: format!(
                        "{plugin_id} moved to {} while it was being enabled",
                        current.package_digest
                    ),
                });
            }
            current.enabled = enabled;
            changes.install(&current)?;
            let view = installation_view(&root, changes, bindings, current)?;
            Ok((view.clone(), Transition::Changed(view)))
        })
    }

    /// Replaces one installation's grant, as the owner acting directly.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::set_grant_with`] returns.
    pub fn set_grant(
        &mut self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
        grant: InstallationGrant,
    ) -> CatalogueResult<Installation> {
        let installed = self
            .installation(environment_id, plugin_id)?
            .ok_or_else(|| not_installed(plugin_id))?;
        self.set_grant_with(
            environment_id,
            plugin_id,
            installed.package_digest,
            grant,
            &mut Change::new(&Owner::confirming()),
        )
        .map(|view| view.installation)
    }

    /// Replaces one installation's grant, for the exact package it names.
    ///
    /// A grant is about the release the owner was shown, so it names that release's package hash
    /// and is refused, inside the commit, when the installation is on another one. A grant may
    /// name only capabilities the package asks for. It may name fewer: withdrawing one leaves the
    /// installation in place and the capability unavailable, which is what withdrawing is. A grant
    /// that adds anything is the owner's decision, so the change's authority has to carry the
    /// owner's confirmation of it.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the package is not installed here,
    /// [`CatalogueError::InvalidArgument`] when it is installed at another hash,
    /// [`CatalogueError::GrantRequired`] when the new set names a capability the package does not
    /// ask for, and [`CatalogueError::OwnerConfirmationRequired`] for a wider grant without it.
    pub fn set_grant_with(
        &mut self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
        package_digest: PayloadDigest,
        grant: InstallationGrant,
        change: &mut Change<'_>,
    ) -> CatalogueResult<InstallationView> {
        change.authority.check()?;
        let confirmed = change.authority.owner_confirmed();
        let root = self.root.clone();
        let bindings = &self.bindings;
        committing(&mut self.db, change, |changes| {
            let mut current = changes
                .installation(environment_id, plugin_id)?
                .ok_or_else(|| not_installed(plugin_id))?;
            if current.package_digest != package_digest {
                return Err(CatalogueError::InvalidArgument {
                    detail: format!(
                        "{plugin_id} is installed at {} and this grant is for {package_digest}",
                        current.package_digest
                    ),
                });
            }
            for capability in grant.capabilities() {
                if !current
                    .requested
                    .iter()
                    .any(|request| request.capability == capability)
                {
                    return Err(CatalogueError::GrantRequired {
                        capability,
                        requirement: format!(
                            "a package that asks for it: {plugin_id} does not request \
                                 {capability}"
                        ),
                    });
                }
            }
            if let Some(added) = current.grant.increase_over(&grant).first().copied()
                && !confirmed
            {
                return Err(CatalogueError::OwnerConfirmationRequired {
                    detail: format!(
                        "granting {added} to {plugin_id} widens what it may do, which is the \
                             owner's decision"
                    ),
                });
            }
            current.grant = grant;
            changes.install(&current)?;
            let view = installation_view(&root, changes, bindings, current)?;
            Ok((view.clone(), Transition::Changed(view)))
        })
    }

    /// Removes an installation and closes every binding that held it, as the owner acting
    /// directly.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::uninstall_with`] returns.
    pub fn uninstall(
        &mut self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
    ) -> CatalogueResult<u64> {
        self.uninstall_with(
            environment_id,
            plugin_id,
            &mut Change::new(&Owner::acting()),
        )
    }

    /// Removes an installation and closes every binding that held it.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the package is not installed here.
    pub fn uninstall_with(
        &mut self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
        change: &mut Change<'_>,
    ) -> CatalogueResult<u64> {
        change.authority.check()?;
        let closing = self.bindings.count_for(environment_id, plugin_id);
        committing(&mut self.db, change, |changes| {
            changes
                .installation(environment_id, plugin_id)?
                .ok_or_else(|| not_installed(plugin_id))?;
            changes.uninstall(environment_id, plugin_id)?;
            Ok((
                (),
                Transition::Uninstalled {
                    plugin_id: plugin_id.clone(),
                    closed_bindings: closing,
                },
            ))
        })?;
        // The installation is gone for good now, so the bindings that held it close with it.
        Ok(self.bindings.close_for(environment_id, plugin_id))
    }

    /// Pins or unpins an installation to the exact hash it holds, as the owner acting directly.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::pin_package_with`] returns.
    pub fn pin_package(
        &mut self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
        package_digest: Option<PayloadDigest>,
    ) -> CatalogueResult<Installation> {
        self.pin_package_with(
            environment_id,
            plugin_id,
            package_digest,
            &mut Change::new(&Owner::acting()),
        )
        .map(|view| view.installation)
    }

    /// Pins or unpins an installation to the exact hash it holds.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the package is not installed here, and
    /// [`CatalogueError::InvalidArgument`] when the pin names another hash.
    pub fn pin_package_with(
        &mut self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
        package_digest: Option<PayloadDigest>,
        change: &mut Change<'_>,
    ) -> CatalogueResult<InstallationView> {
        change.authority.check()?;
        let root = self.root.clone();
        let bindings = &self.bindings;
        committing(&mut self.db, change, |changes| {
            let mut current = changes
                .installation(environment_id, plugin_id)?
                .ok_or_else(|| not_installed(plugin_id))?;
            current.pinned = current.pinned_to(package_digest)?;
            changes.install(&current)?;
            let view = installation_view(&root, changes, bindings, current)?;
            Ok((view.clone(), Transition::Changed(view)))
        })
    }
}

/// Runs one change to the catalogue's records, with its receipt, in one transaction inside the
/// admitting authority's commit.
///
/// Files a change relies on are published before this, each in a commit of its own, so the row
/// that names a file never commits before the file is whole and flushed.
fn committing<T>(
    db: &mut Db,
    change: &mut Change<'_>,
    apply: impl FnOnce(&Changes<'_>) -> CatalogueResult<(T, Transition)>,
) -> CatalogueResult<T> {
    let authority = change.authority;
    let settlement = &mut change.settlement;
    // The write lock first. Whatever wait there is for another writer happens here, before the
    // authority is asked for the last time, so no wait comes between its answer and the change.
    let pending = db.begin()?;
    committed(authority, &Effect::Records, move |permit| {
        pending.run(permit, |changes| {
            let (value, transition) = apply(changes)?;
            if let Some(settlement) = settlement.as_mut() {
                let result = (settlement.render)(&transition)?;
                changes.settle_applied(&settlement.key, &result, settlement.now_ms)?;
            }
            Ok(value)
        })
    })
}

/// Makes room for `length` more bytes, without touching a live-bound or pinned payload.
///
/// What is protected is read under the database's write lock, from the records as they are then,
/// and the payloads are removed before that lock is released. A pin another catalogue commits is
/// therefore ordered wholly before this reclaim, which sees it, or wholly after it, when there was
/// nothing of it yet to protect. A protection set read before a wait and used after it would let a
/// pin made in between lose the payloads it pins.
#[allow(clippy::too_many_arguments)]
fn reclaim(
    db: &mut Db,
    authority: &dyn Authority,
    bindings: &Bindings,
    broker: &dyn BrokerBridge,
    key: &EnrolmentKey,
    store: &Store,
    length: u64,
    subject: &str,
    also_protected: &BTreeSet<PayloadDigest>,
) -> CatalogueResult<()> {
    let pending = db.begin()?;
    let plan = pending.read(|records| {
        let enrolled = records
            .enrolment_by_key(key)?
            .ok_or_else(|| CatalogueError::NotFound {
                detail: "the repository was removed while it was being fetched from".to_owned(),
            })?;
        // A reclaim that has to remove nothing asks nothing about what is protected: a live
        // package this host cannot name holds up only the removals it would have to be weighed
        // against.
        let ledger = ledger_of(store, &enrolled)?;
        if ledger
            .check_payload_bytes(length, Stage::Declared, subject)
            .is_ok()
        {
            return Ok(store::ReclaimPlan::default());
        }
        // A package's hash names its manifest. Protecting only that would leave the component and
        // the assets a live binding actually runs on evictable, so every payload of a protected
        // package is protected with it.
        let mut protected: BTreeSet<PayloadDigest> = install::protected_payloads(
            &records.installations()?,
            bindings,
            &broker.live_packages(),
            |package| store.package_payloads(package),
        )?
        .into_iter()
        .collect();
        protected.extend(also_protected.iter().copied());
        // A pinned generation is what a pin holds the repository at, so everything that
        // generation references stays too. A pinned index this host cannot read stops the
        // reclaim: evicting without knowing what the pin protects is what a pin forbids.
        if let Some(pinned) = enrolled.enrolment.pinned_generation
            && let Some(active) = enrolled.active
            && active.generation == pinned.get()
        {
            for entry in &store.index(&active)?.entries {
                protected.insert(entry.manifest_digest);
                protected.extend(entry.payloads.iter().map(|payload| payload.digest));
            }
        }
        store.plan_reclaim(length, &ledger, &protected, subject)
    })?;
    if plan.is_empty() {
        return Ok(());
    }
    let effect = Effect::Reclaim {
        packages: plan.packages(),
        payloads: plan.payloads(),
        bytes: plan.bytes(),
    };
    committed(authority, &effect, |permit| store.remove(permit, &plan))?;
    // The lock is released only now, after the removal: nothing in the transaction changed, so
    // dropping it commits nothing.
    drop(pending);
    Ok(())
}

/// Checks that an installation may proceed: the ceiling and the grant, the pin on what it
/// replaces, and that it widens nothing the previous release was not permitted.
fn check_installation(
    entry: &IndexEntry,
    repository_ceiling: &CapabilityCeiling,
    grant: &InstallationGrant,
    previous: Option<&Installation>,
) -> CatalogueResult<()> {
    // A native bridge runs under the application's own permissions, outside the component
    // sandbox, and needs the owner's confirmation of this exact package. Installing carries no
    // such confirmation, so this host does not install one; granting it on an installed package
    // is `plugin.grant`'s, under the owner's confirmation.
    if entry
        .capabilities
        .iter()
        .any(|request| request.capability == PluginCapability::NativeBridgeInstall)
    {
        return Err(CatalogueError::GrantRequired {
            capability: PluginCapability::NativeBridgeInstall,
            requirement: "the owner's confirmation of this exact package, which an installation \
                          does not carry; this host does not install a native bridge"
                .to_owned(),
        });
    }
    // A grant names only what the package asks for. A grant for anything else would be authority
    // an installation holds with nothing in the package to use it, waiting for a later release to
    // ask for it without anybody deciding again.
    for capability in grant.capabilities() {
        if !entry
            .capabilities
            .iter()
            .any(|request| request.capability == capability)
        {
            return Err(CatalogueError::GrantRequired {
                capability,
                requirement: format!(
                    "a package that asks for it: {} does not request {capability}",
                    entry.plugin_id
                ),
            });
        }
    }
    ceiling::check_installable(&entry.capabilities, repository_ceiling, grant)?;
    if let Some(previous) = previous {
        // A pin holds an installation at the hash it names. Installing something else over it is
        // the pin's decision to make, not the install's.
        if previous.pinned && previous.package_digest != entry.manifest_digest {
            return Err(CatalogueError::InvalidArgument {
                detail: format!(
                    "{} is pinned to {}; unpin it before installing {}",
                    entry.plugin_id, previous.package_digest, entry.version
                ),
            });
        }
        // What an upgrade may do is compared as effective sets rather than as grant lists, and
        // the previous set under the ceiling the previous release was installed under: a release
        // that newly requests something the ceiling already permits, a wider enrolment, and a move
        // between repositories must not make an increase look like something already held.
        let held = ceiling::effective(&previous.requested, &previous.ceiling, &previous.grant);
        let proposed = ceiling::effective(&entry.capabilities, repository_ceiling, grant);
        if let Some(added) = proposed.difference(&held).next().copied() {
            return Err(CatalogueError::GrantRequired {
                capability: added,
                requirement: format!(
                    "an explicit installation grant: the installed release was not permitted \
                     {added}, and an installation does not widen what a package may do"
                ),
            });
        }
    }
    Ok(())
}

/// Returns what a sync or a fetch measures against: the enrolment's budgets and what its
/// directory holds now, its cached payloads and the packages extracted from them.
///
/// Counted from the directory each time rather than carried: a count kept in memory drifts from
/// the directory whenever another writer changes it, and a budget nobody can explain is the
/// result.
fn ledger_of(store: &Store, enrolled: &Enrolled) -> CatalogueResult<BudgetLedger> {
    let mut ledger = BudgetLedger::new(enrolled.enrolment.budgets);
    for size in store
        .cached_payloads()?
        .values()
        .chain(store.package_trees()?.values())
    {
        ledger.add_payload_bytes(*size);
    }
    if let Some(active) = enrolled.active {
        ledger.accept_metadata(active.index_bytes, active.entries);
    }
    Ok(ledger)
}

/// Returns what the retention budgets measure of each generation a repository keeps.
fn retained(kept: &[KeptGeneration]) -> Vec<Retained> {
    kept.iter()
        .map(|kept| Retained {
            generation: kept.generation,
            index_bytes: kept.index_bytes,
        })
        .collect()
}

fn accepted_of(active: Option<ActiveGeneration>) -> Option<(RepositoryGeneration, PayloadDigest)> {
    active.map(|active| {
        (
            RepositoryGeneration::new(active.generation),
            active.index_digest,
        )
    })
}

fn repository_view(enrolled: Enrolled) -> RepositoryView {
    RepositoryView {
        enrolment: enrolled.enrolment,
        active: enrolled.active,
    }
}

/// Builds what a caller is told about one installation.
fn installation_view(
    root: &Path,
    records: &Records<'_>,
    bindings: &Bindings,
    installation: Installation,
) -> CatalogueResult<InstallationView> {
    // Whether the release is revoked is what its repository's current generation says. A
    // repository that is no longer enrolled, or has no generation, publishes nothing about it; an
    // index this host cannot read is a failure and is returned as one.
    let revoked = match records.enrolment_by_key(&installation.enrolment)? {
        Some(Enrolled {
            key,
            active: Some(active),
            ..
        }) => Store::at(root, &key)
            .index(&active)?
            .find(&installation.plugin_id, &installation.version)
            .is_some_and(|entry| !entry.accepts_new_bindings()),
        _ => false,
    };
    let live_bindings = bindings.count_for(installation.environment_id, &installation.plugin_id);
    let decisions = ceiling::decide(
        &installation.requested,
        &installation.ceiling,
        &installation.grant,
    );
    Ok(InstallationView {
        installation,
        revoked,
        live_bindings,
        decisions,
    })
}

fn not_enrolled(id: &RepositoryId) -> CatalogueError {
    CatalogueError::NotFound {
        detail: format!("{id} is not enrolled"),
    }
}

fn not_installed(plugin_id: &PluginId) -> CatalogueError {
    CatalogueError::NotFound {
        detail: format!("{plugin_id} is not installed in this environment"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::flush_fault;
    use kr_plugin_sdk::limits::RepositoryBudgets;
    use kr_protocol::error::{ErrorCode, ProtocolError};
    use kr_protocol::receipt::ReceiptState;

    /// Copies the published development generation onto the internal disk and enrols it.
    fn development() -> (tempfile::TempDir, Catalogue, RepositoryId) {
        let home = tempfile::tempdir().expect("a temporary directory");
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/plugins/catalogue/development");
        let copy = home.path().join("development");
        let mut pending = vec![fixture.clone()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory).expect("readable").flatten() {
                let source = entry.path();
                if source.is_dir() {
                    pending.push(source);
                    continue;
                }
                let destination = copy.join(source.strip_prefix(&fixture).expect("inside"));
                std::fs::create_dir_all(destination.parent().expect("a parent")).expect("writable");
                std::fs::copy(&source, &destination).expect("copyable");
            }
        }
        let id = RepositoryId::new("development").expect("a valid identifier");
        let location = |name: &str| {
            url::Url::from_directory_path(copy.join(name)).expect("an absolute directory")
        };
        let enrolment = Enrolment::new(
            id.clone(),
            RepositoryKind::Local,
            location("metadata"),
            location("targets"),
            std::fs::read(copy.join("root.json")).expect("a root"),
            RepositoryBudgets::defaults(),
            CapabilityCeiling::default_ceiling(),
        )
        .expect("an enrolment");
        let mut catalogue =
            Catalogue::open(&home.path().join("catalogue")).expect("an openable catalogue");
        catalogue
            .enrol(enrolment, true)
            .expect("the owner adopted the root");
        (home, catalogue, id)
    }

    /// A kept root that resets the role floors says so until a verified checkpoint is published,
    /// and the working copy the next verification starts from leaves those floors out.
    #[tokio::test]
    async fn a_reset_kept_with_a_root_is_owed_until_a_checkpoint_is_published() {
        let (_home, mut catalogue, id) = development();
        catalogue.sync(&id).await.expect("a generation");
        let enrolled = catalogue.enrolled(&id).expect("enrolled");
        let store = catalogue.store(&id).expect("enrolled");
        let (key, root) = (&enrolled.key, &enrolled.enrolment.root);
        let owed = |catalogue: &Catalogue| {
            catalogue
                .db
                .read(|records| records.trust_reset(key))
                .expect("readable")
        };
        let set_root = |catalogue: &mut Catalogue, reset: bool| {
            let pending = catalogue.db.begin().expect("the write lock");
            committed(&Owner::acting(), &Effect::Records, move |permit| {
                pending.run(permit, |changes| changes.set_root(key, root, reset))
            })
            .expect("recorded");
        };
        assert!(!owed(&catalogue));
        set_root(&mut catalogue, true);
        assert!(owed(&catalogue));
        set_root(&mut catalogue, false);
        assert!(
            owed(&catalogue),
            "a later root that changes nothing does not clear it"
        );

        // The copy holds what the client reads back: the two floors and the time it last saw. The
        // documents it writes afresh on every load, the top-level targets among them, are not
        // carried into it.
        let floors = |working: &crate::store::WorkingDatastore| {
            [
                "timestamp.json",
                "snapshot.json",
                "latest_known_time.json",
                "targets.json",
            ]
            .map(|role| working.path().join(role).is_file())
        };
        assert!(store.datastore().join("targets.json").is_file());
        assert_eq!(
            floors(&store.working_datastore(false).expect("a copy")),
            [true, true, true, false]
        );
        assert_eq!(
            floors(&store.working_datastore(true).expect("a copy")),
            [false, false, true, false],
            "the reset leaves the timestamp and snapshot floors out of the copy"
        );

        catalogue.sync(&id).await.expect("verified again");
        assert!(
            !owed(&catalogue),
            "a published checkpoint settles the reset"
        );
    }

    /// Arranges for a sync to move `id` on to its next generation just before the next index
    /// document is opened on this thread, keeping only the new generation: the commit that moves
    /// the repository and stops naming the old generation, then the old document's removal.
    fn a_sync_moves_on_before_the_next_index_read(catalogue: &Catalogue, id: &RepositoryId) -> u64 {
        let enrolled = catalogue.enrolled(id).expect("enrolled");
        let store = catalogue.store(id).expect("enrolled");
        let first = enrolled.active.expect("a generation");
        let mut index = store.index(&first).expect("readable");
        index.generation = RepositoryGeneration::new(first.generation + 1);
        let rendered = index
            .canonical_json()
            .expect("a renderable index")
            .into_bytes();
        let (index_digest, index_bytes) =
            committed(&Owner::acting(), &Effect::Index(id.clone()), |permit| {
                store.write_index(permit, &rendered)
            })
            .expect("written");
        let next = ActiveGeneration {
            generation: first.generation + 1,
            index_digest,
            index_bytes,
            entries: first.entries,
            versions: first.versions,
        };
        let root = catalogue.root().to_path_buf();
        let key = enrolled.key;
        crate::store::index_pause::once(move || {
            let mut db = Db::open(&root).expect("a second connection");
            let pending = db.begin().expect("the write lock");
            committed(&Owner::acting(), &Effect::Records, |permit| {
                pending.run(permit, |changes| {
                    changes.activate(&key, &next, &[])?;
                    changes.forget_generation(&key, first.generation)
                })
            })
            .expect("moved on");
            std::fs::remove_file(Store::at(&root, &key).index_path(first.index_digest))
                .expect("the old document removed");
        });
        next.generation
    }

    /// A reader whose records were read just before a sync stopped keeping the generation they name,
    /// and removed its index document, reads again and answers from what is kept now.
    #[tokio::test]
    async fn a_reader_that_meets_a_sync_reads_what_is_kept_now() {
        let (_home, mut catalogue, id) = development();
        catalogue.sync(&id).await.expect("a generation");
        let environment = EnvironmentId::new(kr_protocol::scalars::Uuid::NIL);
        let entry = catalogue
            .index(&id)
            .expect("an index")
            .entries
            .first()
            .expect("a package")
            .clone();
        catalogue
            .install(
                &id,
                environment,
                &entry.plugin_id,
                &entry.version,
                entry.manifest_digest,
                InstallationGrant::none(),
            )
            .await
            .expect("installed");

        let next = a_sync_moves_on_before_the_next_index_read(&catalogue, &id);
        let index = catalogue
            .current_index(&id)
            .expect("read again")
            .expect("an index");
        assert_eq!(index.generation.get(), next);

        // The views of what is installed read the current index for revocations the same way.
        let next = a_sync_moves_on_before_the_next_index_read(&catalogue, &id);
        let views = catalogue
            .installation_views(environment)
            .expect("read again");
        assert_eq!(views.len(), 1);
        a_sync_moves_on_before_the_next_index_read(&catalogue, &id);
        catalogue
            .installation_view(environment, &entry.plugin_id)
            .expect("read again");
        assert_eq!(
            catalogue
                .active(&id)
                .expect("enrolled")
                .map(|active| active.generation),
            Some(next + 1)
        );
    }

    /// An enrolment whose budgets lack an allowance this build enforces is a record it cannot read,
    /// and every answer about that repository says so and names it; there is no other shape of
    /// the record to read.
    #[tokio::test]
    async fn an_enrolment_without_every_budget_is_a_record_this_build_cannot_read() {
        let (_home, catalogue, id) = development();
        let connection =
            rusqlite::Connection::open(catalogue.root().join(crate::db::DATABASE_FILE))
                .expect("the catalogue's database");
        let budgets: String = connection
            .query_row("SELECT budgets FROM enrolments", [], |row| row.get(0))
            .expect("one enrolment");
        let mut shape: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&budgets).expect("an object");
        shape.remove("retained_generations");
        shape.remove("retained_metadata_bytes");
        connection
            .execute(
                "UPDATE enrolments SET budgets = ?1",
                [serde_json::Value::Object(shape).to_string()],
            )
            .expect("rewritten");
        drop(connection);
        let refusal = catalogue
            .repository(&id)
            .expect_err("a record this build cannot read");
        assert!(
            matches!(&refusal, CatalogueError::StorageUnavailable { detail }
                if detail.contains("cannot read") && detail.contains("development")
                    && detail.contains("retained_generations")),
            "{refusal:?}"
        );
    }

    /// Enrols a generation the suite signed into a catalogue of its own under `home`.
    fn enrolled_generation(
        home: &Path,
        generation: &crate::test_support::Generation,
    ) -> (Catalogue, RepositoryId) {
        let id = RepositoryId::new("official").expect("a valid identifier");
        let mut catalogue =
            Catalogue::open(&home.join("catalogue")).expect("an openable catalogue");
        catalogue
            .enrol(
                Enrolment::new(
                    id.clone(),
                    RepositoryKind::Official,
                    generation.metadata_url(),
                    generation.targets_url(),
                    generation.root_bytes(),
                    RepositoryBudgets::defaults(),
                    CapabilityCeiling::default_ceiling(),
                )
                .expect("an enrolment"),
                true,
            )
            .expect("the owner adopted the root");
        (catalogue, id)
    }

    /// The versions of the timestamp and snapshot the accepted checkpoint holds: the floors the
    /// next verification compares against.
    fn floors(catalogue: &Catalogue, id: &RepositoryId) -> (u64, u64) {
        let checkpoint = catalogue.store(id).expect("enrolled").datastore();
        let read = |name: &str| std::fs::read(checkpoint.join(name)).expect("a floor");
        let timestamp: tough::schema::Signed<tough::schema::Timestamp> =
            serde_json::from_slice(&read("timestamp.json")).expect("a timestamp");
        let snapshot: tough::schema::Signed<tough::schema::Snapshot> =
            serde_json::from_slice(&read("snapshot.json")).expect("a snapshot");
        (
            timestamp.signed.version.get(),
            snapshot.signed.version.get(),
        )
    }

    /// A checkpoint publication stopped after any number of documents leaves each document whole,
    /// from one generation or the other, and floors no lower than before. After a restart, a replay
    /// of the generation before is refused exactly where a floor moved on, and the new generation
    /// is accepted whatever the stop left.
    #[tokio::test]
    async fn a_publication_stopped_after_any_document_keeps_its_floors_and_refuses_a_rollback() {
        use crate::test_support::{Generation, GenerationSpec, copy_tree};

        // The root, the time, the snapshot, the targets and the timestamp, in the order they go.
        for stop in 0..=5usize {
            let home = tempfile::tempdir().expect("a temporary directory");
            let generation = Generation::build(home.path(), GenerationSpec::default()).await;
            let first = home.path().join("first");
            copy_tree(&generation.directory(), &first);
            let (mut catalogue, id) = enrolled_generation(home.path(), &generation);
            catalogue.sync(&id).await.expect("the first generation");
            generation.rewrite_as(2).await;

            crate::store::publish_fault::stop_after(stop);
            let outcome = catalogue.sync(&id).await;
            crate::store::publish_fault::clear();
            match (stop, outcome) {
                (5, outcome) => {
                    outcome.expect("the whole checkpoint published");
                }
                (0, Err(CatalogueError::StorageUnavailable { .. })) => {}
                (_, Err(CatalogueError::PublicationUncertain { .. })) => {}
                (_, outcome) => panic!("stopped after {stop}: {outcome:?}"),
            }

            drop(catalogue);
            let mut catalogue = Catalogue::open(&home.path().join("catalogue")).expect("reopens");
            let (timestamp, snapshot) = floors(&catalogue, &id);
            assert!(
                [1, 2].contains(&timestamp) && [1, 2].contains(&snapshot),
                "stopped after {stop}"
            );
            let moved = timestamp == 2 || snapshot == 2;

            std::fs::remove_dir_all(generation.directory()).expect("removable");
            copy_tree(&first, &generation.directory());
            let replayed = catalogue.sync(&id).await;
            assert_eq!(
                replayed.is_err(),
                moved,
                "stopped after {stop}: floors {timestamp}, {snapshot}: {replayed:?}"
            );
            if let Err(refusal) = replayed {
                assert!(
                    matches!(refusal, CatalogueError::Untrusted { .. }),
                    "stopped after {stop}: {refusal:?}"
                );
            }

            generation.rewrite_as(2).await;
            catalogue
                .sync(&id)
                .await
                .unwrap_or_else(|refusal| panic!("stopped after {stop}: {refusal}"));
            assert_eq!(
                catalogue
                    .active(&id)
                    .expect("enrolled")
                    .map(|active| active.generation),
                Some(2)
            );
        }
    }

    /// A root that changes the timestamp key and keeps the others is kept through the rotation
    /// callback, which records the floors it resets. Whether the publication that follows stops
    /// after any document or at the commit that settles the reset, the reset stays owed across a
    /// restart, the next sync accepts the lower versions the new key signs, and a replay of the
    /// generation before the rotation, signed with the key the new root no longer trusts, is
    /// refused.
    #[tokio::test]
    async fn a_partial_key_change_stays_owed_until_a_whole_checkpoint_settles_it() {
        use crate::test_support::{Generation, GenerationSpec, KeySet, TestKey, copy_tree};

        for stop in [None, Some(0usize), Some(1), Some(2), Some(3), Some(4)] {
            let home = tempfile::tempdir().expect("a temporary directory");
            let generation = Generation::build(
                home.path(),
                GenerationSpec {
                    generation: 3,
                    ..GenerationSpec::default()
                },
            )
            .await;
            let before = home.path().join("before");
            copy_tree(&generation.directory(), &before);
            let (mut catalogue, id) = enrolled_generation(home.path(), &generation);
            catalogue.sync(&id).await.expect("the first generation");
            let old = generation.keys();
            let retained = KeySet {
                timestamp: TestKey::generate(),
                ..old.clone()
            };
            generation
                .rotate_to(GenerationSpec {
                    generation: 4,
                    metadata_version: Some(2),
                    keys: Some(retained),
                    root_version: 2,
                    ..GenerationSpec::default()
                })
                .await;

            match stop {
                None => crate::store::publish_fault::fail_reset(),
                Some(documents) => crate::store::publish_fault::stop_after(documents),
            }
            let outcome = catalogue.sync(&id).await;
            crate::store::publish_fault::clear();
            assert!(outcome.is_err(), "{stop:?}: {outcome:?}");

            drop(catalogue);
            let mut catalogue = Catalogue::open(&home.path().join("catalogue")).expect("reopens");
            let enrolled = catalogue.enrolled(&id).expect("enrolled");
            let kept: tough::schema::Signed<tough::schema::Root> =
                serde_json::from_slice(&enrolled.enrolment.root).expect("a root");
            assert_eq!(
                kept.signed.version.get(),
                2,
                "{stop:?}: the rotation is kept"
            );
            assert!(
                catalogue
                    .db
                    .read(|records| records.trust_reset(&enrolled.key))
                    .expect("readable"),
                "{stop:?}: the reset the rotation recorded is still owed"
            );

            catalogue
                .sync(&id)
                .await
                .unwrap_or_else(|refusal| panic!("{stop:?}: {refusal}"));
            assert!(
                !catalogue
                    .db
                    .read(|records| records.trust_reset(&enrolled.key))
                    .expect("readable"),
                "{stop:?}: a whole checkpoint settles it"
            );
            assert_eq!(floors(&catalogue, &id), (2, 2), "{stop:?}");

            std::fs::remove_dir_all(generation.directory()).expect("removable");
            copy_tree(&before, &generation.directory());
            let refusal = catalogue
                .sync(&id)
                .await
                .expect_err("the old timestamp key is no longer trusted");
            assert!(
                matches!(refusal, CatalogueError::Untrusted { .. }),
                "{stop:?}: {refusal:?}"
            );
        }
    }

    /// What a store keeps against its retained metadata budget: the checkpoint, and every index
    /// document there, named or not.
    fn retained_on_disk(catalogue: &Catalogue, id: &RepositoryId) -> u64 {
        let store = catalogue.store(id).expect("enrolled");
        store.checkpoint_bytes().expect("readable")
            + store
                .index_documents()
                .expect("readable")
                .into_values()
                .sum::<u64>()
    }

    /// Changes one enrolment's budgets, as the owner may.
    fn rebudget(
        catalogue: &mut Catalogue,
        id: &RepositoryId,
        change: impl FnOnce(&mut RepositoryBudgets),
    ) {
        let mut enrolment = catalogue
            .repository(id)
            .expect("readable")
            .expect("enrolled");
        change(&mut enrolment.budgets);
        catalogue
            .update_enrolment(enrolment, false)
            .expect("a budget is the owner's to change");
    }

    /// A package set aside to make room whose copy cannot then be removed is room the reclaim did
    /// not make. The install stops as uncertain before anything of the new package is written, the
    /// removal is recorded as unconfirmed, and the receipt says so after a restart.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_package_set_aside_that_cannot_be_removed_stops_the_install_as_uncertain() {
        use crate::test_support::{Generation, GenerationSpec};
        use std::os::unix::fs::PermissionsExt as _;

        let home = tempfile::tempdir().expect("a temporary directory");
        let first = Generation::build(
            home.path(),
            GenerationSpec {
                asset_copy: true,
                ..GenerationSpec::default()
            },
        )
        .await;
        let second = Generation::build(
            &home.path().join("second"),
            GenerationSpec {
                generation: 2,
                package_version: "0.2.0".to_owned(),
                keys: Some(first.keys()),
                ..GenerationSpec::default()
            },
        )
        .await;
        let (mut catalogue, id) = enrolled_generation(home.path(), &first);
        let environment = EnvironmentId::new(kr_protocol::scalars::Uuid::NIL);
        let plugin = PluginId::new("kalareach/example-declarative").expect("a plugin identifier");
        catalogue.sync(&id).await.expect("the first generation");
        catalogue
            .install(
                &id,
                environment,
                &plugin,
                &PackageVersion::parse("0.1.0").expect("a version"),
                first.manifest_digest(),
                InstallationGrant::none(),
            )
            .await
            .expect("the first release");
        catalogue
            .uninstall(environment, &plugin)
            .expect("uninstalled");
        first.replace_with(&second);
        catalogue.sync(&id).await.expect("the second generation");

        // Room for the second release exactly once the first release's extracted copy is gone.
        let store = catalogue.store(&id).expect("enrolled");
        let cached = store.cached_payloads().expect("readable");
        let trees = store.package_trees().expect("readable");
        let held: u64 = cached.values().sum::<u64>() + trees.values().sum::<u64>();
        let entry = catalogue.index(&id).expect("an index").entries[0].clone();
        let staged = entry.manifest_size_bytes.get()
            + entry
                .payloads
                .iter()
                .map(|payload| payload.size_bytes.get())
                .sum::<u64>();
        let fetched = entry.manifest_size_bytes.get();
        let old = first.manifest_digest();
        rebudget(&mut catalogue, &id, |budgets| {
            budgets.payload_cache_bytes =
                kr_protocol::scalars::U64::new(held + staged + fetched - trees[&old]);
        });
        let held_open = store.package_dir(old).join("assets");
        std::fs::set_permissions(&held_open, std::fs::Permissions::from_mode(0o555))
            .expect("read-only");

        let owner = Owner::acting();
        let key = ReceiptKey::new("kr:local", "install");
        assert_eq!(
            catalogue.claim(&claim("install"), 1).expect("recorded"),
            Claimed::Fresh
        );
        let recording = Recording::new(&owner);
        let mut never = |_: &Transition| -> CatalogueResult<Vec<u8>> {
            unreachable!("an action that stopped renders no answer")
        };
        let stopped = catalogue
            .install_with(
                &id,
                environment,
                &plugin,
                &entry.version,
                entry.manifest_digest,
                InstallationGrant::none(),
                &mut Change::settling(&recording, key.clone(), 2, &mut never),
            )
            .await;
        let aside = store
            .datastore()
            .parent()
            .expect("the store")
            .join("staging")
            .join(format!("removed-{old}"))
            .join("assets");
        std::fs::set_permissions(&aside, std::fs::Permissions::from_mode(0o755))
            .expect("writable again");

        let stopped = stopped.expect_err("the room was not made");
        assert!(
            matches!(stopped, CatalogueError::PublicationUncertain { .. }),
            "{stopped:?}"
        );
        assert!(
            matches!(
                recording.committed().as_slice(),
                [Committed {
                    effect: Effect::Reclaim { packages: 1, .. },
                    confirmed: false,
                }]
            ),
            "{:?}",
            recording.committed()
        );
        assert!(!store.package_dir(entry.manifest_digest).exists());
        assert!(
            !store
                .cached_payloads()
                .expect("readable")
                .contains_key(&entry.manifest_digest),
            "nothing of the second release was fetched"
        );
        let failure = recording.failure(&stopped.into());
        assert_eq!(failure.state(), ReceiptState::Unknown);
        catalogue
            .settle_failure(&key, &failure, 3)
            .expect("recorded");
        drop(catalogue);
        let reopened = Catalogue::open(&home.path().join("catalogue")).expect("reopens");
        assert_eq!(
            reopened
                .receipt(&key)
                .expect("readable")
                .expect("a receipt")
                .state,
            ReceiptState::Unknown
        );
    }

    /// Before a checkpoint is published into the room an older generation held, that generation's
    /// index document has to be gone. One that cannot be removed stops the sync with the accepted
    /// checkpoint as it was and what is kept inside the budget; once it can be removed, the sync
    /// goes through after a restart.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_index_that_cannot_be_removed_before_publication_stops_the_sync_inside_its_budget() {
        use crate::test_support::{Generation, GenerationSpec};
        use std::os::unix::fs::PermissionsExt as _;

        let home = tempfile::tempdir().expect("a temporary directory");
        let generation = Generation::build(home.path(), GenerationSpec::default()).await;
        let (mut catalogue, id) = enrolled_generation(home.path(), &generation);
        catalogue.sync(&id).await.expect("the first generation");
        generation.rewrite_as(2).await;
        catalogue.sync(&id).await.expect("the second generation");
        // What is kept now, the checkpoint and both indexes, is the whole budget.
        let limit = retained_on_disk(&catalogue, &id);
        rebudget(&mut catalogue, &id, |budgets| {
            budgets.retained_metadata_bytes = kr_protocol::scalars::U64::new(limit);
        });
        // The third generation delegates, so its checkpoint is the larger, and it fits beside the
        // generation in use only once the first generation's index is gone.
        let third = Generation::build(
            &home.path().join("third"),
            GenerationSpec {
                generation: 3,
                keys: Some(generation.keys()),
                delegations: vec![(
                    "vendor".to_owned(),
                    "packages/kalareach/*/*/*".to_owned(),
                    false,
                )],
                ..GenerationSpec::default()
            },
        )
        .await;
        generation.replace_with(&third);
        let store = catalogue.store(&id).expect("enrolled");
        let accepted = |store: &Store| -> BTreeMap<std::path::PathBuf, Vec<u8>> {
            std::fs::read_dir(store.datastore())
                .expect("readable")
                .flatten()
                .map(|entry| (entry.path(), std::fs::read(entry.path()).expect("readable")))
                .collect()
        };
        let before = accepted(&store);
        let index_directory = store
            .index_path(PayloadDigest::of(b""))
            .parent()
            .expect("the index directory")
            .to_owned();
        std::fs::set_permissions(&index_directory, std::fs::Permissions::from_mode(0o555))
            .expect("read-only");
        let refusal = catalogue.sync(&id).await;
        std::fs::set_permissions(&index_directory, std::fs::Permissions::from_mode(0o755))
            .expect("writable again");
        let refusal = refusal.expect_err("the older index could not be removed");
        assert!(
            matches!(refusal, CatalogueError::StorageUnavailable { .. }),
            "{refusal:?}"
        );
        assert_eq!(accepted(&store), before, "the checkpoint was not published");
        assert_eq!(
            catalogue
                .active(&id)
                .expect("enrolled")
                .map(|active| active.generation),
            Some(2)
        );
        assert!(retained_on_disk(&catalogue, &id) <= limit);

        drop(catalogue);
        let mut catalogue = Catalogue::open(&home.path().join("catalogue")).expect("reopens");
        catalogue
            .sync(&id)
            .await
            .expect("the removal goes through now");
        assert_eq!(
            catalogue
                .active(&id)
                .expect("enrolled")
                .map(|active| active.generation),
            Some(3)
        );
        assert!(retained_on_disk(&catalogue, &id) <= limit);
    }

    /// A checkpoint publication stopped at any step, with consistent snapshots and three delegated
    /// roles whose documents are named by version, keeps what is held inside a budget that fits
    /// either whole checkpoint beside the generation in use: the documents the verification no
    /// longer holds go before any new one arrives, so the two generations' delegated documents never
    /// stand side by side. Every floor stays, and the publication goes through after a restart.
    #[tokio::test]
    async fn a_publication_stopped_at_any_step_keeps_what_is_held_inside_the_budget() {
        use crate::test_support::{Generation, GenerationSpec};

        // Three documents to remove, then eight to write.
        for stop in 0..=11usize {
            let home = tempfile::tempdir().expect("a temporary directory");
            let generation = Generation::build(
                home.path(),
                GenerationSpec {
                    consistent_snapshot: true,
                    delegation_chain: 3,
                    ..GenerationSpec::default()
                },
            )
            .await;
            let (mut catalogue, id) = enrolled_generation(home.path(), &generation);
            catalogue.sync(&id).await.expect("the first generation");
            let limit = retained_on_disk(&catalogue, &id);
            rebudget(&mut catalogue, &id, |budgets| {
                budgets.retained_metadata_bytes = kr_protocol::scalars::U64::new(limit);
            });
            generation.rewrite_as(2).await;

            crate::store::publish_fault::stop_after(stop);
            let outcome = catalogue.sync(&id).await;
            crate::store::publish_fault::clear();
            assert_eq!(
                outcome.is_ok(),
                stop == 11,
                "stopped at {stop}: {outcome:?}"
            );

            drop(catalogue);
            let mut catalogue = Catalogue::open(&home.path().join("catalogue")).expect("reopens");
            assert!(
                retained_on_disk(&catalogue, &id) <= limit,
                "stopped at {stop}: {} against {limit}",
                retained_on_disk(&catalogue, &id)
            );
            let (timestamp, snapshot) = floors(&catalogue, &id);
            assert!(
                [1, 2].contains(&timestamp) && [1, 2].contains(&snapshot),
                "stopped at {stop}"
            );
            catalogue
                .sync(&id)
                .await
                .unwrap_or_else(|refusal| panic!("stopped at {stop}: {refusal}"));
            assert!(
                retained_on_disk(&catalogue, &id) <= limit,
                "stopped at {stop}"
            );
        }
    }

    /// A publication is measured at the most it holds on the way, not at the checkpoint it ends
    /// with. The first generation's targets document is the larger, since it pins one more target,
    /// and the second generation's last delegated document is the larger, since it pins one more
    /// file. A stop after the second generation's delegated documents arrive and before the targets
    /// document is replaced would hold the larger of each; so a budget that fits either whole
    /// checkpoint beside its own index, and not that, refuses the sync before anything is kept.
    #[tokio::test]
    async fn a_publication_is_refused_where_its_peak_and_not_its_end_is_past_the_budget() {
        use crate::test_support::{Generation, GenerationSpec, copy_tree};

        let home = tempfile::tempdir().expect("a temporary directory");
        let first = Generation::build(
            &home.path().join("first"),
            GenerationSpec {
                consistent_snapshot: true,
                delegation_chain: 3,
                extra_targets: vec![(
                    format!(
                        "extra/{}.json",
                        "pinned-only-by-the-first-generation-".repeat(3)
                    ),
                    vec![7; 64],
                )],
                ..GenerationSpec::default()
            },
        )
        .await;
        let second = Generation::build(
            &home.path().join("second"),
            GenerationSpec {
                generation: 2,
                consistent_snapshot: true,
                delegation_chain: 3,
                asset_copy: true,
                keys: Some(first.keys()),
                ..GenerationSpec::default()
            },
        )
        .await;
        let publish = |from: &Generation, at: &Path| {
            let _ = std::fs::remove_dir_all(at);
            copy_tree(&from.directory(), at);
        };

        // The finished second checkpoint, measured in a catalogue of its own.
        let probe_at = home.path().join("probe");
        publish(&first, &probe_at);
        let probe_generation = |at: &Path| -> Enrolment {
            Enrolment::new(
                RepositoryId::new("official").expect("a valid identifier"),
                RepositoryKind::Official,
                url::Url::from_directory_path(at.join("metadata")).expect("a location"),
                url::Url::from_directory_path(at.join("targets")).expect("a location"),
                first.root_bytes(),
                RepositoryBudgets::defaults(),
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrolment")
        };
        let id = RepositoryId::new("official").expect("a valid identifier");
        let mut probe = Catalogue::open(&home.path().join("probe-catalogue")).expect("openable");
        probe
            .enrol(probe_generation(&probe_at), true)
            .expect("enrolled");
        probe.sync(&id).await.expect("the first generation");
        let first_index: u64 = probe
            .store(&id)
            .expect("enrolled")
            .index_documents()
            .expect("readable")
            .into_values()
            .sum();
        let first_checkpoint = probe
            .store(&id)
            .expect("enrolled")
            .checkpoint_bytes()
            .expect("readable");
        publish(&second, &probe_at);
        probe.sync(&id).await.expect("the second generation");
        let store = probe.store(&id).expect("enrolled");
        let finished = store.checkpoint_bytes().expect("readable");
        let second_index = store
            .index_documents()
            .expect("readable")
            .into_values()
            .sum::<u64>()
            - first_index;

        let at = home.path().join("case");
        publish(&first, &at);
        let mut catalogue = Catalogue::open(&home.path().join("catalogue")).expect("openable");
        catalogue
            .enrol(probe_generation(&at), true)
            .expect("enrolled");
        catalogue.sync(&id).await.expect("the first generation");
        let limit = (first_checkpoint + first_index).max(finished + second_index);
        assert!(retained_on_disk(&catalogue, &id) <= limit);
        rebudget(&mut catalogue, &id, |budgets| {
            budgets.retained_metadata_bytes = kr_protocol::scalars::U64::new(limit);
        });
        let before = retained_on_disk(&catalogue, &id);
        publish(&second, &at);
        let refusal = catalogue
            .sync(&id)
            .await
            .expect_err("the publication's peak is past the budget");
        assert!(
            matches!(&refusal, CatalogueError::ResourceLimit(limit)
                if limit.resource == crate::budget::Resource::RetainedMetadataBytes),
            "{refusal:?}"
        );
        assert_eq!(retained_on_disk(&catalogue, &id), before);
        assert_eq!(
            catalogue
                .active(&id)
                .expect("enrolled")
                .map(|active| active.generation),
            Some(1)
        );
    }

    /// A read that fails while no repository stopped keeping anything fails as it is.
    #[tokio::test]
    async fn a_reader_whose_index_is_lost_without_a_sync_is_told_so() {
        let (_home, mut catalogue, id) = development();
        catalogue.sync(&id).await.expect("a generation");
        let active = catalogue
            .active(&id)
            .expect("enrolled")
            .expect("a generation");
        let store = catalogue.store(&id).expect("enrolled");
        std::fs::remove_file(store.index_path(active.index_digest)).expect("removable");
        let refusal = catalogue
            .current_index(&id)
            .expect_err("the document is gone and nothing moved");
        assert!(
            matches!(refusal, CatalogueError::StorageUnavailable { .. }),
            "{refusal:?}"
        );
    }

    fn claim(action: &str) -> ReceiptClaim {
        ReceiptClaim {
            key: ReceiptKey::new("kr:local", action),
            digest: vec![5; 32],
            method: "plugin.install".to_owned(),
            method_version: 1,
            deadline_ms: None,
        }
    }

    /// Checks what a reader sees of an action that stopped after an unconfirmed publication.
    fn uncertain_receipt(catalogue: &mut Catalogue, action: &str, answer: &ProtocolError) {
        let Claimed::Retained(record) = catalogue.claim(&claim(action), 9).expect("readable")
        else {
            panic!("{action} is claimed again rather than answered from its receipt");
        };
        assert_eq!(record.state, ReceiptState::Unknown, "{action}");
        assert_eq!(record.error.as_ref(), Some(answer), "{action}");
    }

    /// A publication whose directory does not confirm it is in place, is unknown, and reads the
    /// same after a restart.
    ///
    /// The rename has happened by the time the flush fails, so what readers see is the published
    /// object, and the action that published it is neither refused nor performed again. The index
    /// a sync writes and the package an installation moves into place are the two publications a
    /// row later names.
    #[tokio::test]
    async fn a_publication_its_directory_did_not_confirm_is_unknown_before_and_after_a_restart() {
        let (home, mut catalogue, id) = development();
        let owner = Owner::acting();
        let store = catalogue.store(&id).expect("enrolled");
        let unnamed = PayloadDigest::of(b"");
        let mut never = |_: &Transition| -> CatalogueResult<Vec<u8>> {
            unreachable!("an action that stopped renders no answer")
        };

        // A sync whose index is renamed into place and whose directory then does not flush.
        let index_directory = store
            .index_path(unnamed)
            .parent()
            .expect("a parent")
            .to_owned();
        assert_eq!(
            catalogue.claim(&claim("sync"), 1).expect("recorded"),
            Claimed::Fresh
        );
        let recording = Recording::new(&owner);
        flush_fault::fail(&index_directory);
        let stopped = catalogue
            .sync_with(
                &id,
                &mut Change::settling(
                    &recording,
                    ReceiptKey::new("kr:local", "sync"),
                    2,
                    &mut never,
                ),
            )
            .await;
        flush_fault::clear();
        let stopped = stopped.expect_err("the index directory did not confirm the index");
        assert!(
            matches!(stopped, CatalogueError::PublicationUncertain { .. }),
            "{stopped:?}"
        );
        assert_eq!(
            recording.committed(),
            vec![
                Committed {
                    effect: Effect::Checkpoint(id.clone()),
                    confirmed: true,
                },
                Committed {
                    effect: Effect::Index(id.clone()),
                    confirmed: false,
                },
            ],
            "the verified metadata is accepted before the index is written"
        );
        let sync_failure = recording.failure(&stopped.into());
        assert_eq!(sync_failure.state(), ReceiptState::Unknown);
        assert_eq!(sync_failure.answer().code, ErrorCode::OutcomeUnknown);
        catalogue
            .settle_failure(&ReceiptKey::new("kr:local", "sync"), &sync_failure, 3)
            .expect("recorded");
        assert_eq!(catalogue.active(&id).expect("enrolled"), None);
        assert_eq!(
            std::fs::read_dir(&index_directory)
                .expect("readable")
                .count(),
            1,
            "the index is in place"
        );

        // An installation whose package is renamed into place and whose directory then does not
        // flush. Its payloads were cached first, and the answer says so.
        catalogue.sync(&id).await.expect("a generation");
        let index = catalogue.index(&id).expect("an index");
        let entry = index.entries.first().expect("a package").clone();
        let packages = store
            .package_dir(unnamed)
            .parent()
            .expect("a parent")
            .to_owned();
        assert_eq!(
            catalogue.claim(&claim("install"), 4).expect("recorded"),
            Claimed::Fresh
        );
        let recording = Recording::new(&owner);
        flush_fault::fail(&packages);
        let stopped = catalogue
            .install_with(
                &id,
                EnvironmentId::new(kr_protocol::scalars::Uuid::NIL),
                &entry.plugin_id,
                &entry.version,
                entry.manifest_digest,
                InstallationGrant::none(),
                &mut Change::settling(
                    &recording,
                    ReceiptKey::new("kr:local", "install"),
                    5,
                    &mut never,
                ),
            )
            .await;
        flush_fault::clear();
        let stopped = stopped.expect_err("the packages directory did not confirm the package");
        assert!(
            matches!(stopped, CatalogueError::PublicationUncertain { .. }),
            "{stopped:?}"
        );
        let committed = recording.committed();
        assert_eq!(
            committed.last(),
            Some(&Committed {
                effect: Effect::Package(entry.manifest_digest),
                confirmed: false,
            })
        );
        assert!(
            committed[..committed.len() - 1]
                .iter()
                .all(|change| matches!(change.effect, Effect::Payload(_)) && change.confirmed),
            "{committed:?}"
        );
        let install_failure = recording.failure(&stopped.into());
        assert_eq!(install_failure.state(), ReceiptState::Unknown);
        assert!(
            install_failure
                .answer()
                .message
                .contains("payloads written into the cache"),
            "{:?}",
            install_failure.answer()
        );
        catalogue
            .settle_failure(&ReceiptKey::new("kr:local", "install"), &install_failure, 6)
            .expect("recorded");
        assert!(
            matches!(
                store
                    .check_package(entry.manifest_digest)
                    .expect("readable"),
                PackageCheck::Complete(_)
            ),
            "the package is in place"
        );
        let environment = EnvironmentId::new(kr_protocol::scalars::Uuid::NIL);
        assert!(
            catalogue
                .installation(environment, &entry.plugin_id)
                .expect("readable")
                .is_none(),
            "no row names it"
        );

        // What a reader sees now is what it sees after a restart.
        uncertain_receipt(&mut catalogue, "sync", sync_failure.answer());
        uncertain_receipt(&mut catalogue, "install", install_failure.answer());
        drop(catalogue);
        let mut reopened = Catalogue::open(&home.path().join("catalogue")).expect("reopens");
        assert_eq!(reopened.recover_interrupted(8).expect("recorded"), 0);
        uncertain_receipt(&mut reopened, "sync", sync_failure.answer());
        uncertain_receipt(&mut reopened, "install", install_failure.answer());
        assert!(matches!(
            store
                .check_package(entry.manifest_digest)
                .expect("readable"),
            PackageCheck::Complete(_)
        ));
        assert!(
            reopened
                .installation(environment, &entry.plugin_id)
                .expect("readable")
                .is_none()
        );
        assert_eq!(
            reopened
                .active(&id)
                .expect("enrolled")
                .map(|active| active.generation),
            Some(index.generation.get()),
            "the generation the second sync activated"
        );
    }
}
