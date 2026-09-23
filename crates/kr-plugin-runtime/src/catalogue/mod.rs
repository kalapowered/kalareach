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

pub use crate::catalogue::authority::{Authority, Committed, Effect, Failure, Owner, Recording};
pub use crate::catalogue::broker::{BrokerBridge, UnboundBroker};
pub use crate::catalogue::budget::{BudgetLedger, Resource, ResourceLimit, Stage};
pub use crate::catalogue::ceiling::{
    CapabilityDecision, GrantRequirement, InstallationGrant, capability_from_str,
};
pub use crate::catalogue::db::{
    ActiveGeneration, Claimed, Durability, Enrolled, ReceiptClaim, ReceiptKey, ReceiptRecord,
};
pub use crate::catalogue::error::{CatalogueError, CatalogueResult};
pub use crate::catalogue::install::{
    Binding, BindingId, Bindings, DisablePolicy, Installation, RevocationNotice,
};
pub use crate::catalogue::repository::{
    CapabilityCeiling, Enrolment, EnrolmentKey, RepositoryId, RepositoryKind,
};
pub use crate::catalogue::search::{Candidate, MatchIndex, Observation, Resolution};
pub use crate::catalogue::store::{PackageCheck, ReadyPackage, Store};
pub use crate::catalogue::trust::{MetadataVersions, VerifiedGeneration};

use crate::catalogue::authority::committed;
use crate::catalogue::db::{Changes, Db, Records};
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
        let Some(enrolled) = self.db.read(|records| records.enrolment(id))? else {
            return Ok(None);
        };
        let Some(active) = enrolled.active else {
            return Ok(None);
        };
        Store::at(&self.root, &enrolled.key)
            .index(&active)
            .map(Some)
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
        self.db.read(|records| {
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
        self.db.read(|records| {
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

        // The metadata verified, so it becomes the accepted checkpoint now, in a commit of its
        // own: trust progress is kept whatever the generation checks, the mirror or the index
        // activation that follow decide, and the reset the checkpoint carries is no longer owed.
        {
            let key = &enrolled.key;
            let pending = self.db.begin()?;
            committed(authority, &Effect::Checkpoint(id.clone()), |permit| {
                store.publish_checkpoint(permit, &working)?;
                pending
                    .run(permit, |changes| changes.clear_trust_reset(key))
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

        let index_digest = verified
            .index
            .digest()
            .map_err(|source| CatalogueError::Integrity {
                detail: format!("the index could not be rendered: {source}"),
            })?;
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
            store.write_index(permit, &verified.index)
        })?;
        committing(&mut self.db, change, |changes| {
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
        let enrolled = self.enrolled(id)?;
        let store = Store::open(&self.root, &enrolled.key)?;
        let _lock = store.lock()?;
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
                .fetch(enrolled, store, &target, payload.digest, reason, authority)
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
    async fn fetch(
        &mut self,
        enrolled: &Enrolled,
        store: &Store,
        target: &str,
        digest: PayloadDigest,
        reason: FetchReason,
        authority: &dyn Authority,
    ) -> CatalogueResult<Vec<u8>> {
        // A cached object that is not cached, or whose bytes no longer hash to its name, is
        // fetched again. A store that cannot be read is neither: it is a failure of this host's
        // own disk, and reporting it as an absent payload would send a person looking at their
        // repository instead of their filesystem.
        match store.read_payload(digest) {
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
            &BTreeSet::new(),
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
        let enrolled = self.enrolled(id)?;
        let store = Store::open(&self.root, &enrolled.key)?;
        let _lock = store.lock()?;
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
                    let store = Store::open(&self.root, &enrolled.key)?;
                    let _lock = store.lock()?;
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
        store.plan_reclaim(length, &ledger_of(store, &enrolled)?, &protected, subject)
    })?;
    if plan.is_empty() {
        return Ok(());
    }
    let effect = Effect::Reclaim {
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
/// directory holds now.
///
/// Counted from the directory each time rather than carried: a count kept in memory drifts from
/// the directory whenever another writer changes it, and a budget nobody can explain is the
/// result.
fn ledger_of(store: &Store, enrolled: &Enrolled) -> CatalogueResult<BudgetLedger> {
    let mut ledger = BudgetLedger::new(enrolled.enrolment.budgets);
    for size in store.cached_payloads()?.values() {
        ledger.add_payload_bytes(*size);
    }
    if let Some(active) = enrolled.active {
        ledger.accept_metadata(active.index_bytes, active.entries);
    }
    Ok(ledger)
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
    use crate::catalogue::store::flush_fault;
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

        let floors = |working: &crate::catalogue::store::WorkingDatastore| {
            ["timestamp.json", "snapshot.json", "targets.json"]
                .map(|role| working.path().join(role).is_file())
        };
        assert_eq!(
            floors(&store.working_datastore(false).expect("a copy")),
            [true, true, true]
        );
        assert_eq!(
            floors(&store.working_datastore(true).expect("a copy")),
            [false, false, true],
            "the reset leaves the timestamp and snapshot floors out of the copy"
        );

        catalogue.sync(&id).await.expect("verified again");
        assert!(
            !owed(&catalogue),
            "a published checkpoint settles the reset"
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
