//! The plugin catalogue and plugin method groups, hosted by the control daemon.
//!
//! The daemon owns the admission and the environment; `kr-plugin-catalogue` owns the trust roots,
//! the budgets, the signed snapshot, the packages, what an installed package may do and the
//! receipts of the actions performed on them. What this module adds is the part that has to be
//! the daemon's.
//!
//! * Every method arrives through the daemon's ordinary path. A read is checked against current
//!   authority, a mutation carries an action window and is checked against the method registry,
//!   and neither has an admission path of its own.
//! * The admission travels into the catalogue as an [`Authority`], and the catalogue asks it again
//!   where the change becomes durable. [`DaemonAdmission`] answers by holding this daemon's
//!   connection table for the length of the commit, so a withdrawal lands wholly before the change
//!   or wholly after it.
//! * Adopting a trust root, granting a capability and an installation that widens what a package
//!   may do are the owner's decisions, and section 10 says outright that an operating-system
//!   identity is not that decision. Those methods carry the owner's confirmation of one exact
//!   action: the challenge this host issued and is still holding, answered under the enrolled
//!   signer, bound to the root, the grant or the installation in front of the owner, and consumed
//!   here so one ceremony authorises one action. The accepted confirmation is checked again inside
//!   the same commit.
//! * An action is claimed before it is performed, and its effect and the answer it gave commit in
//!   one transaction, so a resubmission is answered from that record rather than performed again,
//!   and an action a stopped daemon left mid-way reads as unknown rather than as refused.
//! * Enlarging trust is never a side effect of another method. A sync verifies inside the ceiling
//!   the enrolment already has and refuses a generation that would need more; an install that may
//!   do more than the installation it replaces, or, with nothing to replace, more than its
//!   repository's ceiling permits by itself, and every release that installs a native bridge, is
//!   refused unless it carries the owner's confirmation of that exact installation.

pub mod admissions;
pub mod bridge;
pub mod evidence;
pub(crate) mod files;
pub mod integrations;
pub mod native_bridge;

use std::sync::Arc;

use kr_plugin_catalogue::transport::RepositoryTransport;
use kr_plugin_catalogue::{
    Authority, CapabilityCeiling, Catalogue, CatalogueError, CatalogueResult, Change, Claimed,
    Effect, Enrolment, Installation, InstallationGrant, InstallationView, Owner, ReceiptClaim,
    ReceiptKey, ReceiptRecord, Recording, RepositoryId, RepositoryKind, RepositoryView, Transition,
    capability_from_str,
};
use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::version::PackageVersion;
use kr_protocol::actor::ActorIngress;
use kr_protocol::catalogue as wire;
use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{
    ActionId, ActorId, EnvironmentId, PluginId, RepositoryGeneration, RequestId,
};
use kr_protocol::method::{Method, MethodGroup};
use kr_protocol::receipt::ReceiptState;
use kr_protocol::scalars::{Digest256, Nullable, U64};
use tokio::sync::Mutex;

use crate::sharing::{ConfirmedAction, OwnerConfirmations};

/// What a catalogue call answers with: the method's result, or the refusal the service decided.
pub type Answer<T> = std::result::Result<T, ProtocolError>;

/// What a catalogue mutation is admitted under, as the catalogue and its receipt see it.
///
/// It is the catalogue's [`Authority`], asked again where each change becomes durable, and it
/// says which wall-clock deadline the mutation was accepted under, which its receipt records.
pub trait Admission: Authority {
    /// The deadline this mutation was accepted under, on the wall clock, where it has one.
    fn accepted_deadline_ms(&self) -> Option<u64>;
}

impl Admission for Owner {
    fn accepted_deadline_ms(&self) -> Option<u64> {
        None
    }
}

/// A catalogue mutation's admission, as this daemon carries it.
///
/// It is asked twice. [`Authority::check`] before the slow work, so a lapsed admission stops
/// without downloading anything, and [`Authority::commit`] where the change becomes durable,
/// holding this daemon's table of admitted connections for the length of the commit. Revoking
/// authority and withdrawing a connection take the same table, so neither can be ordered between
/// the check and the change.
pub struct DaemonAdmission {
    controller: Arc<crate::service::Controller>,
    admitted: crate::authority::AdmittedMutation,
}

impl DaemonAdmission {
    /// The admission one connection's mutation was accepted under.
    #[must_use]
    pub fn new(
        controller: Arc<crate::service::Controller>,
        admitted: crate::authority::AdmittedMutation,
    ) -> Self {
        Self {
            controller,
            admitted,
        }
    }
}

impl Authority for DaemonAdmission {
    fn check(&self) -> CatalogueResult<()> {
        self.controller
            .check_registration(&self.admitted)
            .map_err(|error| CatalogueError::Refused(error.to_protocol_error()))
    }

    fn commit(
        &self,
        _effect: &Effect,
        commit: &mut dyn FnMut() -> CatalogueResult<()>,
    ) -> CatalogueResult<()> {
        self.controller
            .under_registration(&self.admitted, commit)
            .map_err(|error| CatalogueError::Refused(error.to_protocol_error()))?
    }

    fn owner_confirmed(&self) -> bool {
        false
    }
}

impl Admission for DaemonAdmission {
    fn accepted_deadline_ms(&self) -> Option<u64> {
        self.controller.receipt_deadline_ms(&self.admitted)
    }
}

/// An admission that also carries the owner's accepted confirmation of one exact action.
///
/// The confirmation was accepted, and its challenge consumed, once. What is asked again at the
/// commit is whether that accepted confirmation still covers this action on this host within its
/// lifetime, inside the same held order as the admission itself.
struct Confirmed<'a> {
    admission: &'a dyn Authority,
    confirmed: ConfirmedAction,
    action_digest: Digest256,
    confirmations: &'a dyn OwnerConfirmations,
    subject: &'static str,
}

impl Confirmed<'_> {
    fn covers(&self) -> CatalogueResult<()> {
        self.confirmed
            .covers(
                self.action_digest,
                self.confirmations.host_device_id(),
                self.confirmations.clock(),
                self.subject,
            )
            .map_err(|error| CatalogueError::Refused(error.to_protocol_error()))
    }
}

impl Authority for Confirmed<'_> {
    fn check(&self) -> CatalogueResult<()> {
        self.admission.check()?;
        self.covers()
    }

    fn commit(
        &self,
        effect: &Effect,
        commit: &mut dyn FnMut() -> CatalogueResult<()>,
    ) -> CatalogueResult<()> {
        self.admission.commit(effect, &mut || {
            self.covers()?;
            commit()
        })
    }

    fn owner_confirmed(&self) -> bool {
        true
    }
}

/// How this host's catalogue reaches its repositories.
///
/// A directory on this host is read where it is, and an address is fetched with this product's
/// trust and through `proxy`, or directly when that is `None`. A host whose certificate
/// verification cannot be set up still reads the repositories on its own disk, and says why
/// whenever it is asked to fetch one.
#[must_use]
pub fn repository_transport(proxy: Option<&kr_transport::config::ProxyUrl>) -> RepositoryTransport {
    match kr_client::services::http::client_builder(proxy) {
        Ok(builder) => RepositoryTransport::over(builder),
        Err(error) => {
            RepositoryTransport::local_only(format!("this host fetches no repository: {error}"))
        }
    }
}

/// The catalogue, as the daemon holds it.
#[derive(Debug)]
pub struct CatalogueModule {
    catalogue: Arc<Mutex<Catalogue>>,
    environment_id: EnvironmentId,
    /// The native bridges installed packages put in their applications' own directories.
    bridges: Arc<native_bridge::NativeBridges>,
    /// The last snapshot of admissions computed, with the revision and the live releases it was
    /// computed for: rounds at an unchanged revision reuse it. Nothing a snapshot carries moves
    /// without the revision moving, the bridges included (see [`Self::write`]).
    snapshots: Arc<std::sync::Mutex<Option<CachedSnapshot>>>,
    /// The enrolment budgets this host's configuration puts in force: set at the daemon's start
    /// and at every acceptance of the configuration after it, by the rule every value in force
    /// follows (`config::catalogue::budgets_in_force`), and read by each enrolment and each
    /// synchronisation, never cached at open.
    budgets: std::sync::Mutex<kr_protocol::hostinfo::configuration::EnrolmentBudgets>,
    /// The limits those budgets set, which the catalogue reads at every use: every package's, and
    /// what one synchronisation may transfer.
    limits: kr_plugin_catalogue::LimitsInForce,
    /// Run at each [`TestingPoint`], for tests that hold a computation there.
    #[cfg(feature = "testing")]
    testing_hook: Arc<std::sync::Mutex<Option<TestingHook>>>,
    /// Set by this host's own tests to make the next raise of the admission revision for moved
    /// package limits fail as a store that does not answer would. Compiled away in every shipped
    /// build.
    #[cfg(feature = "testing")]
    raise_fault: std::sync::atomic::AtomicBool,
    /// The disable policy each snapshot this module computed carried, in the order they were
    /// computed, for this host's own tests. Compiled away in every shipped build.
    #[cfg(feature = "testing")]
    policies_carried: Arc<std::sync::Mutex<Vec<kr_protocol::admission::RevocationPolicy>>>,
}

/// Where a test may hold a computation of this module.
#[cfg(feature = "testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestingPoint {
    /// A read of the records for a round, a refresh or the cadence, once the catalogue is held.
    Records,
    /// A snapshot's package checks, once the catalogue is let go.
    PackageChecks,
}

/// A hook a test runs at each [`TestingPoint`].
#[cfg(feature = "testing")]
#[derive(Clone)]
struct TestingHook(Arc<dyn Fn(TestingPoint) + Send + Sync>);

#[cfg(feature = "testing")]
impl std::fmt::Debug for TestingHook {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TestingHook")
    }
}

/// One computed snapshot and what it was computed for.
#[derive(Debug)]
struct CachedSnapshot {
    revision: u64,
    live: Vec<kr_protocol::admission::LiveRelease>,
    snapshot: admissions::Snapshot,
}

impl CatalogueModule {
    /// Opens the environment's catalogue.
    ///
    /// Every action an earlier daemon left mid-dispatch is settled as unknown here, before this
    /// one serves anything: its change may have been made, so it is never performed again and
    /// never reported as refused.
    ///
    /// Its repositories are fetched with this product's trust and through `proxy`, the one this
    /// host's configuration document selected when the daemon started, or directly when it
    /// selected none; a directory on this host is read where it is.
    ///
    /// `budgets` and `policy` are what this host's configuration puts in force when the daemon
    /// starts: the limits the budgets set hold every package from the first check on, and the
    /// disable policy is recorded, with the admission revision it moves, before any snapshot is
    /// computed, so the first round a worker that outlived the last daemon receives carries it.
    /// `None` leaves the policy this catalogue already records. `allowed` is the adapters the
    /// organisation's policy allows, or `None` for every adapter: it is in force before any native
    /// bridge is brought to what its installation wants, so a restart puts back no registration
    /// the list excludes.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ControllerError::RegistryUnavailable`] when the catalogue's directory or
    /// its records cannot be opened, or when the policy cannot be recorded: a host that cannot
    /// put its administrator's policy in force does not start without saying so.
    pub fn open(
        paths: &kr_ipc::paths::EnvironmentPaths,
        proxy: Option<&kr_transport::config::ProxyUrl>,
        broker: Arc<dyn kr_plugin_catalogue::BrokerBridge>,
        budgets: kr_protocol::hostinfo::configuration::EnrolmentBudgets,
        policy: Option<kr_protocol::admission::RevocationPolicy>,
        allowed: Option<std::collections::BTreeSet<PluginId>>,
    ) -> crate::Result<Self> {
        Self::open_with(
            paths,
            proxy,
            native_bridge::BridgeHost::discover(paths.state_dir()),
            broker,
            budgets,
            policy,
            allowed,
        )
    }

    /// Opens the environment's catalogue, applying native bridges where `bridges` says, and asking
    /// `broker` what the workers hold live whenever a reclaim needs room.
    ///
    /// `budgets` and `policy` are what [`Self::open`] describes. Before this daemon serves
    /// anything, every package's bridge is brought to what its installation wants: a recipe an
    /// earlier daemon left part way is finished or undone, and one whose package is no longer
    /// installed is taken out.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::open`] returns.
    pub fn open_with(
        paths: &kr_ipc::paths::EnvironmentPaths,
        proxy: Option<&kr_transport::config::ProxyUrl>,
        bridges: native_bridge::BridgeHost,
        broker: Arc<dyn kr_plugin_catalogue::BrokerBridge>,
        budgets: kr_protocol::hostinfo::configuration::EnrolmentBudgets,
        policy: Option<kr_protocol::admission::RevocationPolicy>,
        allowed: Option<std::collections::BTreeSet<PluginId>>,
    ) -> crate::Result<Self> {
        let root = paths.state_dir().join("catalogue");
        let unavailable = |error: CatalogueError| crate::ControllerError::RegistryUnavailable {
            detail: error.to_string(),
        };
        let mut catalogue =
            Catalogue::with_broker(&root, broker, Arc::new(repository_transport(proxy)))
                .map_err(unavailable)?;
        catalogue
            .recover_interrupted(kr_ipc::now_ms().get())
            .map_err(unavailable)?;
        if let Some(policy) = policy {
            record_disable_policy(&mut catalogue, admissions::disable_policy_of(policy))
                .map_err(unavailable)?;
        }
        catalogue
            .set_allowed_adapters(allowed, &Owner::acting())
            .map_err(unavailable)?;
        let limits = kr_plugin_catalogue::LimitsInForce::default();
        limits.put(limits_of(&budgets));
        catalogue.read_limits_from(limits.clone());
        let bridges = Arc::new(native_bridge::NativeBridges::new(bridges));
        let environment_id = paths.environment_id();
        for plugin_id in bridge_subjects(&catalogue, &bridges, environment_id) {
            follow_bridge(&catalogue, &bridges, environment_id, &plugin_id);
        }
        Ok(Self {
            catalogue: Arc::new(Mutex::new(catalogue)),
            environment_id,
            bridges,
            snapshots: Arc::new(std::sync::Mutex::new(None)),
            budgets: std::sync::Mutex::new(budgets),
            limits,
            #[cfg(feature = "testing")]
            testing_hook: Arc::new(std::sync::Mutex::new(None)),
            #[cfg(feature = "testing")]
            raise_fault: std::sync::atomic::AtomicBool::new(false),
            #[cfg(feature = "testing")]
            policies_carried: Arc::default(),
        })
    }

    /// Returns the native bridges installed packages put in place, which say what each applied
    /// release yields.
    #[must_use]
    pub fn native_bridges(&self) -> &native_bridge::NativeBridges {
        &self.bridges
    }

    /// Returns the admissions in force now, as records on the wire, for this host: what new
    /// bindings may use and the state of every admitted release and of every release in `live`.
    ///
    /// Everything here ends at `deadline`: the wait for the catalogue, which a synchronisation
    /// holds across its network work, the reading of its records, and the package checks. The
    /// records and the bridges are read while the catalogue is held; the package checks read only
    /// copies their hashes name, and run after it is let go, so a slow package holds this snapshot
    /// and no other catalogue work. A snapshot computed for this revision, these bridges and these
    /// live releases is reused.
    ///
    /// # Errors
    ///
    /// Returns `RESOURCE_UNAVAILABLE` when the catalogue stays busy or the computation runs past
    /// `deadline`, and the refusal the catalogue decided when its records cannot be read.
    pub async fn snapshot_within(
        &self,
        live: &[kr_protocol::admission::LiveRelease],
        deadline: tokio::time::Instant,
    ) -> Answer<admissions::Snapshot> {
        enum First {
            Cached(admissions::Snapshot),
            Planned(Box<admissions::Planned>),
        }
        let catalogue = tokio::time::timeout_at(deadline, Arc::clone(&self.catalogue).lock_owned())
            .await
            .map_err(|_| busy())?;
        let bridges = Arc::clone(&self.bridges);
        let snapshots = Arc::clone(&self.snapshots);
        let environment_id = self.environment_id;
        let live = live.to_vec();
        let key = live.clone();
        let first = tokio::task::spawn_blocking(move || -> Answer<First> {
            let revision = catalogue
                .admission_revision()
                .map_err(ProtocolError::from)?;
            if let Some(held) = snapshots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                && held.revision == revision
                && held.live == live
            {
                return Ok(First::Cached(held.snapshot.clone()));
            }
            let planned = admissions::plan(
                &catalogue,
                &bridges,
                environment_id,
                &live,
                &kr_plugin_catalogue::this_host(),
            )
            .map_err(ProtocolError::from)?;
            Ok(First::Planned(Box::new(planned)))
        });
        let planned = match tokio::time::timeout_at(deadline, first)
            .await
            .map_err(|_| busy())?
            .map_err(|error| {
                ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string())
            })?? {
            First::Cached(snapshot) => return Ok(snapshot),
            First::Planned(planned) => *planned,
        };
        let revision = planned.revision();
        let snapshots = Arc::clone(&self.snapshots);
        #[cfg(feature = "testing")]
        let hook = self.testing_hook();
        #[cfg(feature = "testing")]
        let carried = Arc::clone(&self.policies_carried);
        let second = tokio::task::spawn_blocking(move || -> Answer<admissions::Snapshot> {
            #[cfg(feature = "testing")]
            if let Some(hook) = hook {
                (hook.0)(TestingPoint::PackageChecks);
            }
            let snapshot = planned.complete().map_err(ProtocolError::from)?;
            #[cfg(feature = "testing")]
            carried
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(snapshot.policy);
            *snapshots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(CachedSnapshot {
                revision,
                live: key,
                snapshot: snapshot.clone(),
            });
            Ok(snapshot)
        });
        tokio::time::timeout_at(deadline, second)
            .await
            .map_err(|_| busy())?
            .map_err(|error| ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string()))?
    }

    /// Makes the next raise of the admission revision for moved package limits fail, as a store
    /// that does not answer would, for this host's own tests.
    #[cfg(feature = "testing")]
    pub fn fail_next_revision_raise(&self) {
        self.raise_fault
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Returns the disable policy each snapshot this module computed carried, oldest first, for
    /// this host's own tests.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn policies_carried(&self) -> Vec<kr_protocol::admission::RevocationPolicy> {
        self.policies_carried
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Runs `hook` at each [`TestingPoint`] a computation of this module reaches.
    #[cfg(feature = "testing")]
    pub fn at_testing_point(&self, hook: impl Fn(TestingPoint) + Send + Sync + 'static) {
        *self
            .testing_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(TestingHook(Arc::new(hook)));
    }

    #[cfg(feature = "testing")]
    fn testing_hook(&self) -> Option<TestingHook> {
        self.testing_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Returns the admission revision now, waiting for the catalogue no later than `deadline`.
    ///
    /// # Errors
    ///
    /// Returns `RESOURCE_UNAVAILABLE` when the catalogue stays busy past `deadline`, and the refusal
    /// the catalogue decided when the record cannot be read.
    pub async fn admission_revision_within(&self, deadline: tokio::time::Instant) -> Answer<u64> {
        self.read_within(deadline, |catalogue| {
            catalogue.admission_revision().map_err(ProtocolError::from)
        })
        .await
    }

    /// Puts the enrolment budgets this host's configuration holds in force for the changes that
    /// follow, and the limits they set in force for every check the catalogue makes from now on.
    ///
    /// Package limits that move move what the admissions carry with no record changing, so the
    /// admission revision rises with them, in one step under the catalogue's own lock: the
    /// revision is raised first and the budgets are put in force once it is written. No read of
    /// the catalogue sees the old revision with the new limits or the new revision with the old
    /// ones, and every snapshot under the new limits is above every one under the old. Returns true
    /// when the package limits moved, so the caller sends every worker a round.
    ///
    /// # Errors
    ///
    /// Returns the refusal the catalogue gave when the revision could not be raised, and then
    /// nothing is put in force: the budgets and limits in force still differ from `budgets`, so
    /// the next acceptance of the same configuration tries again.
    pub async fn put_budgets_in_force(
        &self,
        budgets: kr_protocol::hostinfo::configuration::EnrolmentBudgets,
    ) -> Answer<bool> {
        let mut catalogue = self.catalogue.lock().await;
        let limits = limits_of(&budgets);
        let moved = self.limits.get().package != limits.package;
        if moved {
            #[cfg(feature = "testing")]
            if self
                .raise_fault
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(ProtocolError::new(
                    ErrorCode::StorageUnavailable,
                    "the admission revision could not be written",
                ));
            }
            catalogue
                .raise_admission_revision(&Owner::acting())
                .map_err(ProtocolError::from)?;
        }
        *self
            .budgets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = budgets;
        self.limits.put(limits);
        Ok(moved)
    }

    /// Puts the disable policy this host's configuration decides in force for the admissions that
    /// follow, and returns true when that changed what was in force, so the caller sends every
    /// worker a round.
    ///
    /// The policy is part of what the admissions carry, so the admission revision rises with it,
    /// in the same commit that records the policy, under the catalogue's own lock: no read of the
    /// catalogue sees the new policy at the old revision. A policy equal to the one in force
    /// changes nothing and raises nothing, and a record that cannot be read is replaced by the
    /// policy the configuration decides.
    ///
    /// # Errors
    ///
    /// Returns the refusal the catalogue gave when the policy could not be recorded, and then the
    /// policy in force is the one before: the next acceptance of the same configuration tries
    /// again.
    pub async fn put_disable_policy_in_force(
        &self,
        policy: kr_protocol::admission::RevocationPolicy,
    ) -> Answer<bool> {
        let mut catalogue = self.catalogue.lock().await;
        let wanted = admissions::disable_policy_of(policy);
        if matches!(catalogue.disable_policy(), Ok(held) if held == wanted) {
            return Ok(false);
        }
        #[cfg(feature = "testing")]
        if self
            .raise_fault
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(ProtocolError::new(
                ErrorCode::StorageUnavailable,
                "the admission revision could not be written",
            ));
        }
        record_disable_policy(&mut catalogue, wanted).map_err(ProtocolError::from)
    }

    /// Puts the adapters an organisation's policy allows in force for the admissions that follow,
    /// or every adapter with `None`, and returns true when that changed what was in force, so the
    /// caller sends every worker a round.
    ///
    /// # Errors
    ///
    /// Returns the refusal the catalogue gave when the revision could not be raised, and then the
    /// list in force is the one before.
    pub async fn put_allowed_adapters(
        &self,
        allowed: Option<std::collections::BTreeSet<PluginId>>,
    ) -> Answer<bool> {
        let mut catalogue = self.catalogue.lock().await;
        let moved = catalogue
            .set_allowed_adapters(allowed, &Owner::acting())
            .map_err(ProtocolError::from)?;
        if moved {
            // The list changed which packages may run in an application's name, so each bridge
            // follows what its installation now wants, under the same lock and after the change's
            // commit, as a plugin change's bridge does.
            let subjects = bridge_subjects(&catalogue, &self.bridges, self.environment_id);
            let wanted = self.wanted_bridges(&catalogue, subjects);
            self.follow_bridges(wanted).await;
        }
        Ok(moved)
    }

    /// What each of `subjects`' installations wants of its native bridge, read from the catalogue
    /// the caller holds.
    fn wanted_bridges(
        &self,
        catalogue: &Catalogue,
        subjects: Vec<PluginId>,
    ) -> Vec<(PluginId, CatalogueResult<WantedBridge>)> {
        subjects
            .into_iter()
            .map(|plugin_id| {
                let wanted = wanted_bridge(catalogue, self.environment_id, &plugin_id);
                (plugin_id, wanted)
            })
            .collect()
    }

    /// Brings each native bridge to what its installation wants. What a bridge does is its own
    /// journal's and never changes the answer of the change that moved it.
    async fn follow_bridges(&self, wanted: Vec<(PluginId, CatalogueResult<WantedBridge>)>) {
        for (plugin_id, wanted) in wanted {
            let bridges = Arc::clone(&self.bridges);
            let followed = tokio::task::spawn_blocking(move || {
                reconcile_bridge(&bridges, &plugin_id, wanted);
            })
            .await;
            if let Err(error) = followed {
                eprintln!("kr-controller: a native bridge was not reconciled: {error}");
            }
        }
    }

    /// Resolves a confirmation subject the catalogue describes into what its challenge names and
    /// what an owner device is shown, from the exact `catalogue.add` or `plugin.install` request
    /// and from what this host holds, never from anything the caller says about the request.
    ///
    /// The digest is the one the effect builds from the same request, so the challenge issued for
    /// a subject is spent by that request and by no other. For an installation that asks for a
    /// native bridge the statement is read from the verified manifest of the exact package hash,
    /// which may have to be fetched, so this runs before the challenge exists and nothing is
    /// issued for a release whose manifest cannot be read.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` for a request that already carries a proof or for a subject the
    /// catalogue does not describe, and the refusal the same request would meet: another
    /// environment, a budget this host does not allow, a root that cannot be read, a repository
    /// that is not enrolled, or a release the index does not carry.
    pub async fn resolve_confirmation(
        &self,
        subject: &kr_protocol::confirmation::ConfirmationSubject,
    ) -> Answer<crate::service::net::owner::Resolved> {
        use kr_protocol::confirmation::{ConfirmationDisplay, ConfirmationSubject};
        let carries_a_proof = || {
            ProtocolError::new(
                ErrorCode::InvalidArgument,
                "a confirmation is asked for a request without its proof: the request that \
                 carries one is not waiting for an answer",
            )
        };
        match subject {
            ConfirmationSubject::CatalogueAdd(params) => {
                if params.owner_confirmation.is_present() {
                    return Err(carries_a_proof());
                }
                self.check_environment(params.environment_id)?;
                within_budgets(&params.budgets, &self.budgets_in_force())?;
                let enrolment = enrolment_from(params)?;
                let plan = trust_plan(params, &enrolment)?;
                let digest = plan
                    .action_digest()
                    .map_err(|error| error.to_protocol_error())?;
                Ok(crate::service::net::owner::Resolved {
                    action: crate::sharing::CatalogueTrustPlan::sensitive_action(),
                    digest,
                    destination: None,
                    rights: kr_protocol::scalars::CanonicalSet::new(),
                    display: ConfirmationDisplay::CatalogueAdd {
                        environment_id: params.environment_id,
                        catalogue_id: plan.catalogue_id.clone(),
                        kind: params.kind,
                        metadata_url: params.metadata_url.clone(),
                        targets_url: params.targets_url.clone(),
                        root_digest: plan.root_digest.clone(),
                        root_key_ids: plan.root_key_ids.iter().cloned().collect(),
                        ceiling: plan.ceiling.iter().cloned().collect(),
                    },
                    first_owner: false,
                })
            }
            ConfirmationSubject::PluginInstall(params) => {
                if params.owner_confirmation.is_present() {
                    return Err(carries_a_proof());
                }
                self.check_environment(params.environment_id)?;
                let mut catalogue = self.catalogue.lock().await;
                let (plan, _) = install_plan(&mut catalogue, params).await?;
                drop(catalogue);
                let digest = plan
                    .action_digest()
                    .map_err(|error| error.to_protocol_error())?;
                Ok(crate::service::net::owner::Resolved {
                    action: crate::sharing::PluginInstallPlan::sensitive_action(),
                    digest,
                    destination: None,
                    rights: kr_protocol::scalars::CanonicalSet::new(),
                    display: ConfirmationDisplay::PluginInstall {
                        environment_id: params.environment_id,
                        catalogue_id: plan.catalogue_id.clone(),
                        plugin_id: plan.plugin_id.clone(),
                        version: plan.version.clone(),
                        package_digest: plan.package_digest.clone(),
                        ceiling: plan.ceiling.iter().cloned().collect(),
                        grant: plan.grant.iter().cloned().collect(),
                        grant_statement: Nullable(plan.grant_statement.clone()),
                    },
                    first_owner: false,
                })
            }
            _ => Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                "the catalogue describes a repository's root and an installation, and nothing \
                 else",
            )),
        }
    }

    /// Returns the disable policy in force.
    ///
    /// # Errors
    ///
    /// Returns the refusal the catalogue gave when the setting cannot be read.
    pub async fn disable_policy_in_force(
        &self,
    ) -> Answer<kr_protocol::admission::RevocationPolicy> {
        let catalogue = self.catalogue.lock().await;
        catalogue
            .disable_policy()
            .map(admissions::revocation_policy_of)
            .map_err(ProtocolError::from)
    }

    /// Returns the enrolment budgets in force.
    #[must_use]
    pub fn budgets_in_force(&self) -> kr_protocol::hostinfo::configuration::EnrolmentBudgets {
        *self
            .budgets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Returns one evidence record per enrolled repository, for the doctor, waiting no later than
    /// `deadline`.
    ///
    /// # Errors
    ///
    /// Returns `RESOURCE_UNAVAILABLE` when the catalogue stays busy or the read runs past
    /// `deadline`, and the refusal the catalogue decided when its records cannot be read.
    pub async fn evidence_within(
        &self,
        deadline: tokio::time::Instant,
    ) -> Answer<Vec<crate::config::catalogue::RepositoryEvidence>> {
        self.read_within(deadline, |catalogue| {
            evidence::repositories(catalogue).map_err(ProtocolError::from)
        })
        .await
    }

    /// Runs `read` on the catalogue on a thread that may block, waiting for the catalogue and for
    /// the read no later than `deadline`. A read still running then finishes on its own, holding
    /// the catalogue until it does, and its answer is dropped.
    async fn read_within<T: Send + 'static>(
        &self,
        deadline: tokio::time::Instant,
        read: impl FnOnce(&Catalogue) -> Answer<T> + Send + 'static,
    ) -> Answer<T> {
        let catalogue = tokio::time::timeout_at(deadline, Arc::clone(&self.catalogue).lock_owned())
            .await
            .map_err(|_| busy())?;
        #[cfg(feature = "testing")]
        let hook = self.testing_hook();
        let task = tokio::task::spawn_blocking(move || {
            #[cfg(feature = "testing")]
            if let Some(hook) = hook {
                (hook.0)(TestingPoint::Records);
            }
            read(&catalogue)
        });
        tokio::time::timeout_at(deadline, task)
            .await
            .map_err(|_| busy())?
            .map_err(|error| ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string()))?
    }

    /// Returns the admission revision now.
    ///
    /// # Errors
    ///
    /// Returns the refusal the catalogue decided when the record cannot be read.
    pub async fn admission_revision(&self) -> Answer<u64> {
        self.catalogue
            .lock()
            .await
            .admission_revision()
            .map_err(ProtocolError::from)
    }

    /// Returns the admission revision and the release every installation in this environment
    /// holds, by the key a live release is found by, read together and waiting for the catalogue
    /// no later than `deadline`.
    ///
    /// # Errors
    ///
    /// Returns `RESOURCE_UNAVAILABLE` when the catalogue stays busy past `deadline`, and the refusal
    /// the catalogue decided when a record cannot be read.
    pub async fn installed_within(
        &self,
        deadline: tokio::time::Instant,
    ) -> Answer<(u64, std::collections::BTreeSet<bridge::ReleaseKey>)> {
        let environment_id = self.environment_id;
        self.read_within(deadline, move |catalogue| {
            let revision = catalogue
                .admission_revision()
                .map_err(ProtocolError::from)?;
            let installed = catalogue
                .installations()
                .map_err(ProtocolError::from)?
                .into_iter()
                .filter(|installation| installation.environment_id == environment_id)
                .map(|installation| installed_key(&installation))
                .collect();
            Ok((revision, installed))
        })
        .await
    }

    /// Returns true when this daemon serves the method.
    #[must_use]
    pub fn serves(method: Method) -> bool {
        matches!(
            method.group(),
            MethodGroup::PluginCatalogues | MethodGroup::Plugins
        )
    }

    /// Checks that a catalogue mutation's envelope and its parameters name the same subject.
    ///
    /// A catalogue and a package belong to an environment, not to a session or a foreground
    /// application, so a target that names one is refused rather than producing a receipt against
    /// something the effect never touched.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ControllerError::InvalidArgument`] when the two disagree.
    pub fn check_subject(method: Method, mutation: &MutationRequest) -> crate::Result<()> {
        if mutation.target.session_id.is_present()
            || mutation.target.application_instance_id.is_present()
        {
            return Err(crate::ControllerError::InvalidArgument(format!(
                "{} acts on a catalogue or a package, not on a session or an application",
                method.as_str()
            )));
        }
        let named = match method {
            Method::CatalogueAdd => subject::<wire::CatalogueAddParams>(&mutation.params)?,
            Method::CatalogueSync => subject::<wire::CatalogueSyncParams>(&mutation.params)?,
            Method::CataloguePin => subject::<wire::CataloguePinParams>(&mutation.params)?,
            Method::CatalogueRemove => subject::<wire::CatalogueRemoveParams>(&mutation.params)?,
            Method::PluginInstall => subject::<wire::PluginInstallParams>(&mutation.params)?,
            Method::PluginRemove => subject::<wire::PluginRemoveParams>(&mutation.params)?,
            Method::PluginPin => subject::<wire::PluginPinParams>(&mutation.params)?,
            Method::PluginEnable | Method::PluginDisable => {
                subject::<wire::PluginEnableParams>(&mutation.params)?
            }
            Method::PluginGrant => subject::<wire::PluginGrantParams>(&mutation.params)?,
            _ => {
                return Err(crate::ControllerError::InvalidArgument(format!(
                    "{} is not a catalogue mutation this daemon serves",
                    method.as_str()
                )));
            }
        };
        if named != mutation.target.environment_id {
            return Err(crate::ControllerError::InvalidArgument(
                "the request's target and its parameters name different environments".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the catalogue itself, for a caller that already holds the daemon.
    #[must_use]
    pub const fn catalogue(&self) -> &Arc<Mutex<Catalogue>> {
        &self.catalogue
    }

    /// Serves one catalogue or plugin read and returns the frame it answers with.
    ///
    /// `view` is what the workers reported, which `plugin.list` counts from; every other read
    /// takes none.
    #[must_use]
    pub async fn read_frame(
        &self,
        ingress: ActorIngress,
        request: &Request,
        view: Option<&bridge::LiveView>,
    ) -> ControlFrame {
        frame(request.request_id, self.read(ingress, request, view).await)
    }

    /// Serves one catalogue or plugin read.
    ///
    /// `ingress` is where the request arrived. The registry lists each of these reads at more than
    /// one ingress, so the answer is decided at the caller's own: a method kept to private IPC
    /// stays unreachable from a paired device even though this module serves both.
    ///
    /// # Errors
    ///
    /// Returns the refusal the catalogue decided, under the catalogue's own code.
    pub async fn read(
        &self,
        ingress: ActorIngress,
        request: &Request,
        view: Option<&bridge::LiveView>,
    ) -> Answer<ParamsValue> {
        let Some(method) = request.method.method() else {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "the method is not in the registry",
            ));
        };
        match kr_protocol::method::decide(request.method.as_str(), request.method_version, ingress)
        {
            kr_protocol::authority::AuthorityDecision::Listed(_) => {}
            kr_protocol::authority::AuthorityDecision::Denied(reason) => {
                return Err(match reason.error_code() {
                    ErrorCode::UnsupportedSchema => ProtocolError::new(
                        ErrorCode::UnsupportedSchema,
                        format!(
                            "{} is not implemented at version {}",
                            request.method.as_str(),
                            request.method_version
                        ),
                    ),
                    _ => ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        format!(
                            "{} is not a read this daemon serves",
                            request.method.as_str()
                        ),
                    ),
                });
            }
        }
        let catalogue = self.catalogue.lock().await;
        match method {
            Method::CatalogueList => {
                let params: wire::CatalogueListParams = typed(&request.params)?;
                self.check_environment(params.environment_id)?;
                let views = catalogue.repository_views().map_err(ProtocolError::from)?;
                encode(&wire::CatalogueListResult {
                    catalogues: views.iter().map(summary).collect(),
                })
            }
            Method::PluginList => {
                let params: wire::PluginListParams = typed(&request.params)?;
                self.check_environment(params.environment_id)?;
                let views = catalogue
                    .installation_views(params.environment_id)
                    .map_err(ProtocolError::from)?;
                let empty = bridge::LiveView::default();
                let view = view.unwrap_or(&empty);
                // Counts read at another revision than the one this answer renders are not given:
                // a change committed since the workers answered makes them unknown.
                let current = catalogue
                    .admission_revision()
                    .map_err(ProtocolError::from)?;
                let counts = view.counts.as_ref().filter(|_| view.revision == current);
                let admissions = view
                    .admissions
                    .as_ref()
                    .filter(|admissions| admissions.revision == current);
                let mut plugins = Vec::with_capacity(views.len());
                for installation in &views {
                    let mut summary = plugin_summary(installation)?;
                    let key = installed_key(&installation.installation);
                    summary.live_bindings = Nullable::from(counts.map(|counts| {
                        U64::new(counts.get(&key).map_or(0, |(_, count, _)| *count))
                    }));
                    summary.admission = Nullable::from(admissions.and_then(|admissions| {
                        admissions.admission_of(
                            &installation.installation.plugin_id,
                            installation.installation.package_digest,
                        )
                    }));
                    plugins.push(summary);
                }
                let installed: std::collections::BTreeSet<bridge::ReleaseKey> = views
                    .iter()
                    .map(|installation| installed_key(&installation.installation))
                    .collect();
                // Every release a worker reports that no installation describes stays listed,
                // ending where it ends, until its bindings close; its revocation is its own
                // origin's.
                let left: Vec<kr_protocol::admission::LiveRelease> = view
                    .live
                    .iter()
                    .filter(|(key, _)| !installed.contains(*key))
                    .map(|(_, (release, _))| release.clone())
                    .collect();
                let states = admissions::release_states(
                    &catalogue,
                    self.environment_id,
                    &left,
                    &kr_plugin_catalogue::this_host(),
                )
                .map_err(ProtocolError::from)?;
                let live_releases = left
                    .iter()
                    .map(|release| {
                        let key = bridge::key_of(release);
                        let state = states.iter().find(|state| {
                            (
                                state.plugin_id.clone(),
                                state.package_digest,
                                state.origin.clone(),
                            ) == key
                        });
                        kr_protocol::admission::LiveReleaseSummary {
                            plugin_id: release.plugin_id.clone(),
                            version: release.version.clone(),
                            package_digest: kr_plugin_sdk::digest::PayloadDigest::from_bytes(
                                *release.package_digest.as_bytes(),
                            )
                            .to_string(),
                            catalogue_id: release.origin.repository_id.clone(),
                            live_bindings: Nullable::from(counts.map(|counts| {
                                U64::new(counts.get(&key).map_or(0, |(_, count, _)| *count))
                            })),
                            ending: view.live.get(&key).is_some_and(|(_, ending)| *ending)
                                || state.is_some_and(|state| state.ends_at_next_boundary),
                            revoked: state.is_some_and(|state| state.revocation.is_present()),
                        }
                    })
                    .collect();
                encode(&wire::PluginListResult {
                    plugins,
                    live_releases,
                })
            }
            Method::PluginCapabilities => {
                let params: wire::PluginCapabilitiesParams = typed(&request.params)?;
                self.check_environment(params.environment_id)?;
                let view = catalogue
                    .installation_view(params.environment_id, &params.plugin_id)
                    .map_err(ProtocolError::from)?;
                let installation = &view.installation;
                // The repository may have been removed since this package was installed. An
                // installed package stays usable, so an answer about it never depends on an
                // enrolment: no enrolment and no index are answers, and the evidence is then built
                // from what the installation itself recorded. A record or an index this host
                // cannot read is not such an answer and is returned as the failure it is.
                let generation = match catalogue
                    .repository(&installation.repository)
                    .map_err(ProtocolError::from)?
                {
                    Some(_) => catalogue
                        .active(&installation.repository)
                        .map_err(ProtocolError::from)?
                        .map_or(1, |active| active.generation),
                    None => 1,
                };
                let current = catalogue
                    .current_index(&installation.repository)
                    .map_err(ProtocolError::from)?;
                let evidence_records = if let Some(index) = current.as_ref()
                    && let Some(entry) = index.find(&installation.plugin_id, &installation.version)
                {
                    evidence(entry, installation, generation)?
                } else {
                    fallback_evidence(installation, generation)?
                };
                encode(&wire::PluginCapabilitiesResult {
                    plugin: plugin_summary(&view)?,
                    capabilities: grants(&installation.requested, &view.decisions)?,
                    evidence: evidence_records,
                })
            }
            _ => Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                format!("{} is not a read this daemon serves", method.as_str()),
            )),
        }
    }

    /// Returns the answer a retained catalogue or plugin mutation is owed.
    #[must_use]
    pub async fn retained(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        _method: Method,
    ) -> Option<ControlFrame> {
        // A mutation whose digest cannot be computed is refused for that when it is performed;
        // there is no receipt to find for it here.
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id).ok()?;
        let catalogue = self.catalogue.lock().await;
        match catalogue.receipt(&receipt_key(actor_id, mutation.action_id)) {
            Ok(Some(record)) => Some(frame(
                mutation.request_id,
                answered(&record, &digest, mutation.action_id),
            )),
            Ok(None) => None,
            Err(error) => Some(frame(mutation.request_id, Err(error.into()))),
        }
    }

    /// Returns one catalogue action's receipt, for `action.read` in the host's own scope.
    ///
    /// The receipt belongs to the actor that submitted the action, and nobody else reads it here.
    /// `None` means this catalogue holds no receipt for that actor's action.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::StorageUnavailable`] when the record cannot be read.
    pub async fn action_read(
        &self,
        actor_id: &ActorId,
        action_id: ActionId,
    ) -> Answer<Option<kr_protocol::receipt::ActionReadResult>> {
        let catalogue = self.catalogue.lock().await;
        let Some(record) = catalogue
            .receipt(&receipt_key(actor_id, action_id))
            .map_err(ProtocolError::from)?
        else {
            return Ok(None);
        };
        Ok(Some(action_read_result(actor_id, action_id, &record)?))
    }

    /// Serves one catalogue or plugin mutation and returns the frame it answers with.
    #[must_use]
    pub async fn write_frame(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        confirmations: Option<&dyn OwnerConfirmations>,
        admission: Arc<dyn Admission>,
        removal: Option<(u64, u64)>,
    ) -> ControlFrame {
        frame(
            mutation.request_id,
            self.write(
                actor_id,
                mutation,
                method,
                confirmations,
                admission,
                removal,
            )
            .await,
        )
    }

    /// Serves one catalogue or plugin mutation as the owner acting directly, with no admission
    /// window to lapse.
    #[must_use]
    pub async fn write_frame_admitted(
        &self,
        mutation: &MutationRequest,
        method: Method,
        confirmations: Option<&dyn OwnerConfirmations>,
    ) -> ControlFrame {
        let actor = ActorId::new("kr:local").expect("a default actor");
        self.write_frame(
            &actor,
            mutation,
            method,
            confirmations,
            Arc::new(Owner::acting()),
            None,
        )
        .await
    }

    /// Serves one catalogue or plugin mutation.
    ///
    /// `confirmations` is where the methods that need the owner's confirmation (adopting a root, a
    /// grant, an installation that widens what a package may do) check the owner's decision.
    /// `None` is a host with no enrolled owner signer, which refuses them rather than performing
    /// them under the identity of whoever called.
    ///
    /// `removal` is, for `plugin.remove`, how many live bindings the workers reported holding the
    /// package and the admission revision their reports were at; the removal answers with that
    /// count only when it commits right after that revision.
    ///
    /// # Errors
    ///
    /// Returns the refusal the catalogue decided, under the catalogue's own code.
    pub async fn write(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        confirmations: Option<&dyn OwnerConfirmations>,
        admission: Arc<dyn Admission>,
        removal: Option<(u64, u64)>,
    ) -> Answer<ParamsValue> {
        let mut catalogue = self.catalogue.lock().await;
        admission.check().map_err(ProtocolError::from)?;
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        let key = receipt_key(actor_id, mutation.action_id);
        let claim = ReceiptClaim {
            key: key.clone(),
            digest: digest.as_bytes().to_vec(),
            method: method.as_str().to_owned(),
            method_version: mutation.method_version.0,
            deadline_ms: admission.accepted_deadline_ms(),
        };
        // Claimed before anything is performed, and durably: a claim this host cannot record is a
        // refusal, because an action performed without one could be performed twice.
        match catalogue
            .claim(&claim, kr_ipc::now_ms().get())
            .map_err(ProtocolError::from)?
        {
            Claimed::Retained(record) => return answered(&record, &digest, mutation.action_id),
            Claimed::Fresh => {}
        }
        // Every change the action makes commits through this recording, so what it left behind
        // when it stops is known rather than guessed.
        let recording = Recording::new(&*admission);
        let outcome = self
            .perform_write(
                &mut catalogue,
                mutation,
                method,
                confirmations,
                &recording,
                key.clone(),
                removal,
            )
            .await;
        let answer = match outcome {
            Ok(result) => Ok(result),
            Err(error) => {
                // Refused only when nothing of the action committed; anything else is unknown, and
                // the answer names what the action left behind. The caller is told the same thing
                // every later resubmission is told.
                let failure = recording.failure(&error);
                // A settlement this host cannot record leaves the claim dispatching, and every
                // later reader is told that is unknown: the action is never performed again, and
                // nobody is told it had no effect on the strength of a record that was never
                // written.
                let _ = catalogue.settle_failure(&key, &failure, kr_ipc::now_ms().get());
                Err(failure.into_answer())
            }
        };
        // Each native bridge the change can move follows what its installation now wants, under
        // the same lock and after the change's commit: the package a plugin mutation names, and
        // every installed package after a change to a repository's generation, which can add or
        // withdraw the signed build records a recipe's version is read from. What a bridge does is
        // its own journal's and never changes the answer the change recorded.
        let subjects = match plugin_named(method, &mutation.params) {
            Some(plugin_id) => vec![plugin_id],
            None if matches!(
                method,
                Method::CatalogueSync | Method::CataloguePin | Method::CatalogueRemove
            ) =>
            {
                bridge_subjects(&catalogue, &self.bridges, self.environment_id)
            }
            None => Vec::new(),
        };
        // A bridge the admissions carry may move here, whether or not the change committed, so the
        // admission revision rises first, under the change's own authority, every time: every
        // snapshot computed before this write is below every one after it, and every worker is
        // sent the bridges as they are now. A change that raised it already raises it once more,
        // which costs nothing a round does not. Where the revision cannot rise, no bridge moves;
        // the daemon's next start or the next change follows them.
        let raised = subjects.is_empty()
            || match catalogue.raise_admission_revision(&*admission) {
                Ok(_) => true,
                Err(error) => {
                    eprintln!(
                        "kr-controller: the native bridges this change names were not followed, \
                         because the admission revision could not rise: {error}"
                    );
                    false
                }
            };
        let subjects = if raised { subjects } else { Vec::new() };
        let wanted = self.wanted_bridges(&catalogue, subjects);
        self.follow_bridges(wanted).await;
        answer
    }

    // Each argument is one part of the change: what was asked, by whom, under which admission,
    // and what the workers reported about the package a removal ends.
    #[allow(clippy::too_many_arguments)]
    async fn perform_write(
        &self,
        catalogue: &mut Catalogue,
        mutation: &MutationRequest,
        method: Method,
        confirmations: Option<&dyn OwnerConfirmations>,
        admission: &dyn Authority,
        key: ReceiptKey,
        removal: Option<(u64, u64)>,
    ) -> Answer<ParamsValue> {
        let now = kr_ipc::now_ms().get();
        let mut answer: Option<ParamsValue> = None;
        match method {
            Method::CatalogueAdd => {
                let params: wire::CatalogueAddParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                within_budgets(&params.budgets, &self.budgets_in_force())?;
                let enrolment = enrolment_from(&params)?;
                // Adopting a root is the owner's act. The confirmation names this repository, this
                // root and this ceiling, so one obtained for a narrower enrolment does not adopt a
                // wider one. Re-anchoring an existing repository is two deliberate acts,
                // `catalogue.remove` and `catalogue.add`, so that a root never changes underneath
                // a repository somebody is already using.
                let plan = trust_plan(&params, &enrolment)?;
                let action_digest = plan
                    .action_digest()
                    .map_err(|error| error.to_protocol_error())?;
                let (confirmations, confirmed) = confirm(
                    confirmations,
                    crate::sharing::CatalogueTrustPlan::sensitive_action(),
                    action_digest,
                    params.owner_confirmation.as_ref(),
                    "enrolment",
                )?;
                let confirmed = Confirmed {
                    admission,
                    confirmed,
                    action_digest,
                    confirmations,
                    subject: "enrolment",
                };
                let mut render = settle(&mut answer, |transition| match transition {
                    Transition::Enrolled(view) => Ok(wire::CatalogueAddResult {
                        catalogue: summary(view),
                    }),
                    _ => Err(unexpected(transition)),
                });
                catalogue
                    .enrol_with(
                        enrolment,
                        &mut Change::settling(&confirmed, key, now, &mut render),
                    )
                    .map_err(ProtocolError::from)?;
            }
            Method::CatalogueSync => {
                let params: wire::CatalogueSyncParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let id = repository_id(&params.catalogue_id)?;
                let mut render = settle(&mut answer, |transition| match transition {
                    Transition::Synced { outcome, .. } => Ok(wire::CatalogueSyncResult {
                        generation: outcome.generation,
                        entries: U64::new(outcome.entries as u64),
                        index_bytes: U64::new(outcome.index_bytes),
                        mirrored_payloads: U64::new(outcome.mirrored_payloads as u64),
                        delegations: outcome
                            .delegations
                            .iter()
                            .map(|(role, publisher_id)| wire::CatalogueDelegation {
                                role: role.clone(),
                                publisher_id: publisher_id.clone(),
                            })
                            .collect(),
                    }),
                    _ => Err(unexpected(transition)),
                });
                catalogue
                    .sync_with(&id, &mut Change::settling(admission, key, now, &mut render))
                    .await
                    .map_err(ProtocolError::from)?;
            }
            Method::CataloguePin => {
                let params: wire::CataloguePinParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let id = repository_id(&params.catalogue_id)?;
                let mut render = settle(&mut answer, |transition| match transition {
                    Transition::Pinned(view) => Ok(wire::CataloguePinResult {
                        catalogue: summary(view),
                    }),
                    _ => Err(unexpected(transition)),
                });
                catalogue
                    .pin_with(
                        &id,
                        params.generation.0,
                        &mut Change::settling(admission, key, now, &mut render),
                    )
                    .map_err(ProtocolError::from)?;
            }
            Method::CatalogueRemove => {
                let params: wire::CatalogueRemoveParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let id = repository_id(&params.catalogue_id)?;
                // A package installed from this repository stays installed, on the hash it was
                // installed at. Removing a repository is not a way to uninstall things somebody
                // is using, and the answer names what is still there.
                let mut render = settle(&mut answer, |transition| match transition {
                    Transition::Removed {
                        enrolment,
                        installed,
                    } => Ok(wire::CatalogueRemoveResult {
                        catalogue_id: enrolment.id.to_string(),
                        installed_packages: installed.clone(),
                    }),
                    _ => Err(unexpected(transition)),
                });
                catalogue
                    .remove_repository_with(
                        &id,
                        &mut Change::settling(admission, key, now, &mut render),
                    )
                    .map_err(ProtocolError::from)?;
            }
            Method::PluginInstall => {
                let params: wire::PluginInstallParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let id = repository_id(&params.catalogue_id)?;
                let version = version(&params.version)?;
                let digest = digest(&params.package_digest)?;
                let grant = grant_from(&params.grant)?;
                // An installation that may do more than the one it replaces, or than its
                // repository's ceiling permits by itself, and every release that installs a native
                // bridge, is the owner's decision, and the catalogue decides whether this one is.
                // The confirmation names the repository and its ceiling with the release, the hash,
                // the grant and what the release's manifest says a native bridge does, and is spent
                // the way `plugin.grant` spends one: accepted and consumed here, and asked again
                // inside the commit. It is the proof the request presents or, with none, the answer
                // an owner device recorded to the challenge this host issued for this request; an
                // installation that needs none asks for neither.
                let (confirmed, decided_under) =
                    match (params.owner_confirmation.as_ref(), confirmations) {
                        (None, None) => (None, None),
                        (proof, Some(_)) => match install_plan(catalogue, &params).await {
                            Ok((plan, ceiling)) => {
                                let action_digest = plan
                                    .action_digest()
                                    .map_err(|error| error.to_protocol_error())?;
                                match confirm(
                                    confirmations,
                                    crate::sharing::PluginInstallPlan::sensitive_action(),
                                    action_digest,
                                    proof,
                                    "installation",
                                ) {
                                    Ok((confirmations, confirmed)) => (
                                        Some(Confirmed {
                                            admission,
                                            confirmed,
                                            action_digest,
                                            confirmations,
                                            subject: "installation",
                                        }),
                                        // The ceiling the owner was shown, which the catalogue holds
                                        // the installation to once the repository is held and inside
                                        // the commit.
                                        Some(ceiling),
                                    ),
                                    // No answer recorded for this request: the catalogue decides
                                    // whether the installation needed one.
                                    Err(error)
                                        if proof.is_none()
                                            && error.code
                                                == ErrorCode::OwnerConfirmationRequired =>
                                    {
                                        (None, None)
                                    }
                                    Err(error) => return Err(error),
                                }
                            }
                            // An installation that presents no proof and cannot even be described
                            // (an unknown repository, a release the index does not carry) is refused
                            // by the catalogue in its own words.
                            Err(_) if proof.is_none() => (None, None),
                            Err(error) => return Err(error),
                        },
                        (Some(_), None) => return Err(off_the_network("installation")),
                    };
                let authority: &dyn Authority = match &confirmed {
                    Some(confirmed) => confirmed,
                    None => admission,
                };
                let mut render = settle(&mut answer, |transition| match transition {
                    Transition::Installed(view) => Ok(wire::PluginInstallResult {
                        plugin: plugin_summary(view)?,
                        capabilities: grants(&view.installation.requested, &view.decisions)?,
                    }),
                    _ => Err(unexpected(transition)),
                });
                catalogue
                    .install_with(
                        &id,
                        params.environment_id,
                        &params.plugin_id,
                        &version,
                        digest,
                        grant,
                        decided_under.as_ref(),
                        &mut Change::settling(authority, key, now, &mut render),
                    )
                    .await
                    .map_err(ProtocolError::from)
                    .map_err(|error| {
                        // Where the installation needed an owner's confirmation and this host is
                        // off the network, nothing could give it one.
                        if confirmations.is_none()
                            && error.code == ErrorCode::OwnerConfirmationRequired
                        {
                            off_the_network("installation")
                        } else {
                            error
                        }
                    })?;
            }
            Method::PluginRemove => {
                let params: wire::PluginRemoveParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let mut render = settle(&mut answer, |transition| match transition {
                    Transition::Uninstalled {
                        plugin_id,
                        affected_bindings,
                    } => Ok(wire::PluginRemoveResult {
                        plugin_id: plugin_id.clone(),
                        affected_bindings: Nullable::from(affected_bindings.map(U64::new)),
                    }),
                    _ => Err(unexpected(transition)),
                });
                catalogue
                    .uninstall_with(
                        params.environment_id,
                        &params.plugin_id,
                        removal,
                        &mut Change::settling(admission, key, now, &mut render),
                    )
                    .map_err(ProtocolError::from)?;
            }
            Method::PluginPin => {
                let params: wire::PluginPinParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let pin = params.package_digest.0.as_deref().map(digest).transpose()?;
                let mut render = settle(&mut answer, |transition| match transition {
                    Transition::Changed(view) => Ok(wire::PluginPinResult {
                        plugin: plugin_summary(view)?,
                    }),
                    _ => Err(unexpected(transition)),
                });
                catalogue
                    .pin_package_with(
                        params.environment_id,
                        &params.plugin_id,
                        pin,
                        &mut Change::settling(admission, key, now, &mut render),
                    )
                    .map_err(ProtocolError::from)?;
            }
            Method::PluginEnable | Method::PluginDisable => {
                let params: wire::PluginEnableParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let mut render = settle(&mut answer, |transition| match transition {
                    Transition::Changed(view) => Ok(wire::PluginEnableResult {
                        plugin: plugin_summary(view)?,
                    }),
                    _ => Err(unexpected(transition)),
                });
                catalogue
                    .set_enabled_with(
                        params.environment_id,
                        &params.plugin_id,
                        method == Method::PluginEnable,
                        &mut Change::settling(admission, key, now, &mut render),
                    )
                    .await
                    .map_err(ProtocolError::from)?;
            }
            Method::PluginGrant => {
                let params: wire::PluginGrantParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let grant = grant_from(&params.grant)?;
                // The grant is about the release the owner was shown. An installation that moved
                // on is a different decision, so the digest is checked before the confirmation is
                // even read rather than the change being applied to whatever is installed now.
                let installed = catalogue
                    .installation(params.environment_id, &params.plugin_id)
                    .map_err(ProtocolError::from)?
                    .ok_or_else(|| {
                        ProtocolError::new(
                            ErrorCode::ResourceUnavailable,
                            format!("{} is not installed in this environment", params.plugin_id),
                        )
                    })?;
                let named = digest(&params.package_digest)?;
                if installed.package_digest != named {
                    return Err(ProtocolError::new(
                        ErrorCode::IdConflict,
                        format!(
                            "{} is installed at {} and this grant is for {}",
                            params.plugin_id, installed.package_digest, named
                        ),
                    ));
                }
                let plan = crate::sharing::PluginGrantPlan {
                    environment_id: params.environment_id,
                    plugin_id: params.plugin_id.clone(),
                    version: installed.version.to_string(),
                    package_digest: named.to_string(),
                    grant: params.grant.iter().cloned().collect(),
                };
                let action_digest = plan
                    .action_digest()
                    .map_err(|error| error.to_protocol_error())?;
                let (confirmations, confirmed) = confirm(
                    confirmations,
                    crate::sharing::PluginGrantPlan::sensitive_action(),
                    action_digest,
                    Some(&params.owner_confirmation),
                    "grant",
                )?;
                let confirmed = Confirmed {
                    admission,
                    confirmed,
                    action_digest,
                    confirmations,
                    subject: "grant",
                };
                let mut render = settle(&mut answer, |transition| match transition {
                    Transition::Changed(view) => Ok(wire::PluginGrantResult {
                        plugin: plugin_summary(view)?,
                        capabilities: grants(&view.installation.requested, &view.decisions)?,
                    }),
                    _ => Err(unexpected(transition)),
                });
                // The grant is bound to the release the owner was shown, and the catalogue refuses
                // it inside the commit if the installation moved to another one meanwhile.
                catalogue
                    .set_grant_with(
                        params.environment_id,
                        &params.plugin_id,
                        named,
                        grant,
                        &mut Change::settling(&confirmed, key, now, &mut render),
                    )
                    .map_err(ProtocolError::from)?;
            }
            _ => {
                return Err(ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    format!("{} is not a mutation this daemon serves", method.as_str()),
                ));
            }
        }
        answer.ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::OutcomeUnknown,
                format!(
                    "{} was performed and its answer was not recorded",
                    method.as_str()
                ),
            )
        })
    }

    /// Refuses a request for an environment this daemon does not own.
    fn check_environment(&self, environment_id: EnvironmentId) -> Answer<()> {
        if environment_id == self.environment_id {
            return Ok(());
        }
        Err(ProtocolError::new(
            ErrorCode::InvalidArgument,
            format!("this daemon owns environment {}", self.environment_id),
        ))
    }
}

/// The refusal of a read that ran past its bound, waiting for a busy catalogue or reading a slow
/// package.
fn busy() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::ResourceUnavailable,
        "the admissions could not be read in time: the catalogue is busy with another change or a \
         package is slow to read; the workers are asked again on the cadence",
    )
}

/// The key an installation's release is found by among the releases the workers report.
fn installed_key(installation: &Installation) -> bridge::ReleaseKey {
    (
        installation.plugin_id.clone(),
        Digest256::from_bytes(*installation.package_digest.as_bytes()),
        kr_protocol::admission::ReleaseOrigin {
            repository_id: installation.repository.to_string(),
            enrolment_key: installation.enrolment.as_str().to_owned(),
        },
    )
}

/// The package a plugin mutation names, where it names one.
pub(crate) fn plugin_named(method: Method, params: &ParamsValue) -> Option<PluginId> {
    match method {
        Method::PluginInstall => typed::<wire::PluginInstallParams>(params)
            .ok()
            .map(|params| params.plugin_id),
        Method::PluginRemove => typed::<wire::PluginRemoveParams>(params)
            .ok()
            .map(|params| params.plugin_id),
        Method::PluginPin => typed::<wire::PluginPinParams>(params)
            .ok()
            .map(|params| params.plugin_id),
        Method::PluginEnable | Method::PluginDisable => typed::<wire::PluginEnableParams>(params)
            .ok()
            .map(|params| params.plugin_id),
        Method::PluginGrant => typed::<wire::PluginGrantParams>(params)
            .ok()
            .map(|params| params.plugin_id),
        _ => None,
    }
}

/// Every package whose bridge may need bringing to what its installation wants: each installed
/// one whose manifest carries a recipe, and each with a journal.
fn bridge_subjects(
    catalogue: &Catalogue,
    bridges: &native_bridge::NativeBridges,
    environment_id: EnvironmentId,
) -> Vec<PluginId> {
    let mut subjects = std::collections::BTreeSet::new();
    match catalogue.installations() {
        Ok(installations) => subjects.extend(
            installations
                .into_iter()
                .filter(|installation| installation.environment_id == environment_id)
                .map(|installation| installation.plugin_id),
        ),
        Err(error) => eprintln!("kr-controller: the installations could not be read: {error}"),
    }
    match bridges.journaled() {
        Ok(journaled) => subjects.extend(journaled),
        Err(error) => {
            eprintln!("kr-controller: the native bridge journals could not be read: {error}")
        }
    }
    subjects.into_iter().collect()
}

/// Brings one package's bridge to what its installation wants, where that can be read.
fn follow_bridge(
    catalogue: &Catalogue,
    bridges: &native_bridge::NativeBridges,
    environment_id: EnvironmentId,
    plugin_id: &PluginId,
) {
    reconcile_bridge(
        bridges,
        plugin_id,
        wanted_bridge(catalogue, environment_id, plugin_id),
    );
}

/// What one package's installation wants of its native bridge.
enum WantedBridge {
    /// Nothing: the package is not installed, the grant does not hold, or the release carries no
    /// recipe.
    Nothing,
    /// One release's recipe.
    Release(Box<native_bridge::BridgeTarget>),
    /// The installed package is not whole here, or is past a package limit in force and so not
    /// used, so what it wants is not read, and its bridge is left as it is.
    Unknown,
}

/// Records `policy` as the disable policy, in the commit that raises the admission revision with
/// it, and returns true when that changed what was recorded. A record that cannot be read is
/// replaced, since the policy in force is the one this records.
fn record_disable_policy(
    catalogue: &mut Catalogue,
    policy: kr_plugin_catalogue::DisablePolicy,
) -> CatalogueResult<bool> {
    if matches!(catalogue.disable_policy(), Ok(held) if held == policy) {
        return Ok(false);
    }
    catalogue.set_disable_policy(policy)?;
    Ok(true)
}

/// The limits a set of enrolment budgets puts in force: each package limit no larger than the
/// package format's own maximum, and what one synchronisation may transfer.
fn limits_of(
    budgets: &kr_protocol::hostinfo::configuration::EnrolmentBudgets,
) -> kr_plugin_catalogue::Limits {
    kr_plugin_catalogue::Limits {
        package: kr_plugin_catalogue::PackageLimits::configured(
            budgets.package_bytes,
            budgets.object_count,
            budgets.expanded_pack_bytes,
        ),
        transfer_bytes: budgets.transfer_bytes,
    }
}

/// What one package's installation wants of its bridge.
///
/// A registration in an application's directory is the package running in that application's
/// name, so it follows the standing the admissions decide: a package the owner disabled, a release
/// its repository revoked and one the organisation's allowlist does not name want none, and the
/// installation stays. What needs no index is decided first, so a package left out by the owner or
/// by the list loses its registration whatever state the index is in; what does need it, the
/// revocation and the signed builds, is read once, and where the index cannot be read nothing is
/// known to stand, so the registration is not kept on its account.
fn wanted_bridge(
    catalogue: &Catalogue,
    environment_id: EnvironmentId,
    plugin_id: &PluginId,
) -> CatalogueResult<WantedBridge> {
    let Some(installation) = catalogue.installation(environment_id, plugin_id)? else {
        return Ok(WantedBridge::Nothing);
    };
    if catalogue.standing(&installation, None).is_some() {
        return Ok(WantedBridge::Nothing);
    }
    // The grant is what permits the bridge: a release installed without it, or an installation
    // that withdrew it, wants none.
    if !catalogue
        .effective_capabilities(environment_id, plugin_id)?
        .contains(&PluginCapability::NativeBridgeInstall)
    {
        return Ok(WantedBridge::Nothing);
    }
    let store = catalogue.store_of(&installation);
    let package = match store.check_package(
        installation.package_digest,
        catalogue.limits_in_force().get().package,
    )? {
        kr_plugin_catalogue::PackageCheck::Complete(package) => package,
        kr_plugin_catalogue::PackageCheck::PastALimit(_)
        | kr_plugin_catalogue::PackageCheck::Missing { .. }
        | kr_plugin_catalogue::PackageCheck::Corrupt { .. } => return Ok(WantedBridge::Unknown),
    };
    let manifest = package.manifest();
    let Some(recipe) = manifest.native_bridge.as_ref().cloned() else {
        return Ok(WantedBridge::Nothing);
    };
    // The current generation of the installation's origin: whether it revoked this release, and
    // which version an executable is from the signed builds it names for this host's platform. With
    // none, the recipe's version requirement refuses the recipe rather than guessing.
    let entry = match catalogue.release_entry(&installation) {
        Ok(entry) => entry,
        Err(error) => {
            eprintln!(
                "kr-controller: the index that says whether {plugin_id} is revoked could not be \
                 read, so its native bridge is not kept: {error}"
            );
            return Ok(WantedBridge::Nothing);
        }
    };
    if catalogue.standing(&installation, entry.as_ref()).is_some() {
        return Ok(WantedBridge::Nothing);
    }
    let host = kr_plugin_catalogue::this_host();
    let qualified = match (host.os, host.architecture, entry.as_ref()) {
        (Some(os), Some(architecture), Some(entry)) => entry
            .builds_for(os, architecture)
            .map(|build| native_bridge::QualifiedExecutable {
                digest: Digest256::from_bytes(*build.executable_digest.as_bytes()),
                version: build.version.to_string(),
            })
            .collect(),
        _ => Vec::new(),
    };
    let target = native_bridge::BridgeTarget {
        plugin_id: plugin_id.clone(),
        package_digest: installation.package_digest,
        package_dir: store.package_dir(installation.package_digest),
        recipe,
        match_rules: manifest.match_rules.clone(),
        qualified,
    };
    Ok(WantedBridge::Release(Box::new(target)))
}

/// Runs one reconciliation and says what went wrong, where something did.
fn reconcile_bridge(
    bridges: &native_bridge::NativeBridges,
    plugin_id: &PluginId,
    wanted: CatalogueResult<WantedBridge>,
) {
    let wanted = match wanted {
        Ok(WantedBridge::Nothing) => None,
        Ok(WantedBridge::Release(target)) => Some(target),
        Ok(WantedBridge::Unknown) => return,
        Err(error) => {
            eprintln!(
                "kr-controller: what the installation of {plugin_id} wants of its native bridge \
                 could not be read: {error}"
            );
            return;
        }
    };
    if let Err(error) = bridges.reconcile(plugin_id, wanted.as_deref()) {
        eprintln!(
            "kr-controller: the native bridge of {plugin_id} was not reconciled, and is reconciled \
             again when this daemon next starts: {error}"
        );
    }
}

/// The receipt key one actor's action is recorded under.
fn receipt_key(actor_id: &ActorId, action_id: ActionId) -> ReceiptKey {
    ReceiptKey::new(actor_id.as_str(), action_id.to_string())
}

/// Returns the answer a retained receipt gives a resubmission of the same action.
fn answered(
    record: &ReceiptRecord,
    digest: &Digest256,
    action_id: ActionId,
) -> Answer<ParamsValue> {
    if record.claim.digest != digest.as_bytes() {
        return Err(ProtocolError::new(
            ErrorCode::IdConflict,
            format!("action {action_id} was already used with different parameters"),
        ));
    }
    match record.state {
        ReceiptState::Applied => match &record.result {
            Some(bytes) => decode_result(bytes),
            None => Err(ProtocolError::new(
                ErrorCode::StorageUnavailable,
                format!("action {action_id} applied and its answer is not retained"),
            )),
        },
        ReceiptState::Refused | ReceiptState::Unknown | ReceiptState::Rejected => {
            Err(record.error.clone().unwrap_or_else(|| {
                ProtocolError::new(
                    ErrorCode::OutcomeUnknown,
                    format!("action {action_id} has no retained answer"),
                )
            }))
        }
        ReceiptState::Received | ReceiptState::Accepted | ReceiptState::Dispatching => {
            Err(ProtocolError::new(
                ErrorCode::OutcomeUnknown,
                format!(
                    "action {action_id} is being performed or was interrupted; it is not \
                     performed again, and action.read reports where it stands"
                ),
            ))
        }
    }
}

/// Builds the `action.read` answer for one retained catalogue receipt.
fn action_read_result(
    actor_id: &ActorId,
    action_id: ActionId,
    record: &ReceiptRecord,
) -> Answer<kr_protocol::receipt::ActionReadResult> {
    let digest: [u8; 32] = record.claim.digest.as_slice().try_into().map_err(|_| {
        ProtocolError::new(
            ErrorCode::StorageUnavailable,
            format!("action {action_id}'s receipt holds a digest this build cannot read"),
        )
    })?;
    let result = match (record.state, &record.result) {
        (ReceiptState::Applied, Some(bytes)) => Nullable(Some(decode_result(bytes)?)),
        _ => Nullable(None),
    };
    Ok(kr_protocol::receipt::ActionReadResult {
        receipt: kr_protocol::receipt::Receipt {
            action_id,
            actor_id: actor_id.clone(),
            method: kr_protocol::method::MethodName::new(&record.claim.method).map_err(
                |error| ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string()),
            )?,
            method_version: kr_protocol::method::MethodVersion(record.claim.method_version),
            revision: U64::new(record.revision),
            state: record.state,
            reason: Nullable(None),
            payload_digest: Digest256::from_bytes(digest),
            accepted_deadline_ms: Nullable(
                record
                    .claim
                    .deadline_ms
                    .map(kr_protocol::scalars::TimestampMs::new),
            ),
            error: Nullable(record.error.clone()),
            error_withheld: false,
            updated_at_ms: kr_protocol::scalars::TimestampMs::new(record.updated_at_ms),
        },
        result,
    })
}

fn decode_result(bytes: &[u8]) -> Answer<ParamsValue> {
    kr_cbor::decode(bytes, &kr_cbor::Limits::DEFAULT)
        .map(ParamsValue::new)
        .map_err(|error| ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string()))
}

/// Makes the settlement that renders a method's answer from what its change did.
///
/// The answer is rendered inside the change's own transaction and recorded there, and the same
/// value is what the caller is answered with, so the first answer and every retained one are the
/// same bytes.
fn settle<'a, T, F>(
    answer: &'a mut Option<ParamsValue>,
    render: F,
) -> impl FnMut(&Transition) -> CatalogueResult<Vec<u8>> + Send + 'a
where
    T: serde::Serialize,
    F: Fn(&Transition) -> Answer<T> + Send + 'a,
{
    move |transition| {
        let value = render(transition)
            .and_then(|result| encode(&result))
            .map_err(CatalogueError::Refused)?;
        let bytes = kr_cbor::encode(value.as_value());
        *answer = Some(value);
        Ok(bytes)
    }
}

fn unexpected(transition: &Transition) -> ProtocolError {
    ProtocolError::new(
        ErrorCode::StorageUnavailable,
        format!("the catalogue reported a change this method does not make: {transition:?}"),
    )
}

/// What a caller is told about one repository.
fn summary(view: &RepositoryView) -> wire::CatalogueSummary {
    let enrolment = &view.enrolment;
    wire::CatalogueSummary {
        catalogue_id: enrolment.id.to_string(),
        kind: kind_of(enrolment.kind),
        metadata_url: enrolment.metadata_url.to_string(),
        targets_url: enrolment.targets_url.to_string(),
        root_digest: enrolment.root_digest().to_string(),
        generation: Nullable(
            view.active
                .map(|active| RepositoryGeneration::new(active.generation)),
        ),
        pinned_generation: Nullable(enrolment.pinned_generation),
        budgets: wire::CatalogueBudgets {
            metadata_bytes: enrolment.budgets.metadata_bytes,
            metadata_entries: enrolment.budgets.metadata_entries,
            retained_generations: enrolment.budgets.retained_generations,
            retained_metadata_bytes: enrolment.budgets.retained_metadata_bytes,
            payload_cache_bytes: enrolment.budgets.payload_cache_bytes,
            full_offline_mirror: enrolment.budgets.full_offline_mirror,
        },
        ceiling: enrolment
            .ceiling
            .capabilities()
            .into_iter()
            .map(|capability| capability.as_str().to_owned())
            .collect(),
        entries: U64::new(view.active.map_or(0, |active| active.entries)),
        synced_at_ms: Nullable(None),
    }
}

/// What a caller is told about one installed package.
fn plugin_summary(view: &InstallationView) -> Answer<wire::PluginSummary> {
    let installation = &view.installation;
    Ok(wire::PluginSummary {
        plugin_id: plugin_id_of(installation)?,
        catalogue_id: installation.repository.to_string(),
        version: installation.version.to_string(),
        package_digest: installation.package_digest.to_string(),
        environment_id: installation.environment_id,
        enabled: installation.enabled,
        pinned: installation.pinned,
        revoked: view.revoked,
        // The workers' own records are what counts bindings, and this answer asks none of them.
        live_bindings: Nullable::null(),
        // The admissions are computed for `plugin.list` alone, beside its refresh.
        admission: Nullable::null(),
    })
}

/// The evidence an installed package is described with when its repository publishes nothing
/// about it now: what the installation itself declared, untested.
fn fallback_evidence(
    installation: &Installation,
    generation: u64,
) -> Answer<Vec<wire::PluginCapabilityEvidence>> {
    let now = kr_ipc::now_ms();
    let revision = kr_protocol::ids::CapabilityRevision::new(generation.max(1));
    installation
        .requested
        .iter()
        .map(|request| {
            Ok(wire::PluginCapabilityEvidence {
                capability: capability_id(request.capability)?,
                capability_version: installation.version.to_string(),
                revision,
                subject: wire::PluginEvidenceSubject {
                    environment_id: installation.environment_id,
                    application: Nullable::null(),
                    terminal: Nullable::null(),
                    desktop_generation: Nullable::null(),
                },
                state: wire::PluginCapabilityState::NotTested,
                source: wire::PluginEvidenceSource::PackageDeclaration,
                package_digest: installation.package_digest.to_string(),
                profile_digest: Nullable::null(),
                invalidated_by: Vec::new(),
                disabled_reason: Nullable(Some(
                    "the package is installed offline and the catalogue has no qualification \
                     data for it"
                        .to_owned(),
                )),
                observed_at_ms: now,
            })
        })
        .collect()
}

fn grants(
    requested: &[kr_plugin_sdk::capability::CapabilityRequest],
    decisions: &[kr_plugin_catalogue::CapabilityDecision],
) -> Answer<Vec<wire::PluginCapabilityGrant>> {
    decisions
        .iter()
        .map(|decision| {
            let reason = requested
                .iter()
                .find(|request| request.capability == decision.capability)
                .map(|request| request.reason.as_str().to_owned())
                .unwrap_or_default();
            Ok(wire::PluginCapabilityGrant {
                capability: capability_id(decision.capability)?,
                requirement: requirement_of(decision.requirement),
                permitted: decision.permitted,
                reason,
            })
        })
        .collect()
}

fn evidence(
    entry: &kr_plugin_sdk::catalogue::IndexEntry,
    installation: &Installation,
    generation: u64,
) -> Answer<Vec<wire::PluginCapabilityEvidence>> {
    let now = kr_protocol::scalars::TimestampMs::new(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0),
    );
    let revision = kr_protocol::ids::CapabilityRevision::new(generation.max(1));
    let mut records = Vec::new();
    for qualification in &entry.qualification {
        match kr_plugin_catalogue::evidence::from_qualification(
            entry,
            installation,
            qualification,
            revision,
            now,
        ) {
            Ok(record) => records.push(wire_evidence(&record)?),
            // A qualification this host will not read is reported as refused rather than left
            // out. Dropping it would make a publisher's rejected claim look the same as no claim
            // at all, and the person deciding whether to trust this package would not be told.
            Err(refusal) => records.push(wire::PluginCapabilityEvidence {
                capability: qualification.capability_id.clone(),
                capability_version: qualification.capability_version.to_string(),
                revision,
                subject: wire::PluginEvidenceSubject {
                    environment_id: installation.environment_id,
                    application: Nullable(Some(qualification.subject.to_string())),
                    terminal: Nullable(None),
                    desktop_generation: Nullable(None),
                },
                state: wire::PluginCapabilityState::NotTested,
                source: wire::PluginEvidenceSource::SignedRecord,
                package_digest: installation.package_digest.to_string(),
                profile_digest: Nullable(Some(qualification.profile_digest.to_string())),
                invalidated_by: vec![wire::PluginInvalidationTrigger::ProfileChanged],
                disabled_reason: Nullable(Some(format!(
                    "this host refused the publisher's qualification: {refusal}"
                ))),
                observed_at_ms: now,
            }),
        }
    }
    // What the installed package asks for is what its own manifest declared. The current entry is
    // a later statement about the same hash, and it does not add capabilities to answer for.
    for request in &installation.requested {
        let id = capability_id(request.capability)?;
        if records.iter().any(|record| record.capability == id) {
            continue;
        }
        let record = kr_plugin_catalogue::evidence::untested(
            installation,
            request.capability,
            revision,
            now,
        )
        .map_err(ProtocolError::from)?;
        records.push(wire_evidence(&record)?);
    }
    Ok(records)
}

fn wire_evidence(
    record: &kr_plugin_sdk::capability::CapabilityEvidence,
) -> Answer<wire::PluginCapabilityEvidence> {
    use kr_plugin_sdk::capability::{CapabilityState, EvidenceSource, InvalidationTrigger};
    Ok(wire::PluginCapabilityEvidence {
        capability: record.capability_id.clone(),
        capability_version: record.capability_version.to_string(),
        revision: record.revision,
        subject: wire::PluginEvidenceSubject {
            environment_id: record.subject.environment_id,
            application: Nullable(
                record
                    .subject
                    .application
                    .0
                    .as_ref()
                    .map(|label| label.as_str().to_owned()),
            ),
            terminal: Nullable(
                record
                    .subject
                    .terminal
                    .0
                    .as_ref()
                    .map(|label| label.as_str().to_owned()),
            ),
            desktop_generation: Nullable(
                record
                    .subject
                    .desktop_generation
                    .0
                    .as_ref()
                    .map(|label| label.as_str().to_owned()),
            ),
        },
        state: match record.state {
            CapabilityState::QualifiedAvailable => wire::PluginCapabilityState::QualifiedAvailable,
            CapabilityState::VersionQualified => wire::PluginCapabilityState::VersionQualified,
            CapabilityState::MissingInstallation => {
                wire::PluginCapabilityState::MissingInstallation
            }
            CapabilityState::PermissionRequired => wire::PluginCapabilityState::PermissionRequired,
            CapabilityState::Incompatible => wire::PluginCapabilityState::Incompatible,
            CapabilityState::TemporarilyUnavailable => {
                wire::PluginCapabilityState::TemporarilyUnavailable
            }
            CapabilityState::NotTested => wire::PluginCapabilityState::NotTested,
        },
        source: match record.source {
            EvidenceSource::HostProbe => wire::PluginEvidenceSource::HostProbe,
            EvidenceSource::LiveBinding => wire::PluginEvidenceSource::LiveBinding,
            EvidenceSource::SignedRecord => wire::PluginEvidenceSource::SignedRecord,
            EvidenceSource::PackageDeclaration => wire::PluginEvidenceSource::PackageDeclaration,
        },
        package_digest: record
            .identity
            .package_digest
            .0
            .map(|digest| digest.to_string())
            .unwrap_or_default(),
        profile_digest: Nullable(
            record
                .identity
                .profile_digest
                .0
                .map(|digest| digest.to_string()),
        ),
        invalidated_by: record
            .invalidated_by
            .iter()
            .map(|trigger| match trigger {
                InvalidationTrigger::BinaryChanged => {
                    wire::PluginInvalidationTrigger::BinaryChanged
                }
                InvalidationTrigger::BindingChanged => {
                    wire::PluginInvalidationTrigger::BindingChanged
                }
                InvalidationTrigger::SchemaChanged => {
                    wire::PluginInvalidationTrigger::SchemaChanged
                }
                InvalidationTrigger::OsPermissionChanged => {
                    wire::PluginInvalidationTrigger::OsPermissionChanged
                }
                InvalidationTrigger::DesktopGenerationChanged => {
                    wire::PluginInvalidationTrigger::DesktopGenerationChanged
                }
                InvalidationTrigger::ProfileChanged => {
                    wire::PluginInvalidationTrigger::ProfileChanged
                }
            })
            .collect(),
        disabled_reason: Nullable(
            record
                .disabled_reason
                .0
                .as_ref()
                .map(|reason| reason.as_str().to_owned()),
        ),
        observed_at_ms: record.observed_at,
    })
}

fn capability_id(capability: PluginCapability) -> Answer<kr_protocol::ids::CapabilityId> {
    kr_plugin_catalogue::evidence::capability_id(capability).map_err(ProtocolError::from)
}

const fn requirement_of(
    requirement: kr_plugin_catalogue::GrantRequirement,
) -> wire::PluginGrantRequirement {
    use kr_plugin_catalogue::GrantRequirement as Source;
    match requirement {
        Source::WithinCeiling => wire::PluginGrantRequirement::WithinCeiling,
        Source::RepositoryGrant => wire::PluginGrantRequirement::RepositoryGrant,
        Source::InstallationGrant => wire::PluginGrantRequirement::InstallationGrant,
        Source::ConfirmedInstallationGrant => {
            wire::PluginGrantRequirement::ConfirmedInstallationGrant
        }
    }
}

const fn kind_of(kind: RepositoryKind) -> wire::CatalogueKind {
    match kind {
        RepositoryKind::Official => wire::CatalogueKind::Official,
        RepositoryKind::Vendor => wire::CatalogueKind::Vendor,
        RepositoryKind::Community => wire::CatalogueKind::Community,
        RepositoryKind::Local => wire::CatalogueKind::Local,
        RepositoryKind::Mirror => wire::CatalogueKind::Mirror,
    }
}

/// The plan an enrolment's confirmation covers, from the exact request and the root it carries.
fn trust_plan(
    params: &wire::CatalogueAddParams,
    enrolment: &Enrolment,
) -> Answer<crate::sharing::CatalogueTrustPlan> {
    Ok(crate::sharing::CatalogueTrustPlan {
        environment_id: params.environment_id,
        catalogue_id: enrolment.id.to_string(),
        root_digest: enrolment.root_digest().to_string(),
        root_key_ids: enrolment
            .root_key_ids()
            .map_err(ProtocolError::from)?
            .into_iter()
            .collect(),
        ceiling: params.ceiling.iter().cloned().collect(),
    })
}

/// The plan an installation's confirmation covers, from the exact request and what this host
/// holds: the repository's ceiling as `catalogue.list` reports it and, where the grant asks for a
/// native bridge, the statement the signed index's own manifest for this release makes of it.
///
/// Returns the repository's ceiling beside the plan, which the catalogue holds the installation to.
async fn install_plan(
    catalogue: &mut Catalogue,
    params: &wire::PluginInstallParams,
) -> Answer<(crate::sharing::PluginInstallPlan, CapabilityCeiling)> {
    let repository = repository_id(&params.catalogue_id)?;
    let release = version(&params.version)?;
    let package_hash = digest(&params.package_digest)?;
    let enrolment = catalogue
        .repository(&repository)
        .map_err(ProtocolError::from)?
        .ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::ResourceUnavailable,
                format!("{repository} is not enrolled"),
            )
        })?;
    let grant_statement = if params
        .grant
        .iter()
        .any(|name| name == PluginCapability::NativeBridgeInstall.as_str())
    {
        catalogue
            .grant_statement(&repository, &params.plugin_id, &release, package_hash)
            .await
            .map_err(ProtocolError::from)?
    } else {
        None
    };
    let plan = crate::sharing::PluginInstallPlan {
        environment_id: params.environment_id,
        catalogue_id: repository.to_string(),
        ceiling: enrolment
            .ceiling
            .capabilities()
            .into_iter()
            .map(|capability| capability.as_str().to_owned())
            .collect(),
        plugin_id: params.plugin_id.clone(),
        version: release.to_string(),
        package_digest: package_hash.to_string(),
        grant: params.grant.iter().cloned().collect(),
        grant_statement,
    };
    Ok((plan, enrolment.ceiling))
}

/// Accepts the owner's confirmation of one exact action, or refuses the method.
///
/// The challenge is consumed here, once. What the change asks again at its commit is whether the
/// accepted confirmation still covers it, which reads without consuming anything.
///
/// A host with no enrolled owner signer has no way to obtain a confirmation, and section 10 does
/// not let it fall back to the identity of whoever called. It refuses, and says why.
fn confirm<'a>(
    confirmations: Option<&'a dyn OwnerConfirmations>,
    action: kr_protocol::pairing::SensitiveAction,
    action_digest: Digest256,
    proof: Option<&kr_protocol::pairing::OwnerConfirmationProof>,
    subject: &str,
) -> Answer<(&'a dyn OwnerConfirmations, ConfirmedAction)> {
    let confirmations = confirmations.ok_or_else(|| off_the_network(subject))?;
    let confirmed = match proof {
        // The owner's own proof, presented with the request.
        Some(proof) => confirmations.accept(action, action_digest, proof),
        // None presented: the answer an owner device recorded to the challenge this host issued
        // for exactly this request, spent once.
        None => confirmations.accept_recorded(action, action_digest),
    }
    .map_err(|error| error.to_protocol_error())?;
    Ok((confirmations, confirmed))
}

/// What a confirmed method answers on a host that is not on the network: it has no owner device to
/// ask, whether or not the request carries a proof.
fn off_the_network(subject: &str) -> ProtocolError {
    ProtocolError::new(
        ErrorCode::HostNotConfigured,
        format!(
            "this {subject} needs an owner device's confirmation, and this host is not on the \
             network, so it has none to ask; select a network and restart it"
        ),
    )
}

/// Refuses, by name, an enrolment that asks for more than this host's configuration allows.
///
/// The configured budgets bound what a repository may cost here, whatever the SDK's defaults are:
/// an allowance configured above a default admits a request within it, and one configured below
/// refuses a request above it.
fn within_budgets(
    requested: &wire::CatalogueBudgets,
    in_force: &kr_protocol::hostinfo::configuration::EnrolmentBudgets,
) -> Answer<()> {
    for (name, asked, allowed) in [
        (
            "metadata_bytes",
            requested.metadata_bytes.get(),
            in_force.metadata_bytes,
        ),
        (
            "metadata_entries",
            requested.metadata_entries.get(),
            in_force.metadata_entries,
        ),
        (
            "retained_generations",
            requested.retained_generations.get(),
            in_force.retained_generations,
        ),
        (
            "retained_metadata_bytes",
            requested.retained_metadata_bytes.get(),
            in_force.retained_metadata_bytes,
        ),
        (
            "cached_payload_bytes",
            requested.payload_cache_bytes.get(),
            in_force.cached_payload_bytes,
        ),
    ] {
        if asked > allowed {
            return Err(ProtocolError::new(
                ErrorCode::QuotaExceeded,
                format!(
                    "the enrolment asks for {asked} of {name}, and this host's configuration \
                     allows {allowed}; ask for less, or raise {name} in the configuration's \
                     enrolment budgets"
                ),
            ));
        }
    }
    if requested.full_offline_mirror && !in_force.full_offline_mirror {
        return Err(ProtocolError::new(
            ErrorCode::QuotaExceeded,
            "the enrolment asks for a full offline mirror, and this host's configuration does \
             not allow one; ask for none, or set full_offline_mirror in the configuration's \
             enrolment budgets",
        ));
    }
    Ok(())
}

fn enrolment_from(params: &wire::CatalogueAddParams) -> Answer<Enrolment> {
    let id = repository_id(&params.catalogue_id)?;
    let kind = match params.kind {
        wire::CatalogueKind::Official => RepositoryKind::Official,
        wire::CatalogueKind::Vendor => RepositoryKind::Vendor,
        wire::CatalogueKind::Community => RepositoryKind::Community,
        wire::CatalogueKind::Local => RepositoryKind::Local,
        wire::CatalogueKind::Mirror => RepositoryKind::Mirror,
    };
    let metadata_url = location(&params.metadata_url)?;
    let targets_url = location(&params.targets_url)?;
    let root = decode_root(&params.root)?;
    let mut ceiling = Vec::new();
    for name in &params.ceiling {
        ceiling.push(capability_from_str(name).map_err(ProtocolError::from)?);
    }
    let budgets = kr_plugin_sdk::limits::RepositoryBudgets {
        metadata_bytes: params.budgets.metadata_bytes,
        metadata_entries: params.budgets.metadata_entries,
        retained_generations: params.budgets.retained_generations,
        retained_metadata_bytes: params.budgets.retained_metadata_bytes,
        payload_cache_bytes: params.budgets.payload_cache_bytes,
        full_offline_mirror: params.budgets.full_offline_mirror,
    };
    Enrolment::new(
        id,
        kind,
        metadata_url,
        targets_url,
        root,
        budgets,
        CapabilityCeiling::with(ceiling),
    )
    .map_err(ProtocolError::from)
}

fn grant_from(names: &[String]) -> Answer<InstallationGrant> {
    let mut grant = InstallationGrant::none();
    for name in names {
        grant.add(capability_from_str(name).map_err(ProtocolError::from)?);
    }
    Ok(grant)
}

fn repository_id(text: &str) -> Answer<RepositoryId> {
    RepositoryId::new(text).map_err(ProtocolError::from)
}

fn location(text: &str) -> Answer<url::Url> {
    url::Url::parse(text).map_err(|source| {
        ProtocolError::new(
            ErrorCode::InvalidArgument,
            format!(
                "{} is not a repository location: {source}",
                shown_location(text)
            ),
        )
    })
}

/// Names a location a caller sent by its scheme and host alone.
///
/// A location can carry a user name and a token before its host, and a refusal is read by whoever
/// the answer reaches, so nothing else of the text is repeated. Where the text holds a user name,
/// the host cannot be told from it safely: a location that does not parse can have a `/`, `?` or
/// `#` inside its user name or token, so the refusal names its scheme alone. Where no scheme can be
/// read, it is named as "the location".
fn shown_location(text: &str) -> String {
    let Some((scheme, rest)) = text.split_once("://") else {
        return "the location".to_owned();
    };
    let is_scheme = scheme
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "+-.".contains(character));
    if !is_scheme {
        return "the location".to_owned();
    }
    if rest.contains('@') {
        return format!("the {scheme} location");
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    format!("{scheme}://{host}")
}

fn decode_root(text: &str) -> Answer<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|source| {
            ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "the trust root is not base64: {}",
                    kr_protocol::scalars::decode_fault(
                        &source,
                        kr_protocol::scalars::Base64Alphabet::Standard
                    )
                ),
            )
        })
}

fn version(text: &str) -> Answer<PackageVersion> {
    PackageVersion::parse(text).map_err(|source| {
        ProtocolError::new(
            ErrorCode::InvalidArgument,
            format!("{text} is not a package version: {source}"),
        )
    })
}

fn digest(text: &str) -> Answer<PayloadDigest> {
    PayloadDigest::parse(text).map_err(|source| {
        ProtocolError::new(
            ErrorCode::InvalidArgument,
            format!("{text} is not a package hash: {source}"),
        )
    })
}

fn plugin_id_of(installation: &Installation) -> Answer<PluginId> {
    PluginId::new(installation.plugin_id.to_string()).map_err(|source| {
        ProtocolError::new(
            ErrorCode::StorageUnavailable,
            format!("an installed package has an unreadable identifier: {source}"),
        )
    })
}

pub(crate) fn frame(request_id: RequestId, outcome: Answer<ParamsValue>) -> ControlFrame {
    ControlFrame::Response(Response {
        request_id,
        outcome: match outcome {
            Ok(value) => Outcome::Ok(value),
            Err(error) => Outcome::Error(error),
        },
    })
}

/// Returns the environment a mutation's parameters name.
fn subject<T>(params: &ParamsValue) -> crate::Result<EnvironmentId>
where
    T: kr_protocol::wire::WireMessage + HasEnvironment,
{
    let params: T = params
        .to_typed()
        .map_err(|error| crate::ControllerError::InvalidArgument(error.to_string()))?;
    Ok(params.environment_id())
}

/// What every catalogue and plugin mutation names.
trait HasEnvironment {
    /// Returns the environment the request acts in.
    fn environment_id(&self) -> EnvironmentId;
}

macro_rules! has_environment {
    ($($type:ty),+ $(,)?) => {
        $(
            impl HasEnvironment for $type {
                fn environment_id(&self) -> EnvironmentId {
                    self.environment_id
                }
            }
        )+
    };
}

has_environment!(
    wire::CatalogueAddParams,
    wire::CatalogueSyncParams,
    wire::CataloguePinParams,
    wire::CatalogueRemoveParams,
    wire::PluginInstallParams,
    wire::PluginRemoveParams,
    wire::PluginPinParams,
    wire::PluginEnableParams,
    wire::PluginGrantParams,
);

fn typed<T: kr_protocol::wire::WireMessage>(params: &ParamsValue) -> Answer<T> {
    params
        .to_typed()
        .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))
}

fn encode<T: serde::Serialize>(value: &T) -> Answer<ParamsValue> {
    ParamsValue::from_typed(value)
        .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trust root that is not base64 is refused by the rule it broke and the offset where, never
    /// by the symbol there or that symbol's byte, which base64's own message quotes; one that is
    /// base64 decodes as before.
    #[test]
    fn a_refused_trust_root_names_the_offset_and_never_the_symbol() {
        for planted in ['~', '\u{a7}', '#'] {
            let text = format!("AAAA{planted}AAA");
            let Err(refused) = decode_root(&text) else {
                panic!("a root with {planted:?} in it is refused");
            };
            let said = refused.message;
            assert!(said.contains("offset 4"), "{said}");
            assert!(!said.contains(planted), "{said}");
            let mut first = [0; 4];
            let byte = planted.encode_utf8(&mut first).as_bytes()[0];
            assert!(!said.contains(&byte.to_string()), "{said}");
        }
        assert_eq!(
            decode_root("AAECAw==").ok(),
            Some(vec![0, 1, 2, 3]),
            "a root that is base64 decodes"
        );
    }

    /// KR-REQ-26.14: a repository address is fetched through the proxy this host selected. The
    /// proxy is asked for a tunnel to the repository, and when it refuses, the fetch fails rather
    /// than going around it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_repository_is_fetched_through_the_proxy_this_host_selected() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            0,
        )))
        .await
        .expect("a loopback port");
        let proxy_port = listener.local_addr().expect("an address").port();
        let asked = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let recorded = Arc::clone(&asked);
        let proxy = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read_u8().await {
                        Ok(byte) => head.push(byte),
                        Err(_) => break,
                    }
                }
                let line = String::from_utf8_lossy(&head)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                recorded
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(line);
                let _ = stream
                    .write_all(b"HTTP/1.1 403 Refused\r\ncontent-length: 0\r\n\r\n")
                    .await;
            }
        });
        // Nothing listens at the repository's address: a fetch that went around the proxy would
        // fail too, so what the proxy was asked is the whole of the evidence.
        let unused = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let repository = unused.local_addr().expect("an address");
        drop(unused);

        let transport = repository_transport(Some(
            &format!("http://127.0.0.1:{proxy_port}")
                .parse()
                .expect("a proxy address"),
        ));
        let Ok(stream) = tough::Transport::fetch(
            &transport,
            format!("https://{repository}/1.root.json")
                .parse()
                .expect("an address"),
        )
        .await
        else {
            panic!("the fetch answered without a stream");
        };
        let fetched = futures_util::TryStreamExt::try_collect::<Vec<tough::Bytes>>(stream).await;
        proxy.abort();
        assert!(fetched.is_err(), "the proxy refused every tunnel");
        let asked = asked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let tunnel = format!("CONNECT {repository} HTTP/1.1");
        assert!(
            !asked.is_empty() && asked.iter().all(|line| *line == tunnel),
            "{asked:?}"
        );
    }

    /// A loopback server that answers every request with `status` and `body`, and counts them.
    async fn answering(
        status: u16,
        body: &'static [u8],
    ) -> (
        String,
        Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            0,
        )))
        .await
        .expect("a loopback port");
        let origin = format!(
            "http://127.0.0.1:{}",
            listener.local_addr().expect("an address").port()
        );
        let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&asked);
        let serving = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read_u8().await {
                        Ok(byte) => head.push(byte),
                        Err(_) => break,
                    }
                }
                let answer = format!(
                    "HTTP/1.1 {status} Answer\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(answer.as_bytes()).await;
                let _ = stream.write_all(body).await;
            }
        });
        (origin, asked, serving)
    }

    /// Fetches `address` through the transport a host with no proxy selected builds, and reads
    /// what arrives.
    ///
    /// The fetch itself always answers with a stream, and what the request came to arrives
    /// through it: the update client reads an error from the fetch as the file not being there.
    async fn fetched(address: &str) -> Result<Vec<u8>, tough::TransportError> {
        use futures_util::TryStreamExt as _;

        let Ok(stream) = tough::Transport::fetch(
            &repository_transport(None),
            address.parse().expect("an address"),
        )
        .await
        else {
            panic!("the fetch of {address} answered without a stream");
        };
        let chunks: Vec<tough::Bytes> = stream.try_collect().await?;
        Ok(chunks.concat())
    }

    /// A file a repository's server answers 403, 404 or 410 for is not there, which is how the
    /// update client finds the newest signed root. It is asked for once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_file_its_server_answers_403_404_or_410_for_is_not_there() {
        for status in [403, 404, 410] {
            let (origin, asked, serving) = answering(status, b"").await;
            let error = fetched(&format!("{origin}/2.root.json"))
                .await
                .expect_err("no such file");
            assert_eq!(
                error.kind(),
                tough::TransportErrorKind::FileNotFound,
                "{status}: {error}"
            );
            assert_eq!(
                asked.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "{status}"
            );
            serving.abort();
        }
    }

    /// A server that fails is asked again, four times in all, and then the fetch fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_server_that_fails_is_asked_again_and_then_the_fetch_fails() {
        let (origin, asked, serving) = answering(503, b"").await;
        let error = fetched(&format!("{origin}/timestamp.json"))
            .await
            .expect_err("the server keeps failing");
        assert_eq!(error.kind(), tough::TransportErrorKind::Other, "{error}");
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 4);
        serving.abort();
    }

    /// A file the server has is read whole, as it arrives.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_file_the_server_has_is_read_whole() {
        let (origin, asked, serving) = answering(200, b"{\"signed\": {}}").await;
        let body = fetched(&format!("{origin}/timestamp.json"))
            .await
            .expect("the file");
        assert_eq!(body, b"{\"signed\": {}}");
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1);
        serving.abort();
    }

    /// A host whose certificate verification cannot be set up still reads a repository on its
    /// own disk, and says why whenever it is asked to fetch one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_host_that_cannot_verify_reads_its_disk_and_says_why_it_fetches_nothing() {
        use futures_util::TryStreamExt as _;

        let transport = RepositoryTransport::local_only("no certificate store");
        let directory = tempfile::tempdir().expect("a directory");
        let file = directory.path().join("1.root.json");
        std::fs::write(&file, b"{}").expect("a file");
        let read: Vec<tough::Bytes> = tough::Transport::fetch(
            &transport,
            url::Url::from_file_path(&file).expect("a file address"),
        )
        .await
        .expect("the file")
        .try_collect()
        .await
        .expect("its bytes");
        assert_eq!(read.concat(), b"{}");
        let Ok(stream) = tough::Transport::fetch(
            &transport,
            "https://plugins.example/1.root.json"
                .parse()
                .expect("an address"),
        )
        .await
        else {
            panic!("the fetch answered without a stream");
        };
        let refused = stream
            .try_collect::<Vec<tough::Bytes>>()
            .await
            .expect_err("nothing is fetched");
        assert!(
            std::error::Error::source(&refused)
                .is_some_and(|cause| cause.to_string() == "no certificate store"),
            "{refused:?}"
        );
    }

    #[test]
    fn the_daemon_serves_the_two_plugin_groups() {
        for method in [
            Method::CatalogueList,
            Method::CatalogueAdd,
            Method::CatalogueSync,
            Method::CataloguePin,
            Method::CatalogueRemove,
            Method::PluginList,
            Method::PluginInstall,
            Method::PluginRemove,
            Method::PluginPin,
            Method::PluginEnable,
            Method::PluginDisable,
            Method::PluginGrant,
            Method::PluginCapabilities,
        ] {
            assert!(CatalogueModule::serves(method), "{}", method.as_str());
        }
        // A plugin action is the worker's, not this daemon's.
        assert!(!CatalogueModule::serves(Method::PluginActionInvoke));
        assert!(!CatalogueModule::serves(Method::SessionCreate));
    }

    #[test]
    fn every_method_in_the_two_groups_has_one_exhaustive_authority_entry() {
        use kr_protocol::actor::ActorIngress;
        use kr_protocol::authority::AuthorityDecision;
        use kr_protocol::method::{MethodVersion, decide};

        for entry in kr_protocol::method::REGISTRY {
            if !matches!(
                entry.group,
                MethodGroup::PluginCatalogues | MethodGroup::Plugins
            ) {
                continue;
            }
            let AuthorityDecision::Listed(listed) =
                decide(entry.name, MethodVersion::V1, ActorIngress::LocalIpc)
            else {
                panic!("{} is not listed", entry.name);
            };
            assert_eq!(listed.name, entry.name);
            // Every mutating member of both groups requires host management.
            if listed.effect == kr_protocol::authority::EffectClass::Write {
                assert!(
                    listed.required_rights.iter().any(|required| matches!(
                        required.authority,
                        kr_protocol::authority::RequiredAuthority::Right {
                            right: kr_protocol::rights::ActionRight::HostManage
                        }
                    )),
                    "{} does not require host.manage",
                    entry.name
                );
            }
        }
    }

    #[test]
    fn a_new_root_always_needs_the_owners_confirmation() {
        use kr_protocol::authority::ConfirmationRequirement;
        let entry = kr_protocol::method::REGISTRY
            .iter()
            .find(|entry| entry.name == "catalogue.add")
            .expect("catalogue.add is registered");
        assert_eq!(entry.confirmation, ConfirmationRequirement::Always);
        let sync = kr_protocol::method::REGISTRY
            .iter()
            .find(|entry| entry.name == "catalogue.sync")
            .expect("catalogue.sync is registered");
        assert_eq!(
            sync.confirmation,
            ConfirmationRequirement::WhenEnlargingAuthority
        );
    }

    /// A location a caller sent can carry a user name and a token before its host, so a refusal of
    /// one names its scheme and host and nothing else of what was sent; where a user name is there,
    /// the host cannot be told from it, since one that does not parse can hold a separator, and the
    /// refusal names the scheme alone.
    #[test]
    fn a_refused_location_names_only_its_scheme_and_host() {
        for (sent, shown) in [
            (
                "https://someone:s3cret-token@plugins.exa mple/metadata/",
                "the https location",
            ),
            (
                "https://s3cret-token@plugins.example:99999/",
                "the https location",
            ),
            (
                "https://someone:s3cret/token@plugins.example",
                "the https location",
            ),
            (
                "https://someone:s3c?ret@plugins.example",
                "the https location",
            ),
            (
                "https://someone:s3c#ret@plugins.example",
                "the https location",
            ),
            (
                "https://plugins.exa mple/metadata/?token=s3cret",
                "https://plugins.exa mple",
            ),
            ("s3cret-token plugins.example", "the location"),
        ] {
            let refusal = location(sent).expect_err("not a location");
            assert_eq!(refusal.code, ErrorCode::InvalidArgument);
            assert!(
                !refusal.message.contains("s3cret") && !refusal.message.contains("someone"),
                "{}",
                refusal.message
            );
            assert!(refusal.message.starts_with(shown), "{}", refusal.message);
        }
    }

    #[test]
    fn a_catalogue_refusal_keeps_its_own_code() {
        use kr_plugin_catalogue::CatalogueError;
        assert_eq!(
            ProtocolError::from(CatalogueError::UnavailableOffline {
                detail: "component.wasm is not cached here".to_owned(),
            })
            .code,
            ErrorCode::PackageUnavailableOffline
        );
        assert_eq!(
            ProtocolError::from(CatalogueError::Untrusted {
                detail: "the root is not trusted".to_owned(),
            })
            .code,
            ErrorCode::RepositoryUntrusted
        );
    }
}
