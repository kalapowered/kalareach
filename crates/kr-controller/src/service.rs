//! The control daemon itself: admission, the rendezvous and the local service.
//!
//! Creating a session is the part with an order that matters. The reservation is durable before
//! anything is spawned, the launcher's identity is recorded before the worker connects, and the
//! worker's key is stored inside the same transition that marks the session live. A daemon that
//! dies at any point in that sequence finds a record that tells it what happened, which is what
//! makes a lost reply something to resolve rather than a reason to start a second shell.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use kr_ipc::client::LocalClient;
use kr_ipc::paths::EnvironmentPaths;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::identity::BootIdentity;
use kr_protocol::ids::{
    BootEpoch, BuildId, ConnectionId, ControllerGeneration, RequestId, SessionId,
};
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs};
use kr_protocol::session::{SessionReadResult, SessionSummary};
use kr_protocol::worker::ReservationId;
use kr_transport::clock::{ContinuousClock, SystemContinuousClock};
use kr_transport::window::ActionWindowIssuer;
use tokio::sync::Mutex;

use crate::desktop::power::Inhibitor;
use crate::directory::Directory;
use crate::error::{ControllerError, Result};
use crate::registry::{LaunchPhase, Registry};
use crate::singleton::SingletonLock;
use crate::supervision::WorkerSupervisor;

#[cfg(any(feature = "testing", test))]
use tokio::sync::oneshot;

/// The daemon on the network.
///
/// It is a child of this module because it is part of the same daemon: it shares the registry, the
/// authority store, the worker directory and the dispatch leases below, and a network module that
/// reached them through a public surface would be a second way into the daemon's own state.
#[path = "net/mod.rs"]
pub mod net;

/// The rounds of plugin admissions this daemon sends its workers.
#[path = "catalogue/rounds.rs"]
mod admission_rounds;

mod admission;
mod attention_reach;
mod authority_changes;
mod barrier;
mod capabilities;
mod close;
mod configuration;
mod create;
mod host;
mod inhibition;
mod local;
mod machine_group;
mod reads;
mod recovery;
mod rendezvous;
mod revocation;
mod routes;
mod standing;
mod start;
mod voice_actions;
mod workers;

pub use barrier::DEBT_PASS_INTERVAL;
pub use capabilities::{CAPABILITY_REVISION_FILE, DESKTOP_REREAD_INTERVAL};
pub use close::{CLOSE_EXCHANGE, CLOSURE_WATCH_TIMEOUT};
pub use create::RENDEZVOUS_TIMEOUT;
pub use inhibition::{DEMAND_BUDGET, DEMAND_PATIENCE, POWER_REVIEW_INTERVAL};
pub use local::{LOCAL_KEEPALIVE, WINDOW_RENEWAL};
pub use rendezvous::LAUNCH_IDENTITY_TIMEOUT;
pub use routes::local_actor;
pub use start::{BOOT_FILE, ControllerSetup, JOB_SWEEP_BOUND};

use admission::{AdmittedConnection, LeaseDenied, remaining_deadline};
use barrier::{Debts, Reach};
use capabilities::DesktopReading;
use create::PendingCreate;
use inhibition::DemandScan;
use workers::{UNACCOUNTED_WORKER, WORKER_EXCHANGE};

/// A wall clock, read in UTC milliseconds.
#[derive(Clone)]
pub struct WallClock(Arc<dyn Fn() -> u64 + Send + Sync>);

impl WallClock {
    /// The machine's own wall clock.
    #[must_use]
    pub fn system() -> Self {
        Self::from_fn(|| kr_ipc::now_ms().get())
    }

    /// A wall clock that reads `read`.
    #[must_use]
    pub fn from_fn(read: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        Self(Arc::new(read))
    }

    /// Its reading now, in UTC milliseconds.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        (self.0)()
    }
}

impl std::ops::Deref for WallClock {
    type Target = dyn Fn() -> u64 + Send + Sync;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl std::fmt::Debug for WallClock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WallClock")
    }
}

/// The two clocks a daemon measures time on.
///
/// The continuous clock carries every deadline the daemon decides, and the wall clock every
/// reading of UTC it decides from, raised into its floor first. [`Controller::start`] runs on the
/// machine's own; a test can start a daemon on clocks it moves by hand, by the same path.
#[derive(Clone)]
pub struct Clocks {
    /// The suspend-aware continuous clock.
    pub continuous: Arc<dyn ContinuousClock>,
    /// The wall clock.
    pub wall: WallClock,
}

impl Clocks {
    /// The machine's own clocks.
    #[must_use]
    pub fn system() -> Self {
        Self {
            continuous: Arc::new(SystemContinuousClock::new()),
            wall: WallClock::system(),
        }
    }
}

impl std::fmt::Debug for Clocks {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Clocks")
            .field("continuous", &self.continuous)
            .field("wall", &self.wall)
            .finish()
    }
}

/// A point in a read, or in a worker's rendezvous, that this host's own tests can stop it at: it
/// says it has arrived and waits there until the test lets it go. Armed once, it fires once.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Default)]
struct ReadPause(std::sync::Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>);

#[cfg(any(test, feature = "testing"))]
impl ReadPause {
    /// Arms the pause. Returns the end that says the read has arrived, and the end that lets it
    /// go.
    fn arm(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (arrived, arrival) = oneshot::channel();
        let (go, going) = oneshot::channel();
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((arrived, going));
        (arrival, go)
    }

    /// Waits here when the pause is armed.
    async fn wait(&self) {
        let armed = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some((arrived, go)) = armed {
            let _ = arrived.send(());
            let _ = go.await;
        }
    }
}

/// The control daemon.
pub struct Controller {
    /// This daemon, as something a task started from a method that has no counted reference can
    /// take one from.
    ///
    /// Recording a closure is the one place that needs it: a closure is written from paths that
    /// hold only a borrow, and every one of them ends work this host may be holding an assertion
    /// for. Weak, because a review must never be what keeps a daemon, and its environment lock,
    /// alive.
    me: std::sync::Weak<Self>,
    registry: Mutex<Registry>,
    directory: Mutex<Directory>,
    /// One authenticated connection per worker.
    ///
    /// Presenting a generation token fences whatever connection held that authority before it, so
    /// a daemon that opened a fresh connection for every call would spend its time fencing itself:
    /// a status read would invalidate a close that had already been authorised. One connection per
    /// worker, used in order, is what stops that.
    connections: Mutex<BTreeMap<SessionId, Arc<tokio::sync::Mutex<Option<LocalClient>>>>>,
    pending: Mutex<BTreeMap<ReservationId, PendingCreate>>,
    /// The reservations a look or a publication currently holds.
    ///
    /// A challenge presents a generation token, and one presented while that worker's own report is
    /// being published fences the connection this daemon has just opened. So a look and a
    /// publication take the reservation between them, one at a time. Two different reservations
    /// have nothing to say to each other and never wait for one another: a worker that reported
    /// itself must not sit behind a look at somebody else's silent process.
    recovering: std::sync::Mutex<std::collections::BTreeSet<ReservationId>>,
    /// Woken whenever a reservation is given back.
    recovered: tokio::sync::Notify,
    /// Every connection this daemon has admitted, and the authority revision it was admitted at.
    ///
    /// This is the daemon's authority store for live connections. A registration is written in the
    /// same critical section as the caller's final record validation, and withdrawn when the
    /// authority it was made under is revoked or the connection ends.
    admitted: std::sync::Mutex<BTreeMap<ConnectionId, AdmittedConnection>>,
    identity: ControllerIdentity,
    /// Which store this daemon keeps its keys in.
    secret_store: kr_crypto::store::StoreSelection,
    generation: ControllerGeneration,
    paths: EnvironmentPaths,
    boot_identity: BootIdentity,
    /// The compact form of the boot above, which is what an action window is bound to.
    boot_epoch: BootEpoch,
    /// The suspend-aware continuous clock every deadline this daemon decides is measured on.
    clock: Arc<dyn ContinuousClock>,
    /// The wall clock every reading of UTC this daemon decides from is taken on.
    wall: WallClock,
    /// The machine's own continuous clock, which is the one a deadline crosses a socket on.
    shared_clock: Arc<dyn kr_ipc::clock::SharedClock>,
    /// The action windows of every connection this daemon serves.
    ///
    /// One issuer for the whole daemon, so ending a connection retires its windows and a window
    /// can never first-admit anything through a connection it does not belong to.
    windows: ActionWindowIssuer,
    /// The remote dispatch leases this daemon issues to its workers.
    ///
    /// A lease carries the generation and the authority revision it was issued at, so advancing
    /// the revision invalidates every outstanding lease at once and a replacement daemon cannot
    /// renew a lease it did not issue. The same type holds the revocation barrier, because a lease
    /// running out is not a barrier holding and the two have to be read together.
    leases: crate::authority::AuthorityBarrier,
    /// The network host this daemon serves, once it is on a network.
    ///
    /// The host is what a revocation needs: withdrawing a registration stops the next request, and
    /// the connections holding those registrations have to lose their write boundary with it. It is
    /// recorded before the listener serves anything, so no connection can be admitted before the
    /// revocation path can reach it.
    network: std::sync::OnceLock<Arc<net::NetworkGuard>>,
    supervisor: Box<dyn WorkerSupervisor>,
    /// The environment's backup service: the generations this host has produced, their staged
    /// ciphertext and the outbox that carries them.
    ///
    /// It serves no method of its own. `backup.manifest` is a *service* method, which this host
    /// calls rather than answers, so what belongs to the daemon is the accounting: what was
    /// admitted, what is staged, what has been dispatched and what became of it.
    backup: Arc<crate::backup::BackupService>,
    /// The configuration this daemon has put into force.
    ///
    /// A document is a file a person may also edit by hand, and its effects live outside it: the
    /// session number admission enforces is in the registry, the authority fence is in the lease
    /// issuer, and the capability evidence is in the desktop reading. This is what keeps them one
    /// fact. It holds the document those effects came from, so the next acceptance can tell what
    /// moved and run exactly the effects the move owes, whoever wrote it. Every revision is
    /// accepted through one path, and holding this across the read and the effects is what puts
    /// them in order: two acceptances cannot interleave, so the one that finishes last is the one
    /// that read the document on disk.
    accepted_configuration: Mutex<crate::config::AcceptedState>,
    /// The ordinary preferences in force, for the effects that act on them.
    ///
    /// The sleep inhibitor and the desktop reading run outside the acceptance that decided what
    /// they act on, and a document they read for themselves is a second reading: an external
    /// writer can publish between the two, and then an effect acts on one document while the
    /// report describes another. They read this instead, which acceptance writes.
    in_force: std::sync::Mutex<crate::config::InForce>,
    /// The network and voice selections this daemon read when it started.
    ///
    /// Both are built once, at startup, from the document on disk then, so these are what the
    /// daemon acts on until it next starts, and a later edit is reported as applying then.
    started: crate::config::Started,
    /// The rights ceiling a paired device's every request is decided against, when one is in force.
    ///
    /// Seeded from the document this environment durably accepted, and replaced by every
    /// acceptance whose reading produced a document, before the fence that reading owes is raised:
    /// a narrower ceiling decides every request from that moment, and the fence stops what was
    /// admitted under the wider one. A reading that produced no document leaves it as it is.
    pub(crate) rights_ceiling:
        Arc<std::sync::Mutex<Option<CanonicalSet<kr_protocol::rights::ActionRight>>>>,
    /// The restrictive changes whose debt no barrier has retired yet ([`Debts`]).
    ///
    /// Section 26 fences dispatch before a change affecting authority is acknowledged, so a
    /// restriction whose barrier has not run stops every admission and forward rather than being
    /// reported and passed over ([`Self::check_fence`]).
    debts: Arc<std::sync::Mutex<Debts>>,
    /// Wakes the debt pass for a debt left to it ([`OwnBarrier`]).
    debt_pass: Arc<tokio::sync::Notify>,
    /// Where this host's own tests stop a lease presentation that has read the clock, before it
    /// waits for the policy's lock. Compiled away in every shipped build.
    #[cfg(feature = "testing")]
    before_presentation_lock: crate::attention::Pause,
    /// Where this host's own tests stop a worker's rendezvous once its claim is committed, before
    /// its specification is made. Compiled away in every shipped build.
    #[cfg(feature = "testing")]
    after_the_claim: ReadPause,
    /// How the loop that serves one local connection paces what it writes unasked. A shipped build
    /// has the one pace the constants name; this host's own tests choose another.
    #[cfg(feature = "testing")]
    local_pace: std::sync::Mutex<local::LocalPace>,
    /// How many writes of a local connection's loop have had to wait for their peer. Compiled
    /// away in every shipped build.
    #[cfg(feature = "testing")]
    local_writes_blocked: std::sync::atomic::AtomicUsize,
    /// Where this host's own tests stop a forwarded mutation once its admission has been asked and
    /// before it takes its lease, so that a debt can be published there. Compiled away in every
    /// shipped build.
    #[cfg(feature = "testing")]
    before_the_lease: ReadPause,
    /// Where this host's own tests stop a barrier's first step once it has advanced the revision
    /// and withdrawn the registrations, before the lease issuer adopts the revision. The pause
    /// holds the thread, not the task: nothing the test asks from here awaits. Compiled away in
    /// every shipped build.
    #[cfg(feature = "testing")]
    before_the_leases_adopt: crate::attention::Pause,
    /// Where this host's own tests stop a retry that has found its retained answer, before the
    /// admission it arrived under is asked again, so that a withdrawal can land in between.
    /// Compiled away in every shipped build.
    #[cfg(feature = "testing")]
    after_the_retained_lookup: ReadPause,
    /// Where this host's own tests stop a read whose worker has stopped answering, once it has
    /// asked the kernel and before it looks at what this daemon holds of the session. Compiled
    /// away in every shipped build.
    #[cfg(test)]
    before_the_record: ReadPause,
    /// Where this host's own tests stop a barrier the debt pass raised, once it has captured its
    /// debts and before it tells the workers. Compiled away in every shipped build.
    #[cfg(test)]
    before_the_pass_tells: ReadPause,
    /// The environment's transfer service, whose methods this daemon admits and dispatches.
    transfer: Arc<crate::transfer::TransferModule>,
    /// The environment's project service, whose methods this daemon admits and dispatches.
    project: Arc<crate::project::ProjectModule>,
    /// The environment's plugin catalogues, whose two method groups this daemon dispatches.
    catalogue: Arc<crate::catalogue::CatalogueModule>,
    /// What the workers hold live and which of them have reported it, which the catalogue asks
    /// before a reclaim that needs room.
    plugin_bridge: Arc<crate::catalogue::bridge::WorkerBridge>,
    /// What asks the admissions cadence for a pass before its next tick.
    admissions_due: Arc<tokio::sync::Notify>,
    /// Why admissions could not be handed over lately, for the doctor's catalogue check.
    admission_notes: std::sync::Mutex<Vec<String>>,
    /// The reader of admitted packages a session's command integrations are filled from, which
    /// checks each package once.
    integrations: Arc<crate::catalogue::integrations::Integrations>,
    /// The environment's grants and invitations, which the sharing and device method groups act on.
    sharing: Arc<crate::sharing::SharingService>,
    /// The environment's voice service: the coordinator and the seams it reads and proposes
    /// through. Built after the daemon exists, because two of its seams hold a weak reference back.
    voice: std::sync::OnceLock<Arc<crate::voice::VoiceModule>>,
    /// The environment's privacy record: privacy mode's generation, what each session still owes,
    /// and the root that drives the backup service, delivery and the descriptions through it.
    pub(crate) privacy: Arc<crate::privacy::EnvironmentPrivacy>,
    /// The environment's session names and descriptions: the pins people set and the provenance of
    /// generated descriptions, which outlive a session.
    pub(crate) descriptions: Arc<crate::describe::DescribeModule>,
    /// The environment's notification delivery service.
    pub delivery: Arc<crate::push::DeliveryModule>,
    /// The loop that drives it: recovery at start, then a pass on every tick.
    delivery_runtime: Arc<crate::push::runtime::DeliveryRuntime>,
    /// The paired devices, for the device method group.
    ///
    /// A view on this daemon's own registry database, which is the file the network half keeps its
    /// device records in, so the two see one set of devices whether or not this host is on a
    /// network.
    devices: Arc<net::devices::DeviceDirectory>,
    /// Every grant's lifetime on this host, measured on this daemon's clocks.
    lifetimes: Arc<net::lifetimes::GrantLifetimes>,
    /// What is true of this host rather than of one grant: the revision in force, the organisation
    /// leases it holds and the optional bounded offline-validity policy its owner chose.
    ///
    /// Every request intersects its grant with this, so it is read far more often than it is
    /// written and a plain lock is what it wants. It is shared rather than owned outright: the
    /// delivery runtime intersects an external destination's grant with the same policy at every
    /// question, and the automation service decides each node it dispatches under it.
    policy: Arc<std::sync::Mutex<crate::grants::HostPolicy>>,
    /// Moves whenever something a paired device's authority is decided from changes: this host's
    /// policy, or the rights ceiling in force.
    ///
    /// A batch a subscription carries is written under the decision that allowed it, and that
    /// decision names the epoch it was taken at. The write boundary reads this at every attempt to
    /// hand bytes over, so a change that lands while a batch waits for the writer or for the peer
    /// stops it there: the batch is decided again, or, once bytes are moving, the connection ends.
    authority_epoch: std::sync::atomic::AtomicU64,
    /// The policy's clock floor itself, which the policy shares with every holder of it.
    ///
    /// The write boundary decides at every attempt to hand bytes over whether a relayed batch's
    /// decision has run out by this host's reading of UTC, and a poll cannot wait for the policy's
    /// lock. This is the same floor the lock guards, not a copy of it: whoever raises it under the
    /// lock, the automation path included, raises what the poll reads, and the reading the poll
    /// takes raises what every later decision stands on.
    ///
    /// It also keeps what is owed a record. A refusal the clock decided has to outlive this
    /// process: a clock wound back before the next start would otherwise find the floor as it was
    /// last written and allow what was refused. The write can fail, so the debt is kept rather than
    /// dropped, and while it is owed no decision that reads the clock is taken
    /// ([`crate::grants::policy::UtcFloor::bound`]). Every later decision on the floor, the relay
    /// once a batch is refused, and the network's record task write the floor again until a write
    /// lands.
    utc_floor: Arc<crate::grants::policy::UtcFloor>,
    /// This host's half of the remote authority feed: the revisions only it issues, the revocation
    /// records it retains, and the synchronisation it owes before it serves remote work again.
    feed: std::sync::Mutex<crate::grants::AuthorityFeed>,
    /// The environment's change-set service, which reads repositories through the project
    /// service's own profile and boundary.
    changesets: Arc<crate::changeset::ChangeSetModule>,
    /// The environment's automation service: workflow definitions, runs and the causal budgets
    /// they share. It reads the grant each definition names from this daemon's own grant store.
    automation: Arc<crate::automation::AutomationModule>,
    /// The session number admission enforces now, as the registry last took it, readable without
    /// the registry's lock. A new workflow chain's created-session ceiling does not exceed it.
    sessions_in_force: std::sync::atomic::AtomicU64,
    /// The environment's attention store: one inbox, review state and visits across every session.
    attention: Arc<crate::attention::AttentionModule>,
    /// The serial boundary every contact-skill installation passes through.
    ///
    /// Reading an action's record, writing its dispatch marker, changing the files and recording
    /// the outcome are one sequence, and two callers running it at once could both find no record
    /// and both do the work. One daemon owns an environment, so one lock covers it.
    agent_tools: tokio::sync::Mutex<()>,
    worker_program: PathBuf,
    build_id: BuildId,
    release: String,
    /// Where this host's qualified shell packages are, when it keeps them somewhere of its own.
    shell_packages: Option<PathBuf>,
    terminal: Arc<dyn crate::supervision::TerminalPresenter>,
    /// What came of each session's local presentation, for a create token asked twice.
    ///
    /// A replayed create must not open a second window, and it must not claim the first one
    /// opened. Bounded by the sessions this host has: an entry goes when its worker is retired.
    presentations: Mutex<std::collections::HashMap<SessionId, Option<ProtocolError>>>,
    started_at_ms: TimestampMs,
    /// The desktop this host has, as last read, and the capability revision that reading is
    /// evidence for.
    desktop: Mutex<DesktopReading>,
    /// The sleep assertion this daemon holds, where it holds one, and whether a review of it is
    /// running.
    inhibitor: Mutex<Inhibitor>,
    /// How far the last look at what this host has outstanding got, and what it saw.
    demand_scan: Mutex<DemandScan>,
    /// Held while a session's closure is being finalised.
    ///
    /// Finding that no closure has been recorded and recording one are two steps. Two callers that
    /// ran them at once would each find none and each write one, and the record a person reads
    /// would be whichever finished last: a worker's own account of how its session ended could be
    /// replaced by this daemon's account of a worker it found gone. The closure watcher and the
    /// reconciliation this daemon does on its own both reach that point for the same session, so
    /// the two steps are one transaction.
    finalising: Mutex<()>,
    /// This daemon's side of an update of the host: its gate to new sessions, the creates under
    /// way, and whether it has been told to stop.
    handover: host::Handover,
    /// The machine group this environment records for itself, and the lock its steps are taken
    /// under.
    machine: machine_group::Machine,
    /// The environment's singleton lock, held for as long as this daemon runs. Every change to a
    /// record only the daemon that holds it may write takes it as proof.
    lock: SingletonLock,
}

impl std::fmt::Debug for Controller {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Controller")
            .field("environment", &self.paths.environment_id())
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl Controller {
    /// Returns the generation this daemon speaks for.
    #[must_use]
    pub const fn generation(&self) -> ControllerGeneration {
        self.generation
    }

    /// The environment's grants and invitations.
    #[must_use]
    pub fn devices(&self) -> &Arc<net::devices::DeviceDirectory> {
        &self.devices
    }

    /// The environment's grants and invitations.
    pub fn sharing(&self) -> &Arc<crate::sharing::SharingService> {
        &self.sharing
    }

    /// This host's policy as it stands, for a caller that only reads it.
    ///
    /// A copy rather than a guard: every accepted *change* goes through
    /// [`Self::update_policy`], which writes it down, and handing out a mutable guard would be a
    /// way to change the policy without that happening.
    #[must_use]
    pub fn policy(&self) -> crate::grants::HostPolicy {
        self.policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// This host's half of the remote authority feed.
    pub fn authority_feed(&self) -> std::sync::MutexGuard<'_, crate::grants::AuthorityFeed> {
        self.feed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Every grant's lifetime on this host.
    pub(crate) const fn lifetimes(&self) -> &Arc<net::lifetimes::GrantLifetimes> {
        &self.lifetimes
    }

    /// The host's clock floor: the one reading of UTC every process of this environment decides
    /// from in this boot.
    #[must_use]
    pub fn utc_floor(&self) -> &Arc<crate::grants::policy::UtcFloor> {
        &self.utc_floor
    }

    /// Returns this daemon's continuous clock, for a caller that has to build an admission.
    #[must_use]
    pub fn continuous_now(&self) -> kr_transport::clock::ContinuousInstant {
        self.clock.now()
    }

    /// Returns the environment's directories.
    #[must_use]
    pub const fn paths(&self) -> &EnvironmentPaths {
        &self.paths
    }

    /// Returns the catalogue module, for tests that read what it holds in force.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn catalogue(&self) -> &crate::catalogue::CatalogueModule {
        &self.catalogue
    }

    /// Returns which store this daemon keeps its keys in.
    #[must_use]
    pub const fn secret_store(&self) -> kr_crypto::store::StoreSelection {
        self.secret_store
    }

    /// Returns the environment's transfer service.
    #[must_use]
    pub const fn transfer(&self) -> &Arc<crate::transfer::TransferModule> {
        &self.transfer
    }

    /// Returns the environment's project service.
    #[must_use]
    pub const fn project(&self) -> &Arc<crate::project::ProjectModule> {
        &self.project
    }

    /// Returns the environment's change-set service.
    #[must_use]
    pub const fn changesets(&self) -> &Arc<crate::changeset::ChangeSetModule> {
        &self.changesets
    }

    /// Returns the environment's notification delivery service.
    #[must_use]
    pub fn delivery(&self) -> &Arc<crate::push::DeliveryModule> {
        &self.delivery
    }

    /// Returns the loop that drives delivery, and the credentials it delivers under.
    #[must_use]
    pub fn delivery_runtime(&self) -> &Arc<crate::push::runtime::DeliveryRuntime> {
        &self.delivery_runtime
    }

    /// Attaches the transport every delivery exchange goes through.
    ///
    /// The composition root's decision, made once at startup: the daemon attaches the managed
    /// transport, and a test attaches a recorder. Until one is attached the daemon delivers
    /// nothing and claims nothing. Returns false when one was already attached.
    pub fn attach_delivery_transport(
        &self,
        transports: Arc<dyn crate::push::transport::DeliveryTransports>,
    ) -> bool {
        self.delivery_runtime.attach_transport(transports)
    }

    /// The environment's automation service.
    #[must_use]
    pub const fn automation(&self) -> &Arc<crate::automation::AutomationModule> {
        &self.automation
    }

    /// Returns the environment's attention store.
    #[must_use]
    pub const fn attention(&self) -> &Arc<crate::attention::AttentionModule> {
        &self.attention
    }

    /// Returns the registry, for a module that needs to read the environment's own records.
    pub(crate) const fn registry_handle(&self) -> &Mutex<Registry> {
        &self.registry
    }

    /// Returns the environment's backup service.
    ///
    /// The daemon owns it so that one process accounts for what this environment has produced:
    /// two writers of one `backup.sqlite` would be two accounts of the same archive.
    #[must_use]
    pub fn backup(&self) -> &Arc<crate::backup::BackupService> {
        &self.backup
    }
}

/// Reads a worker's answer to `session.read`.
///
/// A daemon is replaced without its workers: an upgrade restarts this process and leaves every
/// live session's worker running the build that started it. Such a worker answers with the fields
/// its own build has, and the three this build added are not among them: the launch profile, the
/// last command block and the outstanding launch count. It is read through [`ReportedRead`]
/// instead, which is that answer with those three absent, so an upgraded daemon goes on listing
/// and describing the sessions it inherited.
///
/// Remove `ReportedRead` and this fallback once no worker from a build before those fields can
/// still be running, which is when every session that was live across the upgrade has closed.
///
/// # Errors
///
/// Returns the decoding failure when the answer is neither shape.
pub(crate) fn reported_read(value: &ParamsValue) -> std::result::Result<SessionReadResult, String> {
    match value.to_typed::<SessionReadResult>() {
        Ok(read) => Ok(read),
        // The older shape is checked against its own schema before it is decoded, like any
        // answer: an answer with a field neither shape declares is refused, not read as this.
        Err(error) => match value.to_typed::<ReportedRead>() {
            Ok(reported) => Ok(reported.into()),
            // Neither shape, so it is reported as the answer this build cannot read rather than
            // as an older worker's.
            Err(_) => Err(error.to_string()),
        },
    }
}

/// A session read as a worker from a build before the launch profile answers it.
#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReportedRead {
    session: SessionSummary,
    endpoint: Nullable<String>,
}

impl From<ReportedRead> for SessionReadResult {
    fn from(reported: ReportedRead) -> Self {
        Self {
            session: reported.session,
            endpoint: reported.endpoint,
            // A worker that does not report these says nothing about them, which is what null is.
            launch_profile: Nullable::null(),
            last_command_block: Nullable::null(),
            outstanding_launches: Nullable::null(),
        }
    }
}

/// This machine's wall clock, in UTC milliseconds.
///
/// The voice service's deadlines are wall-clock figures, because a paired device and a managed
/// service both read them and neither can read this host's anchored clock.
fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

fn parse<T: kr_protocol::wire::WireMessage>(params: &ParamsValue) -> Result<T> {
    params
        .to_typed()
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

fn encode<T: serde::Serialize>(value: &T) -> Result<ParamsValue> {
    ParamsValue::from_typed(value)
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

fn respond(request_id: RequestId, outcome: Result<ParamsValue>) -> ControlFrame {
    match outcome {
        Ok(value) => ControlFrame::Response(Response {
            request_id,
            outcome: Outcome::Ok(value),
        }),
        Err(error) => ControlFrame::Response(Response {
            request_id,
            outcome: Outcome::Error(error.to_protocol_error()),
        }),
    }
}

fn error_reply(request_id: RequestId, code: ErrorCode, message: impl Into<String>) -> ControlFrame {
    ControlFrame::Response(Response {
        request_id,
        outcome: Outcome::Error(ProtocolError::new(code, message)),
    })
}

#[cfg(test)]
mod tests;

/// A create the host refuses before it launches anything.
///
/// The windows these cover cannot be reached from outside the daemon: a create passes the
/// admission check, writes its reservation, prepares what the launch needs and only then waits.
/// What holds it there is the map it records its pending launch report in, which is taken between
/// the reservation and the transition to `spawned` and nowhere else during a create, and the
/// connection table, which the transition itself reads. What each of them has to leave behind is
/// the same: no process, and a reservation that has stopped occupying the environment.
#[cfg(test)]
mod a_create_that_launches_nothing;

/// A close to a worker that stops answering.
///
/// The daemon holds one connection per worker, and a close is the operation most likely to meet a
/// worker that has stopped answering: it is asking that worker to stop. What this covers is the
/// connection afterwards: that the caller is told, that the link is not put back in the shared
/// slot part way through an exchange, and that the next caller is not waiting behind the first.
#[cfg(test)]
mod a_close_a_worker_never_answers;

#[cfg(test)]
mod a_read_that_meets_a_worker_on_its_way_out;

#[cfg(test)]
mod a_floor_owed_its_record;

#[cfg(test)]
mod one_fence_for_one_debt;

#[cfg(test)]
mod one_barrier_for_every_restriction;

#[cfg(test)]
mod the_debt_pass;

/// A privacy change and a rename whose admission lapses while they wait for what they write to, and
/// the tick that takes a session for ended only when the registry shows its launch is over.
#[cfg(test)]
mod a_change_that_waits_for_its_store;

/// What the local door asks again where a retained answer goes back and where a mutation lands.
#[cfg(test)]
mod the_fence_at_every_effect;

/// A local connection whose peer stops reading.
#[cfg(test)]
mod a_peer_that_stops_reading;

/// This daemon's link to a worker, given up whenever what it carried did not end whole.
#[cfg(test)]
mod a_link_that_is_not_given_back;

/// A dispatch lease that runs out while its action waits at a real worker.
#[cfg(test)]
mod a_lease_that_runs_out_at_a_worker;

/// A daemon making way for an update: its gate to new sessions, the creates it waits for, and
/// the stop, through its own door.
#[cfg(test)]
mod making_way_for_an_update;
