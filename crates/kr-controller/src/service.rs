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
use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::split;
use kr_ipc::paths::EnvironmentPaths;
use kr_ipc::peer::PeerIdentity;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::envelope::{
    ControlEvent, ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{ActionWindow, PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::hostinfo::export::Sentence;
use kr_protocol::identity::BootIdentity;
use kr_protocol::ids::{
    ActorId, AuthorityRevision, BootEpoch, BuildId, CapabilityRevision, ConnectionId,
    ControllerGeneration, EnvironmentId, GrantId, RequestId, SessionId,
};
use kr_protocol::local::{LocalHelloAck, LocalPeer, LocalRole};
use kr_protocol::method::Method;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs, U64};
use kr_protocol::session::{
    ClosureReason, SessionCloseParams, SessionCreateParams, SessionReadResult, SessionSummary,
};
use kr_protocol::worker::ReservationId;
use kr_transport::clock::{ContinuousClock, SystemContinuousClock};
use kr_transport::lease::LeaseRefusal;
use kr_transport::window::{AcceptedDeadline, ActionWindowIssuer, MAX_WINDOW_VALIDITY};
use tokio::sync::Mutex;

use crate::desktop::power::Inhibitor;
use crate::directory::Directory;
use crate::error::{ControllerError, Result};
use crate::registry::{LaunchPhase, Registry};
use crate::singleton::SingletonLock;
use crate::supervision::{JobRetirement, WorkerSupervisor};

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

mod attention_reach;
mod authority_changes;
mod barrier;
mod capabilities;
mod close;
mod configuration;
mod create;
mod host;
mod inhibition;
mod reads;
mod recovery;
mod rendezvous;
mod revocation;
mod standing;
mod voice_actions;
mod workers;

pub use barrier::DEBT_PASS_INTERVAL;
pub use capabilities::{CAPABILITY_REVISION_FILE, DESKTOP_REREAD_INTERVAL};
pub use close::{CLOSE_EXCHANGE, CLOSURE_WATCH_TIMEOUT};
pub use create::RENDEZVOUS_TIMEOUT;
pub use inhibition::{DEMAND_BUDGET, DEMAND_PATIENCE, POWER_REVIEW_INTERVAL};
pub use rendezvous::LAUNCH_IDENTITY_TIMEOUT;

use authority_changes::{declaration_answer, destination_identifier, secret_params};
use barrier::{Debts, PassSchedule, Published, Reach};
use capabilities::{DesktopReading, capability_revision, resolved_desktop};
use create::PendingCreate;
use inhibition::DemandScan;
use workers::{UNACCOUNTED_WORKER, WORKER_EXCHANGE};

/// How long a daemon's start spends looking at the worker jobs its environment still has defined.
///
/// Each job takes launchd a few milliseconds to answer for, so this is room for hundreds of them. A
/// launchd that has stopped answering costs a start this long, and the bounded questions about the
/// job in hand when it runs out, rather than the start; the jobs not reached are looked at again by
/// the next one.
pub const JOB_SWEEP_BOUND: std::time::Duration = std::time::Duration::from_secs(30);

/// The file this environment's current boot identity is recorded in.
///
/// It lives in the state directory rather than the runtime one because it has to outlive the boot
/// it names, and a runtime directory does not.
pub const BOOT_FILE: &str = "boot";

/// The longest boot record this host reads.
const BOOT_FILE_LIMIT: u64 = 1_024;

/// How often the daemon replaces a live connection's action window.
///
/// Half the window's validity, which is the schedule the transport uses: a client is never left
/// holding a window that expired while a renewal was still in flight, and a connection that is
/// about to submit a mutation does not have to ask for one.
pub const WINDOW_RENEWAL: std::time::Duration =
    std::time::Duration::from_millis(MAX_WINDOW_VALIDITY.as_millis() as u64 / 2);

/// How often a local connection sends a keepalive.
///
/// Section 23 puts it at ten seconds while the connection is active. A network connection has the
/// transport's own keepalive underneath it; a Unix socket or a named pipe has nothing equivalent,
/// so the control stream carries one itself.
pub const LOCAL_KEEPALIVE: std::time::Duration = std::time::Duration::from_secs(10);

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
        std::sync::Mutex<Option<CanonicalSet<kr_protocol::rights::ActionRight>>>,
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
    _lock: SingletonLock,
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
    /// Starts the daemon: takes the lock, advances the generation and rebuilds the directory.
    ///
    /// # Errors
    ///
    /// Returns an error when another daemon owns the environment, the registry cannot be opened,
    /// or the controller identity is missing.
    pub async fn start(setup: ControllerSetup) -> Result<Arc<Self>> {
        Self::start_with(setup, Clocks::system()).await
    }

    /// Starts the daemon on the clocks a test gives it, by the same path [`Self::start`] takes on
    /// the machine's own.
    ///
    /// # Errors
    ///
    /// As [`Self::start`].
    #[cfg(feature = "testing")]
    pub async fn start_on_clocks(setup: ControllerSetup, clocks: Clocks) -> Result<Arc<Self>> {
        Self::start_with(setup, clocks).await
    }

    async fn start_with(setup: ControllerSetup, clocks: Clocks) -> Result<Arc<Self>> {
        Self::start_passing(setup, clocks, PassSchedule::every(DEBT_PASS_INTERVAL)).await
    }

    /// The one start, with the schedule its debt pass keeps.
    async fn start_passing(
        setup: ControllerSetup,
        clocks: Clocks,
        passes: PassSchedule,
    ) -> Result<Arc<Self>> {
        let Clocks {
            continuous: clock,
            wall,
        } = clocks;
        setup.paths.create()?;
        // The lock comes before everything the environment owns: the registry's own creation and
        // migration, the persistent identity, the generation and the directory. Two daemons
        // starting together would otherwise both run the schema creation, and both find an empty
        // key store, and the loser would overwrite the key every live worker recorded at spawn.
        let mut lock = SingletonLock::acquire(&setup.paths.singleton_lock(), setup.environment_id)?;
        let mut registry = Registry::open(setup.paths.registry_database(), setup.environment_id)?;
        let generation = lock.advance(&mut registry)?;
        // The configured session number, intersected with what this machine's resources allow,
        // becomes the number admission enforces. Only when the document actually names one: a
        // document that says nothing, and one this build cannot read, must not lift a restriction
        // the owner accepted through some other path.
        let startup_configuration = crate::config::open(&setup.paths);
        // A document on disk is not evidence that this host ever acted on it. An edit is written
        // before its effects run, so a daemon that stopped in between leaves a file nothing has
        // been done about, and a file edited while no daemon was running is the same case. The
        // durable record is the only thing that says which document this environment accepted:
        // anything else is an edit this host has not seen yet, and it goes through acceptance
        // below rather than being taken for a fact.
        let durably_accepted = registry.accepted_configuration()?;
        let accepted_document = crate::config::from_record(durably_accepted.document.as_deref());
        let unaccepted = accepted_document != startup_configuration.loaded().document;
        // The document whose effects are in force, which is the one the record holds and not the
        // one on disk. What an edit owes is the difference between the two, so a daemon that seeded
        // itself from the file would derive nothing from a ceiling somebody removed while it was
        // not running, and would fence nothing.
        // The rights ceiling this environment accepted is in force from the first request, before
        // any acceptance below runs: it is what the fences recorded against it were raised for.
        let rights_ceiling = accepted_document
            .as_ref()
            .and_then(|document| crate::config::ceilings::configured_rights(&document.ceilings));
        // So are the enrolment budgets it accepted. A startup reading that loaded a document
        // replaces them below, by the session number's rule; one that decided nothing leaves them.
        let accepted_budgets = accepted_document
            .as_ref()
            .map(|document| crate::config::catalogue::budgets(&document.ceilings));
        let mut accepted_configuration = crate::config::AcceptedState {
            revision: durably_accepted.revision,
            document: accepted_document,
            sessions: registry.session_limit()?,
        };
        if let Some(limit) = crate::config::session_limit_in_force(
            &startup_configuration,
            crate::config::HardLimits {
                sessions_per_environment: None,
            },
        ) {
            registry.set_session_limit(limit)?;
            accepted_configuration.sessions = limit;
        }
        let sessions_in_force = accepted_configuration.sessions;
        let in_force = crate::config::InForce::of(&startup_configuration);
        let startup_budgets = crate::config::catalogue::budgets_in_force(&startup_configuration);
        // The network and the voice broker come from this same reading, and from nothing a
        // process inherited: section 26 keeps a provider origin out of reach of an environment
        // variable. They apply for as long as this daemon runs.
        let started = crate::config::Started::of(startup_configuration.loaded().document.as_ref());
        drop(startup_configuration);
        let identity = (setup.identity)()?;
        let boot_epoch = kr_ipc::identity::boot_epoch(&setup.boot_identity)?;
        let boot = setup.boot_identity.clone();
        let paths = setup.paths.clone();
        let recorded_revision = capability_revision(&paths);
        let started_at_ms = kr_ipc::now_ms();
        let authority_revision = registry.authority_revision()?;
        let transfer = Arc::new(crate::transfer::TransferModule::open(&setup.paths).await?);
        let project = Arc::new(crate::project::ProjectModule::open(&setup.paths).await?);
        // The catalogue fetches through the proxy this daemon started with, the endpoint's own,
        // and asks this generation's member set what the workers hold before it makes room.
        let plugin_bridge = Arc::new(crate::catalogue::bridge::WorkerBridge::new(generation));
        // The budgets in force from the start, so the limits they set hold every package from
        // the catalogue's first check on.
        let catalogue = Arc::new(crate::catalogue::CatalogueModule::open(
            &setup.paths,
            Self::proxy_of(&started)?.as_ref(),
            Arc::clone(&plugin_bridge) as Arc<dyn kr_plugin_catalogue::BrokerBridge>,
            startup_budgets.or(accepted_budgets).unwrap_or_default(),
        )?);
        // The change-set service reads every repository through the project service's own opened
        // handles and restricted execution profile, so it takes that service rather than opening
        // a second one.
        let changesets = Arc::new(
            crate::changeset::ChangeSetModule::open(&setup.paths, Arc::clone(project.service()))
                .await?,
        );
        // Opening the backup store migrates it and touches the disk, so it runs on a blocking
        // task rather than on the daemon's reactor, exactly as the two above do.
        let backup = {
            let paths = setup.paths.clone();
            Arc::new(
                tokio::task::spawn_blocking(move || {
                    crate::backup::BackupService::open(paths.state_dir())
                })
                .await
                .map_err(|_| ControllerError::RegistryUnavailable {
                    detail: "the backup service could not be opened".to_owned(),
                })??,
            )
        };
        // The executable the daemon was told to start, resolved here rather than at the launch: a
        // worker runs in a directory of its own, so a relative name would be looked for beneath
        // that instead of beneath the directory this daemon was started in. It is resolved before
        // the daemon is built, because what builds it cannot fail.
        let worker_program = kr_ipc::paths::resolve_here(setup.worker_program)?;
        // The grants and the invitations live in the daemon's own registry database, beside the
        // devices that hold them, so an authority object and the device it was issued to are in
        // one file and one backup.
        // This host's own device identity is derived from its environment, the same way the
        // network half derives it, so the feed speaks for the same host across restarts.
        let host_device_id = kr_protocol::ids::DeviceId::new(setup.environment_id.get());
        let sharing = Arc::new(crate::sharing::SharingService::new(
            crate::grants::GrantDirectory::open(setup.paths.registry_database())?,
            host_device_id,
        ));
        // The policy and the feed are read back from the store rather than rebuilt empty. A host
        // that came back unrestricted after every restart would be the same failure as one that
        // accepted a restored old policy, by a different route.
        let stored = match sharing.grants().stored_policy()? {
            Some(stored) => stored,
            None => crate::grants::HostPolicy::personal(authority_revision).snapshot(),
        };
        // The host's one reading of UTC in this boot, which every worker maps too. It is opened,
        // adopted or created here, before any worker is adopted or spawned, and it starts at least
        // where this host's record of it stands.
        let (floor_words, continuity_lost) = open_utc_floor(
            &mut registry,
            &setup.paths,
            setup.environment_id,
            boot_epoch,
            stored.utc_floor_ms.get(),
        )?;
        let utc_floor = Arc::new(crate::grants::policy::UtcFloor::on(
            floor_words,
            stored.utc_floor_ms.get(),
        ));
        if continuity_lost {
            utc_floor.lose_continuity();
        }
        let policy =
            crate::grants::HostPolicy::restore(&stored, authority_revision, Arc::clone(&utc_floor));
        // Written down again with the revision the registry reached. A start that cannot write it
        // still starts, with its floor owed its record: no decision that reads the clock is taken
        // until a write lands, and a personal grant that never expires is used as before. Stopping
        // instead would leave no daemon at all while the store is full.
        let snapshot = policy.snapshot();
        match sharing.grants().store_policy(&snapshot) {
            Ok(()) => utc_floor.wrote(snapshot.utc_floor_ms.get()),
            Err(error) => {
                eprintln!(
                    "kr-controller: could not write this host's policy at start, so no decision \
                     that reads the clock is taken until it can: {error}"
                );
                utc_floor.could_not_write();
            }
        }
        let policy = Arc::new(std::sync::Mutex::new(policy));
        let mut feed = match sharing.grants().stored_feed()? {
            Some(stored) => crate::grants::AuthorityFeed::restore(&stored),
            None => crate::grants::AuthorityFeed::new(host_device_id, authority_revision),
        };
        // The registry is the allocator. A feed restored below it would number its next entry with
        // a revision the registry has already used, and would report an old number as the one in
        // force.
        feed.note_revision(authority_revision);
        sharing.grants().store_feed(&feed.snapshot())?;
        let attention = Arc::new(crate::attention::AttentionModule::open(
            &setup.paths,
            setup.boot_identity.clone(),
        )?);
        let devices = Arc::new(net::devices::DeviceDirectory::open(
            setup.paths.registry_database(),
        )?);
        // The offline bound's time, taken as the policy holding it is restored and before anything
        // remote is decided under it: from what this boot recorded of it, advanced by the boot
        // clock, and never less than this host's reading of UTC says.
        let shared_clock: Arc<dyn kr_ipc::clock::SharedClock> =
            Arc::new(kr_ipc::clock::SystemSharedClock);
        // One record of every grant's lifetime, on this daemon's clocks. The network's connections
        // and the owner confirmations they spend ask it, and so does everything else here that
        // decides a grant's time, so no two parts of the host can disagree about one grant.
        let lifetimes = Arc::new(net::lifetimes::GrantLifetimes::new(
            Arc::clone(&devices),
            Arc::clone(&clock),
            Arc::clone(&shared_clock),
            setup.boot_identity.clone(),
            wall.clone(),
            Arc::clone(&utc_floor),
        ));
        // The store decides a grant's time bound at the moment of its effect, on this host's own
        // clocks, under the floor every other decision stands on and from the same anchors.
        sharing
            .grants()
            .bind_host_clock(crate::grants::store::HostClock {
                floor: Arc::clone(&utc_floor),
                wall: wall.clone(),
                lifetimes: Arc::clone(&lifetimes),
            });
        let offline_anchor = net::offline_anchor(
            policy
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .offline_validity(),
            None,
            &lifetimes.anchor_sources(),
        )?;
        // A record for any other synchronisation is one a policy write never reached.
        if let Err(error) = devices
            .forget_offline_anchors_except(offline_anchor.map(|anchor| anchor.synchronised_at_ms()))
        {
            eprintln!("kr-controller: could not forget stale offline bound records: {error}");
        }
        // The offline bound's cell states both of its ends from here, before anything is decided
        // under it.
        {
            let policy = policy
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            lifetimes.hold_offline_anchor(offline_anchor, &policy);
            net::publish_offline_bound(
                policy.offline_cell(),
                policy.offline_validity(),
                offline_anchor,
                clock.now(),
                utc_floor.get(),
            );
        }
        // The automation service carries out its change-set nodes through the change-set service,
        // so it takes that rather than opening anything of its own beside its journal. The grant
        // each definition names is read from the stores this daemon holds and decided under this
        // daemon's own model once the daemon exists, which is where it is bound below.
        let automation = Arc::new(
            crate::automation::AutomationModule::open(
                &setup.paths,
                setup.environment_id,
                Arc::clone(changesets.service()),
            )
            .await?,
        );
        let (initial_desktop, initial_evidence) = resolved_desktop(in_force.worker_profile, &boot);
        let opened_store = setup
            .secret_store
            .open(
                kr_ipc::verify::CONTROLLER_SECRET_SERVICE,
                &setup.paths.secrets_dir(),
            )
            .map_err(ControllerError::registry)?;
        let secret_store: Arc<dyn kr_crypto::store::SecretStore> = Arc::from(opened_store.store);
        let device_keys = net::host_device_keys(&*secret_store, setup.environment_id)?;
        // External destinations' credentials are kept in the same store as this host's own keys,
        // in a scope of their own, and never in the delivery journal.
        let delivery = Arc::new(crate::push::DeliveryModule::open(
            &setup.paths,
            device_keys.notification_preview,
            device_keys.stored_envelope,
            crate::push::secrets::DestinationSecrets::new(secret_store, setup.environment_id),
        )?);
        // The runtime is built here and started once the daemon exists. Its renewals are proven
        // with this host's own authorisation key, which the installation named when it authorised
        // the host, and an external message's authority is the grant its rule names.
        let delivery_runtime = crate::push::runtime::DeliveryRuntime::new(
            Arc::clone(&delivery),
            Arc::new(crate::push::credentials::HeldCredentials::new()),
            Arc::new(crate::push::authority::GrantedRecipients::new(
                Arc::clone(&sharing),
                Arc::clone(&policy),
                setup.environment_id,
                Arc::clone(&lifetimes),
            )),
            Arc::new(crate::push::sender::HostSigner::new(
                device_keys.authorisation,
            )),
            crate::push::runtime::Cadence::DEFAULT,
            tokio::runtime::Handle::current(),
        );
        let controller = Arc::new_cyclic(|me| Self {
            me: me.clone(),
            registry: Mutex::new(registry),
            directory: Mutex::new(Directory::default()),
            connections: Mutex::new(BTreeMap::new()),
            pending: Mutex::new(BTreeMap::new()),
            recovering: std::sync::Mutex::new(std::collections::BTreeSet::new()),
            recovered: tokio::sync::Notify::new(),
            admitted: std::sync::Mutex::new(BTreeMap::new()),
            identity,
            secret_store: setup.secret_store,
            generation,
            paths: setup.paths,
            plugin_bridge,
            admissions_due: Arc::new(tokio::sync::Notify::new()),
            admission_notes: std::sync::Mutex::new(Vec::new()),
            integrations: Arc::new(crate::catalogue::integrations::Integrations::new()),
            accepted_configuration: Mutex::new(accepted_configuration),
            in_force: std::sync::Mutex::new(in_force),
            started,
            rights_ceiling: std::sync::Mutex::new(rights_ceiling),
            debts: Arc::new(std::sync::Mutex::new(Debts::default())),
            debt_pass: Arc::new(tokio::sync::Notify::new()),
            #[cfg(feature = "testing")]
            before_presentation_lock: crate::attention::Pause::default(),
            #[cfg(feature = "testing")]
            after_the_claim: ReadPause::default(),
            #[cfg(test)]
            before_the_record: ReadPause::default(),
            #[cfg(test)]
            before_the_pass_tells: ReadPause::default(),
            boot_identity: setup.boot_identity,
            boot_epoch,
            windows: ActionWindowIssuer::with_default_validity(Arc::clone(&clock) as Arc<_>),
            shared_clock,
            leases: crate::authority::AuthorityBarrier::new(generation, authority_revision),
            clock,
            wall,
            network: std::sync::OnceLock::new(),
            supervisor: setup.supervisor,
            backup,
            transfer,
            project,
            catalogue,
            sharing,
            voice: std::sync::OnceLock::new(),
            delivery,
            delivery_runtime,
            devices,
            lifetimes,
            policy,
            authority_epoch: std::sync::atomic::AtomicU64::new(0),
            utc_floor,
            feed: std::sync::Mutex::new(feed),
            changesets,
            automation,
            sessions_in_force: std::sync::atomic::AtomicU64::new(sessions_in_force),
            attention,
            agent_tools: tokio::sync::Mutex::new(()),
            worker_program,
            build_id: setup.build_id,
            release: setup.release,
            started_at_ms,
            shell_packages: setup.shell_packages,
            terminal: Arc::from(setup.terminal),
            presentations: Mutex::new(std::collections::HashMap::new()),
            desktop: Mutex::new(DesktopReading {
                context: initial_desktop,
                evidence: initial_evidence,
                revision: recorded_revision.unwrap_or_else(|| CapabilityRevision::new(0)),
                durable_revision: recorded_revision.is_some(),
                records: Vec::new(),
                read_at: std::time::Instant::now(),
            }),
            inhibitor: Mutex::new(Inhibitor::new()),
            demand_scan: Mutex::new(DemandScan::default()),
            finalising: Mutex::new(()),
            _lock: lock,
        });
        // Bound before anything can reach the module: from here on a workflow's grant is decided
        // under this daemon's policy, its configured ceiling and its clock model, and a node's
        // change-set write is held under this daemon's registry.
        controller.automation.bind(Arc::downgrade(&controller));
        // Reconnecting is not only verifying. A replacement daemon has to present the generation it
        // advanced to, because that is what fences the daemon it replaced.
        let directory = {
            let registry = controller.registry.lock().await;
            Directory::rebuild(&controller.paths, &registry, &controller.reconnect()).await?
        };
        *controller.directory.lock().await = directory;
        // Every reservation whose claim was consumed and every recorded worker is a member of the
        // plugin admissions' set before anything is served, each pending until it reports.
        controller.seed_admission_members().await?;
        // A reboot ends every live execution, of either profile. Sessions published in an earlier
        // boot are closed with that as their reason before anything tries to recover them, so the
        // record says the host restarted rather than that a worker died for reasons unknown.
        controller.close_previous_boot().await?;
        controller.recover_reservations().await?;
        // Recovery has settled every reservation it can, so what is left under the workers
        // directory that no session claims is nothing's.
        controller.sweep_worker_dirs().await?;
        // Before this daemon serves anything, so no job a create of its own defines is looked at.
        controller.retire_ended_jobs().await;
        // The workers recovery reached are sent their admissions from here on, and every member
        // that is pending or not confirmed ended is asked about on a cadence.
        controller.start_admissions_cadence();
        // A fence this environment recorded and never saw answered is announced again, to the
        // workers this daemon has just reconnected to. The debt is durable, so a daemon that
        // stopped between raising a fence and hearing every answer comes back still owing it; the
        // announcement is how a worker that has since acknowledged, or since ended, settles it.
        if controller.registry.lock().await.fence_owed()?.is_some() {
            controller.announce_authority_revision().await?;
        }
        // Every fence debt on disk is owed a barrier: its restriction took effect before the stop,
        // or never will. They are published before anything is served, a barrier is raised for
        // them now, and the pass raises one again until it lands.
        {
            let owed = controller.sharing.grants().fence_owed()?;
            let mut debts = controller.debts();
            for debt in owed {
                debts.published.insert(
                    debt,
                    Published {
                        reach: Reach::Host,
                        covered: false,
                    },
                );
            }
        }
        if let Err(error) = controller.raise_owed_barrier().await {
            eprintln!(
                "kr-controller: the barrier this host owes from before it stopped could not be \
                 raised yet, so nothing is admitted or forwarded until it is: {error}"
            );
        }
        controller.start_debt_pass(passes);
        // A document this environment has not accepted is put through acceptance here rather than
        // left for whoever reads next. What it owes can include fencing dispatch, and work must not
        // be dispatched under an authority that a document already written on this disk withdrew.
        // Nothing here can fail the start: acceptance reports what it could not do in the value it
        // returns, the durable record is advanced only once every effect landed, and an acceptance
        // that got nowhere is attempted again by the next one.
        if unaccepted {
            let accepted = controller.accept_configuration().await;
            // A fence this document owes has to be up before anything can be dispatched under the
            // authority it withdrew, so a start that could not raise one does not go on to serve.
            // Failing to *record* an acceptance whose effects all landed is a different thing: the
            // effects are in force, and the next start derives them again.
            if !accepted.effects_applied {
                let problem = accepted
                    .not_in_force
                    .clone()
                    .unwrap_or_else(|| Sentence::new().stated("the reason was not recorded"));
                return Err(ControllerError::Configuration(format!(
                    "this environment's configuration document could not be put into force: \
                     {problem}"
                )));
            }
        }
        controller.start_voice();
        // Every session the attention store reads: the live ones over their workers, and the ones
        // whose closure an earlier daemon recorded and which the store has not finished yet.
        controller.start_attention().await;
        // Backup work an earlier daemon left unfinished is resolved before anything can add to it:
        // what is still authorised goes back in hand, what is not is cancelled, and a publication
        // that left this host and was never answered is recorded as unknown rather than guessed at.
        {
            let backup = Arc::clone(&controller.backup);
            let now_ms = kr_ipc::now_ms();
            tokio::task::spawn_blocking(move || backup.reconcile(now_ms))
                .await
                .map_err(|_| ControllerError::RegistryUnavailable {
                    detail: "the backup service could not be reconciled".to_owned(),
                })??;
        }
        // Delivery the same way: what an earlier daemon left on the wire becomes an outcome
        // nobody knows, and what is no longer authorised is taken back, before a pass can claim
        // anything. The loop then drives the outbox until the daemon goes.
        controller.delivery_runtime.start().await;
        // A key update that stopped between its two stores is finished here, from the one that
        // took it first. A daemon that cannot write its own device directory does not start as
        // though it had: the next start tries again, and nothing serves a device from a directory
        // behind the journal in the meantime.
        controller.recover_preview_keys()?;
        crate::transfer::serve(&controller)?;
        // The owner's setting is the owner's setting across a restart. A daemon that waited for a
        // client to ask before it looked would leave an enabled setting doing nothing until
        // somebody happened to run a command.
        let _ = controller.power_state().await;
        // The network comes up last. A paired device must not reach a daemon that has not yet
        // recovered its reservations and rebuilt its worker directory, because it would be told
        // that sessions this host is running do not exist. Registering it also lends the project
        // service this host's owner, its owner devices, for its location decisions.
        //
        // What it joins is the configuration document's network section, read when this daemon
        // started: a selection that cannot be used stops the start with its key named, rather than
        // leaving a host that looks up and cannot be reached.
        if let Some(setup) = net::NetworkSetup::from_configuration(
            &controller.started.network,
            &controller.paths,
            controller.secret_store(),
        )? {
            net::register(&controller, setup).await?;
        }
        // Unattended workflow execution starts last. The journal was recovered when the module
        // was opened, but nothing it holds runs until every gate above has passed, the
        // configuration put into force among them: a withdrawal it made may owe a fence that has
        // to be up before anything is dispatched, and a start that fails anywhere above executes
        // nothing at all.
        controller.automation.start();
        Ok(controller)
    }

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

    /// Answers an action this daemon has already admitted for this caller, if it has.
    ///
    /// The de-duplication key is the actor and the action together, and the payload digest decides
    /// whether it is the same action or a reused identifier. Only `session.create` has a retained
    /// record here; a close is retained by the worker that owns the session, which answers its own
    /// duplicates.
    async fn retained(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        connection_id: ConnectionId,
    ) -> Option<ControlFrame> {
        if matches!(method, Method::AgentToolsInstall | Method::AgentToolsRemove) {
            return self
                .retained_installation(actor_id, mutation, connection_id)
                .await;
        }
        // An authority change this host already holds a claim on is answered from it, here, before
        // freshness is asked for: its result, its refusal, that it is still running, or what this
        // host's records prove an attempt that ended unrecorded did. Section 9 keeps a receipt
        // readable after the window that admitted it has expired, and a retry of a revocation that
        // cannot reach its result would otherwise be told its window is gone rather than what
        // happened.
        if matches!(
            method,
            Method::GrantCreate
                | Method::GrantRevoke
                | Method::DeviceRevoke
                | Method::DevicePreviewKeyUpdate
                | Method::DeliveryDestinationSecretSet
        ) {
            return self.retained_authority_answer(actor_id, mutation).await;
        }
        // A declaration of a device's keys is answered the same way, from the outcome the device
        // directory recorded beside the keys: a completion or a refusal alike, so a retry whose
        // reply was lost is told what happened rather than that its window is gone.
        if method == Method::DeviceKeysComplete {
            let digest = kr_protocol::digest::mutation_digest(mutation, actor_id).ok()?;
            return match self
                .devices
                .recorded_declaration(actor_id, mutation.action_id)
            {
                Ok(Some(recorded)) => Some(respond(
                    mutation.request_id,
                    declaration_answer(mutation, &digest, recorded),
                )),
                Ok(None) => None,
                Err(error) => Some(respond(mutation.request_id, Err(error))),
            };
        }
        // A voice change is claimed in the same store and answered the same way: section 9 keeps
        // a receipt readable after the window that admitted it has expired, and a retry that
        // cannot reach its result would otherwise be told its window is gone rather than what
        // happened. A delegation is not here, because it does not go through that store.
        if crate::voice::VoiceModule::serves(method) && method != Method::VoiceDelegate {
            return match self.voice_answered(actor_id, mutation).await {
                Ok(Some(answered)) => Some(ControlFrame::Response(Response {
                    request_id: mutation.request_id,
                    outcome: Outcome::Ok(answered),
                })),
                Ok(None) => None,
                Err(error) => Some(respond(mutation.request_id, Err(error))),
            };
        }

        if method != Method::SessionCreate {
            return None;
        }
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id).ok()?;
        let existing = {
            let registry = self.registry.lock().await;
            registry
                .reservation_for_token(actor_id, mutation.action_id.get())
                .ok()
                .flatten()?
        };
        if existing.payload_digest != digest {
            return Some(respond(
                mutation.request_id,
                Err(ControllerError::IdConflict {
                    token: mutation.action_id.to_string(),
                }),
            ));
        }
        Some(respond(
            mutation.request_id,
            self.replay_create(&existing).await,
        ))
    }

    /// Validates a local caller's record and registers its connection in one step.
    ///
    /// The two have to be one step. Validating first and registering afterwards leaves a gap in
    /// which authority can be withdrawn, and a connection registered in that gap would pass every
    /// later check. The registry lock is taken first and the connection table second, which is the
    /// order [`Self::revoke_authority`] uses, so neither can interleave with the other.
    async fn admit_connection(
        &self,
        connection_id: ConnectionId,
        actor_id: &ActorId,
        peer: &PeerIdentity,
    ) -> Result<()> {
        let registry = self.registry.lock().await;
        let admitted_revision = registry.authority_revision()?;
        // A local caller's record is the operating-system identity the listener authenticated.
        // Re-checking it here, inside the same critical section as the registration, is the final
        // validation the transport's contract names: the listener's check happened when the
        // connection was accepted, and this one happens where the registration is written, so
        // nothing can be admitted between the two.
        peer.authorise(kr_ipc::paths::current_uid())?;
        let mut admitted = self.admitted_table();
        admitted.insert(
            connection_id,
            AdmittedConnection {
                actor_id: actor_id.clone(),
                admitted_revision,
            },
        );
        drop(admitted);
        drop(registry);
        Ok(())
    }

    /// Refuses a mutation whose admission no longer stands, inside the caller's transaction.
    ///
    /// The caller holds the store lock it is about to write under, and passes the registry guard
    /// it took next: that order is the one admission and revocation both take, so neither can
    /// interleave with this. Nothing is awaited between this answer and the write, which is what
    /// makes the answer still true when the write happens.
    ///
    /// Checking before the wait would prove the admission stood before the wait, which is not the
    /// question. `docs/host/README.md` states the rule for the services outside this crate.
    ///
    /// # Errors
    ///
    /// Returns the way the admission lapsed: its deadline passed, the authority it was admitted
    /// under was withdrawn, or its connection's registration was.
    pub fn check_admission(
        &self,
        registry: &Registry,
        admission: &crate::authority::AdmittedMutation,
    ) -> Result<()> {
        self.check_fence()?;
        let authority_revision = registry.authority_revision()?;
        let admitted = self.admitted_table();
        let registered = admitted
            .get(&admission.connection_id)
            .is_some_and(|connection| connection.admitted_revision >= authority_revision);
        drop(admitted);
        admission
            .check(crate::authority::AdmissionContext {
                now: self.clock.now(),
                authority_revision,
                registered,
            })
            .map_err(|lapse| match lapse {
                crate::authority::AdmissionLapse::Expired => ControllerError::WindowExpired {
                    detail: lapse.to_string(),
                },
                crate::authority::AdmissionLapse::Revoked
                | crate::authority::AdmissionLapse::Deregistered => {
                    ControllerError::PermissionDenied {
                        detail: lapse.to_string(),
                    }
                }
            })
    }

    /// The admission check a mutation's own effect repeats, when it is carrying an admission.
    ///
    /// A withdrawal is several writes and not all of them are in one store, and each waits for a
    /// lock of its own. The check is cheap and the guard is already held, so a caller repeats it
    /// before each write **that can still be refused**: once authority has actually been
    /// withdrawn, the rest of that withdrawal follows whatever the clock has done since, and its
    /// caller stops asking. `None` on either side is the local owner's own path, which carries no
    /// mutation window.
    fn still_admitted(
        &self,
        registry: Option<&Registry>,
        carried: Option<&crate::authority::AdmittedMutation>,
    ) -> Result<()> {
        match (registry, carried) {
            (Some(registry), Some(carried)) => self.check_admission(registry, carried),
            _ => Ok(()),
        }
    }

    /// Returns the table of admitted connections.
    ///
    /// A synchronous lock, deliberately: nothing is awaited while it is held, and the registry
    /// guard often is. A connection table behind an asynchronous lock would make every reader of
    /// it require the registry to be shared across threads, which a SQLite connection is not.
    fn admitted_table(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<ConnectionId, AdmittedConnection>> {
        self.admitted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Returns this daemon's continuous clock, for a caller that has to build an admission.
    #[must_use]
    pub fn continuous_now(&self) -> kr_transport::clock::ContinuousInstant {
        self.clock.now()
    }

    /// Runs one service transaction under a carried admission.
    ///
    /// This is the guarded operation `docs/host/README.md` names for a service in another crate. A
    /// service holds its own store lock, calls this, and writes inside the closure: the registry
    /// lock is taken here and held across the check and the write, so a revocation cannot land
    /// between them. Nothing is awaited inside the closure, which is what makes the answer still
    /// true when the write happens.
    ///
    /// # Errors
    ///
    /// Returns the way the admission lapsed, or whatever the closure returns.
    pub async fn enter_admitted<T>(
        &self,
        admission: &crate::authority::AdmittedMutation,
        write: impl FnOnce(&mut Registry) -> Result<T>,
    ) -> Result<T> {
        // An admission with no deadline is a retry's admission: it may be *answered* from what
        // this host already holds, and it may not write. Section 9 keeps a receipt readable after
        // the freshness that admitted it is gone; what the freshness admitted was the action, and
        // nothing here can admit a new one without it.
        if admission.deadline.is_none() {
            return Err(ControllerError::WindowExpired {
                detail: "this action carries no freshness, so it may be answered from what this                          host holds and may not write"
                    .to_owned(),
            });
        }
        let mut registry = self.registry.lock().await;
        self.check_admission(&registry, admission)?;
        write(&mut registry)
    }

    /// Refuses a request on a connection whose registration has been withdrawn.
    fn authorised(&self, connection_id: ConnectionId) -> Result<ActorId> {
        let admitted = self.admitted_table();
        match admitted.get(&connection_id) {
            Some(connection) => Ok(connection.actor_id.clone()),
            None => Err(ControllerError::PermissionDenied {
                detail: "the authority this connection was admitted under has been withdrawn; \
                         open a new connection"
                    .to_owned(),
            }),
        }
    }

    /// The admission a service asks again from inside the work a mutation has begun.
    ///
    /// Every service that performs a mutation's effect after a wait is handed this one check, the
    /// project service, the transfer service and the workflow journal alike:
    /// [`Self::check_registration`], which asks the fence this host owes before the connection's
    /// registration and the accepted deadline.
    pub(crate) fn admission_in_service(
        self: &Arc<Self>,
        carried: crate::authority::AdmittedMutation,
    ) -> impl Fn() -> std::result::Result<(), ProtocolError> + Send + Sync + 'static {
        let controller = Arc::clone(self);
        move || {
            controller
                .check_registration(&carried)
                .map_err(|error| error.to_protocol_error())
        }
    }

    /// Refuses a mutation that a fence this host owes stops, or whose registration or accepted
    /// deadline has lapsed.
    ///
    /// These are the answers a caller can have without waiting for anything, so this can be asked
    /// from inside work that has already begun — a blocking task, a service's own call — where
    /// taking the registry's asynchronous lock is not possible.
    ///
    /// The fence comes first. A withdrawal whose fence could not be raised did not advance the
    /// revision, so every registration still stands under the revision it carries; without the
    /// fence this would let a mutation admitted just before that failure act after it.
    ///
    /// The registration carries the revision it stands under, and that is what makes the reading
    /// sufficient. Both revocations keep it true. [`Self::revoke_authority`] takes every
    /// connection out of the table before anything can observe the revision it installed, so a
    /// mutation whose connection is gone is refused. A revocation that withdraws one device leaves
    /// the rest registered and stamps them with the revision it advanced to, so a mutation
    /// admitted before that point finds its registration standing under a *later* revision than
    /// the one it carries, which is the authority it was admitted under having been replaced. The
    /// registration therefore has to stand under exactly the revision the mutation carries: a
    /// lower one is a registration this host has already replaced, and a higher one is a
    /// revocation this mutation predates.
    ///
    /// The order is the contract's: authority first, then freshness, so a caller that may act on a
    /// spent deadline cannot read past a withdrawal with it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::PermissionDenied`] while a fence is owed and for a registration
    /// that has been withdrawn or replaced, and [`ControllerError::WindowExpired`] for a deadline
    /// that has passed.
    pub(crate) fn check_registration(
        &self,
        admission: &crate::authority::AdmittedMutation,
    ) -> Result<()> {
        self.check_registration_in(&self.admitted_table(), admission)
    }

    /// Runs `commit` while a mutation's registration is held standing, and refuses it where
    /// [`Self::check_registration`] would: a fence owed, the registration withdrawn or replaced,
    /// or the deadline passed.
    ///
    /// [`Self::check_registration`] answers for the moment it is asked. A change that becomes
    /// durable later asks here instead: the connection table stays held from the check to the end
    /// of `commit`, and revoking authority and withdrawing a connection both take that table, so
    /// a withdrawal is ordered wholly before the check or wholly after the commit. `commit` is
    /// short, synchronous and awaits nothing, because the table is a synchronous lock that every
    /// admission waits on.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::check_registration`] returns, in which case `commit` did not run.
    pub(crate) fn under_registration<T>(
        &self,
        admission: &crate::authority::AdmittedMutation,
        commit: impl FnOnce() -> T,
    ) -> Result<T> {
        let admitted = self.admitted_table();
        self.check_registration_in(&admitted, admission)?;
        let committed = commit();
        drop(admitted);
        Ok(committed)
    }

    /// Returns the wall-clock deadline a mutation was accepted under, for the receipt it leaves.
    ///
    /// The deadline decides on the continuous clock. A receipt carries a wall-clock one, because
    /// that is what a person and the wire read, so what is left of it is measured on the clock
    /// that decides it and laid over the wall clock now.
    pub(crate) fn receipt_deadline_ms(
        &self,
        admission: &crate::authority::AdmittedMutation,
    ) -> Option<u64> {
        let deadline = admission.deadline?;
        let remaining = u64::try_from(
            deadline
                .saturating_duration_since(self.clock.now())
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        Some(kr_ipc::now_ms().get().saturating_add(remaining))
    }

    /// [`Self::check_registration`], for a caller that already holds the connection table.
    ///
    /// A caller that writes a marker under that table, so that a revocation cannot withdraw the
    /// registration between the answer and the marker, asks here rather than taking the table a
    /// second time.
    ///
    /// # Errors
    ///
    /// As [`Self::check_registration`].
    fn check_registration_in(
        &self,
        admitted: &BTreeMap<ConnectionId, AdmittedConnection>,
        admission: &crate::authority::AdmittedMutation,
    ) -> Result<()> {
        self.check_fence()?;
        let standing = admitted
            .get(&admission.connection_id)
            .map(|connection| connection.admitted_revision);
        let Some(standing) = standing else {
            return Err(ControllerError::PermissionDenied {
                detail: crate::authority::AdmissionLapse::Deregistered.to_string(),
            });
        };
        if standing != admission.admitted_revision {
            return Err(ControllerError::PermissionDenied {
                detail: crate::authority::AdmissionLapse::Revoked.to_string(),
            });
        }
        if admission
            .deadline
            .is_some_and(|deadline| self.clock.now() >= deadline)
        {
            return Err(ControllerError::WindowExpired {
                detail: crate::authority::AdmissionLapse::Expired.to_string(),
            });
        }
        Ok(())
    }

    /// Returns the authority revision a connection was admitted under.
    fn admitted_revision(&self, connection_id: ConnectionId) -> Result<AuthorityRevision> {
        let admitted = self.admitted_table();
        admitted.get(&connection_id).map_or_else(
            || {
                Err(ControllerError::PermissionDenied {
                    detail: "the authority this connection was admitted under has been withdrawn; \
                             open a new connection"
                        .to_owned(),
                })
            },
            |connection| Ok(connection.admitted_revision),
        )
    }

    /// Withdraws one connection's registration.
    fn deregister(&self, connection_id: ConnectionId) {
        self.admitted_table().remove(&connection_id);
    }

    /// Takes the dispatch lease a remote-origin mutation needs, and returns its deadline.
    ///
    /// Section 9 requires a live worker-held authority lease from the current controller generation
    /// and revision for remote dispatch. A locally authenticated caller is not remote dispatch and
    /// needs none, which is why the ingress decides rather than the method.
    async fn dispatch_lease(
        &self,
        session_id: SessionId,
        actor: &kr_protocol::actor::ActorEnvelope,
    ) -> Result<Option<kr_transport::clock::ContinuousInstant>> {
        if actor.ingress != kr_protocol::actor::ActorIngress::PairedDevice {
            return Ok(None);
        }
        match self
            .leases
            .renew(session_id, self.generation, &*self.clock)
            .map_err(|error| ControllerError::supervision(error.to_string()))?
        {
            Ok(lease) => Ok(Some(lease.deadline)),
            Err(LeaseRefusal::GenerationReplaced) => Err(ControllerError::PermissionDenied {
                detail: "this daemon no longer holds the generation this lease was issued under"
                    .to_owned(),
            }),
            Err(LeaseRefusal::RevisionNotAcknowledged | LeaseRefusal::NoLease) => {
                Err(ControllerError::PermissionDenied {
                    detail:
                        "the worker has not acknowledged this environment's authority revision, \
                             so no remote action can be dispatched to it"
                            .to_owned(),
                })
            }
        }
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

    /// The proxy this host's outbound HTTPS goes through: the configuration document's
    /// `network.proxy_url` as this daemon read it when it started, or `None` when it named none.
    ///
    /// It is the reading the network endpoint was built from, so the endpoint, the rendezvous,
    /// delivery and the plugin catalogue never go through two different proxies, and an edit
    /// applies to all of them at the next start.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] naming `network.proxy_url` when the address it
    /// holds is not one this host can use as a proxy.
    pub fn started_proxy(&self) -> Result<Option<kr_transport::config::ProxyUrl>> {
        Self::proxy_of(&self.started)
    }

    /// The proxy `started` selects, read as the network endpoint reads it.
    fn proxy_of(
        started: &crate::config::Started,
    ) -> Result<Option<kr_transport::config::ProxyUrl>> {
        started
            .network
            .proxy_url()
            .map(|value| {
                value
                    .parse()
                    .map_err(|error: kr_transport::config::ProxyUrlError| {
                        ControllerError::InvalidArgument(format!(
                            "network.proxy_url in this host's configuration document ({}) is not \
                             usable: {error}",
                            kr_protocol::hostinfo::configuration::FILE_NAME
                        ))
                    })
            })
            .transpose()
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

    /// Serves the client endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when accepting fails.
    pub async fn serve_clients(self: Arc<Self>, listener: Listener) -> Result<()> {
        loop {
            let (connection, peer) = listener.accept().await?;
            let controller = Arc::clone(&self);
            tokio::spawn(async move {
                let _ = controller
                    .client(connection, peer, StreamKind::Control)
                    .await;
            });
        }
    }

    fn acknowledgement(
        &self,
        role: LocalRole,
        action_window: ActionWindow,
        peer: &PeerIdentity,
    ) -> Box<LocalHelloAck> {
        Box::new(LocalHelloAck {
            selected_version: PROTOCOL_VERSION,
            role,
            connection_id: action_window.connection_id,
            environment_id: self.paths.environment_id(),
            boot_identity: self.boot_identity.clone(),
            peer: LocalPeer {
                uid: U64::new(u64::from(peer.uid)),
                gid: U64::new(u64::from(peer.gid)),
                pid: Nullable(peer.pid.map(|pid| U64::new(u64::from(pid)))),
            },
            action_window,
            capabilities: CanonicalSet::new(),
            max_receive: ReceiveLimits::default(),
            build: Some(kr_protocol::local::LocalBuild::this(self.build_id.clone())),
        })
    }

    /// Issues an action window for one authenticated connection.
    ///
    /// # Errors
    ///
    /// Returns an error when the random generator is unavailable.
    fn issue_window(&self, connection_id: ConnectionId) -> Result<ActionWindow> {
        self.windows
            .issue(connection_id, self.boot_epoch)
            .map_err(|error| ControllerError::supervision(error.to_string()))
    }

    /// Checks the envelope of a mutation this daemon is asked to perform.
    ///
    /// The target says which environment the effect belongs to, and the window says whether this
    /// is a first admission the host will accept at all. Both are checked before the create token
    /// reaches the registry, so an expired window never reserves a session.
    fn check_envelope(
        &self,
        connection_id: ConnectionId,
        mutation: &MutationRequest,
        method: Method,
        received_at: kr_transport::clock::ContinuousInstant,
    ) -> Result<AcceptedDeadline> {
        use kr_protocol::authority::AuthorityDecision;

        // The registry decides first: an unlisted name, a version this build does not implement
        // and an ingress that may not reach the method are all refused before a parameter is read.
        let entry = match kr_protocol::method::decide(
            mutation.method.as_str(),
            mutation.method_version,
            kr_protocol::actor::ActorIngress::LocalIpc,
        ) {
            AuthorityDecision::Listed(entry) => entry,
            AuthorityDecision::Denied(reason) => {
                return Err(match reason.error_code() {
                    ErrorCode::UnsupportedSchema => ControllerError::InvalidArgument(format!(
                        "{} is not implemented at version {}",
                        mutation.method.as_str(),
                        mutation.method_version
                    )),
                    _ => ControllerError::NotListed {
                        method: mutation.method.as_str().to_owned(),
                    },
                });
            }
        };
        mutation
            .target
            .validate()
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        if mutation.target.environment_id != self.paths.environment_id() {
            return Err(ControllerError::InvalidArgument(format!(
                "this daemon owns environment {}",
                self.paths.environment_id()
            )));
        }
        // The target and the parameters have to name the same subject. A close that pointed at
        // one session and carried another in its parameters would close the one nobody addressed.
        // Creation is where the selector table and the envelope differ for a good reason:
        // `session.create` selects a session because it allocates one, and no request can name a
        // session that does not exist yet, so its subject is the environment.
        match method {
            Method::SessionClose => {
                let named = mutation
                    .target
                    .session_id
                    .as_ref()
                    .copied()
                    .ok_or_else(|| {
                        ControllerError::InvalidArgument(format!(
                            "{} names the session it acts on",
                            entry.name
                        ))
                    })?;
                let params: SessionCloseParams = parse(&mutation.params)?;
                if params.session_id != named {
                    return Err(ControllerError::InvalidArgument(
                        "the request's target and its parameters name different sessions"
                            .to_owned(),
                    ));
                }
            }
            Method::SessionCreate => {
                if mutation.target.session_id.as_ref().is_some() {
                    return Err(ControllerError::InvalidArgument(
                        "a create allocates the session it is for, so it names none".to_owned(),
                    ));
                }
                let params: SessionCreateParams = parse(&mutation.params)?;
                if params.environment_id != mutation.target.environment_id {
                    return Err(ControllerError::InvalidArgument(
                        "the request's target and its parameters name different environments"
                            .to_owned(),
                    ));
                }
            }
            // A skill installation is the host's, not a session's, so its target names the
            // environment and nothing else. A request that named a session here would be asking
            // for an installation scoped to something installations do not have.
            Method::AgentToolsInstall | Method::AgentToolsRemove => {
                if mutation.target.session_id.as_ref().is_some() {
                    return Err(ControllerError::InvalidArgument(
                        "an installation belongs to this host, not to a session".to_owned(),
                    ));
                }
                let _: kr_protocol::skill::AgentToolsParams = parse(&mutation.params)?;
            }
            // Sharing acts on a session, and the session it acts on is the one its target names.
            Method::GrantCreate => {
                let named = mutation
                    .target
                    .session_id
                    .as_ref()
                    .copied()
                    .ok_or_else(|| {
                        ControllerError::InvalidArgument(format!(
                            "{} names the session it shares",
                            entry.name
                        ))
                    })?;
                let params: kr_protocol::sharing::GrantCreateParams = parse(&mutation.params)?;
                if params.session_id != named {
                    return Err(ControllerError::InvalidArgument(
                        "the request's target and its parameters name different sessions"
                            .to_owned(),
                    ));
                }
            }
            // A revocation acts on a grant or a device, both of which belong to this host rather
            // than to one session: a grant can cover several sessions, and a device holds several
            // grants. A request that named a session here would be asking for a revocation scoped
            // to something revocations do not have.
            Method::GrantRevoke => {
                if mutation.target.session_id.as_ref().is_some() {
                    return Err(ControllerError::InvalidArgument(
                        "a grant belongs to this host, not to one session".to_owned(),
                    ));
                }
                let _: kr_protocol::sharing::GrantRevokeParams = parse(&mutation.params)?;
            }
            Method::DeviceRevoke => {
                if mutation.target.session_id.as_ref().is_some() {
                    return Err(ControllerError::InvalidArgument(
                        "a device belongs to this host, not to one session".to_owned(),
                    ));
                }
                let _: kr_protocol::sharing::DeviceRevokeParams = parse(&mutation.params)?;
            }
            // An enrolment, a removal and a refresh all act on this host's own record of the
            // environments it reaches, not on a session. A request that named a session here
            // would be asking for a record scoped to something the record does not have.
            Method::EnvironmentEnrol | Method::EnvironmentForget | Method::EnvironmentRefresh => {
                if mutation.target.session_id.as_ref().is_some() {
                    return Err(ControllerError::InvalidArgument(
                        "an enrolled environment belongs to this host, not to one session"
                            .to_owned(),
                    ));
                }
            }
            Method::DevicePreviewKeyUpdate => {
                if mutation.target.session_id.as_ref().is_some() {
                    return Err(ControllerError::InvalidArgument(
                        "a device belongs to this host, not to one session".to_owned(),
                    ));
                }
                let _: kr_protocol::sharing::DevicePreviewKeyUpdateParams =
                    parse(&mutation.params)?;
            }
            // A notification destination belongs to this environment, not to a session. The
            // credential is checked here, before the action is claimed, so a credential of the
            // wrong shape is refused without holding its action identifier.
            Method::DeliveryDestinationSecretSet => {
                if mutation.target.session_id.as_ref().is_some()
                    || mutation.target.application_instance_id.is_present()
                {
                    return Err(ControllerError::InvalidArgument(
                        "a notification destination belongs to this environment, not to one \
                         session"
                            .to_owned(),
                    ));
                }
                let params = secret_params(&mutation.params)?;
                destination_identifier(&params.destination_id)?;
                crate::push::external::check_secret(&params.secret)
                    .map_err(ControllerError::InvalidArgument)?;
            }
            _ if crate::voice::VoiceModule::serves(method) => {
                crate::voice::VoiceModule::check_subject(method, mutation)?;
            }
            _ if crate::transfer::TransferModule::serves(method) => {
                crate::transfer::TransferModule::check_subject(method, mutation)?;
            }
            _ if crate::project::ProjectModule::serves(method) => {
                crate::project::ProjectModule::check_subject(method, mutation)?;
            }
            _ if crate::catalogue::CatalogueModule::serves(method) => {
                crate::catalogue::CatalogueModule::check_subject(method, mutation)?;
            }
            _ if crate::changeset::ChangeSetModule::serves(method) => {
                crate::changeset::ChangeSetModule::check_subject(method, mutation)?;
            }
            _ if crate::automation::AutomationModule::serves(method) => {
                crate::automation::AutomationModule::check_subject(method, mutation)?;
            }
            _ if crate::attention::AttentionModule::serves(method) => {
                crate::attention::AttentionModule::check_subject(method, mutation)?;
            }
            // Pairing and owner confirmation act on this host rather than on a session, so the
            // target names this environment and no session inside it.
            _ if net::methods::serves(method) => {
                if mutation.target.session_id.is_present() {
                    return Err(ControllerError::InvalidArgument(format!(
                        "{} acts on this host and names no session",
                        entry.name
                    )));
                }
            }
            _ => {
                return Err(ControllerError::InvalidArgument(format!(
                    "{} is not a mutation this daemon serves",
                    entry.name
                )));
            }
        }
        // A local caller's authority is the operating-system caller the listener authenticated.
        if mutation.grant_id.as_ref().is_some() {
            return Err(ControllerError::InvalidArgument(
                "a local caller acts under its authenticated operating-system identity, not a \
                 grant"
                    .to_owned(),
            ));
        }
        // The requested lifetime is the caller's request, not its decision. A lifetime beyond the
        // protocol maximum is a malformed envelope rather than a longer deadline.
        if mutation.requested_ttl_ms.get() > kr_protocol::limits::MAX_MUTATION_TTL.get() {
            return Err(ControllerError::InvalidArgument(format!(
                "a mutation lifetime is at most {} milliseconds",
                kr_protocol::limits::MAX_MUTATION_TTL.get()
            )));
        }
        // Preconditions belong to the subject, and the subject of a session mutation is the
        // worker. They are forwarded there unchanged; what this daemon checks is that the field is
        // a map at all, so a malformed envelope is refused before a reservation is written.
        if !matches!(
            mutation.expected.as_value(),
            kr_cbor::CanonicalValue::Map(_)
        ) {
            return Err(ControllerError::InvalidArgument(
                "the subject preconditions are a map of the facts the caller depends on".to_owned(),
            ));
        }
        // The accepted deadline is the earliest of what the window has left, receipt time plus the
        // requested lifetime, and any applicable authority deadline. The caller never supplies an
        // authoritative deadline, and nothing downstream lengthens this one.
        self.windows
            .accept_at(
                &mutation.action_window_id,
                connection_id,
                self.boot_epoch,
                received_at,
                mutation.requested_ttl_ms,
                None,
            )
            .map_err(|refusal| ControllerError::WindowExpired {
                detail: window_refusal_detail(refusal).to_owned(),
            })
    }

    pub(crate) async fn client(
        self: &Arc<Self>,
        connection: Connection,
        peer: PeerIdentity,
        kind: StreamKind,
    ) -> Result<()> {
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        let (mut reader, mut writer) = split(connection, kind);
        let outcome = self
            .serve_client(&mut reader, &mut writer, connection_id, &peer, kind)
            .await;
        // A connection that ends takes its windows and its registration with it. A window that
        // outlived its connection could first-admit a request through a connection that no longer
        // exists, and a registration that outlived it would be an authority nothing can revoke.
        self.windows.retire_connection(connection_id);
        self.deregister(connection_id);
        outcome
    }

    async fn serve_client(
        self: &Arc<Self>,
        reader: &mut kr_ipc::framed::FrameReader,
        writer: &mut kr_ipc::framed::FrameWriter,
        connection_id: ConnectionId,
        peer: &PeerIdentity,
        kind: StreamKind,
    ) -> Result<()> {
        let actor_id = ActorId::new(format!("{LOCAL_PRINCIPAL_PREFIX}{}", peer.uid))
            .unwrap_or_else(|_| ActorId::new("local").expect("a valid principal"));
        let mut negotiated = false;
        // Both timers fire once immediately; that first tick is consumed here so a connection is
        // not handed a replacement window before it has read the first one.
        let mut renewal = tokio::time::interval(WINDOW_RENEWAL);
        renewal.tick().await;
        let mut keepalive = tokio::time::interval(LOCAL_KEEPALIVE);
        keepalive.tick().await;
        loop {
            let frame = tokio::select! {
                frame = reader.read_message::<ControlFrame>() => match frame {
                    Ok(frame) => frame,
                    Err(_) => break,
                },
                // The window is replaced without being asked for, at half its validity. A client
                // never has to renew before a mutation, and never holds a window that expired
                // while its renewal was in flight.
                _ = renewal.tick(), if negotiated => {
                    let Ok(window) = self.issue_window(connection_id) else {
                        break;
                    };
                    let renewed = ControlFrame::Event(ControlEvent::ActionWindowRenewed(window));
                    if writer.write_message(&renewed).await.is_err() {
                        break;
                    }
                    continue;
                }
                _ = keepalive.tick(), if negotiated => {
                    let beat = ControlFrame::Event(ControlEvent::Keepalive);
                    if writer.write_message(&beat).await.is_err() {
                        break;
                    }
                    continue;
                }
            };
            let reply = match frame {
                ControlFrame::Hello(hello) => {
                    // A peer that says it can hold no outstanding mutation at all is refused
                    // rather than quietly read as one. The worker's endpoint refuses the same
                    // offer, and a limit this host would then ignore is worse than a refusal.
                    if hello.max_receive.max_outstanding_mutations.get() == 0 {
                        let refusal = error_reply(
                            RequestId::new(0),
                            ErrorCode::InvalidArgument,
                            "a connection holds at least one outstanding mutation; offering none \
                             is not a limit this host serves",
                        );
                        let _ = writer.write_message(&refusal).await;
                        break;
                    }
                    if hello
                        .offered_versions
                        .iter()
                        .any(|offered| offered.major == PROTOCOL_VERSION.major)
                    {
                        // Validating the caller's record and registering the connection in the
                        // authority store happen together, under the store's own lock, so a
                        // revocation cannot land between the two and leave a connection admitted
                        // under authority that has already been withdrawn.
                        match self.admit_connection(connection_id, &actor_id, peer).await {
                            Ok(()) => {}
                            Err(error) => {
                                let refusal = error_reply(
                                    RequestId::new(0),
                                    ErrorCode::PermissionDenied,
                                    error.to_string(),
                                );
                                let _ = writer.write_message(&refusal).await;
                                break;
                            }
                        }
                        negotiated = true;
                        let Ok(window) = self.issue_window(connection_id) else {
                            break;
                        };
                        ControlFrame::HelloAck(self.acknowledgement(
                            LocalRole::Controller,
                            window,
                            peer,
                        ))
                    } else {
                        error_reply(
                            RequestId::new(0),
                            ErrorCode::UnsupportedSchema,
                            format!("this host speaks protocol {PROTOCOL_VERSION}"),
                        )
                    }
                }
                ControlFrame::Request(request)
                    if negotiated && !crate::transfer::carries(kind, request.method.method()) =>
                {
                    error_reply(
                        request.request_id,
                        ErrorCode::PermissionDenied,
                        crate::transfer::WRONG_ENDPOINT,
                    )
                }
                ControlFrame::Mutation(mutation)
                    if negotiated && !crate::transfer::carries(kind, mutation.method.method()) =>
                {
                    error_reply(
                        mutation.request_id,
                        ErrorCode::PermissionDenied,
                        crate::transfer::WRONG_ENDPOINT,
                    )
                }
                ControlFrame::Request(request)
                    if negotiated
                        && request
                            .method
                            .method()
                            .is_some_and(crate::attention::AttentionModule::serves) =>
                {
                    // The attention store's reads carry session text, which leaves this daemon only
                    // under the text's privacy fence: its ticket is checked before every write.
                    match self.authorised(connection_id) {
                        Ok(_) => {
                            let released = self
                                .attention
                                .read_released(
                                    self.attention_reach().as_ref(),
                                    &crate::attention::Caller::Owner,
                                    &actor_id,
                                    &request,
                                )
                                .await;
                            match self.authorised(connection_id) {
                                Ok(_) => {
                                    if self
                                        .attention
                                        .write_released(writer, kind, released)
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                    continue;
                                }
                                Err(error) => error_reply(
                                    request.request_id,
                                    ErrorCode::PermissionDenied,
                                    error.to_string(),
                                ),
                            }
                        }
                        Err(error) => error_reply(
                            request.request_id,
                            ErrorCode::PermissionDenied,
                            error.to_string(),
                        ),
                    }
                }
                ControlFrame::Request(request) if negotiated => {
                    match self.authorised(connection_id) {
                        Ok(_) => {
                            let answer = self.read_method(&actor_id, &request).await;
                            // Checked again now the read has finished. A read that passed its check
                            // and then waited for the registry can complete after the authority
                            // behind it was withdrawn, and what the contract forbids is *serving*
                            // that state rather than reading it.
                            match self.authorised(connection_id) {
                                Ok(_) => answer,
                                Err(error) => error_reply(
                                    request.request_id,
                                    ErrorCode::PermissionDenied,
                                    error.to_string(),
                                ),
                            }
                        }
                        Err(error) => error_reply(
                            request.request_id,
                            ErrorCode::PermissionDenied,
                            error.to_string(),
                        ),
                    }
                }
                ControlFrame::Mutation(mutation) if negotiated => {
                    let confirm = mutation.action_id;
                    let reply = self.perform(&actor_id, connection_id, *mutation).await;
                    // The acceptance reaches the caller here. A worker that is holding a close for
                    // this action learns that it has, and only then starts signalling.
                    if writer.write_message(&reply).await.is_err() {
                        break;
                    }
                    self.confirm_delivery(confirm).await;
                    continue;
                }
                _ => error_reply(
                    RequestId::new(0),
                    ErrorCode::UnsupportedSchema,
                    "a local connection negotiates its version before anything else",
                ),
            };
            if writer.write_message(&reply).await.is_err() {
                break;
            }
        }
        Ok(())
    }

    /// Admits one mutation and performs it on an owner that outlives this connection.
    ///
    /// A connection task is dropped the moment its control stream ends, and dropping a future is a
    /// cancellation: destructors run, but nothing after an outstanding `await` finishes. A durable
    /// commit cannot be left half done by a peer going away, so the effect runs in its own task.
    /// Dropping the handle this awaits does not stop that task; it only stops this connection
    /// hearing the answer.
    async fn perform(
        self: &Arc<Self>,
        actor_id: &ActorId,
        connection_id: ConnectionId,
        mutation: MutationRequest,
    ) -> ControlFrame {
        // Receipt time, recorded before anything this daemon then waits for. Section 9 measures a
        // requested lifetime from when the request arrived, and the retained lookup below takes
        // the registry lock: sampling the clock after it would hand the request its whole lifetime
        // back after the wait.
        let received_at = self.clock.now();
        if let Err(error) = self.authorised(connection_id) {
            return error_reply(
                mutation.request_id,
                ErrorCode::PermissionDenied,
                error.to_string(),
            );
        }
        let Some(method) = mutation.method.method() else {
            return error_reply(
                mutation.request_id,
                ErrorCode::PermissionDenied,
                "the method is not in the registry",
            );
        };
        // A retained action is answered before anything about a first admission is considered.
        // Section 9 makes the freshness window the thing that admits a *new* action; applying it to
        // a retry would refuse a caller its own completed result because its window has since been
        // replaced, and replacing the window of an action already submitted is not allowed either.
        //
        // Every store that retains an action here is asked in turn, and whichever answers, the
        // answer passes through the same guard. Finding a retained action takes a lock and can
        // wait for a blocking thread; what the contract forbids is *disclosing* a retained result
        // under authority that has since been withdrawn, so the check belongs where the answer is
        // about to be written rather than only where the lookup began.
        // The authority revision this mutation is admitted under, read here: beside the
        // registration check above and before the first thing this daemon waits for. The network
        // ingress reads its own in the same critical section as that check, and the two doors have
        // to agree. A revocation of somebody else's device advances the revision and leaves every
        // surviving registration stamped with the new one, so a door that read the revision after
        // a retained lookup, a lock or a task being scheduled would admit a mutation under an
        // authority the other door refuses the same mutation under. The project and change-set
        // paths use it; every other effect still reads it where its own transaction does.
        let admitted = self.admitted_revision(connection_id).ok();
        let mut retained = self
            .retained(actor_id, &mutation, method, connection_id)
            .await;
        if retained.is_none() && crate::transfer::TransferModule::serves(method) {
            retained = self.transfer.retained(actor_id, &mutation, method).await;
        }
        if retained.is_none() && crate::project::ProjectModule::serves(method) {
            retained = self.project.retained(actor_id, &mutation, method).await;
        }
        if retained.is_none() && crate::catalogue::CatalogueModule::serves(method) {
            retained = self.catalogue.retained(actor_id, &mutation, method).await;
        }
        if retained.is_none() && crate::changeset::ChangeSetModule::serves(method) {
            retained = self.changesets.retained(actor_id, &mutation, method).await;
        }
        if retained.is_none() && crate::automation::AutomationModule::serves(method) {
            retained = self.automation.retained(actor_id, &mutation, method).await;
        }
        if retained.is_none() && crate::attention::AttentionModule::serves(method) {
            retained = self.attention.retained(actor_id, &mutation, method);
        }
        if retained.is_none() && net::methods::serves(method) {
            retained = self
                .pairing_retained(
                    net::owner::Caller::local(actor_id.clone()),
                    method,
                    &mutation,
                )
                .await
                .map(|outcome| respond(mutation.request_id, outcome));
        }
        if let Some(retained) = retained {
            if let Err(error) = self.authorised(connection_id) {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    error.to_string(),
                );
            }
            return retained;
        }
        let accepted = match self.check_envelope(connection_id, &mutation, method, received_at) {
            Ok(accepted) => Some(accepted),
            // A window that admits nothing says nothing about an action the host may already
            // hold. Section 9 keeps a receipt readable after the freshness that admitted it is
            // gone, and for a mutation this daemon forwards, the worker that owns the session is
            // the only thing that knows whether it holds one. So the mutation goes on with no
            // freshness at all: a retry finds its receipt there, and a first admission is refused
            // there for the same reason it would have been refused here.
            Err(ControllerError::WindowExpired { .. }) if forwarded_to_worker(method) => None,
            Err(error) => {
                return ControlFrame::Response(Response {
                    request_id: mutation.request_id,
                    outcome: Outcome::Error(error.to_protocol_error()),
                });
            }
        };
        let request_id = mutation.request_id;
        let controller = Arc::clone(self);
        let actor_id = actor_id.clone();
        let effect = tokio::spawn(async move {
            controller
                .write_method(
                    &actor_id,
                    &mutation,
                    method,
                    connection_id,
                    accepted,
                    admitted,
                )
                .await
        });
        effect.await.unwrap_or_else(|_| {
            error_reply(
                request_id,
                ErrorCode::OutcomeUnknown,
                "the daemon could not report what happened to this action",
            )
        })
    }

    /// Returns the answer a retained installation action is owed.
    ///
    /// It runs before first-admission freshness, like every other retained action: a caller that
    /// reconnects and asks again about work it already submitted must get its own result rather
    /// than a refusal about a window that has since been replaced.
    async fn retained_installation(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        connection_id: ConnectionId,
    ) -> Option<ControlFrame> {
        let installer = self.installer().ok()?;
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id).ok()?;
        let _admission = self.agent_tools.lock().await;
        // Waiting for that lock takes time, and a retained result is a read of somebody's action.
        // Section 9 checks current authority before returning one, so it is checked after the wait
        // rather than before it.
        if let Err(error) = self.authorised(connection_id) {
            return Some(respond(mutation.request_id, Err(error)));
        }
        match installer.retained(actor_id, mutation.action_id, &digest) {
            Ok(Some(result)) => Some(ControlFrame::Response(Response {
                request_id: mutation.request_id,
                outcome: Outcome::Ok(result),
            })),
            Ok(None) => None,
            Err(error) => Some(respond(mutation.request_id, Err(error))),
        }
    }

    /// Performs one project or workspace mutation under the admission its ingress recorded.
    ///
    /// Both doors reach the project service through here, so the checks the daemon owes such a
    /// mutation are made once rather than once per ingress: a local caller and a paired device get
    /// the same answer to the same request, and neither can drift away from the other.
    ///
    /// Everything between the envelope check and this point can wait: for this task to be
    /// scheduled and for the registry's lock. The admission is asked about here, with the registry
    /// lock held across the answer for the reason [`Self::check_admission`] states, and it travels
    /// into the service through [`Self::check_registration`], which the service asks twice more:
    /// immediately before it acts, and inside the transaction that begins the effect, so its own
    /// preparation is covered as well.
    ///
    /// `grant` is the grant a paired device holds, set by the network door, or none for a caller on
    /// this machine's own socket. It is how the service tells the two apart.
    ///
    /// # Errors
    ///
    /// Returns the refusal the admission or the project service decided.
    pub(crate) async fn project_mutation(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        carried: crate::authority::AdmittedMutation,
        grant: Option<GrantId>,
    ) -> std::result::Result<ParamsValue, ProtocolError> {
        // A mutation carrying no freshness at all is a retry of an action this host may already
        // hold: section 9 keeps its record readable after the window that admitted it is gone, and
        // the project service's own retained record is where such a retry is answered from above.
        // What it may not do is perform the action again.
        if carried.deadline.is_none() {
            return Err(ControllerError::WindowExpired {
                detail: "this action carries no freshness, so it may be answered from what this \
                         host holds and may not be performed"
                    .to_owned(),
            }
            .to_protocol_error());
        }
        {
            let registry = self.registry.lock().await;
            self.check_admission(&registry, &carried)
                .map_err(|error| error.to_protocol_error())?;
        }
        // And again inside the service's own work. Between the answer above and the effect there
        // is a blocking task to be scheduled and a retained record to be looked for, and a clone
        // or a materialisation takes long enough that a grant can run out or a revocation can
        // complete inside one. The service asks this immediately after it has failed to find a
        // retained record and immediately before it performs the action, so a retry still gets its
        // own result while a first admission does not begin under authority that has gone, nor
        // while a fence this host owes stops dispatch.
        //
        // And once more inside the transaction that begins the effect: the one that writes the
        // operation row, the one that writes the workspace row and the one that reserves a
        // removal. Resolving a destination, opening and surveying a repository and taking the
        // journal's lock all happen before it, so a revocation or an expiry that completes during
        // that preparation, or a fence this host fails to raise in it, reaches an action that then
        // does not begin. That is section 9's revalidation immediately before the effect.
        let admission = self.admission_in_service(carried);
        self.project
            .write(actor_id, mutation, method, admission, grant)
            .await
    }

    /// Performs one automation mutation under the admission its ingress recorded.
    ///
    /// The admission is asked here, under the registry lock, for the reason
    /// [`Self::check_admission`] states, and then carried into the workflow journal, which asks it
    /// again inside the transaction that performs the action, immediately before the action's
    /// first write ([`Self::admission_in_service`]: a fence this host owes, the registration, the
    /// deadline). Nothing the service does before that write can wait long enough to outlast
    /// it: the answer and the write are under the journal's one lock, and the journal holds no
    /// record of an action it has not written. A retry is answered from its record before the
    /// admission is asked, so a caller whose window has since been replaced still gets its own
    /// result.
    ///
    /// # Errors
    ///
    /// Returns the refusal the admission or the automation service decided.
    pub(crate) async fn automation_mutation(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        carried: crate::authority::AdmittedMutation,
        caller_grant: Option<kr_protocol::ids::GrantId>,
    ) -> std::result::Result<ParamsValue, ProtocolError> {
        // A mutation carrying no freshness at all is a retry of an action this host may already
        // hold, and the journal's record is where such a retry is answered from. What it may not
        // do is perform the action.
        if carried.deadline.is_none() {
            return Err(ControllerError::WindowExpired {
                detail: "this action carries no freshness, so it may be answered from what this \
                         host holds and may not be performed"
                    .to_owned(),
            }
            .to_protocol_error());
        }
        {
            let registry = self.registry.lock().await;
            self.check_admission(&registry, &carried)
                .map_err(|error| error.to_protocol_error())?;
        }
        let admission: crate::automation::Admission = Arc::new(self.admission_in_service(carried));
        self.automation
            .write(actor_id, mutation, method, admission, caller_grant)
            .await
    }

    async fn read_method(self: &Arc<Self>, actor_id: &ActorId, request: &Request) -> ControlFrame {
        let Some(method) = request.method.method() else {
            return error_reply(
                request.request_id,
                ErrorCode::PermissionDenied,
                "the method is not in the registry",
            );
        };
        if crate::transfer::TransferModule::serves(method) {
            return self.transfer.read_frame(actor_id, request).await;
        }
        if crate::project::ProjectModule::serves(method) {
            return self.project.read_frame(request).await;
        }
        if crate::voice::VoiceModule::serves(method) {
            // Voice is reachable from a paired device and nothing else, which is the registry's
            // own entry rather than a rule restated here. An actor that resolves to no live device
            // reaches none of it.
            let Some(device_id) = self.paired_device(actor_id) else {
                return error_reply(
                    request.request_id,
                    ErrorCode::PermissionDenied,
                    "voice is reachable from a paired device",
                );
            };
            return self
                .voice()
                .read_frame(device_id, request, wall_clock_ms())
                .await;
        }
        if crate::catalogue::CatalogueModule::serves(method) {
            return self
                .catalogue_read_frame(kr_protocol::actor::ActorIngress::LocalIpc, request)
                .await;
        }
        if crate::changeset::ChangeSetModule::serves(method) {
            return self.changesets.read_frame(request).await;
        }
        if crate::automation::AutomationModule::serves(method) {
            return self.automation.read_frame(request, None).await;
        }
        if net::methods::serves(method) {
            let caller = net::owner::Caller::local(actor_id.clone());
            let outcome = self.pairing_read(caller, method, &request.params).await;
            return respond(request.request_id, outcome);
        }
        // The diagnostics are two answers, not one. The owner at their own machine is shown the
        // paths this host resolved and the names they chose, because that is a person asking their
        // own host where its files are; everything else that reaches a read arrived over the
        // network, and what leaves for somebody else to read carries each value on its class's
        // terms. The two are separated here rather than inside each answer, so a diagnostic added
        // later cannot forget which one it is.
        let owner = is_owners_own_socket(actor_id);
        let outcome = match method {
            Method::HostInfo => self
                .host_info()
                .await
                .and_then(|answer| host_read(answer, owner)),
            Method::EnvironmentCapabilities => self
                .environment_capabilities(&request.params)
                .await
                .and_then(|answer| host_read(answer, owner)),
            Method::EnvironmentList => self
                .environment_list()
                .await
                .and_then(|answer| host_read(answer, owner)),
            Method::EnvironmentInventory => self.environment_inventory(&request.params).await,
            Method::HostDoctor => self
                .host_doctor()
                .await
                .and_then(|answer| host_read(answer, owner)),
            Method::SessionList => self.session_list(&request.params).await,
            Method::SessionRead => self.session_read(&request.params).await,
            // A closed or crashed session's history and receipts are the archive's, and it serves
            // them with no worker. A live session's are its worker's, and this daemon says which
            // endpoint to ask rather than reading another process's journal behind its back.
            Method::HistoryPage => self.archive_history_page(&request.params).await,
            Method::ActionRead => {
                // A receipt of an action this host performed itself names no session and is kept
                // by the service that performed it. The catalogue's are answered from there, for
                // the actor that submitted the action; every other receipt is the archive's.
                if let Some(answer) = self.host_action_read(actor_id, request).await {
                    return answer;
                }
                self.archive_action_read(actor_id, &request.params).await
            }
            Method::AgentToolsStatus => self.agent_tools_status(&request.params),
            Method::GrantList => self.grant_list(self.host_device_id(), &request.params),
            Method::DeviceList => self.device_list(&request.params).await,
            _ => Err(ControllerError::InvalidArgument(format!(
                "{} is not a read this daemon serves",
                method.as_str()
            ))),
        };
        respond(request.request_id, outcome)
    }

    async fn write_method(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        connection_id: ConnectionId,
        accepted: Option<AcceptedDeadline>,
        admitted: Option<AuthorityRevision>,
    ) -> ControlFrame {
        if net::methods::serves(method) {
            // Pairing and owner confirmation are the network module's, and a local caller reaches
            // them as the host's own account: the issuing owner of what it invites.
            let caller = net::owner::Caller::local(actor_id.clone());
            let admission = self.pairing_admission(
                connection_id,
                admitted,
                accepted.map(|accepted| accepted.deadline),
            );
            let outcome = self
                .pairing_write(caller, method, mutation, admission)
                .await;
            return respond(mutation.request_id, outcome);
        }
        if crate::transfer::TransferModule::serves(method) {
            // The stored subject is read first, because reading it waits: for a blocking thread
            // and for the journal's lock. The admission is asked after it, inside the service's
            // own work, so that answer is the last thing between this mutation and its effect
            // rather than one more thing with waits after it.
            if let Err(error) = self
                .transfer
                .check_subject_of_record(actor_id, mutation, method)
                .await
            {
                return ControlFrame::Response(Response {
                    request_id: mutation.request_id,
                    outcome: Outcome::Error(error),
                });
            }
            // A mutation carrying no freshness at all is refused here. This service answers its
            // own retained actions before this point, so anything still travelling is a first
            // admission, and a first admission needs a deadline it was admitted under.
            let Some(accepted) = accepted else {
                return respond(
                    mutation.request_id,
                    Err(ControllerError::WindowExpired {
                        detail: "this action carries no freshness, so it may be answered from \
                                 what this host holds and may not write"
                            .to_owned(),
                    }),
                );
            };
            let Some(admitted_revision) = admitted else {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    "the authority this connection was admitted under has been withdrawn; open a \
                     new connection",
                );
            };
            // The admission travels into the service's blocking work and is asked there, once no
            // retained record has answered and immediately before the action: this task, a
            // blocking thread and the journal are all waited for before it. It is the check every
            // service asks from inside its work, so a fence this host owes, a registration it has
            // withdrawn or replaced, and a deadline that has passed each stop the action.
            let carried = crate::authority::AdmittedMutation {
                connection_id,
                admitted_revision,
                deadline: Some(accepted.deadline),
            };
            return self
                .transfer
                .write_frame(
                    actor_id,
                    mutation,
                    method,
                    self.admission_in_service(carried),
                )
                .await;
        }
        if crate::voice::VoiceModule::serves(method) {
            // Section 23 gives `voice.grant` both ingresses: a paired device changes its own voice
            // grant, and the person at this machine changes a device's. The other four are a
            // paired device's alone, which the registry refuses before this, and an actor on this
            // socket that resolves to no device reaches none of them.
            let actor = match self.paired_device(actor_id) {
                Some(device_id) => crate::voice::VoiceActor::Device(device_id),
                None if method == Method::VoiceGrant => crate::voice::VoiceActor::Owner,
                None => {
                    return error_reply(
                        mutation.request_id,
                        ErrorCode::PermissionDenied,
                        "voice is reachable from a paired device",
                    );
                }
            };
            // Everything between the envelope check and here can wait: for this task to be
            // scheduled, for a blocking thread, for the coordinator's own lock. An action whose
            // accepted deadline passed while it queued does not go on to write. A retry of a
            // completed voice change is answered from its record before this, so anything still
            // travelling is a first admission, and a first admission needs a deadline.
            let Some(accepted) = accepted.filter(|accepted| self.clock.now() < accepted.deadline)
            else {
                return respond(
                    mutation.request_id,
                    Err(ControllerError::WindowExpired {
                        detail: "the deadline this action was admitted under passed before it \
                                 could run"
                            .to_owned(),
                    }),
                );
            };
            if let Err(error) = self.authorised(connection_id) {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    error.to_string(),
                );
            }
            let Some(admitted_revision) = admitted else {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    "the authority this connection was admitted under has been withdrawn; open a \
                     new connection",
                );
            };
            // The admission travels with the change, as it does with a project or an automation
            // mutation, and the voice service asks it again where it writes.
            let carried = crate::authority::AdmittedMutation {
                connection_id,
                admitted_revision,
                deadline: Some(accepted.deadline),
            };
            // The revision this daemon is at, read now: a voice grant is written under the
            // authority in force at the moment of the write rather than the one a connection was
            // admitted under.
            let authority_revision = self.policy.lock().map_or_else(
                |_| AuthorityRevision::new(0),
                |policy| policy.authority_revision(),
            );
            return respond(
                mutation.request_id,
                self.voice_mutation(
                    actor_id,
                    actor,
                    mutation,
                    method,
                    authority_revision,
                    carried,
                )
                .await,
            );
        }
        if crate::catalogue::CatalogueModule::serves(method) {
            let Some(admitted_revision) = admitted else {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    "the authority this connection was admitted under has been withdrawn; open a \
                     new connection",
                );
            };
            let carried = crate::authority::AdmittedMutation {
                connection_id,
                admitted_revision,
                deadline: accepted.map(|accepted| accepted.deadline),
            };
            // The admission travels into the catalogue and is asked again where the change
            // becomes durable, holding this daemon's connection table for that commit.
            let admission: Arc<dyn crate::catalogue::Admission> = Arc::new(
                crate::catalogue::DaemonAdmission::new(Arc::clone(self), carried),
            );
            // The owner's own ceremony, checked by this host's pairing service against its owner
            // devices. `None` is a host that is not on the network and so has no owner device, and
            // every method that needs the owner's confirmation (adopting a root, a grant, an
            // installation that widens what a package may do) is then refused rather than
            // performed under the identity of whoever asked.
            let pairing = self.network.get().map(|guard| Arc::clone(guard.pairing()));
            let confirmations = pairing
                .as_deref()
                .map(|host| host as &dyn crate::sharing::OwnerConfirmations);
            return crate::catalogue::frame(
                mutation.request_id,
                self.catalogue_write(actor_id, mutation, method, confirmations, admission)
                    .await,
            );
        }
        if crate::project::ProjectModule::serves(method) {
            let Some(admitted_revision) = admitted else {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    "the authority this connection was admitted under has been withdrawn; open a \
                     new connection",
                );
            };
            let carried = crate::authority::AdmittedMutation {
                connection_id,
                admitted_revision,
                deadline: accepted.map(|accepted| accepted.deadline),
            };
            return crate::project::frame(
                mutation.request_id,
                // The machine's own socket: the caller holds no grant.
                self.project_mutation(actor_id, mutation, method, carried, None)
                    .await,
            );
        }
        if crate::automation::AutomationModule::serves(method) {
            let Some(admitted_revision) = admitted else {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    "the authority this connection was admitted under has been withdrawn; open a \
                     new connection",
                );
            };
            let carried = crate::authority::AdmittedMutation {
                connection_id,
                admitted_revision,
                deadline: accepted.map(|accepted| accepted.deadline),
            };
            let answered = crate::automation::frame(
                mutation.request_id,
                self.automation_mutation(actor_id, mutation, method, carried, None)
                    .await,
            );
            // A run dispatches its nodes and waits for each of them, so the effect and its reply
            // are separated by however long that took, and a revocation can land in the interval.
            // What this host must not do is **disclose** an answer under authority that has since
            // been withdrawn, so the check is made again here, where the reply is about to go out.
            if let Err(error) = self.authorised(connection_id) {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    error.to_string(),
                );
            }
            return answered;
        }
        if crate::attention::AttentionModule::serves(method) {
            // The attention store's actions are the daemon's own, committed with their records
            // inside this daemon's guarded operation, so a revocation that begins while one is
            // committing finishes after it.
            if accepted.is_none_or(|accepted| self.clock.now() >= accepted.deadline) {
                return respond(
                    mutation.request_id,
                    Err(ControllerError::WindowExpired {
                        detail: "the deadline this action was admitted under passed before it \
                                 could run"
                            .to_owned(),
                    }),
                );
            }
            let Some(admitted_revision) = admitted else {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    "the authority this connection was admitted under has been withdrawn; open a \
                     new connection",
                );
            };
            let carried = crate::authority::AdmittedMutation {
                connection_id,
                admitted_revision,
                deadline: accepted.map(|accepted| accepted.deadline),
            };
            let answered = self
                .attention
                .write_frame(
                    self,
                    &crate::attention::Caller::Owner,
                    actor_id,
                    mutation,
                    method,
                    &carried,
                )
                .await;
            if let Err(error) = self.authorised(connection_id) {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    error.to_string(),
                );
            }
            return answered;
        }
        if crate::changeset::ChangeSetModule::serves(method) {
            // Everything between the envelope check and this point can wait: for this task to be
            // scheduled and for a blocking thread. An action whose accepted deadline passed while
            // it queued does not go on to write, and neither does one whose connection lost its
            // authority in the meantime.
            if accepted.is_none_or(|accepted| self.clock.now() >= accepted.deadline) {
                return respond(
                    mutation.request_id,
                    Err(ControllerError::WindowExpired {
                        detail: "the deadline this action was admitted under passed before it \
                                 could run"
                            .to_owned(),
                    }),
                );
            }
            if let Err(error) = self.authorised(connection_id) {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    error.to_string(),
                );
            }
            let Some(admitted_revision) = admitted else {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    "the authority this connection was admitted under has been withdrawn; open a \
                     new connection",
                );
            };
            // What the change-set service holds its effects under: the connection this mutation
            // arrived on, the authority revision it was admitted under, and the deadline this
            // daemon accepted. Between this point and the transaction that commits an effect lie
            // a blocking task, the journal's own lock and, for a capture, a whole working tree
            // being read, and authority can run out inside any of them. The service runs each of
            // those transactions inside this daemon's own guarded operation, so a revocation that
            // begins while one is committing finishes after it.
            let carried = crate::authority::AdmittedMutation {
                connection_id,
                admitted_revision,
                deadline: accepted.map(|accepted| accepted.deadline),
            };
            let controller = Arc::clone(self);
            let answered = self
                .changesets
                .write_frame(actor_id, mutation, method, carried, controller)
                .await;
            // The effect and its reply are separated by everything a blocking task waits for, and
            // a revocation can land in that interval. What this host must not do is **disclose**
            // an answer under authority that has since been withdrawn, so the check is made again
            // here, where the reply is about to go out.
            if let Err(error) = self.authorised(connection_id) {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    error.to_string(),
                );
            }
            return answered;
        }
        // The admission the mutation carries into its transaction: the deadline this daemon
        // accepted, the authority revision it was admitted under, and the connection it arrived
        // on. Every service re-checks all three inside its own transaction.
        let admitted_revision = match self.admitted_revision(connection_id) {
            Ok(revision) => revision,
            Err(error) => {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    error.to_string(),
                );
            }
        };
        let carried = crate::authority::AdmittedMutation {
            connection_id,
            admitted_revision,
            deadline: accepted.map(|accepted| accepted.deadline),
        };
        let outcome = match method {
            // A create needs freshness of its own. An admission that carries none is a retry of an
            // action this host may already hold: section 9 keeps its record readable after the
            // window that admitted it is gone, and the reservation above is where such a retry is
            // answered from. What it may not do is start a session.
            Method::SessionCreate => match accepted {
                Some(_) => self.session_create(actor_id, mutation, carried).await,
                None => Err(ControllerError::WindowExpired {
                    detail: "this action carries no freshness, so it may be answered from what \
                             this host holds and may not start a session"
                        .to_owned(),
                }),
            },
            Method::SessionClose => {
                let actor = local_actor(actor_id.clone(), connection_id, self.generation);
                let closed = self
                    .session_close(mutation, &actor, accepted, carried)
                    .await;
                // A closure the host has accepted and not finished is a request outstanding, and
                // the setting decides whether that keeps the machine awake while it finishes. The
                // caller's answer does not wait for that decision.
                self.review_power_soon();
                closed
            }
            // The revision `perform` read beside the registration check, before anything waited,
            // rather than the one read above. A revocation of another device stamps every
            // surviving registration with the revision it advanced to, so a change admitted before
            // it and checked against a revision read afterwards would be checked against the
            // authority that replaced the one it was admitted under.
            Method::AgentToolsInstall | Method::AgentToolsRemove => match admitted {
                Some(admitted_revision) => {
                    self.agent_tools_change(
                        actor_id,
                        mutation,
                        method,
                        crate::authority::AdmittedMutation {
                            admitted_revision,
                            ..carried
                        },
                    )
                    .await
                }
                None => Err(ControllerError::PermissionDenied {
                    detail: "the authority this connection was admitted under has been \
                             withdrawn; open a new connection"
                        .to_owned(),
                }),
            },
            Method::GrantCreate
            | Method::GrantRevoke
            | Method::DeviceRevoke
            | Method::DevicePreviewKeyUpdate
            | Method::DeliveryDestinationSecretSet => {
                self.authority_change(actor_id, mutation, method, carried)
                    .await
            }
            Method::EnvironmentEnrol | Method::EnvironmentForget | Method::EnvironmentRefresh => {
                // The envelope this host built for the connection, not anything the caller sent.
                // A refresh may open a bridge, and what may cross one is decided by this.
                let actor = local_actor(actor_id.clone(), connection_id, self.generation);
                self.environment_record(&actor, mutation, method).await
            }
            _ => Err(ControllerError::InvalidArgument(format!(
                "{} is not a mutation this daemon serves",
                method.as_str()
            ))),
        };
        respond(mutation.request_id, outcome)
    }

    /// Closes every session recorded in an earlier boot.
    ///
    /// A reboot ends the live executions of both profiles: a desktop-bound worker went with its
    /// login session and a headless one went with the machine. The record says the host restarted,
    /// which is what happened, rather than describing a worker that vanished.
    ///
    /// The boot this environment last ran in is kept in its own state directory, beside the
    /// registry, because that is the only place that survives what a reboot removes. A runtime
    /// directory does not: on most hosts it is cleared with the boot it belonged to, taking the
    /// published descriptors with it, so a daemon that compared descriptors would find nothing to
    /// compare after exactly the event it was looking for.
    async fn close_previous_boot(&self) -> Result<()> {
        let path = self.paths.state_dir().join(BOOT_FILE);
        let current = kr_cbor::to_canonical_vec(&self.boot_identity)
            .map_err(|error| ControllerError::registry(error.to_string()))?;
        let bytes = kr_ipc::paths::read_owner_only_file(&path, BOOT_FILE_LIMIT)?;
        // A host with no record has not run here before, so there is nothing of an earlier boot to
        // close. A record that is there and does not decode is a damaged file rather than a boot,
        // and closing live sessions on the strength of one would be closing them for no reason.
        // Either way the record is written again below.
        let recorded = bytes.as_deref().and_then(|bytes| {
            kr_cbor::from_canonical_slice::<kr_protocol::identity::BootIdentity>(
                bytes,
                &kr_cbor::Limits::DEFAULT,
            )
            .ok()
        });
        if recorded.is_some_and(|recorded| recorded != self.boot_identity) {
            let rows = {
                let registry = self.registry.lock().await;
                registry.workers()?
            };
            for row in rows {
                self.directory.lock().await.remove(row.session_id);
                // The worker went with the boot it was in: a boot that is not this one ended
                // every process in it, which is what the boot record establishes and what the
                // kernel may still decline to say about any one of them. So the closure is
                // recorded either way.
                //
                // The recovery pass is not. It opens the session's stores, so it runs only where
                // the kernel confirms the death, and where it does not the store is left exactly
                // as it is. Nothing reads it afterwards either: writing the closure removes the
                // worker row and retires the descriptor, so the closure carries the fact itself,
                // and a session whose closure names a worker this host never saw end is refused
                // every archive read rather than served an incomplete one.
                let archive = self.archive();
                let validated = if let Ok(ownership) = archive.take_ownership(
                    row.session_id,
                    row.display_number,
                    &row.process_identity,
                ) {
                    let _ = archive.recover_journal(&ownership);
                    true
                } else {
                    false
                };
                self.record_final(
                    row.session_id,
                    ClosureReason::HostShutdown,
                    &row.process_identity,
                    &crate::archive::ArchiveService::nothing_fenced(row.session_id),
                    validated,
                )
                .await?;
            }
        }
        if bytes.as_deref() != Some(current.as_slice()) {
            kr_ipc::paths::write_owner_only_file(&path, &current)?;
        }
        Ok(())
    }

    /// Removes the directories of workers this environment no longer runs.
    ///
    /// One directory per session, and the session is the only thing that can say whether it is
    /// still wanted. A launch that failed after its directory was made, a removal a platform
    /// refused while the worker was exiting, and a daemon that died between the two all leave one
    /// behind; this is where they go.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read.
    async fn sweep_worker_dirs(&self) -> Result<()> {
        let live = {
            let registry = self.registry.lock().await;
            let mut live: std::collections::BTreeSet<SessionId> = registry
                .workers()?
                .into_iter()
                .map(|worker| worker.session_id)
                .collect();
            // Every phase in which something may still be running, or may still be resolved. A
            // reservation that has not been settled keeps its directory.
            for phase in [
                LaunchPhase::Reserved,
                LaunchPhase::Spawned,
                LaunchPhase::Claimed,
                LaunchPhase::Live,
                LaunchPhase::Fenced,
            ] {
                live.extend(
                    registry
                        .reservations_in(phase)?
                        .into_iter()
                        .map(|reservation| reservation.session_id),
                );
            }
            live
        };
        let Ok(entries) = std::fs::read_dir(self.paths.workers_dir()) else {
            return Ok(());
        };
        for entry in entries.flatten() {
            // The name is the session the directory belongs to. Anything else under here was not
            // put there by this daemon, and this daemon does not remove what it did not write.
            let Some(session_id) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<SessionId>().ok())
            else {
                continue;
            };
            if !live.contains(&session_id) {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
        Ok(())
    }

    /// Removes the job of every worker this environment defined one for that has ended.
    ///
    /// A daemon that was not running when a worker ended, or that stopped before that worker's job
    /// was removed, leaves the job loaded, and nothing else would ever remove it. So every job this
    /// environment still has defined is looked at when the daemon starts: one whose process has
    /// ended goes, and one whose process is still running is a live session's and is left exactly
    /// as it is. It is finished before the daemon serves anything, which is what keeps a job that
    /// a create of this daemon has defined and not yet started off the list. launchd is asked
    /// about each job in a few milliseconds. A look that reaches every job leaves defined only the
    /// jobs of workers that are still running and those whose removal launchd did not confirm; one
    /// that [`JOB_SWEEP_BOUND`] cuts short leaves the jobs it did not reach for the next start.
    async fn retire_ended_jobs(&self) {
        let jobs = self.paths.jobs_dir();
        let _ = tokio::task::spawn_blocking(move || {
            let deadline = std::time::Instant::now() + JOB_SWEEP_BOUND;
            let defined = crate::supervision::defined_worker_jobs(&jobs);
            for (looked, reservation_id) in defined.iter().enumerate() {
                if std::time::Instant::now() >= deadline {
                    eprintln!(
                        "kr-controller: {} of {} worker jobs were not looked at within \
                         {JOB_SWEEP_BOUND:?}; the next start looks at them again",
                        defined.len() - looked,
                        defined.len()
                    );
                    return;
                }
                if let JobRetirement::Unsettled(detail) =
                    crate::supervision::retire_worker_job(&jobs, *reservation_id)
                {
                    eprintln!(
                        "kr-controller: the job of the worker started for reservation \
                         {reservation_id} could not be removed: {detail}"
                    );
                }
            }
        })
        .await;
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

/// Builds the actor envelope a local caller acts under.
///
/// Ingress is recorded as the local operating-system path, never as a paired device. A local
/// caller cannot relabel itself, because the host constructs this rather than accepting it.
#[must_use]
pub fn local_actor(
    actor_id: ActorId,
    connection_id: ConnectionId,
    generation: ControllerGeneration,
) -> kr_protocol::actor::ActorEnvelope {
    kr_protocol::actor::ActorEnvelope {
        actor_id,
        ingress: kr_protocol::actor::ActorIngress::LocalIpc,
        device_id: Nullable::null(),
        grant_id: Nullable::null(),
        grant_revision: Nullable::null(),
        controller_generation: generation,
        connection_id,
    }
}

/// One connection this daemon has admitted, and the authority it was admitted under.
///
/// The transport's contract names this as the host's to keep: the final validation of the caller's
/// record and the registration of the connection are one step, and the registration stays
/// revocable for the life of the session. A read or a subscription on a connection that was
/// authorised a moment before authority was withdrawn is fenced here; section 9's dispatch barrier
/// covers a worker's dispatch and does not cover this.
#[derive(Clone, Debug)]
struct AdmittedConnection {
    /// The principal the daemon assigned to the operating-system caller.
    actor_id: ActorId,
    /// The authority revision in force when the connection was registered.
    admitted_revision: kr_protocol::ids::AuthorityRevision,
}

/// What a controller needs before it starts.
pub struct ControllerSetup {
    /// The environment's directories.
    pub paths: EnvironmentPaths,
    /// The environment identity.
    pub environment_id: EnvironmentId,
    /// Opens or creates the persistent identity this daemon signs generation tokens with.
    ///
    /// It is a closure because it must run **after** the singleton lock is held: creating the
    /// environment's key is a first-start step, and two daemons racing for it would leave one of
    /// them holding a key no live worker recognises.
    pub identity: Box<dyn FnOnce() -> Result<ControllerIdentity> + Send>,
    /// Which store this daemon keeps its keys in.
    ///
    /// The closure above opens it for the identity; this is the same choice, for everything else
    /// this daemon keeps a key in. The transport's device keys are the one that matters: they are
    /// opened only when the environment selects a network, which is after startup.
    pub secret_store: kr_crypto::store::StoreSelection,
    /// The boot this host is running.
    pub boot_identity: BootIdentity,
    /// How workers are started.
    pub supervisor: Box<dyn WorkerSupervisor>,
    /// The worker executable.
    pub worker_program: PathBuf,
    /// This daemon's build.
    pub build_id: BuildId,
    /// The release string sessions report as their terminal program version.
    pub release: String,
    /// Where the qualified shell packages are installed.
    ///
    /// `None` is the installation's own directory, or whatever
    /// [`PACKAGE_ROOT_VARIABLE`](kr_shell_integration::host::package::PACKAGE_ROOT_VARIABLE)
    /// names. A host that keeps its packages somewhere else is told, rather than being expected to
    /// arrange a variable for every process that needs to know.
    pub shell_packages: Option<PathBuf>,
    /// How a `terminal` presentation opens its window.
    ///
    /// This daemon is the only party on the host that can open one for a session created from
    /// somewhere else, so the presentation is its work. A host that opens nothing says so with
    /// [`NoTerminal`](crate::supervision::NoTerminal).
    pub terminal: Box<dyn crate::supervision::TerminalPresenter>,
}

/// Resolves the qualified package a create request selects, against one package root.
///
/// Section 7: an unqualified system shell may be a child application or an explicitly selected
/// `native_compat` top-level shell; it cannot claim the managed contract. The refusal names the
/// shell rather than substituting another, and at admission it happens before a reservation is
/// recorded, so an unsupported request costs the caller an error rather than a session that closes
/// itself.
///
/// Free of the controller on purpose: it reads the filesystem, so it runs on a thread that may
/// block rather than on the runtime this daemon serves its clients on.
///
/// # Errors
///
/// Returns [`ControllerError::ShellIntegrationUnsupported`] naming the shell, never a substitution.
/// Opens, adopts or creates this environment's clock floor for the boot, and says whether the
/// boot's clock continuity is lost.
///
/// Three cases, told apart by the file and by the registry's record of the floors created in
/// this boot:
///
/// 1. A file of this environment and boot that passes every check, whose identity is not recorded
///    as lost: opened as it stands, never truncated or replaced, so every worker that outlived a
///    daemon restart keeps mapping the same word. An identity the registry does not know (a start
///    that stopped between publishing the file and recording it) is recorded now.
/// 2. No usable file and no floor recorded for this boot: the boot's first start. A new floor is
///    created under a fresh identity and recorded as the boot's floor in force.
/// 3. No usable file and a floor recorded for this boot: the floor was lost, and a worker of this
///    boot may still map it. The boot's clock continuity is recorded as lost first, then a new
///    floor is created and recorded in force. A reading published only in the lost floor may have
///    passed a deadline nothing on record shows as passed, so until the owner establishes the
///    clock no bound that can pass is decided ([`crate::grants::policy::UtcFloor::bound`]).
///
/// A file of another boot, one that fails a check, and one whose identity is recorded as lost
/// count as no usable file and are replaced: a lost floor moved back into place is never adopted.
/// A new floor's first value is `durable_ms`, the floor this host last wrote down.
fn open_utc_floor(
    registry: &mut Registry,
    paths: &EnvironmentPaths,
    environment_id: EnvironmentId,
    boot_epoch: BootEpoch,
    durable_ms: u64,
) -> Result<(Arc<kr_ipc::floor::SharedFloor>, bool)> {
    use kr_ipc::floor::SharedFloor;

    registry.forget_other_boots(boot_epoch)?;
    let recorded = registry.floors_of_boot(boot_epoch)?;
    let path = paths.utc_floor_file();
    let adopted = SharedFloor::open(&path, environment_id, boot_epoch)
        .ok()
        .filter(|floor| {
            let identity = floor.identity();
            !recorded
                .iter()
                .any(|known| Some(known.identity) == identity && !known.in_force)
        });
    let floor = match adopted {
        Some(floor) => {
            if let Some(identity) = floor.identity()
                && !recorded.iter().any(|known| known.identity == identity)
            {
                registry.record_floor_in_force(boot_epoch, identity, kr_ipc::now_ms())?;
            }
            floor
        }
        None => {
            if !recorded.is_empty() {
                registry.lose_clock_continuity(boot_epoch, kr_ipc::now_ms())?;
            }
            let floor = SharedFloor::create(&path, environment_id, boot_epoch, durable_ms)?;
            let identity =
                floor
                    .identity()
                    .ok_or_else(|| ControllerError::RegistryUnavailable {
                        detail: "a clock floor created from a file has no identity".to_owned(),
                    })?;
            registry.record_floor_in_force(boot_epoch, identity, kr_ipc::now_ms())?;
            floor
        }
    };
    let lost = registry.clock_continuity_lost(boot_epoch)?;
    Ok((Arc::new(floor), lost))
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

/// Returns the accepted deadline on the machine's own continuous clock, bounded by any lease.
///
/// The daemon decides deadlines on its own anchored clock, which nothing outside this process can
/// read. This converts one of those into the shared reading a worker can compare against. The
/// machine's clock is read **first** and the daemon's own clock second, so a pause between the two
/// readings shortens the answer rather than lengthening it: what is left is measured from the later
/// moment and anchored at the earlier one. `None` means the deadline has already passed, which is
/// never forwarded as though it had time left.
fn remaining_deadline(
    shared: &dyn kr_ipc::clock::SharedClock,
    clock: &dyn ContinuousClock,
    accepted: kr_transport::clock::ContinuousInstant,
    lease: Option<kr_transport::clock::ContinuousInstant>,
) -> Option<U64> {
    // The machine's clock first, the daemon's own clock second.
    let shared_now = shared.boot_elapsed_ms();
    let now = clock.now();
    let deadline = lease.map_or(accepted, |lease| lease.min(accepted));
    let remaining = deadline.saturating_duration_since(now);
    kr_ipc::clock::transferred_deadline(shared_now, remaining).map(U64::new)
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

/// Returns whether this daemon forwards the method to the worker that owns the session.
///
/// It decides what a window refusal means. A mutation this daemon performs itself has its
/// retained action here, and a window that admits nothing has already been past it; one it
/// forwards has its retained action in the worker's journal, which only the worker can read.
const fn forwarded_to_worker(method: Method) -> bool {
    matches!(method, Method::SessionClose)
}

const fn window_refusal_detail(refusal: kr_transport::window::WindowRefusal) -> &'static str {
    use kr_transport::window::WindowRefusal;
    match refusal {
        WindowRefusal::Unknown => {
            "this action window is not the one this connection holds, so the request cannot be \
             admitted for the first time"
        }
        WindowRefusal::WrongConnection => {
            "this action window belongs to another connection, so it admits nothing here"
        }
        WindowRefusal::StaleBoot => {
            "this action window was issued in another boot of this host, so it admits nothing"
        }
        WindowRefusal::Expired => {
            "this action window has expired; the host has already replaced it, so submit a new \
             request rather than replaying this one"
        }
    }
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

/// Whether this caller is the owner, at this machine, over its own socket.
///
/// The local listener admits an operating-system peer and names it after that peer's user; a paired
/// device is named after its device identity by the transport. Anything this host cannot recognise
/// as the local peer is treated as somebody else, because that is the answer that withholds rather
/// than the one that publishes.
fn is_owners_own_socket(actor_id: &ActorId) -> bool {
    actor_id.as_str().starts_with(LOCAL_PRINCIPAL_PREFIX)
}

/// Encodes one host-and-environment read for whoever asked: the one function that decides what a
/// paired device reads of this host.
///
/// The owner at their own machine, on its owner-only socket, is answered with the display form:
/// the account the environments belong to, the directories this host resolved, what the platform
/// said. Everybody else - a paired device, and any caller that is not the owner's own socket - is
/// answered with the export form of the same answer,
/// [`kr_protocol::hostinfo::export::ForExport::for_export`], which carries each
/// account name, path and platform message as its class and its length and composes the rest
/// from this build's own words. The four answers are `host.info`, `environment.list`,
/// `environment.capabilities` and `host.doctor`; each has its one reduction beside its type, and
/// the protocol's tests walk every field of all four, so a field added to one is classed before it
/// can be sent.
fn host_read<T>(answer: T, owner: bool) -> Result<ParamsValue>
where
    T: kr_protocol::hostinfo::export::ForExport + serde::Serialize,
{
    if owner {
        encode(&answer)
    } else {
        encode(answer.for_export().get())
    }
}

/// How the local listener names the operating-system peer it admitted.
const LOCAL_PRINCIPAL_PREFIX: &str = "local:";

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
