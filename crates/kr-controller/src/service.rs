//! The control daemon itself: admission, the rendezvous and the local service.
//!
//! Creating a session is the part with an order that matters. The reservation is durable before
//! anything is spawned, the launcher's identity is recorded before the worker connects, and the
//! worker's key is stored inside the same transition that marks the session live. A daemon that
//! dies at any point in that sequence finds a record that tells it what happened, which is what
//! makes a lost reply something to resolve rather than a reason to start a second shell.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::split;
use kr_ipc::paths::{Endpoint, EnvironmentPaths};
use kr_ipc::peer::PeerIdentity;
use kr_ipc::verify::{ControllerIdentity, check_rendezvous};
use kr_protocol::action::RevocationBarrier;
use kr_protocol::desktop::{
    DesktopContext, EnvironmentCapabilitiesParams, EnvironmentCapabilitiesResult,
    SleepInhibitionState,
};
use kr_protocol::envelope::{
    ControlEvent, ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{ActionWindow, PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::hostinfo::export::{ContentClass, Sentence};
use kr_protocol::hostinfo::{
    DoctorCheck, DoctorStatus, EnvironmentListResult, EnvironmentSummary, HostDoctorResult,
    HostInfoResult,
};
use kr_protocol::identity::{BootIdentity, WorkerProfile};
use kr_protocol::ids::{
    ActorId, AuthorityRevision, BootEpoch, BuildId, CapabilityRevision, ConnectionId,
    ControllerGeneration, EnvironmentId, RequestId, SessionEpoch, SessionId,
};
use kr_protocol::local::{LocalClientKind, LocalHelloAck, LocalPeer, LocalRole};
use kr_protocol::method::Method;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs, U64};
use kr_protocol::session::{
    ClosureReason, ClosureRecord, SessionCloseParams, SessionCloseResult, SessionCreateParams,
    SessionCreateResult, SessionListParams, SessionListResult, SessionReadParams,
    SessionReadResult, SessionState, SessionSummary,
};
use kr_protocol::worker::{
    ReservationId, WorkerDescriptor, WorkerLaunchSpec, WorkerReady, WorkerRendezvous,
};
use kr_transport::clock::{ContinuousClock, SystemContinuousClock};
use kr_transport::lease::LeaseRefusal;
use kr_transport::window::{AcceptedDeadline, ActionWindowIssuer, MAX_WINDOW_VALIDITY};
use tokio::sync::{Mutex, oneshot};

use crate::desktop::power::{self, Demand, Inhibitor};
use crate::directory::{Directory, KnownWorker, Reconnect};
use crate::error::{ControllerError, Result};
use crate::registry::{LaunchPhase, Registry, WorkerRecord};
use crate::singleton::SingletonLock;
use crate::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};

/// The daemon on the network.
///
/// It is a child of this module because it is part of the same daemon: it shares the registry, the
/// authority store, the worker directory and the dispatch leases below, and a network module that
/// reached them through a public surface would be a second way into the daemon's own state.
#[path = "net/mod.rs"]
pub mod net;

/// How long a closing worker is watched before the controller stops waiting for it to end.
pub const CLOSURE_WATCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// The file this environment's capability revision is recorded in.
///
/// It is durable because a revision must never repeat: a caller compares the revision a record
/// carried with the one it is given now, and a revision that came round again would make a stale
/// record look current.
pub const CAPABILITY_REVISION_FILE: &str = "capabilities";

/// The longest capability-revision record this host reads.
const CAPABILITY_REVISION_LIMIT: u64 = 64;

/// The resource kind a closure uses to say its worker was never confirmed gone.
///
/// A closure removes the registry's worker row and retires the published descriptor, so after it
/// is written those two can no longer say whether anything is still there. This is what does: a
/// session closed on a boot record the platform would not corroborate lists its worker here
/// rather than among the processes it terminated, and every read and migration asks for it.
const UNACCOUNTED_WORKER: &str = "unaccounted_worker";

/// The file this environment's current boot identity is recorded in.
///
/// It lives in the state directory rather than the runtime one because it has to outlive the boot
/// it names, and a runtime directory does not.
pub const BOOT_FILE: &str = "boot";

/// The longest boot record this host reads.
const BOOT_FILE_LIMIT: u64 = 1_024;

/// What a caller is told when it asks for a desktop this host does not have.
const NO_DESKTOP_TO_BIND: &str = "this host has no graphical login session to bind a session to; create it in the headless \
     user profile instead";

/// How long a desktop reading is reused before the platform is asked again.
///
/// The reading costs a conversation with the platform's session facilities, and the answer changes
/// only when somebody logs in or out. Nothing waits this out: it is the age at which the next
/// question asks the platform rather than the cache.
pub const DESKTOP_REREAD_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// How often the sleep setting is looked at while it is on.
///
/// This runs only while the owner has enabled the setting, so a host that has not is not paying
/// for it. It is how often the question is asked rather than a bound on the answer: one review
/// asks as many of its sessions as its own budget allows and the rest keep what they last said,
/// a worker that stops answering keeps its last answer until the kernel says its process has
/// gone, and a closure counts until this host has recorded it.
pub const POWER_REVIEW_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// Whether an evaluation of the sleep setting may take over reviewing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Claim {
    /// This evaluation starts a review when one is wanted and none is running.
    Take,
    /// This evaluation is the review, and it gives the mark up when nothing wants it.
    Hold,
}

/// What an evaluation of the sleep setting decided about reviewing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Review {
    /// A review is wanted and this evaluation took it on.
    Start,
    /// Whoever is reviewing keeps doing so.
    Continue,
    /// Nothing wants a review, and the mark has been given up.
    Stop,
}

/// How long one worker is given to say what it has outstanding.
pub const DEMAND_PATIENCE: std::time::Duration = std::time::Duration::from_millis(500);

/// How long the whole scan of what this host has outstanding may take.
pub const DEMAND_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

/// How long the rendezvous waits for the launcher to report the worker's identity.
pub const LAUNCH_IDENTITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a create waits for its worker to report itself.
pub const RENDEZVOUS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How many pages of one worker's fence evidence this daemon collects in one announcement.
///
/// The names are in the worker's journal, so there is no bound on how many a busy session can
/// produce; what is bounded is how long one announcement spends collecting them. A worker with
/// more than this many pages keeps the rest, the report says how many have not arrived, and the
/// next announcement continues from where this one stopped.
const MAX_EVIDENCE_PAGES: usize = 64;

/// How long the daemon waits for one worker to answer before it reports that worker as pending.
///
/// Section 9: waiting is not completion. A worker that will not answer is `pending`, and the only
/// way to make it complete is an acknowledgement or a confirmed ending, so the wait has a bound and
/// the report goes out without it.
const WORKER_EXCHANGE: std::time::Duration = std::time::Duration::from_secs(5);

/// How long a close waits for the worker that owns the session.
///
/// Section 7's own timing for a closure: five seconds for the processes to stop and two more to
/// drain their output. A worker that has not answered a close by then has taken longer than the
/// whole closure is allowed to take, so this daemon stops waiting for it rather than holding the
/// one connection it has to that worker for whoever asks next. The bound covers acquiring that
/// connection as well as the exchange over it, because a caller queueing behind a worker that
/// stopped answering waits exactly as long as one talking to it.
pub const CLOSE_EXCHANGE: std::time::Duration = std::time::Duration::from_millis(
    kr_worker::session::GRACE_PERIOD.as_millis() as u64
        + kr_worker::session::DRAIN_PERIOD.as_millis() as u64,
);

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

/// The clock the owner-confirmation ceremony reads, which is this daemon's own.
///
/// The monotonic reading and the boot identity are what a confirmation's deadline is measured on,
/// so a wall clock that moves cannot lengthen one.
#[derive(Debug)]
struct PairingTime;

impl kr_pairing::platform::PairingClock for PairingTime {
    fn monotonic_ms(&self) -> u64 {
        kr_ipc::clock::SharedClock::boot_elapsed_ms(&kr_ipc::clock::SystemSharedClock)
    }

    fn boot_identity(&self) -> kr_pairing::platform::BootIdentity {
        // The daemon's own boot value, hashed to the fixed width this clock's identity uses. Two
        // boots differ here whenever they differ there, which is the whole of what it is for.
        let value = kr_ipc::identity::boot_identity()
            .map(|identity| identity.value.as_slice().to_vec())
            .unwrap_or_default();
        kr_pairing::platform::BootIdentity(kr_cbor::sha256(&value))
    }

    fn wall_clock_ms(&self) -> u64 {
        kr_ipc::now_ms().get()
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
    clock: Arc<SystemContinuousClock>,
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
    /// The catalogue's evidence about itself, once a catalogue has registered some.
    ///
    /// Section 11 gives `kr doctor`, launch buttons and disabled-action UI one shared capability
    /// evidence to read, and this is where the catalogue's half of it arrives. It is empty on a
    /// host that has never synchronised a catalogue, and the diagnostic says so rather than
    /// claiming anything about a catalogue this host does not have.
    catalogue_evidence: Option<Arc<dyn crate::config::catalogue::CatalogueEvidence>>,
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
    /// True while a ceiling this host accepted asked for a fence it could not raise.
    ///
    /// Section 26 fences dispatch before a change affecting authority is acknowledged, so a fence
    /// that could not be raised has to stop dispatch rather than be reported and passed over. The
    /// revision did not advance, which is exactly why every connection admitted under the old one
    /// still looks admitted: nothing in the registry says otherwise, so this does, and admission
    /// refuses while it is set.
    ///
    /// In this process and no longer. A daemon that stops here comes back, reads the same
    /// document, finds the same fence owed and raises it or refuses to serve.
    fence_unraised: std::sync::atomic::AtomicBool,
    /// The environment's transfer service, whose methods this daemon admits and dispatches.
    transfer: Arc<crate::transfer::TransferModule>,
    /// The environment's project service, whose methods this daemon admits and dispatches.
    project: Arc<crate::project::ProjectModule>,
    /// The environment's grants and invitations, which the sharing and device method groups act on.
    sharing: Arc<crate::sharing::SharingService>,
    /// The environment's voice service: the coordinator and the seams it reads and proposes
    /// through. Built after the daemon exists, because two of its seams hold a weak reference back.
    voice: std::sync::OnceLock<Arc<crate::voice::VoiceModule>>,
    /// The paired devices, for the device method group.
    ///
    /// A view on this daemon's own registry database, which is the file the network half keeps its
    /// device records in, so the two see one set of devices whether or not this host is on a
    /// network.
    devices: Arc<net::devices::DeviceDirectory>,
    /// What is true of this host rather than of one grant: the revision in force, the organisation
    /// leases it holds and the optional bounded offline-validity policy its owner chose.
    ///
    /// Every request intersects its grant with this, so it is read far more often than it is
    /// written and a plain lock is what it wants.
    policy: std::sync::Mutex<crate::grants::HostPolicy>,
    /// This host's half of the remote authority feed: the revisions only it issues, the revocation
    /// records it retains, and the synchronisation it owes before it serves remote work again.
    feed: std::sync::Mutex<crate::grants::AuthorityFeed>,
    /// The environment's change-set service, which reads repositories through the project
    /// service's own profile and boundary.
    changesets: Arc<crate::changeset::ChangeSetModule>,
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

/// Where the last look at what this host has outstanding got to, and what it found.
///
/// A scan that cannot ask every worker inside its budget is not evidence that the work it did not
/// ask about has ended, so what each session last answered is kept here and counted again. Only a
/// session's own answer changes what that session contributes, and an entry lives exactly as long
/// as its session is in the directory: a closed session's work goes with its entry.
#[derive(Debug, Default)]
struct DemandScan {
    /// Where the last scan stopped, so the next one starts after it.
    cursor: usize,
    /// What each live session was last observed to have outstanding.
    seen: BTreeMap<SessionId, SessionDemand>,
}

/// What one session was last observed to have outstanding.
///
/// The worker's own activity and this host's own work are separate fields because they end
/// separately. A worker that has gone is not working and is not waiting for an answer, and a
/// closure this host accepted is its own work until it has recorded it.
#[derive(Clone, Copy, Debug, Default)]
struct SessionDemand {
    /// Whether its worker reported an agent at work.
    work: bool,
    /// Whether its worker reported a decision waiting to be answered.
    approval: bool,
    /// Whether this host has a closure for it that it has not finished recording.
    closing: bool,
    /// How many launch confirmations its worker is waiting on its reader for.
    ///
    /// A managed session waiting for a reader's answer to `shell.launch` is a request this host
    /// admitted and has not finished, and suspending underneath one delays the answer past the
    /// window the caller was given. A session that cannot have one reports null and contributes
    /// nothing here, which is not the same as reporting none.
    launches: u64,
}

/// The desktop this host has, and how old the reading is.
#[derive(Debug)]
struct DesktopReading {
    /// The desktop this machine actually has, labelled with the execution context the
    /// configuration resolves to.
    ///
    /// What a desktop-bound create is checked against, because whether a desktop is there is a
    /// fact about the machine rather than a preference.
    context: DesktopContext,
    /// The same reading taken in the resolved execution context, which is what the capability
    /// evidence is about.
    ///
    /// A headless context takes no login session, so it has no desktop session, no display server
    /// and no graphical access. Evidence that said `headless_user` while carrying a desktop's
    /// identity would describe a worker this host never creates.
    evidence: DesktopContext,
    /// The revision the capability records of this context are evidence for.
    ///
    /// It advances whenever the evidence changes: a new login, a tool installed or replaced, a
    /// permission that now answers differently, a screen that is now locked. Section 11 requires
    /// evidence to be invalidated when any of those move, and an advancing revision is how a
    /// caller holding the old answer can see that it has been superseded.
    ///
    /// It starts at the moment this daemon began serving rather than at one, so a daemon that
    /// restarts does not hand out a revision it has used before.
    revision: CapabilityRevision,
    /// Whether the revision can be kept across a restart.
    ///
    /// A record this host could not read leaves this false, and then the revision stays at zero:
    /// zero claims nothing, where advancing from it would hand out a number this environment may
    /// already have used.
    durable_revision: bool,
    /// The records that revision was established for, so a change to any of them can be seen.
    records: Vec<kr_protocol::desktop::CapabilityRecord>,
    /// When the platform was last asked.
    read_at: std::time::Instant,
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

/// One reservation, held by whichever of a look and a publication took it.
///
/// Giving it back wakes everybody who is waiting, and each of them looks for the one reservation it
/// came for: whoever was waiting for this one takes it, and the rest wait again.
struct ReservationHold<'a> {
    controller: &'a Controller,
    reservation_id: ReservationId,
}

impl Drop for ReservationHold<'_> {
    fn drop(&mut self) {
        self.controller
            .recovering
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.reservation_id);
        self.controller.recovered.notify_waiters();
    }
}

struct PendingCreate {
    ready: oneshot::Sender<std::result::Result<WorkerReady, ProtocolError>>,
}

impl Controller {
    /// Starts the daemon: takes the lock, advances the generation and rebuilds the directory.
    ///
    /// # Errors
    ///
    /// Returns an error when another daemon owns the environment, the registry cannot be opened,
    /// or the controller identity is missing.
    pub async fn start(setup: ControllerSetup) -> Result<Arc<Self>> {
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
        let in_force = crate::config::InForce::of(&startup_configuration);
        drop(startup_configuration);
        let identity = (setup.identity)()?;
        let boot_epoch = kr_ipc::identity::boot_epoch(&setup.boot_identity)?;
        let boot = setup.boot_identity.clone();
        let paths = setup.paths.clone();
        let recorded_revision = capability_revision(&paths);
        let started_at_ms = kr_ipc::now_ms();
        let clock = Arc::new(SystemContinuousClock::new());
        let authority_revision = registry.authority_revision()?;
        let transfer = Arc::new(crate::transfer::TransferModule::open(&setup.paths).await?);
        let project = Arc::new(crate::project::ProjectModule::open(&setup.paths).await?);
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
        let policy = match sharing.grants().stored_policy()? {
            Some(stored) => crate::grants::HostPolicy::restore(&stored, authority_revision),
            None => crate::grants::HostPolicy::personal(authority_revision),
        };
        sharing.grants().store_policy(&policy.snapshot())?;
        let mut feed = match sharing.grants().stored_feed()? {
            Some(stored) => crate::grants::AuthorityFeed::restore(&stored),
            None => crate::grants::AuthorityFeed::new(host_device_id, authority_revision),
        };
        // The registry is the allocator. A feed restored below it would number its next entry with
        // a revision the registry has already used, and would report an old number as the one in
        // force.
        feed.note_revision(authority_revision);
        sharing.grants().store_feed(&feed.snapshot())?;
        let devices = Arc::new(net::devices::DeviceDirectory::open(
            setup.paths.registry_database(),
        )?);
        let (initial_desktop, initial_evidence) = resolved_desktop(in_force.worker_profile, &boot);
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
            catalogue_evidence: None,
            accepted_configuration: Mutex::new(accepted_configuration),
            in_force: std::sync::Mutex::new(in_force),
            fence_unraised: std::sync::atomic::AtomicBool::new(false),
            boot_identity: setup.boot_identity,
            boot_epoch,
            windows: ActionWindowIssuer::with_default_validity(Arc::clone(&clock) as Arc<_>),
            shared_clock: Arc::new(kr_ipc::clock::SystemSharedClock),
            leases: crate::authority::AuthorityBarrier::new(generation, authority_revision),
            clock,
            network: std::sync::OnceLock::new(),
            supervisor: setup.supervisor,
            backup,
            transfer,
            project,
            sharing,
            voice: std::sync::OnceLock::new(),
            devices,
            policy: std::sync::Mutex::new(policy),
            feed: std::sync::Mutex::new(feed),
            changesets,
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
        // Reconnecting is not only verifying. A replacement daemon has to present the generation it
        // advanced to, because that is what fences the daemon it replaced.
        let directory = {
            let registry = controller.registry.lock().await;
            Directory::rebuild(&controller.paths, &registry, &controller.reconnect()).await?
        };
        *controller.directory.lock().await = directory;
        // A reboot ends every live execution, of either profile. Sessions published in an earlier
        // boot are closed with that as their reason before anything tries to recover them, so the
        // record says the host restarted rather than that a worker died for reasons unknown.
        controller.close_previous_boot().await?;
        controller.recover_reservations().await?;
        // Recovery has settled every reservation it can, so what is left under the workers
        // directory that no session claims is nothing's.
        controller.sweep_worker_dirs().await?;
        // A fence this environment recorded and never saw answered is announced again, to the
        // workers this daemon has just reconnected to. The debt is durable, so a daemon that
        // stopped between raising a fence and hearing every answer comes back still owing it; the
        // announcement is how a worker that has since acknowledged, or since ended, settles it.
        if controller.registry.lock().await.fence_owed()?.is_some() {
            controller.announce_authority_revision().await?;
        }
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
        crate::transfer::serve(&controller)?;
        // The owner's setting is the owner's setting across a restart. A daemon that waited for a
        // client to ask before it looked would leave an enabled setting doing nothing until
        // somebody happened to run a command.
        let _ = controller.power_state().await;
        // The network comes up last. A paired device must not reach a daemon that has not yet
        // recovered its reservations and rebuilt its worker directory, because it would be told
        // that sessions this host is running do not exist.
        net::register_from_environment(&controller).await?;
        Ok(controller)
    }

    /// Resolves every create that a previous daemon did not finish.
    ///
    /// The rule is the one section 24 asks for: a launch that is confirmed not to have started is
    /// resolved and stops occupying the environment; a launch that may have started is preserved,
    /// never respawned, and keeps its slot until something confirms what happened to it.
    async fn recover_reservations(&self) -> Result<()> {
        let unresolved = {
            let registry = self.registry.lock().await;
            let mut rows = registry.reservations_in(LaunchPhase::Reserved)?;
            rows.extend(registry.reservations_in(LaunchPhase::Spawned)?);
            rows.extend(registry.reservations_in(LaunchPhase::Claimed)?);
            rows
        };
        for reservation in unresolved {
            match reservation.phase {
                // Nothing was ever handed to the service manager: the phase moves to `spawned`
                // before the call and this one never got there.
                LaunchPhase::Reserved => {
                    let mut registry = self.registry.lock().await;
                    registry.set_phase(reservation.reservation_id, LaunchPhase::Failed)?;
                }
                // Spawned and never claimed. A worker starts its shell only after the rendezvous
                // hands it a launch specification, and that never happened, so an ended process
                // means nothing came of this launch. A process still running, or one the kernel
                // will not describe, keeps its slot.
                LaunchPhase::Spawned => match reservation.launcher_identity.as_ref() {
                    Some(identity) => {
                        if matches!(
                            kr_ipc::identity::process_state(identity),
                            kr_ipc::identity::ProcessState::Ended
                        ) {
                            let mut registry = self.registry.lock().await;
                            registry.set_phase(reservation.reservation_id, LaunchPhase::Failed)?;
                        }
                    }
                    // Spawned with no launcher recorded: the daemon died between handing the launch
                    // to the service manager and writing down what it returned. A process may be
                    // running, but it cannot have started a shell: a worker starts one only after
                    // the rendezvous hands it a launch specification, and this reservation's claim
                    // was never consumed. Resolving it as failed both frees the slot and fences it,
                    // because a claim is admitted only against a reservation that is still spawned.
                    None => {
                        let mut registry = self.registry.lock().await;
                        registry.set_phase(reservation.reservation_id, LaunchPhase::Failed)?;
                    }
                },
                // Claimed. This worker received its launch specification, so it may have started a
                // shell. It is recovered by challenge where it still answers, and recorded as an
                // abnormal closure where its process is confirmed gone; a claim is never resolved
                // as though nothing had run.
                LaunchPhase::Claimed => self.recover_claim(&reservation).await?,
                _ => {}
            }
        }
        self.recover_workers().await?;
        Ok(())
    }

    /// Recovers a worker whose claim was consumed but whose session never reached the directory.
    async fn recover_claim(&self, reservation: &crate::registry::Reservation) -> Result<()> {
        let endpoint = self.paths.worker_endpoint(reservation.display_number)?;
        if let Some(key) = reservation.claimed_key
            && let Ok(proof) = self
                .challenge(&endpoint, &key, reservation.session_id)
                .await
        {
            // The worker is alive and is the one this reservation admitted. Its descriptor and its
            // registry row are rebuilt from its own signed answer.
            self.adopt(reservation.display_number, &key, &proof, &endpoint)
                .await?;
            let mut registry = self.registry.lock().await;
            registry.resolve_claim(reservation.reservation_id, LaunchPhase::Live)?;
            return Ok(());
        }
        let ended = reservation
            .launcher_identity
            .as_ref()
            .is_some_and(|identity| {
                matches!(
                    kr_ipc::identity::process_state(identity),
                    kr_ipc::identity::ProcessState::Ended
                )
            });
        if ended {
            // The worker that held this claim is gone. It may have started a shell, so this is
            // recorded as a session that ended abnormally rather than as a launch that never
            // happened, and the coverage says the host did not watch it end.
            let identity = reservation
                .launcher_identity
                .clone()
                .expect("the identity was just read");
            self.record_final(
                reservation.session_id,
                ClosureReason::WorkerCrash,
                &identity,
                &crate::archive::ArchiveService::nothing_fenced(reservation.session_id),
                true,
            )
            .await?;
        }
        Ok(())
    }

    /// Looks again for a worker whose claim this daemon has not resolved.
    ///
    /// A daemon that restarts while a managed session is still qualifying is refused its own
    /// startup challenge, because a worker whose root integration has never qualified proves
    /// nothing for the session it is still making. That worker qualifies a moment later, and
    /// nothing would look again until the next restart. So every request that goes looking for a
    /// session looks here too: a reservation still recorded as claimed is a live process this
    /// daemon has not adopted yet.
    ///
    /// A claim whose worker is gone is resolved the same way it is at startup, and one whose worker
    /// is alive and still unqualified is simply left for the next look.
    async fn recover_claims(&self) -> Result<()> {
        let claimed = {
            let registry = self.registry.lock().await;
            registry.reservations_in(LaunchPhase::Claimed)?
        };
        for reservation in claimed {
            // One session's failure is not another's, and a list asks about every session. A
            // reservation that cannot be recovered now is left claimed for the next look.
            let _ = self.recover_unresolved(reservation.reservation_id).await;
        }
        Ok(())
    }

    /// Looks again for one session's own unresolved claim, and says what went wrong.
    ///
    /// The same look as [`Self::recover_claims`], for a caller that asked about one session and is
    /// owed the reason rather than a session that is simply not there.
    async fn recover_claim_for(&self, session_id: kr_protocol::ids::SessionId) -> Result<()> {
        let reservation = {
            let registry = self.registry.lock().await;
            registry.reservation_for_session(session_id)?
        };
        let Some(reservation) = reservation else {
            return Ok(());
        };
        self.recover_unresolved(reservation.reservation_id).await
    }

    /// Recovers one claim, after asking again whether it is still this daemon's to recover.
    ///
    /// The reservation is read here rather than trusted from whatever the caller saw, because a
    /// challenge takes time and the answer can be stale by the time its turn comes: a create that
    /// finished during an earlier challenge in the same scan has already resolved its own claim and
    /// published its worker, and challenging that worker again would present a second generation
    /// token and fence the connection this daemon is already using.
    ///
    /// Three things say it is not this daemon's to recover: a reservation that is no longer
    /// claimed, a create this daemon is still running, and a worker already in the directory.
    async fn recover_unresolved(&self, reservation_id: ReservationId) -> Result<()> {
        let _held = self.hold_reservation(reservation_id).await;
        let reservation = {
            let registry = self.registry.lock().await;
            registry.reservation(reservation_id)?
        };
        let Some(reservation) = reservation else {
            return Ok(());
        };
        if reservation.phase != LaunchPhase::Claimed
            || self.pending.lock().await.contains_key(&reservation_id)
            || self
                .directory
                .lock()
                .await
                .get(reservation.session_id)
                .is_some()
        {
            return Ok(());
        }
        self.recover_claim(&reservation).await
    }

    /// Takes one reservation from whatever else would look at it, and gives it back on drop.
    ///
    /// Only that reservation: a caller waiting here is waiting for one worker's own turn, never for
    /// a scan of somebody else's.
    async fn hold_reservation(&self, reservation_id: ReservationId) -> ReservationHold<'_> {
        loop {
            // Created before the set is read, so a reservation given back between the two is not
            // missed: a wake from that moment on is already counted for this waiter, and the wait
            // below ends at once rather than sleeping through it.
            let given_back = self.recovered.notified();
            {
                let mut held = self
                    .recovering
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if held.insert(reservation_id) {
                    return ReservationHold {
                        controller: self,
                        reservation_id,
                    };
                }
            }
            given_back.await;
        }
    }

    /// Restores the directory entry of every worker the registry records.
    ///
    /// A daemon that crashed between recording a worker and publishing its descriptor left a row
    /// with nothing on disk pointing at it. The row carries the key and the endpoint, which is
    /// everything a challenge needs, and the worker's own answer carries everything a descriptor
    /// needs.
    async fn recover_workers(&self) -> Result<()> {
        let rows = {
            let registry = self.registry.lock().await;
            registry.workers()?
        };
        for row in rows {
            if self.directory.lock().await.get(row.session_id).is_some() {
                continue;
            }
            // A fenced reservation is one the host stopped trusting. Publishing its worker again
            // because a descriptor happened to be missing would undo the fence through the back
            // door, so recovery leaves it alone and it stays out of the directory.
            let reservation = {
                let registry = self.registry.lock().await;
                registry.reservation_for_session(row.session_id)?
            };
            let Some(reservation) = reservation else {
                continue;
            };
            if reservation.phase == LaunchPhase::Fenced {
                continue;
            }
            // This row's own reservation, taken from whatever else would look at it. A challenge
            // here presents a generation token too, and one presented while that worker's own
            // report is being published fences the connection the daemon has just opened.
            let _held = self.hold_reservation(reservation.reservation_id).await;
            // The directory again, now that nothing else can be publishing into it: the report may
            // have landed while this row was waiting its turn.
            if self.directory.lock().await.get(row.session_id).is_some() {
                continue;
            }
            let Ok(endpoint) = Endpoint::from_path(&row.endpoint) else {
                continue;
            };
            match self
                .challenge(&endpoint, &row.public_key, row.session_id)
                .await
            {
                Ok(proof) => {
                    self.adopt(row.display_number, &row.public_key, &proof, &endpoint)
                        .await?;
                }
                // A worker that does not answer is not necessarily gone. Reconciliation asks the
                // kernel; only a confirmed death produces a closure record.
                Err(_) => {
                    let _ = self.reconcile(row.session_id).await;
                }
            }
        }
        Ok(())
    }

    /// Challenges a worker against a key this daemon already holds, and presents its generation.
    async fn challenge(
        &self,
        endpoint: &Endpoint,
        worker_public_key: &kr_protocol::scalars::AuthorisationKey,
        session_id: SessionId,
    ) -> Result<kr_protocol::worker::WorkerVerifyProof> {
        let identity = &self.identity;
        let generation = self.generation;
        let boot = self.boot_identity.clone();
        let endpoint_text = endpoint.as_text();
        tokio::time::timeout(crate::directory::RECONNECT_TIMEOUT, async move {
            let mut client =
                LocalClient::connect(endpoint, LocalClientKind::Controller, self.build_id.clone())
                    .await?;
            let proof = client
                .challenge_worker(
                    worker_public_key,
                    session_id,
                    SessionEpoch::V1,
                    &endpoint_text,
                )
                .await?;
            client
                .present_generation(move |nonce| {
                    identity
                        .generation_token(generation, &boot, nonce)
                        .map_err(kr_ipc::IpcError::from)
                })
                .await?;
            Ok::<_, ControllerError>(proof)
        })
        .await
        .map_err(|_| {
            ControllerError::supervision("the worker did not answer its challenge in time")
        })?
    }

    /// Records a recovered worker and republishes its descriptor.
    async fn adopt(
        &self,
        display_number: kr_protocol::session::DisplayNumber,
        worker_public_key: &kr_protocol::scalars::AuthorisationKey,
        proof: &kr_protocol::worker::WorkerVerifyProof,
        endpoint: &Endpoint,
    ) -> Result<()> {
        let record = WorkerRecord {
            session_id: proof.session_id,
            display_number,
            public_key: *worker_public_key,
            process_identity: proof.process_start_identity.clone(),
            endpoint: proof.endpoint.clone(),
            profile: WorkerProfile::HeadlessUser,
            state: SessionState::Live,
            // A worker starts having acknowledged nothing. The first announcement it receives is
            // what moves this.
            acknowledged_revision: kr_protocol::ids::AuthorityRevision::new(0),
        };
        {
            let mut registry = self.registry.lock().await;
            registry.adopt_worker(&record)?;
        }
        let descriptor = WorkerDescriptor {
            session_id: proof.session_id,
            session_epoch: proof.session_epoch,
            environment_id: self.paths.environment_id(),
            display_number,
            boot_identity: proof.boot_identity.clone(),
            process_start_identity: proof.process_start_identity.clone(),
            protocol_version: proof.protocol_version,
            endpoint: proof.endpoint.clone(),
            worker_public_key: *worker_public_key,
            worker_profile: WorkerProfile::HeadlessUser,
            published_at_ms: kr_ipc::now_ms(),
        };
        kr_ipc::descriptor::publish(&self.paths, &descriptor)?;
        self.directory.lock().await.insert(KnownWorker {
            descriptor,
            endpoint: endpoint.clone(),
        });
        Ok(())
    }

    /// Returns the generation this daemon speaks for.
    #[must_use]
    pub const fn generation(&self) -> ControllerGeneration {
        self.generation
    }

    /// Tells every worker holding a close for this action that the caller has its acceptance.
    ///
    /// The worker cannot know when the daemon finished passing the reply on, and it must not
    /// signal a process group whose command is still waiting to read its own answer.
    async fn confirm_delivery(&self, action_id: kr_protocol::ids::ActionId) {
        let links: Vec<(SessionId, Arc<tokio::sync::Mutex<Option<LocalClient>>>)> = self
            .connections
            .lock()
            .await
            .iter()
            .map(|(session_id, link)| (*session_id, Arc::clone(link)))
            .collect();
        for (session_id, link) in links {
            let mut held = link.lock().await;
            if let Some(client) = held.as_mut()
                && client.confirm_delivery(action_id).await.is_err()
            {
                *held = None;
                self.lost_control_path(session_id);
            }
        }
    }

    /// Announces the environment's current authority revision to every worker it knows about.
    ///
    /// A revocation is not complete when the daemon records it. It is complete for a worker when
    /// that worker has acknowledged the revision that removed the authority **and** fenced the
    /// undispatched actions it affects, or when the worker is confirmed ended. Anything else is
    /// pending, and this reports which, along with every action whose dispatch transition had
    /// already won the serial race and may therefore have executed.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read or written.
    pub async fn announce_authority_revision(&self) -> Result<RevocationBarrier> {
        let revision = {
            let registry = self.registry.lock().await;
            registry.authority_revision()?
        };
        let workers: Vec<KnownWorker> = self.directory.lock().await.iter().cloned().collect();
        // Membership comes from the registry, not from the verified directory. A worker whose
        // challenge failed, or that this daemon has never reached, is outside the directory and
        // still durably recorded: a revocation is not complete for a worker this daemon cannot
        // account for, and reporting over the directory alone would let a replacement daemon that
        // has reached nobody report success.
        let known: Vec<SessionId> = {
            let registry = self.registry.lock().await;
            registry
                .workers()?
                .into_iter()
                .map(|worker| worker.session_id)
                .collect()
        };
        let mut attempted: Vec<SessionId> = Vec::new();
        for worker in workers {
            let session_id = worker.descriptor.session_id;
            attempted.push(session_id);
            // The binding is taken before the announcement travels, so an acknowledgement that
            // arrives over a control path this daemon has already given up on lifts nothing.
            // The control path is registered before the announcement travels, so an
            // acknowledgement is measured against a binding this daemon actually holds. Without
            // it a replacement daemon would compare every answer against a binding of zero.
            let binding = self.leases.bind(session_id);
            let outcome = {
                match tokio::time::timeout(WORKER_EXCHANGE, self.worker_client(&worker)).await {
                    Ok(Ok(mut held)) => {
                        let client = held.as_mut().expect("the connection is open");
                        // Bounded, because a worker that will not answer must not stop the
                        // revocation from reporting `pending` for it, and must not stop the
                        // announcement reaching the workers after it. Section 9 makes waiting the
                        // opposite of completion.
                        let answered = tokio::time::timeout(
                            WORKER_EXCHANGE,
                            client.announce_revision(
                                kr_protocol::worker::AuthorityRevisionNotice {
                                    environment_id: self.paths.environment_id(),
                                    revision,
                                    evidence_from: 0,
                                },
                            ),
                        )
                        .await;
                        match answered {
                            Ok(Ok(ack)) => Some(ack),
                            Ok(Err(_)) | Err(_) => {
                                // An exchange that failed or ran out leaves a client whose stream
                                // position nothing knows, so it is retired rather than returned.
                                *held = None;
                                self.leases.stop_renewal(session_id, binding);
                                None
                            }
                        }
                    }
                    Ok(Err(_)) | Err(_) => {
                        self.leases.stop_renewal(session_id, binding);
                        None
                    }
                }
            };
            match outcome {
                Some(ack) if ack.revision.get() >= revision.get() => {
                    // The barrier first, because it is what validates the binding: this
                    // announcement was made over one control path, and another exchange can lose
                    // that path and advance the binding while this one waits. Recording the
                    // acknowledgement in the registry before the barrier had judged it would let a
                    // stale answer move `revision_pending` even where the barrier refused it.
                    //
                    // Under the binding this announcement was made over, not whatever the binding
                    // is now.
                    // Whether this worker reported what its fence did, which is the half of the
                    // acknowledgement the durable row stands for. Recording the revision for a
                    // worker that said nothing about its fence would make `revision_pending` and
                    // the barrier disagree, and the barrier is the one section 9 defines.
                    let evidenced = ack.fence.is_some();
                    let accepted =
                        self.leases
                            .acknowledge(session_id, binding, ack.revision, ack.fence);
                    if accepted && evidenced {
                        {
                            let mut registry = self.registry.lock().await;
                            registry.record_acknowledged_revision(session_id, ack.revision)?;
                        }
                        // The evidence travels a page at a time, because one acknowledgement is
                        // one control frame. The barrier holds on the first page, which is the
                        // acknowledgement itself; what these further exchanges complete is the
                        // naming section 9 requires, and each one is bounded like the first.
                        self.collect_owed_evidence(session_id, binding, revision)
                            .await;
                    }
                }
                // A worker that is confirmed gone answers the question a different way: it can no
                // longer act under anything.
                _ => {
                    if self.reconcile(session_id).await?.is_some() {
                        self.leases.worker_ended(session_id);
                    }
                }
            }
        }
        // Every durably recorded worker the directory does not list. Those are the ones this
        // daemon has never reached or has given up on verifying, and the announcement cannot go to
        // them: what can still be established is whether they are gone. A worker confirmed ended
        // satisfies the barrier as surely as one that acknowledged, and one that is still running
        // stays pending rather than being left unaccounted for because nobody could see it.
        for session_id in &known {
            if attempted.contains(session_id) {
                continue;
            }
            if self.reconcile(*session_id).await?.is_some() {
                self.leases.worker_ended(*session_id);
            }
        }
        let report = self.leases.report(revision, known);
        // The one place a fence debt is settled. Every worker has acknowledged this revision or is
        // confirmed ended, which is the whole of what a completed revocation is; nothing else -
        // not an effect that succeeded, not a restart, not a document that stopped being usable -
        // may clear it.
        if report.holds() {
            self.registry.lock().await.settle_fence(revision)?;
        }
        Ok(report)
    }

    /// Asks a worker for the rest of the fence evidence it owes, a page at a time.
    ///
    /// The revision in force comes first, because that is the revocation someone is waiting on.
    /// After it come the older revocations whose names this daemon has not finished collecting: a
    /// page whose exchange failed before a newer revision was installed would otherwise never be
    /// asked for again, and section 9 requires the actions a fence could not take back to be named
    /// in *that* revocation's result. Every page in the whole sequence comes out of one budget, so
    /// a worker with several unfinished revocations cannot make one announcement unbounded.
    async fn collect_owed_evidence(
        &self,
        session_id: SessionId,
        binding: kr_transport::lease::WorkerBinding,
        revision: AuthorityRevision,
    ) {
        let mut budget = MAX_EVIDENCE_PAGES;
        self.collect_fence_evidence(session_id, binding, revision, &mut budget)
            .await;
        for older in self.leases.evidence_outstanding(session_id, revision) {
            if budget == 0 {
                return;
            }
            self.collect_fence_evidence(session_id, binding, older, &mut budget)
                .await;
        }
    }

    /// Asks a worker for the rest of one revocation's fence evidence, a page at a time.
    ///
    /// One page arrives with the acknowledgement; this is how the names that did not fit follow.
    /// It stops when the worker says nothing remains, when an exchange fails, or when the budget
    /// runs out: a worker that kept reporting names remaining would otherwise keep this daemon
    /// asking, and a revocation that cannot finish reporting is still a revocation that holds.
    async fn collect_fence_evidence(
        &self,
        session_id: SessionId,
        binding: kr_transport::lease::WorkerBinding,
        revision: AuthorityRevision,
        budget: &mut usize,
    ) {
        while *budget > 0 {
            *budget -= 1;
            let Some(from) = self.leases.evidence_owed(session_id, revision) else {
                return;
            };
            let notice = kr_protocol::worker::AuthorityRevisionNotice {
                environment_id: self.paths.environment_id(),
                revision,
                evidence_from: from,
            };
            let answered = {
                let Ok(Ok(mut held)) =
                    tokio::time::timeout(WORKER_EXCHANGE, self.worker_client_of(session_id)).await
                else {
                    self.lost_control_path(session_id);
                    return;
                };
                let Some(client) = held.as_mut() else {
                    return;
                };
                match tokio::time::timeout(WORKER_EXCHANGE, client.announce_revision(notice)).await
                {
                    Ok(Ok(ack)) => Some(ack),
                    Ok(Err(_)) | Err(_) => {
                        *held = None;
                        self.lost_control_path(session_id);
                        None
                    }
                }
            };
            let Some(ack) = answered else {
                return;
            };
            if !self
                .leases
                .acknowledge(session_id, binding, ack.revision, ack.fence)
            {
                return;
            }
        }
    }

    /// Advances the environment's authority revision and announces it.
    ///
    /// Advancing invalidates every outstanding dispatch lease at once, because a lease carries the
    /// revision it was issued at, and deregisters every connection admitted under the authority
    /// that has just been withdrawn. Both happen before the announcement travels, so nothing can
    /// be admitted under the old revision while the new one is on its way.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be written.
    pub async fn revoke_authority(&self) -> Result<RevocationBarrier> {
        // The store's lock order is the registry first, then the connections. Admission takes the
        // same two in the same order, so a connection cannot be registered against a revision this
        // has already replaced.
        let revision = {
            let mut registry = self.registry.lock().await;
            registry.advance_authority_revision()?;
            let revision = registry.authority_revision()?;
            let mut admitted = self.admitted_table();
            admitted.retain(|_, connection| connection.admitted_revision >= revision);
            drop(admitted);
            revision
        };
        self.leases.revoke(revision);
        // The registrations are gone; the connections that held them are told. A frame already
        // waiting for its peer is stopped by its connection closing, not by the next check.
        self.fence_network_connections().await;
        self.announce_authority_revision().await
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

    /// Revokes a grant, its descendants, and everything they were being used for.
    ///
    /// The order is the one section 10 requires and the one a revocation cannot be correct
    /// without. The grants go first, because a grant still in the store is a grant the next
    /// request would be decided against. Then the revision advances, which invalidates every
    /// outstanding dispatch lease at once and deregisters the connections admitted under the
    /// authority just withdrawn. Then the connections holding those registrations are fenced, so a
    /// subscription already open is closed rather than left reading. Then the revision is
    /// announced to every worker, and what comes back is the per-worker completion status: a
    /// revocation is complete for a worker once that worker has acknowledged the revision and
    /// fenced the undispatched actions it affects, or once it is confirmed ended.
    ///
    /// A revocation that withdrew nothing — the grant and its subtree were already revoked —
    /// advances no revision. Advancing one would fence every live connection on the host for a
    /// retry that changed nothing.
    ///
    /// `carried` is the admission of the mutation this revocation is performing, when it is
    /// performing one. It is checked again inside the transaction that withdraws the rows, once
    /// the rows have been read and immediately before the first of them changes: an admission has
    /// a deadline, and the wait for the store's lock and the read that follows it can each outlast
    /// one. The local owner's own revocation carries none.
    ///
    /// # Errors
    ///
    /// Returns an error when the grant store or the registry cannot be read or written, or when
    /// the admission has lapsed by the time the rows would be withdrawn.
    pub async fn revoke_grant(
        &self,
        grant_id: kr_protocol::ids::GrantId,
        carried: Option<&crate::authority::AdmittedMutation>,
    ) -> Result<kr_protocol::sharing::RevocationResult> {
        let now_ms = self.settled_now_ms();
        // The revocation writes its own fence debt inside the same transaction that revokes the
        // rows, so a failure afterwards leaves a record a retry can see. Nothing newly revoked is
        // not the same as nothing owed.
        //
        // The registry guard is held across the withdrawal and dropped before the fence, which
        // takes it again. It is what the admission is checked against, so holding it through the
        // write is what makes the check mean something at the moment of the write.
        let revocation = match carried {
            Some(carried) => {
                let registry = self.registry.lock().await;
                self.check_admission(&registry, carried)?;
                self.sharing.revoke(grant_id, now_ms, || {
                    self.check_admission(&registry, carried)
                })?
            }
            None => self.sharing.revoke(grant_id, now_ms, || Ok(()))?,
        };
        self.complete_revocation(revocation.revoked.iter().copied().collect(), now_ms)
            .await
    }

    /// Revokes every grant one device holds, then revokes the device itself.
    ///
    /// The grants go first for the same reason as above. What this does **not** do is withdraw
    /// that one device's network registration selectively: that is `net::Network::revoke_device`,
    /// which owns the in-memory registrations, and this daemon reaches it through the network
    /// entry point rather than from here. What happens instead is the daemon-wide fence, which is
    /// stricter rather than weaker: every registration is withdrawn and re-admitted at the
    /// revision now in force, and the revoked device's record is already marked so it cannot be
    /// re-admitted at all.
    ///
    /// `carried` is as [`Self::revoke_grant`]: the admission of the mutation this is performing.
    /// This withdrawal is more than one write and they are not in one store, so the admission is
    /// checked while it can still decide: before the grants are read, inside the transaction that
    /// withdraws them, and again before the device record when that transaction withdrew nothing
    /// and the record is therefore the whole withdrawal. Once something is withdrawn, the rest
    /// follows whatever the clock has done since, because a half-finished revocation is worse than
    /// a late one.
    ///
    /// # Errors
    ///
    /// Returns an error when the grant store, the device record or the registry cannot be written,
    /// or when the admission has lapsed before anything was withdrawn.
    pub async fn revoke_device_authority(
        &self,
        device_id: kr_protocol::ids::DeviceId,
        carried: Option<&crate::authority::AdmittedMutation>,
    ) -> Result<kr_protocol::sharing::RevocationResult> {
        let now_ms = self.settled_now_ms();
        // Every write this makes happens while the registry guard is held, and the guard goes
        // before the fence, which takes it again. The block is what drops it: nothing this holds
        // may be alive across the await below.
        let (revocation, lapsed, owes_fence) = {
            let registry = match carried {
                Some(carried) => {
                    let registry = self.registry.lock().await;
                    self.check_admission(&registry, carried)?;
                    Some(registry)
                }
                None => None,
            };
            let revocation = self.sharing.grants().revoke_device(device_id, now_ms, || {
                self.still_admitted(registry.as_deref(), carried)
            })?;
            // The device record is marked revoked before the revision advances, so nothing can be
            // authorised against it in between. The directory is a view on this daemon's own
            // registry database, which is the file the network half keeps its device records in.
            // A device can hold its grant in the pairing record and have no row in the grant
            // store, so its own withdrawal owes a fence in its own right, keyed by the device's
            // identity. The intent is written **before** the record changes, because a debt
            // recorded after a withdrawal that then failed to record would be a withdrawal nothing
            // fences.
            // The intent is written only when there is a withdrawal to fence, and once written it
            // is never taken back: a caller that decided its own work was done and deleted the row
            // could delete the row another caller was relying on. Reading the record first is what
            // keeps a repeat from fencing the host again, and two callers racing the first
            // revocation both fence, which is the harmless direction.
            //
            // Whether the admission still decides anything from here depends on what the
            // transaction above did. If it withdrew something, that is committed, and a deadline
            // passing afterwards is no reason to stop half way: grants withdrawn beside a device
            // record still live is the dangerous state, and a revocation takes authority away
            // rather than granting any, so finishing a late one is the safe direction. If it
            // withdrew nothing — the paired device whose grant lives in its pairing record — then
            // the record below is the whole withdrawal, nothing is committed, and each wait
            // between here and it gets its own check.
            let withdrew = !revocation.revoked.is_empty();
            if !withdrew {
                self.still_admitted(registry.as_deref(), carried)?;
            }
            let record_is_live = self
                .devices
                .record_for_device(device_id)?
                .is_some_and(|record| record.revoked_at_ms.is_none());
            if record_is_live {
                if !withdrew {
                    self.still_admitted(registry.as_deref(), carried)?;
                }
                self.sharing
                    .grants()
                    .owe_fence([kr_protocol::ids::GrantId::new(device_id.get())], now_ms)?;
            }
            // The last wait before the record is marked was the debt. A refusal here withdraws
            // nothing, but it leaves a fence owed, so it is answered *after* that fence rather
            // than in place of it.
            let lapsed = if withdrew {
                None
            } else {
                self.still_admitted(registry.as_deref(), carried).err()
            };
            if lapsed.is_none() {
                self.devices.revoke(device_id, TimestampMs::new(now_ms))?;
            }
            (revocation, lapsed, record_is_live)
        };
        match lapsed {
            // Nothing was withdrawn and nothing is owed, so there is nothing to finish.
            Some(error) if !owes_fence => Err(error),
            Some(error) => {
                self.complete_revocation(revocation.revoked.iter().copied().collect(), now_ms)
                    .await?;
                Err(error)
            }
            None => {
                self.complete_revocation(revocation.revoked.iter().copied().collect(), now_ms)
                    .await
            }
        }
    }

    /// Transfers control of a session, then fences what the transfer took away.
    ///
    /// The store's half is one transaction: the replacement is issued and the source revoked
    /// together. The daemon's half is the one every revocation takes, because a transfer *is* a
    /// revocation for the device that gave it up: the revision advances, the connections admitted
    /// under the old authority are fenced, and the answer carries the per-worker completion status.
    ///
    /// # Errors
    ///
    /// Returns an error when the transfer is refused or the registry cannot be written.
    pub async fn transfer_control(
        &self,
        plan: &crate::sharing::TransferPlan,
        confirmation: &crate::sharing::ConfirmedTransfer,
    ) -> Result<(
        crate::sharing::ControlTransfer,
        kr_protocol::sharing::RevocationResult,
    )> {
        let now_ms = self.settled_now_ms();
        let revision = self.policy().authority_revision();
        let transfer =
            self.sharing
                .transfer_control(plan, confirmation, &PairingTime, revision, now_ms)?;
        let completed = self
            .complete_revocation(transfer.revoked.revoked.iter().copied().collect(), now_ms)
            .await?;
        Ok((transfer, completed))
    }

    /// Advances the revision, fences what was admitted under it, and reports the barrier.
    ///
    /// Shared by both revocation paths so the order cannot drift between them.
    ///
    /// "Nothing changed" is not the same as "nothing is owed". A revocation that wrote its rows and
    /// then failed before the revision advanced leaves revoked authority and no fence, and a retry
    /// would see an empty set of *newly* revoked rows. So each half of a revocation writes its debt
    /// down by identity before the fence is attempted, and only a completed fence clears it.
    async fn complete_revocation(
        &self,
        revoked_grants: kr_protocol::scalars::CanonicalSet<kr_protocol::ids::GrantId>,
        now_ms: u64,
    ) -> Result<kr_protocol::sharing::RevocationResult> {
        let _ = now_ms;
        // Captured before the fence starts. A revocation that arrives while this fence is waiting
        // on a worker records its own debt, and clearing the whole table afterwards would retire
        // that one without ever fencing it.
        let covered = self.sharing.grants().fence_owed()?;
        if covered.is_empty() {
            // The work was already done and fenced. The answer is the revision in force and the
            // barrier as it stands, with nothing newly withdrawn. Both come from the barrier: it
            // reads the registry, which is where a revision is allocated, and a second reading
            // taken separately can be a different one — another revocation advances it, and so
            // does the network half. An answer that named one revision and carried a barrier for
            // another would be evidence of no single moment.
            let barrier = self.announce_authority_revision().await?;
            return Ok(kr_protocol::sharing::RevocationResult {
                authority_revision: barrier.authority_revision,
                revoked_grants,
                barrier,
            });
        }
        let barrier = self.revoke_authority().await?;
        self.update_policy(|policy| {
            policy.advance_authority_revision(barrier.authority_revision);
        })?;
        {
            // The feed numbers its entries from the same sequence the registry does, so a feed
            // entry cannot later claim a revision a local revocation has already used.
            let mut feed = self.authority_feed();
            feed.note_revision(barrier.authority_revision);
            self.sharing.grants().store_feed(&feed.snapshot())?;
        }
        // Last, because it is the record that this revocation's fence finished. Writing it before
        // the fence would let a failure in between look like completed work.
        self.sharing.grants().fence_completed(&covered)?;
        Ok(kr_protocol::sharing::RevocationResult {
            authority_revision: barrier.authority_revision,
            revoked_grants,
            barrier,
        })
    }

    /// Changes this host's policy and writes the result down.
    ///
    /// Every accepted change goes through here. A policy that could be changed without being
    /// persisted would come back as the previous one after an ordinary restart, which is the same
    /// failure as accepting a restored old policy by a different route.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the policy cannot be written.
    pub fn update_policy<T>(
        &self,
        change: impl FnOnce(&mut crate::grants::HostPolicy) -> T,
    ) -> Result<T> {
        // The lock is held across the write. Releasing it first would let two accepted changes
        // reach the store out of order and leave the older one on disk, which is the restriction
        // silently coming back after the next restart.
        let mut held = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // The change is made to a copy and published only once it is written down. Mutating the
        // live policy first would let a relaxation that failed to persist take effect anyway, and
        // an error the caller sees would be an error about something that happened.
        let mut candidate = held.clone();
        let value = change(&mut candidate);
        self.sharing.grants().store_policy(&candidate.snapshot())?;
        *held = candidate;
        Ok(value)
    }

    /// The reading this daemon decides expiry from.
    ///
    /// The later of this machine's clock and the highest reading this host has already decided
    /// from, and the floor rises with it. A clock wound back past a deadline therefore does not
    /// revive a grant this host has already refused.
    fn settled_now_ms(&self) -> u64 {
        let now_ms = kr_ipc::now_ms().get();
        // The floor is raised in memory first and kept whether or not the write succeeds. It only
        // ever moves forward, so publishing it before it is persisted can make this host stricter
        // and never laxer, and dropping it after a failed write would let the next reading be an
        // earlier one.
        let mut policy = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        policy.observe_utc(now_ms);
        let settled = policy.settled_now(now_ms);
        // Written while the lock is held, like every other accepted change, so two callers cannot
        // reach the store out of order and leave the older floor on disk. A failure leaves the
        // raised floor in memory, because a floor only moves forward and keeping it is the
        // stricter answer.
        let _ = self.sharing.grants().store_policy(&policy.snapshot());
        settled
    }

    /// Returns which workers have not yet acknowledged the environment's authority revision.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read.
    pub async fn revision_pending(&self) -> Result<Vec<SessionId>> {
        let registry = self.registry.lock().await;
        let revision = registry.authority_revision()?;
        Ok(registry
            .workers()?
            .into_iter()
            .filter(|worker| worker.acknowledged_revision.get() < revision.get())
            .map(|worker| worker.session_id)
            .collect())
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
        // An authority change this host already performed is answered from its record, here,
        // before freshness is asked for. Section 9 keeps a receipt readable after the window that
        // admitted it has expired, and a retry of a revocation that cannot reach its result would
        // otherwise be told its window is gone rather than what happened.
        if matches!(
            method,
            Method::GrantCreate | Method::GrantRevoke | Method::DeviceRevoke
        ) {
            return self.retained_authority_change(actor_id, mutation);
        }
        // A voice change is one of those records: section 9 keeps a receipt readable after the
        // window that admitted it has expired, and a retry that cannot reach its result would
        // otherwise be told its window is gone rather than what happened. A delegation is not
        // here, because it does not go through that store.
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
        // A fence this host owes and could not raise stops everything it would have fenced. The
        // revision did not advance, so the registry still reports every connection as admitted;
        // refusing here is what keeps work admitted under a withdrawn ceiling from being
        // dispatched while the withdrawal is still owed.
        if self
            .fence_unraised
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(ControllerError::PermissionDenied {
                detail: "this host's configuration withdrew authority and the fence that                          withdrawal owes could not be raised, so nothing admitted under it is                          dispatched; run kr doctor to see what stopped it"
                    .to_owned(),
            });
        }
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

    /// Records that a worker's control path was lost, wherever the loss was noticed.
    ///
    /// Renewal stops with the path. Section 9 ties renewal to the live binding rather than to a
    /// revision number, so every place that gives up on a worker's client says so here rather than
    /// leaving a lease renewable over a socket that has gone.
    fn lost_control_path(&self, session_id: SessionId) {
        let binding = self.leases.binding(session_id);
        self.leases.stop_renewal(session_id, binding);
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

    /// Refuses a mutation whose registration or accepted deadline has lapsed.
    ///
    /// These are the two answers a caller can have without waiting for anything, so this can be
    /// asked from inside work that has already begun — a blocking task, a service's own call —
    /// where taking the registry's asynchronous lock is not possible.
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
    /// Returns [`ControllerError::PermissionDenied`] for a registration that has been withdrawn or
    /// replaced, and [`ControllerError::WindowExpired`] for a deadline that has passed.
    pub(crate) fn check_registration(
        &self,
        admission: &crate::authority::AdmittedMutation,
    ) -> Result<()> {
        let admitted = self.admitted_table();
        let standing = admitted
            .get(&admission.connection_id)
            .map(|connection| connection.admitted_revision);
        drop(admitted);
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

    /// Returns what a worker needs to accept this daemon's authority.
    fn reconnect(&self) -> Reconnect<'_> {
        Reconnect {
            identity: &self.identity,
            generation: self.generation,
            boot_identity: &self.boot_identity,
            build_id: &self.build_id,
        }
    }

    /// Returns the environment's directories.
    #[must_use]
    pub const fn paths(&self) -> &EnvironmentPaths {
        &self.paths
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

    /// Returns the registry, for a module that needs to read the environment's own records.
    pub(crate) const fn registry_handle(&self) -> &Mutex<Registry> {
        &self.registry
    }

    /// Serves the owner-only rendezvous socket.
    ///
    /// # Errors
    ///
    /// Returns an error when accepting fails.
    pub async fn serve_rendezvous(self: Arc<Self>, listener: Listener) -> Result<()> {
        loop {
            let (connection, peer) = listener.accept().await?;
            let controller = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(error) = controller.rendezvous(connection, peer).await {
                    eprintln!("kr-controller: a worker rendezvous failed: {error}");
                }
            });
        }
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

    async fn rendezvous(&self, connection: Connection, peer: PeerIdentity) -> Result<()> {
        let (mut reader, mut writer) = split(connection, StreamKind::Control);
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        let hello: ControlFrame = reader.read_message().await?;
        let ControlFrame::Hello(hello) = hello else {
            return Err(ControllerError::rendezvous("the worker did not say hello"));
        };
        if hello.client != LocalClientKind::Worker {
            return Err(ControllerError::rendezvous(
                "only a worker's startup claim is accepted here",
            ));
        }
        let outcome = self
            .rendezvous_exchange(&mut reader, &mut writer, connection_id, &peer)
            .await;
        // A rendezvous connection is one exchange. Its window goes with it rather than staying
        // outstanding for the life of the daemon.
        self.windows.retire_connection(connection_id);
        outcome
    }

    async fn rendezvous_exchange(
        &self,
        reader: &mut kr_ipc::framed::FrameReader,
        writer: &mut kr_ipc::framed::FrameWriter,
        connection_id: ConnectionId,
        peer: &PeerIdentity,
    ) -> Result<()> {
        writer
            .write_message(&ControlFrame::HelloAck(self.acknowledgement(
                LocalRole::Rendezvous,
                self.issue_window(connection_id)?,
                peer,
            )))
            .await?;

        let claim: ControlFrame = reader.read_message().await?;
        let ControlFrame::Rendezvous(claim) = claim else {
            return Err(ControllerError::rendezvous(
                "the worker did not present a startup claim",
            ));
        };
        let specification = self.admit_rendezvous(&claim, peer).await?;
        writer
            .write_message(&ControlFrame::LaunchSpec(Box::new(specification)))
            .await?;

        let report: ControlFrame = reader.read_message().await?;
        let reservation_id = claim.reservation_id;
        match report {
            ControlFrame::WorkerReady(ready) => {
                self.record_ready(reservation_id, &claim, &ready).await?;
                self.resolve(reservation_id, Ok(ready)).await;
                Ok(())
            }
            ControlFrame::WorkerFailed(error) => {
                // A worker that says it could not start resolves its own claim, but only its own:
                // a reservation that was fenced while this report was in flight stays fenced,
                // because the report does not answer the question fencing asked.
                let mut registry = self.registry.lock().await;
                let resolved = registry.resolve_claim(reservation_id, LaunchPhase::Failed)?;
                drop(registry);
                // Only a reservation this report actually resolved. A fenced one is still
                // somebody's question, and the directory stays until it is answered.
                if resolved {
                    self.discard_worker_dir(claim.session_id);
                }
                self.resolve(reservation_id, Err(error)).await;
                Ok(())
            }
            _ => Err(ControllerError::rendezvous(
                "the worker did not report whether it started",
            )),
        }
    }

    async fn admit_rendezvous(
        &self,
        claim: &WorkerRendezvous,
        peer: &PeerIdentity,
    ) -> Result<WorkerLaunchSpec> {
        check_rendezvous(claim).map_err(ControllerError::rendezvous)?;
        {
            let registry = self.registry.lock().await;
            let reservation = registry
                .reservation(claim.reservation_id)?
                .ok_or_else(|| ControllerError::rendezvous("no reservation matches this claim"))?;
            if reservation.session_id != claim.session_id {
                return Err(ControllerError::rendezvous(
                    "the claim names a different session from its reservation",
                ));
            }
        }
        if claim.boot_identity != self.boot_identity {
            return Err(ControllerError::rendezvous(
                "the claim names a different boot",
            ));
        }
        // The launcher's identity is recorded as soon as the service manager reports it, which can
        // be after the worker has already connected. Waiting for it is not optional: without it
        // there is nothing to compare the connecting process against.
        let launcher = self.await_launch_identity(claim.reservation_id).await?;
        let peer_pid = peer
            .pid
            .ok_or_else(|| ControllerError::rendezvous("the platform did not report the peer"))?;
        if u64::from(peer_pid) != launcher.pid.get() {
            self.registry.lock().await.fence(claim.reservation_id)?;
            return Err(ControllerError::rendezvous(
                "the connecting process is not the one the launcher started",
            ));
        }
        // The kernel is asked about the process on the other end of this socket, now. A signed
        // claim only says what the worker believes about itself; reading the identity here is what
        // rules out a different process that happens to hold the same identifier.
        let connected = kr_ipc::identity::process_start_identity(peer_pid).map_err(|error| {
            ControllerError::rendezvous(format!(
                "the kernel would not describe the connecting process: {error}"
            ))
        })?;
        if connected != launcher {
            self.registry.lock().await.fence(claim.reservation_id)?;
            return Err(ControllerError::rendezvous(
                "the connecting process did not start when the launcher's did",
            ));
        }
        if claim.process_start_identity != connected {
            self.registry.lock().await.fence(claim.reservation_id)?;
            return Err(ControllerError::rendezvous(
                "the claim's process identity is not the connecting process's",
            ));
        }

        // Admission is consumed here, in one transaction, together with the key that authenticates
        // this worker from now on. Everything above is a check; this is the commitment.
        let reservation = {
            let mut registry = self.registry.lock().await;
            registry.claim_rendezvous(claim.reservation_id, claim.worker_public_key)?
        };
        let recorded = reservation.create_intent.as_deref().ok_or_else(|| {
            ControllerError::rendezvous(
                "this reservation has no recorded create request, so nothing can be launched from it",
            )
        })?;
        let create = recorded_create(recorded).map_err(|error| {
            ControllerError::registry(format!(
                "the recorded create request cannot be read: {error}"
            ))
        })?;

        // The package this worker will launch is resolved here, by the daemon, against the
        // package root the daemon is configured with. The worker is told which directory to read
        // rather than left to find one in its own environment: the two can differ, and a session
        // must run the package its create was admitted against.
        let shell_package = if create.shell_mode == kr_protocol::session::ShellMode::Managed {
            // On a thread that may block, for the same reason the admission check is: finding a
            // package reads directories and opens files, and a package root that has stopped
            // answering must not occupy one of the runtime's own threads.
            let root = self.shell_packages.clone();
            let requested = create.shell.0.clone();
            let resolved = tokio::task::spawn_blocking(move || {
                qualified_package(root.as_deref(), requested.as_deref())
            })
            .await
            .map_err(|error| ControllerError::supervision(error.to_string()))??;
            Nullable::some(resolved.display().to_string())
        } else {
            Nullable::null()
        };
        Ok(WorkerLaunchSpec {
            session_id: reservation.session_id,
            session_epoch: SessionEpoch::V1,
            environment_id: self.paths.environment_id(),
            display_number: reservation.display_number,
            create,
            shell_package,
            controller_public_key: *self.identity.public_key(),
            controller_generation: self.generation,
            release: self.release.clone(),
        })
    }

    /// Waits for the launcher's reported identity to reach the registry.
    async fn await_launch_identity(
        &self,
        reservation_id: ReservationId,
    ) -> Result<kr_protocol::identity::ProcessStartIdentity> {
        let deadline = std::time::Instant::now() + LAUNCH_IDENTITY_TIMEOUT;
        loop {
            {
                let registry = self.registry.lock().await;
                if let Some(reservation) = registry.reservation(reservation_id)?
                    && let Some(identity) = reservation.launcher_identity
                {
                    return Ok(identity);
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(ControllerError::rendezvous(
                    "the launcher did not report the worker's identity",
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    async fn record_ready(
        &self,
        reservation_id: ReservationId,
        claim: &WorkerRendezvous,
        ready: &WorkerReady,
    ) -> Result<()> {
        // This reservation, taken from whatever else might look at it. A report that arrives after
        // its create gave up on waiting is still this worker's own word, and a look that started
        // before it would otherwise challenge the worker while this is publishing it: two
        // connections to one worker, and the second generation token fences the first.
        let _held = self.hold_reservation(reservation_id).await;
        let mut registry = self.registry.lock().await;
        let reservation = registry
            .reservation(reservation_id)?
            .ok_or_else(|| ControllerError::rendezvous("the reservation vanished"))?;
        // The profile is the one the create request recorded, not a default: it decides what a
        // logout does to this session, and a record that said otherwise would promise the wrong
        // lifetime.
        let recorded = reservation.create_intent.as_deref().ok_or_else(|| {
            ControllerError::rendezvous(
                "this reservation has no recorded create request, so the session it would publish \
                 has no recorded execution context",
            )
        })?;
        let profile = recorded_create(recorded)
            .map_err(|error| {
                ControllerError::registry(format!(
                    "the recorded create request cannot be read: {error}"
                ))
            })?
            .worker_profile;
        let record = WorkerRecord {
            session_id: reservation.session_id,
            display_number: reservation.display_number,
            public_key: claim.worker_public_key,
            process_identity: claim.process_start_identity.clone(),
            endpoint: ready.endpoint.clone(),
            profile,
            state: SessionState::Live,
            // A worker starts having acknowledged nothing. The first announcement it receives is
            // what moves this.
            acknowledged_revision: kr_protocol::ids::AuthorityRevision::new(0),
        };
        // The key and the live phase are committed together: a registry that says a session is
        // live always knows which key answers for it.
        registry.record_worker(reservation_id, &record)?;
        drop(registry);

        let descriptor = WorkerDescriptor {
            session_id: reservation.session_id,
            session_epoch: SessionEpoch::V1,
            environment_id: self.paths.environment_id(),
            display_number: reservation.display_number,
            boot_identity: claim.boot_identity.clone(),
            process_start_identity: claim.process_start_identity.clone(),
            protocol_version: PROTOCOL_VERSION,
            endpoint: ready.endpoint.clone(),
            worker_public_key: claim.worker_public_key,
            worker_profile: profile,
            published_at_ms: kr_ipc::now_ms(),
        };
        kr_ipc::descriptor::publish(&self.paths, &descriptor)?;
        let endpoint = Endpoint::from_path(&ready.endpoint)?;
        self.directory.lock().await.insert(KnownWorker {
            descriptor,
            endpoint,
        });
        Ok(())
    }

    async fn resolve(
        &self,
        reservation_id: ReservationId,
        outcome: std::result::Result<WorkerReady, ProtocolError>,
    ) {
        if let Some(pending) = self.pending.lock().await.remove(&reservation_id) {
            let _ = pending.ready.send(outcome);
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
        })
    }

    /// Registers the voice coordinator beside the other services.
    ///
    /// After the daemon exists, because two of the coordinator's seams hold a weak reference back
    /// to it: a service built inside `Arc::new_cyclic` could not read a session or propose an
    /// effect, which is most of what those seams are for.
    ///
    /// The managed broker is configured only when an origin is set. A host without one is a
    /// complete host: a person's own provider credential and the agent already running in the
    /// session both still work, and `voice.start` says so rather than failing obscurely.
    fn start_voice(self: &Arc<Self>) {
        let authority = Arc::new(crate::voice::GrantAuthority::new(
            Arc::clone(&self.sharing),
            Arc::clone(&self.devices),
            self.sharing.host_device_id(),
        ));
        // Reaching a managed service needs an HTTP exchange, which the client library leaves to
        // the embedder: a desktop build, a mobile build and a test each reach the network
        // differently. An embedder attaches its own with `VoiceModule::with_provider`, and a host
        // with none brokers no managed call.
        let provider = None;
        let module = crate::voice::VoiceModule::new(
            Arc::new(crate::voice::ControllerFacts::new(self.me.clone())),
            authority,
            Arc::new(crate::voice::ControllerDispatch::new(self.me.clone())),
            provider,
            self.sharing.host_device_id(),
            self.paths.environment_id(),
            std::env::var(crate::voice::VOICE_BROKER_ORIGIN_VARIABLE).unwrap_or_default(),
        );
        let _ = self.voice.set(Arc::new(module));
    }

    /// The environment's voice service.
    ///
    /// # Panics
    ///
    /// Panics when the daemon has not finished starting, which no request path can observe: the
    /// endpoint is served after startup returns.
    #[must_use]
    pub fn voice(&self) -> &Arc<crate::voice::VoiceModule> {
        self.voice.get().expect("the voice service is registered")
    }

    /// The device a paired actor acts as, when this host knows one.
    ///
    /// A voice method is reachable from a paired device and nothing else, so the actor has to
    /// resolve to a device record before the coordinator sees it. An actor that resolves to no
    /// live device reaches nothing.
    pub(crate) fn paired_device(&self, actor_id: &ActorId) -> Option<kr_protocol::ids::DeviceId> {
        self.devices
            .devices()
            .ok()?
            .into_iter()
            .find(|record| record.is_paired() && &record.principal() == actor_id)
            .map(|record| record.device_id)
    }

    /// The facts the voice coordinator may read about one session.
    ///
    /// Read through this daemon's ordinary session read, so voice sees what any other reader sees
    /// and nothing more. What this daemon does not hold — the worker's semantic history and its
    /// pending decisions — is reported as unavailable rather than left out silently.
    ///
    /// Every item carries the moment its content was produced, because that moment is what a
    /// grant's history lower bound is checked against. The shell a session runs and the directory
    /// it started in are fixed when the session is created, so the creation time is theirs; a fact
    /// this daemon cannot place in time is withheld rather than stamped with the moment it was
    /// read, which would let a retained summary of a session that closed long ago pass a bound
    /// written after it.
    pub(crate) async fn voice_session_snapshot(
        self: &Arc<Self>,
        session_id: SessionId,
    ) -> Result<crate::voice::SessionSnapshot> {
        let params = ParamsValue::from_typed(&SessionReadParams { session_id })
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let read: SessionReadResult = parse(&self.session_read(&params).await?)?;
        Ok(crate::voice::snapshot_of(&read.session, session_id))
    }

    /// Performs one voice proposal under the method the registry lists for its effect.
    ///
    /// The reads this daemon serves are performed here, as the device that asked and under the
    /// authority that admitted the proposal, checked again immediately before the effect and again
    /// before the answer is served. A proposal waits for the coordinator's own checks, for a
    /// confirmation and for this dispatch, and authority withdrawn inside any of those waits has
    /// to stop it: what the contract forbids is *serving* that state, not reading it.
    ///
    /// Everything else belongs to the worker's own dispatch, which this daemon does not forward,
    /// so it is **admitted and not performed**: section 15 ¶10 makes the receipt the authority, and
    /// reporting an effect this daemon did not cause would be the exact mistake that paragraph
    /// forbids.
    pub(crate) async fn voice_perform(
        self: &Arc<Self>,
        method: Method,
        proposal: &kr_voice::Proposal,
    ) -> Result<kr_voice::seams::HostReceipt> {
        let action_id = proposal.action_id;
        if method == Method::SessionRead {
            let session_id = proposal.session_id.ok_or_else(|| {
                ControllerError::InvalidArgument("that action names a session".to_owned())
            })?;
            let _ = self.voice_authority_now(proposal, session_id)?;
            let params = ParamsValue::from_typed(&SessionReadParams { session_id })
                .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
            let read: SessionReadResult = parse(&self.session_read(&params).await?)?;
            let narrowed = self.voice_authority_now(proposal, session_id)?;
            // The same bound the context path applies, and the answer is built from what it
            // admitted and from nothing else. A session's description carries its number and the
            // shell it runs, and both are facts from the moment it was created: naming them after
            // the filter had withheld them would be the way round the bound rather than an answer
            // under it. Whether a session that is still running is running is a fact about now,
            // so it travels with a description the bound admitted.
            let live = read.session.state != kr_protocol::session::SessionState::Closed;
            let state = read.session.state.as_str().to_owned();
            let filtered = crate::voice::filtered(
                crate::voice::snapshot_of(&read.session, session_id),
                &narrowed,
            );
            let summary = match (filtered.session_description, filtered.working_directory) {
                (None, _) => "this grant's history does not reach that session".to_owned(),
                (Some(description), directory) => {
                    let mut summary = description.text;
                    if live {
                        summary.push_str(" is ");
                        summary.push_str(&state);
                    }
                    match directory {
                        Some(directory) => {
                            summary.push_str(" in ");
                            summary.push_str(&directory.text);
                        }
                        None => {
                            summary.push_str("; where it runs is outside what this grant may see");
                        }
                    }
                    summary
                }
            };
            return Ok(kr_voice::seams::HostReceipt {
                action_id,
                performed: true,
                summary,
            });
        }
        Ok(kr_voice::seams::HostReceipt {
            action_id,
            performed: false,
            summary: format!(
                "{} belongs to the session's worker, which this host does not dispatch",
                method.as_str()
            ),
        })
    }

    /// Performs one voice mutation exactly once for its action identifier.
    ///
    /// Section 23 marks the four voice mutations action-deduplicated, and three of them are not
    /// safe to repeat: a second `voice.grant` would replace the grant the first one wrote and end
    /// the calls started under it, and a second `voice.stop` would find nothing. The claim and the
    /// retained answer are the same ones this host already keeps for an authority change, because
    /// a voice grant is a grant in that same store.
    ///
    /// # Errors
    ///
    /// Returns the refusal the caller is given.
    pub(crate) async fn voice_mutation(
        self: &Arc<Self>,
        actor_id: &ActorId,
        actor: crate::voice::VoiceActor,
        mutation: &MutationRequest,
        method: Method,
        authority_revision: AuthorityRevision,
        accepted: kr_transport::window::AcceptedDeadline,
    ) -> Result<ParamsValue> {
        // The deadline this mutation was admitted under, as a question the coordinator can ask
        // rather than a figure it has to convert. Everything after this waits — for the claim, for
        // the coordinator's own lock, for the store, for the broker — and the write at the end of
        // those waits is what has to be inside the lifetime the host accepted, not merely the
        // dispatch that began it. The reading is this daemon's own continuous clock, which is the
        // clock the deadline is measured on and the one nothing outside this process can move.
        let admission = AdmittedUntil {
            controller: Arc::clone(self),
            deadline: accepted.deadline,
        };
        // A delegation does not go through this host's action store at all, and cannot yet: the
        // answer to a first submission of an action that needs a confirmation is the challenge, a
        // claim taken before that answer is held for longer than the confirmation itself lives,
        // and the store has no way to give a claim back. It is not read here either, because an
        // answer that store holds for a delegation is one an earlier build wrote and is content
        // whose authority nothing on this path re-checks. What makes one delegation one action is
        // the coordinator's own rule, taken under its lock before it waits for anything; the gap
        // that leaves is in the handoff with what closing it needs.
        if method == Method::VoiceDelegate {
            return self
                .voice()
                .answer(
                    actor,
                    mutation,
                    method,
                    authority_revision,
                    wall_clock_ms(),
                    &admission,
                )
                .await;
        }
        // What this action already produced, if it produced anything. Answered before the claim,
        // so a retry of a completed change is its own result rather than a conflict.
        if let Some(answered) = self.voice_answered(actor_id, mutation).await? {
            return Ok(answered);
        }
        match self.claim_voice_action(actor_id, mutation)? {
            Ok(()) => {}
            Err(answered) => return Ok(answered),
        }
        let result = self
            .voice()
            .answer(
                actor,
                mutation,
                method,
                authority_revision,
                wall_clock_ms(),
                &admission,
            )
            .await?;
        self.retain_authority_change(actor_id, mutation, &result)?;
        Ok(result)
    }

    /// The digest one voice action is claimed and answered under.
    ///
    /// The mutation's own digest. A delegation does not reach this: a confirmation is bound to the
    /// request that asked for it, so its signed resubmission is the same action carrying a
    /// different payload, which is what a payload digest refuses.
    fn voice_action_digest(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Result<kr_protocol::scalars::Digest256> {
        kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Claims one voice action for this attempt, or answers with what it already produced.
    fn claim_voice_action(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Result<std::result::Result<(), ParamsValue>> {
        let digest = self.voice_action_digest(actor_id, mutation)?;
        match self.sharing.grants().claim_action(
            actor_id,
            mutation.action_id,
            &digest,
            kr_ipc::now_ms().get(),
        )? {
            crate::grants::ActionClaim::Claimed { .. } => Ok(Ok(())),
            // Somebody else is inside this action. Performing it again would be two effects under
            // one identity, and this is not a conflict: the payload is the same one, so the answer
            // is transient and the caller retries for it.
            crate::grants::ActionClaim::InFlight => Err(ControllerError::Refused {
                code: ErrorCode::ResourceUnavailable,
                detail: "that action is already running on this host".to_owned(),
            }),
            crate::grants::ActionClaim::Answered { result } => {
                let value = kr_cbor::decode(&result, &kr_cbor::Limits::DEFAULT)
                    .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
                Ok(Err(ParamsValue::new(value)))
            }
        }
    }

    /// What one voice action already produced, when this host has its answer.
    ///
    /// The three voice changes this answers for name no session and carry no content about one:
    /// what each produced is the grant it wrote, the call it created or the call it ended. A
    /// delegation does not reach this, because its answer can carry content about a session and
    /// nothing on this path re-checks the authority that content was found under.
    async fn voice_answered(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Result<Option<ParamsValue>> {
        let digest = self.voice_action_digest(actor_id, mutation)?;
        let Some(result) =
            self.sharing
                .grants()
                .answered_action(actor_id, mutation.action_id, &digest)?
        else {
            return Ok(None);
        };
        let value = kr_cbor::decode(&result, &kr_cbor::Limits::DEFAULT)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        Ok(Some(ParamsValue::new(value)))
    }

    /// Checks that the authority a voice proposal was admitted under still stands, now.
    ///
    /// Three things, on this host's one authority store: the device is still paired, the voice
    /// grant the coordinator admitted it under is still live and still reaches the session, and
    /// the device's own ordinary grant still carries what the action needs. The intersection is
    /// `kr_voice::permits`, which is the same rule the coordinator applied, so this is the same
    /// decision taken again rather than a second rule that could disagree with it.
    fn voice_authority_now(
        &self,
        proposal: &kr_voice::Proposal,
        session_id: SessionId,
    ) -> Result<kr_protocol::grant::Grant> {
        use kr_voice::seams::VoiceAuthority as _;

        let denied = |detail: &str| ControllerError::PermissionDenied {
            detail: detail.to_owned(),
        };
        let paired = self
            .devices
            .record_for_device(proposal.device_id)?
            .is_some_and(|record| record.is_paired());
        if !paired {
            return Err(denied("this device is no longer paired with this host"));
        }
        let now_ms = wall_clock_ms();
        let authority = crate::voice::GrantAuthority::new(
            Arc::clone(&self.sharing),
            Arc::clone(&self.devices),
            self.sharing.host_device_id(),
        );
        let store = |error: kr_voice::VoiceError| ControllerError::Refused {
            code: error.code(),
            detail: error.to_string(),
        };
        let voice_grant = authority
            .grant(proposal.voice_grant_id, now_ms)
            .map_err(store)?
            .ok_or_else(|| denied("the voice grant this action was admitted under has ended"))?;
        if !voice_grant.expiry.is_valid_at(now_ms)
            || !voice_grant.session_selector.admits(session_id)
        {
            return Err(denied(
                "the voice grant this action was admitted under no longer reaches that session",
            ));
        }
        let device_grant = authority
            .device_grant(proposal.device_id, Some(session_id), now_ms)
            .map_err(store)?
            .ok_or_else(|| denied("this device's grant no longer covers that session"))?;
        if !kr_voice::permits(&voice_grant, &device_grant, proposal.action) {
            return Err(denied(
                "the authority this action was admitted under no longer carries it",
            ));
        }
        // The narrower of the two history scopes, which is what any content this effect answers
        // with is filtered under.
        Ok(kr_voice::narrower_history(&device_grant, &voice_grant))
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
            _ if crate::voice::VoiceModule::serves(method) => {
                crate::voice::VoiceModule::check_subject(method, mutation)?;
            }
            _ if crate::transfer::TransferModule::serves(method) => {
                crate::transfer::TransferModule::check_subject(method, mutation)?;
            }
            _ if crate::project::ProjectModule::serves(method) => {
                crate::project::ProjectModule::check_subject(method, mutation)?;
            }
            _ if crate::changeset::ChangeSetModule::serves(method) => {
                crate::changeset::ChangeSetModule::check_subject(method, mutation)?;
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
        // authority the other door refuses the same mutation under. Only the project path uses it;
        // every other effect still reads it where its own transaction does.
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
        if retained.is_none() && crate::changeset::ChangeSetModule::serves(method) {
            retained = self.changesets.retained(actor_id, &mutation, method).await;
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
    /// lock held across the answer for the reason [`Self::check_admission`] states, and again
    /// inside the service's own work through [`Self::check_registration`], which is the last thing
    /// this daemon does before the action is performed. What neither covers is the service's own
    /// preparation, which happens after both; the comment on the second answer says what that
    /// leaves.
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
        // own result while a first admission does not begin under authority that has gone.
        //
        // What neither answer covers is the service's own preparation: resolving a destination and
        // taking the store's lock both happen inside the call below, after this. Section 9 asks
        // for authority and expiry to be revalidated *immediately before* the effect, and says
        // outright that durable acceptance does not preserve expired authority, so an action that
        // begins in that window is a gap rather than something the section allows. Closing it
        // means asking inside the service's own transaction, which the service would have to
        // offer; `docs/host/README.md` states the gap.
        let controller = Arc::clone(self);
        let admission = move || {
            controller
                .check_registration(&carried)
                .map_err(|error| error.to_protocol_error())
        };
        self.project
            .write(actor_id, mutation, method, admission)
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
        if crate::changeset::ChangeSetModule::serves(method) {
            return self.changesets.read_frame(request).await;
        }
        // The diagnostics are two answers, not one. The owner at their own machine is shown the
        // paths this host resolved and the names they chose, because that is a person asking their
        // own host where its files are; everything else that reaches a read arrived over the
        // network, and what leaves for somebody else to read carries each value on its class's
        // terms. The two are separated here rather than inside each answer, so a diagnostic added
        // later cannot forget which one it is.
        let owner = is_owners_own_socket(actor_id);
        let outcome = match method {
            Method::HostInfo => self.host_info().await,
            Method::EnvironmentCapabilities => {
                self.environment_capabilities(&request.params, owner).await
            }
            Method::EnvironmentList => self.environment_list().await,
            Method::HostDoctor => self.host_doctor(owner).await,
            Method::SessionList => self.session_list(&request.params).await,
            Method::SessionRead => self.session_read(&request.params).await,
            // A closed or crashed session's history and receipts are the archive's, and it serves
            // them with no worker. A live session's are its worker's, and this daemon says which
            // endpoint to ask rather than reading another process's journal behind its back.
            Method::HistoryPage => self.archive_history_page(&request.params).await,
            Method::ActionRead => self.archive_action_read(actor_id, &request.params).await,
            Method::AgentToolsStatus => self.agent_tools_status(&request.params),
            Method::GrantList => self.grant_list(&request.params),
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
        if crate::transfer::TransferModule::serves(method) {
            // The stored subject is read first, because reading it waits: for a blocking thread
            // and for the journal's lock. Then the admission is checked, so that check is the last
            // thing between this mutation and its effect rather than one more thing with waits
            // after it.
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
            // Everything between the envelope check and this point can wait: for this task to be
            // scheduled, for a blocking thread, for the subject read above. An action whose
            // accepted deadline passed while it queued does not go on to write, and neither does
            // one whose connection lost its authority in the meantime.
            //
            // A mutation carrying no freshness at all is refused here too. This service answers
            // its own retained actions before this point, so anything still travelling is a first
            // admission, and a first admission needs a deadline it was admitted under.
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
            return self.transfer.write_frame(actor_id, mutation, method).await;
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
                    accepted,
                )
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
                self.project_mutation(actor_id, mutation, method, carried)
                    .await,
            );
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
            let answered = self
                .changesets
                .write_frame(actor_id, mutation, method)
                .await;
            // The effect and its reply are separated by everything a blocking task waits for, and
            // a revocation can land in that interval. What this host must not do is **disclose**
            // an answer under authority that has since been withdrawn, so the check is made again
            // here, where the reply is about to go out. What it does not undo is the effect: the
            // admission the service's own transaction would have to carry is the host action
            // contract's, which T-020 owns, and this service has the same gap the project and
            // transfer services have.
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
            Method::AgentToolsInstall | Method::AgentToolsRemove => {
                self.agent_tools_change(actor_id, mutation, method, connection_id, accepted)
                    .await
            }
            Method::GrantCreate | Method::GrantRevoke | Method::DeviceRevoke => {
                self.authority_change(actor_id, mutation, method, carried)
                    .await
            }
            _ => Err(ControllerError::InvalidArgument(format!(
                "{} is not a mutation this daemon serves",
                method.as_str()
            ))),
        };
        respond(mutation.request_id, outcome)
    }

    /// Answers an authority change this host has already performed, before freshness is asked for.
    ///
    /// Only a completed record answers here. A claim with no result is somebody inside the effect,
    /// and this path says nothing about it: the claim is taken where the effect happens, under the
    /// admission this mutation carries.
    fn retained_authority_change(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Option<ControlFrame> {
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id).ok()?;
        match self
            .sharing
            .grants()
            .answered_action(actor_id, mutation.action_id, &digest)
        {
            Ok(Some(result)) => {
                let value = kr_cbor::decode(&result, &kr_cbor::Limits::DEFAULT).ok()?;
                Some(ControlFrame::Response(Response {
                    request_id: mutation.request_id,
                    outcome: Outcome::Ok(ParamsValue::new(value)),
                }))
            }
            Ok(None) => None,
            Err(error) => Some(respond(mutation.request_id, Err(error))),
        }
    }

    /// What a claim on one authority change found.
    ///
    /// Either this caller now holds the claim, with the moment it was made, or the change already
    /// happened and this is what it produced.
    fn claim_authority_change(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Result<std::result::Result<u64, ParamsValue>> {
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        match self.sharing.grants().claim_action(
            actor_id,
            mutation.action_id,
            &digest,
            kr_ipc::now_ms().get(),
        )? {
            crate::grants::ActionClaim::Claimed { claimed_at_ms } => Ok(Ok(claimed_at_ms)),
            // Somebody else is inside this action. Performing it again would advance the revision
            // twice for one withdrawal, and this is not a conflict: the payload is the same one,
            // so the answer is transient and the caller retries for it. An attempt that crashed
            // releases its claim once the mutation's own maximum lifetime has passed.
            crate::grants::ActionClaim::InFlight => Err(ControllerError::Refused {
                code: ErrorCode::ResourceUnavailable,
                detail: "another attempt under this action identifier has not finished".to_owned(),
            }),
            crate::grants::ActionClaim::Answered { result } => {
                let value = kr_cbor::decode(&result, &kr_cbor::Limits::DEFAULT)
                    .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
                Ok(Err(ParamsValue::new(value)))
            }
        }
    }

    /// Records what a claimed authority change produced. A completed receipt is never replaced.
    fn retain_authority_change(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        result: &ParamsValue,
    ) -> Result<()> {
        self.sharing.grants().retain_result(
            actor_id,
            mutation.action_id,
            &kr_cbor::encode(result.as_value()),
            kr_ipc::now_ms().get(),
        )
    }

    /// Lists the grants this host's owner may see.
    ///
    /// A local caller is the operating-system owner of this environment, so the issuer it lists
    /// grants for is this host itself: the grants it issued, and everything delegated from them.
    fn grant_list(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: kr_protocol::sharing::GrantListParams = parse(params)?;
        let result = self.sharing.list_for_issuer(
            self.host_device_id(),
            params.session_id.as_ref().copied(),
            params.include_resolved,
            self.settled_now_ms(),
        )?;
        encode(&result)
    }

    /// Lists the paired devices, with each one's last authority acknowledgement.
    ///
    /// Section 10 puts the acknowledgement in the list because an offline host cannot apply a
    /// revocation it has not received, and a person deciding whether a revocation has taken effect
    /// needs to see which hosts have answered. The feed's staleness is beside it for the same
    /// reason: a list that looked current because nothing had contradicted it would be worse than
    /// no list.
    async fn device_list(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: kr_protocol::sharing::DeviceListParams = parse(params)?;
        let records = self.devices.devices()?;
        let status = self.authority_feed().status();
        // The revision in force is the registry's. The feed's accepted revision is what it has
        // seen and the policy's is what it was last told, and either can be behind the allocator
        // after a revocation this daemon took by another path.
        let authority_revision = {
            let registry = self.registry.lock().await;
            registry.authority_revision()?
        };
        let mut devices = Vec::new();
        for record in records {
            if record.revoked_at_ms.is_some() && !params.include_revoked {
                continue;
            }
            let acknowledged = self.authority_feed().last_acknowledgement(record.device_id);
            devices.push(kr_protocol::sharing::DeviceSummary {
                device_id: record.device_id,
                display_name: record.device_name.as_str().to_owned(),
                grant_id: record.grant.grant_id,
                paired_at_ms: record.paired_at_ms,
                acknowledged_revision: kr_protocol::scalars::Nullable(acknowledged),
                acknowledged_at_ms: kr_protocol::scalars::Nullable::null(),
                revoked: record.revoked_at_ms.is_some(),
            });
        }
        devices.sort_by_key(|device| device.device_id);
        encode(&kr_protocol::sharing::DeviceListResult {
            devices,
            authority_revision,
            feed_synchronised_at_ms: status.last_synchronised_at_ms,
            feed_stale: status.stale,
        })
    }

    /// Performs one authority change under a durable claim, and records what it produced.
    ///
    /// The claim comes first. An authority change is exactly the effect a retry must not repeat:
    /// two `grant.revoke` calls under one action identifier would otherwise advance the revision
    /// twice and fence the host twice for one withdrawal. A claim this host already answered is
    /// answered again from its record rather than performed a second time.
    async fn authority_change(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<ParamsValue> {
        let claimed_at_ms = match self.claim_authority_change(actor_id, mutation)? {
            Ok(claimed_at_ms) => claimed_at_ms,
            Err(answered) => return Ok(answered),
        };
        let result = match method {
            Method::GrantCreate => self.grant_create(mutation, carried, claimed_at_ms).await?,
            Method::GrantRevoke => self.grant_revoke(mutation, carried).await?,
            Method::DeviceRevoke => self.device_revoke(mutation, carried).await?,
            _ => {
                return Err(ControllerError::InvalidArgument(format!(
                    "{} is not an authority change this daemon serves",
                    method.as_str()
                )));
            }
        };
        self.retain_authority_change(actor_id, mutation, &result)?;
        Ok(result)
    }

    /// Shares a session: compiles the role, previews it, and writes the grant and its invitation.
    async fn grant_create(
        &self,
        mutation: &MutationRequest,
        carried: crate::authority::AdmittedMutation,
        claimed_at_ms: u64,
    ) -> Result<ParamsValue> {
        let params: kr_protocol::sharing::GrantCreateParams = parse(&mutation.params)?;
        if params.owner_confirmation.is_present() {
            return Err(ControllerError::InvalidArgument(
                "an owner confirmation is completed through the owner-confirmation methods, and \
                 a local caller acts under its authenticated operating-system identity"
                    .to_owned(),
            ));
        }
        // A host that cannot show the issuer the screen does not share the screen. Section 25
        // requires the preview to show what is being shared, and this daemon holds no screen
        // content of its own: the worker does. An invitation that included it here would be one
        // whose issuer was shown nothing.
        if params.selection.include_live_screen {
            return Err(ControllerError::InvalidArgument(
                "this host cannot preview the screen this invitation would share, so it does not \
                 share it"
                    .to_owned(),
            ));
        }
        // The identities are derived from the action the caller named, not minted fresh. A retry
        // therefore asks for the same grant and the same invitation, and finds the ones it already
        // created rather than making a second pair.
        let action = mutation.action_id.get();
        let request = crate::sharing::ShareRequest {
            invitation_id: kr_protocol::ids::InvitationId::new(Self::derived_identity(
                action,
                b"invitation",
            )),
            grant_id: kr_protocol::ids::GrantId::new(Self::derived_identity(action, b"grant")),
            environment_id: self.paths.environment_id(),
            session_id: params.session_id,
            issuer_device_id: self.host_device_id(),
            recipient_device_id: params.recipient_device_id,
            parent_grant_id: params.parent_grant_id.as_ref().copied(),
            selection: params.selection.clone(),
            lifetime_ms: params.lifetime_ms.as_ref().map(|lifetime| lifetime.get()),
            accepted_notices: params.accepted_notices.clone(),
            live_screen: None,
            named_questions: Vec::new(),
            named_approvals: Vec::new(),
            authority_revision: self.policy().authority_revision(),
            owner_confirmed: false,
            // The moment the claim was made, not the moment this attempt reached here. A retry
            // therefore proposes the same grant with the same deadline rather than a newer one.
            now_ms: claimed_at_ms,
        };
        // The admission is checked under the registry lock, and again inside the transaction that
        // writes the grant. Between the two are the preview, the delegation checks and the wait
        // for the grant store's own lock, and a window that was open when this began can be shut
        // by the time the write happens.
        let registry = self.registry.lock().await;
        self.check_admission(&registry, &carried)?;
        let result = self
            .sharing
            .share(&request, || self.check_admission(&registry, &carried))?;
        drop(registry);
        encode(&result)
    }

    /// Revokes a grant, its descendants, and everything they were being used for.
    async fn grant_revoke(
        &self,
        mutation: &MutationRequest,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<ParamsValue> {
        let params: kr_protocol::sharing::GrantRevokeParams = parse(&mutation.params)?;
        encode(&self.revoke_grant(params.grant_id, Some(&carried)).await?)
    }

    /// Revokes a device, every grant it holds, and everything they were being used for.
    async fn device_revoke(
        &self,
        mutation: &MutationRequest,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<ParamsValue> {
        let params: kr_protocol::sharing::DeviceRevokeParams = parse(&mutation.params)?;
        encode(
            &self
                .revoke_device_authority(params.device_id, Some(&carried))
                .await?,
        )
    }

    /// One identity derived from an action identifier and a purpose.
    ///
    /// Two identities from one action have to differ, and both have to be the same on a retry, so
    /// they are the digest of the action and a purpose label rather than anything freshly random.
    fn derived_identity(
        action: kr_protocol::scalars::Uuid,
        purpose: &[u8],
    ) -> kr_protocol::scalars::Uuid {
        let digest =
            kr_cbor::sha256(&[b"kr-sharing/1".as_slice(), purpose, action.as_bytes()].concat());
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        kr_protocol::scalars::Uuid::from_bytes(bytes)
    }

    /// This host's own device identity, derived from its environment.
    #[must_use]
    fn host_device_id(&self) -> kr_protocol::ids::DeviceId {
        kr_protocol::ids::DeviceId::new(self.paths.environment_id().get())
    }

    /// Reports what is installed for one agent.
    fn agent_tools_status(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: kr_protocol::skill::AgentToolsParams = parse(params)?;
        encode(&self.installer()?.status(&params)?)
    }

    /// Installs or removes the contact skill for one agent.
    ///
    /// An installation changes files, so it runs under section 9's receipt contract: the same
    /// action retried returns what it produced the first time rather than repeating the change,
    /// the same identifier with a different payload is `ID_CONFLICT`, and a marker written before
    /// the change with no outcome after it is `unknown` rather than something to do again. What
    /// can be refused without touching anything is refused before the marker.
    async fn agent_tools_change(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        connection_id: ConnectionId,
        accepted: Option<AcceptedDeadline>,
    ) -> Result<ParamsValue> {
        let params: kr_protocol::skill::AgentToolsParams = parse(&mutation.params)?;
        let installer = self.installer()?;
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        // From here to the recorded outcome is one sequence. Two callers cannot both find no
        // record and both change the same files.
        let _admission = self.agent_tools.lock().await;
        // Waiting for that lock takes time, and what happens next is either a read of somebody's
        // completed action or a change to their files. Both need current authority, so it is
        // checked here rather than before the wait.
        self.authorised(connection_id)?;
        if let Some(retained) = installer.retained(actor_id, mutation.action_id, &digest)? {
            return Ok(retained);
        }
        // What either change can refuse without touching anything, refused here: the platform, the
        // scope, a file or entry this host did not write, a record it cannot read, a document whose
        // protection it cannot keep. A refusal after the marker below would be reported as a change
        // whose outcome nobody knows, for a change that never began.
        match method {
            Method::AgentToolsInstall => installer.check(&params)?,
            Method::AgentToolsRemove => installer.check_removal(&params)?,
            _ => {
                return Err(ControllerError::InvalidArgument(format!(
                    "{} is not an installation this daemon serves",
                    method.as_str()
                )));
            }
        }
        // Everything above can wait: for this task to be scheduled, for the lock, for the checks
        // to read the agent's tree. The deadline this action was admitted under is read after
        // those waits, and the dispatch marker is written while this daemon's authority store is
        // held, so a revocation cannot complete between the check and the marker: withdrawing a
        // registration takes the same lock.
        let registrations = self.admitted_table();
        if !registrations.contains_key(&connection_id) {
            return Err(ControllerError::PermissionDenied {
                detail: "the authority this connection was admitted under has been withdrawn; \
                         open a new connection"
                    .to_owned(),
            });
        }
        // A change carrying no freshness at all is refused here as well. This path answers its own
        // retained actions above, so anything still travelling is a first admission, and a first
        // admission needs a deadline it was admitted under.
        if accepted.is_none_or(|accepted| self.clock.now() >= accepted.deadline) {
            return Err(ControllerError::WindowExpired {
                detail: "the deadline this installation was admitted under passed before it could \
                         run"
                .to_owned(),
            });
        }
        installer.mark_dispatching(actor_id, mutation.action_id, &digest)?;
        drop(registrations);
        let result = match method {
            Method::AgentToolsInstall => encode(&installer.install(&params)?)?,
            Method::AgentToolsRemove => encode(&installer.remove(&params)?)?,
            _ => {
                return Err(ControllerError::InvalidArgument(format!(
                    "{} is not an installation this daemon serves",
                    method.as_str()
                )));
            }
        };
        installer.settle(actor_id, mutation.action_id, &digest, &result)?;
        Ok(result)
    }

    /// Returns the installer, which keeps this host's record of what it wrote.
    fn installer(&self) -> Result<crate::agent_tools::Installer> {
        crate::agent_tools::Installer::discover(self.paths.state_dir())
    }

    async fn host_info(self: &Arc<Self>) -> Result<ParamsValue> {
        // Asking what this host is configured as is what puts its configuration into force, the
        // same way asking for its diagnostics is. Reading the numbers without accepting the
        // document first is how this answer comes to name a session ceiling or a sleep policy a
        // later reading has already replaced.
        drop(self.accept_configuration().await);
        let registry = self.registry.lock().await;
        let live = registry.occupancy()?;
        let limit = registry.session_limit()?;
        drop(registry);
        encode(&HostInfoResult {
            build_id: self.build_id.clone(),
            protocol_version: PROTOCOL_VERSION,
            environment_id: self.paths.environment_id(),
            generation: self.generation,
            boot_identity: self.boot_identity.clone(),
            started_at_ms: self.started_at_ms,
            live_sessions: U64::new(live),
            session_limit: U64::new(limit),
            default_worker_profile: self.default_profile().await,
            power: self.power_state().await,
        })
    }

    /// Returns the desktop this host has, and the revision its capability evidence belongs to.
    ///
    /// The platform is asked again when the reading is older than [`DESKTOP_REREAD_INTERVAL`].
    async fn desktop(&self) -> (DesktopContext, CapabilityRevision) {
        let mut reading = self.desktop.lock().await;
        if reading.read_at.elapsed() >= DESKTOP_REREAD_INTERVAL {
            let (context, evidence) =
                resolved_desktop(self.in_force().worker_profile, &self.boot_identity);
            reading.context = context;
            reading.evidence = evidence;
            reading.read_at = std::time::Instant::now();
        }
        (reading.context.clone(), reading.revision)
    }

    /// Returns the context this host's capability evidence is about, and its revision.
    async fn desktop_evidence(&self) -> (DesktopContext, CapabilityRevision) {
        let _ = self.desktop().await;
        let reading = self.desktop.lock().await;
        (reading.evidence.clone(), reading.revision)
    }

    /// Builds the capability report for this host's desktop, at its current revision.
    ///
    /// The records are compared with the ones the current revision was established for, ignoring
    /// the revision itself and when each was observed. Anything else that has changed is a change
    /// in the evidence, and the revision advances with it: a new login, a tool installed or
    /// replaced, a permission that now answers differently, a desktop that is now locked. A
    /// revision that has moved is how a caller holding an earlier record can tell that the answer
    /// it read has gone stale, which is what section 11 requires of evidence. What this publishes
    /// is the evidence and the revision to compare it against; nothing here refuses an operation,
    /// because no method this daemon serves performs one on a desktop.
    ///
    /// # Errors
    ///
    /// Returns an error when the evidence has changed and the revision it changed to cannot be
    /// recorded. Evidence that has changed is never published under the revision the previous
    /// evidence was described by: one revision would then describe two different answers, and an
    /// action that had bound to the first would find its binding current.
    async fn capability_report(&self) -> Result<kr_protocol::desktop::DesktopCapabilityReport> {
        let (context, revision) = self.desktop_evidence().await;
        let mut report =
            crate::desktop::capabilities(self.paths.environment_id(), context, revision);
        // The comparison and the revision it decides are one hold of this lock. Two reports
        // running at once would otherwise both see the old evidence, one would commit the new
        // revision, and the other would hand out records stamped with a revision that no longer
        // describes them.
        let mut reading = self.desktop.lock().await;
        let unchanged = comparable(&report.records) == comparable(&reading.records);
        let revision = if unchanged || !reading.durable_revision {
            // Evidence that has not changed keeps its revision. An environment whose record this
            // host could not read keeps revision zero, which claims nothing: advancing from it
            // would hand out a number this environment may already have used.
            reading.revision
        } else {
            let advanced = CapabilityRevision::new(reading.revision.get().saturating_add(1));
            // The revision outlives this daemon, so a replacement never hands out one it has used
            // before, and a revision that came round again would make a stale record look
            // current. It is therefore published only once it is stored.
            let path = self.paths.state_dir().join(CAPABILITY_REVISION_FILE);
            match kr_ipc::paths::write_owner_only_file(&path, advanced.get().to_string().as_bytes())
            {
                Ok(()) => {
                    reading.revision = advanced;
                    reading.records = report.records.clone();
                    advanced
                }
                // Nothing was recorded, so nothing is published. Handing these records out under
                // the stored revision would describe the tool that was replaced and the one that
                // replaced it with one number, so the answer is the storage failure it is and the
                // next report tries again.
                Err(error) => return Err(ControllerError::Ipc(error)),
            }
        };
        for record in &mut report.records {
            record.revision = revision;
        }
        drop(reading);
        Ok(report)
    }

    /// Returns the execution profile this host creates sessions with when a request chooses none.
    pub async fn default_profile(&self) -> WorkerProfile {
        self.desktop().await.0.worker_profile
    }

    /// Returns what this host's sleep inhibition is doing, taking or releasing the assertion.
    ///
    /// Every caller that can have changed an input asks this, which is how the assertion follows
    /// the work rather than a clock. A review keeps asking while the setting is on, because
    /// neither the start nor the end of a shell's own job is something this daemon is told about.
    pub async fn power_state(self: &Arc<Self>) -> SleepInhibitionState {
        let (state, review) = self.evaluate_power(Claim::Take).await;
        if review == Review::Start {
            self.review_power();
        }
        state
    }

    /// Looks at the setting beside something else this daemon is doing.
    ///
    /// The caller's own answer does not wait for it: what the host does about its own sleep policy
    /// is never a reason to hold a receipt.
    fn review_power_soon(self: &Arc<Self>) {
        let controller = Arc::clone(self);
        tokio::spawn(async move {
            let _ = controller.power_state().await;
        });
    }

    /// Takes or releases the assertion for what this host currently has outstanding, and settles
    /// who is reviewing it.
    ///
    /// Reading what is outstanding, deciding from it and settling who reviews next all happen in
    /// one hold of the inhibitor's lock. Two holds would let a review that has just decided to
    /// stop clear the mark while another caller is taking an assertion, and that assertion would
    /// then have nothing watching it; and a reading taken before the lock could be applied after a
    /// later one, which is how an assertion outlives the work it was taken for: the closure that
    /// ended the work would have been counted by the older reading and released by the newer, and
    /// then taken again by the older. The cost is that one evaluation waits for another, and a
    /// caller that asks for the state itself waits with it: `host.info`, `environment.capabilities`
    /// and `host.doctor` read the setting through this, so their answer includes whatever
    /// evaluation was already under way as well as their own. A receipt never waits, because the
    /// paths that produce one schedule the look rather than awaiting it.
    async fn evaluate_power(self: &Arc<Self>, claim: Claim) -> (SleepInhibitionState, Review) {
        let mut inhibitor = self.inhibitor.lock().await;
        let setting = self.in_force().sleep_inhibition;
        let off = setting == kr_protocol::desktop::SleepInhibitionSetting::Off;
        // A host whose owner has not chosen this pays nothing for it: no worker is asked and no
        // power source is read. An assertion held under a setting that has since been turned off
        // is released by the evaluation below.
        let demand = if off {
            Demand::default()
        } else {
            self.demand().await
        };
        let source = if off {
            kr_protocol::desktop::PowerSource::Unknown
        } else {
            power::power_source()
        };
        let state = inhibitor.evaluate(setting, demand, source);
        let wanted = state.active || !off;
        let review = match claim {
            Claim::Take => {
                if wanted && !inhibitor.reviewing() {
                    inhibitor.set_reviewing(true);
                    Review::Start
                } else {
                    Review::Continue
                }
            }
            Claim::Hold => {
                if wanted {
                    Review::Continue
                } else {
                    inhibitor.set_reviewing(false);
                    Review::Stop
                }
            }
        };
        (state, review)
    }

    /// Keeps looking at the setting while it can still change what is held.
    ///
    /// The review exists because the work this host inhibits sleep for begins and ends without it
    /// being told: a shell starts a job, an agent finishes a turn, a closure drains its output. It
    /// runs while the setting is on, and stops when the setting is off and nothing is held, so a
    /// host whose owner has not chosen this runs no timer at all.
    fn review_power(self: &Arc<Self>) {
        // A weak reference: a daemon that has been dropped everywhere else is dropped, and its
        // singleton lock goes with it. A review that held the daemon open would keep the
        // environment locked for as long as its own interval.
        let controller = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(POWER_REVIEW_INTERVAL).await;
                let Some(controller) = controller.upgrade() else {
                    return;
                };
                if controller.evaluate_power(Claim::Hold).await.1 == Review::Stop {
                    return;
                }
            }
        });
    }

    /// Returns what this host has outstanding that justifies keeping it awake.
    ///
    /// Both counts are of admitted work rather than of activity. A session counts as work when its
    /// worker reports an agent working. A request counts as outstanding when the host has accepted
    /// it and not finished it: a decision waiting for an answer, a closure that is still stopping
    /// processes and draining their output, and a create that has not reported its worker yet. An
    /// idle shell counts for nothing, however much output it has produced.
    ///
    /// Each worker is given a bounded moment to answer, and no worker can delay the answer another
    /// session is waiting for. A worker that holds its socket and stops answering keeps what it
    /// last said, because a worker that will not answer has not said its work ended; what ends
    /// that is the kernel saying its process has gone, which this scan asks about, or the session
    /// leaving this host's list of workers.
    ///
    /// What a scan cannot ask about inside its budget it counts as it last found it. A partial
    /// scan says nothing about the sessions it skipped, so counting those as idle would release
    /// the assertion in the middle of a closure it had just taken one for. The other side of that
    /// is that a host with more sessions than one scan can ask about carries observations from one
    /// scan to the next, so what is counted can be up to one review interval per unasked session
    /// behind.
    async fn demand(self: &Arc<Self>) -> Demand {
        let mut workers: Vec<KnownWorker> = self.directory.lock().await.iter().cloned().collect();
        let mut scan = self.demand_scan.lock().await;
        // A session that is no longer in the directory is a session that has gone, and what it had
        // outstanding went with it.
        let live: std::collections::BTreeSet<SessionId> = workers
            .iter()
            .map(|worker| worker.descriptor.session_id)
            .collect();
        scan.seen.retain(|session_id, _| live.contains(session_id));
        // Where the last scan stopped. A scan that always began at the same end of the same
        // ordered set would ask the same workers every time, and one that never got past a few
        // slow ones would never see what the rest had outstanding.
        let count = workers.len();
        if count > 0 {
            workers.rotate_left(scan.cursor % count);
        }
        let spent = std::time::Instant::now();
        let mut asked = 0;
        for worker in workers {
            // The scan as a whole is bounded, not only each worker in it. A host with many
            // sessions must still answer within the interval its own review runs on, so what it
            // cannot ask about in this scan it asks about in the next one, starting where this one
            // stopped.
            let Some(left) = DEMAND_BUDGET.checked_sub(spent.elapsed()) else {
                break;
            };
            asked += 1;
            let read = self
                .read_from_worker_within(&worker, Some(DEMAND_PATIENCE.min(left)))
                .await
                .ok();
            let Some(read) = read else {
                // A worker that did not answer has not said its work ended, so what it last said
                // stands. A worker whose process the kernel says is gone is different: it is not
                // running an agent and it is not waiting for an answer, whatever it last said, so
                // those go. What does not go with it is a closure this host accepted, because
                // finishing that is this host's own work and not the worker's; it is outstanding
                // until the closure is recorded, which is also when the session leaves the list
                // above and this record with it. So the host is asked to finish it rather than
                // left to notice another time.
                if matches!(
                    kr_ipc::identity::process_state(&worker.descriptor.process_start_identity),
                    kr_ipc::identity::ProcessState::Ended
                ) {
                    let session_id = worker.descriptor.session_id;
                    let closing = scan.seen.get(&session_id).is_some_and(|seen| seen.closing);
                    if closing {
                        scan.seen.insert(
                            session_id,
                            SessionDemand {
                                work: false,
                                approval: false,
                                closing: true,
                                // Its process is gone, so nothing is waiting on its reader.
                                launches: 0,
                            },
                        );
                    } else {
                        scan.seen.remove(&session_id);
                    }
                    let controller = Arc::clone(self);
                    tokio::spawn(async move {
                        let _ = controller.reconcile(session_id).await;
                    });
                }
                continue;
            };
            let summary = &read.session;
            let mut observed = SessionDemand {
                // A launch the reader has not answered is work outstanding, and it stays
                // outstanding through the revocation: A-17 bounds how long input is held, not how
                // long the reader may take to decide. A session that cannot have one says null
                // and adds nothing.
                launches: read.outstanding_launches.0.map_or(0, U64::get),
                ..SessionDemand::default()
            };
            if summary.application_state.as_ref()
                == Some(&kr_protocol::session::ApplicationState::AgentBusy)
            {
                observed.work = true;
            }
            if summary.application_state.as_ref()
                == Some(&kr_protocol::session::ApplicationState::AwaitingApproval)
            {
                observed.approval = true;
            }
            // A closure this host accepted and has not finished. Suspending in the middle of one
            // is how a session's own processes stop being accounted for. The worker's part of it
            // ends before this host's does: it reports `closing` while it stops those processes
            // and `closed` once they are stopped, and what is left then is this host recording
            // the closure, which is also what takes the session out of the list above. So a
            // closure counts from the first sign of one until then.
            observed.closing =
                matches!(summary.state, SessionState::Closing | SessionState::Closed)
                    || scan
                        .seen
                        .get(&worker.descriptor.session_id)
                        .is_some_and(|seen| seen.closing);
            scan.seen.insert(worker.descriptor.session_id, observed);
        }
        scan.cursor = scan.cursor.wrapping_add(asked);
        let sessions_with_work = scan.seen.values().filter(|seen| seen.work).count() as u64;
        let outstanding = scan
            .seen
            .values()
            .map(|seen| u64::from(seen.approval) + u64::from(seen.closing) + seen.launches)
            .sum::<u64>();
        drop(scan);
        Demand {
            sessions_with_work,
            pending_requests: outstanding + self.pending.lock().await.len() as u64,
        }
    }

    /// Reports what this environment can currently do.
    ///
    /// Capability evidence, never authority: every record says what produced it and what makes it
    /// stale. Nothing here grants anything, and a caller that acts on one of these answers still
    /// needs its own authority for whatever it does and the permissions the operating system
    /// actually granted the tool it uses.
    async fn environment_capabilities(
        self: &Arc<Self>,
        params: &ParamsValue,
        owner: bool,
    ) -> Result<ParamsValue> {
        let params: EnvironmentCapabilitiesParams = parse(params)?;
        if params.environment_id != self.paths.environment_id() {
            return Err(ControllerError::InvalidArgument(format!(
                "this daemon owns environment {}",
                self.paths.environment_id()
            )));
        }
        let mut desktop = self.capability_report().await?;
        if !owner {
            // The records leave this host here, so they cross the same export boundary a support
            // bundle does. A probe names the binary it found on `PATH` and repeats what that
            // binary printed; the evidence this host keeps for its own comparisons is untouched,
            // because a withheld path is no longer a path it can compare.
            desktop.records = kr_protocol::hostinfo::export::capability_records(desktop.records);
            desktop.desktop = kr_protocol::hostinfo::export::desktop_context(desktop.desktop);
        }
        encode(&EnvironmentCapabilitiesResult {
            environment_id: self.paths.environment_id(),
            // The same answer `host.info` gives: what this host creates a session in when the
            // request chooses nothing, which is what the configuration resolves rather than what
            // the platform alone would say. Two reads of one question must not disagree.
            default_worker_profile: self.default_profile().await,
            desktop,
            persistence: crate::desktop::persistence(self.supervisor.describe()),
            power: self.power_state().await,
        })
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

    async fn environment_list(&self) -> Result<ParamsValue> {
        let registry = self.registry.lock().await;
        let live = registry.occupancy()?;
        drop(registry);
        encode(&EnvironmentListResult {
            environments: vec![EnvironmentSummary {
                environment_id: self.paths.environment_id(),
                label: format!("{} on {}", whoami(), std::env::consts::OS),
                os: std::env::consts::OS.to_owned(),
                arch: std::env::consts::ARCH.to_owned(),
                os_user: whoami(),
                runtime_directory: self.paths.runtime_dir().display().to_string(),
                state_directory: self.paths.state_dir().display().to_string(),
                live_sessions: U64::new(live),
            }],
        })
    }

    /// Reads this environment's configuration.
    ///
    /// One reader, so the value a check reports and the value the host acts on cannot be two
    /// different readings of the same document.
    #[must_use]
    pub fn configuration(&self) -> kr_worker::config::Resolver {
        crate::config::open(&self.paths)
    }

    /// The ordinary preferences the last acceptance put in force.
    fn in_force(&self) -> crate::config::InForce {
        *self
            .in_force
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Returns what this host's configuration currently resolves to.
    ///
    /// The document is put into force first and the report is built from that same reading, so a
    /// value a person is shown is the value this host is acting on rather than a second reading of
    /// a file that may since have moved. A document edited outside this daemon therefore takes
    /// effect - ceiling, fence and capability invalidation alike - the next time anything asks
    /// this question, rather than at the next restart.
    pub async fn effective_configuration(&self) -> kr_protocol::hostinfo::EffectiveConfiguration {
        let accepted = self.accept_configuration().await;
        self.report_configuration(&accepted).await
    }

    /// Builds the effective-value report from one accepted configuration.
    async fn report_configuration(
        &self,
        accepted: &crate::config::Accepted,
    ) -> kr_protocol::hostinfo::EffectiveConfiguration {
        crate::config::effective(
            accepted,
            self.hard_limits(),
            crate::desktop::default_profile(&self.desktop().await.0),
        )
    }

    /// Puts the configuration document on disk into force, and returns what is in force.
    ///
    /// The one ordered path, and the whole of the ordering is this lock: it is taken *before* the
    /// document is read, so an edit applying its own effects and a reader accepting what it found
    /// cannot interleave, and whichever of them runs last is the one that read the document that
    /// is actually on disk. The effects are derived from what moved since the last acceptance
    /// rather than from the request that caused it, which is what makes a document edited in a
    /// text editor owe exactly what the same edit made through this daemon owes; and they are
    /// applied on every acceptance rather than only when the revision number moved, because a
    /// document edited by hand can change what it says without changing what it calls itself.
    ///
    /// Nothing here returns an error. A failure is what the returned value carries, because the
    /// report is built from it and a report that quietly dropped the failure would describe a
    /// document this host is not acting on.
    async fn accept_configuration(&self) -> crate::config::Accepted {
        let mut state = self.accepted_configuration.lock().await;
        let resolver = self.configuration();
        let owed = kr_protocol::hostinfo::configuration::owed(
            state.document.as_ref(),
            resolver.loaded().document.as_ref(),
        );
        // The ordinary preferences take effect by being read, so this reading is what the things
        // that act on them read until the next acceptance replaces it. It is written whatever the
        // effects below do: a sleep policy is in force because the document says it, not because
        // a registry write succeeded.
        *self
            .in_force
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            crate::config::InForce::of(&resolver);
        let (sessions, mut failure) = self.apply_session_limit(&resolver, &state).await;
        if sessions.from_document {
            // Recorded the moment the registry took it, separately from everything below. A later
            // effect that fails does not put this number back, and a state that said it had would
            // make the next report describe a ceiling admission is no longer enforcing.
            state.sessions = sessions.value;
        }
        // The durable fact, read before anything acts on it. The flag this process used to keep
        // decided nothing that survived it.
        let (owed_before, mut unreadable) = self.fence_owed().await;
        let mut barrier = None;
        if owed.fences_dispatch {
            // Attempted whatever else failed, because the values above are already in force: the
            // narrower ceiling decides every request from here on, and the work admitted under the
            // one it replaced is dispatchable until the revision advances. An effect that failed
            // earlier is a reason to fence rather than a reason to skip it.
            //
            // Before anything is told the ceiling moved. Work admitted under the ceiling this
            // document withdrew has to stop being dispatchable first, whoever wrote the document.
            // The revision advance writes the debt with it, so the fence is recorded as owed
            // before the announcement travels and before any effect below runs.
            match self.revoke_authority().await {
                Ok(raised) => {
                    barrier = Some(raised);
                    self.fence_unraised
                        .store(false, std::sync::atomic::Ordering::SeqCst);
                }
                Err(error) => {
                    // Before the report, because what this flag stops is dispatch and the report
                    // is read afterwards. Work admitted under the ceiling this document withdrew
                    // is still dispatchable until the revision advances, and the revision is
                    // exactly what did not advance.
                    self.fence_unraised
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    let fenced = Sentence::new()
                        .stated("dispatch could not be fenced: ")
                        .withheld(ContentClass::Message, &error.to_string());
                    // Beside whatever failed before it rather than instead of it. Both are
                    // effects this document owed, and a report that named one of them would send
                    // a person to fix half of what is wrong.
                    failure = Some(match failure {
                        Some(earlier) => earlier.stated("; ").sentence(&fenced),
                        None => fenced,
                    });
                }
            }
        } else if failure.is_none() {
            // This reading asks for no fence, so a fence an earlier reading could not raise is no
            // longer owed: the document that asked for it has moved on.
            self.fence_unraised
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
        if failure.is_none() && !owed.fences_dispatch && owed_before.is_some() {
            // A fence this environment raised earlier that a worker had not acknowledged. The debt
            // is this host's, not the document's: the document has not moved since, so nothing
            // above would raise it again, and a change asked for a second time would otherwise be
            // told it was done. Announcing again is how a worker that has since answered, or since
            // ended, settles it, and it advances no revision.
            match self.announce_authority_revision().await {
                Ok(reported) => barrier = Some(reported),
                Err(error) => {
                    failure = Some(
                        Sentence::new()
                            .stated("the outstanding fence could not be checked: ")
                            .withheld(ContentClass::Message, &error.to_string()),
                    );
                }
            }
        }
        if failure.is_none()
            && owed
                .invalidated
                .contains(&kr_protocol::desktop::CapabilityInvalidation::WorkerProfile)
            && let Err(error) = self.invalidate_profile_evidence(&resolver).await
        {
            failure = Some(
                Sentence::new()
                    .stated(
                        "the capability evidence taken under the old profile could not be \
                         replaced: ",
                    )
                    .withheld(ContentClass::Message, &error.to_string()),
            );
        }
        let effects_applied = failure.is_none();
        // A reading that produced no document decided nothing, so there is nothing to record. An
        // absent or unusable file leaves what was in force in force, which is the rule `owed`
        // follows on the way in; replacing the accepted document with nothing would break it on
        // the way out, because the next usable document would then be compared against empty
        // defaults and a ceiling removed while the file could not be read would be lifted without
        // a fence.
        let decided = resolver.loaded().document.is_some();
        if effects_applied && decided {
            // Recorded once every effect has landed, so a failed acceptance is retried by the
            // next one instead of being remembered as done. What this records is which document
            // was accepted; the fence debt is not here, because a value this process holds cannot
            // outlive it and only a worker answering settles one.
            state.revision = resolver.revision();
            state.document = resolver.loaded().document.clone();
            // And durably, because the next daemon has to be able to tell a document this host
            // acted on from one it never reached. It is the same record in the registry row that
            // holds the fence debt, written in the opposite order: the debt before the effects,
            // because it says what is still owed, and this after them, because it says what is
            // done.
            let accepted = crate::registry::AcceptedConfiguration {
                revision: state.revision,
                document: crate::config::recorded(state.document.as_ref()),
            };
            if let Err(error) = self
                .registry
                .lock()
                .await
                .record_accepted_configuration(&accepted)
            {
                failure = Some(
                    Sentence::new()
                        .stated(
                            "this host applied the document and could not record that it had, so \
                             it will apply it again when it next starts: ",
                        )
                        .withheld(ContentClass::Message, &error.to_string()),
                );
            }
        }
        drop(state);
        // Read back after the effects rather than derived from them. A fence raised above is owed
        // whatever happened afterwards, and one raised by an earlier daemon is owed although
        // nothing in this process raised it.
        let (fence_owed, unreadable_now) = self.fence_owed().await;
        unreadable = unreadable.or(unreadable_now);
        if failure.is_none() {
            failure = unreadable;
        }
        crate::config::Accepted {
            resolver,
            sessions,
            owed,
            barrier,
            fence_owed,
            effects_applied,
            not_in_force: failure,
        }
    }

    /// Reads the fence this environment owes, and why it could not be read when it could not.
    ///
    /// A debt this host cannot read is not a debt it may call settled, so an unreadable registry
    /// answers with the revision in force rather than with nothing. The alternative is a report
    /// that says every worker has answered because the file holding the answer would not open.
    async fn fence_owed(&self) -> (Option<AuthorityRevision>, Option<Sentence>) {
        match self.registry.lock().await.fence_owed() {
            Ok(owed) => (owed, None),
            Err(error) => (
                Some(self.leases.authority_revision()),
                Some(
                    Sentence::new()
                        .stated("the fence this host owes could not be read: ")
                        .withheld(ContentClass::Message, &error.to_string()),
                ),
            ),
        }
    }

    /// Puts the document's session ceiling where admission reads it, and returns what is in force.
    ///
    /// A document this host can read decides the number admission enforces, whether it names one
    /// or leaves it to the product default: both are things the document says. A document that is
    /// absent, one this build cannot read and one whose write failed decide nothing, and then the
    /// number admission already enforces stays exactly as it is and is what the report prints: a
    /// restriction the owner accepted must not be lifted because a later build could not read the
    /// file it was in, and it must not be *reported* as lifted either.
    async fn apply_session_limit(
        &self,
        resolver: &kr_worker::config::Resolver,
        state: &crate::config::AcceptedState,
    ) -> (crate::config::Enforced, Option<Sentence>) {
        let retained = crate::config::Enforced {
            value: state.sessions,
            from_document: false,
        };
        let Some(limit) = crate::config::session_limit_in_force(resolver, self.hard_limits())
        else {
            return (retained, None);
        };
        match self.registry.lock().await.set_session_limit(limit) {
            Ok(()) => (
                crate::config::Enforced {
                    value: limit,
                    from_document: true,
                },
                None,
            ),
            Err(error) => (
                retained,
                Some(
                    Sentence::new()
                        .stated("this host still admits ")
                        .number(state.sessions)
                        .stated(
                            " sessions, because the number this document asks for could not be \
                             recorded: ",
                        )
                        .withheld(ContentClass::Message, &error.to_string()),
                ),
            ),
        }
    }

    /// Replaces the capability evidence taken under a profile this host no longer creates sessions
    /// in.
    ///
    /// Nothing migrates a worker: a running session keeps the profile it was created in, and the
    /// new value applies to sessions created afterwards. What is replaced is the evidence, because
    /// evidence about a profile this host has stopped using is no longer about this host.
    ///
    /// # Errors
    ///
    /// Returns an error when the replacement evidence could not be recorded. Reporting success
    /// would publish records under a revision that no longer describes them, which is the one
    /// thing a revision exists to prevent.
    async fn invalidate_profile_evidence(
        &self,
        resolver: &kr_worker::config::Resolver,
    ) -> Result<()> {
        // Taken from the configuration this acceptance read, so the evidence is replaced under
        // the profile the report describes rather than under whatever is on disk a moment later.
        *self
            .in_force
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            crate::config::InForce::of(resolver);
        let mut reading = self.desktop.lock().await;
        reading.read_at = std::time::Instant::now()
            .checked_sub(DESKTOP_REREAD_INTERVAL)
            .unwrap_or_else(std::time::Instant::now);
        drop(reading);
        self.capability_report().await?;
        Ok(())
    }

    /// Applies one validated configuration edit and does what the change owes.
    ///
    /// A change that affects authority fences dispatch *before* this returns, which is section
    /// 26's "changes affecting authority fence dispatch before acknowledgement": the caller is
    /// told the change is in force only once work admitted under the old authority can no longer
    /// be dispatched. Nothing migrates a worker: a running session keeps the profile it was
    /// created in, and the evidence taken under the old one is invalidated rather than reused.
    ///
    /// # Errors
    ///
    /// Returns an error when the edit is refused, when an effect could not be applied, or when a
    /// worker has not yet acknowledged the fence the change raised.
    pub async fn apply_configuration(
        self: &Arc<Self>,
        change: &kr_protocol::hostinfo::configuration::Change,
    ) -> Result<crate::config::Applied> {
        let edit = crate::config::apply(&self.paths, change, self.hard_limits())?;
        // Inside the edit lock, and through the one path every other revision takes: what this
        // daemon does with a document it wrote is what it does with a document somebody else
        // wrote. Holding the lock across it is what keeps the effects and the write together, so
        // a slower older edit cannot put its number back after a newer one has landed.
        let accepted = self.accept_configuration().await;
        let applied = crate::config::Applied {
            revision: edit.revision,
            effect: edit.effect,
            invalidated: accepted.owed.invalidated.clone(),
            fences_dispatch: accepted.owed.fences_dispatch,
            authority_revision: accepted
                .barrier
                .as_ref()
                .map(|barrier| barrier.authority_revision),
            barrier_holds: accepted
                .barrier
                .as_ref()
                .is_none_or(RevocationBarrier::holds),
            pending_workers: accepted
                .barrier
                .as_ref()
                .map_or(0, |barrier| barrier.pending().len() as u64),
        };
        // The durable debt, not the barrier this call happens to hold. A fence an earlier daemon
        // raised and no worker answered is owed by this environment, and a caller told its change
        // is in force would be told something that is not yet true of that worker.
        let outstanding = accepted.fence_outstanding();
        let not_in_force = accepted.not_in_force.clone();
        drop(accepted);
        drop(edit);
        if let Some(problem) = not_in_force {
            return Err(ControllerError::Configuration(format!(
                "revision {} is written and is not in force: {problem}",
                applied.revision
            )));
        }
        if let Some(outstanding) = outstanding {
            // Section 26 says a change affecting authority fences dispatch *before* it is
            // acknowledged. A worker that has not acknowledged its fence still holds work admitted
            // under the authority this change withdrew, so the revision is recorded and the caller
            // is told what is outstanding rather than told it is done.
            return Err(ControllerError::Configuration(format!(
                "revision {} is written and dispatch is fenced: {outstanding}; the change is in \
                 force for dispatch once they answer",
                applied.revision
            )));
        }
        Ok(applied)
    }

    /// The resource limits a configured ceiling is intersected with on this machine.
    ///
    /// This host does not measure its own headroom, so nothing is established and an owner's
    /// configured number applies. The value is here rather than at each call site so the day it is
    /// measured there is one place to answer from.
    #[must_use]
    pub const fn hard_limits(&self) -> crate::config::HardLimits {
        crate::config::HardLimits {
            sessions_per_environment: None,
        }
    }

    /// The sleep policy line, built from what this host chose rather than from a rendered state.
    ///
    /// `SleepInhibitionState::describe` names the assertion's holder, which the platform supplied,
    /// so the check says what the setting is, whether an assertion is held and on which power
    /// source, and carries the holder's class and length rather than its name.
    fn sleep_setting_detail(
        power: &kr_protocol::desktop::SleepInhibitionState,
        resolved: &kr_worker::config::Effective<kr_protocol::desktop::SleepInhibitionSetting>,
    ) -> Sentence {
        let mut detail = Sentence::new()
            .stated(power.setting.as_str())
            .stated(if power.active {
                ", inhibiting sleep on "
            } else {
                ", holding no assertion on "
            })
            .stated(power.power_source.as_str());
        if let Some(holder) = power.holder.0.as_deref() {
            detail = detail
                .stated(", held as ")
                .withheld(ContentClass::Name, holder);
        }
        detail = detail.stated(" (from ").stated(resolved.source.describe());
        if let Some(origin) = resolved.origin.as_deref() {
            detail = detail.stated(", ").withheld(ContentClass::Name, origin);
        }
        detail.stated(")")
    }

    async fn host_doctor(self: &Arc<Self>, owner: bool) -> Result<ParamsValue> {
        let mut checks = Vec::new();
        checks.push(DoctorCheck::new(
            "runtime-directory",
            "The runtime directory is owner-only",
            DoctorStatus::Ok,
            Sentence::new()
                .stated("created with owner-only permissions and verified on every open: ")
                .withheld(
                    ContentClass::Path,
                    &self.paths.runtime_dir().display().to_string(),
                ),
            None,
        ));
        checks.push(DoctorCheck::new(
            "supervisor",
            "Workers outlive this daemon",
            DoctorStatus::Ok,
            Sentence::new().stated(self.supervisor.describe()),
            None,
        ));
        let directory = self.directory.lock().await;
        let quarantined = directory.quarantined.len();
        let verified = directory.verified.len();
        drop(directory);
        checks.push(DoctorCheck::new(
            "workers",
            "Every published descriptor answered its challenge",
            if quarantined == 0 {
                DoctorStatus::Ok
            } else {
                DoctorStatus::Warning
            },
            Sentence::new()
                .number(verified as u64)
                .stated(" verified, ")
                .number(quarantined as u64)
                .stated(" quarantined"),
            (quarantined > 0).then_some(
                "A quarantined descriptor is never used. Remove it once its session is known to \
                 be gone.",
            ),
        ));
        // One acceptance, one reading, and every configuration line below comes from it. The
        // sleep policy asking the document a second time is how a check and the report it sits
        // beside come to disagree about the same file.
        let accepted = self.accept_configuration().await;
        let power = self.power_state().await;
        let resolved = accepted.resolver.sleep_inhibition(None);
        checks.push(DoctorCheck::new(
            "sleep-setting",
            "This host's sleep policy is the owner's choice",
            DoctorStatus::Ok,
            Self::sleep_setting_detail(&power, &resolved),
            (power.setting == kr_protocol::desktop::SleepInhibitionSetting::Off).then_some(
                "kr host power --set mains_only keeps this host awake for work it has admitted, \
                 while it is on mains power.",
            ),
        ));
        for entry in crate::desktop::persistence(self.supervisor.describe()) {
            checks.push(DoctorCheck::new(
                match entry.profile {
                    WorkerProfile::DesktopBound => "logout-desktop_bound",
                    WorkerProfile::HeadlessUser => "logout-headless_user",
                },
                match entry.profile {
                    WorkerProfile::DesktopBound => "What a logout does to a desktop-bound session",
                    WorkerProfile::HeadlessUser => "What a logout does to a headless session",
                },
                DoctorStatus::Ok,
                Sentence::new()
                    .stated(entry.persistence.as_str())
                    .stated(" through ")
                    .stated_value(entry.mechanism())
                    .stated(": ")
                    .stated_value(entry.detail()),
                None,
            ));
        }
        let pending = self.revision_pending().await?;
        checks.push(DoctorCheck::new(
            "authority-revision",
            "Every worker holds this environment's authority revision",
            if pending.is_empty() {
                DoctorStatus::Ok
            } else {
                DoctorStatus::Warning
            },
            Sentence::new()
                .number(pending.len() as u64)
                .stated(" of ")
                .number(verified as u64)
                .stated(" pending"),
            (!pending.is_empty()).then_some(
                "A revocation is complete for a worker once it acknowledges the revision or is \
                 confirmed ended.",
            ),
        ));
        // The configuration, its precedence, its overrides and its ceilings. After the checks
        // above because those are about whether this host is working; these are about what it is
        // working from.
        let budgets = crate::config::catalogue::budgets(&accepted.resolver.ceilings());
        let effective = self.report_configuration(&accepted).await;
        drop(accepted);
        checks.extend(crate::config::checks(&effective));
        checks.push(DoctorCheck::new(
            "configuration-secrets",
            "Secrets are named references, never configuration exports",
            DoctorStatus::Ok,
            crate::config::secret_line(&effective),
            None,
        ));
        // The shared section 11 capability evidence a catalogue contributes. `NotApplicable` with
        // the reason stated while nothing has synchronised one, rather than a claim about a
        // catalogue this host does not have.
        checks.push(crate::config::catalogue::check(
            self.catalogue_evidence.as_deref(),
            budgets,
        ));
        let result = HostDoctorResult::new(checks, effective);
        if owner {
            return encode(&result);
        }
        // Not the owner's own terminal, so this is an export: every path this host composed from
        // an account name, every label somebody wrote and every message a library produced leaves
        // as its class and its length, beside the rule this platform follows.
        encode(kr_protocol::hostinfo::export::ForExport::for_export(result).get())
    }

    async fn session_list(self: &Arc<Self>, params: &ParamsValue) -> Result<ParamsValue> {
        let params: SessionListParams = parse(params)?;
        // Any worker that has started answering since the last attempt rejoins the directory here,
        // so a list is the current picture rather than the picture at startup. A claim this daemon
        // could not resolve when it started is looked at again for the same reason.
        let _ = self.recover_claims().await;
        let _ = self.recover_workers().await;
        let mut sessions = Vec::new();
        let workers: Vec<KnownWorker> = self.directory.lock().await.iter().cloned().collect();
        for worker in workers {
            match self.read_from_worker(&worker).await {
                Ok(read) => sessions.push(read.session),
                Err(_) => {
                    let _ = self.reconcile(worker.descriptor.session_id).await;
                }
            }
        }
        if params.include_closed {
            let mut closed = Vec::new();
            let registry = self.registry.lock().await;
            for reservation in registry.closed_reservations()? {
                if let Some(closure) = registry.closure(reservation.session_id)? {
                    closed.push((closure, reservation.display_number));
                }
            }
            drop(registry);
            for (closure, display_number) in closed {
                sessions.push(self.closed_session(&closure, display_number).await);
            }
        }
        sessions.sort_by_key(|session| session.display_number.get());
        encode(&SessionListResult { sessions })
    }

    async fn session_read(self: &Arc<Self>, params: &ParamsValue) -> Result<ParamsValue> {
        let params: SessionReadParams = parse(params)?;
        // A worker that did not answer at startup is not gone; it was busy, or it started slowly.
        // Trying again here is what keeps a session readable without another daemon restart.
        if self.directory.lock().await.get(params.session_id).is_none() {
            // This session's own claim, and the reason when it cannot be resolved: a caller that
            // named one session is owed that rather than "no such session".
            self.recover_claim_for(params.session_id).await?;
            let _ = self.recover_workers().await;
        }
        let worker = self.directory.lock().await.get(params.session_id).cloned();
        if let Some(worker) = worker {
            match self.read_from_worker(&worker).await {
                Ok(read) => {
                    return encode(&SessionReadResult {
                        session: read.session,
                        endpoint: Nullable::some(worker.endpoint.as_text()),
                        launch_profile: read.launch_profile,
                        last_command_block: read.last_command_block,
                        outstanding_launches: read.outstanding_launches,
                    });
                }
                // A worker that cannot be reached is not necessarily gone. Reconciliation asks the
                // kernel; only a confirmed death produces a closure record.
                Err(error) => {
                    if self.reconcile(params.session_id).await?.is_none() {
                        return Err(error);
                    }
                }
            }
        }
        // A closed session answers with its record. It never starts anything.
        let registry = self.registry.lock().await;
        let closure = registry.closure(params.session_id)?;
        // The reservation row outlives the worker row, so a closed session keeps the number it was
        // listed under.
        let display = registry
            .reservation_for_session(params.session_id)?
            .map(|reservation| reservation.display_number);
        drop(registry);
        match closure {
            Some(closure) => {
                let display = display.unwrap_or(kr_protocol::session::DisplayNumber::new(0));
                encode(&SessionReadResult {
                    session: self.closed_session(&closure, display).await,
                    endpoint: Nullable::null(),
                    launch_profile: Nullable::null(),
                    last_command_block: Nullable::null(),
                    outstanding_launches: Nullable::null(),
                })
            }
            None => Err(ControllerError::UnknownSession {
                session: params.session_id.to_string(),
            }),
        }
    }

    /// Refuses a managed create whose shell no installed package qualifies.
    ///
    /// Reserves a session and starts its worker.
    ///
    /// `connection_id` is the connection that asked, on whichever ingress. A create is the one
    /// mutation this daemon performs itself and the slowest thing it does: it writes the
    /// reservation, waits for a lock, starts a process and waits for that process to report
    /// itself. The connection identity travels with it so the registration behind it can be
    /// checked again at the moment the launch becomes possible, rather than only when the request
    /// arrived.
    async fn session_create(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<ParamsValue> {
        let create: SessionCreateParams = parse(&mutation.params)?;
        // Before the reservation, because this is a request that can never be served rather than
        // one this environment happens to have no room for. The palette travels to the worker in
        // the launch specification and is recorded there; what cannot travel is a provenance
        // nothing measured.
        if let Some(refusal) = create.palette_refusal() {
            return Err(ControllerError::InvalidArgument(refusal));
        }
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        // The create request itself is recorded with the reservation, before anything is spawned.
        // A daemon that dies between the reservation and the launch then finds a request it can
        // resolve rather than an identifier with nothing behind it.
        let intent = kr_cbor::to_canonical_vec(&create)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        // The action identifier is the create token. One identifier, one session; a retry with the
        // same payload resolves to the same reservation rather than launching a second shell.
        // A managed session needs a KalaReach-qualified shell package, and this is the one place
        // every ingress passes through: the local endpoint reaches it through its own dispatch and
        // a caller on the network reaches it directly. The answer is worked out here, before the
        // registry is locked, because finding a package reads directories and opens files and a
        // filesystem that answers slowly must not hold up every other request in this environment.
        // Finding a package reads directories and opens files, which is work for a thread that may
        // block: a package root on a filesystem that has stopped answering would otherwise occupy
        // one of the runtime's own threads until the platform gave up on it.
        let qualified = match create.shell_mode {
            kr_protocol::session::ShellMode::Managed => {
                let root = self.shell_packages.clone();
                let requested = create.shell.0.clone();
                Some(
                    tokio::task::spawn_blocking(move || {
                        qualified_package(root.as_deref(), requested.as_deref())
                    })
                    .await
                    .map_err(|error| ControllerError::supervision(error.to_string()))?,
                )
            }
            kr_protocol::session::ShellMode::NativeCompat => None,
        };
        let admission = {
            let mut registry = self.registry.lock().await;
            // The token is looked at under the same lock the reservation is taken under, and the
            // refusal above is applied only to a token this registry has never seen. A create this
            // actor already made is a retry, and section 9 says a retry is answered from what its
            // first attempt produced; refusing one because the package went away in between would
            // be refusing an action that already has an outcome.
            let known = registry
                .reservation_for_token(actor_id, mutation.action_id.get())?
                .is_some();
            if !known && let Some(qualified) = qualified {
                // Nothing is reserved and nothing is spawned before this, so an unsupported shell
                // costs the caller a named error rather than a session that closes itself a moment
                // later.
                let _resolved = qualified?;
            }
            registry.reserve(
                actor_id,
                mutation.action_id.get(),
                digest,
                &intent,
                kr_ipc::now_ms(),
            )?
        };
        let reservation = admission.reservation;
        if admission.deduplicated {
            // A repeated token resolves to the session it already created, whatever this host's
            // conditions are now. A desktop that has gone since is a reason not to start a new
            // session rather than a reason to withhold the answer about one that already exists.
            return self.replay_create(&reservation).await;
        }

        // A desktop-bound session needs a desktop, and this host does not manufacture one: an SSH
        // connection is a transport rather than a graphical login, and a request bound to a
        // desktop that is not there would be given a session bound to nothing. The desktop's own
        // environment is collected in the same breath, because both are conversations with the
        // platform and neither may happen after the deadline below is checked.
        let desktop_environment = if create.worker_profile == WorkerProfile::DesktopBound {
            let (desktop, _) = self.desktop().await;
            if !desktop.is_desktop() || !desktop.graphic_access {
                let mut registry = self.registry.lock().await;
                registry.set_phase(reservation.reservation_id, LaunchPhase::Failed)?;
                drop(registry);
                return Err(ControllerError::NotConfigured(
                    NO_DESKTOP_TO_BIND.to_owned(),
                ));
            }
            // The session this host just read its desktop from, so the worker is started on the
            // desktop this host describes rather than on another login of the same user.
            crate::desktop::agent::environment(
                create.worker_profile,
                desktop.platform_session.as_ref().map(String::as_str),
            )
        } else {
            Vec::new()
        };

        let (sender, receiver) = oneshot::channel();
        self.pending
            .lock()
            .await
            .insert(reservation.reservation_id, PendingCreate { ready: sender });

        // Everything the launch needs is prepared before the checks that admit it, so nothing
        // between the last check and the launch can wait: a directory tree is several filesystem
        // operations, and a slow disk would otherwise spend the rest of an accepted deadline here.
        // The directory is inside this environment's state directory, which this daemon owns and
        // which holds nothing a person keeps.
        let working_directory = self.paths.worker_dir(reservation.session_id);
        if let Err(error) =
            kr_ipc::paths::create_private_tree(self.paths.state_root(), &working_directory)
        {
            // Nothing was started, so the reservation is resolved as a confirmed failure and stops
            // occupying the environment.
            self.resolve_failed(reservation.reservation_id).await?;
            return Err(error.into());
        }

        // The reservation moves to `spawned` before anything is started. A worker can reach the
        // rendezvous socket the instant the service manager starts it, which is sooner than the
        // launcher returns, and a reservation still recorded as merely reserved would fence its own
        // worker. The deadline the host accepted and the registration behind the request are both
        // checked in the same critical section, and after the durable write rather than before it:
        // everything from there to the launch runs without waiting for anything, so neither an
        // action whose life ran out queueing for this lock nor one whose authority was withdrawn
        // while it queued goes on to start a shell.
        //
        // The registration is read with the registry lock already held, which is the order a
        // revocation takes: a revocation that has installed its revision has already withdrawn the
        // registrations that revision replaced, so what this reads is never a registration the
        // revocation is part way through removing.
        {
            let mut registry = self.registry.lock().await;
            registry.set_phase(reservation.reservation_id, LaunchPhase::Spawned)?;
            // The admission this create carries, against the registry this guard holds: the
            // authority revision it was admitted under, the registration behind it, and the
            // deadline, in that order. The registration is read with the registry lock already
            // held, which is the order a revocation takes, and the clock is read last, so the last
            // thing between this create and its launch is a reading with nothing left to wait for.
            if let Err(refusal) = self.check_admission(&registry, &carried) {
                // Nothing was started, so the reservation is resolved as a confirmed failure and
                // stops occupying the environment. The caller is told which of the two it was.
                registry.set_phase(reservation.reservation_id, LaunchPhase::Failed)?;
                drop(registry);
                self.pending
                    .lock()
                    .await
                    .remove(&reservation.reservation_id);
                self.discard_worker_dir(reservation.session_id);
                return Err(refusal);
            }
        }
        let launch = WorkerLaunch {
            reservation_id: reservation.reservation_id,
            session_id: reservation.session_id,
            environment_id: self.paths.environment_id(),
            display_number: reservation.display_number,
            program: self.worker_program.clone(),
            rendezvous: self.paths.rendezvous_endpoint()?.as_path().to_path_buf(),
            // The roots, not this environment's directories: the worker derives its own paths
            // from the environment identity, and giving it the derived directory would make it
            // apply the prefix twice.
            runtime_directory: self.paths.runtime_root().to_path_buf(),
            state_directory: self.paths.state_root().to_path_buf(),
            jobs_directory: self.paths.jobs_dir(),
            working_directory,
            // The desktop the worker is started in. Two platforms place a per-user job in the
            // login session that started it and need nothing here; Linux publishes the session's
            // display, compositor and message bus into the user manager, and that is what was
            // collected above.
            desktop_environment,
            // Which login context the worker is started in at all, which its environment alone
            // does not decide.
            profile: create.worker_profile,
        };
        let identity = match self.supervisor.start(&launch) {
            LaunchOutcome::Started(identity) => identity,
            // Nothing started, so the reservation is resolved as a confirmed failure and stops
            // occupying the environment. It is never resumed.
            LaunchOutcome::NotStarted { detail } => {
                self.pending
                    .lock()
                    .await
                    .remove(&reservation.reservation_id);
                let mut registry = self.registry.lock().await;
                registry.set_phase(reservation.reservation_id, LaunchPhase::Failed)?;
                drop(registry);
                self.discard_worker_dir(reservation.session_id);
                return Err(ControllerError::Supervision { detail });
            }
            // A process may be running. The create fails for the caller, and the reservation stays
            // spawned: it keeps its slot until something settles what happened to that process.
            LaunchOutcome::Uncertain { detail, pid } => {
                self.pending
                    .lock()
                    .await
                    .remove(&reservation.reservation_id);
                if let Some(pid) = pid
                    && let Ok(identity) = kr_ipc::identity::process_start_identity(pid)
                {
                    let mut registry = self.registry.lock().await;
                    registry.record_launch(reservation.reservation_id, &identity)?;
                }
                return Err(ControllerError::Supervision { detail });
            }
        };
        {
            let mut registry = self.registry.lock().await;
            registry.record_launch(reservation.reservation_id, &identity)?;
        }

        let ready = match tokio::time::timeout(RENDEZVOUS_TIMEOUT, receiver).await {
            Ok(Ok(Ok(ready))) => ready,
            Ok(Ok(Err(error))) => {
                return Err(ControllerError::Supervision {
                    detail: error.to_string(),
                });
            }
            Ok(Err(_)) | Err(_) => {
                self.pending
                    .lock()
                    .await
                    .remove(&reservation.reservation_id);
                return Err(ControllerError::supervision(
                    "the worker did not report itself in time",
                ));
            }
        };

        let worker = self
            .directory
            .lock()
            .await
            .get(reservation.session_id)
            .cloned()
            .ok_or_else(|| ControllerError::supervision("the worker is not in the directory"))?;
        let summary = self.read_from_worker(&worker).await?.session;
        // A new session can be the work that justifies keeping this host awake, and the setting
        // decides whether it does. That is looked at beside this answer rather than before it:
        // what the host does about its own sleep policy is no reason to hold a caller's receipt.
        self.review_power_soon();
        // Last, and never before the session exists: opening a window is a separate step, so a
        // host that cannot open one answers with the session it made and the reason. Nothing here
        // creates a second session, and a repeated create token never reaches this line, so a
        // retry cannot open a second window either.
        let presentation_error = self.present(&create, reservation.session_id).await;
        encode(&SessionCreateResult {
            session: summary,
            endpoint: Nullable::some(ready.endpoint),
            deduplicated: false,
            presentation_error: Nullable(presentation_error),
        })
    }

    /// Opens the local terminal a `terminal` presentation asks for.
    ///
    /// Section 7: a session created anywhere, including on a paired device, can ask for a local
    /// tab, and failing to open it leaves the session available and returns a separate
    /// presentation error rather than creating a duplicate session. The window runs `kr attach` on
    /// the session's own identifier and environment, never on a display number: two environments
    /// can each have a session one, and a window opened on the number would attach to whichever
    /// the command happened to resolve.
    async fn present(
        &self,
        create: &SessionCreateParams,
        session_id: SessionId,
    ) -> Option<ProtocolError> {
        if create.presentation != kr_protocol::session::Presentation::Terminal {
            return None;
        }
        let command = vec![
            self.attach_program().display().to_string(),
            "attach".to_owned(),
            session_id.to_string(),
            "--environment".to_owned(),
            create.environment_id.to_string(),
        ];
        let terminal = Arc::clone(&self.terminal);
        let requested = create.terminal.0.clone();
        // Opening a window starts a process and waits a bounded moment on it, which is work for a
        // thread that may block rather than for the runtime this daemon serves every other client
        // on.
        let outcome = tokio::task::spawn_blocking(move || {
            terminal.present(requested.as_deref(), &command).err()
        })
        .await
        .unwrap_or_else(|error| {
            Some(
                kr_shell_integration::host::terminal::TerminalUnavailable::CouldNotOpen {
                    application: "the selected terminal".to_owned(),
                    detail: error.to_string(),
                },
            )
        })
        .map(|unavailable| unavailable.to_protocol_error());
        // Retained so a create token asked twice is answered with what happened rather than with
        // a second window or a claim that the first one opened.
        self.presentations
            .lock()
            .await
            .insert(session_id, outcome.clone());
        outcome
    }

    /// Returns what a replayed create says about its session's presentation.
    ///
    /// The outcome this host retained, where it has one. Where it has none the create was admitted
    /// by a daemon that has since been replaced, and whether a window opened is not something this
    /// one can establish: it says so rather than opening a second one or claiming the first.
    async fn replayed_presentation(
        &self,
        create: Option<&SessionCreateParams>,
        session_id: SessionId,
    ) -> Option<ProtocolError> {
        if create.is_none_or(|create| {
            create.presentation != kr_protocol::session::Presentation::Terminal
        }) {
            return None;
        }
        match self.presentations.lock().await.get(&session_id) {
            Some(outcome) => outcome.clone(),
            None => Some(ProtocolError::new(
                ErrorCode::OutcomeUnknown,
                "this host did not admit the create this token replays, so whether its terminal \
                 window opened is not something it can say",
            )),
        }
    }

    /// Returns the client executable a terminal window runs.
    ///
    /// Beside this daemon's own, because they are installed together and a host with two
    /// installations must open the one it is running.
    fn attach_program(&self) -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(|parent| parent.join("kr")))
            .unwrap_or_else(|| PathBuf::from("kr"))
    }

    /// Resolves a reservation that never reached a launch, and releases what it was holding.
    ///
    /// The phase is the durable half: a reservation recorded as failed stops occupying the
    /// environment and is never resumed. The pending report and the directory prepared for the
    /// worker go with it, because nothing is going to use either.
    async fn resolve_failed(&self, reservation_id: ReservationId) -> Result<()> {
        self.pending.lock().await.remove(&reservation_id);
        let mut registry = self.registry.lock().await;
        let session_id = registry
            .reservation(reservation_id)?
            .map(|reservation| reservation.session_id);
        registry.set_phase(reservation_id, LaunchPhase::Failed)?;
        drop(registry);
        if let Some(session_id) = session_id {
            self.discard_worker_dir(session_id);
        }
        Ok(())
    }

    /// Gives back the directory a worker was to run in.
    ///
    /// Best effort by design. A worker on its way out may still be holding it, which on Windows
    /// refuses the removal; what that leaves is an empty directory, and the sweep this daemon runs
    /// at startup takes it then.
    fn discard_worker_dir(&self, session_id: SessionId) {
        let _ = std::fs::remove_dir_all(self.paths.worker_dir(session_id));
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

    async fn replay_create(
        &self,
        reservation: &crate::registry::Reservation,
    ) -> Result<ParamsValue> {
        // A retry can arrive before this daemon has adopted the worker its first attempt started,
        // which is what happens when a restart landed while the session was still qualifying.
        if self
            .directory
            .lock()
            .await
            .get(reservation.session_id)
            .is_none()
        {
            self.recover_claim_for(reservation.session_id).await?;
        }
        let worker = self
            .directory
            .lock()
            .await
            .get(reservation.session_id)
            .cloned();
        // What the first attempt asked for, which is what says whether a window was ever part of
        // this create. A record this build cannot read says nothing about a presentation.
        let requested = reservation
            .create_intent
            .as_deref()
            .and_then(|recorded| recorded_create(recorded).ok());
        if let Some(worker) = worker {
            let summary = self.read_from_worker(&worker).await?.session;
            return encode(&SessionCreateResult {
                session: summary,
                endpoint: Nullable::some(worker.endpoint.as_text()),
                deduplicated: true,
                presentation_error: Nullable(
                    self.replayed_presentation(requested.as_ref(), reservation.session_id)
                        .await,
                ),
            });
        }
        let registry = self.registry.lock().await;
        let closure = registry.closure(reservation.session_id)?;
        drop(registry);
        match closure {
            Some(closure) => encode(&SessionCreateResult {
                session: self
                    .closed_session(&closure, reservation.display_number)
                    .await,
                // A closed session has no endpoint to attach to, which the reply says rather than
                // handing back a path that leads nowhere.
                endpoint: Nullable::null(),
                // A closed session has no window either way, so there is no presentation to
                // report on: what the caller is owed here is the closure record.
                presentation_error: Nullable::null(),
                deduplicated: true,
            }),
            None => Err(ControllerError::supervision(format!(
                "this create token is already recorded as {} and its worker is not available",
                reservation.phase.as_str()
            ))),
        }
    }

    /// Proxies a close to the worker that owns the session.
    ///
    /// The caller's envelope is forwarded, not replaced. The action identifier is the durable
    /// identity of the caller's action, and rewriting it here would give the worker a different
    /// action from the one the caller asked for: a retry would then find no receipt, and the
    /// caller's own identifier would name nothing.
    async fn session_close(
        self: &Arc<Self>,
        mutation: &MutationRequest,
        actor: &kr_protocol::actor::ActorEnvelope,
        accepted: Option<AcceptedDeadline>,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<ParamsValue> {
        let params: SessionCloseParams = parse(&mutation.params)?;
        let worker = self.directory.lock().await.get(params.session_id).cloned();
        let Some(worker) = worker else {
            let registry = self.registry.lock().await;
            let closure = registry.closure(params.session_id)?;
            drop(registry);
            return match closure {
                // A duplicate close returns the existing state rather than closing anything again.
                Some(closure) => encode(&SessionCloseResult {
                    session_id: params.session_id,
                    state: SessionState::Closed,
                    durability: closure.durability,
                    closure: Nullable::some(closure),
                }),
                None => Err(ControllerError::UnknownSession {
                    session: params.session_id.to_string(),
                }),
            };
        };
        // One budget for the whole exchange, started before the wait for the connection. Section 7
        // gives a closure five seconds to stop its processes and two more to drain them, and this
        // daemon holds one connection per worker: a worker that stops answering would otherwise
        // hold that connection for every later caller, and the wait for it would be unbounded on
        // both sides of the handover.
        let budget = tokio::time::Instant::now() + CLOSE_EXCHANGE;
        let result = {
            // The connection comes first. Waiting for it can take as long as whatever else is using
            // it, and a deadline computed before that wait would hand the worker time that had
            // already been spent queueing.
            let mut held = tokio::time::timeout_at(budget, self.worker_client(&worker))
                .await
                .map_err(|_| {
                    // Nothing was dispatched: this close never reached the worker, and the link it
                    // was queueing for belongs to whoever is holding it. The caller can ask again.
                    ControllerError::supervision(
                        "the connection to the worker that owns this session did not come free in \
                         time, so nothing was closed",
                    )
                })??;
            // Taken with the link in hand, not before the wait for it: another operation can lose
            // this worker's control path and a replacement can be established and acknowledged
            // while this close is still queueing, and fencing the binding that was current then
            // would lift nothing. This is the path the exchange below actually runs over.
            let binding = self.leases.binding(params.session_id);
            // The admission is checked here rather than before the wait, because this is where
            // the wait was. A deadline that ran out while this close queued does not stop it
            // reaching the worker, because the worker is the only thing that knows whether it
            // already holds this action's receipt; what a spent deadline stops is a *first*
            // admission, and the worker refuses that for the same reason this daemon would have.
            // The authority half is different: it refuses outright, because disclosing anything
            // under authority that has been withdrawn is what the contract forbids.
            {
                // Inside the same budget as the exchange: this daemon is holding the worker's link
                // while it asks, and a registry another operation is holding must not let that
                // link be held past what a closure is allowed to take.
                let registry = tokio::time::timeout_at(budget, self.registry.lock())
                    .await
                    .map_err(|_| {
                        ControllerError::supervision(
                            "this daemon could not read its own authority in time, so nothing was \
                             closed",
                        )
                    })?;
                match self.check_admission(&registry, &carried) {
                    Ok(()) => {}
                    Err(ControllerError::WindowExpired { .. }) => {}
                    Err(error) => return Err(error),
                }
            }
            // Remote dispatch additionally needs a live lease, taken at the moment the dispatch
            // runs rather than one that was valid when the request arrived. Its own remaining time
            // then bounds the deadline the worker is given.
            let lease_deadline = self.dispatch_lease(params.session_id, actor).await?;
            // What the worker is told is the accepted deadline itself, on the machine's own
            // continuous clock: the same clock the worker reads, so the deadline does not restart
            // on arrival and nothing has to guess at what the journey cost. A deadline already
            // spent is forwarded as spent - nought is in every boot's past - rather than as a
            // refusal, so the worker answers from what it holds and admits nothing new.
            let accepted_deadline_boot_ms = accepted
                .and_then(|accepted| {
                    remaining_deadline(
                        &*self.shared_clock,
                        &*self.clock,
                        accepted.deadline,
                        lease_deadline,
                    )
                })
                .unwrap_or_else(|| U64::new(0));
            let client = held.as_mut().expect("the connection is open");
            match tokio::time::timeout_at(
                budget,
                client.forward(
                    mutation,
                    actor,
                    // A local caller acts under the operating-system identity the listener
                    // authenticated rather than under a grant, so there are no rights to narrow
                    // what it asked for.
                    &CanonicalSet::new(),
                    accepted_deadline_boot_ms,
                ),
            )
            .await
            {
                Ok(Ok(result)) => result,
                // The path this daemon announces authority revisions over is gone, whether it
                // ended or stopped answering. Renewal stops with it: section 9 lets a remote
                // dispatch lease be renewed only after the worker has acknowledged the revision,
                // and this daemon can no longer hear an acknowledgement from that worker.
                Ok(Err(error)) => {
                    *held = None;
                    self.leases.stop_renewal(params.session_id, binding);
                    return Err(error.into());
                }
                // The close was written and no answer came back inside the time a closure is
                // allowed to take. The client is retired rather than returned to the shared slot:
                // its exchange was abandoned part way through, so the next caller to pick it up
                // would read this close's reply as the answer to its own request. Whether the
                // worker acted on it is not known, which is what the caller is told: section 9
                // does not let an interrupted dispatch be reported as a refusal.
                Err(_) => {
                    *held = None;
                    self.leases.stop_renewal(params.session_id, binding);
                    return Err(ControllerError::Uncertain {
                        detail:
                            "the worker did not answer this close within the time a closure is \
                                 given, so whether the session is stopping is not known"
                                .to_owned(),
                    });
                }
            }
        };
        match result {
            Ok(value) => {
                // A retry of an action this worker settled without closing anything answers with
                // its receipt rather than a close result. That is the right answer to the caller's
                // retry, so it is passed through as it stands: reading it as a close result would
                // turn the receipt the caller asked for into a decoding failure.
                let Ok(reply) = value.to_typed::<SessionCloseResult>() else {
                    return Ok(value);
                };
                match reply.closure.as_ref() {
                    // The worker's own account of how its session ended, which is the best one
                    // there is, written through the same boundary as every other closure so that
                    // nothing this daemon writes afterwards can replace it.
                    Some(record) => {
                        self.record_closure_once(record).await?;
                    }
                    // The worker has accepted the close and is stopping its processes. Something
                    // has to notice when that finishes, so the tombstone is written and the
                    // descriptor removed rather than left pointing at a process that has gone.
                    None => {
                        tokio::spawn(
                            Arc::clone(self)
                                .watch_closure(params.session_id, ClosureReason::CloseRequested),
                        );
                    }
                }
                encode(&reply)
            }
            Err(error) => Err(ControllerError::InvalidArgument(error.to_string())),
        }
    }

    /// Waits for a closing worker to end, then records its closure and retires it.
    ///
    /// The worker's acceptance says `closing`, because section 7 gives the requester its answer
    /// before anything is signalled. Something still has to notice when the closure finishes, and
    /// that is this: it watches the process identity the registry holds, and writes the record once
    /// the kernel agrees the worker is gone.
    pub async fn watch_closure(self: Arc<Self>, session_id: SessionId, reason: ClosureReason) {
        let deadline = std::time::Instant::now() + CLOSURE_WATCH_TIMEOUT;
        loop {
            let identity = {
                let registry = self.registry.lock().await;
                registry
                    .workers()
                    .ok()
                    .and_then(|workers| {
                        workers
                            .into_iter()
                            .find(|record| record.session_id == session_id)
                    })
                    .map(|record| record.process_identity)
            };
            let Some(identity) = identity else {
                // The session has left this daemon's directory, which is what recording a closure
                // does, so something else finished what this watcher was waiting for.
                self.review_power_soon();
                return;
            };
            match kr_ipc::identity::process_state(&identity) {
                kr_ipc::identity::ProcessState::Ended => {
                    let _ = self
                        .record_final(
                            session_id,
                            reason,
                            &identity,
                            &crate::archive::ArchiveService::nothing_fenced(session_id),
                            true,
                        )
                        .await;
                    // The closure this watcher was waiting on has finished, so what it was
                    // counted as is over. Whoever asked for it is not waiting for this.
                    self.review_power_soon();
                    return;
                }
                kr_ipc::identity::ProcessState::Running
                | kr_ipc::identity::ProcessState::Unknown { .. } => {}
            }
            if std::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }

    /// Reconciles a session whose worker cannot be reached.
    ///
    /// If the recorded process is gone the session is closed and recorded as an abnormal closure,
    /// which is what section 24 requires when the controller detects a worker's death. If the
    /// process is still running, or the kernel will not say, nothing is recorded: a controller that
    /// cannot reach a worker has not established that the worker is dead.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read or written.
    pub async fn reconcile(&self, session_id: SessionId) -> Result<Option<ClosureRecord>> {
        let record = {
            let registry = self.registry.lock().await;
            registry
                .workers()?
                .into_iter()
                .find(|record| record.session_id == session_id)
        };
        let Some(record) = record else {
            return Ok(None);
        };
        // The archive takes exclusive recovery ownership, and only on its own terms: the kernel
        // is asked whether the recorded process is the process that was recorded, and only then
        // is the endpoint fenced. A query the platform declines is not death, and leaves the
        // session alone. Nothing here creates a worker.
        let archive = self.archive();
        let Ok(ownership) =
            archive.take_ownership(session_id, record.display_number, &record.process_identity)
        else {
            return Ok(None);
        };
        // Section 9's recovery rules are the worker's, and a worker that crashed never ran them.
        // They run once here instead, before anything is served: a dispatch marker with no
        // authoritative outcome becomes `unknown`, and an accepted intent with no marker is
        // rejected. A failure is not a reason to leave the session open, so the closure is still
        // written; what says the store was not reconciled is the archive, which reports an action
        // still accepted or still dispatching when a reader asks.
        let _ = archive.recover_journal(&ownership);
        let reason = self.why_a_worker_is_gone(session_id, record.profile);
        // Section 7's second half, before the session identity is released: whatever the session
        // still owns is fenced, and what this host cannot account for is recorded. A closure
        // written before that would be a closure a crash between the two could not lead back to.
        let reported = ClosureRecord {
            session_id,
            session_epoch: SessionEpoch::V1,
            reason,
            root_exit_code: Nullable::null(),
            root_signal: Nullable::null(),
            terminated: Vec::new(),
            surviving: Vec::new(),
            ownership_coverage: kr_protocol::session::OwnershipCoverage::Incomplete,
            durability: kr_protocol::session::Durability::Durable,
            closed_at_ms: kr_ipc::now_ms(),
        };
        let fenced = archive.fence_owned(&ownership, &reported);
        let closure = self
            .record_final(session_id, reason, &record.process_identity, &fenced, true)
            .await?;
        Ok(Some(closure))
    }

    /// Returns the reason a worker that is confirmed gone ended, where this host can establish
    /// one.
    ///
    /// A desktop-bound worker whose desktop has gone went with it: the platform ended the job with
    /// the login session it was in, which is what a logout does, and the worker had no chance to
    /// write its own record. The desktop the session was created on is in the worker's own
    /// journal, which outlives the worker, so the platform can be asked about that login session
    /// by name. That is an answer rather than a guess even after the person has logged in again,
    /// and it is an answer about the right session on a host where one user holds several at once:
    /// the desktop this daemon itself is in says nothing about another login's.
    ///
    /// Everything else is a worker that ended for reasons this host does not know, including a
    /// desktop it could not read: an unreadable platform is not a logout.
    fn why_a_worker_is_gone(&self, session_id: SessionId, profile: WorkerProfile) -> ClosureReason {
        if profile != WorkerProfile::DesktopBound {
            return ClosureReason::WorkerCrash;
        }
        let Some(recorded) = self.recorded_desktop(session_id) else {
            return ClosureReason::WorkerCrash;
        };
        match kr_worker::desktop::recorded_presence(&recorded) {
            // The login session this session was created on is not there any more.
            kr_worker::desktop::Presence::Ended => ClosureReason::DesktopLost,
            kr_worker::desktop::Presence::Present | kr_worker::desktop::Presence::Unknown => {
                ClosureReason::WorkerCrash
            }
        }
    }

    /// Returns the desktop a session was created on, from its own journal.
    ///
    /// The journal is in the environment's state directory and outlives the worker that wrote it,
    /// which is what makes this readable after the worker has gone.
    fn recorded_desktop(
        &self,
        session_id: SessionId,
    ) -> Option<kr_protocol::identity::DesktopBinding> {
        self.archive().bring_forward(session_id);
        let path = self.paths.journal_database(session_id);
        let journal = kr_worker::journal::Journal::open_read_only(path).ok()?;
        journal
            .read_session(session_id)
            .ok()
            .flatten()
            .map(|summary| summary.desktop)
    }

    /// Records a closure a worker handed over, unless one is already recorded.
    ///
    /// This, [`Self::record_final`] and [`Self::retire`] are the three entry points that write one,
    /// and each holds the same lock for the whole of its check and its write. A worker's own
    /// account of how its session ended carries the root's result and what it stopped, and a record
    /// written from outside knows neither, so one must never be able to replace the other.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read or written.
    async fn record_closure_once(&self, record: &ClosureRecord) -> Result<ClosureRecord> {
        let _finalising = self.finalising.lock().await;
        if let Some(existing) = self.registry.lock().await.closure(record.session_id)? {
            return Ok(existing);
        }
        self.write_closure(record).await?;
        Ok(record.clone())
    }

    /// Records how a session ended, once.
    ///
    /// The whole of it is one transaction: the closure already recorded is the answer where there
    /// is one, and where there is not, the record written here is the only one written. Four paths
    /// reach a closure for the same session, because the closure watcher, this daemon's own
    /// reconciliation, a worker handing over its own account and the answer a worker gives a paired
    /// device all produce one, and a second record would replace the first rather than adding to
    /// it.
    async fn record_final(
        &self,
        session_id: SessionId,
        reason: ClosureReason,
        identity: &kr_protocol::identity::ProcessStartIdentity,
        fenced: &crate::archive::Fenced,
        death_validated: bool,
    ) -> Result<ClosureRecord> {
        let _finalising = self.finalising.lock().await;
        if let Some(existing) = self.registry.lock().await.closure(session_id)? {
            return Ok(existing);
        }
        // The worker's own journal is the authority on how its session ended. It recorded the
        // root's exit status, what it stopped and how much of that it could account for; a record
        // written from outside knows none of those.
        //
        // The worker's own journal is read only where the caller established that the worker
        // ended. Writing this closure removes both the registry's worker row and the published
        // descriptor, which are the two things a later read asks about, so a closure written over
        // an unconfirmed death has to carry that fact itself - see `surviving` below - and must
        // not open the store on the way.
        if death_validated && let Some(recovered) = self.recovered_closure(session_id) {
            self.write_closure(&recovered).await?;
            return Ok(recovered);
        }
        // Nothing authoritative survived. What is written instead says so: the coverage is
        // incomplete and the root's result is absent rather than invented.
        // A worker this host saw end is terminated; one it did not is not, whatever else is true
        // of the session. Saying otherwise in the record would be the record claiming the one
        // thing this host could not establish.
        let mut terminated = Vec::new();
        let mut surviving = fenced.surviving.clone();
        if death_validated {
            terminated.push(kr_protocol::session::TerminatedProcess {
                identity: identity.clone(),
                name: Nullable::some("the session's worker".to_owned()),
                forced: false,
            });
        } else {
            surviving.push(kr_protocol::session::SurvivingResource {
                kind: UNACCOUNTED_WORKER.to_owned(),
                detail: format!(
                    "this host closed the session without confirming that its worker, {}, ended",
                    identity.pid.get()
                ),
            });
        }
        // Whatever the fence did reach, recorded where a later reader is served it rather than
        // only where this daemon can see it.
        terminated.extend(fenced.stopped.iter().map(|identity| {
            kr_protocol::session::TerminatedProcess {
                identity: identity.clone(),
                name: Nullable::some("a process this session still owned".to_owned()),
                forced: true,
            }
        }));
        let record = ClosureRecord {
            session_id,
            session_epoch: SessionEpoch::V1,
            reason,
            root_exit_code: Nullable::null(),
            root_signal: Nullable::null(),
            terminated,
            surviving,
            // The controller confirmed the worker process ended. It does not claim to have
            // discovered every application that worker may have started, and a recovery or a
            // fence that could not finish is another thing it cannot account for.
            ownership_coverage: kr_protocol::session::OwnershipCoverage::Incomplete,
            // Section 23 defines this as whether the *record* was written durably, which is what
            // `write_closure` below does or fails doing. It says nothing about whether the
            // session's own store was reconciled: a recovery pass that was skipped or failed is
            // reported by the archive, which reads the store rather than this record.
            durability: kr_protocol::session::Durability::Durable,
            closed_at_ms: kr_ipc::now_ms(),
        };
        self.write_closure(&record).await?;
        Ok(record)
    }

    /// Serves one page of a closed session's retained output.
    ///
    /// KR-ACC-029: a history request never creates a worker. A session whose worker is alive is
    /// refused here with the endpoint to ask, because that worker owns its own spool and reading
    /// it from outside would be a second reader of a store that is still being written.
    async fn archive_history_page(self: &Arc<Self>, params: &ParamsValue) -> Result<ParamsValue> {
        let params: kr_protocol::recovery::HistoryPageParams = parse(params)?;
        self.refuse_if_live(params.session_id).await?;
        let page = self.archive().history_page(
            params.session_id,
            params.from_cursor.get(),
            params.max_bytes.get(),
        )?;
        encode(&page)
    }

    /// Returns the environment's backup service.
    ///
    /// The daemon owns it so that one process accounts for what this environment has produced:
    /// two writers of one `backup.sqlite` would be two accounts of the same archive.
    #[must_use]
    pub fn backup(&self) -> &Arc<crate::backup::BackupService> {
        &self.backup
    }

    /// Serves one retained receipt of a closed session.
    async fn archive_action_read(
        self: &Arc<Self>,
        actor_id: &ActorId,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        let params: kr_protocol::receipt::ActionReadParams = parse(params)?;
        let Some(session_id) = params.session_id else {
            return Err(ControllerError::InvalidArgument(
                "a receipt this daemon serves belongs to a session, which this request does not                  name"
                    .to_owned(),
            ));
        };
        self.refuse_if_live(session_id).await?;
        let read = self
            .archive()
            .receipt(session_id, actor_id, params.action_id)?;
        encode(&read)
    }

    /// Refuses a read of a session whose worker this daemon has not confirmed gone.
    ///
    /// Three things can say so, and a closure erases two of them: writing it removes the
    /// registry's worker row and retires the published descriptor. So the closure carries the
    /// third itself. A session closed without a confirmed death lists its worker as a surviving
    /// resource rather than a terminated one, and that is what this reads once the other two are
    /// gone.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument refusal naming what this host has not established.
    async fn refuse_if_live(self: &Arc<Self>, session_id: SessionId) -> Result<()> {
        if self.a_worker_may_still_own(session_id).await? {
            return Err(ControllerError::InvalidArgument(format!(
                "session {session_id} has a worker this daemon has not confirmed ended"
            )));
        }
        Ok(())
    }

    /// Returns whether anything this host can read says the session's worker may still be there.
    ///
    /// This is the one question every read and every migration asks. It is deliberately
    /// pessimistic: a query the platform declines establishes nothing, and nothing is the answer
    /// that keeps a store shut.
    async fn a_worker_may_still_own(self: &Arc<Self>, session_id: SessionId) -> Result<bool> {
        let (row, closure) = {
            let registry = self.registry.lock().await;
            // A registry this host cannot read answers nothing, and nothing is not "no worker".
            // Both reads are propagated rather than flattened away, because the caller refusing
            // with the registry's own error is the safe end of that.
            let row = registry
                .workers()?
                .into_iter()
                .find(|row| row.session_id == session_id);
            (row, registry.closure(session_id)?)
        };
        if let Some(row) = row
            && !matches!(
                kr_ipc::identity::process_state(&row.process_identity),
                kr_ipc::identity::ProcessState::Ended
            )
        {
            return Ok(true);
        }
        if let Some(closure) = closure
            && closure
                .surviving
                .iter()
                .any(|resource| resource.kind == UNACCOUNTED_WORKER)
        {
            return Ok(true);
        }
        Ok(self.archive().a_worker_may_still_own(session_id))
    }

    /// Reads what one session left behind, with the registry's own record beside it.
    ///
    /// A crashed worker never wrote its own closure and the record this host wrote for it is in
    /// the registry, so the archive is given it rather than left to report a closure as missing
    /// that this host is holding.
    ///
    /// # Errors
    ///
    /// Returns the registry's refusal, or the archive's.
    pub async fn session_archive(
        self: &Arc<Self>,
        session_id: SessionId,
    ) -> Result<crate::archive::Archive> {
        // The same question every archive read asks first. A session whose registry record names
        // a process this daemon has not seen end is refused here rather than read from: the
        // worker owns its own stores while it is alive, and a closure written over a death this
        // host could not confirm is not a licence to open them.
        self.refuse_if_live(session_id).await?;
        let recorded = self.registry.lock().await.closure(session_id)?;
        self.archive().archive_beside(session_id, recorded)
    }

    /// Reads the closure a worker wrote for itself, when one survived it.
    fn recovered_closure(&self, session_id: SessionId) -> Option<ClosureRecord> {
        self.archive().bring_forward(session_id);
        let path = self.paths.journal_database(session_id);
        let journal = kr_worker::journal::Journal::open_read_only(&path).ok()?;
        journal.read_closure(session_id).ok().flatten()
    }

    /// Reads the session a worker described, when its journal survived it.
    fn recovered_summary(&self, session_id: SessionId) -> Option<SessionSummary> {
        // A session that closed before this build shipped wrote an earlier schema. The archive
        // brings such a store forward once, under this daemon's ownership of a session with no
        // worker, so the shell, the directory, the geometry and the creation time it holds are
        // still what a person is shown.
        self.archive().bring_forward(session_id);
        let path = self.paths.journal_database(session_id);
        let journal = kr_worker::journal::Journal::open_read_only(&path).ok()?;
        journal.read_session(session_id).ok().flatten()
    }

    /// Describes a closed session from what its worker recorded, or from what is left.
    async fn closed_session(
        &self,
        closure: &ClosureRecord,
        display_number: kr_protocol::session::DisplayNumber,
    ) -> SessionSummary {
        // The worker recorded what its session was. Using it keeps the shell, the directory, the
        // geometry and the creation time a person sees after the session has closed - but only
        // where this host established that the worker ended. A closure this host wrote over a
        // death it could not confirm says so in its own surviving list, and then the store stays
        // shut and the summary is built from the closure alone.
        if closure
            .surviving
            .iter()
            .any(|resource| resource.kind == UNACCOUNTED_WORKER)
        {
            return closed_summary(closure, self.paths.environment_id(), display_number);
        }
        self.recovered_summary(closure.session_id).map_or_else(
            || closed_summary(closure, self.paths.environment_id(), display_number),
            |mut summary| {
                summary.state = SessionState::Closed;
                summary.attachment_count = U64::ZERO;
                summary.application_state = Nullable::null();
                summary.root_process = Nullable::null();
                summary.closure = Nullable::some(closure.clone());
                summary
            },
        )
    }

    /// Records a closure from outside this daemon's own bookkeeping, unless one is already
    /// recorded, and looks at the sleep setting afterwards.
    ///
    /// This is the entry point for a closure a caller outside this module has been handed, which
    /// today is the answer a worker gives a paired device. It holds the same lock across its check
    /// and its write as [`Self::record_closure_once`] and [`Self::record_final`], so a worker's own
    /// account of how its session ended can never be replaced by a later record, whichever path
    /// carried it. A session that has ended is work that has ended, so the setting is looked at
    /// once the record is written; the caller's own answer never waits for that.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read or written.
    pub async fn retire(self: &Arc<Self>, record: &ClosureRecord) -> Result<()> {
        let written = {
            let _finalising = self.finalising.lock().await;
            if self
                .registry
                .lock()
                .await
                .closure(record.session_id)?
                .is_some()
            {
                // Somebody else recorded this closure first. That it is recorded at all is what
                // the setting is about, so the look below happens either way.
                Ok(())
            } else {
                self.write_closure(record).await
            }
        };
        // Outside the lock, and before the result is returned: the registry row is written before
        // the descriptor is removed, so a failure after that point is a closure that counts as
        // finished with an error to report about the tidying.
        self.review_power_soon();
        written
    }

    /// Records a closed session, removes its descriptor and forgets its key.
    ///
    /// The caller holds `finalising` and has found that no closure is recorded yet. Nothing else
    /// may write one: two writers without that hold would let this daemon's own account of a
    /// worker it found gone replace the worker's own.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be written.
    async fn write_closure(&self, record: &ClosureRecord) -> Result<()> {
        let mut registry = self.registry.lock().await;
        registry.record_closure(record)?;
        drop(registry);
        // This daemon's own view of the session goes as soon as the closure is recorded, before
        // the published descriptor is removed and whether or not that succeeds. The closure is
        // the fact; a worker kept in the directory after it would be a session this daemon still
        // asked about, still counted as work outstanding, and still answered for.
        self.directory.lock().await.remove(record.session_id);
        self.connections.lock().await.remove(&record.session_id);
        // A closed session has no window to report on, and a create token that replays one is
        // answered from the closure record.
        self.presentations.lock().await.remove(&record.session_id);
        // The barrier is told before the record is gone. A worker that has ended satisfies the
        // barrier, and the barrier keeps a participant it has ever heard of: without this, a
        // retired worker would stay pending for every later revocation, because nothing would be
        // left to say that it ended.
        self.leases.worker_ended(record.session_id);
        // The session has stopped being work this host counts, and this is the line where that
        // became true of everything the counting reads: the record is written and the session has
        // left the directory a demand scan takes its list from. Every path that records a closure
        // reaches here, so the look at the setting happens here rather than at each of them, and
        // it happens before the tidying below, which can fail.
        if let Some(controller) = self.me.upgrade() {
            controller.review_power_soon();
        }
        // The directory the worker ran in goes with the session. It holds nothing the closure
        // record needs, and one per session that nothing removes would outlive every session this
        // host has ever run. A worker still on its way out may be holding it; on the platforms
        // where that refuses the removal, the next start writes the directory again.
        let _ = std::fs::remove_dir_all(self.paths.worker_dir(record.session_id));
        kr_ipc::descriptor::retire(&self.paths, record.session_id)?;
        Ok(())
    }

    async fn read_from_worker(&self, worker: &KnownWorker) -> Result<SessionReadResult> {
        self.read_from_worker_within(worker, None).await
    }

    /// Reads a session from its worker, optionally giving the worker a bounded moment to answer.
    ///
    /// The bound belongs here rather than around the call. A request abandoned from outside would
    /// leave this connection with an answer nobody read, and the next caller to use it would take
    /// that answer for its own; ending the connection is the only way to abandon a request on it,
    /// and that can only be done from inside, while its guard is still held.
    ///
    /// One deadline covers both halves. Waiting for the connection and waiting for the answer are
    /// two waits on one worker, and giving each the whole patience would let a worker take twice
    /// what its caller allowed, which is what a caller dividing a budget between workers is
    /// counting on it not doing.
    async fn read_from_worker_within(
        &self,
        worker: &KnownWorker,
        patience: Option<std::time::Duration>,
    ) -> Result<SessionReadResult> {
        let deadline = patience.map(|patience| tokio::time::Instant::now() + patience);
        let mut held = match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, self.worker_client(worker))
                .await
                .map_err(|_| {
                    ControllerError::supervision("the worker's connection was busy for too long")
                })??,
            None => self.worker_client(worker).await?,
        };
        let client = held.as_mut().expect("the connection is open");
        let params = SessionReadParams {
            session_id: worker.descriptor.session_id,
        };
        let asked = client.request(Method::SessionRead, &params);
        let result = match deadline {
            Some(deadline) => match tokio::time::timeout_at(deadline, asked).await {
                Ok(result) => result,
                Err(_) => {
                    // The request was abandoned, so this connection has an answer nobody will
                    // read. It ends here; the next call opens a new one.
                    *held = None;
                    return Err(ControllerError::supervision(
                        "the worker did not answer in time",
                    ));
                }
            },
            None => asked.await,
        };
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                // A transport failure ends this connection. The next call opens a new one and
                // presents the generation again rather than writing into a socket that is gone,
                // and renewal stops with the path rather than outliving it.
                *held = None;
                self.lost_control_path(worker.descriptor.session_id);
                return Err(error.into());
            }
        };
        match result {
            Ok(value) => reported_read(&value)
                .map_err(|error| ControllerError::InvalidArgument(error.to_string())),
            Err(error) => Err(ControllerError::InvalidArgument(error.to_string())),
        }
    }

    /// Returns this daemon's one connection to a worker, opening it if there is none.
    ///
    /// The guard is held for the whole call, so two operations against one worker run in order
    /// rather than racing each other's authority.
    async fn worker_client(
        &self,
        worker: &KnownWorker,
    ) -> Result<tokio::sync::OwnedMutexGuard<Option<LocalClient>>> {
        let link = {
            let mut connections = self.connections.lock().await;
            Arc::clone(
                connections
                    .entry(worker.descriptor.session_id)
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(None))),
            )
        };
        let mut held = link.lock_owned().await;
        if held.is_none() {
            *held = Some(self.open_worker(worker).await?);
        }
        Ok(held)
    }

    /// Returns this daemon's one connection to the worker of one session.
    ///
    /// The directory is what says where that worker is. A session the directory does not list has
    /// no connection to open, which is a worker this daemon has not reached rather than an error
    /// about the session.
    async fn worker_client_of(
        &self,
        session_id: SessionId,
    ) -> Result<tokio::sync::OwnedMutexGuard<Option<LocalClient>>> {
        let worker = self.directory.lock().await.get(session_id).cloned();
        let worker = worker.ok_or_else(|| ControllerError::UnknownSession {
            session: session_id.to_string(),
        })?;
        self.worker_client(&worker).await
    }

    async fn open_worker(&self, worker: &KnownWorker) -> Result<LocalClient> {
        let mut client = LocalClient::connect(
            &worker.endpoint,
            LocalClientKind::Controller,
            self.build_id.clone(),
        )
        .await?;
        // Two proofs, both required: the worker proves it is the one the descriptor names, and
        // this daemon proves which generation it speaks for.
        client.verify_worker(&worker.descriptor).await?;
        let identity = &self.identity;
        let generation = self.generation;
        let boot = self.boot_identity.clone();
        client
            .present_generation(move |nonce| {
                identity
                    .generation_token(generation, &boot, nonce)
                    .map_err(kr_ipc::IpcError::from)
            })
            .await?;
        Ok(client)
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
fn qualified_package(root: Option<&Path>, requested: Option<&str>) -> Result<PathBuf> {
    use kr_shell_integration::host::package::{PackageSet, default_package_root};

    let installed = match root {
        Some(root) => PackageSet::discover(root),
        None => PackageSet::installed(&default_package_root()),
    }
    .map_err(|fault| ControllerError::ShellIntegrationUnsupported(fault.to_string()))?;
    installed
        .select(requested)
        .map(|package| package.directory.clone())
        .map_err(|fault| ControllerError::ShellIntegrationUnsupported(fault.to_string()))
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
fn reported_read(value: &ParamsValue) -> std::result::Result<SessionReadResult, String> {
    match value.to_typed::<SessionReadResult>() {
        Ok(read) => Ok(read),
        Err(error) => match value.to_typed::<ReportedRead>() {
            Ok(reported) => Ok(reported.into()),
            // Neither shape, so it is reported as the answer this build cannot read rather than
            // as an older worker's.
            Err(_) => Err(error.to_string()),
        },
    }
}

/// A session read as a worker from a build before the launch profile answers it.
#[derive(serde::Serialize, serde::Deserialize)]
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

/// Reads the create request a reservation recorded.
///
/// A reservation outlives the request that made it: its row is written before the worker starts
/// and is still there while the session is live, so a daemon that was replaced part-way through an
/// upgrade reads rows an earlier build wrote. A row recorded before this build's launch profile and
/// terminal selection existed is read through [`RecordedCreate`] and given the defaults those two
/// fields have, which is exactly what that session was created with.
///
/// Remove `RecordedCreate` and this fallback once no reservation recorded before the launch
/// profile existed can still be in a registry. A reservation row outlives the session it made, so
/// that is a migration or a retention boundary rather than a restart: the condition is met when
/// the registry has been rewritten forward, or when retention has removed every row written before
/// the field existed.
///
/// # Errors
///
/// Returns the decoding failure when the record is neither shape.
fn recorded_create(recorded: &[u8]) -> std::result::Result<SessionCreateParams, String> {
    match kr_cbor::from_canonical_slice::<SessionCreateParams>(recorded, &kr_cbor::Limits::DEFAULT)
    {
        Ok(create) => Ok(create),
        Err(error) => match kr_cbor::from_canonical_slice::<RecordedCreate>(
            recorded,
            &kr_cbor::Limits::DEFAULT,
        ) {
            Ok(legacy) => Ok(legacy.into()),
            // The row is neither shape, so it is reported as the record this build cannot read
            // rather than as a legacy row.
            Err(_) => Err(error.to_string()),
        },
    }
}

/// A create request as a build before the launch profile recorded it.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedCreate {
    environment_id: EnvironmentId,
    presentation: kr_protocol::session::Presentation,
    shell: Nullable<String>,
    shell_mode: kr_protocol::session::ShellMode,
    cwd: Nullable<String>,
    dimensions: Nullable<kr_protocol::session::Dimensions>,
    worker_profile: WorkerProfile,
    environment_snapshot: Vec<kr_protocol::session::EnvironmentVariable>,
    palette: Nullable<kr_protocol::session::PaletteRequest>,
}

impl From<RecordedCreate> for SessionCreateParams {
    fn from(recorded: RecordedCreate) -> Self {
        Self {
            environment_id: recorded.environment_id,
            presentation: recorded.presentation,
            shell: recorded.shell,
            shell_mode: recorded.shell_mode,
            cwd: recorded.cwd,
            dimensions: recorded.dimensions,
            worker_profile: recorded.worker_profile,
            environment_snapshot: recorded.environment_snapshot,
            palette: recorded.palette,
            launch_profile: kr_protocol::session::LaunchProfile::default(),
            terminal: Nullable::null(),
        }
    }
}

fn closed_summary(
    closure: &ClosureRecord,
    environment_id: EnvironmentId,
    display_number: kr_protocol::session::DisplayNumber,
) -> SessionSummary {
    SessionSummary {
        session_id: closure.session_id,
        session_epoch: closure.session_epoch,
        environment_id,
        display_number,
        state: SessionState::Closed,
        shell_mode: kr_protocol::session::ShellMode::NativeCompat,
        shell_path: String::new(),
        cwd: String::new(),
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: kr_protocol::identity::DesktopBinding::none(),
        created_at_ms: closure.closed_at_ms,
        dimensions: kr_protocol::session::INVISIBLE_DEFAULT_DIMENSIONS,
        attachment_count: U64::ZERO,
        application_state: Nullable::null(),
        root_process: Nullable::null(),
        closure: Nullable::some(closure.clone()),
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

/// The admission one voice mutation arrived under, as the coordinator asks about it.
///
/// The deadline is on this daemon's own continuous clock, which is what section 9 measures a
/// mutation's lifetime on and the only clock nothing outside this process can move. The
/// coordinator asks rather than converting, so no reading of the wall clock comes between the
/// admission and the effect.
struct AdmittedUntil {
    controller: Arc<Controller>,
    deadline: kr_transport::clock::ContinuousInstant,
}

impl std::fmt::Debug for AdmittedUntil {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmittedUntil")
            .finish_non_exhaustive()
    }
}

impl kr_voice::Admission for AdmittedUntil {
    fn still_admitted(&self) -> bool {
        self.controller.clock.now() < self.deadline
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

/// Returns whether this daemon forwards the method to the worker that owns the session.
///
/// It decides what a window refusal means. A mutation this daemon performs itself has its
/// retained action here, and a window that admits nothing has already been past it; one it
/// forwards has its retained action in the worker's journal, which only the worker can read.
const fn forwarded_to_worker(method: Method) -> bool {
    matches!(method, Method::SessionClose)
}

/// Returns the sentence a caller is given when a window cannot first-admit a request.
/// Returns the capability revision this environment has already handed out.
///
/// Three answers, and the difference matters. An environment with no record has handed out
/// nothing and starts at zero. A record that reads as a number says what it has handed out. A
/// record that is there and cannot be read says nothing at all, and `None` is that: this host then
/// serves revision zero, which claims nothing, rather than starting again from one and handing out
/// a revision it may already have used.
/// Reads the desktop this host has, and the evidence its resolved execution context has.
///
/// Two readings, because they answer two different questions. The first is what this machine has:
/// a desktop-bound create is refused when there is no desktop, and that is a fact about the
/// machine whatever the configuration prefers. The second is what a session created here would
/// actually get, which is the reading taken in the resolved context rather than the machine's
/// reading with a different label on it: a headless context takes no login session, so it has no
/// desktop session, no display server and no graphical access.
///
/// The platform reading comes first either way, because what the platform offers decides the
/// default the configuration may then override.
fn resolved_desktop(
    chosen: Option<kr_protocol::identity::WorkerProfile>,
    boot: &BootIdentity,
) -> (DesktopContext, DesktopContext) {
    let mut physical = crate::desktop::current(boot.clone());
    let platform = crate::desktop::default_profile(&physical);
    // The product default is the platform's own answer, established here; the rungs above it were
    // read when the configuration was accepted, so this is not a second reading of the document.
    let resolved = chosen.unwrap_or(platform);
    let evidence = if resolved == physical.worker_profile {
        physical.clone()
    } else {
        kr_worker::desktop::context(resolved, boot.clone())
    };
    physical.worker_profile = resolved;
    (physical, evidence)
}

fn capability_revision(paths: &EnvironmentPaths) -> Option<CapabilityRevision> {
    let path = paths.state_dir().join(CAPABILITY_REVISION_FILE);
    match kr_ipc::paths::read_owner_only_file(&path, CAPABILITY_REVISION_LIMIT) {
        Ok(None) => Some(CapabilityRevision::new(0)),
        Ok(Some(bytes)) => String::from_utf8(bytes)
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
            .map(CapabilityRevision::new),
        Err(_) => None,
    }
}

/// Returns capability records in the form two reports are compared in.
///
/// The revision is what the comparison decides, so it cannot be part of it, and the moment each
/// record was observed changes on every report whether anything else did or not. Everything else
/// is evidence.
fn comparable(
    records: &[kr_protocol::desktop::CapabilityRecord],
) -> Vec<kr_protocol::desktop::CapabilityRecord> {
    records
        .iter()
        .map(|record| {
            let mut record = record.clone();
            record.revision = CapabilityRevision::new(0);
            record.observed_at_ms = TimestampMs::new(0);
            record
        })
        .collect()
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

fn parse<T: serde::de::DeserializeOwned + serde::Serialize>(params: &ParamsValue) -> Result<T> {
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

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| format!("uid {}", kr_ipc::paths::current_uid()))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use kr_transport::clock::{ContinuousInstant, ManualClock};

    use super::{ContinuousClock, remaining_deadline};

    /// Two clocks with one pause between the first reading and the second.
    ///
    /// Converting a deadline between two clocks is two readings and a subtraction, and what decides
    /// whether the conversion can add time is which reading comes first. A pause between them is
    /// not something a test can arrange with the real clocks, so this arranges it: whichever side
    /// is read first, both clocks move on by `pause` before the other side is read.
    #[derive(Debug)]
    struct PausedPair {
        shared: kr_ipc::clock::ManualSharedClock,
        process: ManualClock,
        paused: AtomicBool,
        pause: Duration,
    }

    impl PausedPair {
        fn new(pause: Duration) -> Arc<Self> {
            Arc::new(Self {
                shared: kr_ipc::clock::ManualSharedClock::new(),
                process: ManualClock::new(),
                paused: AtomicBool::new(false),
                pause,
            })
        }

        fn pause_once(&self) {
            if !self.paused.swap(true, Ordering::AcqRel) {
                self.shared.advance(self.pause);
                self.process.advance(self.pause);
            }
        }
    }

    #[derive(Debug)]
    struct SharedSide(Arc<PausedPair>);

    impl kr_ipc::clock::SharedClock for SharedSide {
        fn boot_elapsed_ms(&self) -> u64 {
            let reading = kr_ipc::clock::SharedClock::boot_elapsed_ms(&self.0.shared);
            self.0.pause_once();
            reading
        }
    }

    #[derive(Debug)]
    struct ProcessSide(Arc<PausedPair>);

    impl ContinuousClock for ProcessSide {
        fn now(&self) -> ContinuousInstant {
            let reading = self.0.process.now();
            self.0.pause_once();
            reading
        }
    }

    #[test]
    fn a_pause_between_the_two_readings_never_lengthens_a_forwarded_deadline() {
        // A hundred milliseconds left, and a second passes between the two clock readings. The
        // deadline is spent by the time the conversion finishes, so nothing is forwarded.
        let pair = PausedPair::new(Duration::from_secs(1));
        let accepted = pair
            .process
            .now()
            .checked_add(Duration::from_millis(100))
            .expect("a deadline a hundred milliseconds out");
        assert_eq!(
            remaining_deadline(
                &SharedSide(Arc::clone(&pair)),
                &ProcessSide(Arc::clone(&pair)),
                accepted,
                None,
            ),
            None,
            "a deadline whose remaining time was spent between the readings is not forwarded"
        );
    }

    #[test]
    fn a_forwarded_deadline_loses_the_pause_rather_than_gaining_it() {
        let pair = PausedPair::new(Duration::from_millis(10));
        let accepted = pair
            .process
            .now()
            .checked_add(Duration::from_millis(100))
            .expect("a deadline a hundred milliseconds out");
        let forwarded = remaining_deadline(
            &SharedSide(Arc::clone(&pair)),
            &ProcessSide(Arc::clone(&pair)),
            accepted,
            None,
        )
        .expect("some of the deadline is left");
        // The machine's clock read zero, and the deadline was a hundred milliseconds away on it.
        // What crosses is ninety: the ten milliseconds spent between the readings are gone.
        assert_eq!(forwarded.get(), 90);
    }

    #[test]
    fn a_lease_shortens_a_forwarded_deadline_and_never_extends_it() {
        let pair = PausedPair::new(Duration::ZERO);
        let accepted = pair
            .process
            .now()
            .checked_add(Duration::from_millis(5_000))
            .expect("a deadline five seconds out");
        let lease = pair
            .process
            .now()
            .checked_add(Duration::from_millis(400))
            .expect("a lease four hundred milliseconds out");
        let forwarded = remaining_deadline(
            &SharedSide(Arc::clone(&pair)),
            &ProcessSide(Arc::clone(&pair)),
            accepted,
            Some(lease),
        )
        .expect("some of the deadline is left");
        assert_eq!(forwarded.get(), 400);
    }
}

/// A create the host refuses before it launches anything.
///
/// The windows these cover cannot be reached from outside the daemon: a create passes the
/// admission check, writes its reservation, prepares what the launch needs and only then waits.
/// What holds it there is the map it records its pending launch report in, which is taken between
/// the reservation and the transition to `spawned` and nowhere else during a create, and the
/// connection table, which the transition itself reads. What each of them has to leave behind is
/// the same: no process, and a reservation that has stopped occupying the environment.
#[cfg(test)]
mod a_create_that_launches_nothing {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use kr_crypto::store::MemoryStore;
    use kr_ipc::peer::PeerIdentity;
    use kr_protocol::envelope::{ActionTarget, MutationRequest, ParamsValue};
    use kr_protocol::error::ErrorCode;
    use kr_protocol::ids::{ActionId, ActionWindowId, BuildId, ConnectionId, RequestId};
    use kr_protocol::method::{Method, MethodVersion};
    use kr_protocol::scalars::{DurationMs, Nullable};
    use kr_protocol::session::{LaunchProfile, Presentation, SessionCreateParams, ShellMode};
    use kr_transport::clock::ContinuousClock as _;
    use kr_transport::window::{AcceptedDeadline, DeadlineBound};

    use crate::error::ControllerError;
    use crate::registry::LaunchPhase;
    use crate::service::{Controller, ControllerSetup};
    use crate::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};

    /// A supervisor that records what it was asked to start, and starts nothing.
    #[derive(Debug, Default)]
    struct RecordingSupervisor {
        asked: Arc<Mutex<Vec<WorkerLaunch>>>,
    }

    impl WorkerSupervisor for RecordingSupervisor {
        fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
            self.asked
                .lock()
                .expect("the record is not poisoned")
                .push(launch.clone());
            LaunchOutcome::NotStarted {
                detail: "this test starts no workers".to_owned(),
            }
        }

        fn describe(&self) -> &'static str {
            "a supervisor that records every launch and starts nothing"
        }
    }

    /// A reservation recorded before the launch profile existed still names its session's context.
    #[test]
    fn a_create_request_recorded_by_an_earlier_build_is_read_with_the_defaults() {
        use kr_protocol::session::{LaunchProfile, Presentation, ShellMode};

        let environment_id =
            kr_protocol::ids::EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([3; 16]));
        let legacy = super::RecordedCreate {
            environment_id,
            presentation: Presentation::Terminal,
            shell: Nullable::some("zsh".to_owned()),
            shell_mode: ShellMode::Managed,
            cwd: Nullable::some("/work".to_owned()),
            dimensions: Nullable::null(),
            worker_profile: kr_protocol::identity::WorkerProfile::DesktopBound,
            environment_snapshot: Vec::new(),
            palette: Nullable::null(),
        };
        let recorded = kr_cbor::to_canonical_vec(&legacy).expect("encodes");
        let read =
            super::recorded_create(&recorded).expect("an earlier build's record still reads");
        assert_eq!(
            read.worker_profile,
            kr_protocol::identity::WorkerProfile::DesktopBound,
            "the execution context is the one that was recorded, never a substituted default"
        );
        assert_eq!(read.presentation, Presentation::Terminal);
        assert_eq!(read.launch_profile, LaunchProfile::default());
        assert!(read.terminal.0.is_none());

        // This build's own shape reads as itself, and a record that is neither is refused.
        let current = kr_cbor::to_canonical_vec(&create_params(environment_id)).expect("encodes");
        assert!(super::recorded_create(&current).is_ok());
        assert!(super::recorded_create(b"not a record").is_err());
    }

    fn create_params(environment_id: kr_protocol::ids::EnvironmentId) -> SessionCreateParams {
        SessionCreateParams {
            environment_id,
            presentation: Presentation::Invisible,
            shell: Nullable::null(),
            shell_mode: ShellMode::NativeCompat,
            cwd: Nullable::some("/".to_owned()),
            dimensions: Nullable::null(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            environment_snapshot: Vec::new(),
            palette: Nullable::null(),
            launch_profile: LaunchProfile::default(),
            terminal: Nullable::null(),
        }
    }

    fn create_request(environment_id: kr_protocol::ids::EnvironmentId) -> MutationRequest {
        MutationRequest {
            request_id: RequestId::new(1),
            method: Method::SessionCreate.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(kr_ipc::new_uuid()),
            grant_id: Nullable::null(),
            target: ActionTarget::environment(environment_id),
            expected: ParamsValue::empty(),
            action_window_id: ActionWindowId::new("local:test").expect("a window"),
            requested_ttl_ms: DurationMs::new(30_000),
            params: ParamsValue::from_typed(&create_params(environment_id)).expect("encodes"),
        }
    }

    /// Starts a daemon on a tree of its own, with a supervisor that starts nothing.
    /// The admission a create carries in these tests: this connection, the revision in force and
    /// the deadline the host accepted.
    fn carried(
        controller: &Controller,
        connection_id: ConnectionId,
        accepted: AcceptedDeadline,
    ) -> crate::authority::AdmittedMutation {
        crate::authority::AdmittedMutation {
            connection_id,
            admitted_revision: controller.leases.authority_revision(),
            deadline: Some(accepted.deadline),
        }
    }

    /// Holds this daemon's connection table the way a create's own transition reads it.
    ///
    /// The table is a synchronous lock, so it is held on a blocking thread rather than across an
    /// await: holding it in this task would stop the runtime the create needs rather than pause
    /// the create.
    struct HeldConnections {
        release: Option<std::sync::mpsc::Sender<()>>,
        task: Option<tokio::task::JoinHandle<()>>,
    }

    impl HeldConnections {
        fn hold(controller: &Arc<Controller>) -> Self {
            let (release, wait) = std::sync::mpsc::channel::<()>();
            let (held, confirmed) = std::sync::mpsc::channel::<()>();
            let controller = Arc::clone(controller);
            let task = tokio::task::spawn_blocking(move || {
                let _table = controller.admitted_table();
                held.send(()).expect("the test is waiting");
                // Held until the test releases it. The receiver ends when the sender is dropped,
                // so a test that panics does not leave the table locked for the rest of the suite.
                let _ = wait.recv();
            });
            confirmed.recv().expect("the connection table is held");
            Self {
                release: Some(release),
                task: Some(task),
            }
        }

        async fn release(mut self) {
            drop(self.release.take());
            if let Some(task) = self.task.take() {
                task.await.expect("the holding thread finishes");
            }
        }
    }

    async fn daemon() -> (
        kr_ipc::testing::TempHost,
        Arc<Controller>,
        Arc<Mutex<Vec<WorkerLaunch>>>,
    ) {
        let temp = kr_ipc::testing::TempHost::create();
        let program = temp.root().join("kr-worker");
        let (controller, asked) = daemon_running(&temp, program, None).await;
        (temp, controller, asked)
    }

    /// Starts a daemon told to launch `program`, which may be a relative name.
    ///
    /// `shell_packages` is where the daemon looks for qualified shell packages. A test that says
    /// where they are describes an installation of its own rather than reading the one this machine
    /// happens to have.
    async fn daemon_running(
        temp: &kr_ipc::testing::TempHost,
        program: std::path::PathBuf,
        shell_packages: Option<std::path::PathBuf>,
    ) -> (Arc<Controller>, Arc<Mutex<Vec<WorkerLaunch>>>) {
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let controller = Controller::start(ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                Ok(kr_ipc::verify::ControllerIdentity::open(
                    &MemoryStore::new(),
                    environment_id,
                    false,
                )
                .expect("an identity"))
            }),
            secret_store: kr_crypto::store::StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(RecordingSupervisor {
                asked: Arc::clone(&asked),
            }),
            worker_program: program,
            build_id: BuildId::new("kr-test/0").expect("a build identifier"),
            release: "0".to_owned(),
            shell_packages,
            terminal: Box::new(crate::supervision::NoTerminal),
        })
        .await
        .expect("the daemon starts");
        (controller, asked)
    }

    /// Registers one connection, the way a caller's handshake does.
    async fn admitted(controller: &Controller) -> (ConnectionId, kr_protocol::ids::ActorId) {
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        let actor_id = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
        controller
            .admit_connection(
                connection_id,
                &actor_id,
                &PeerIdentity {
                    uid: kr_ipc::paths::current_uid(),
                    gid: 0,
                    pid: None,
                },
            )
            .await
            .expect("the connection is registered");
        (connection_id, actor_id)
    }

    /// Waits until the create under test has written its reservation.
    async fn reserved(controller: &Controller) {
        loop {
            let registry = controller.registry.lock().await;
            let reserved = registry
                .reservations_in(LaunchPhase::Reserved)
                .expect("reads the reservations");
            drop(registry);
            if !reserved.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// KR-REQ-08.44: an invisible session has no terminal, so probed colours are refused.
    ///
    /// Before the reservation, because this is a request the host can never serve rather than one
    /// the environment happens to have no room for: nothing is started, nothing is reserved, and
    /// the caller is told which of its own fields disagree.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_invisible_creation_cannot_adopt_a_probed_palette() {
        use kr_protocol::projection::Rgb;
        use kr_protocol::session::{PalettePreset, PaletteRequest, ProbedPalette};

        let (temp, controller, asked) = daemon().await;
        let environment_id = temp.environment_id();
        let (connection_id, actor_id) = admitted(&controller).await;
        let accepted = AcceptedDeadline {
            deadline: controller
                .clock
                .now()
                .checked_add(Duration::from_secs(30))
                .expect("a deadline half a minute out"),
            bound: DeadlineBound::RequestedTtl,
        };

        let mut probed = create_request(environment_id);
        probed.params = ParamsValue::from_typed(&SessionCreateParams {
            palette: Nullable::some(PaletteRequest::Probe(ProbedPalette {
                foreground: Rgb {
                    red: 0xd0,
                    green: 0xd0,
                    blue: 0xd0,
                },
                background: Rgb {
                    red: 0x10,
                    green: 0x10,
                    blue: 0x18,
                },
            })),
            ..create_params(environment_id)
        })
        .expect("encodes");
        let error = controller
            .session_create(
                &actor_id,
                &probed,
                carried(&controller, connection_id, accepted),
            )
            .await
            .expect_err("an invisible session has no terminal to have probed");
        assert_eq!(
            error.code(),
            ErrorCode::InvalidArgument,
            "the refusal is about the request rather than about this host: {error}"
        );
        assert!(
            error.to_string().contains("no terminal to probe"),
            "and it says which field disagrees with which: {error}"
        );
        assert!(
            asked.lock().expect("the record is not poisoned").is_empty(),
            "no worker is started for a create the host refused"
        );
        let registry = controller.registry.lock().await;
        assert_eq!(
            registry.occupancy().expect("counts"),
            0,
            "and the refusal takes no reservation at all"
        );
        drop(registry);

        // The same session, with a preset, is exactly what section 8 says an invisible creation
        // selects. It reaches the launch, which this supervisor refuses for its own reasons.
        let mut preset = create_request(environment_id);
        preset.params = ParamsValue::from_typed(&SessionCreateParams {
            palette: Nullable::some(PaletteRequest::Preset(PalettePreset::Dark)),
            ..create_params(environment_id)
        })
        .expect("encodes");
        let outcome = controller
            .session_create(
                &actor_id,
                &preset,
                carried(&controller, connection_id, accepted),
            )
            .await;
        assert!(
            outcome.is_err(),
            "this test's supervisor starts nothing, so the create cannot succeed"
        );
        let launches = asked.lock().expect("the record is not poisoned").len();
        assert_eq!(
            launches, 1,
            "but a preset is admitted and reaches the launch"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_create_that_waited_across_a_revocation_launches_nothing() {
        let (temp, controller, asked) = daemon().await;
        let environment_id = temp.environment_id();
        let (connection_id, actor_id) = admitted(&controller).await;

        let accepted = AcceptedDeadline {
            deadline: controller
                .clock
                .now()
                .checked_add(Duration::from_secs(30))
                .expect("a deadline half a minute out"),
            bound: DeadlineBound::RequestedTtl,
        };
        let mutation = create_request(environment_id);

        // The create stops here, between its reservation and the transition to `spawned`.
        let paused_pending = controller.pending.lock().await;
        let create = tokio::spawn({
            let controller = Arc::clone(&controller);
            let actor_id = actor_id.clone();
            async move {
                controller
                    .session_create(
                        &actor_id,
                        &mutation,
                        carried(&controller, connection_id, accepted),
                    )
                    .await
            }
        });
        // The reservation is durable before the launch, so its row is what says the create has
        // reached the point this test is about.
        reserved(&controller).await;

        // The revocation completes while the create waits: the revision is advanced and every
        // registration made under the old one is withdrawn.
        controller
            .revoke_authority()
            .await
            .expect("the revocation completes");
        drop(paused_pending);

        let outcome = create.await.expect("the create finishes");
        let error = outcome.expect_err("a create whose authority was withdrawn starts nothing");
        assert_eq!(
            error.code(),
            ErrorCode::PermissionDenied,
            "the receipt says the authority behind the create was withdrawn: {error}"
        );
        assert!(
            matches!(error, ControllerError::PermissionDenied { .. }),
            "the refusal names the withdrawn registration: {error}"
        );
        assert!(
            asked.lock().expect("the record is not poisoned").is_empty(),
            "no worker is started for a create the host refused"
        );
        let registry = controller.registry.lock().await;
        assert_eq!(
            registry
                .reservations_in(LaunchPhase::Failed)
                .expect("reads the reservations")
                .len(),
            1,
            "the refused create is resolved rather than left occupying the environment"
        );
        assert_eq!(
            registry.occupancy().expect("counts"),
            0,
            "the reservation it made is released"
        );
    }

    /// The deadline is the last thing checked before the launch.
    ///
    /// Reading the registration waits, and a create that queues behind a revocation taking the
    /// connection table can spend the rest of its accepted lifetime there. A registration that
    /// still stands is not permission to start a shell under a deadline that has since passed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_create_whose_deadline_passed_while_it_waited_launches_nothing() {
        let (temp, controller, asked) = daemon().await;
        let environment_id = temp.environment_id();
        let (connection_id, actor_id) = admitted(&controller).await;

        let accepted = AcceptedDeadline {
            deadline: controller
                .clock
                .now()
                .checked_add(Duration::from_millis(300))
                .expect("a deadline a moment out"),
            bound: DeadlineBound::RequestedTtl,
        };
        let mutation = create_request(environment_id);

        // The create stops at the transition to `spawned`, which reads the connection table.
        let paused = HeldConnections::hold(&controller);
        let create = tokio::spawn({
            let controller = Arc::clone(&controller);
            let actor_id = actor_id.clone();
            async move {
                controller
                    .session_create(
                        &actor_id,
                        &mutation,
                        carried(&controller, connection_id, accepted),
                    )
                    .await
            }
        });
        // Long enough for the deadline to pass while the create is held here. The registry lock
        // is held by the create while it waits for the connection table, so nothing here asks the
        // registry what the create has reached: the deadline is absolute, and a create that has
        // not started yet still finds it spent by the time it looks.
        tokio::time::sleep(Duration::from_millis(600)).await;
        paused.release().await;

        let outcome = create.await.expect("the create finishes");
        let error = outcome.expect_err("a create whose deadline has passed starts nothing");
        assert_eq!(
            error.code(),
            ErrorCode::PermissionDenied,
            "an expired freshness window is refused as such: {error}"
        );
        assert!(
            matches!(error, ControllerError::WindowExpired { .. }),
            "the receipt says the deadline passed: {error}"
        );
        assert!(
            asked.lock().expect("the record is not poisoned").is_empty(),
            "no worker is started for a create the host refused"
        );
        let registry = controller.registry.lock().await;
        assert_eq!(
            registry.occupancy().expect("counts"),
            0,
            "the reservation it made is released"
        );
    }

    /// A create whose registration survived a revocation is still refused: it was admitted under
    /// the revision before it.
    ///
    /// One device's revocation advances the revision and leaves every other connection registered,
    /// at the revision now in force. What that connection may do is submit new work; what it may
    /// not do is finish work admitted before the revocation, and the admission this create carries
    /// is what says which this is.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_create_admitted_before_a_revision_is_refused_though_its_connection_stands() {
        let (temp, controller, asked) = daemon().await;
        let environment_id = temp.environment_id();
        let (connection_id, actor_id) = admitted(&controller).await;

        let accepted = AcceptedDeadline {
            deadline: controller
                .clock
                .now()
                .checked_add(Duration::from_secs(30))
                .expect("a deadline half a minute out"),
            bound: DeadlineBound::RequestedTtl,
        };
        // The admission this create carries, taken at the revision in force now.
        let admitted_at = carried(&controller, connection_id, accepted);

        // The revision advances and this connection keeps its registration *at the revision now in
        // force*, which is exactly what a revocation of somebody else's device leaves behind.
        {
            let mut registry = controller.registry.lock().await;
            registry
                .advance_authority_revision()
                .expect("the revision advances");
            let revision = registry
                .authority_revision()
                .expect("the revision in force");
            let mut admitted = controller.admitted_table();
            for connection in admitted.values_mut() {
                connection.admitted_revision = revision;
            }
        }
        // So new work from that connection is admitted: what is refused below is not the
        // registration but the revision this create was admitted under.
        {
            let registry = controller.registry.lock().await;
            let fresh = crate::authority::AdmittedMutation {
                connection_id,
                admitted_revision: registry
                    .authority_revision()
                    .expect("the revision in force"),
                deadline: Some(accepted.deadline),
            };
            controller
                .check_admission(&registry, &fresh)
                .expect("new work from this connection is admitted at the revision in force");
        }

        let error = controller
            .session_create(&actor_id, &create_request(environment_id), admitted_at)
            .await
            .expect_err("a create admitted under the revision before is refused");
        assert!(
            matches!(error, ControllerError::PermissionDenied { .. }),
            "the authority it was admitted under was withdrawn: {error}"
        );
        assert!(
            asked.lock().expect("the record is not poisoned").is_empty(),
            "no worker is started for a create the host refused"
        );
        let registry = controller.registry.lock().await;
        assert_eq!(
            registry.occupancy().expect("counts"),
            0,
            "the reservation it made is released"
        );
    }

    /// A managed create with no qualified package is refused on the path every ingress takes.
    ///
    /// The local endpoint checks its own envelope before it dispatches; a caller on the network
    /// reaches `session_create` directly. The package check belongs to the create itself, so this
    /// drives the create the way the network path does and expects the same named refusal, with
    /// nothing reserved and nothing started.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_managed_create_that_did_not_pass_a_local_envelope_is_refused_the_same_way() {
        let temp = kr_ipc::testing::TempHost::create();
        // An installation of this test's own, with no package in it, so the refusal is this
        // request's shell rather than whatever this machine happens to have installed.
        let packages = temp.root().join("packages");
        std::fs::create_dir_all(&packages).expect("creates the package root");
        let (controller, asked) =
            daemon_running(&temp, temp.root().join("kr-worker"), Some(packages)).await;
        let environment_id = temp.environment_id();
        let (connection_id, actor_id) = admitted(&controller).await;

        let error = controller
            .session_create(
                &actor_id,
                &managed_request(environment_id),
                carried(&controller, connection_id, half_a_minute(&controller)),
            )
            .await
            .expect_err("a shell no package qualifies is refused");
        assert_eq!(
            error.code(),
            kr_protocol::error::ErrorCode::ShellIntegrationUnsupported,
            "{error}"
        );
        assert!(
            asked.lock().expect("the record is not poisoned").is_empty(),
            "nothing is started for a shell no package qualifies"
        );
        let registry = controller.registry.lock().await;
        assert_eq!(
            registry.occupancy().expect("counts"),
            0,
            "and nothing is reserved either"
        );
    }

    /// A worker's own report never waits behind a look at somebody else's silent process.
    ///
    /// A look and a publication take one reservation between them, because a challenge presents a
    /// generation token and one presented mid-publication fences the connection the daemon has just
    /// opened. Two reservations are two different questions: a worker that reported itself must not
    /// sit behind a challenge to a process that will never answer, because its create is waiting on
    /// a deadline of its own.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_report_does_not_wait_for_a_look_at_another_reservation() {
        use kr_crypto::keys::AuthorisationKeyPair;
        use kr_ipc::endpoint::Listener;

        let (temp, controller, _asked) = daemon().await;
        let environment = temp.environment();
        let actor_id = kr_protocol::ids::ActorId::new("local:test").expect("a principal");

        // One claimed reservation whose worker accepts a connection and answers nothing, so a look
        // at it waits out the whole challenge.
        let silent = seed_claim(&controller, &actor_id).await;
        let silent_endpoint = environment
            .worker_endpoint(silent.display_number)
            .expect("an endpoint");
        let _silent_listener = Listener::bind(&silent_endpoint).expect("binds a silent worker");

        // Another reservation, whose worker is about to report itself.
        let ready = seed_claim(&controller, &actor_id).await;
        let keys = AuthorisationKeyPair::generate().expect("a key");
        let process = kr_ipc::identity::current_process_start_identity().expect("this process");
        let claim = kr_protocol::worker::WorkerRendezvous {
            reservation_id: kr_protocol::worker::ReservationId::new(ready.reservation_id.get()),
            session_id: ready.session_id,
            worker_public_key: *keys.public(),
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            process_start_identity: process.clone(),
            // The claim is not verified here: `record_ready` records what an admitted claim said.
            signature: kr_crypto::sign::sign_elements(&keys, "kr-test/record-ready", Vec::new())
                .expect("a signature"),
        };
        let report = kr_protocol::worker::WorkerReady {
            session_id: ready.session_id,
            endpoint: environment
                .worker_endpoint(ready.display_number)
                .expect("an endpoint")
                .as_text(),
            root_process: process,
            shell_path: "/bin/cat".to_owned(),
            dimensions: kr_protocol::session::Dimensions::new(80, 24),
        };

        // The look starts first and is still inside the silent worker's challenge.
        let looking = {
            let controller = Arc::clone(&controller);
            tokio::spawn(async move { controller.recover_claims().await })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!looking.is_finished(), "the look is inside its challenge");

        // The report goes through on its own reservation, without waiting for that look.
        tokio::time::timeout(
            Duration::from_secs(2),
            controller.record_ready(ready.reservation_id, &claim, &report),
        )
        .await
        .expect("a report does not wait for another reservation's look")
        .expect("records the worker");
        assert!(
            controller
                .directory
                .lock()
                .await
                .get(ready.session_id)
                .is_some(),
            "and the session it published is there"
        );
        looking.abort();
    }

    /// A worker's own report and a look at *its* reservation do not overlap.
    ///
    /// The hold is per reservation, and the point of it is this: a challenge presents a generation
    /// token, and one presented while that reservation's own report is being published fences the
    /// connection the daemon has just opened. The two therefore take turns, and which of them goes
    /// first does not matter as long as neither is inside the other.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_report_waits_for_a_look_at_its_own_reservation() {
        use kr_crypto::keys::AuthorisationKeyPair;
        use kr_ipc::endpoint::Listener;

        let (temp, controller, _asked) = daemon().await;
        let environment = temp.environment();
        let actor_id = kr_protocol::ids::ActorId::new("local:test").expect("a principal");

        // One reservation, whose worker accepts a connection and answers nothing. A look at it
        // therefore stays inside its challenge for as long as this test needs.
        let reservation = seed_claim(&controller, &actor_id).await;
        let endpoint = environment
            .worker_endpoint(reservation.display_number)
            .expect("an endpoint");
        let _listener = Listener::bind(&endpoint).expect("binds the silent worker");

        let keys = AuthorisationKeyPair::generate().expect("a key");
        let process = kr_ipc::identity::current_process_start_identity().expect("this process");
        let claim = kr_protocol::worker::WorkerRendezvous {
            reservation_id: kr_protocol::worker::ReservationId::new(
                reservation.reservation_id.get(),
            ),
            session_id: reservation.session_id,
            worker_public_key: *keys.public(),
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            process_start_identity: process.clone(),
            signature: kr_crypto::sign::sign_elements(&keys, "kr-test/record-ready", Vec::new())
                .expect("a signature"),
        };
        let report = kr_protocol::worker::WorkerReady {
            session_id: reservation.session_id,
            endpoint: endpoint.as_text(),
            root_process: process,
            shell_path: "/bin/cat".to_owned(),
            dimensions: kr_protocol::session::Dimensions::new(80, 24),
        };

        // The look starts first and is inside this reservation's challenge.
        let looking = {
            let controller = Arc::clone(&controller);
            tokio::spawn(async move { controller.recover_claims().await })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!looking.is_finished(), "the look is inside its challenge");

        // The report is about the same reservation, so it waits rather than publishing underneath
        // a challenge that is still in flight.
        let held = tokio::time::timeout(
            Duration::from_secs(1),
            controller.record_ready(reservation.reservation_id, &claim, &report),
        )
        .await;
        assert!(
            held.is_err(),
            "a report does not publish while a look at its own reservation is in flight"
        );
        assert!(
            controller
                .directory
                .lock()
                .await
                .get(reservation.session_id)
                .is_none(),
            "and nothing of it reached the directory"
        );

        // The look ends, and the report goes through on its own.
        looking.abort();
        let _ = looking.await;
        tokio::time::timeout(
            Duration::from_secs(5),
            controller.record_ready(reservation.reservation_id, &claim, &report),
        )
        .await
        .expect("the report goes through once the look has let go")
        .expect("records the worker");
        assert!(
            controller
                .directory
                .lock()
                .await
                .get(reservation.session_id)
                .is_some(),
            "and the session it published is there"
        );
    }

    /// Records a reservation in the phase a worker's claim leaves it in.
    async fn seed_claim(
        controller: &Controller,
        actor_id: &kr_protocol::ids::ActorId,
    ) -> crate::registry::Reservation {
        let mut registry = controller.registry.lock().await;
        // A reservation records the create request it was made for, because that is what a later
        // launch and a later publication both read the session's own context out of.
        let intent = kr_cbor::to_canonical_vec(&create_params(controller.paths.environment_id()))
            .expect("encodes");
        let admission = registry
            .reserve(
                actor_id,
                kr_ipc::new_uuid(),
                kr_protocol::scalars::Digest256::from_bytes([0x3c; 32]),
                &intent,
                kr_ipc::now_ms(),
            )
            .expect("reserves");
        let reservation_id = admission.reservation.reservation_id;
        registry
            .set_phase(reservation_id, LaunchPhase::Spawned)
            .expect("spawned");
        registry
            .claim_rendezvous(
                reservation_id,
                *kr_crypto::keys::AuthorisationKeyPair::generate()
                    .expect("a key")
                    .public(),
            )
            .expect("claims")
    }

    /// A create token that already has a reservation is answered from it, not refused again.
    ///
    /// Section 9: a retry resolves to what its first attempt produced. What this pins is that the
    /// package check has no say over a token the registry already knows, whatever that check would
    /// answer now: an installation whose package was removed, replaced or made unreadable between
    /// the two attempts must not turn a recorded action into a refusal. The reservation here is
    /// recorded through the registry's own method, which is what a first attempt leaves behind.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_retry_of_an_admitted_create_is_not_refused_because_its_package_went_away() {
        let temp = kr_ipc::testing::TempHost::create();
        let packages = temp.root().join("packages");
        std::fs::create_dir_all(&packages).expect("creates the package root");
        let (controller, asked) =
            daemon_running(&temp, temp.root().join("kr-worker"), Some(packages)).await;
        let environment_id = temp.environment_id();
        let (connection_id, actor_id) = admitted(&controller).await;
        let request = managed_request(environment_id);

        // What a first attempt leaves: a reservation under this token. The package root is empty,
        // so a create that let the package check speak before reading the token would refuse this
        // retry instead of answering it.
        let create: SessionCreateParams = super::parse(&request.params).expect("decodes");
        let digest =
            kr_protocol::digest::mutation_digest(&request, &actor_id).expect("a mutation digest");
        let intent = kr_cbor::to_canonical_vec(&create).expect("encodes the intent");
        {
            let mut registry = controller.registry.lock().await;
            registry
                .reserve(
                    &actor_id,
                    request.action_id.get(),
                    digest,
                    &intent,
                    kr_ipc::now_ms(),
                )
                .expect("records the first attempt's reservation");
        }

        let error = controller
            .session_create(
                &actor_id,
                &request,
                carried(&controller, connection_id, half_a_minute(&controller)),
            )
            .await
            .expect_err("the reservation has no worker behind it in this test");
        assert_ne!(
            error.code(),
            kr_protocol::error::ErrorCode::ShellIntegrationUnsupported,
            "a retry is answered from its own reservation rather than refused again: {error}"
        );
        assert!(
            error.to_string().contains("already recorded"),
            "and the answer is the recorded one: {error}"
        );
        assert!(
            asked.lock().expect("the record is not poisoned").is_empty(),
            "a retry starts nothing of its own"
        );
    }

    /// A create request for a managed session whose shell no package can qualify.
    fn managed_request(environment_id: kr_protocol::ids::EnvironmentId) -> MutationRequest {
        let mut request = create_request(environment_id);
        let mut params = create_params(environment_id);
        params.shell_mode = ShellMode::Managed;
        params.shell = Nullable::some("/bin/ksh".to_owned());
        request.params = ParamsValue::from_typed(&params).expect("encodes");
        request
    }

    /// An accepted deadline half a minute out, which nothing in these tests reaches.
    fn half_a_minute(controller: &Controller) -> AcceptedDeadline {
        AcceptedDeadline {
            deadline: controller
                .clock
                .now()
                .checked_add(Duration::from_secs(30))
                .expect("a deadline half a minute out"),
            bound: DeadlineBound::RequestedTtl,
        }
    }

    /// What the launch needs is prepared before the create is admitted, and a preparation that
    /// fails resolves the reservation rather than leaving it occupying the environment.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_create_whose_directory_cannot_be_made_releases_its_reservation() {
        let (temp, controller, asked) = daemon().await;
        let environment_id = temp.environment_id();
        let (connection_id, actor_id) = admitted(&controller).await;

        // The directory every worker's own directory goes under is replaced by a file, so making
        // one under it fails the way a full disk or a wrong permission would.
        let workers = temp.environment().workers_dir();
        std::fs::remove_dir_all(&workers).expect("clears the workers directory");
        std::fs::write(&workers, b"not a directory").expect("puts a file in its place");

        let accepted = AcceptedDeadline {
            deadline: controller
                .clock
                .now()
                .checked_add(Duration::from_secs(30))
                .expect("a deadline half a minute out"),
            bound: DeadlineBound::RequestedTtl,
        };
        let error = controller
            .session_create(
                &actor_id,
                &create_request(environment_id),
                carried(&controller, connection_id, accepted),
            )
            .await
            .expect_err("a create that cannot be prepared starts nothing");
        assert!(
            asked.lock().expect("the record is not poisoned").is_empty(),
            "no worker is started for a create the host could not prepare: {error}"
        );
        let registry = controller.registry.lock().await;
        assert_eq!(
            registry.occupancy().expect("counts"),
            0,
            "the reservation it made is released"
        );
        assert_eq!(
            registry
                .reservations_in(LaunchPhase::Failed)
                .expect("reads the reservations")
                .len(),
            1,
            "and it is resolved rather than left to recovery"
        );
    }

    /// Returns the sessions that still have a directory under this environment's workers folder.
    ///
    /// A directory that cannot be read is a failure rather than an empty answer: an assertion that
    /// treated it as empty would pass for the wrong reason.
    fn worker_dirs(temp: &kr_ipc::testing::TempHost) -> Vec<String> {
        let directory = temp.environment().workers_dir();
        let mut names: Vec<String> = std::fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("reads {}: {error}", directory.display()))
            .map(|entry| {
                entry.unwrap_or_else(|error| {
                    panic!("reads an entry of {}: {error}", directory.display())
                })
            })
            .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
            .collect();
        names.sort();
        names
    }

    /// A launch that is confirmed not to have started gives its directory back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_create_whose_launch_never_started_leaves_no_directory() {
        let (temp, controller, asked) = daemon().await;
        let environment_id = temp.environment_id();
        let (connection_id, actor_id) = admitted(&controller).await;
        let accepted = AcceptedDeadline {
            deadline: controller
                .clock
                .now()
                .checked_add(Duration::from_secs(30))
                .expect("a deadline half a minute out"),
            bound: DeadlineBound::RequestedTtl,
        };
        controller
            .session_create(
                &actor_id,
                &create_request(environment_id),
                carried(&controller, connection_id, accepted),
            )
            .await
            .expect_err("this supervisor starts nothing");
        assert_eq!(
            asked.lock().expect("the record is not poisoned").len(),
            1,
            "the launch was prepared and attempted"
        );
        assert!(
            worker_dirs(&temp).is_empty(),
            "and the directory it was prepared with is given back: {:?}",
            worker_dirs(&temp)
        );
    }

    /// The directory a create is refused before its launch goes back with the reservation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_refused_create_leaves_no_directory() {
        let (temp, controller, asked) = daemon().await;
        let environment_id = temp.environment_id();
        let (connection_id, actor_id) = admitted(&controller).await;
        let accepted = AcceptedDeadline {
            deadline: controller
                .clock
                .now()
                .checked_add(Duration::from_millis(300))
                .expect("a deadline a moment out"),
            bound: DeadlineBound::RequestedTtl,
        };
        let mutation = create_request(environment_id);
        let paused = HeldConnections::hold(&controller);
        let create = tokio::spawn({
            let controller = Arc::clone(&controller);
            let actor_id = actor_id.clone();
            async move {
                controller
                    .session_create(
                        &actor_id,
                        &mutation,
                        carried(&controller, connection_id, accepted),
                    )
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(600)).await;
        paused.release().await;
        create
            .await
            .expect("the create finishes")
            .expect_err("a create whose deadline has passed starts nothing");
        assert!(asked.lock().expect("the record is not poisoned").is_empty());
        assert!(
            worker_dirs(&temp).is_empty(),
            "the directory goes with the reservation: {:?}",
            worker_dirs(&temp)
        );
    }

    /// The sweep keeps what a reservation still claims and removes what nothing does.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_sweep_removes_only_the_directories_no_session_claims() {
        let (temp, controller, _asked) = daemon().await;
        let environment = temp.environment();
        // One directory belonging to a reservation that is still unresolved, and one belonging to
        // nothing at all.
        let reserved = {
            let mut registry = controller.registry.lock().await;
            registry
                .reserve(
                    &kr_protocol::ids::ActorId::new("local:test").expect("a principal"),
                    kr_ipc::new_uuid(),
                    kr_protocol::scalars::Digest256::from_bytes([7; 32]),
                    &[0xa0],
                    kr_ipc::now_ms(),
                )
                .expect("reserves")
                .reservation
                .session_id
        };
        let stray = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid());
        for session_id in [reserved, stray] {
            kr_ipc::paths::create_private_tree(
                environment.state_root(),
                &environment.worker_dir(session_id),
            )
            .expect("makes the directory");
        }

        controller
            .sweep_worker_dirs()
            .await
            .expect("the sweep runs");
        assert_eq!(
            worker_dirs(&temp),
            vec![reserved.to_string()],
            "a reservation nothing has settled keeps its directory; a session nobody knows does not"
        );
    }

    /// Every path a launch carries is one the worker can use from a directory of its own.
    ///
    /// The worker is started somewhere this daemon chose, so a name this daemon was given
    /// relatively would be looked for beneath that instead. This one is told to launch a relative
    /// name on purpose.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_launch_carries_paths_the_worker_can_use_from_its_own_directory() {
        let temp = kr_ipc::testing::TempHost::create();
        let (controller, asked) =
            daemon_running(&temp, std::path::PathBuf::from("kr-worker-relative"), None).await;
        let environment_id = temp.environment_id();
        let (connection_id, actor_id) = admitted(&controller).await;
        let accepted = AcceptedDeadline {
            deadline: controller
                .clock
                .now()
                .checked_add(Duration::from_secs(30))
                .expect("a deadline half a minute out"),
            bound: DeadlineBound::RequestedTtl,
        };
        controller
            .session_create(
                &actor_id,
                &create_request(environment_id),
                carried(&controller, connection_id, accepted),
            )
            .await
            .expect_err("this supervisor starts nothing");

        let asked = asked.lock().expect("the record is not poisoned");
        let launch = asked.first().expect("the supervisor was asked to launch");
        for (what, path) in [
            ("the executable", &launch.program),
            ("the runtime root", &launch.runtime_directory),
            ("the state root", &launch.state_directory),
            ("the jobs directory", &launch.jobs_directory),
            ("the working directory", &launch.working_directory),
        ] {
            assert!(
                path.is_absolute(),
                "{what} is a path the worker can use from anywhere: {}",
                path.display()
            );
        }
        // The rendezvous endpoint is a socket path on Unix and a pipe name on Windows. What the
        // launch carries is whatever names the endpoint this daemon bound, unchanged.
        assert_eq!(
            launch.rendezvous,
            controller
                .paths
                .rendezvous_endpoint()
                .expect("an endpoint")
                .as_path(),
            "the launch names the endpoint this daemon bound"
        );
        #[cfg(unix)]
        assert!(
            launch.rendezvous.is_absolute(),
            "and where that is a path, it is one the worker can use from anywhere: {}",
            launch.rendezvous.display()
        );
        assert_eq!(
            launch.program,
            std::env::current_dir()
                .expect("this process has a directory")
                .join("kr-worker-relative"),
            "the relative name is resolved where the daemon was started, not where the worker runs"
        );
    }

    /// The check a service makes again from inside work that has already begun.
    ///
    /// A project mutation reaches its service through a blocking task, and a clone or a
    /// materialisation takes long enough that authority can go while it waits. The service asks
    /// again before it acts, from memory, so the answer costs nothing and can be asked from a
    /// blocking thread. What this covers is the two revocations a host performs: one that
    /// withdraws every registration, and one that withdraws a device's and stamps the rest with
    /// the revision it advanced to. It does not stage a queued effect; what it establishes is that
    /// the check itself answers each of those correctly, and where it is called is read from
    /// `project_mutation` and `ProjectModule::write`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_admission_a_service_checks_again_answers_both_revocations() {
        let (_temp, controller, _asked) = daemon().await;
        let (connection_id, _actor_id) = admitted(&controller).await;
        let admitted_revision = controller
            .admitted_revision(connection_id)
            .expect("the connection is registered");
        let live = crate::authority::AdmittedMutation {
            connection_id,
            admitted_revision,
            deadline: Some(
                controller
                    .clock
                    .now()
                    .checked_add(Duration::from_secs(60))
                    .expect("a deadline"),
            ),
        };
        controller
            .check_registration(&live)
            .expect("a live admission stands");

        // A deadline that has passed refuses a first admission, and says so as freshness rather
        // than as authority: the two are answered differently by the caller.
        let spent = crate::authority::AdmittedMutation {
            deadline: Some(controller.clock.now()),
            ..live
        };
        assert!(matches!(
            controller.check_registration(&spent),
            Err(ControllerError::WindowExpired { .. })
        ));

        // A revocation takes the registration, and the check then refuses whatever was waiting.
        controller
            .revoke_authority()
            .await
            .expect("the revocation completes");
        assert!(matches!(
            controller.check_registration(&live),
            Err(ControllerError::PermissionDenied { .. })
        ));

        // A revocation that withdraws one device leaves every other connection registered and
        // stamps it with the revision it advanced to, which is what `Network::revoke_device`
        // does. A mutation admitted before that point then finds its registration standing under a
        // later revision than the one it carries, and that is the authority it was admitted under
        // having been replaced.
        let (surviving, _actor_id) = admitted(&controller).await;
        let carried_before = crate::authority::AdmittedMutation {
            connection_id: surviving,
            admitted_revision: controller
                .admitted_revision(surviving)
                .expect("the connection is registered"),
            ..live
        };
        controller
            .check_registration(&carried_before)
            .expect("nothing has been revoked yet");
        {
            let mut registry = controller.registry.lock().await;
            registry
                .advance_authority_revision()
                .expect("the revision advances");
            let revision = registry
                .authority_revision()
                .expect("the revision in force");
            let mut admitted = controller.admitted_table();
            for connection in admitted.values_mut() {
                connection.admitted_revision = revision;
            }
        }
        assert!(
            matches!(
                controller.check_registration(&carried_before),
                Err(ControllerError::PermissionDenied { .. })
            ),
            "a mutation admitted before the revocation is refused although its connection stands"
        );

        // And the connection's own next mutation, admitted at the revision now in force, is not.
        let carried_after = crate::authority::AdmittedMutation {
            admitted_revision: controller
                .admitted_revision(surviving)
                .expect("the connection is registered"),
            ..carried_before
        };
        controller
            .check_registration(&carried_after)
            .expect("one device's revocation is not everybody's reconnection");
    }
}

/// A close to a worker that stops answering.
///
/// The daemon holds one connection per worker, and a close is the operation most likely to meet a
/// worker that has stopped answering: it is asking that worker to stop. What this covers is the
/// connection afterwards: that the caller is told, that the link is not put back in the shared
/// slot part way through an exchange, and that the next caller is not waiting behind the first.
#[cfg(test)]
mod a_close_a_worker_never_answers {
    use std::sync::Arc;
    use std::time::Duration;

    use kr_crypto::store::MemoryStore;
    use kr_ipc::endpoint::Listener;
    use kr_ipc::framed::split;
    use kr_ipc::verify::WorkerIdentity;
    use kr_protocol::envelope::{ActionTarget, ControlFrame, MutationRequest, ParamsValue};
    use kr_protocol::error::ErrorCode;
    use kr_protocol::frame::StreamKind;
    use kr_protocol::hello::{ActionWindow, ReceiveLimits};
    use kr_protocol::identity::WorkerProfile;
    use kr_protocol::ids::{
        ActionId, ActionWindowId, BuildId, ConnectionId, RequestId, SessionEpoch, SessionId,
    };
    use kr_protocol::local::{LocalHelloAck, LocalRole};
    use kr_protocol::method::{Method, MethodVersion};
    use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable};
    use kr_protocol::session::{DisplayNumber, SessionCloseParams};
    use kr_protocol::worker::{GenerationAccepted, GenerationChallenge, WorkerDescriptor};
    use kr_transport::window::{AcceptedDeadline, DeadlineBound};

    use crate::directory::KnownWorker;
    use crate::error::ControllerError;
    use crate::service::{CLOSE_EXCHANGE, Controller, ControllerSetup};
    use crate::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
    use kr_transport::clock::ContinuousClock as _;

    #[derive(Debug)]
    struct RefusingSupervisor;

    impl WorkerSupervisor for RefusingSupervisor {
        fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
            LaunchOutcome::NotStarted {
                detail: "this test starts no workers".to_owned(),
            }
        }

        fn describe(&self) -> &'static str {
            "a supervisor that starts nothing"
        }
    }

    /// An endpoint that proves itself as a worker and then answers nothing.
    ///
    /// It completes the handshake the daemon makes before it will speak to a worker at all (the
    /// version exchange, the challenge over the descriptor's key and the controller generation)
    /// and then reads whatever arrives without replying. That is a worker that has stopped
    /// answering, which is different from one that has gone: the connection stays open.
    fn serve_silent_worker(
        listener: Listener,
        identity: Arc<WorkerIdentity>,
        endpoint_text: String,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let Ok((connection, peer)) = listener.accept().await else {
                    return;
                };
                let identity = Arc::clone(&identity);
                let endpoint_text = endpoint_text.clone();
                tokio::spawn(async move {
                    let (mut reader, mut writer) = split(connection, StreamKind::Control);
                    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
                    while let Ok(frame) = reader.read_message::<ControlFrame>().await {
                        let answers = match frame {
                            ControlFrame::Hello(_) => vec![
                                ControlFrame::HelloAck(Box::new(LocalHelloAck {
                                    selected_version: kr_protocol::hello::PROTOCOL_VERSION,
                                    role: LocalRole::Worker,
                                    connection_id,
                                    environment_id: identity_environment(),
                                    boot_identity: kr_ipc::identity::boot_identity()
                                        .expect("a boot identity"),
                                    peer: peer.to_wire(),
                                    action_window: ActionWindow {
                                        action_window_id: ActionWindowId::new("worker:test")
                                            .expect("a window"),
                                        connection_id,
                                        boot_epoch: kr_protocol::ids::BootEpoch::new(1),
                                        issued_at_ms: kr_ipc::now_ms(),
                                        valid_for_ms: DurationMs::new(60_000),
                                    },
                                    capabilities: CanonicalSet::new(),
                                    max_receive: ReceiveLimits::default(),
                                })),
                                ControlFrame::GenerationChallenge(GenerationChallenge {
                                    nonce: kr_ipc::verify::fresh_challenge()
                                        .expect("a challenge")
                                        .nonce,
                                }),
                            ],
                            ControlFrame::VerifyChallenge(challenge) => {
                                vec![ControlFrame::VerifyProof(
                                    identity
                                        .answer(&challenge, &endpoint_text)
                                        .expect("answers its own challenge"),
                                )]
                            }
                            ControlFrame::GenerationToken(token) => {
                                vec![ControlFrame::GenerationAccepted(GenerationAccepted {
                                    generation: token.generation,
                                    fenced_previous: false,
                                })]
                            }
                            // The close arrives here and is never answered.
                            _ => Vec::new(),
                        };
                        for answer in answers {
                            if writer.write_message(&answer).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        })
    }

    /// The environment the fake worker's acknowledgement names.
    ///
    /// The daemon does not compare it with its own, so any identity does; this keeps one value in
    /// one place rather than inventing a second.
    fn identity_environment() -> kr_protocol::ids::EnvironmentId {
        kr_protocol::ids::EnvironmentId::new(kr_protocol::scalars::Uuid::NIL)
    }

    fn close_request(
        environment_id: kr_protocol::ids::EnvironmentId,
        session_id: SessionId,
    ) -> MutationRequest {
        MutationRequest {
            request_id: RequestId::new(1),
            method: Method::SessionClose.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(kr_ipc::new_uuid()),
            grant_id: Nullable::null(),
            target: ActionTarget {
                environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            expected: ParamsValue::empty(),
            action_window_id: ActionWindowId::new("local:test").expect("a window"),
            requested_ttl_ms: DurationMs::new(30_000),
            params: ParamsValue::from_typed(&SessionCloseParams { session_id }).expect("encodes"),
        }
    }

    /// A daemon with one silent worker in its directory, and everything a close needs.
    /// Registers one caller and returns the admission its close carries: the connection it
    /// arrived on, the revision in force and the deadline this host accepted.
    async fn admission(
        controller: &Controller,
        accepted: AcceptedDeadline,
    ) -> crate::authority::AdmittedMutation {
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        let actor_id = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
        controller
            .admit_connection(
                connection_id,
                &actor_id,
                &kr_ipc::peer::PeerIdentity {
                    uid: kr_ipc::paths::current_uid(),
                    gid: 0,
                    pid: None,
                },
            )
            .await
            .expect("the connection is registered");
        crate::authority::AdmittedMutation {
            connection_id,
            admitted_revision: controller.leases.authority_revision(),
            deadline: Some(accepted.deadline),
        }
    }

    struct Silent {
        _temp: kr_ipc::testing::TempHost,
        controller: Arc<Controller>,
        environment_id: kr_protocol::ids::EnvironmentId,
        session_id: SessionId,
        worker: KnownWorker,
        actor: kr_protocol::actor::ActorEnvelope,
        accepted: AcceptedDeadline,
        serving: tokio::task::JoinHandle<()>,
    }

    async fn silent_worker() -> Silent {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        let controller = Controller::start(ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                Ok(kr_ipc::verify::ControllerIdentity::open(
                    &MemoryStore::new(),
                    environment_id,
                    false,
                )
                .expect("an identity"))
            }),
            secret_store: kr_crypto::store::StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(RefusingSupervisor),
            worker_program: temp.root().join("kr-worker"),
            build_id: BuildId::new("kr-test/0").expect("a build identifier"),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(crate::supervision::NoTerminal),
        })
        .await
        .expect("the daemon starts");

        let session_id = SessionId::new(kr_ipc::new_uuid());
        let worker_endpoint = environment
            .worker_endpoint(DisplayNumber::new(1))
            .expect("an endpoint");
        let identity = Arc::new(
            WorkerIdentity::generate(
                session_id,
                SessionEpoch::V1,
                kr_ipc::identity::boot_identity().expect("a boot identity"),
                kr_ipc::identity::process_start_identity(std::process::id())
                    .expect("this process's start identity"),
                kr_protocol::hello::PROTOCOL_VERSION,
            )
            .expect("generates a worker identity"),
        );
        let descriptor = WorkerDescriptor {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: DisplayNumber::new(1),
            boot_identity: identity.boot_identity().clone(),
            process_start_identity: identity.process_start_identity().clone(),
            protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
            endpoint: worker_endpoint.as_text(),
            worker_public_key: *identity.public_key(),
            worker_profile: WorkerProfile::HeadlessUser,
            published_at_ms: kr_ipc::now_ms(),
        };
        let listener = Listener::bind(&worker_endpoint).expect("binds the worker endpoint");
        let serving =
            serve_silent_worker(listener, Arc::clone(&identity), worker_endpoint.as_text());
        let worker = KnownWorker {
            descriptor,
            endpoint: worker_endpoint,
        };
        controller
            .directory
            .lock()
            .await
            .verified
            .insert(session_id, worker.clone());

        let actor = crate::service::local_actor(
            kr_protocol::ids::ActorId::new("local:test").expect("a principal"),
            ConnectionId::new(kr_ipc::new_uuid()),
            controller.generation,
        );
        let accepted = AcceptedDeadline {
            deadline: controller
                .clock
                .now()
                .checked_add(Duration::from_secs(300))
                .expect("a deadline five minutes out"),
            bound: DeadlineBound::RequestedTtl,
        };
        Silent {
            _temp: temp,
            controller,
            environment_id,
            session_id,
            worker,
            actor,
            accepted,
            serving,
        }
    }

    /// Records that this worker has acknowledged the revision in force, so its leases renew.
    fn acknowledged(controller: &Controller, session_id: SessionId) {
        let binding = controller.leases.binding(session_id);
        controller.leases.acknowledge(
            session_id,
            binding,
            controller.leases.authority_revision(),
            None,
        );
    }

    /// A close that has the worker's link and cannot read this daemon's own authority gives the
    /// link back rather than holding it past what a closure may take.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_close_that_cannot_read_this_daemons_authority_in_time_gives_the_link_back() {
        let Silent {
            _temp,
            controller,
            environment_id,
            session_id,
            actor,
            accepted,
            serving,
            ..
        } = silent_worker().await;
        acknowledged(&controller, session_id);
        let carried = admission(&controller, accepted).await;

        // Something else is holding the registry for longer than a closure may take. The close
        // acquires the worker's link first and then waits for the registry, inside the same
        // budget as the exchange itself.
        let held = controller.registry.lock().await;
        let started = tokio::time::Instant::now();
        let refused = controller
            .session_close(
                &close_request(environment_id, session_id),
                &actor,
                Some(accepted),
                carried,
            )
            .await
            .expect_err("a close that cannot read this daemon's authority closes nothing");
        let waited = started.elapsed();
        drop(held);
        assert!(
            waited <= CLOSE_EXCHANGE + Duration::from_secs(2),
            "the wait is bounded by what a closure may take: {waited:?}"
        );
        assert_eq!(
            refused.code(),
            ErrorCode::ResourceUnavailable,
            "the caller is told this daemon could not answer, not that the worker did: {refused}"
        );

        // And the link is back: the next caller finds it rather than waiting behind this one.
        let link = tokio::time::timeout(
            Duration::from_secs(5),
            controller.worker_client_of(session_id),
        )
        .await
        .expect("the link is free")
        .expect("the link is this daemon's own");
        drop(link);
        serving.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_client_is_retired_rather_than_held_for_the_next_caller() {
        let Silent {
            _temp,
            controller,
            environment_id,
            session_id,
            actor,
            accepted,
            serving,
            ..
        } = silent_worker().await;

        // The worker holds this environment's authority revision, so its dispatch leases renew.
        acknowledged(&controller, session_id);
        assert!(
            matches!(
                controller
                    .leases
                    .renew(session_id, controller.generation, &*controller.clock),
                Ok(Ok(_))
            ),
            "an acknowledged worker's lease renews before the close"
        );

        let started = tokio::time::Instant::now();
        let first = controller
            .session_close(
                &close_request(environment_id, session_id),
                &actor,
                Some(accepted),
                admission(&controller, accepted).await,
            )
            .await
            .expect_err("a worker that never answers produces no closure");
        assert_eq!(
            first.code(),
            ErrorCode::OutcomeUnknown,
            "a close that was written and never answered is uncertain, not refused: {first}"
        );
        assert!(
            matches!(first, ControllerError::Uncertain { .. }),
            "the caller is told the outcome is not known: {first}"
        );

        // The path this daemon announces authority revisions over is the one it just gave up on,
        // so renewal stops with it: section 9 lets a remote dispatch lease be renewed only after
        // the worker has acknowledged the revision, and an acknowledgement can no longer arrive.
        assert!(
            controller.leases.is_fenced(session_id),
            "renewal is fenced for the worker whose link was retired"
        );
        assert!(
            matches!(
                controller
                    .leases
                    .renew(session_id, controller.generation, &*controller.clock),
                Ok(Err(
                    kr_transport::lease::LeaseRefusal::RevisionNotAcknowledged
                ))
            ),
            "and a lease is refused until that worker acknowledges the revision again"
        );

        // The slot this daemon keeps for that worker is free, and what was in it has gone. A
        // client whose exchange was abandoned part way through would answer the next caller's
        // request with this close's reply, so it is retired rather than put back.
        let link = controller
            .connections
            .lock()
            .await
            .get(&session_id)
            .map(Arc::clone)
            .expect("the daemon opened a connection to this worker");
        let held = link
            .try_lock()
            .expect("the shared slot is free for the next caller");
        assert!(
            held.is_none(),
            "an interrupted client is retired rather than returned to the shared slot"
        );
        drop(held);

        // The second caller is not waiting behind the first. It opens its own connection to the
        // same silent worker and is bounded in its own right.
        let second = controller
            .session_close(
                &close_request(environment_id, session_id),
                &actor,
                Some(accepted),
                admission(&controller, accepted).await,
            )
            .await
            .expect_err("the second close meets the same silent worker");
        assert_eq!(second.code(), ErrorCode::OutcomeUnknown);
        assert!(
            started.elapsed() < CLOSE_EXCHANGE * 3,
            "two closes against a silent worker cost two bounded waits, not an unbounded one"
        );
        serving.abort();
    }

    /// The link a close fences is the link it actually ran over.
    ///
    /// A close can queue for this daemon's one connection to a worker while another operation
    /// loses that connection and a replacement is established and acknowledged. Fencing the
    /// control path that was current when the close arrived would lift nothing: that path has
    /// already been given up on, and the renewal the close means to stop belongs to the one it
    /// used.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_link_a_close_fences_is_the_one_it_ran_over() {
        let Silent {
            _temp,
            controller,
            environment_id,
            session_id,
            worker,
            actor,
            accepted,
            serving,
            ..
        } = silent_worker().await;
        acknowledged(&controller, session_id);

        // The slot is held, so the close below waits for it.
        let occupied = controller
            .worker_client(&worker)
            .await
            .expect("the daemon opens its link to the worker");

        let close = tokio::spawn({
            let controller = Arc::clone(&controller);
            let actor = actor.clone();
            let mutation = close_request(environment_id, session_id);
            async move {
                let admission = admission(&controller, accepted).await;
                controller
                    .session_close(&mutation, &actor, Some(accepted), admission)
                    .await
            }
        });
        // Long enough for the close to be queueing for the slot.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Meanwhile the control path this worker was acknowledged over is lost, and a replacement
        // is established and acknowledged.
        let lost = controller.leases.binding(session_id);
        controller.leases.stop_renewal(session_id, lost);
        acknowledged(&controller, session_id);
        assert!(
            !controller.leases.is_fenced(session_id),
            "the replacement path renews before the close reaches the worker"
        );
        drop(occupied);

        let error = close
            .await
            .expect("the close finishes")
            .expect_err("a worker that never answers produces no closure");
        assert_eq!(error.code(), ErrorCode::OutcomeUnknown);
        assert!(
            controller.leases.is_fenced(session_id),
            "the close fences the path it used, not the one it was queued behind"
        );
        serving.abort();
    }
}
